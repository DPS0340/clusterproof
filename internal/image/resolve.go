package image

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ResolveOptions bounds explicit, opt-in tag-to-digest resolution.
type ResolveOptions struct {
	// AllowedRegistries is the exact registry host allowlist. Resolution
	// refuses any registry not listed; an empty list resolves nothing.
	AllowedRegistries []string
	// Timeout bounds each registry request.
	Timeout time.Duration
	// MaxResponseBytes bounds each registry response.
	MaxResponseBytes int64
	// Transport overrides the HTTP transport in tests.
	Transport http.RoundTripper
}

// DefaultResolveOptions returns conservative resolution bounds with an
// empty registry allowlist: the caller must name every allowed registry.
func DefaultResolveOptions() ResolveOptions {
	return ResolveOptions{
		Timeout:          10 * time.Second,
		MaxResponseBytes: 1 << 20,
	}
}

// Resolution records one explicit digest resolution for evidence.
type Resolution struct {
	Raw        string    `json:"raw"`
	Registry   string    `json:"registry"`
	Repository string    `json:"repository"`
	Tag        string    `json:"tag"`
	Digest     string    `json:"digest"`
	ResolvedAt time.Time `json:"resolved_at"`
	// NetworkUsed is always true for a resolution; recorded explicitly so
	// evidence consumers never have to infer network activity.
	NetworkUsed bool `json:"network_used"`
}

// Resolve resolves one tagged reference to its current registry digest.
// It never sends credentials: only anonymous manifest HEAD requests are
// made, and responses are bounded. Already-pinned references are rejected
// so the caller cannot mistake a lookup for a verification.
func Resolve(ctx context.Context, reference Reference, options ResolveOptions) (Resolution, error) {
	if reference.Pinned() {
		return Resolution{}, fmt.Errorf("image %q is already digest pinned; resolution is unnecessary", reference.Raw)
	}
	if reference.Tag == "" {
		return Resolution{}, fmt.Errorf("image %q has no tag to resolve", reference.Raw)
	}
	if options.Timeout <= 0 || options.MaxResponseBytes <= 0 {
		return Resolution{}, errors.New("resolution timeout and response limit must be positive")
	}
	if !registryAllowed(reference.Registry, options.AllowedRegistries) {
		return Resolution{}, fmt.Errorf(
			"registry %q is not in the explicit allowlist %v; add it to resolve %q",
			reference.Registry, sortedCopy(options.AllowedRegistries), reference.Raw)
	}

	requestContext, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s",
		reference.Registry, reference.Repository, reference.Tag)
	request, err := http.NewRequestWithContext(requestContext, http.MethodHead, url, nil)
	if err != nil {
		return Resolution{}, fmt.Errorf("build registry request: %w", err)
	}
	request.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))

	client := &http.Client{
		Timeout: options.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("registry redirects are not followed")
		},
	}
	if options.Transport != nil {
		client.Transport = options.Transport
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
	}

	response, err := client.Do(request)
	if err != nil {
		return Resolution{}, fmt.Errorf("resolve %q: %w", reference.Raw, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, options.MaxResponseBytes))
		response.Body.Close()
	}()

	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return Resolution{}, fmt.Errorf(
			"registry %q requires authentication for %q; ClusterProof resolves anonymously and never stores credentials",
			reference.Registry, reference.Repository)
	}
	if response.StatusCode != http.StatusOK {
		return Resolution{}, fmt.Errorf("registry returned status %d for %q", response.StatusCode, reference.Raw)
	}

	digest := response.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return Resolution{}, fmt.Errorf("registry response for %q lacks a content digest header", reference.Raw)
	}
	if err := ValidateDigest(digest); err != nil {
		return Resolution{}, fmt.Errorf("registry returned an invalid digest: %w", err)
	}

	return Resolution{
		Raw:         reference.Raw,
		Registry:    reference.Registry,
		Repository:  reference.Repository,
		Tag:         reference.Tag,
		Digest:      digest,
		ResolvedAt:  time.Now().UTC(),
		NetworkUsed: true,
	}, nil
}

func registryAllowed(registry string, allowlist []string) bool {
	for _, allowed := range allowlist {
		if allowed == registry {
			return true
		}
	}
	return false
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

// MarshalInventory renders a deterministic JSON inventory export.
func MarshalInventory(references []Reference) ([]byte, error) {
	document := struct {
		SchemaVersion string      `json:"schema_version"`
		Images        []Reference `json:"images"`
	}{
		SchemaVersion: "1",
		Images:        references,
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode image inventory: %w", err)
	}
	return append(data, '\n'), nil
}
