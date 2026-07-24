// Package image builds deterministic image inventories and optionally
// resolves tags to registry digests under explicit opt-in.
package image

import (
	"fmt"
	"sort"
	"strings"

	"github.com/DPS0340/clusterproof/internal/manifest"
)

// Reference is one parsed image reference from a workload.
type Reference struct {
	// Raw is the exact image string from the manifest.
	Raw string `json:"raw"`
	// Registry is the registry host, defaulting to docker.io.
	Registry string `json:"registry"`
	// Repository is the image path within the registry.
	Repository string `json:"repository"`
	// Tag is the tag portion; "latest" when implicit and no digest exists.
	Tag string `json:"tag,omitempty"`
	// Digest is the sha256 digest when pinned in the reference.
	Digest string `json:"digest,omitempty"`
	// Workloads lists the namespace/kind/name targets using this image.
	Workloads []string `json:"workloads"`
}

// Pinned reports whether the reference is digest pinned.
func (r Reference) Pinned() bool {
	return r.Digest != ""
}

// Inventory builds a deterministic, deduplicated image inventory from
// normalized workloads. It performs no network access.
func Inventory(workloads []manifest.Workload) []Reference {
	byRaw := make(map[string]*Reference)
	for _, workload := range workloads {
		for _, container := range workload.PodSpec.AllContainers() {
			raw := strings.TrimSpace(container.Image)
			if raw == "" {
				continue
			}
			entry := byRaw[raw]
			if entry == nil {
				parsed := parseReference(raw)
				entry = &parsed
				byRaw[raw] = entry
			}
			entry.Workloads = append(entry.Workloads, workload.Target())
		}
	}

	references := make([]Reference, 0, len(byRaw))
	for _, entry := range byRaw {
		sort.Strings(entry.Workloads)
		entry.Workloads = dedupeSorted(entry.Workloads)
		references = append(references, *entry)
	}
	sort.Slice(references, func(i, j int) bool {
		return references[i].Raw < references[j].Raw
	})
	return references
}

// parseReference splits an image reference into registry, repository, tag,
// and digest without validating registry reachability.
func parseReference(raw string) Reference {
	reference := Reference{Raw: raw}
	rest := raw

	if index := strings.Index(rest, "@sha256:"); index >= 0 {
		reference.Digest = rest[index+1:]
		rest = rest[:index]
	}

	// The tag is the content after the last colon only when that colon
	// appears after the last slash; otherwise the colon belongs to a port.
	lastSlash := strings.LastIndex(rest, "/")
	lastColon := strings.LastIndex(rest, ":")
	if lastColon > lastSlash {
		reference.Tag = rest[lastColon+1:]
		rest = rest[:lastColon]
	} else if reference.Digest == "" {
		reference.Tag = "latest"
	}

	// A registry host contains a dot, a colon, or is "localhost" before the
	// first slash; otherwise the reference belongs to docker.io.
	firstSlash := strings.Index(rest, "/")
	if firstSlash > 0 {
		host := rest[:firstSlash]
		if strings.ContainsAny(host, ".:") || host == "localhost" {
			reference.Registry = host
			reference.Repository = rest[firstSlash+1:]
			return reference
		}
	}
	reference.Registry = "docker.io"
	if firstSlash < 0 {
		reference.Repository = "library/" + rest
	} else {
		reference.Repository = rest
	}
	return reference
}

func dedupeSorted(values []string) []string {
	result := values[:0]
	var previous string
	for index, value := range values {
		if index == 0 || value != previous {
			result = append(result, value)
		}
		previous = value
	}
	return result
}

// ValidateDigest confirms a digest has the exact sha256 format.
func ValidateDigest(digest string) error {
	if !strings.HasPrefix(digest, "sha256:") {
		return fmt.Errorf("digest %q must use the sha256 algorithm", digest)
	}
	hexPart := strings.TrimPrefix(digest, "sha256:")
	if len(hexPart) != 64 {
		return fmt.Errorf("digest %q must contain 64 hex characters", digest)
	}
	for _, character := range hexPart {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return fmt.Errorf("digest %q contains a non-hex character", digest)
		}
	}
	return nil
}
