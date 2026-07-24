// Package sigstore verifies image signatures against the explicit trust
// policy through a bounded cosign subprocess adapter.
//
// ClusterProof never implements signature cryptography itself; it invokes a
// caller-provided cosign binary with fixed arguments and no shell, bounds
// its output, and interprets only its exit status and JSON result shape.
package sigstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/DPS0340/clusterproof/internal/image"
	"github.com/DPS0340/clusterproof/internal/trust"
)

// Options bounds the cosign subprocess.
type Options struct {
	Executable     string
	Timeout        time.Duration
	MaxOutputBytes int64
	MaxErrorBytes  int64
	// AllowNetwork permits online transparency-log and registry lookups.
	// When false, verification requires an offline bundle and cosign runs
	// with new-bundle/offline flags only.
	AllowNetwork bool
	// BundlePath is a local Sigstore bundle for offline verification.
	BundlePath string
}

// DefaultOptions returns safe subprocess limits with network disabled.
func DefaultOptions() Options {
	return Options{
		Executable:     "cosign",
		Timeout:        2 * time.Minute,
		MaxOutputBytes: 10 << 20,
		MaxErrorBytes:  64 << 10,
		AllowNetwork:   false,
	}
}

// Verification records one signature verification outcome for evidence.
type Verification struct {
	Image        string    `json:"image"`
	Digest       string    `json:"digest"`
	Verified     bool      `json:"verified"`
	Mode         string    `json:"mode"` // "key" or "keyless"
	Identity     string    `json:"identity,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	KeyName      string    `json:"key_name,omitempty"`
	Offline      bool      `json:"offline"`
	NetworkUsed  bool      `json:"network_used"`
	VerifiedAt   time.Time `json:"verified_at"`
	FailureCause string    `json:"failure_cause,omitempty"`
}

// VerifyArgs returns the exact cosign invocation for one identity or key.
// Exported so tests can prove the argument contract never drifts.
func VerifyArgs(reference string, identity *trust.Identity, key *trust.Key, options Options) []string {
	args := []string{"verify", "--output", "json"}
	if identity != nil {
		args = append(args,
			"--certificate-identity", identity.Subject,
			"--certificate-oidc-issuer", identity.Issuer,
		)
	}
	if key != nil {
		args = append(args, "--key", key.Path)
	}
	if options.BundlePath != "" {
		args = append(args, "--bundle", options.BundlePath)
	}
	if !options.AllowNetwork {
		args = append(args, "--offline", "--private-infrastructure")
	}
	return append(args, "--", reference)
}

// Verify checks one digest-pinned image reference against the trust policy.
// A floating tag alone can never satisfy verification: the reference must
// carry an exact digest before cosign is invoked.
func Verify(ctx context.Context, reference image.Reference, policy trust.Policy, options Options) (Verification, error) {
	if !reference.Pinned() {
		return Verification{}, fmt.Errorf(
			"image %q is not digest pinned; resolve the tag first — a floating tag alone never satisfies signature policy",
			reference.Raw)
	}
	if err := image.ValidateDigest(reference.Digest); err != nil {
		return Verification{}, fmt.Errorf("refuse verification: %w", err)
	}
	if len(policy.Identities) == 0 && len(policy.Keys) == 0 {
		return Verification{}, errors.New("trust policy defines no identity or key; nothing can verify")
	}
	if options.Executable == "" || options.Timeout <= 0 ||
		options.MaxOutputBytes <= 0 || options.MaxErrorBytes <= 0 {
		return Verification{}, errors.New("invalid sigstore options")
	}
	if !options.AllowNetwork && options.BundlePath == "" {
		return Verification{}, errors.New(
			"offline verification requires a bundle path; pass an offline bundle or explicitly allow network access")
	}
	if options.BundlePath != "" {
		info, err := os.Lstat(options.BundlePath)
		if err != nil {
			return Verification{}, fmt.Errorf("inspect bundle %q: %w", options.BundlePath, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return Verification{}, fmt.Errorf("bundle %q is not a regular file", options.BundlePath)
		}
	}

	pinnedReference := reference.Registry + "/" + reference.Repository + "@" + reference.Digest

	// Try each pinned identity, then each key. First success wins; every
	// failure cause is retained so a rejection is explainable.
	var causes []string
	for index := range policy.Identities {
		identity := policy.Identities[index]
		verification, err := runCosign(ctx, pinnedReference, &identity, nil, reference, options)
		if err != nil {
			return Verification{}, err
		}
		if verification.Verified {
			return verification, nil
		}
		causes = append(causes, verification.FailureCause)
	}
	for index := range policy.Keys {
		key := policy.Keys[index]
		if key.Path == "" {
			causes = append(causes, "key "+key.Name+": inline PEM keys require a file path for cosign")
			continue
		}
		verification, err := runCosign(ctx, pinnedReference, nil, &key, reference, options)
		if err != nil {
			return Verification{}, err
		}
		if verification.Verified {
			return verification, nil
		}
		causes = append(causes, verification.FailureCause)
	}

	return Verification{
		Image:        reference.Raw,
		Digest:       reference.Digest,
		Verified:     false,
		Offline:      !options.AllowNetwork,
		NetworkUsed:  options.AllowNetwork,
		VerifiedAt:   time.Now().UTC(),
		FailureCause: strings.Join(causes, "; "),
	}, nil
}

func runCosign(
	ctx context.Context,
	pinnedReference string,
	identity *trust.Identity,
	key *trust.Key,
	reference image.Reference,
	options Options,
) (Verification, error) {
	executable, err := exec.LookPath(options.Executable)
	if err != nil {
		return Verification{}, fmt.Errorf("find cosign executable: %w", err)
	}
	runContext, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()

	stdout := newCappedBuffer(options.MaxOutputBytes)
	stderr := newCappedBuffer(options.MaxErrorBytes)
	command := exec.CommandContext(runContext, executable, VerifyArgs(pinnedReference, identity, key, options)...)
	command.Stdout = stdout
	command.Stderr = stderr

	verification := Verification{
		Image:       reference.Raw,
		Digest:      reference.Digest,
		Offline:     !options.AllowNetwork,
		NetworkUsed: options.AllowNetwork,
		VerifiedAt:  time.Now().UTC(),
	}
	if identity != nil {
		verification.Mode = "keyless"
		verification.Identity = identity.Subject
		verification.Issuer = identity.Issuer
	} else if key != nil {
		verification.Mode = "key"
		verification.KeyName = key.Name
	}

	runErr := command.Run()
	if errors.Is(runContext.Err(), context.DeadlineExceeded) {
		return Verification{}, fmt.Errorf("signature verification exceeded timeout of %s", options.Timeout)
	}
	if stdout.exceeded || stderr.exceeded {
		return Verification{}, fmt.Errorf("cosign output exceeds configured limits")
	}
	if runErr != nil {
		verification.Verified = false
		verification.FailureCause = describeFailure(identity, key, stderr.String())
		return verification, nil
	}

	// cosign exit 0 must still produce a parsable, non-empty JSON claim
	// list; an empty result is treated as unverified, never as success.
	var claims []json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &claims); err != nil || len(claims) == 0 {
		verification.Verified = false
		verification.FailureCause = describeFailure(identity, key, "cosign returned no verifiable claims")
		return verification, nil
	}
	verification.Verified = true
	return verification, nil
}

func describeFailure(identity *trust.Identity, key *trust.Key, detail string) string {
	scope := "verification"
	if identity != nil {
		scope = "identity " + identity.Subject
	} else if key != nil {
		scope = "key " + key.Name
	}
	detail = cleanText(detail)
	if detail == "" {
		detail = "cosign rejected the signature"
	}
	return scope + ": " + detail
}

func cleanText(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, current := range value {
		if builder.Len() >= 500 {
			break
		}
		if current == '\n' || current == '\r' || current == '\t' {
			builder.WriteRune(' ')
			continue
		}
		builder.WriteRune(current)
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int64
	exceeded bool
}

func newCappedBuffer(limit int64) *cappedBuffer {
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - int64(b.buffer.Len())
	if remaining > 0 {
		toWrite := data
		if int64(len(toWrite)) > remaining {
			toWrite = toWrite[:remaining]
		}
		_, _ = b.buffer.Write(toWrite)
	}
	if int64(len(data)) > remaining {
		b.exceeded = true
	}
	return len(data), nil
}

func (b *cappedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *cappedBuffer) String() string { return b.buffer.String() }
