// Package trust defines the data-only supply-chain trust policy contract.
//
// A trust policy pins the identities, issuers, keys, builders, sources, and
// attestation predicate types that signature and provenance verification
// accept. The policy is pure data: it never contains private key material,
// and loading it performs no network access and executes nothing.
package trust

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the supported trust policy contract version.
const SchemaVersion = "1"

// Limits bounds work performed on an untrusted trust policy file.
type Limits struct {
	MaxFileBytes  int64
	MaxIdentities int
	MaxKeys       int
	MaxPredicates int
	MaxTextBytes  int
}

// DefaultLimits returns conservative trust policy limits.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:  1 << 20,
		MaxIdentities: 100,
		MaxKeys:       100,
		MaxPredicates: 50,
		MaxTextBytes:  2_000,
	}
}

// Policy is the versioned, data-only trust contract.
type Policy struct {
	SchemaVersion string `yaml:"schema_version" json:"schema_version"`
	// Identities lists accepted keyless (certificate) identities. Keyless
	// verification requires certificate identity AND OIDC issuer together;
	// an entry missing either field is rejected at load time.
	Identities []Identity `yaml:"identities" json:"identities,omitempty"`
	// Keys lists accepted public keys by reference. Only PEM-encoded public
	// key content or a local file path is accepted; never a private key.
	Keys []Key `yaml:"keys" json:"keys,omitempty"`
	// Provenance pins SLSA provenance expectations.
	Provenance *Provenance `yaml:"provenance" json:"provenance,omitempty"`
	// AllowedPredicateTypes lists accepted in-toto predicate type URIs.
	// Attestations with other predicate types fail closed.
	AllowedPredicateTypes []string `yaml:"allowed_predicate_types" json:"allowed_predicate_types,omitempty"`
}

// Identity is one accepted keyless certificate identity.
type Identity struct {
	// Subject is the exact certificate SAN, such as a workflow URI or email.
	Subject string `yaml:"subject" json:"subject"`
	// Issuer is the exact OIDC issuer URL that must have issued the
	// certificate. Required: identity without issuer is not a policy.
	Issuer string `yaml:"issuer" json:"issuer"`
}

// Key is one accepted public key reference.
type Key struct {
	// Name identifies the key in findings and evidence.
	Name string `yaml:"name" json:"name"`
	// PublicKeyPEM is inline PEM public key content.
	PublicKeyPEM string `yaml:"public_key_pem" json:"public_key_pem,omitempty"`
	// Path is a local file path to a PEM public key. Exactly one of
	// PublicKeyPEM or Path must be set.
	Path string `yaml:"path" json:"path,omitempty"`
}

// Provenance pins builder and source expectations for SLSA verification.
type Provenance struct {
	// BuilderID is the exact expected builder identifier.
	BuilderID string `yaml:"builder_id" json:"builder_id,omitempty"`
	// SourceRepository is the exact expected source repository URI.
	SourceRepository string `yaml:"source_repository" json:"source_repository,omitempty"`
}

// Load reads and validates one bounded trust policy file. Unknown fields,
// missing required pairs, and private key material fail closed.
func Load(path string, limits Limits) (Policy, error) {
	if limits.MaxFileBytes <= 0 || limits.MaxIdentities <= 0 || limits.MaxKeys <= 0 ||
		limits.MaxPredicates <= 0 || limits.MaxTextBytes <= 0 {
		return Policy{}, errors.New("all trust policy limits must be positive")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Policy{}, fmt.Errorf("inspect trust policy %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Policy{}, fmt.Errorf("trust policy %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return Policy{}, fmt.Errorf("open trust policy %q: %w", path, err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, limits.MaxFileBytes+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read trust policy %q: %w", path, err)
	}
	if int64(len(data)) > limits.MaxFileBytes {
		return Policy{}, fmt.Errorf("trust policy %q exceeds limit of %d bytes", path, limits.MaxFileBytes)
	}
	return Parse(data, limits)
}

// Parse validates one bounded trust policy document.
func Parse(data []byte, limits Limits) (Policy, error) {
	var policy Policy
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("decode trust policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("trust policy must contain exactly one document")
	}
	if err := validate(policy, limits); err != nil {
		return Policy{}, err
	}
	normalize(&policy)
	return policy, nil
}

func validate(policy Policy, limits Limits) error {
	if policy.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported trust policy schema version %q; supported: %s",
			policy.SchemaVersion, SchemaVersion)
	}
	if len(policy.Identities) == 0 && len(policy.Keys) == 0 {
		return errors.New("trust policy must define at least one identity or key")
	}
	if len(policy.Identities) > limits.MaxIdentities {
		return fmt.Errorf("trust policy exceeds identity limit of %d", limits.MaxIdentities)
	}
	if len(policy.Keys) > limits.MaxKeys {
		return fmt.Errorf("trust policy exceeds key limit of %d", limits.MaxKeys)
	}
	if len(policy.AllowedPredicateTypes) > limits.MaxPredicates {
		return fmt.Errorf("trust policy exceeds predicate type limit of %d", limits.MaxPredicates)
	}

	for index, identity := range policy.Identities {
		if err := requireText("identities.subject", identity.Subject, limits.MaxTextBytes); err != nil {
			return fmt.Errorf("identity %d: %w", index+1, err)
		}
		if err := requireText("identities.issuer", identity.Issuer, limits.MaxTextBytes); err != nil {
			return fmt.Errorf("identity %d: %w (keyless verification requires both certificate identity and OIDC issuer)", index+1, err)
		}
		if !strings.HasPrefix(identity.Issuer, "https://") {
			return fmt.Errorf("identity %d: issuer must be an https URL", index+1)
		}
	}

	for index, key := range policy.Keys {
		if err := requireText("keys.name", key.Name, limits.MaxTextBytes); err != nil {
			return fmt.Errorf("key %d: %w", index+1, err)
		}
		hasPEM := strings.TrimSpace(key.PublicKeyPEM) != ""
		hasPath := strings.TrimSpace(key.Path) != ""
		if hasPEM == hasPath {
			return fmt.Errorf("key %d (%s): exactly one of public_key_pem or path is required", index+1, key.Name)
		}
		if hasPEM {
			if strings.Contains(key.PublicKeyPEM, "PRIVATE KEY") {
				return fmt.Errorf("key %d (%s): trust policies must never contain private key material", index+1, key.Name)
			}
			if !strings.Contains(key.PublicKeyPEM, "BEGIN PUBLIC KEY") {
				return fmt.Errorf("key %d (%s): public_key_pem must be a PEM public key", index+1, key.Name)
			}
		}
	}

	for index, predicate := range policy.AllowedPredicateTypes {
		if err := requireText("allowed_predicate_types", predicate, limits.MaxTextBytes); err != nil {
			return fmt.Errorf("predicate type %d: %w", index+1, err)
		}
		if !strings.HasPrefix(predicate, "https://") {
			return fmt.Errorf("predicate type %d must be a https URI, got %q", index+1, predicate)
		}
	}

	if policy.Provenance != nil {
		if policy.Provenance.BuilderID == "" && policy.Provenance.SourceRepository == "" {
			return errors.New("provenance section must pin builder_id, source_repository, or both")
		}
	}
	return nil
}

func requireText(field, value string, maxBytes int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("field %q is required", field)
	}
	if len(value) > maxBytes {
		return fmt.Errorf("field %q exceeds limit of %d bytes", field, maxBytes)
	}
	if strings.ContainsAny(value, "\x00\r") {
		return fmt.Errorf("field %q contains control characters", field)
	}
	return nil
}

func normalize(policy *Policy) {
	sort.Slice(policy.Identities, func(i, j int) bool {
		if policy.Identities[i].Subject != policy.Identities[j].Subject {
			return policy.Identities[i].Subject < policy.Identities[j].Subject
		}
		return policy.Identities[i].Issuer < policy.Identities[j].Issuer
	})
	sort.Slice(policy.Keys, func(i, j int) bool {
		return policy.Keys[i].Name < policy.Keys[j].Name
	})
	sort.Strings(policy.AllowedPredicateTypes)
}

// AllowsPredicate reports whether a predicate type URI is accepted. An
// empty allowlist accepts nothing: predicates must be pinned explicitly.
func (p Policy) AllowsPredicate(predicateType string) bool {
	for _, allowed := range p.AllowedPredicateTypes {
		if allowed == predicateType {
			return true
		}
	}
	return false
}

// MatchesIdentity reports whether an exact subject and issuer pair is
// accepted. Both must match the same policy entry.
func (p Policy) MatchesIdentity(subject, issuer string) bool {
	for _, identity := range p.Identities {
		if identity.Subject == subject && identity.Issuer == issuer {
			return true
		}
	}
	return false
}
