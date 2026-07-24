// Package slsa verifies SLSA v1 provenance statements against the exact
// resolved artifact and the explicit trust policy.
package slsa

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/DPS0340/clusterproof/internal/image"
	"github.com/DPS0340/clusterproof/internal/trust"
)

// SupportedPredicateType is the SLSA v1 provenance predicate this verifier
// understands. Other predicate versions fail as not verified.
const SupportedPredicateType = "https://slsa.dev/provenance/v1"

// Limits bounds work performed on an untrusted provenance statement.
type Limits struct {
	MaxStatementBytes int64
	MaxSubjects       int
}

// DefaultLimits returns conservative provenance limits.
func DefaultLimits() Limits {
	return Limits{
		MaxStatementBytes: 5 << 20,
		MaxSubjects:       500,
	}
}

// Verification records one provenance check outcome for evidence.
type Verification struct {
	Image  string `json:"image"`
	Digest string `json:"digest"`
	// Status is verified, missing, invalid, or policy_mismatch. Only
	// verified means the statement bound the exact digest and satisfied
	// every pinned expectation.
	Status        string    `json:"status"`
	PredicateType string    `json:"predicate_type,omitempty"`
	BuilderID     string    `json:"builder_id,omitempty"`
	SourceURI     string    `json:"source_uri,omitempty"`
	Cause         string    `json:"cause,omitempty"`
	VerifiedAt    time.Time `json:"verified_at"`
}

// Verification statuses.
const (
	StatusVerified       = "verified"
	StatusMissing        = "missing"
	StatusInvalid        = "invalid"
	StatusPolicyMismatch = "policy_mismatch"
)

// statement is the bounded in-toto v1 statement shape.
type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     predicate `json:"predicate"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type predicate struct {
	BuildDefinition buildDefinition `json:"buildDefinition"`
	RunDetails      runDetails      `json:"runDetails"`
}

type buildDefinition struct {
	ExternalParameters   map[string]json.RawMessage `json:"externalParameters"`
	ResolvedDependencies []resourceDescriptor       `json:"resolvedDependencies"`
}

type resourceDescriptor struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

type runDetails struct {
	Builder builder `json:"builder"`
}

type builder struct {
	ID string `json:"id"`
}

// VerifyFile loads one bounded provenance statement file and verifies it
// against the reference digest and trust policy.
func VerifyFile(path string, reference image.Reference, policy trust.Policy, limits Limits) (Verification, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return missing(reference, fmt.Sprintf("provenance file: %v", err)), nil
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Verification{}, fmt.Errorf("provenance %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return Verification{}, fmt.Errorf("open provenance %q: %w", path, err)
	}
	defer file.Close()
	return Verify(file, reference, policy, limits)
}

// Verify checks one provenance statement stream.
func Verify(reader io.Reader, reference image.Reference, policy trust.Policy, limits Limits) (Verification, error) {
	if limits.MaxStatementBytes <= 0 || limits.MaxSubjects <= 0 {
		return Verification{}, errors.New("all provenance limits must be positive")
	}
	if !reference.Pinned() {
		return Verification{}, fmt.Errorf(
			"image %q is not digest pinned; provenance verification requires the exact artifact digest", reference.Raw)
	}
	if err := image.ValidateDigest(reference.Digest); err != nil {
		return Verification{}, err
	}

	data, err := io.ReadAll(io.LimitReader(reader, limits.MaxStatementBytes+1))
	if err != nil {
		return Verification{}, fmt.Errorf("read provenance statement: %w", err)
	}
	if int64(len(data)) > limits.MaxStatementBytes {
		return Verification{}, fmt.Errorf("provenance statement exceeds limit of %d bytes", limits.MaxStatementBytes)
	}

	var parsed statement
	if err := json.Unmarshal(data, &parsed); err != nil {
		return invalid(reference, "statement is not valid JSON"), nil
	}
	if parsed.Type != "https://in-toto.io/Statement/v1" {
		return invalid(reference, fmt.Sprintf("unsupported statement type %q", clean(parsed.Type))), nil
	}
	if parsed.PredicateType != SupportedPredicateType {
		return invalid(reference, fmt.Sprintf(
			"unsupported predicate type %q; this verifier supports %s",
			clean(parsed.PredicateType), SupportedPredicateType)), nil
	}
	if !policy.AllowsPredicate(parsed.PredicateType) {
		return mismatch(reference, parsed, fmt.Sprintf(
			"predicate type %s is not in the trust policy allowlist", parsed.PredicateType)), nil
	}
	if len(parsed.Subject) == 0 {
		return invalid(reference, "statement has no subject"), nil
	}
	if len(parsed.Subject) > limits.MaxSubjects {
		return Verification{}, fmt.Errorf("provenance subject count exceeds limit of %d", limits.MaxSubjects)
	}

	// The subject digest must match the exact resolved image digest.
	expected := strings.TrimPrefix(reference.Digest, "sha256:")
	subjectMatched := false
	for _, candidate := range parsed.Subject {
		if candidate.Digest["sha256"] == expected {
			subjectMatched = true
			break
		}
	}
	if !subjectMatched {
		return mismatch(reference, parsed,
			"no statement subject matches the resolved image digest; the attestation describes a different artifact"), nil
	}

	// Builder and source are checked only against explicit policy pins.
	if policy.Provenance != nil {
		builderID := parsed.Predicate.RunDetails.Builder.ID
		if policy.Provenance.BuilderID != "" && builderID != policy.Provenance.BuilderID {
			return mismatch(reference, parsed, fmt.Sprintf(
				"builder %q does not match pinned builder %q",
				clean(builderID), policy.Provenance.BuilderID)), nil
		}
		if policy.Provenance.SourceRepository != "" {
			if !sourceMatches(parsed, policy.Provenance.SourceRepository) {
				return mismatch(reference, parsed, fmt.Sprintf(
					"no resolved dependency matches pinned source repository %q",
					policy.Provenance.SourceRepository)), nil
			}
		}
	}

	return Verification{
		Image:         reference.Raw,
		Digest:        reference.Digest,
		Status:        StatusVerified,
		PredicateType: parsed.PredicateType,
		BuilderID:     clean(parsed.Predicate.RunDetails.Builder.ID),
		SourceURI:     firstSourceURI(parsed),
		VerifiedAt:    time.Now().UTC(),
	}, nil
}

func sourceMatches(parsed statement, pinned string) bool {
	for _, dependency := range parsed.Predicate.BuildDefinition.ResolvedDependencies {
		if dependency.URI == pinned || strings.HasPrefix(dependency.URI, pinned+"@") {
			return true
		}
	}
	return false
}

func firstSourceURI(parsed statement) string {
	for _, dependency := range parsed.Predicate.BuildDefinition.ResolvedDependencies {
		if dependency.URI != "" {
			return clean(dependency.URI)
		}
	}
	return ""
}

func missing(reference image.Reference, cause string) Verification {
	return Verification{
		Image: reference.Raw, Digest: reference.Digest,
		Status: StatusMissing, Cause: clean(cause), VerifiedAt: time.Now().UTC(),
	}
}

func invalid(reference image.Reference, cause string) Verification {
	return Verification{
		Image: reference.Raw, Digest: reference.Digest,
		Status: StatusInvalid, Cause: clean(cause), VerifiedAt: time.Now().UTC(),
	}
}

func mismatch(reference image.Reference, parsed statement, cause string) Verification {
	return Verification{
		Image: reference.Raw, Digest: reference.Digest,
		Status:        StatusPolicyMismatch,
		PredicateType: clean(parsed.PredicateType),
		BuilderID:     clean(parsed.Predicate.RunDetails.Builder.ID),
		Cause:         clean(cause),
		VerifiedAt:    time.Now().UTC(),
	}
}

func clean(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, current := range value {
		if builder.Len() >= 500 {
			break
		}
		if current < 0x20 || current == 0x7f {
			builder.WriteRune(' ')
			continue
		}
		builder.WriteRune(current)
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}
