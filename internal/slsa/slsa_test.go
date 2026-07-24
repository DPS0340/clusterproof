package slsa

import (
	"fmt"
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/image"
	"github.com/DPS0340/clusterproof/internal/trust"
)

const goodDigestHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func pinnedReference() image.Reference {
	return image.Reference{
		Raw:        "ghcr.io/example/app@sha256:" + goodDigestHex,
		Registry:   "ghcr.io",
		Repository: "example/app",
		Digest:     "sha256:" + goodDigestHex,
	}
}

func pinnedPolicy() trust.Policy {
	return trust.Policy{
		SchemaVersion: "1",
		Identities: []trust.Identity{{
			Subject: "s", Issuer: "https://issuer.example.com",
		}},
		Provenance: &trust.Provenance{
			BuilderID:        "https://github.com/actions/runner",
			SourceRepository: "git+https://github.com/example/app",
		},
		AllowedPredicateTypes: []string{SupportedPredicateType},
	}
}

func validStatement(digestHex string) string {
	return fmt.Sprintf(`{
	  "_type": "https://in-toto.io/Statement/v1",
	  "subject": [{"name": "ghcr.io/example/app", "digest": {"sha256": "%s"}}],
	  "predicateType": "https://slsa.dev/provenance/v1",
	  "predicate": {
	    "buildDefinition": {
	      "resolvedDependencies": [
	        {"uri": "git+https://github.com/example/app@refs/tags/v1.0.0", "digest": {"gitCommit": "abc"}}
	      ]
	    },
	    "runDetails": {"builder": {"id": "https://github.com/actions/runner"}}
	  }
	}`, digestHex)
}

func verify(t *testing.T, statement string, policy trust.Policy) Verification {
	t.Helper()
	verification, err := Verify(strings.NewReader(statement), pinnedReference(), policy, DefaultLimits())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return verification
}

func TestVerifyAcceptsValidProvenance(t *testing.T) {
	verification := verify(t, validStatement(goodDigestHex), pinnedPolicy())
	if verification.Status != StatusVerified {
		t.Fatalf("status = %s (%s), want verified", verification.Status, verification.Cause)
	}
	if verification.BuilderID != "https://github.com/actions/runner" {
		t.Fatalf("builder = %q", verification.BuilderID)
	}
}

func TestVerifyRejectsForgedSubjectDigest(t *testing.T) {
	forged := strings.Repeat("b", 64)
	verification := verify(t, validStatement(forged), pinnedPolicy())
	if verification.Status != StatusPolicyMismatch {
		t.Fatalf("status = %s, want policy_mismatch for forged subject", verification.Status)
	}
	if !strings.Contains(verification.Cause, "different artifact") {
		t.Fatalf("cause = %q", verification.Cause)
	}
}

func TestVerifyRejectsWrongBuilder(t *testing.T) {
	statement := strings.Replace(validStatement(goodDigestHex),
		"https://github.com/actions/runner", "https://evil.example.com/builder", 1)
	verification := verify(t, statement, pinnedPolicy())
	if verification.Status != StatusPolicyMismatch || !strings.Contains(verification.Cause, "builder") {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyRejectsWrongSource(t *testing.T) {
	statement := strings.Replace(validStatement(goodDigestHex),
		"git+https://github.com/example/app@refs/tags/v1.0.0",
		"git+https://github.com/attacker/fork@refs/heads/main", 1)
	verification := verify(t, statement, pinnedPolicy())
	if verification.Status != StatusPolicyMismatch || !strings.Contains(verification.Cause, "source repository") {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyDistinguishesInvalidStatements(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		cause     string
	}{
		{name: "not JSON", statement: "{unclosed", cause: "not valid JSON"},
		{
			name:      "wrong statement type",
			statement: strings.Replace(validStatement(goodDigestHex), "https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1", 1),
			cause:     "statement type",
		},
		{
			name:      "unsupported predicate version",
			statement: strings.Replace(validStatement(goodDigestHex), "https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v0.2", 1),
			cause:     "predicate type",
		},
		{
			name:      "no subject",
			statement: strings.Replace(validStatement(goodDigestHex), `[{"name": "ghcr.io/example/app", "digest": {"sha256": "`+goodDigestHex+`"}}]`, "[]", 1),
			cause:     "no subject",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verification := verify(t, test.statement, pinnedPolicy())
			if verification.Status != StatusInvalid {
				t.Fatalf("status = %s, want invalid", verification.Status)
			}
			if !strings.Contains(verification.Cause, test.cause) {
				t.Fatalf("cause = %q, want mention of %q", verification.Cause, test.cause)
			}
		})
	}
}

func TestVerifyRequiresPredicateAllowlist(t *testing.T) {
	policy := pinnedPolicy()
	policy.AllowedPredicateTypes = nil // empty allowlist accepts nothing
	verification := verify(t, validStatement(goodDigestHex), policy)
	if verification.Status != StatusPolicyMismatch || !strings.Contains(verification.Cause, "allowlist") {
		t.Fatalf("verification = %#v", verification)
	}
}

func TestVerifyRefusesUnpinnedReference(t *testing.T) {
	floating := image.Reference{Raw: "ghcr.io/example/app:latest", Tag: "latest"}
	_, err := Verify(strings.NewReader(validStatement(goodDigestHex)), floating, pinnedPolicy(), DefaultLimits())
	if err == nil || !strings.Contains(err.Error(), "digest pinned") {
		t.Fatalf("unpinned reference accepted: %v", err)
	}
}

func TestVerifyOversizedStatementFails(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxStatementBytes = 64
	_, err := Verify(strings.NewReader(validStatement(goodDigestHex)), pinnedReference(), pinnedPolicy(), limits)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized statement accepted: %v", err)
	}
}

func TestVerifySubjectCountLimit(t *testing.T) {
	var subjects []string
	for index := 0; index < 3; index++ {
		subjects = append(subjects, fmt.Sprintf(`{"name": "s%d", "digest": {"sha256": "%s"}}`, index, goodDigestHex))
	}
	statement := strings.Replace(validStatement(goodDigestHex),
		`[{"name": "ghcr.io/example/app", "digest": {"sha256": "`+goodDigestHex+`"}}]`,
		"["+strings.Join(subjects, ",")+"]", 1)
	limits := DefaultLimits()
	limits.MaxSubjects = 2
	_, err := Verify(strings.NewReader(statement), pinnedReference(), pinnedPolicy(), limits)
	if err == nil || !strings.Contains(err.Error(), "subject count") {
		t.Fatalf("subject count limit not enforced: %v", err)
	}
}
