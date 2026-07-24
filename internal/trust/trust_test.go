package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPolicy = `schema_version: "1"
identities:
  - subject: https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.0.0
    issuer: https://token.actions.githubusercontent.com
keys:
  - name: release-key
    public_key_pem: |
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
      -----END PUBLIC KEY-----
provenance:
  builder_id: https://github.com/actions/runner
  source_repository: https://github.com/example/app
allowed_predicate_types:
  - https://slsa.dev/provenance/v1
`

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trust-policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestLoadAcceptsValidPolicy(t *testing.T) {
	policy, err := Load(writePolicy(t, validPolicy), DefaultLimits())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(policy.Identities) != 1 || len(policy.Keys) != 1 {
		t.Fatalf("policy = %#v", policy)
	}
	if !policy.AllowsPredicate("https://slsa.dev/provenance/v1") {
		t.Fatal("pinned predicate type not allowed")
	}
	if policy.AllowsPredicate("https://example.com/other") {
		t.Fatal("unpinned predicate type allowed")
	}
	if !policy.MatchesIdentity(
		"https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.0.0",
		"https://token.actions.githubusercontent.com") {
		t.Fatal("pinned identity not matched")
	}
}

func TestLoadRejectsInvalidPolicies(t *testing.T) {
	tests := []struct {
		name    string
		content string
		message string
	}{
		{
			name:    "missing schema version",
			content: "identities:\n  - {subject: s, issuer: https://issuer.example.com}\n",
			message: "schema version",
		},
		{
			name:    "empty policy",
			content: "schema_version: \"1\"\n",
			message: "at least one identity or key",
		},
		{
			name:    "identity without issuer",
			content: "schema_version: \"1\"\nidentities:\n  - {subject: s}\n",
			message: "issuer",
		},
		{
			name:    "identity without subject",
			content: "schema_version: \"1\"\nidentities:\n  - {issuer: https://issuer.example.com}\n",
			message: "subject",
		},
		{
			name:    "non-https issuer",
			content: "schema_version: \"1\"\nidentities:\n  - {subject: s, issuer: http://issuer.example.com}\n",
			message: "https",
		},
		{
			name:    "unknown field",
			content: validPolicy + "auto_approve: true\n",
			message: "field",
		},
		{
			name: "private key material",
			content: "schema_version: \"1\"\nkeys:\n  - name: bad\n    public_key_pem: |\n" +
				"      -----BEGIN PRIVATE KEY-----\n      AAAA\n      -----END PRIVATE KEY-----\n",
			message: "private key",
		},
		{
			name:    "key with neither pem nor path",
			content: "schema_version: \"1\"\nkeys:\n  - {name: empty}\n",
			message: "exactly one",
		},
		{
			name: "key with both pem and path",
			content: "schema_version: \"1\"\nkeys:\n  - name: both\n    path: /tmp/key.pem\n    public_key_pem: |\n" +
				"      -----BEGIN PUBLIC KEY-----\n      AAAA\n      -----END PUBLIC KEY-----\n",
			message: "exactly one",
		},
		{
			name:    "non-https predicate",
			content: "schema_version: \"1\"\nidentities:\n  - {subject: s, issuer: https://i.example.com}\nallowed_predicate_types: [ftp://bad]\n",
			message: "https",
		},
		{
			name:    "empty provenance section",
			content: "schema_version: \"1\"\nidentities:\n  - {subject: s, issuer: https://i.example.com}\nprovenance: {}\n",
			message: "provenance",
		},
		{
			name:    "two documents",
			content: validPolicy + "---\nschema_version: \"1\"\n",
			message: "one document",
		},
		{
			name:    "malformed YAML",
			content: "{unclosed",
			message: "decode",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load(writePolicy(t, test.content), DefaultLimits())
			if err == nil {
				t.Fatal("Load succeeded for invalid policy")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.message)) {
				t.Fatalf("error %q does not mention %q", err, test.message)
			}
		})
	}
}

func TestLoadRejectsOversizedInput(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFileBytes = 32
	if _, err := Load(writePolicy(t, validPolicy), limits); err == nil {
		t.Fatal("oversized policy accepted")
	}

	long := strings.Repeat("x", DefaultLimits().MaxTextBytes+1)
	content := "schema_version: \"1\"\nidentities:\n  - {subject: " + long + ", issuer: https://i.example.com}\n"
	if _, err := Load(writePolicy(t, content), DefaultLimits()); err == nil {
		t.Fatal("oversized subject accepted")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	real := writePolicy(t, validPolicy)
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := Load(link, DefaultLimits()); err == nil {
		t.Fatal("symlinked policy accepted")
	}
}

func TestPolicyOrderIsDeterministic(t *testing.T) {
	shuffled := `schema_version: "1"
identities:
  - {subject: zeta, issuer: https://issuer.example.com}
  - {subject: alpha, issuer: https://issuer.example.com}
allowed_predicate_types:
  - https://z.example.com/predicate
  - https://a.example.com/predicate
`
	policy, err := Load(writePolicy(t, shuffled), DefaultLimits())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if policy.Identities[0].Subject != "alpha" {
		t.Fatalf("identities not sorted: %#v", policy.Identities)
	}
	if policy.AllowedPredicateTypes[0] != "https://a.example.com/predicate" {
		t.Fatalf("predicates not sorted: %#v", policy.AllowedPredicateTypes)
	}
}
