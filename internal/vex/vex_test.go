package vex

import (
	"strings"
	"testing"
	"time"

	"github.com/DPS0340/clusterproof/internal/model"
)

const validVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "Example Security Team",
  "timestamp": "2026-07-01T00:00:00Z",
  "statements": [
    {
      "vulnerability": {"name": "CVE-2026-1234"},
      "products": [{"identifiers": {"purl": "pkg:npm/left-pad@1.3.0"}}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    },
    {
      "vulnerability": {"name": "CVE-2026-5678"},
      "products": [{"identifiers": {"purl": "pkg:generic/zlib@1.3.1"}}],
      "status": "affected"
    }
  ]
}`

func parse(t *testing.T, input string) Document {
	t.Helper()
	document, err := Parse(strings.NewReader(input), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return document
}

func TestParseNormalizesStatements(t *testing.T) {
	document := parse(t, validVEX)
	if len(document.Statements) != 2 {
		t.Fatalf("statements = %#v", document.Statements)
	}
	first := document.Statements[0]
	if first.Vulnerability != "CVE-2026-1234" || first.Status != StatusNotAffected {
		t.Fatalf("statement = %#v", first)
	}
	if first.Timestamp.IsZero() {
		t.Fatal("statement timestamp missing")
	}
}

func TestSuppressionRequiresExactIdentity(t *testing.T) {
	document := parse(t, validVEX)
	now := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	maxAge := 365 * 24 * time.Hour

	if _, ok := document.SuppressionFor("CVE-2026-1234", "pkg:npm/left-pad@1.3.0", now, maxAge); !ok {
		t.Fatal("exact not_affected match did not suppress")
	}
	if _, ok := document.SuppressionFor("CVE-2026-1234", "pkg:npm/left-pad@1.2.0", now, maxAge); ok {
		t.Fatal("different product version suppressed")
	}
	if _, ok := document.SuppressionFor("CVE-2026-9999", "pkg:npm/left-pad@1.3.0", now, maxAge); ok {
		t.Fatal("different vulnerability suppressed")
	}
	if _, ok := document.SuppressionFor("CVE-2026-5678", "pkg:generic/zlib@1.3.1", now, maxAge); ok {
		t.Fatal("affected status suppressed a finding")
	}
}

func TestSuppressionRejectsStaleStatements(t *testing.T) {
	document := parse(t, validVEX)
	now := time.Date(2028, 7, 24, 0, 0, 0, 0, time.UTC) // two years later
	if _, ok := document.SuppressionFor("CVE-2026-1234", "pkg:npm/left-pad@1.3.0", now, 365*24*time.Hour); ok {
		t.Fatal("stale VEX statement suppressed a finding")
	}
}

func TestParseRejectsAmbiguousStatements(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		message string
	}{
		{
			name: "not OpenVEX",
			mutate: func(input string) string {
				return strings.Replace(input, "https://openvex.dev/ns/v0.2.0", "https://example.com/vex", 1)
			},
			message: "OpenVEX",
		},
		{
			name:    "unknown status",
			mutate:  func(input string) string { return strings.Replace(input, `"affected"`, `"probably_fine"`, 1) },
			message: "status",
		},
		{
			name: "not_affected without justification",
			mutate: func(input string) string {
				return strings.Replace(input, `"justification": "vulnerable_code_not_in_execute_path"`, `"justification": ""`, 1)
			},
			message: "justification",
		},
		{
			name:    "missing vulnerability name",
			mutate:  func(input string) string { return strings.Replace(input, "CVE-2026-1234", "", 1) },
			message: "vulnerability",
		},
		{
			name:    "missing product purl",
			mutate:  func(input string) string { return strings.Replace(input, "pkg:npm/left-pad@1.3.0", "", 1) },
			message: "purl",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(test.mutate(validVEX)), DefaultLimits())
			if err == nil {
				t.Fatal("Parse succeeded for ambiguous statement")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.message)) {
				t.Fatalf("error %q does not mention %q", err, test.message)
			}
		})
	}
}

func TestParseLimitsFailClosed(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxBytes = 16
	if _, err := Parse(strings.NewReader(validVEX), limits); err == nil {
		t.Fatal("oversized VEX accepted")
	}
	limits = DefaultLimits()
	limits.MaxStatements = 1
	if _, err := Parse(strings.NewReader(validVEX), limits); err == nil {
		t.Fatal("statement count above limit accepted")
	}
}

func vulnFinding(vulnerability, purl string) model.Finding {
	external := map[string]string{}
	if vulnerability != "" {
		external["vulnerability"] = vulnerability
	}
	if purl != "" {
		external["purl"] = purl
	}
	return model.Finding{
		ID:           "CP-VULN-001",
		Severity:     model.SeverityHigh,
		Target:       "image/layer",
		ExternalRefs: external,
	}
}

func TestApplyToFindingsSuppressesExactMatchOnly(t *testing.T) {
	document := parse(t, validVEX)
	now := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	findings := []model.Finding{
		vulnFinding("CVE-2026-1234", "pkg:npm/left-pad@1.3.0"), // suppressed: not_affected
		vulnFinding("CVE-2026-5678", "pkg:generic/zlib@1.3.1"), // kept: affected
		vulnFinding("CVE-2026-1234", "pkg:npm/left-pad@1.2.0"), // kept: wrong version
		vulnFinding("CVE-2026-1234", ""),                       // kept: no purl identity
		vulnFinding("", "pkg:npm/left-pad@1.3.0"),              // kept: no vulnerability ID
	}

	kept, suppressed := document.ApplyToFindings(findings, now, DefaultMaxAge)
	if len(kept) != 4 || len(suppressed) != 1 {
		t.Fatalf("kept=%d suppressed=%d, want 4/1", len(kept), len(suppressed))
	}
	entry := suppressed[0]
	if entry.RuleID != "CP-VULN-001" || !strings.Contains(entry.Reason, "not_affected") ||
		!strings.Contains(entry.Reason, "vulnerable_code_not_in_execute_path") {
		t.Fatalf("suppressed identity incomplete: %#v", entry)
	}
	if entry.Owner != "Example Security Team" {
		t.Fatalf("owner = %q", entry.Owner)
	}
}

func TestApplyToFindingsStaleStatementsKeepFindings(t *testing.T) {
	document := parse(t, validVEX)
	later := time.Date(2028, 7, 24, 0, 0, 0, 0, time.UTC)
	findings := []model.Finding{vulnFinding("CVE-2026-1234", "pkg:npm/left-pad@1.3.0")}

	kept, suppressed := document.ApplyToFindings(findings, later, DefaultMaxAge)
	if len(kept) != 1 || len(suppressed) != 0 {
		t.Fatalf("stale VEX suppressed a finding: kept=%d suppressed=%d", len(kept), len(suppressed))
	}
}
