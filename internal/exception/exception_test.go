package exception

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DPS0340/clusterproof/internal/model"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write exception file: %v", err)
	}
	return path
}

const validFile = `schema_version: "1"
exceptions:
  - rule: CP-K8S-010
    target: payments/Deployment/api
    owner: team-payments
    reason: Workload calls the Kubernetes API; reviewed 2026-07.
    expires: "2026-12-31"
`

func TestLoadAcceptsValidFile(t *testing.T) {
	entries, err := Load(writeFile(t, validFile), DefaultLimits())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(entries) != 1 || entries[0].RuleID != "CP-K8S-010" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestLoadRejectsInvalidFiles(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{name: "missing schema version", content: `exceptions: [{rule: R, target: T, owner: O, reason: X, expires: "2026-12-31"}]`},
		{name: "wrong schema version", content: `{schema_version: "2", exceptions: [{rule: R, target: T, owner: O, reason: X, expires: "2026-12-31"}]}`},
		{name: "no exceptions", content: `{schema_version: "1", exceptions: []}`},
		{name: "unknown field", content: `{schema_version: "1", approve_all: true, exceptions: [{rule: R, target: T, owner: O, reason: X, expires: "2026-12-31"}]}`},
		{name: "missing owner", content: `{schema_version: "1", exceptions: [{rule: R, target: T, reason: X, expires: "2026-12-31"}]}`},
		{name: "missing reason", content: `{schema_version: "1", exceptions: [{rule: R, target: T, owner: O, expires: "2026-12-31"}]}`},
		{name: "missing expiry", content: `{schema_version: "1", exceptions: [{rule: R, target: T, owner: O, reason: X}]}`},
		{name: "bad expiry format", content: `{schema_version: "1", exceptions: [{rule: R, target: T, owner: O, reason: X, expires: "soon"}]}`},
		{name: "duplicate entry", content: "schema_version: \"1\"\nexceptions:\n  - {rule: R, target: T, owner: O, reason: X, expires: \"2026-12-31\"}\n  - {rule: R, target: T, owner: P, reason: Y, expires: \"2027-01-31\"}"},
		{name: "malformed YAML", content: `{unclosed`},
		{name: "two documents", content: validFile + "---\nschema_version: \"1\"\nexceptions:\n  - {rule: R, target: T, owner: O, reason: X, expires: \"2026-12-31\"}"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(writeFile(t, test.content), DefaultLimits()); err == nil {
				t.Fatal("Load succeeded for invalid file")
			}
		})
	}
}

func TestLoadRejectsOversizedFileAndFields(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFileBytes = 64
	if _, err := Load(writeFile(t, validFile), limits); err == nil {
		t.Fatal("oversized file accepted")
	}

	long := strings.Repeat("x", DefaultLimits().MaxTextBytes+1)
	content := "schema_version: \"1\"\nexceptions:\n  - {rule: R, target: T, owner: O, reason: " + long + ", expires: \"2026-12-31\"}"
	if _, err := Load(writeFile(t, content), DefaultLimits()); err == nil {
		t.Fatal("oversized reason field accepted")
	}
}

func TestLoadRejectsEntryCountAboveLimit(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("schema_version: \"1\"\nexceptions:\n")
	for index := 0; index < 3; index++ {
		builder.WriteString("  - {rule: R" + strings.Repeat("x", index) + ", target: T, owner: O, reason: X, expires: \"2026-12-31\"}\n")
	}
	limits := DefaultLimits()
	limits.MaxEntries = 2
	if _, err := Load(writeFile(t, builder.String()), limits); err == nil {
		t.Fatal("entry count above limit accepted")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	real := writeFile(t, validFile)
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := Load(link, DefaultLimits()); err == nil {
		t.Fatal("symlinked exception file accepted")
	}
}

func testFinding(rule, target string) model.Finding {
	return model.Finding{
		ID:       rule,
		Severity: model.SeverityMedium,
		Target:   target,
		Location: model.Location{Path: "deploy/api.yaml", Container: "api"},
	}
}

func TestApplySuppressesExactUnexpiredMatch(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{
		testFinding("CP-K8S-010", "payments/Deployment/api"),
		testFinding("CP-K8S-010", "payments/Deployment/worker"),
		testFinding("CP-K8S-009", "payments/Deployment/api"),
	}
	exceptions := []Exception{{
		RuleID:  "CP-K8S-010",
		Target:  "payments/Deployment/api",
		Owner:   "team-payments",
		Reason:  "reviewed",
		Expires: "2026-12-31",
	}}

	kept, suppressed := Apply(findings, exceptions, now)
	if len(kept) != 2 {
		t.Fatalf("kept = %#v, want 2 findings", kept)
	}
	if len(suppressed) != 1 || suppressed[0].RuleID != "CP-K8S-010" ||
		suppressed[0].Target != "payments/Deployment/api" ||
		suppressed[0].Owner != "team-payments" || suppressed[0].Expires != "2026-12-31" {
		t.Fatalf("suppressed = %#v", suppressed)
	}
	for _, finding := range kept {
		if finding.ID == "CP-K8S-010" && finding.Target == "payments/Deployment/api" {
			t.Fatal("suppressed finding still present in kept set")
		}
	}
}

func TestApplyExpiredExceptionDoesNotSuppress(t *testing.T) {
	findings := []model.Finding{testFinding("CP-K8S-010", "payments/Deployment/api")}
	exceptions := []Exception{{
		RuleID: "CP-K8S-010", Target: "payments/Deployment/api",
		Owner: "o", Reason: "r", Expires: "2026-07-23",
	}}

	now := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	kept, suppressed := Apply(findings, exceptions, now)
	if len(kept) != 1 || len(suppressed) != 0 {
		t.Fatalf("expired exception suppressed a finding: kept=%#v suppressed=%#v", kept, suppressed)
	}
}

func TestApplyExceptionValidThroughItsExpiryDate(t *testing.T) {
	findings := []model.Finding{testFinding("CP-K8S-010", "payments/Deployment/api")}
	exceptions := []Exception{{
		RuleID: "CP-K8S-010", Target: "payments/Deployment/api",
		Owner: "o", Reason: "r", Expires: "2026-07-24",
	}}

	now := time.Date(2026, 7, 24, 23, 59, 0, 0, time.UTC)
	kept, suppressed := Apply(findings, exceptions, now)
	if len(kept) != 0 || len(suppressed) != 1 {
		t.Fatalf("exception on its expiry date did not suppress: kept=%#v", kept)
	}
}

func TestApplyRequiresExactMatch(t *testing.T) {
	now := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	findings := []model.Finding{testFinding("CP-K8S-010", "payments/Deployment/api")}
	tests := []struct {
		name  string
		entry Exception
	}{
		{name: "different rule", entry: Exception{RuleID: "CP-K8S-009", Target: "payments/Deployment/api", Owner: "o", Reason: "r", Expires: "2026-12-31"}},
		{name: "different target", entry: Exception{RuleID: "CP-K8S-010", Target: "payments/Deployment/worker", Owner: "o", Reason: "r", Expires: "2026-12-31"}},
		{name: "wildcard target is literal", entry: Exception{RuleID: "CP-K8S-010", Target: "*", Owner: "o", Reason: "r", Expires: "2026-12-31"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kept, suppressed := Apply(findings, []Exception{test.entry}, now)
			if len(kept) != 1 || len(suppressed) != 0 {
				t.Fatalf("non-matching exception suppressed a finding")
			}
		})
	}
}
