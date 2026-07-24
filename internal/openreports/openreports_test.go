package openreports

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validReport = `{
  "apiVersion": "openreports.io/v1alpha1",
  "kind": "Report",
  "scope": {"kind": "Pod", "namespace": "payments", "name": "api"},
  "results": [
    {"policy": "require-owner", "rule": "owner-label", "result": "fail", "severity": "medium", "source": "kyverno", "message": "SENSITIVE"},
    {"policy": "require-owner", "rule": "team-label", "result": "pass", "source": "kyverno"},
    {"policy": "psa", "rule": "warn-latest", "result": "warn", "source": "kyverno"}
  ]
}`

func parse(t *testing.T, input string) Result {
	t.Helper()
	result, err := Parse(strings.NewReader(input), "openreports.json", DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return result
}

func TestParseNormalizesFailAndWarnOmittingPass(t *testing.T) {
	result := parse(t, validReport)
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %#v, want fail and warn only", result.Findings)
	}
	fail := result.Findings[0]
	if fail.Severity != "medium" || fail.Target != "payments/Pod/api" {
		t.Fatalf("fail finding = %#v", fail)
	}
	if !strings.HasPrefix(fail.ID, "CP-OPENREPORT-") {
		t.Fatalf("finding ID = %q", fail.ID)
	}
	if fail.Source != "openreports:kyverno" {
		t.Fatalf("source = %q", fail.Source)
	}
	if fail.ExternalRefs["adapter_version"] != AdapterVersion {
		t.Fatalf("adapter version missing: %#v", fail.ExternalRefs)
	}
	if result.Input.SHA256 == "" || result.Input.Bytes == 0 {
		t.Fatalf("input hash missing: %#v", result.Input)
	}
}

func TestParseNeverEmitsProducerMessages(t *testing.T) {
	result := parse(t, validReport)
	for _, finding := range result.Findings {
		for _, text := range []string{finding.Title, finding.Description, finding.Evidence.Observed} {
			if strings.Contains(text, "SENSITIVE") {
				t.Fatalf("producer message leaked: %q", text)
			}
		}
	}
}

func TestParseSupportsClusterReportAndLists(t *testing.T) {
	clusterReport := `{
	  "apiVersion": "v1",
	  "kind": "List",
	  "items": [{
	    "apiVersion": "openreports.io/v1alpha1",
	    "kind": "ClusterReport",
	    "scope": {"kind": "Namespace", "name": "payments"},
	    "results": [{"policy": "ns-policy", "result": "error"}]
	  }]
	}`
	result := parse(t, clusterReport)
	if len(result.Findings) != 1 || result.Findings[0].Target != "Namespace/payments" {
		t.Fatalf("findings = %#v", result.Findings)
	}
}

func TestParseRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "wrong apiVersion", input: `{"apiVersion": "openreports.io/v1", "kind": "Report"}`},
		{name: "wrong kind", input: `{"apiVersion": "openreports.io/v1alpha1", "kind": "PolicyReport"}`},
		{name: "unknown outcome", input: `{"apiVersion": "openreports.io/v1alpha1", "kind": "Report", "results": [{"policy": "p", "result": "maybe"}]}`},
		{name: "invalid severity", input: `{"apiVersion": "openreports.io/v1alpha1", "kind": "Report", "results": [{"policy": "p", "result": "fail", "severity": "urgent"}]}`},
		{name: "malformed JSON", input: `{unclosed`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(test.input), "test.json", DefaultLimits()); err == nil {
				t.Fatal("Parse succeeded for invalid input")
			}
		})
	}
}

func TestParseLimitsFailClosed(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxBytes = 16
	if _, err := Parse(strings.NewReader(validReport), "test.json", limits); err == nil {
		t.Fatal("oversized input accepted")
	}

	limits = DefaultLimits()
	limits.MaxResults = 1
	if _, err := Parse(strings.NewReader(validReport), "test.json", limits); err == nil {
		t.Fatal("result count above limit accepted")
	}

	limits = DefaultLimits()
	limits.MaxReports = 0
	if _, err := Parse(strings.NewReader(validReport), "test.json", limits); err == nil {
		t.Fatal("non-positive limit accepted")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	real := filepath.Join(directory, "report.json")
	if err := os.WriteFile(real, []byte(validReport), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := Load(link, DefaultLimits()); err == nil {
		t.Fatal("symlinked OpenReports file accepted")
	}
}

func TestExistingPolicyReportBehaviorUnchanged(t *testing.T) {
	// The OpenReports adapter must reject wgpolicyk8s.io input so the two
	// adapters never silently overlap.
	wgPolicy := `{"apiVersion": "wgpolicyk8s.io/v1alpha2", "kind": "PolicyReport", "results": []}`
	if _, err := Parse(strings.NewReader(wgPolicy), "test.json", DefaultLimits()); err == nil {
		t.Fatal("OpenReports adapter accepted a wgpolicyk8s object")
	}
}
