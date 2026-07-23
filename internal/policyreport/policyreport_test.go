package policyreport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/model"
)

func TestParseNormalizesFailedPolicyResults(t *testing.T) {
	input := `{
	  "apiVersion": "v1",
	  "kind": "List",
	  "items": [{
	    "apiVersion": "wgpolicyk8s.io/v1alpha2",
	    "kind": "PolicyReport",
	    "scope": {
	      "apiVersion": "v1",
	      "kind": "Pod",
	      "namespace": "payments",
	      "name": "api"
	    },
	    "results": [
	      {
	        "policy": "require-labels",
	        "rule": "team",
	        "result": "fail",
	        "severity": "high",
	        "source": "kyverno",
	        "category": "governance",
	        "message": "team label is missing"
	      },
	      {
	        "policy": "warn-policy",
	        "rule": "owner",
	        "result": "warn",
	        "source": "kyverno",
	        "message": "owner label is missing"
	      },
	      {"policy": "passing", "rule": "ok", "result": "pass"},
	      {"policy": "excepted", "rule": "skip", "result": "skip"}
	    ]
	  }]
	}`

	result, err := Parse(strings.NewReader(input), "policy-report.json", DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("got %d findings, want 2: %#v", len(result.Findings), result.Findings)
	}
	first := result.Findings[0]
	if first.Severity != model.SeverityHigh || first.Target != "payments/Pod/api" ||
		first.Source != "policyreport:kyverno" || first.ExternalRefs["policy"] != "require-labels" {
		t.Fatalf("unexpected failed result: %#v", first)
	}
	if result.Findings[1].Severity != model.SeverityLow {
		t.Fatalf("warn severity = %q, want low", result.Findings[1].Severity)
	}
	if result.Input.Path != "policy-report.json" || result.Input.SHA256 == "" ||
		result.Input.Bytes != int64(len(input)) {
		t.Fatalf("unexpected input inventory: %#v", result.Input)
	}
}

func TestParseCleansHostileText(t *testing.T) {
	message := "\u001b[31m" + strings.Repeat("x", 2_000)
	input := `{
	  "apiVersion":"wgpolicyk8s.io/v1alpha2",
	  "kind":"ClusterPolicyReport",
	  "scope":{"kind":"Namespace","name":"payments"},
	  "results":[{
	    "policy":"unsafe\npolicy",
	    "rule":"rule",
	    "result":"error",
	    "message":` + quoteJSON(message) + `
	  }]
	}`

	result, err := Parse(strings.NewReader(input), "policy-report.json", DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("unexpected findings: %#v", result.Findings)
	}
	encoded := result.Findings[0].Title + result.Findings[0].Description
	if strings.ContainsRune(encoded, '\u001b') || strings.ContainsRune(encoded, '\n') || len(encoded) > 1_200 {
		t.Fatalf("hostile text was not cleaned: %q", encoded)
	}
}

func TestParseRejectsUnsupportedAndUnknownResults(t *testing.T) {
	tests := []string{
		`{"apiVersion":"openreports.io/v1alpha1","kind":"PolicyReport"}`,
		`{"apiVersion":"wgpolicyk8s.io/v1alpha2","kind":"PolicyReport","results":[{"result":"mystery"}]}`,
	}
	for _, input := range tests {
		if _, err := Parse(strings.NewReader(input), "policy-report.json", DefaultLimits()); err == nil {
			t.Fatalf("Parse accepted unsupported input: %s", input)
		}
	}
}

func TestParseEnforcesResourceLimits(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxBytes = 4
	if _, err := Parse(strings.NewReader(`{"kind":"PolicyReport"}`), "report.json", limits); err == nil {
		t.Fatal("Parse accepted oversized input")
	}

	limits = DefaultLimits()
	limits.MaxResults = 1
	input := `{
	  "apiVersion":"wgpolicyk8s.io/v1alpha2",
	  "kind":"PolicyReport",
	  "results":[{"result":"pass"},{"result":"pass"}]
	}`
	if _, err := Parse(strings.NewReader(input), "report.json", limits); err == nil {
		t.Fatal("Parse accepted too many results")
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "report.json")
	link := filepath.Join(root, "report-link.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := Load(link, DefaultLimits()); err == nil {
		t.Fatal("Load followed symlink")
	}
}

func quoteJSON(value string) string {
	var builder strings.Builder
	builder.WriteByte('"')
	for _, current := range value {
		switch current {
		case '\\', '"':
			builder.WriteByte('\\')
			builder.WriteRune(current)
		case '\u001b':
			builder.WriteString(`\u001b`)
		default:
			builder.WriteRune(current)
		}
	}
	builder.WriteByte('"')
	return builder.String()
}
