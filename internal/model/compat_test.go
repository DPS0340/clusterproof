package model_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DPS0340/clusterproof/internal/model"
)

// TestCurrentCodeDecodesV03Report proves the additive-only compatibility
// policy: a report produced by v0.3.0 must decode with current code without
// losing any field.
func TestCurrentCodeDecodesV03Report(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "compat", "report-v0.3.json"))
	if err != nil {
		t.Fatalf("read v0.3 fixture: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report model.Report
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("v0.3 report no longer decodes with strict fields: %v", err)
	}

	if report.SchemaVersion != "1" {
		t.Fatalf("schema version = %q, want 1", report.SchemaVersion)
	}
	if report.Ruleset == nil || report.Ruleset.Version != "1.0.0" {
		t.Fatalf("ruleset reference lost: %#v", report.Ruleset)
	}
	if len(report.Findings) != 1 || report.Findings[0].ID != "CP-K8S-001" {
		t.Fatalf("findings lost: %#v", report.Findings)
	}
	if report.Findings[0].Location.Container != "api" || report.Findings[0].Evidence.Observed == "" {
		t.Fatalf("nested finding fields lost: %#v", report.Findings[0])
	}
	if len(report.Suppressed) != 0 {
		t.Fatalf("v0.3 report unexpectedly produced suppressed findings: %#v", report.Suppressed)
	}
	if report.Summary.Critical != 1 {
		t.Fatalf("summary lost: %#v", report.Summary)
	}
}

// TestCurrentReportOmitsNewFieldsWhenUnused proves that reports produced
// without new features stay byte-compatible for strict v0.3 consumers that
// reject unknown fields.
func TestCurrentReportOmitsNewFieldsWhenUnused(t *testing.T) {
	report := model.Report{SchemaVersion: "1", Target: "./deploy", ToolVersion: "dev"}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encode report: %v", err)
	}
	if bytes.Contains(encoded, []byte("suppressed_findings")) {
		t.Fatalf("unused additive field is not omitted: %s", encoded)
	}
}
