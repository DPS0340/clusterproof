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
	for _, field := range []string{"suppressed_findings", "assessment", "cluster_scopes"} {
		if bytes.Contains(encoded, []byte(field)) {
			t.Fatalf("unused additive field %q is not omitted: %s", field, encoded)
		}
	}
}

// TestCurrentCodeDecodesV06Report proves the v0.6 fixture, which uses every
// additive field, decodes strictly with current code. This test must keep
// passing for two consecutive minor releases before v1.0.
func TestCurrentCodeDecodesV06Report(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "compat", "report-v0.6.json"))
	if err != nil {
		t.Fatalf("read v0.6 fixture: %v", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report model.Report
	if err := decoder.Decode(&report); err != nil {
		t.Fatalf("v0.6 report no longer decodes with strict fields: %v", err)
	}
	if report.SchemaVersion != "1" {
		t.Fatalf("schema version = %q, want 1", report.SchemaVersion)
	}
	if report.Assessment == nil || report.Assessment.Status == "" {
		t.Fatalf("assessment lost: %#v", report.Assessment)
	}
	if len(report.Suppressed) == 0 {
		t.Fatalf("suppressed findings lost: %#v", report.Suppressed)
	}
	if len(report.Scopes) != 2 || report.Scopes[1].Status != "denied" {
		t.Fatalf("cluster scopes lost: %#v", report.Scopes)
	}
	if len(report.Findings) == 0 || report.Summary.Critical == 0 {
		t.Fatalf("findings or summary lost: %d findings, %#v", len(report.Findings), report.Summary)
	}
}
