package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/model"
)

func report(findings ...model.Finding) model.Report {
	return model.Report{
		SchemaVersion: "1",
		Ruleset:       &model.RulesetReference{ID: "clusterproof-default", Version: "1.2.0", RulesEvaluated: 24},
		Findings:      findings,
	}
}

func finding(id, target, container string, severity model.Severity) model.Finding {
	return model.Finding{
		ID:       id,
		Source:   "clusterproof",
		Target:   target,
		Severity: severity,
		Location: model.Location{Container: container},
	}
}

func TestReportsClassifiesAllTransitions(t *testing.T) {
	before := report(
		finding("CP-K8S-001", "a/Pod/x", "app", model.SeverityCritical), // resolved
		finding("CP-K8S-005", "a/Pod/x", "app", model.SeverityMedium),   // severity change
		finding("CP-K8S-009", "a/Pod/x", "app", model.SeverityMedium),   // unchanged
	)
	after := report(
		finding("CP-K8S-005", "a/Pod/x", "app", model.SeverityHigh),
		finding("CP-K8S-009", "a/Pod/x", "app", model.SeverityMedium),
		finding("CP-K8S-010", "a/Pod/x", "", model.SeverityMedium), // new
	)

	result, err := Reports(before, after, "hash-before", "hash-after")
	if err != nil {
		t.Fatalf("Reports: %v", err)
	}
	if len(result.New) != 1 || result.New[0].ID != "CP-K8S-010" {
		t.Fatalf("new = %#v", result.New)
	}
	if len(result.Resolved) != 1 || result.Resolved[0].ID != "CP-K8S-001" {
		t.Fatalf("resolved = %#v", result.Resolved)
	}
	if len(result.SeverityChanged) != 1 ||
		result.SeverityChanged[0].Before != model.SeverityMedium ||
		result.SeverityChanged[0].After != model.SeverityHigh {
		t.Fatalf("severityChanged = %#v", result.SeverityChanged)
	}
	if result.Unchanged != 1 {
		t.Fatalf("unchanged = %d, want 1", result.Unchanged)
	}
	if result.BeforeSHA256 != "hash-before" || result.AfterSHA256 != "hash-after" {
		t.Fatalf("input hashes missing: %#v", result)
	}
}

func TestReportsIsDeterministic(t *testing.T) {
	before := report(
		finding("CP-K8S-002", "b/Pod/y", "", model.SeverityHigh),
		finding("CP-K8S-001", "a/Pod/x", "app", model.SeverityCritical),
	)
	after := report()

	first, err := Reports(before, after, "h1", "h2")
	if err != nil {
		t.Fatalf("Reports: %v", err)
	}
	second, err := Reports(before, after, "h1", "h2")
	if err != nil {
		t.Fatalf("Reports: %v", err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("comparison output is not deterministic")
	}
	if len(first.Resolved) != 2 || first.Resolved[0].ID != "CP-K8S-001" {
		t.Fatalf("resolved not sorted: %#v", first.Resolved)
	}
}

func TestReportsTreatsDuplicatesOnce(t *testing.T) {
	duplicate := finding("CP-K8S-001", "a/Pod/x", "app", model.SeverityCritical)
	result, err := Reports(report(duplicate, duplicate), report(duplicate), "h1", "h2")
	if err != nil {
		t.Fatalf("Reports: %v", err)
	}
	if result.Unchanged != 1 || len(result.New) != 0 || len(result.Resolved) != 0 {
		t.Fatalf("duplicate handling wrong: %#v", result)
	}
}

func TestReportsRejectsIncompatibleInputs(t *testing.T) {
	base := report()
	differentSchema := base
	differentSchema.SchemaVersion = "2"
	if _, err := Reports(base, differentSchema, "h1", "h2"); err == nil ||
		!strings.Contains(err.Error(), "schema versions differ") {
		t.Fatalf("schema mismatch accepted: %v", err)
	}

	differentRuleset := report()
	differentRuleset.Ruleset = &model.RulesetReference{ID: "clusterproof-default", Version: "1.0.0"}
	if _, err := Reports(base, differentRuleset, "h1", "h2"); err == nil ||
		!strings.Contains(err.Error(), "ruleset versions differ") {
		t.Fatalf("ruleset mismatch accepted: %v", err)
	}
}

func TestFilesComparesJSONAndEvidenceDirectory(t *testing.T) {
	directory := t.TempDir()
	beforePath := filepath.Join(directory, "before.json")
	beforeReport := report(finding("CP-K8S-001", "a/Pod/x", "app", model.SeverityCritical))
	writeJSON(t, beforePath, beforeReport)

	evidenceDir := filepath.Join(directory, "evidence")
	if err := os.Mkdir(evidenceDir, 0o700); err != nil {
		t.Fatalf("mkdir evidence: %v", err)
	}
	writeJSON(t, filepath.Join(evidenceDir, "scan.json"), report())

	result, err := Files(beforePath, evidenceDir)
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if len(result.Resolved) != 1 || result.BeforeSHA256 == "" || result.AfterSHA256 == "" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.BeforeSHA256 == result.AfterSHA256 {
		t.Fatal("distinct inputs share one hash")
	}
}

func TestFilesRejectsHostileInputs(t *testing.T) {
	directory := t.TempDir()
	valid := filepath.Join(directory, "valid.json")
	writeJSON(t, valid, report())

	notReport := filepath.Join(directory, "not-report.json")
	if err := os.WriteFile(notReport, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := Files(valid, notReport); err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("non-report JSON accepted: %v", err)
	}

	malformed := filepath.Join(directory, "malformed.json")
	if err := os.WriteFile(malformed, []byte("{unclosed"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := Files(valid, malformed); err == nil {
		t.Fatal("malformed JSON accepted")
	}

	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(valid, link); err == nil {
		if _, err := Files(valid, link); err == nil {
			t.Fatal("symlinked report accepted")
		}
	}

	if _, err := Files(valid, filepath.Join(directory, "missing.json")); err == nil {
		t.Fatal("missing report accepted")
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("encode %q: %v", path, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
