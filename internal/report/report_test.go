package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DPS0340/clusterproof/internal/model"
)

func TestSARIFContainsRuleAndLocation(t *testing.T) {
	input := sampleReport()
	var output bytes.Buffer
	if err := SARIF(&output, input); err != nil {
		t.Fatalf("SARIF: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if document["version"] != "2.1.0" {
		t.Fatalf("SARIF version = %#v", document["version"])
	}
	if !bytes.Contains(output.Bytes(), []byte(`"ruleId": "CP-K8S-001"`)) {
		t.Fatalf("SARIF missing rule: %s", output.Bytes())
	}
	if !bytes.Contains(output.Bytes(), []byte(`"startLine": 7`)) {
		t.Fatalf("SARIF missing location: %s", output.Bytes())
	}
}

func TestWriteNewRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteNew(path, []byte("first")); err != nil {
		t.Fatalf("WriteNew first: %v", err)
	}
	if err := WriteNew(path, []byte("second")); err == nil {
		t.Fatal("WriteNew overwrote existing report")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "first" {
		t.Fatalf("existing report changed: %q", data)
	}
}

func sampleReport() model.Report {
	findings := []model.Finding{{
		ID:          "CP-K8S-001",
		Severity:    model.SeverityCritical,
		Title:       "Privileged container",
		Description: "Container bypasses isolation.",
		Remediation: "Disable privileged mode.",
		Source:      "clusterproof",
		Target:      "default/Pod/api",
		Location:    model.Location{Path: "pod.yaml", Line: 7},
		ControlRefs: []string{"SOC2:CC6"},
	}}
	return model.Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC),
		Target:        ".",
		ToolVersion:   "dev",
		Findings:      findings,
		Summary:       model.Summarize(findings),
	}
}
