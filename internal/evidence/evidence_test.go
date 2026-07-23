package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kitae1645/clusterproof/internal/model"
)

func TestWriteBundleCreatesHashedReadinessEvidence(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "evidence")
	finding := model.Finding{
		ID:          "CP-K8S-001",
		Severity:    model.SeverityCritical,
		ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
	}
	scan := model.Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC),
		ToolVersion:   "dev",
		Inputs:        []model.Input{{Path: "pod.yaml", SHA256: "abc", Bytes: 12}},
		Findings:      []model.Finding{finding},
		Summary:       model.Summarize([]model.Finding{finding}),
	}

	if err := WriteBundle(directory, scan); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	for _, name := range []string{"scan.json", "controls.json", "metadata.json", "bundle-manifest.json"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(directory, "controls.json"))
	if err != nil {
		t.Fatalf("read controls: %v", err)
	}
	var controls struct {
		Controls []struct {
			Reference string `json:"reference"`
			Findings  int    `json:"findings"`
		} `json:"controls"`
	}
	if err := json.Unmarshal(data, &controls); err != nil {
		t.Fatalf("decode controls: %v", err)
	}
	if len(controls.Controls) != 2 || controls.Controls[1].Reference != "SOC2:CC6" {
		t.Fatalf("unexpected control coverage: %#v", controls)
	}

	if err := VerifyBundle(directory); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

func TestWriteBundleRefusesExistingDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := WriteBundle(directory, model.Report{}); err == nil {
		t.Fatal("WriteBundle reused existing directory")
	}
}
