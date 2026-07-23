package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DPS0340/clusterproof/internal/model"
)

type decodedControl struct {
	Reference     string   `json:"reference"`
	Status        string   `json:"status"`
	AssessedRules []string `json:"assessed_rules"`
	FindingRules  []string `json:"finding_rules"`
	Findings      int      `json:"findings"`
	Highest       string   `json:"highest_severity"`
}

type decodedCoverage struct {
	SchemaVersion string `json:"schema_version"`
	Ruleset       struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	} `json:"ruleset"`
	Controls []decodedControl `json:"controls"`
}

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
	for _, name := range []string{"scan.json", "ruleset.json", "controls.json", "metadata.json", "bundle-manifest.json"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(directory, "controls.json"))
	if err != nil {
		t.Fatalf("read controls: %v", err)
	}
	var controls decodedCoverage
	if err := json.Unmarshal(data, &controls); err != nil {
		t.Fatalf("decode controls: %v", err)
	}
	if controls.SchemaVersion != "2" || controls.Ruleset.ID != "clusterproof-default" ||
		controls.Ruleset.Version == "" {
		t.Fatalf("unexpected coverage identity: %#v", controls)
	}
	soc2 := findControl(controls.Controls, "SOC2:CC6")
	if soc2.Status != "attention_required" || soc2.Findings != 1 ||
		soc2.Highest != "critical" || len(soc2.AssessedRules) == 0 {
		t.Fatalf("unexpected control coverage: %#v", controls)
	}
	if containsComplianceClaim(string(data)) {
		t.Fatalf("controls contain a compliance claim: %s", data)
	}

	if err := VerifyBundle(directory); err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
}

func TestWriteBundleRecordsNoFindingsObservedForAssessedRules(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "evidence")
	scan := model.Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC),
		ToolVersion:   "dev",
	}

	if err := WriteBundle(directory, scan); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "controls.json"))
	if err != nil {
		t.Fatalf("read controls: %v", err)
	}
	var controls decodedCoverage
	if err := json.Unmarshal(data, &controls); err != nil {
		t.Fatalf("decode controls: %v", err)
	}
	soc2 := findControl(controls.Controls, "SOC2:CC6")
	if soc2.Status != "no_findings_observed" {
		t.Fatalf("SOC2:CC6 status = %q", soc2.Status)
	}
	if containsComplianceClaim(string(data)) {
		t.Fatalf("controls contain a compliance claim: %s", data)
	}
}

func TestWriteBundleKeepsExternalFindingsOutOfNativeAssessedRules(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "evidence")
	scan := model.Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC),
		ToolVersion:   "dev",
		Findings: []model.Finding{{
			ID:          "CP-VULN-001",
			Severity:    model.SeverityHigh,
			ControlRefs: []string{"SOC2:CC7", "Vulnerability-Management"},
		}},
	}

	if err := WriteBundle(directory, scan); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "controls.json"))
	if err != nil {
		t.Fatalf("read controls: %v", err)
	}
	var controls decodedCoverage
	if err := json.Unmarshal(data, &controls); err != nil {
		t.Fatalf("decode controls: %v", err)
	}

	soc2 := findControl(controls.Controls, "SOC2:CC7")
	if containsString(soc2.AssessedRules, "CP-VULN-001") {
		t.Fatalf("external finding was recorded as a native assessed rule: %#v", soc2)
	}
	if !containsString(soc2.FindingRules, "CP-VULN-001") ||
		soc2.Status != "attention_required" {
		t.Fatalf("external observation missing from coverage: %#v", soc2)
	}
	vulnerability := findControl(controls.Controls, "Vulnerability-Management")
	if len(vulnerability.AssessedRules) != 0 ||
		!containsString(vulnerability.FindingRules, "CP-VULN-001") {
		t.Fatalf("unmapped external coverage is misleading: %#v", vulnerability)
	}
}

func TestWriteBundleRefusesExistingDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := WriteBundle(directory, model.Report{}); err == nil {
		t.Fatal("WriteBundle reused existing directory")
	}
}

func TestVerifyBundleRejectsExtraFile(t *testing.T) {
	directory := writeTestBundle(t)
	if err := os.WriteFile(filepath.Join(directory, "untracked.txt"), []byte("extra"), 0o600); err != nil {
		t.Fatalf("write extra file: %v", err)
	}
	if err := VerifyBundle(directory); err == nil {
		t.Fatal("VerifyBundle accepted an untracked file")
	}
}

func TestVerifyBundleRejectsModifiedFile(t *testing.T) {
	directory := writeTestBundle(t)
	if err := os.WriteFile(filepath.Join(directory, "scan.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("modify scan: %v", err)
	}
	if err := VerifyBundle(directory); err == nil {
		t.Fatal("VerifyBundle accepted modified evidence")
	}
}

func TestVerifyBundleRejectsMissingFile(t *testing.T) {
	directory := writeTestBundle(t)
	if err := os.Remove(filepath.Join(directory, "scan.json")); err != nil {
		t.Fatalf("remove scan: %v", err)
	}
	if err := VerifyBundle(directory); err == nil {
		t.Fatal("VerifyBundle accepted a missing file")
	}
}

func TestVerifyBundleRejectsSymlinkedFile(t *testing.T) {
	directory := writeTestBundle(t)
	path := filepath.Join(directory, "controls.json")
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove controls: %v", err)
	}
	if err := os.Symlink(filepath.Join(directory, "scan.json"), path); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if err := VerifyBundle(directory); err == nil {
		t.Fatal("VerifyBundle followed a symlink")
	}
}

func TestVerifyBundleRejectsDuplicateManifestEntry(t *testing.T) {
	directory := writeTestBundle(t)
	path := filepath.Join(directory, "bundle-manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest bundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.Files = append(manifest.Files, manifest.Files[0])
	data, err = marshal(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("replace manifest: %v", err)
	}
	if err := VerifyBundle(directory); err == nil {
		t.Fatal("VerifyBundle accepted a duplicate manifest entry")
	}
}

func TestVerifyBundleEnforcesManifestLimit(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "bundle-manifest.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 128)), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	limits := defaultVerifyLimits()
	limits.MaxManifestBytes = 16
	if err := verifyBundle(directory, limits); err == nil {
		t.Fatal("verifyBundle accepted an oversized manifest")
	}
}

func TestVerifyBundleEnforcesFileLimit(t *testing.T) {
	directory := writeTestBundle(t)
	limits := defaultVerifyLimits()
	limits.MaxFileBytes = 1
	if err := verifyBundle(directory, limits); err == nil {
		t.Fatal("verifyBundle accepted an oversized evidence file")
	}
}

func TestVerifyBundleRejectsMalformedHash(t *testing.T) {
	directory := writeTestBundle(t)
	path := filepath.Join(directory, "bundle-manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest bundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.Files[0].SHA256 = "not-a-sha256"
	data, err = marshal(manifest)
	if err != nil {
		t.Fatalf("encode manifest: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("replace manifest: %v", err)
	}
	if err := VerifyBundle(directory); err == nil {
		t.Fatal("VerifyBundle accepted a malformed hash")
	}
}

func writeTestBundle(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "evidence")
	scan := model.Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Date(2026, 7, 23, 1, 2, 3, 0, time.UTC),
		ToolVersion:   "dev",
	}
	if err := WriteBundle(directory, scan); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	return directory
}

func findControl(controls []decodedControl, reference string) decodedControl {
	for _, control := range controls {
		if control.Reference == reference {
			return control
		}
	}
	return decodedControl{}
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsComplianceClaim(value string) bool {
	for _, forbidden := range []string{`"compliant"`, `"passed"`, `"certified"`} {
		if strings.Contains(strings.ToLower(value), forbidden) {
			return true
		}
	}
	return false
}
