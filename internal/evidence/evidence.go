// Package evidence writes immutable, hashed technical readiness bundles.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DPS0340/clusterproof/internal/model"
	"github.com/DPS0340/clusterproof/internal/rules"
)

type controlCoverage struct {
	SchemaVersion   string                 `json:"schema_version"`
	FrameworkNotice string                 `json:"framework_notice"`
	Ruleset         model.RulesetReference `json:"ruleset"`
	Controls        []controlAssessment    `json:"controls"`
}

type controlAssessment struct {
	Reference       string   `json:"reference"`
	Status          string   `json:"status"`
	AssessedRules   []string `json:"assessed_rules"`
	Findings        int      `json:"findings"`
	HighestSeverity string   `json:"highest_severity,omitempty"`
}

type metadata struct {
	SchemaVersion string                 `json:"schema_version"`
	GeneratedAt   string                 `json:"generated_at"`
	ToolVersion   string                 `json:"tool_version"`
	Target        string                 `json:"target"`
	Ruleset       model.RulesetReference `json:"ruleset"`
	Inputs        []model.Input          `json:"inputs"`
	Notice        string                 `json:"notice"`
}

type bundleManifest struct {
	Algorithm string       `json:"algorithm"`
	Files     []bundleFile `json:"files"`
}

type bundleFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// WriteBundle creates a new evidence directory and never reuses an existing one.
func WriteBundle(directory string, scan model.Report) (err error) {
	if strings.TrimSpace(directory) == "" {
		return fmt.Errorf("evidence directory is required")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create evidence directory %q: %w", directory, err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(directory)
		}
	}()

	catalog := rules.DefaultCatalog()
	rulesetReference := catalog.Reference()
	if scan.Ruleset != nil && *scan.Ruleset != rulesetReference {
		return fmt.Errorf(
			"report ruleset %s@%s does not match evidence catalog %s@%s",
			scan.Ruleset.ID, scan.Ruleset.Version, rulesetReference.ID, rulesetReference.Version,
		)
	}
	scan.Ruleset = &rulesetReference
	controls := buildControls(scan.Findings, catalog)
	meta := metadata{
		SchemaVersion: scan.SchemaVersion,
		GeneratedAt:   scan.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		ToolVersion:   scan.ToolVersion,
		Target:        scan.Target,
		Ruleset:       rulesetReference,
		Inputs:        scan.Inputs,
		Notice:        "Technical readiness evidence only; not a SOC 2 audit opinion or certification.",
	}

	files := map[string]any{
		"scan.json":     scan,
		"controls.json": controls,
		"metadata.json": meta,
		"ruleset.json":  catalog,
	}
	names := []string{"controls.json", "metadata.json", "ruleset.json", "scan.json"}
	manifest := bundleManifest{Algorithm: "SHA-256"}
	for _, name := range names {
		data, err := marshal(files[name])
		if err != nil {
			return fmt.Errorf("encode %s: %w", name, err)
		}
		if err := writePrivate(filepath.Join(directory, name), data); err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, bundleFile{
			Path:   name,
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  int64(len(data)),
		})
	}

	manifestData, err := marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode bundle manifest: %w", err)
	}
	if err := writePrivate(filepath.Join(directory, "bundle-manifest.json"), manifestData); err != nil {
		return err
	}
	complete = true
	return nil
}

// VerifyBundle confirms the size and SHA-256 of every recorded bundle file.
func VerifyBundle(directory string) error {
	data, err := os.ReadFile(filepath.Join(directory, "bundle-manifest.json"))
	if err != nil {
		return fmt.Errorf("read bundle manifest: %w", err)
	}
	var manifest bundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("decode bundle manifest: %w", err)
	}
	if manifest.Algorithm != "SHA-256" {
		return fmt.Errorf("unsupported bundle hash algorithm %q", manifest.Algorithm)
	}
	for _, file := range manifest.Files {
		if filepath.Base(file.Path) != file.Path || file.Path == "." {
			return fmt.Errorf("unsafe bundle path %q", file.Path)
		}
		content, err := os.ReadFile(filepath.Join(directory, file.Path))
		if err != nil {
			return fmt.Errorf("read bundle file %q: %w", file.Path, err)
		}
		sum := sha256.Sum256(content)
		if int64(len(content)) != file.Bytes || hex.EncodeToString(sum[:]) != file.SHA256 {
			return fmt.Errorf("bundle file %q failed integrity verification", file.Path)
		}
	}
	return nil
}

func buildControls(findings []model.Finding, catalog rules.Catalog) controlCoverage {
	type state struct {
		rules    map[string]struct{}
		findings int
		highest  model.Severity
	}
	states := make(map[string]*state)
	for _, rule := range catalog.Rules {
		for _, reference := range rule.ControlRefs {
			current := states[reference]
			if current == nil {
				current = &state{rules: make(map[string]struct{})}
				states[reference] = current
			}
			current.rules[rule.ID] = struct{}{}
		}
	}
	for _, finding := range findings {
		for _, reference := range finding.ControlRefs {
			current := states[reference]
			if current == nil {
				current = &state{rules: make(map[string]struct{})}
				states[reference] = current
			}
			current.rules[finding.ID] = struct{}{}
			current.findings++
			if severityRank(finding.Severity) > severityRank(current.highest) {
				current.highest = finding.Severity
			}
		}
	}
	references := make([]string, 0, len(states))
	for reference := range states {
		references = append(references, reference)
	}
	sort.Strings(references)

	controls := make([]controlAssessment, 0, len(references))
	for _, reference := range references {
		current := states[reference]
		assessedRules := make([]string, 0, len(current.rules))
		for ruleID := range current.rules {
			assessedRules = append(assessedRules, ruleID)
		}
		sort.Strings(assessedRules)
		status := "no_findings_observed"
		if current.findings > 0 {
			status = "attention_required"
		}
		controls = append(controls, controlAssessment{
			Reference:       reference,
			Status:          status,
			AssessedRules:   assessedRules,
			Findings:        current.findings,
			HighestSeverity: string(current.highest),
		})
	}
	return controlCoverage{
		SchemaVersion:   "2",
		FrameworkNotice: "Partial technical readiness observations only; references do not reproduce licensed criteria or constitute an audit opinion.",
		Ruleset:         catalog.Reference(),
		Controls:        controls,
	}
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 5
	case model.SeverityHigh:
		return 4
	case model.SeverityMedium:
		return 3
	case model.SeverityLow:
		return 2
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func marshal(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create evidence file %q: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("write evidence file %q: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync evidence file %q: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close evidence file %q: %w", path, err)
	}
	return nil
}
