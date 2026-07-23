// Package evidence writes and verifies hashed technical readiness bundles.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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
	FindingRules    []string `json:"finding_rules,omitempty"`
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

type verifyLimits struct {
	MaxManifestBytes int64
	MaxFiles         int
	MaxFileBytes     int64
	MaxTotalBytes    int64
}

func defaultVerifyLimits() verifyLimits {
	return verifyLimits{
		MaxManifestBytes: 1 << 20,
		MaxFiles:         32,
		MaxFileBytes:     200 << 20,
		MaxTotalBytes:    500 << 20,
	}
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
	return verifyBundle(directory, defaultVerifyLimits())
}

func verifyBundle(directory string, limits verifyLimits) error {
	if limits.MaxManifestBytes <= 0 || limits.MaxFiles <= 0 ||
		limits.MaxFileBytes <= 0 || limits.MaxTotalBytes <= 0 {
		return fmt.Errorf("all evidence verification limits must be positive")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect evidence directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("evidence path is not a regular directory")
	}

	manifestPath := filepath.Join(directory, "bundle-manifest.json")
	data, err := readRegularBounded(manifestPath, limits.MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("read bundle manifest: %w", err)
	}
	var manifest bundleManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("decode bundle manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("decode bundle manifest: trailing JSON content")
	}
	if manifest.Algorithm != "SHA-256" {
		return fmt.Errorf("unsupported bundle hash algorithm %q", manifest.Algorithm)
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > limits.MaxFiles {
		return fmt.Errorf("bundle file count must be between 1 and %d", limits.MaxFiles)
	}

	expected := make(map[string]bundleFile, len(manifest.Files))
	var totalBytes int64
	for _, file := range manifest.Files {
		if filepath.Base(file.Path) != file.Path || file.Path == "." || file.Path == "" ||
			file.Path == "bundle-manifest.json" {
			return fmt.Errorf("unsafe bundle path %q", file.Path)
		}
		if _, exists := expected[file.Path]; exists {
			return fmt.Errorf("duplicate bundle path %q", file.Path)
		}
		hash, err := hex.DecodeString(file.SHA256)
		if err != nil || len(hash) != sha256.Size || strings.ToLower(file.SHA256) != file.SHA256 {
			return fmt.Errorf("invalid SHA-256 for bundle file %q", file.Path)
		}
		if file.Bytes < 0 || file.Bytes > limits.MaxFileBytes {
			return fmt.Errorf("bundle file %q has invalid size %d", file.Path, file.Bytes)
		}
		if totalBytes > limits.MaxTotalBytes-file.Bytes {
			return fmt.Errorf("bundle exceeds total size limit of %d bytes", limits.MaxTotalBytes)
		}
		totalBytes += file.Bytes
		expected[file.Path] = file
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read evidence directory: %w", err)
	}
	if len(entries) != len(expected)+1 {
		return fmt.Errorf("evidence directory contains an unexpected number of files")
	}
	for _, entry := range entries {
		if entry.Name() == "bundle-manifest.json" {
			continue
		}
		if _, exists := expected[entry.Name()]; !exists {
			return fmt.Errorf("untracked evidence file %q", entry.Name())
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return fmt.Errorf("evidence file %q is not regular", entry.Name())
		}
	}

	for _, file := range manifest.Files {
		path := filepath.Join(directory, file.Path)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect bundle file %q: %w", file.Path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("bundle file %q is not regular", file.Path)
		}
		if info.Size() != file.Bytes {
			return fmt.Errorf("bundle file %q failed integrity verification", file.Path)
		}
		input, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open bundle file %q: %w", file.Path, err)
		}
		hasher := sha256.New()
		written, copyErr := io.Copy(hasher, input)
		closeErr := input.Close()
		if copyErr != nil {
			return fmt.Errorf("hash bundle file %q: %w", file.Path, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close bundle file %q: %w", file.Path, closeErr)
		}
		if written != file.Bytes || hex.EncodeToString(hasher.Sum(nil)) != file.SHA256 {
			return fmt.Errorf("bundle file %q failed integrity verification", file.Path)
		}
	}
	return nil
}

func readRegularBounded(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%q exceeds limit of %d bytes", path, maxBytes)
	}
	return data, nil
}

func buildControls(findings []model.Finding, catalog rules.Catalog) controlCoverage {
	type state struct {
		assessedRules map[string]struct{}
		findingRules  map[string]struct{}
		findings      int
		highest       model.Severity
	}
	states := make(map[string]*state)
	for _, rule := range catalog.Rules {
		for _, reference := range rule.ControlRefs {
			current := states[reference]
			if current == nil {
				current = &state{
					assessedRules: make(map[string]struct{}),
					findingRules:  make(map[string]struct{}),
				}
				states[reference] = current
			}
			current.assessedRules[rule.ID] = struct{}{}
		}
	}
	for _, finding := range findings {
		for _, reference := range finding.ControlRefs {
			current := states[reference]
			if current == nil {
				current = &state{
					assessedRules: make(map[string]struct{}),
					findingRules:  make(map[string]struct{}),
				}
				states[reference] = current
			}
			current.findingRules[finding.ID] = struct{}{}
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
		assessedRules := make([]string, 0, len(current.assessedRules))
		for ruleID := range current.assessedRules {
			assessedRules = append(assessedRules, ruleID)
		}
		sort.Strings(assessedRules)
		findingRules := make([]string, 0, len(current.findingRules))
		for ruleID := range current.findingRules {
			findingRules = append(findingRules, ruleID)
		}
		sort.Strings(findingRules)
		status := "no_findings_observed"
		if current.findings > 0 {
			status = "attention_required"
		}
		controls = append(controls, controlAssessment{
			Reference:       reference,
			Status:          status,
			AssessedRules:   assessedRules,
			FindingRules:    findingRules,
			Findings:        current.findings,
			HighestSeverity: string(current.highest),
		})
	}
	return controlCoverage{
		SchemaVersion:   "2",
		FrameworkNotice: "Partial technical readiness observations only; assessed_rules lists the native catalog while finding_rules may include external observations. References do not reproduce licensed criteria or constitute an audit opinion.",
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
