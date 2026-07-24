// Package compare deterministically diffs two ClusterProof reports without
// retaining history in any service.
package compare

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
)

// MaxReportBytes bounds each compared report file.
const MaxReportBytes = 200 << 20

// Result is the deterministic classification of two reports.
type Result struct {
	SchemaVersion string `json:"schema_version"`
	// BeforeSHA256 and AfterSHA256 identify the exact compared inputs.
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256"`
	// Ruleset versions of both reports; equal versions are required.
	Ruleset  string          `json:"ruleset"`
	New      []model.Finding `json:"new"`
	Resolved []model.Finding `json:"resolved"`
	// SeverityChanged lists findings whose identity matched but severity moved.
	SeverityChanged []SeverityChange `json:"severity_changed"`
	Unchanged       int              `json:"unchanged"`
}

// SeverityChange records one finding whose severity differs between runs.
type SeverityChange struct {
	Finding model.Finding  `json:"finding"`
	Before  model.Severity `json:"before"`
	After   model.Severity `json:"after"`
}

// Reports compares two decoded reports.
func Reports(before, after model.Report, beforeHash, afterHash string) (Result, error) {
	if before.SchemaVersion != after.SchemaVersion {
		return Result{}, fmt.Errorf(
			"schema versions differ (%q vs %q); migrate the older report before comparing",
			before.SchemaVersion, after.SchemaVersion)
	}
	beforeRuleset := rulesetIdentity(before)
	afterRuleset := rulesetIdentity(after)
	if beforeRuleset != afterRuleset {
		return Result{}, fmt.Errorf(
			"ruleset versions differ (%s vs %s); rescan the before target with the current ruleset for a meaningful diff",
			beforeRuleset, afterRuleset)
	}

	beforeSet := findingSet(before.Findings)
	afterSet := findingSet(after.Findings)

	result := Result{
		SchemaVersion: "1",
		BeforeSHA256:  beforeHash,
		AfterSHA256:   afterHash,
		Ruleset:       afterRuleset,
	}
	for key, finding := range afterSet {
		previous, existed := beforeSet[key]
		switch {
		case !existed:
			result.New = append(result.New, finding)
		case previous.Severity != finding.Severity:
			result.SeverityChanged = append(result.SeverityChanged, SeverityChange{
				Finding: finding,
				Before:  previous.Severity,
				After:   finding.Severity,
			})
		default:
			result.Unchanged++
		}
	}
	for key, finding := range beforeSet {
		if _, exists := afterSet[key]; !exists {
			result.Resolved = append(result.Resolved, finding)
		}
	}
	sortFindings(result.New)
	sortFindings(result.Resolved)
	sort.Slice(result.SeverityChanged, func(i, j int) bool {
		return findingKey(result.SeverityChanged[i].Finding) < findingKey(result.SeverityChanged[j].Finding)
	})
	return result, nil
}

// Files loads and compares two report files. Each path may be a JSON report
// or an evidence bundle directory containing scan.json.
func Files(beforePath, afterPath string) (Result, error) {
	before, beforeHash, err := loadReport(beforePath)
	if err != nil {
		return Result{}, fmt.Errorf("load before report: %w", err)
	}
	after, afterHash, err := loadReport(afterPath)
	if err != nil {
		return Result{}, fmt.Errorf("load after report: %w", err)
	}
	return Reports(before, after, beforeHash, afterHash)
}

func loadReport(path string) (model.Report, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return model.Report{}, "", fmt.Errorf("inspect %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return model.Report{}, "", fmt.Errorf("%q is a symlink", path)
	}
	if info.IsDir() {
		path = filepath.Join(path, "scan.json")
		info, err = os.Lstat(path)
		if err != nil {
			return model.Report{}, "", fmt.Errorf("evidence directory has no scan.json: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return model.Report{}, "", fmt.Errorf("%q is not a regular file", path)
		}
	} else if !info.Mode().IsRegular() {
		return model.Report{}, "", fmt.Errorf("%q is not a regular file or directory", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return model.Report{}, "", fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxReportBytes+1))
	if err != nil {
		return model.Report{}, "", fmt.Errorf("read %q: %w", path, err)
	}
	if int64(len(data)) > MaxReportBytes {
		return model.Report{}, "", fmt.Errorf("%q exceeds limit of %d bytes", path, int64(MaxReportBytes))
	}

	var report model.Report
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&report); err != nil {
		return model.Report{}, "", fmt.Errorf("decode %q: %w", path, err)
	}
	if report.SchemaVersion == "" {
		return model.Report{}, "", fmt.Errorf("%q has no schema_version; not a ClusterProof report", path)
	}
	sum := sha256.Sum256(data)
	return report, hex.EncodeToString(sum[:]), nil
}

func rulesetIdentity(report model.Report) string {
	if report.Ruleset == nil {
		return "unversioned"
	}
	return report.Ruleset.ID + "@" + report.Ruleset.Version
}

// findingKey identifies a finding across runs without its severity, so a
// severity change is a change, not a new-plus-resolved pair.
func findingKey(finding model.Finding) string {
	return strings.Join([]string{
		finding.ID,
		finding.Source,
		finding.Target,
		finding.Location.Container,
	}, "\x00")
}

func findingSet(findings []model.Finding) map[string]model.Finding {
	set := make(map[string]model.Finding, len(findings))
	for _, finding := range findings {
		key := findingKey(finding)
		if _, exists := set[key]; !exists {
			set[key] = finding
		}
	}
	return set
}

func sortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return findingKey(findings[i]) < findingKey(findings[j])
	})
}
