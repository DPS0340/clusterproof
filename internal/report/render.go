// Package report renders ClusterProof's canonical report into public formats.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/DPS0340/clusterproof/internal/model"
)

// JSON writes deterministic indented JSON.
func JSON(writer io.Writer, report model.Report) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// Table writes a compact human-readable finding list.
func Table(writer io.Writer, report model.Report) error {
	table := tabwriter.NewWriter(writer, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(table, "SEVERITY\tRULE\tTARGET\tCONTAINER\tTITLE"); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		if _, err := fmt.Fprintf(
			table, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(string(finding.Severity)),
			finding.ID,
			finding.Target,
			finding.Location.Container,
			finding.Title,
		); err != nil {
			return err
		}
	}
	if err := table.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(
		writer,
		"\nSummary: %d critical, %d high, %d medium, %d low, %d info\n",
		report.Summary.Critical,
		report.Summary.High,
		report.Summary.Medium,
		report.Summary.Low,
		report.Summary.Info,
	)
	if err != nil {
		return err
	}
	if len(report.Suppressed) > 0 {
		_, err = fmt.Fprintf(
			writer,
			"Suppressed by reviewed exceptions: %d (identities recorded in the report)\n",
			len(report.Suppressed),
		)
		if err != nil {
			return err
		}
	}
	if report.Assessment != nil && report.Assessment.Status == model.AssessmentStatusNoWorkloads {
		_, err = fmt.Fprintf(
			writer,
			"Assessment: no supported workloads were found in %d input(s); this is not a clean security result.\n",
			report.Assessment.InputsScanned,
		)
	}
	return err
}

// SARIF writes SARIF 2.1.0 suitable for code scanning systems.
func SARIF(writer io.Writer, report model.Report) error {
	document := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ClusterProof",
				Version:        report.ToolVersion,
				InformationURI: "https://github.com/DPS0340/clusterproof",
				Rules:          sarifRules(report.Findings),
			}},
			Results: sarifResults(report.Findings),
		}},
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func sarifRules(findings []model.Finding) []sarifRule {
	byID := make(map[string]model.Finding)
	for _, finding := range findings {
		if _, exists := byID[finding.ID]; !exists {
			byID[finding.ID] = finding
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		finding := byID[id]
		rules = append(rules, sarifRule{
			ID:               id,
			Name:             finding.Title,
			ShortDescription: sarifMessage{Text: finding.Description},
			Help:             sarifMessage{Text: finding.Remediation},
		})
	}
	return rules
}

func sarifResults(findings []model.Finding) []sarifResult {
	results := make([]sarifResult, 0, len(findings))
	for _, finding := range findings {
		result := sarifResult{
			RuleID:  finding.ID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifMessage{Text: finding.Title + ": " + finding.Remediation},
			PartialFingerprints: map[string]string{
				"clusterproof/v1": findingFingerprint(finding),
			},
		}
		if finding.Location.Path != "" {
			result.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: filepath.ToSlash(finding.Location.Path)},
				Region:           sarifRegion{StartLine: finding.Location.Line},
			}}}
		}
		results = append(results, result)
	}
	return results
}

func sarifLevel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func findingFingerprint(finding model.Finding) string {
	value := strings.Join([]string{
		finding.ID,
		finding.Target,
		finding.Location.Path,
		finding.Location.Container,
	}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	Help             sarifMessage `json:"help"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}
