// Package model defines ClusterProof's stable public report contract.
package model

import (
	"fmt"
	"strings"
	"time"
)

// Severity is the normalized risk level of a finding.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRanks = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// ParseSeverity parses a case-insensitive severity name.
func ParseSeverity(raw string) (Severity, error) {
	severity := Severity(strings.ToLower(strings.TrimSpace(raw)))
	if _, ok := severityRanks[severity]; !ok {
		return "", fmt.Errorf("unknown severity %q", raw)
	}
	return severity, nil
}

// Meets reports whether a severity is at or above a policy threshold.
func (s Severity) Meets(threshold Severity) bool {
	return severityRanks[s] >= severityRanks[threshold]
}

// Location points to the source of a finding without containing source values.
type Location struct {
	Path      string `json:"path,omitempty"`
	Document  int    `json:"document,omitempty"`
	Line      int    `json:"line,omitempty"`
	Resource  string `json:"resource,omitempty"`
	Container string `json:"container,omitempty"`
}

// Evidence describes the observed and desired states in safe-to-display form.
type Evidence struct {
	Observed string `json:"observed,omitempty"`
	Expected string `json:"expected,omitempty"`
}

// Finding is one normalized security observation.
type Finding struct {
	ID           string            `json:"id"`
	Severity     Severity          `json:"severity"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Remediation  string            `json:"remediation"`
	Source       string            `json:"source"`
	Target       string            `json:"target"`
	Location     Location          `json:"location"`
	Evidence     Evidence          `json:"evidence"`
	ControlRefs  []string          `json:"control_refs"`
	ExternalRefs map[string]string `json:"external_refs,omitempty"`
}

// Input records a scanned file without storing its contents.
type Input struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Summary contains deterministic severity totals.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Report is the canonical output consumed by every reporter.
type Report struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Target        string    `json:"target"`
	ToolVersion   string    `json:"tool_version"`
	Inputs        []Input   `json:"inputs"`
	Findings      []Finding `json:"findings"`
	Summary       Summary   `json:"summary"`
}

// Summarize counts findings by severity.
func Summarize(findings []Finding) Summary {
	var summary Summary
	for _, finding := range findings {
		switch finding.Severity {
		case SeverityCritical:
			summary.Critical++
		case SeverityHigh:
			summary.High++
		case SeverityMedium:
			summary.Medium++
		case SeverityLow:
			summary.Low++
		case SeverityInfo:
			summary.Info++
		}
	}
	return summary
}
