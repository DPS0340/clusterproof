// Package openreports imports bounded openreports.io/v1alpha1 results
// behind an explicitly experimental adapter.
//
// The upstream OpenReports API has not reached a stable contract; this
// adapter is versioned separately and may change with upstream. Import
// never installs CRDs or executes producer policy code.
package openreports

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/DPS0340/clusterproof/internal/model"
)

// AdapterVersion identifies this experimental adapter's contract.
const AdapterVersion = "experimental-1"

const supportedAPIVersion = "openreports.io/v1alpha1"

// Limits bounds work performed on untrusted OpenReports input.
type Limits struct {
	MaxBytes   int64
	MaxReports int
	MaxResults int
}

// DefaultLimits returns conservative OpenReports import limits.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:   10 << 20,
		MaxReports: 5_000,
		MaxResults: 50_000,
	}
}

// Result contains normalized findings and the hashed imported input.
type Result struct {
	Findings []model.Finding
	Input    model.Input
}

type rawReport struct {
	APIVersion string      `json:"apiVersion"`
	Kind       string      `json:"kind"`
	Items      []rawReport `json:"items"`
	Scope      rawScope    `json:"scope"`
	Results    []rawResult `json:"results"`
}

type rawScope struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type rawResult struct {
	Policy   string `json:"policy"`
	Rule     string `json:"rule"`
	Result   string `json:"result"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Category string `json:"category"`
}

// Load reads one regular OpenReports JSON file without following a symlink.
func Load(path string, limits Limits) (Result, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Result{}, fmt.Errorf("inspect OpenReports file %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Result{}, fmt.Errorf("OpenReports file %q is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("OpenReports file %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open OpenReports file %q: %w", path, err)
	}
	defer file.Close()
	return Parse(file, path, limits)
}

// Parse normalizes fail, warn, and error outcomes; pass and skip are
// omitted. Unknown outcomes fail closed.
func Parse(reader io.Reader, source string, limits Limits) (Result, error) {
	if strings.TrimSpace(source) == "" {
		return Result{}, errors.New("OpenReports source is required")
	}
	if limits.MaxBytes <= 0 || limits.MaxReports <= 0 || limits.MaxResults <= 0 {
		return Result{}, errors.New("all OpenReports limits must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limits.MaxBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read OpenReports input: %w", err)
	}
	if int64(len(data)) > limits.MaxBytes {
		return Result{}, fmt.Errorf("OpenReports input exceeds limit of %d bytes", limits.MaxBytes)
	}

	var root rawReport
	if err := json.Unmarshal(data, &root); err != nil {
		return Result{}, fmt.Errorf("decode OpenReports JSON: %w", err)
	}
	sum := sha256.Sum256(data)
	result := Result{
		Input: model.Input{
			Path:   source,
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  int64(len(data)),
		},
	}

	queue := []rawReport{root}
	reports := 0
	results := 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.Kind == "List" || strings.HasSuffix(current.Kind, "ReportList") {
			queue = append(queue, current.Items...)
			continue
		}
		if current.APIVersion != supportedAPIVersion ||
			(current.Kind != "Report" && current.Kind != "ClusterReport") {
			return Result{}, fmt.Errorf(
				"unsupported OpenReports object %s %s; this experimental adapter accepts only %s Report and ClusterReport",
				cleanText(current.APIVersion), cleanText(current.Kind), supportedAPIVersion)
		}
		reports++
		if reports > limits.MaxReports {
			return Result{}, fmt.Errorf("OpenReports report count exceeds limit of %d", limits.MaxReports)
		}
		results += len(current.Results)
		if results > limits.MaxResults {
			return Result{}, fmt.Errorf("OpenReports result count exceeds limit of %d", limits.MaxResults)
		}
		for _, reportResult := range current.Results {
			finding, include, err := normalizeResult(source, current.Scope, reportResult)
			if err != nil {
				return Result{}, err
			}
			if include {
				result.Findings = append(result.Findings, finding)
			}
		}
	}
	sortFindings(result.Findings)
	return result, nil
}

func normalizeResult(source string, scope rawScope, result rawResult) (model.Finding, bool, error) {
	outcome := strings.ToLower(strings.TrimSpace(result.Result))
	switch outcome {
	case "pass", "skip":
		return model.Finding{}, false, nil
	case "fail", "warn", "error":
	default:
		return model.Finding{}, false, fmt.Errorf("unsupported OpenReports result %q", cleanText(result.Result))
	}

	severity, err := resultSeverity(result.Severity, outcome)
	if err != nil {
		return model.Finding{}, false, err
	}
	policy := cleanText(result.Policy)
	rule := cleanText(result.Rule)
	reportSource := cleanText(result.Source)
	if reportSource == "" {
		reportSource = "external"
	}
	identity := reportSource + "\x00" + policy + "\x00" + rule
	sum := sha256.Sum256([]byte(identity))
	titleTarget := policy
	if rule != "" {
		titleTarget += "/" + rule
	}
	if titleTarget == "" {
		titleTarget = "unnamed rule"
	}
	external := map[string]string{
		"policy":          policy,
		"rule":            rule,
		"adapter_version": AdapterVersion,
	}
	if category := cleanText(result.Category); category != "" {
		external["category"] = category
	}
	return model.Finding{
		ID:          "CP-OPENREPORT-" + strings.ToUpper(hex.EncodeToString(sum[:6])),
		Severity:    severity,
		Title:       "External OpenReports result: " + titleTarget,
		Description: "An imported OpenReports object recorded an external result requiring review; the original message is intentionally omitted.",
		Remediation: "Review the source policy and resource, document any approved exception, and re-run the producing engine.",
		Source:      "openreports:" + reportSource,
		Target:      scopeTarget(scope),
		Location: model.Location{
			Path:     source,
			Resource: cleanText(scope.Kind) + "/" + cleanText(scope.Name),
		},
		Evidence: model.Evidence{
			Observed: "report result: " + outcome,
			Expected: "report result: pass",
		},
		ControlRefs:  []string{},
		ExternalRefs: external,
	}, true, nil
}

func resultSeverity(raw, outcome string) (model.Severity, error) {
	if strings.TrimSpace(raw) != "" {
		severity, err := model.ParseSeverity(raw)
		if err != nil {
			return "", fmt.Errorf("invalid OpenReports severity: %w", err)
		}
		return severity, nil
	}
	if outcome == "warn" {
		return model.SeverityLow, nil
	}
	return model.SeverityMedium, nil
}

func scopeTarget(scope rawScope) string {
	kind := cleanText(scope.Kind)
	if kind == "" {
		kind = "Resource"
	}
	name := cleanText(scope.Name)
	if name == "" {
		name = "unknown"
	}
	if namespace := cleanText(scope.Namespace); namespace != "" {
		return namespace + "/" + kind + "/" + name
	}
	return kind + "/" + name
}

func cleanText(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	for _, current := range value {
		if builder.Len() >= 1_000 {
			break
		}
		if unicode.IsControl(current) {
			builder.WriteRune(' ')
			continue
		}
		builder.WriteRune(current)
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}

func sortFindings(findings []model.Finding) {
	rank := map[model.Severity]int{
		model.SeverityInfo: 0, model.SeverityLow: 1, model.SeverityMedium: 2,
		model.SeverityHigh: 3, model.SeverityCritical: 4,
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return rank[findings[i].Severity] > rank[findings[j].Severity]
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Target < findings[j].Target
	})
}
