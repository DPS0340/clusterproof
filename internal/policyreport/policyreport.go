// Package policyreport normalizes bounded Kubernetes PolicyReport JSON results.
package policyreport

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

const supportedAPIVersion = "wgpolicyk8s.io/v1alpha2"

// Limits bounds work performed on an untrusted PolicyReport.
type Limits struct {
	MaxBytes   int64
	MaxReports int
	MaxResults int
}

// DefaultLimits returns conservative PolicyReport import limits.
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
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
}

type rawResult struct {
	Policy   string `json:"policy"`
	Rule     string `json:"rule"`
	Result   string `json:"result"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
	Category string `json:"category"`
}

// Load reads one regular PolicyReport JSON file without following a symlink.
func Load(path string, limits Limits) (Result, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Result{}, fmt.Errorf("inspect policy report %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Result{}, fmt.Errorf("policy report %q is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("policy report %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open policy report %q: %w", path, err)
	}
	defer file.Close()
	return Parse(file, path, limits)
}

// Parse normalizes report failures without executing imported policy code.
func Parse(reader io.Reader, source string, limits Limits) (Result, error) {
	if strings.TrimSpace(source) == "" {
		return Result{}, errors.New("policy report source is required")
	}
	if limits.MaxBytes <= 0 || limits.MaxReports <= 0 || limits.MaxResults <= 0 {
		return Result{}, errors.New("all policy report limits must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(reader, limits.MaxBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read policy report: %w", err)
	}
	if int64(len(data)) > limits.MaxBytes {
		return Result{}, fmt.Errorf("policy report exceeds limit of %d bytes", limits.MaxBytes)
	}

	var root rawReport
	if err := json.Unmarshal(data, &root); err != nil {
		return Result{}, fmt.Errorf("decode policy report JSON: %w", err)
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
		if current.Kind == "List" {
			if current.APIVersion != "v1" {
				return Result{}, fmt.Errorf("unsupported PolicyReport list apiVersion %q", current.APIVersion)
			}
			queue = append(queue, current.Items...)
			continue
		}
		if current.APIVersion != supportedAPIVersion ||
			(current.Kind != "PolicyReport" && current.Kind != "ClusterPolicyReport") {
			return Result{}, fmt.Errorf(
				"unsupported PolicyReport object %s %s",
				current.APIVersion,
				current.Kind,
			)
		}
		reports++
		if reports > limits.MaxReports {
			return Result{}, fmt.Errorf("policy report count exceeds limit of %d", limits.MaxReports)
		}
		results += len(current.Results)
		if results > limits.MaxResults {
			return Result{}, fmt.Errorf("policy result count exceeds limit of %d", limits.MaxResults)
		}
		for _, policyResult := range current.Results {
			finding, include, err := normalizeResult(source, current.Scope, policyResult)
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
		return model.Finding{}, false, fmt.Errorf("unsupported policy result %q", cleanText(result.Result))
	}

	severity, err := policySeverity(result.Severity, outcome)
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
	target := scopeTarget(scope)
	titleTarget := policy
	if rule != "" {
		titleTarget += "/" + rule
	}
	if titleTarget == "" {
		titleTarget = "unnamed rule"
	}
	external := map[string]string{
		"policy": policy,
		"rule":   rule,
	}
	if category := cleanText(result.Category); category != "" {
		external["category"] = category
	}
	return model.Finding{
		ID:          "CP-POLICY-" + strings.ToUpper(hex.EncodeToString(sum[:6])),
		Severity:    severity,
		Title:       "External policy result: " + titleTarget,
		Description: "An imported PolicyReport recorded an external policy result requiring review; the original message is intentionally omitted.",
		Remediation: "Review the source policy and resource, document any approved exception, and re-run the policy engine.",
		Source:      "policyreport:" + reportSource,
		Target:      target,
		Location: model.Location{
			Path:     source,
			Resource: cleanText(scope.Kind) + "/" + cleanText(scope.Name),
		},
		Evidence: model.Evidence{
			Observed: "policy result: " + outcome,
			Expected: "policy result: pass",
		},
		ControlRefs:  []string{},
		ExternalRefs: external,
	}, true, nil
}

func policySeverity(raw, outcome string) (model.Severity, error) {
	if strings.TrimSpace(raw) != "" {
		severity, err := model.ParseSeverity(raw)
		if err != nil {
			return "", fmt.Errorf("invalid policy result severity: %w", err)
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
