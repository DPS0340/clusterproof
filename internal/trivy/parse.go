package trivy

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/kitae1645/clusterproof/internal/model"
)

type report struct {
	Results []result `json:"Results"`
}

type result struct {
	Target            string             `json:"Target"`
	Vulnerabilities   []vulnerability    `json:"Vulnerabilities"`
	Misconfigurations []misconfiguration `json:"Misconfigurations"`
	Secrets           []secretFinding    `json:"Secrets"`
}

type vulnerability struct {
	ID               string `json:"VulnerabilityID"`
	Package          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL"`
}

type misconfiguration struct {
	ID         string `json:"ID"`
	AVDID      string `json:"AVDID"`
	Title      string `json:"Title"`
	Resolution string `json:"Resolution"`
	Severity   string `json:"Severity"`
	Status     string `json:"Status"`
	PrimaryURL string `json:"PrimaryURL"`
	Cause      struct {
		Resource  string `json:"Resource"`
		StartLine int    `json:"StartLine"`
	} `json:"CauseMetadata"`
}

type secretFinding struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
}

// Parse normalizes bounded Trivy JSON and intentionally discards secret matches.
func Parse(reader io.Reader, maxBytes int64) ([]model.Finding, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("Trivy output limit must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Trivy output: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("Trivy output exceeds limit of %d bytes", maxBytes)
	}

	var decoded report
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("decode Trivy JSON: %w", err)
	}

	var findings []model.Finding
	for _, result := range decoded.Results {
		findings = append(findings, normalizeVulnerabilities(result)...)
		findings = append(findings, normalizeMisconfigurations(result)...)
		findings = append(findings, normalizeSecrets(result)...)
	}
	sortFindings(findings)
	return findings, nil
}

func normalizeVulnerabilities(result result) []model.Finding {
	findings := make([]model.Finding, 0, len(result.Vulnerabilities))
	for _, vulnerability := range result.Vulnerabilities {
		severity := normalizeSeverity(vulnerability.Severity)
		remediation := "Upgrade or replace the affected package after validating application compatibility."
		if vulnerability.FixedVersion != "" {
			remediation = "Upgrade " + cleanText(vulnerability.Package) + " to a fixed version such as " + cleanText(vulnerability.FixedVersion) + "."
		}
		external := map[string]string{
			"vulnerability": cleanText(vulnerability.ID),
		}
		if strings.HasPrefix(vulnerability.PrimaryURL, "https://") {
			external["advisory"] = vulnerability.PrimaryURL
		}
		findings = append(findings, model.Finding{
			ID:          "CP-VULN-001",
			Severity:    severity,
			Title:       "Known vulnerability: " + cleanText(vulnerability.ID),
			Description: "Trivy found a known vulnerability in package " + cleanText(vulnerability.Package) + ".",
			Remediation: remediation,
			Source:      "trivy",
			Target:      cleanTarget(result.Target),
			Location:    model.Location{Path: cleanTarget(result.Target)},
			Evidence: model.Evidence{
				Observed: "installed version " + cleanText(vulnerability.InstalledVersion),
				Expected: "patched or not affected",
			},
			ControlRefs:  []string{"SOC2:CC7", "Vulnerability-Management"},
			ExternalRefs: external,
		})
	}
	return findings
}

func normalizeMisconfigurations(result result) []model.Finding {
	var findings []model.Finding
	for _, misconfiguration := range result.Misconfigurations {
		if strings.EqualFold(misconfiguration.Status, "PASS") {
			continue
		}
		ruleID := misconfiguration.ID
		if ruleID == "" {
			ruleID = misconfiguration.AVDID
		}
		external := map[string]string{"trivy_rule": cleanText(ruleID)}
		if strings.HasPrefix(misconfiguration.PrimaryURL, "https://") {
			external["guidance"] = misconfiguration.PrimaryURL
		}
		remediation := cleanText(misconfiguration.Resolution)
		if remediation == "" {
			remediation = "Apply the safe configuration recommended by the scanner and re-run the check."
		}
		findings = append(findings, model.Finding{
			ID:          "CP-TRIVY-CONFIG-001",
			Severity:    normalizeSeverity(misconfiguration.Severity),
			Title:       cleanText(misconfiguration.Title),
			Description: "Trivy reported a failed infrastructure configuration check.",
			Remediation: remediation,
			Source:      "trivy",
			Target:      cleanTarget(result.Target),
			Location: model.Location{
				Path:     cleanTarget(result.Target),
				Line:     misconfiguration.Cause.StartLine,
				Resource: cleanText(misconfiguration.Cause.Resource),
			},
			Evidence:     model.Evidence{Observed: "failed check " + cleanText(ruleID), Expected: "check passes"},
			ControlRefs:  []string{"SOC2:CC6", "SOC2:CC7"},
			ExternalRefs: external,
		})
	}
	return findings
}

func normalizeSecrets(result result) []model.Finding {
	findings := make([]model.Finding, 0, len(result.Secrets))
	for _, secret := range result.Secrets {
		findings = append(findings, model.Finding{
			ID:          "CP-SECRET-001",
			Severity:    normalizeSeverity(secret.Severity),
			Title:       "Potential embedded secret: " + cleanText(secret.Title),
			Description: "Trivy detected a value matching a secret rule. The matched value is intentionally omitted.",
			Remediation: "Revoke the exposed credential, remove it from current and historical source, and use an approved secret store.",
			Source:      "trivy",
			Target:      cleanTarget(result.Target),
			Location:    model.Location{Path: cleanTarget(result.Target), Line: secret.StartLine},
			Evidence:    model.Evidence{Observed: "matched secret category " + cleanText(secret.Category), Expected: "no embedded credentials"},
			ControlRefs: []string{"SOC2:CC6", "Secret-Management"},
			ExternalRefs: map[string]string{
				"trivy_rule": cleanText(secret.RuleID),
			},
		})
	}
	return findings
}

func normalizeSeverity(raw string) model.Severity {
	severity, err := model.ParseSeverity(raw)
	if err != nil {
		return model.SeverityInfo
	}
	return severity
}

func cleanTarget(value string) string {
	cleaned := cleanText(value)
	at := strings.Index(cleaned, "@")
	colon := strings.Index(cleaned, ":")
	if at > 0 && colon >= 0 && colon < at {
		return "<redacted>@" + cleaned[at+1:]
	}
	return cleaned
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
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		return findings[i].Location.Line < findings[j].Location.Line
	})
}
