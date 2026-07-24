package rules

import (
	"sort"
	"strings"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
)

// PSA label keys defined by Kubernetes Pod Security Admission.
const (
	psaEnforceLabel        = "pod-security.kubernetes.io/enforce"
	psaEnforceVersionLabel = "pod-security.kubernetes.io/enforce-version"
	psaAuditLabel          = "pod-security.kubernetes.io/audit"
	psaWarnLabel           = "pod-security.kubernetes.io/warn"
)

var psaLevels = map[string]int{
	"privileged": 0,
	"baseline":   1,
	"restricted": 2,
}

// EvaluateNamespaces assesses Pod Security Admission labels on collected
// Namespace metadata. It observes only labels and never namespace payloads.
func EvaluateNamespaces(namespaces []manifest.Namespace) []model.Finding {
	var findings []model.Finding
	for _, namespace := range namespaces {
		findings = append(findings, evaluateNamespacePSA(namespace)...)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Target < findings[j].Target
	})
	return findings
}

func evaluateNamespacePSA(namespace manifest.Namespace) []model.Finding {
	if isSystemNamespace(namespace.Name) {
		// Control-plane namespaces are commonly exempted by the admission
		// configuration itself; labeling them is an operator decision, not a
		// per-namespace defect. Recording them as findings would train users
		// to ignore the rule.
		return nil
	}

	var findings []model.Finding
	enforce := namespace.Labels[psaEnforceLabel]

	if enforce == "" {
		findings = append(findings, namespaceFinding(
			namespace,
			"CP-K8S-018", model.SeverityMedium,
			"Namespace has no Pod Security Admission enforce level",
			"Without an enforce label, the namespace admits pods that violate every Pod Security Standard.",
			"Set pod-security.kubernetes.io/enforce to baseline or restricted on the namespace.",
			model.Evidence{Observed: "enforce label absent", Expected: "enforce: baseline or restricted"},
		))
	} else if psaLevels[enforce] == 0 && enforce != "privileged" {
		findings = append(findings, namespaceFinding(
			namespace,
			"CP-K8S-019", model.SeverityMedium,
			"Namespace Pod Security Admission level is not a defined value",
			"An unrecognized enforce level is rejected by the admission controller and behaves like no enforcement.",
			"Use privileged, baseline, or restricted as the enforce level.",
			model.Evidence{Observed: "enforce: " + enforce, Expected: "a defined PSA level"},
		))
	} else if enforce == "privileged" {
		findings = append(findings, namespaceFinding(
			namespace,
			"CP-K8S-020", model.SeverityLow,
			"Namespace explicitly enforces the privileged profile",
			"The privileged profile is intentionally unrestricted; workloads in this namespace bypass all PSS controls.",
			"Confirm the namespace requires privileged workloads or raise the enforce level to baseline.",
			model.Evidence{Observed: "enforce: privileged", Expected: "baseline or restricted unless reviewed"},
		))
	}

	if enforceVersion := namespace.Labels[psaEnforceVersionLabel]; enforceVersion == "" || strings.EqualFold(enforceVersion, "latest") {
		observed := "enforce-version label absent"
		if enforceVersion != "" {
			observed = "enforce-version: " + enforceVersion
		}
		findings = append(findings, namespaceFinding(
			namespace,
			"CP-K8S-021", model.SeverityLow,
			"Pod Security Admission version is not pinned",
			"An unpinned or latest policy version silently changes admission behavior on cluster upgrades.",
			"Set pod-security.kubernetes.io/enforce-version to the tested Kubernetes minor, such as v1.36.",
			model.Evidence{Observed: observed, Expected: "a pinned version like v1.36"},
		))
	}

	if weaker := weakerAuxiliaryModes(namespace.Labels); len(weaker) > 0 {
		findings = append(findings, namespaceFinding(
			namespace,
			"CP-K8S-022", model.SeverityLow,
			"Audit or warn level is weaker than the enforce level",
			"Weaker audit or warn levels hide violations that the next enforce-level increase would reject.",
			"Set audit and warn to at least the enforce level.",
			model.Evidence{Observed: strings.Join(weaker, ", "), Expected: "audit and warn at or above enforce"},
		))
	}
	return findings
}

func weakerAuxiliaryModes(labels map[string]string) []string {
	enforce, defined := psaLevels[labels[psaEnforceLabel]]
	if !defined {
		return nil
	}
	var weaker []string
	for _, label := range []string{psaAuditLabel, psaWarnLabel} {
		value := labels[label]
		if value == "" {
			continue // absent auxiliary modes default to privileged upstream but are covered by enforce
		}
		level, known := psaLevels[value]
		if known && level < enforce {
			weaker = append(weaker, strings.TrimPrefix(label, "pod-security.kubernetes.io/")+": "+value)
		}
	}
	sort.Strings(weaker)
	return weaker
}

func isSystemNamespace(name string) bool {
	return name == "kube-system" || name == "kube-public" || name == "kube-node-lease"
}

func namespaceFinding(
	namespace manifest.Namespace,
	id string,
	severity model.Severity,
	title, description, remediation string,
	evidence model.Evidence,
) model.Finding {
	return model.Finding{
		ID:          id,
		Severity:    severity,
		Title:       title,
		Description: description,
		Remediation: remediation,
		Source:      "clusterproof",
		Target:      namespace.Name + "/Namespace/" + namespace.Name,
		Location:    namespace.Location,
		Evidence:    evidence,
		ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSA"},
		ExternalRefs: map[string]string{
			"guidance": "https://kubernetes.io/docs/concepts/security/pod-security-admission/",
		},
	}
}
