package rules

import (
	"testing"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
)

func compliantNamespace() manifest.Namespace {
	return manifest.Namespace{
		Name: "payments",
		Labels: map[string]string{
			"pod-security.kubernetes.io/enforce":         "restricted",
			"pod-security.kubernetes.io/enforce-version": "v1.36",
			"pod-security.kubernetes.io/audit":           "restricted",
			"pod-security.kubernetes.io/warn":            "restricted",
		},
	}
}

func TestEvaluateNamespacesCleanConfiguration(t *testing.T) {
	findings := EvaluateNamespaces([]manifest.Namespace{compliantNamespace()})
	if len(findings) != 0 {
		t.Fatalf("pinned restricted namespace produced findings: %#v", findings)
	}
}

func TestEvaluateNamespacesPSAStates(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*manifest.Namespace)
		wantID   string
		severity model.Severity
	}{
		{
			name: "missing enforce label",
			mutate: func(namespace *manifest.Namespace) {
				delete(namespace.Labels, "pod-security.kubernetes.io/enforce")
			},
			wantID:   "CP-K8S-018",
			severity: model.SeverityMedium,
		},
		{
			name: "undefined enforce level",
			mutate: func(namespace *manifest.Namespace) {
				namespace.Labels["pod-security.kubernetes.io/enforce"] = "unrestricted"
			},
			wantID:   "CP-K8S-019",
			severity: model.SeverityMedium,
		},
		{
			name: "privileged enforce level",
			mutate: func(namespace *manifest.Namespace) {
				namespace.Labels["pod-security.kubernetes.io/enforce"] = "privileged"
			},
			wantID:   "CP-K8S-020",
			severity: model.SeverityLow,
		},
		{
			name: "missing version pin",
			mutate: func(namespace *manifest.Namespace) {
				delete(namespace.Labels, "pod-security.kubernetes.io/enforce-version")
			},
			wantID:   "CP-K8S-021",
			severity: model.SeverityLow,
		},
		{
			name: "latest version pin",
			mutate: func(namespace *manifest.Namespace) {
				namespace.Labels["pod-security.kubernetes.io/enforce-version"] = "latest"
			},
			wantID:   "CP-K8S-021",
			severity: model.SeverityLow,
		},
		{
			name: "weaker audit mode",
			mutate: func(namespace *manifest.Namespace) {
				namespace.Labels["pod-security.kubernetes.io/audit"] = "privileged"
			},
			wantID:   "CP-K8S-022",
			severity: model.SeverityLow,
		},
		{
			name: "weaker warn mode",
			mutate: func(namespace *manifest.Namespace) {
				namespace.Labels["pod-security.kubernetes.io/warn"] = "baseline"
			},
			wantID:   "CP-K8S-022",
			severity: model.SeverityLow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := compliantNamespace()
			tt.mutate(&namespace)

			finding, ok := findByID(EvaluateNamespaces([]manifest.Namespace{namespace}), tt.wantID)
			if !ok {
				t.Fatalf("finding %s not produced", tt.wantID)
			}
			if finding.Severity != tt.severity {
				t.Fatalf("severity = %s, want %s", finding.Severity, tt.severity)
			}
			if finding.Remediation == "" || len(finding.ControlRefs) == 0 {
				t.Fatalf("finding lacks remediation or control refs: %#v", finding)
			}
		})
	}
}

func TestEvaluateNamespacesSkipsSystemNamespaces(t *testing.T) {
	for _, name := range []string{"kube-system", "kube-public", "kube-node-lease"} {
		findings := EvaluateNamespaces([]manifest.Namespace{{Name: name}})
		if len(findings) != 0 {
			t.Fatalf("system namespace %s produced findings: %#v", name, findings)
		}
	}
}

func TestEvaluateNamespacesAbsentAuxiliaryModesAreNotWeaker(t *testing.T) {
	namespace := compliantNamespace()
	delete(namespace.Labels, "pod-security.kubernetes.io/audit")
	delete(namespace.Labels, "pod-security.kubernetes.io/warn")

	if _, ok := findByID(EvaluateNamespaces([]manifest.Namespace{namespace}), "CP-K8S-022"); ok {
		t.Fatal("absent audit/warn labels must not be reported as weaker modes")
	}
}
