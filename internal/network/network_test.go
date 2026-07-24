package network

import (
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
)

func workload(namespace, name string, labels map[string]string) manifest.Workload {
	return manifest.Workload{
		Kind:      "Deployment",
		Namespace: namespace,
		Name:      name,
		PodLabels: labels,
		PodSpec: manifest.PodSpec{
			Containers: []manifest.Container{{Name: "app", Image: "example/app:v1"}},
		},
	}
}

func defaultDeny(namespace string, policyTypes ...string) manifest.NetworkPolicy {
	return manifest.NetworkPolicy{
		Namespace:      namespace,
		Name:           "default-deny",
		SelectsAllPods: true,
		PolicyTypes:    policyTypes,
	}
}

func analyze(t *testing.T, workloads []manifest.Workload, policies []manifest.NetworkPolicy, services []manifest.Service) []model.Finding {
	t.Helper()
	findings, err := Analyze(workloads, policies, services, DefaultLimits())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}

func TestAnalyzeReportsMissingDefaultDeny(t *testing.T) {
	findings := analyze(t, []manifest.Workload{workload("payments", "api", nil)}, nil, nil)
	if len(findings) != 1 || findings[0].ID != "CP-NET-001" {
		t.Fatalf("findings = %#v", findings)
	}
	if !strings.Contains(findings[0].Evidence.Observed, "ingress") ||
		!strings.Contains(findings[0].Evidence.Observed, "egress") {
		t.Fatalf("evidence lacks directions: %q", findings[0].Evidence.Observed)
	}
}

func TestAnalyzePartialDefaultDenyReportsMissingDirection(t *testing.T) {
	findings := analyze(t,
		[]manifest.Workload{workload("payments", "api", nil)},
		[]manifest.NetworkPolicy{defaultDeny("payments", "Ingress")},
		nil,
	)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	observed := findings[0].Evidence.Observed
	if strings.Contains(observed, "ingress") || !strings.Contains(observed, "egress") {
		t.Fatalf("wrong missing directions: %q", observed)
	}
}

func TestAnalyzeFullDefaultDenyIsClean(t *testing.T) {
	findings := analyze(t,
		[]manifest.Workload{workload("payments", "api", nil)},
		[]manifest.NetworkPolicy{defaultDeny("payments", "Ingress", "Egress")},
		nil,
	)
	if len(findings) != 0 {
		t.Fatalf("covered namespace produced findings: %#v", findings)
	}
}

func TestAnalyzeNarrowPolicyIsNotDefaultDeny(t *testing.T) {
	narrow := manifest.NetworkPolicy{
		Namespace:         "payments",
		Name:              "allow-app",
		SelectsAllPods:    false,
		PodSelectorLabels: map[string]string{"app": "api"},
		PolicyTypes:       []string{"Ingress", "Egress"},
	}
	findings := analyze(t, []manifest.Workload{workload("payments", "api", nil)},
		[]manifest.NetworkPolicy{narrow}, nil)
	if len(findings) != 1 || findings[0].ID != "CP-NET-001" {
		t.Fatalf("narrow policy treated as default deny: %#v", findings)
	}
}

func TestAnalyzeEmptyPolicyTypesDefaultsToIngress(t *testing.T) {
	findings := analyze(t,
		[]manifest.Workload{workload("payments", "api", nil)},
		[]manifest.NetworkPolicy{defaultDeny("payments")},
		nil,
	)
	if len(findings) != 1 {
		t.Fatalf("findings = %#v", findings)
	}
	observed := findings[0].Evidence.Observed
	if strings.Contains(observed, "ingress") || !strings.Contains(observed, "egress") {
		t.Fatalf("empty policyTypes must count as Ingress only: %q", observed)
	}
}

func TestAnalyzeReportsExposedRiskyWorkload(t *testing.T) {
	risky := workload("payments", "legacy", map[string]string{"app": "legacy"})
	risky.PodSpec.HostNetwork = true
	privileged := true
	risky.PodSpec.Containers[0].SecurityContext.Privileged = &privileged

	services := []manifest.Service{{
		Namespace: "payments",
		Name:      "legacy-external",
		Type:      "LoadBalancer",
		Selector:  map[string]string{"app": "legacy"},
	}}
	policies := []manifest.NetworkPolicy{defaultDeny("payments", "Ingress", "Egress")}

	findings := analyze(t, []manifest.Workload{risky}, policies, services)
	if len(findings) != 1 || findings[0].ID != "CP-NET-002" {
		t.Fatalf("findings = %#v", findings)
	}
	observed := findings[0].Evidence.Observed
	if !strings.Contains(observed, "LoadBalancer") || !strings.Contains(observed, "hostNetwork") {
		t.Fatalf("evidence incomplete: %q", observed)
	}
}

func TestAnalyzeClusterIPServiceIsNotExposure(t *testing.T) {
	risky := workload("payments", "legacy", map[string]string{"app": "legacy"})
	risky.PodSpec.HostNetwork = true
	services := []manifest.Service{{
		Namespace: "payments", Name: "internal", Type: "ClusterIP",
		Selector: map[string]string{"app": "legacy"},
	}}
	policies := []manifest.NetworkPolicy{defaultDeny("payments", "Ingress", "Egress")}

	if findings := analyze(t, []manifest.Workload{risky}, policies, services); len(findings) != 0 {
		t.Fatalf("ClusterIP service reported as exposure: %#v", findings)
	}
}

func TestAnalyzeSelectorMustMatchNamespaceAndLabels(t *testing.T) {
	risky := workload("payments", "legacy", map[string]string{"app": "legacy"})
	risky.PodSpec.HostNetwork = true
	policies := []manifest.NetworkPolicy{
		defaultDeny("payments", "Ingress", "Egress"),
		defaultDeny("billing", "Ingress", "Egress"),
	}

	otherNamespace := []manifest.Service{{
		Namespace: "billing", Name: "external", Type: "LoadBalancer",
		Selector: map[string]string{"app": "legacy"},
	}}
	if findings := analyze(t, []manifest.Workload{risky}, policies, otherNamespace); len(findings) != 0 {
		t.Fatalf("cross-namespace selector matched: %#v", findings)
	}

	wrongLabels := []manifest.Service{{
		Namespace: "payments", Name: "external", Type: "LoadBalancer",
		Selector: map[string]string{"app": "modern"},
	}}
	if findings := analyze(t, []manifest.Workload{risky}, policies, wrongLabels); len(findings) != 0 {
		t.Fatalf("non-matching selector matched: %#v", findings)
	}

	selectorless := []manifest.Service{{
		Namespace: "payments", Name: "external", Type: "LoadBalancer",
	}}
	if findings := analyze(t, []manifest.Workload{risky}, policies, selectorless); len(findings) != 0 {
		t.Fatalf("selector-less service matched: %#v", findings)
	}
}

func TestAnalyzeHardenedExposedWorkloadIsClean(t *testing.T) {
	hardened := workload("payments", "api", map[string]string{"app": "api"})
	services := []manifest.Service{{
		Namespace: "payments", Name: "api-external", Type: "LoadBalancer",
		Selector: map[string]string{"app": "api"},
	}}
	policies := []manifest.NetworkPolicy{defaultDeny("payments", "Ingress", "Egress")}

	if findings := analyze(t, []manifest.Workload{hardened}, policies, services); len(findings) != 0 {
		t.Fatalf("hardened exposed workload produced findings: %#v", findings)
	}
}

func TestAnalyzeLimitsFailClosed(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxPolicies = 1
	policies := []manifest.NetworkPolicy{defaultDeny("a"), defaultDeny("b")}
	if _, err := Analyze(nil, policies, nil, limits); err == nil {
		t.Fatal("policy limit exceeded but Analyze succeeded")
	}
	limits = DefaultLimits()
	limits.MaxWorkloads = 0
	if _, err := Analyze(nil, nil, nil, limits); err == nil {
		t.Fatal("non-positive limit accepted")
	}
}
