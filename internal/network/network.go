// Package network relates workloads to NetworkPolicies and Services within
// documented CNI-dependent limits.
package network

import (
	"fmt"
	"sort"
	"strings"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
)

// Limits bounds the analyzed network graph. Exceeding any limit fails closed.
type Limits struct {
	MaxPolicies  int
	MaxServices  int
	MaxWorkloads int
}

// DefaultLimits returns bounds suitable for large production clusters.
func DefaultLimits() Limits {
	return Limits{
		MaxPolicies:  10_000,
		MaxServices:  20_000,
		MaxWorkloads: 50_000,
	}
}

// Analyze reports default-deny gaps and external exposure of risky
// workloads. Findings describe declared policy objects only; ClusterProof
// never claims effective packet filtering because enforcement depends on
// the installed CNI.
func Analyze(
	workloads []manifest.Workload,
	policies []manifest.NetworkPolicy,
	services []manifest.Service,
	limits Limits,
) ([]model.Finding, error) {
	if limits.MaxPolicies <= 0 || limits.MaxServices <= 0 || limits.MaxWorkloads <= 0 {
		return nil, fmt.Errorf("all network limits must be positive")
	}
	if len(policies) > limits.MaxPolicies {
		return nil, fmt.Errorf("network input exceeds policy limit of %d", limits.MaxPolicies)
	}
	if len(services) > limits.MaxServices {
		return nil, fmt.Errorf("network input exceeds service limit of %d", limits.MaxServices)
	}
	if len(workloads) > limits.MaxWorkloads {
		return nil, fmt.Errorf("network input exceeds workload limit of %d", limits.MaxWorkloads)
	}

	var findings []model.Finding
	findings = append(findings, defaultDenyFindings(workloads, policies)...)
	findings = append(findings, exposureFindings(workloads, services)...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].Target < findings[j].Target
	})
	return findings, nil
}

// defaultDenyFindings reports namespaces that run workloads without any
// NetworkPolicy selecting all pods for a direction.
func defaultDenyFindings(workloads []manifest.Workload, policies []manifest.NetworkPolicy) []model.Finding {
	type coverage struct {
		ingress bool
		egress  bool
	}
	namespaceCoverage := make(map[string]*coverage)
	for _, policy := range policies {
		state := namespaceCoverage[policy.Namespace]
		if state == nil {
			state = &coverage{}
			namespaceCoverage[policy.Namespace] = state
		}
		if !policy.SelectsAllPods {
			continue // a narrow policy is not namespace-wide default deny
		}
		for _, policyType := range policy.PolicyTypes {
			switch strings.ToLower(policyType) {
			case "ingress":
				state.ingress = true
			case "egress":
				state.egress = true
			}
		}
		// A policy with an empty podSelector and no declared policyTypes
		// defaults to Ingress per the Kubernetes API.
		if len(policy.PolicyTypes) == 0 {
			state.ingress = true
		}
	}

	workloadNamespaces := make(map[string]manifest.Workload)
	for _, workload := range workloads {
		namespace := workload.Namespace
		if namespace == "" {
			namespace = "default"
		}
		if _, exists := workloadNamespaces[namespace]; !exists {
			workloadNamespaces[namespace] = workload
		}
	}

	names := make([]string, 0, len(workloadNamespaces))
	for namespace := range workloadNamespaces {
		names = append(names, namespace)
	}
	sort.Strings(names)

	var findings []model.Finding
	for _, namespace := range names {
		state := namespaceCoverage[namespace]
		missing := []string{}
		if state == nil || !state.ingress {
			missing = append(missing, "ingress")
		}
		if state == nil || !state.egress {
			missing = append(missing, "egress")
		}
		if len(missing) == 0 {
			continue
		}
		findings = append(findings, model.Finding{
			ID:          "CP-NET-001",
			Severity:    model.SeverityMedium,
			Title:       "Namespace lacks default-deny NetworkPolicy coverage",
			Description: "Without a namespace-wide policy, every pod accepts traffic that the CNI would otherwise filter.",
			Remediation: "Add a NetworkPolicy with an empty podSelector that declares both Ingress and Egress policy types.",
			Source:      "clusterproof",
			Target:      namespace + "/Namespace/" + namespace,
			Location:    workloadNamespaces[namespace].Location,
			Evidence: model.Evidence{
				Observed: "no all-pod policy for: " + strings.Join(missing, ", "),
				Expected: "default-deny ingress and egress policies",
			},
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:NetworkPolicy"},
			ExternalRefs: map[string]string{
				"guidance": "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
			},
		})
	}
	return findings
}

// exposureFindings reports externally reachable Services that select
// workloads with high-risk posture (host namespaces or privileged).
func exposureFindings(workloads []manifest.Workload, services []manifest.Service) []model.Finding {
	var findings []model.Finding
	for _, service := range services {
		if service.Type != "NodePort" && service.Type != "LoadBalancer" {
			continue
		}
		if len(service.Selector) == 0 {
			continue // selector-less services route to manual endpoints; no workload identity to assess
		}
		for _, workload := range workloads {
			workloadNamespace := workload.Namespace
			if workloadNamespace == "" {
				workloadNamespace = "default"
			}
			serviceNamespace := service.Namespace
			if serviceNamespace == "" {
				serviceNamespace = "default"
			}
			if workloadNamespace != serviceNamespace {
				continue
			}
			if !labelsMatch(service.Selector, workload.PodLabels) {
				continue
			}
			if risk := workloadRisk(workload); risk != "" {
				findings = append(findings, model.Finding{
					ID:          "CP-NET-002",
					Severity:    model.SeverityHigh,
					Title:       "High-risk workload exposed outside the cluster",
					Description: "An externally reachable Service selects a workload whose posture weakens node isolation.",
					Remediation: "Fix the workload posture or move it behind a ClusterIP Service and an authenticating proxy.",
					Source:      "clusterproof",
					Target:      workload.Target(),
					Location:    workload.Location,
					Evidence: model.Evidence{
						Observed: service.Type + " Service " + serviceNamespace + "/" + service.Name + " selects workload with " + risk,
						Expected: "external exposure only for hardened workloads",
					},
					ControlRefs: []string{"SOC2:CC6", "Kubernetes:NetworkPolicy"},
					ExternalRefs: map[string]string{
						"guidance": "https://kubernetes.io/docs/concepts/services-networking/network-policies/",
					},
				})
			}
		}
	}
	return findings
}

// labelsMatch reports whether every selector label appears in the pod labels.
func labelsMatch(selector, labels map[string]string) bool {
	if len(labels) == 0 {
		return false
	}
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func workloadRisk(workload manifest.Workload) string {
	var risks []string
	spec := workload.PodSpec
	if spec.HostNetwork {
		risks = append(risks, "hostNetwork")
	}
	if spec.HostPID {
		risks = append(risks, "hostPID")
	}
	for _, container := range spec.AllContainers() {
		if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			risks = append(risks, "privileged container "+container.Name)
		}
	}
	sort.Strings(risks)
	return strings.Join(risks, ", ")
}
