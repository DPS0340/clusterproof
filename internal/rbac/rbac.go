// Package rbac analyzes bounded RBAC grants for high-signal privilege paths
// without exposing credential data.
package rbac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
)

// Limits bounds the analyzed RBAC graph. Exceeding any limit fails closed.
type Limits struct {
	MaxRoles    int
	MaxBindings int
	MaxSubjects int
	MaxRules    int
}

// DefaultLimits returns bounds suitable for large production clusters.
func DefaultLimits() Limits {
	return Limits{
		MaxRoles:    10_000,
		MaxBindings: 20_000,
		MaxSubjects: 100_000,
		MaxRules:    100_000,
	}
}

// riskCheck defines one high-signal privilege pattern.
type riskCheck struct {
	id          string
	severity    model.Severity
	title       string
	description string
	remediation string
	expected    string
	matches     func(rule manifest.RBACRule) (string, bool)
}

var riskChecks = []riskCheck{
	{
		id:          "CP-RBAC-001",
		severity:    model.SeverityCritical,
		title:       "Wildcard permission grant",
		description: "A role granting * verbs on * resources is cluster-admin-equivalent for its scope.",
		remediation: "Replace wildcard verbs and resources with the explicit permissions the subject needs.",
		expected:    "explicit verbs and resources",
		matches: func(rule manifest.RBACRule) (string, bool) {
			if containsWildcard(rule.Verbs) && containsWildcard(rule.Resources) {
				return "verbs: [*], resources: [*]", true
			}
			return "", false
		},
	},
	{
		id:          "CP-RBAC-002",
		severity:    model.SeverityHigh,
		title:       "Secrets read access granted",
		description: "Reading Secrets exposes every credential in the grant's scope.",
		remediation: "Scope Secret access to named resources or use projected volumes and workload identity.",
		expected:    "no broad Secret read access",
		matches: func(rule manifest.RBACRule) (string, bool) {
			if !matchesResource(rule, "", "secrets") {
				return "", false
			}
			if verbs := readVerbs(rule.Verbs); len(verbs) > 0 {
				return "secrets: " + strings.Join(verbs, ", "), true
			}
			return "", false
		},
	},
	{
		id:          "CP-RBAC-003",
		severity:    model.SeverityHigh,
		title:       "Workload creation privilege",
		description: "Creating workloads lets a subject run arbitrary pods, including privileged ones, in scope.",
		remediation: "Restrict workload creation to deployment automation with reviewed pipelines.",
		expected:    "workload creation limited to deploy automation",
		matches: func(rule manifest.RBACRule) (string, bool) {
			targets := map[string]string{
				"pods":         "",
				"deployments":  "apps",
				"daemonsets":   "apps",
				"statefulsets": "apps",
				"replicasets":  "apps",
				"jobs":         "batch",
				"cronjobs":     "batch",
			}
			var matched []string
			for resource, group := range targets {
				if matchesResource(rule, group, resource) && hasVerb(rule.Verbs, "create") {
					matched = append(matched, resource)
				}
			}
			if len(matched) > 0 {
				sort.Strings(matched)
				return "create: " + strings.Join(matched, ", "), true
			}
			return "", false
		},
	},
	{
		id:          "CP-RBAC-004",
		severity:    model.SeverityHigh,
		title:       "Pod exec privilege",
		description: "pods/exec provides interactive code execution inside every reachable container.",
		remediation: "Limit exec to break-glass roles with audit logging.",
		expected:    "no standing pods/exec access",
		matches: func(rule manifest.RBACRule) (string, bool) {
			if matchesResource(rule, "", "pods/exec") && (hasVerb(rule.Verbs, "create") || hasVerb(rule.Verbs, "get")) {
				return "pods/exec granted", true
			}
			return "", false
		},
	},
	{
		id:          "CP-RBAC-005",
		severity:    model.SeverityHigh,
		title:       "Impersonation privilege",
		description: "Impersonation lets the subject act as any user or group it can name, bypassing its own authorization.",
		remediation: "Remove impersonate verbs outside dedicated, audited administrative tooling.",
		expected:    "no impersonate verbs",
		matches: func(rule manifest.RBACRule) (string, bool) {
			if hasVerb(rule.Verbs, "impersonate") {
				return "impersonate: " + strings.Join(lowerAll(rule.Resources), ", "), true
			}
			return "", false
		},
	},
	{
		id:          "CP-RBAC-006",
		severity:    model.SeverityHigh,
		title:       "Bind or escalate privilege",
		description: "bind and escalate allow granting permissions beyond the subject's own, defeating RBAC containment.",
		remediation: "Reserve bind and escalate for the cluster's role-management controller.",
		expected:    "no bind or escalate verbs",
		matches: func(rule manifest.RBACRule) (string, bool) {
			var verbs []string
			if hasVerb(rule.Verbs, "bind") {
				verbs = append(verbs, "bind")
			}
			if hasVerb(rule.Verbs, "escalate") {
				verbs = append(verbs, "escalate")
			}
			if len(verbs) > 0 {
				return strings.Join(verbs, ", ") + " granted", true
			}
			return "", false
		},
	},
	{
		id:          "CP-RBAC-007",
		severity:    model.SeverityMedium,
		title:       "Service account token creation privilege",
		description: "serviceaccounts/token lets the subject mint credentials for other identities.",
		remediation: "Remove token creation or scope it to the specific automation account that needs it.",
		expected:    "no serviceaccounts/token creation",
		matches: func(rule manifest.RBACRule) (string, bool) {
			if matchesResource(rule, "", "serviceaccounts/token") && hasVerb(rule.Verbs, "create") {
				return "serviceaccounts/token: create", true
			}
			return "", false
		},
	},
}

// Analyze evaluates normalized RBAC objects and returns findings that
// identify the subject-to-role path for each risky grant.
func Analyze(roles []manifest.RBACRole, bindings []manifest.RBACBinding, limits Limits) ([]model.Finding, error) {
	if limits.MaxRoles <= 0 || limits.MaxBindings <= 0 || limits.MaxSubjects <= 0 || limits.MaxRules <= 0 {
		return nil, fmt.Errorf("all RBAC limits must be positive")
	}
	if len(roles) > limits.MaxRoles {
		return nil, fmt.Errorf("RBAC input exceeds role limit of %d", limits.MaxRoles)
	}
	if len(bindings) > limits.MaxBindings {
		return nil, fmt.Errorf("RBAC input exceeds binding limit of %d", limits.MaxBindings)
	}
	subjects, rules := 0, 0
	for _, binding := range bindings {
		subjects += len(binding.Subjects)
	}
	if subjects > limits.MaxSubjects {
		return nil, fmt.Errorf("RBAC input exceeds subject limit of %d", limits.MaxSubjects)
	}
	for _, role := range roles {
		rules += len(role.Rules)
	}
	if rules > limits.MaxRules {
		return nil, fmt.Errorf("RBAC input exceeds rule limit of %d", limits.MaxRules)
	}

	// Index roles by kind and identity for binding resolution. Bindings in a
	// namespace may reference a Role in the same namespace or a ClusterRole.
	roleIndex := make(map[string]manifest.RBACRole, len(roles))
	for _, role := range roles {
		roleIndex[roleKey(role.Kind, role.Namespace, role.Name)] = role
	}

	var findings []model.Finding
	for _, binding := range bindings {
		role, resolved := resolveRole(roleIndex, binding)
		if !resolved {
			continue // the referenced role was not collected; do not guess
		}
		scope := "namespace " + binding.Namespace
		if binding.Kind == "ClusterRoleBinding" {
			scope = "cluster-wide"
		}
		for _, check := range riskChecks {
			observed, matched := matchRole(role, check)
			if !matched {
				continue
			}
			for _, subject := range binding.Subjects {
				findings = append(findings, model.Finding{
					ID:          check.id,
					Severity:    check.severity,
					Title:       check.title,
					Description: check.description,
					Remediation: check.remediation,
					Source:      "clusterproof",
					Target:      subjectTarget(subject),
					Location:    binding.Location,
					Evidence: model.Evidence{
						Observed: fmt.Sprintf("%s -> %s %s (%s): %s",
							bindingPath(binding), role.Kind, role.Name, scope, observed),
						Expected: check.expected,
					},
					ControlRefs: []string{"SOC2:CC6", "Kubernetes:RBAC-Good-Practices"},
					ExternalRefs: map[string]string{
						"guidance": "https://kubernetes.io/docs/concepts/security/rbac-good-practices/",
					},
				})
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Target != findings[j].Target {
			return findings[i].Target < findings[j].Target
		}
		return findings[i].Evidence.Observed < findings[j].Evidence.Observed
	})
	return findings, nil
}

func matchRole(role manifest.RBACRole, check riskCheck) (string, bool) {
	var observations []string
	for _, rule := range role.Rules {
		if observed, matched := check.matches(rule); matched {
			observations = append(observations, observed)
		}
	}
	if len(observations) == 0 {
		return "", false
	}
	sort.Strings(observations)
	return strings.Join(dedupe(observations), "; "), true
}

func resolveRole(index map[string]manifest.RBACRole, binding manifest.RBACBinding) (manifest.RBACRole, bool) {
	if binding.RoleKind == "ClusterRole" {
		role, ok := index[roleKey("ClusterRole", "", binding.RoleName)]
		return role, ok
	}
	role, ok := index[roleKey("Role", binding.Namespace, binding.RoleName)]
	return role, ok
}

func roleKey(kind, namespace, name string) string {
	return kind + "\x00" + namespace + "\x00" + name
}

func bindingPath(binding manifest.RBACBinding) string {
	if binding.Namespace != "" {
		return binding.Kind + " " + binding.Namespace + "/" + binding.Name
	}
	return binding.Kind + " " + binding.Name
}

func subjectTarget(subject manifest.RBACSubject) string {
	if subject.Kind == "ServiceAccount" && subject.Namespace != "" {
		return subject.Namespace + "/ServiceAccount/" + subject.Name
	}
	return subject.Kind + "/" + subject.Name
}

func containsWildcard(values []string) bool {
	for _, value := range values {
		if value == "*" {
			return true
		}
	}
	return false
}

func matchesResource(rule manifest.RBACRule, group, resource string) bool {
	groupMatched := len(rule.APIGroups) == 0
	for _, apiGroup := range rule.APIGroups {
		if apiGroup == "*" || strings.EqualFold(apiGroup, group) {
			groupMatched = true
			break
		}
	}
	if !groupMatched {
		return false
	}
	for _, candidate := range rule.Resources {
		if candidate == "*" || strings.EqualFold(candidate, resource) {
			return true
		}
	}
	return false
}

func hasVerb(verbs []string, verb string) bool {
	for _, candidate := range verbs {
		if candidate == "*" || strings.EqualFold(candidate, verb) {
			return true
		}
	}
	return false
}

func readVerbs(verbs []string) []string {
	var matched []string
	for _, verb := range []string{"get", "list", "watch"} {
		if hasVerb(verbs, verb) {
			matched = append(matched, verb)
		}
	}
	return matched
}

func lowerAll(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, strings.ToLower(value))
	}
	sort.Strings(result)
	return result
}

func dedupe(sorted []string) []string {
	result := sorted[:0]
	var previous string
	for index, value := range sorted {
		if index == 0 || value != previous {
			result = append(result, value)
		}
		previous = value
	}
	return result
}
