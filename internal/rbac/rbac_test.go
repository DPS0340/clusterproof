package rbac

import (
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
)

func role(kind, namespace, name string, rules ...manifest.RBACRule) manifest.RBACRole {
	return manifest.RBACRole{Kind: kind, Namespace: namespace, Name: name, Rules: rules}
}

func binding(kind, namespace, name, roleKind, roleName string, subjects ...manifest.RBACSubject) manifest.RBACBinding {
	return manifest.RBACBinding{
		Kind: kind, Namespace: namespace, Name: name,
		RoleKind: roleKind, RoleName: roleName, Subjects: subjects,
	}
}

func serviceAccount(namespace, name string) manifest.RBACSubject {
	return manifest.RBACSubject{Kind: "ServiceAccount", Namespace: namespace, Name: name}
}

func analyze(t *testing.T, roles []manifest.RBACRole, bindings []manifest.RBACBinding) []model.Finding {
	t.Helper()
	findings, err := Analyze(roles, bindings, DefaultLimits())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}

func TestAnalyzeDetectsRiskPatterns(t *testing.T) {
	tests := []struct {
		name   string
		rule   manifest.RBACRule
		wantID string
	}{
		{
			name:   "full wildcard",
			rule:   manifest.RBACRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			wantID: "CP-RBAC-001",
		},
		{
			name:   "secrets read",
			rule:   manifest.RBACRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
			wantID: "CP-RBAC-002",
		},
		{
			name:   "workload creation",
			rule:   manifest.RBACRule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}},
			wantID: "CP-RBAC-003",
		},
		{
			name:   "pod exec",
			rule:   manifest.RBACRule{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
			wantID: "CP-RBAC-004",
		},
		{
			name:   "impersonation",
			rule:   manifest.RBACRule{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"}},
			wantID: "CP-RBAC-005",
		},
		{
			name:   "bind",
			rule:   manifest.RBACRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"bind"}},
			wantID: "CP-RBAC-006",
		},
		{
			name:   "escalate",
			rule:   manifest.RBACRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"escalate"}},
			wantID: "CP-RBAC-006",
		},
		{
			name:   "token creation",
			rule:   manifest.RBACRule{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}},
			wantID: "CP-RBAC-007",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roles := []manifest.RBACRole{role("ClusterRole", "", "risky", tt.rule)}
			bindings := []manifest.RBACBinding{binding(
				"ClusterRoleBinding", "", "risky-binding", "ClusterRole", "risky",
				serviceAccount("payments", "runner"),
			)}
			findings := analyze(t, roles, bindings)
			var found *model.Finding
			for index := range findings {
				if findings[index].ID == tt.wantID {
					found = &findings[index]
				}
			}
			if found == nil {
				t.Fatalf("finding %s not produced: %#v", tt.wantID, findings)
			}
			if found.Target != "payments/ServiceAccount/runner" {
				t.Fatalf("target = %q", found.Target)
			}
			if !strings.Contains(found.Evidence.Observed, "ClusterRoleBinding risky-binding") ||
				!strings.Contains(found.Evidence.Observed, "ClusterRole risky") {
				t.Fatalf("evidence lacks subject-to-role path: %q", found.Evidence.Observed)
			}
		})
	}
}

func TestAnalyzeSafeGrantsProduceNoFindings(t *testing.T) {
	roles := []manifest.RBACRole{role("Role", "payments", "reader",
		manifest.RBACRule{APIGroups: []string{""}, Resources: []string{"configmaps", "pods"}, Verbs: []string{"get", "list", "watch"}},
	)}
	bindings := []manifest.RBACBinding{binding(
		"RoleBinding", "payments", "reader-binding", "Role", "reader",
		serviceAccount("payments", "app"),
	)}
	if findings := analyze(t, roles, bindings); len(findings) != 0 {
		t.Fatalf("read-only grant produced findings: %#v", findings)
	}
}

func TestAnalyzeNamespacedRoleResolution(t *testing.T) {
	roles := []manifest.RBACRole{
		role("Role", "payments", "shared-name",
			manifest.RBACRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}),
		role("Role", "billing", "shared-name",
			manifest.RBACRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}),
	}
	bindings := []manifest.RBACBinding{binding(
		"RoleBinding", "billing", "safe-binding", "Role", "shared-name",
		serviceAccount("billing", "app"),
	)}
	if findings := analyze(t, roles, bindings); len(findings) != 0 {
		t.Fatalf("binding resolved a role from the wrong namespace: %#v", findings)
	}
}

func TestAnalyzeUnresolvedRoleIsSkipped(t *testing.T) {
	bindings := []manifest.RBACBinding{binding(
		"ClusterRoleBinding", "", "dangling", "ClusterRole", "not-collected",
		serviceAccount("payments", "app"),
	)}
	if findings := analyze(t, nil, bindings); len(findings) != 0 {
		t.Fatalf("dangling binding produced findings without role data: %#v", findings)
	}
}

func TestAnalyzeGroupAndUserSubjects(t *testing.T) {
	roles := []manifest.RBACRole{role("ClusterRole", "", "admin-like",
		manifest.RBACRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
	)}
	bindings := []manifest.RBACBinding{binding(
		"ClusterRoleBinding", "", "admins", "ClusterRole", "admin-like",
		manifest.RBACSubject{Kind: "Group", Name: "platform-admins"},
		manifest.RBACSubject{Kind: "User", Name: "root@example.com"},
	)}
	findings := analyze(t, roles, bindings)
	targets := make(map[string]bool)
	for _, finding := range findings {
		targets[finding.Target] = true
	}
	if !targets["Group/platform-admins"] || !targets["User/root@example.com"] {
		t.Fatalf("group/user subjects missing: %#v", targets)
	}
}

func TestAnalyzeLimitsFailClosed(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxBindings = 1
	bindings := []manifest.RBACBinding{
		binding("ClusterRoleBinding", "", "a", "ClusterRole", "x"),
		binding("ClusterRoleBinding", "", "b", "ClusterRole", "x"),
	}
	if _, err := Analyze(nil, bindings, limits); err == nil {
		t.Fatal("binding limit exceeded but Analyze succeeded")
	}

	limits = DefaultLimits()
	limits.MaxRoles = 0
	if _, err := Analyze(nil, nil, limits); err == nil {
		t.Fatal("non-positive limit accepted")
	}
}

func TestAnalyzeIsDeterministic(t *testing.T) {
	roles := []manifest.RBACRole{role("ClusterRole", "", "risky",
		manifest.RBACRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
	)}
	bindings := []manifest.RBACBinding{binding(
		"ClusterRoleBinding", "", "b", "ClusterRole", "risky",
		serviceAccount("z-namespace", "z"),
		serviceAccount("a-namespace", "a"),
	)}
	first := analyze(t, roles, bindings)
	second := analyze(t, roles, bindings)
	if len(first) != len(second) {
		t.Fatalf("nondeterministic count: %d vs %d", len(first), len(second))
	}
	for index := range first {
		if first[index].Target != second[index].Target {
			t.Fatalf("nondeterministic order at %d: %q vs %q", index, first[index].Target, second[index].Target)
		}
	}
	if first[0].Target != "a-namespace/ServiceAccount/a" {
		t.Fatalf("findings not sorted by target: %#v", first[0].Target)
	}
}
