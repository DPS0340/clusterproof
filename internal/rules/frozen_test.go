package rules

import "testing"

// frozenRuleIDs is the append-only registry of every rule ID ever released
// together with the exact title it shipped with. AGENTS.md forbids reusing
// an ID for a different rule; this test turns that policy into a gate.
//
// Adding a new rule requires adding it here. Changing or deleting an
// existing entry requires a schema-major decision, not a code review nit.
var frozenRuleIDs = map[string]string{
	"CP-K8S-001":    "Privileged container",
	"CP-K8S-002":    "Host namespace sharing enabled",
	"CP-K8S-003":    "Host filesystem mounted into workload",
	"CP-K8S-004":    "Privilege escalation is not disabled",
	"CP-K8S-005":    "Non-root execution is not guaranteed",
	"CP-K8S-006":    "Seccomp isolation is not enforced",
	"CP-K8S-007":    "Additional Linux capabilities requested",
	"CP-K8S-008":    "Default Linux capabilities are not dropped",
	"CP-K8S-009":    "Container root filesystem is writable",
	"CP-K8S-010":    "Service account token is automatically mounted",
	"CP-K8S-011":    "Host port binding requested",
	"CP-K8S-012":    "Volume type outside the restricted allowlist",
	"CP-K8S-013":    "Non-default proc mount requested",
	"CP-K8S-014":    "Sysctl outside the safe allowlist requested",
	"CP-K8S-015":    "AppArmor profile is overridden to an unconfined state",
	"CP-K8S-016":    "Disallowed SELinux options requested",
	"CP-K8S-017":    "Windows HostProcess pod requested",
	"CP-K8S-018":    "Namespace has no Pod Security Admission enforce level",
	"CP-K8S-019":    "Namespace Pod Security Admission level is not a defined value",
	"CP-K8S-020":    "Namespace explicitly enforces the privileged profile",
	"CP-K8S-021":    "Pod Security Admission version is not pinned",
	"CP-K8S-022":    "Audit or warn level is weaker than the enforce level",
	"CP-RBAC-001":   "Wildcard permission grant",
	"CP-RBAC-002":   "Secrets read access granted",
	"CP-RBAC-003":   "Workload creation privilege",
	"CP-RBAC-004":   "Pod exec privilege",
	"CP-RBAC-005":   "Impersonation privilege",
	"CP-RBAC-006":   "Bind or escalate privilege",
	"CP-RBAC-007":   "Service account token creation privilege",
	"CP-NET-001":    "Namespace lacks default-deny NetworkPolicy coverage",
	"CP-NET-002":    "High-risk workload exposed outside the cluster",
	"CP-SUPPLY-001": "Container image uses a mutable latest tag",
	"CP-SUPPLY-002": "Container image is not digest pinned",
}

// TestRuleIDsAreFrozen proves no released rule ID is removed, retitled to
// mean something different, or reused, and that every catalog rule is
// registered in the frozen list.
func TestRuleIDsAreFrozen(t *testing.T) {
	catalog := DefaultCatalog()
	seen := make(map[string]struct{}, len(catalog.Rules))
	for _, rule := range catalog.Rules {
		seen[rule.ID] = struct{}{}
		frozenTitle, registered := frozenRuleIDs[rule.ID]
		if !registered {
			t.Errorf("rule %s is not in the frozen registry; new rules must be registered", rule.ID)
			continue
		}
		if frozenTitle != rule.Title {
			t.Errorf("rule %s title changed from %q to %q; IDs must never be reused for a different rule",
				rule.ID, frozenTitle, rule.Title)
		}
	}
	for id := range frozenRuleIDs {
		if _, exists := seen[id]; !exists {
			t.Errorf("released rule %s disappeared from the catalog; removal requires a schema-major decision", id)
		}
	}
}
