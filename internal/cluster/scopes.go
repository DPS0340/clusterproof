package cluster

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/DPS0340/clusterproof/internal/manifest"
)

// ScopeContractVersion identifies the read-allowlist contract. Any change to
// a scope's resource list requires bumping this version.
const ScopeContractVersion = "1"

// ScopeWorkloads is the default read-only workload snapshot scope.
const ScopeWorkloads = "workloads"

// ScopeNamespaces reads Namespace metadata only, for Pod Security Admission
// label assessment. No namespaced payload object is requested.
const ScopeNamespaces = "namespaces"

// ScopeRBAC reads Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings
// for privilege-path analysis. No Secret or credential data is requested.
const ScopeRBAC = "rbac"

// scopeResources is the fixed, versioned read allowlist. Verbs are never
// configurable: every scope is exactly one bounded kubectl get.
var scopeResources = map[string]string{
	ScopeWorkloads:  workloadResources,
	ScopeNamespaces: "namespaces",
	ScopeRBAC:       "roles.rbac.authorization.k8s.io,clusterroles.rbac.authorization.k8s.io,rolebindings.rbac.authorization.k8s.io,clusterrolebindings.rbac.authorization.k8s.io",
}

// ScopeNames returns the sorted names of every defined scope.
func ScopeNames() []string {
	names := make([]string, 0, len(scopeResources))
	for name := range scopeResources {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ScopeStatus is the honest collection outcome of one requested scope.
type ScopeStatus struct {
	// Scope is the requested scope name.
	Scope string `json:"scope"`
	// Resources is the exact fixed resource argument of the scope.
	Resources string `json:"resources"`
	// Status is collected, denied, or absent. A denied or absent scope was
	// not assessed; its resources must never appear clean.
	Status string `json:"status"`
	// Detail carries a cleaned, bounded diagnostic for non-collected scopes.
	Detail string `json:"detail,omitempty"`
}

// Scope collection statuses.
const (
	ScopeStatusCollected = "collected"
	ScopeStatusDenied    = "denied"
	ScopeStatusAbsent    = "absent"
)

// ScopedResult aggregates per-scope snapshots and their statuses.
type ScopedResult struct {
	Result manifest.Result
	Scopes []ScopeStatus
}

// ScopeArgs returns the fixed read-only kubectl invocation for one scope.
func ScopeArgs(options Options, scope string) []string {
	resources := scopeResources[scope]
	args := []string{"--kubeconfig", options.Kubeconfig}
	if options.Context != "" {
		args = append(args, "--context", options.Context)
	}
	args = append(args, "get", resources)
	switch scope {
	case ScopeNamespaces:
		// Namespace metadata is cluster-scoped; no namespace flag applies.
	case ScopeRBAC:
		// ClusterRoles and ClusterRoleBindings are cluster-scoped, so the
		// combined RBAC read always spans all namespaces for the namespaced
		// kinds; a namespace filter would silently hide bindings.
		args = append(args, "--all-namespaces")
	default:
		if options.Namespace == "" {
			args = append(args, "--all-namespaces")
		} else {
			args = append(args, "--namespace", options.Namespace)
		}
	}
	return append(args,
		"--output=yaml",
		"--show-managed-fields=false",
		"--request-timeout="+options.Timeout.String(),
	)
}

// CollectScopes collects every requested scope with the fixed allowlist.
// A permission or missing-resource failure in one scope is recorded as a
// partial assessment instead of failing the entire scan; any other failure
// aborts, because silently dropping a scope would misrepresent coverage.
func CollectScopes(ctx context.Context, options Options, scopes []string) (ScopedResult, error) {
	if len(scopes) == 0 {
		return ScopedResult{}, fmt.Errorf("at least one collection scope is required")
	}
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if _, known := scopeResources[scope]; !known {
			return ScopedResult{}, fmt.Errorf(
				"unknown scope %q; defined scopes: %s", scope, strings.Join(ScopeNames(), ", "))
		}
		if _, duplicate := seen[scope]; duplicate {
			return ScopedResult{}, fmt.Errorf("scope %q requested more than once", scope)
		}
		seen[scope] = struct{}{}
	}

	var aggregate ScopedResult
	for _, scope := range scopes {
		result, err := collectScope(ctx, options, scope)
		if err != nil {
			status, detail, partial := classifyCollectionError(err)
			if !partial {
				return ScopedResult{}, fmt.Errorf("collect scope %s: %w", scope, err)
			}
			aggregate.Scopes = append(aggregate.Scopes, ScopeStatus{
				Scope:     scope,
				Resources: scopeResources[scope],
				Status:    status,
				Detail:    detail,
			})
			continue
		}
		aggregate.Result.Workloads = append(aggregate.Result.Workloads, result.Workloads...)
		aggregate.Result.Namespaces = append(aggregate.Result.Namespaces, result.Namespaces...)
		aggregate.Result.RBACRoles = append(aggregate.Result.RBACRoles, result.RBACRoles...)
		aggregate.Result.RBACBindings = append(aggregate.Result.RBACBindings, result.RBACBindings...)
		aggregate.Result.Inputs = append(aggregate.Result.Inputs, result.Inputs...)
		aggregate.Scopes = append(aggregate.Scopes, ScopeStatus{
			Scope:     scope,
			Resources: scopeResources[scope],
			Status:    ScopeStatusCollected,
		})
	}
	return aggregate, nil
}

// classifyCollectionError distinguishes partial-assessment outcomes from
// operational failures. Only authorization denial and an absent resource
// type continue as partial; everything else must abort the scan.
func classifyCollectionError(err error) (status, detail string, partial bool) {
	message := err.Error()
	lowered := strings.ToLower(message)
	switch {
	case strings.Contains(lowered, "forbidden") || strings.Contains(lowered, "cannot list"):
		return ScopeStatusDenied, cleanText(message), true
	case strings.Contains(lowered, "doesn't have a resource type") ||
		strings.Contains(lowered, "the server could not find the requested resource"):
		return ScopeStatusAbsent, cleanText(message), true
	default:
		return "", "", false
	}
}

func collectScope(ctx context.Context, options Options, scope string) (manifest.Result, error) {
	return runCollection(ctx, options, ScopeArgs(options, scope), scope)
}
