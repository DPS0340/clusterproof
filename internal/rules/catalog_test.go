package rules

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
	"github.com/DPS0340/clusterproof/internal/rbac"
)

func TestDefaultCatalogCoversEveryNativeFinding(t *testing.T) {
	privileged := true
	hostProcess := true
	procMount := "Unmasked"
	workload := manifest.Workload{
		Kind: "Pod",
		Name: "all-rules",
		PodSpec: manifest.PodSpec{
			HostNetwork: true,
			Volumes: []manifest.Volume{
				{
					Name:     "host",
					HostPath: &manifest.HostPath{Path: "/"},
					Types:    []string{"hostPath"},
				},
				{Name: "legacy", Types: []string{"nfs"}},
			},
			SecurityContext: manifest.SecurityContext{
				Sysctls:         []manifest.Sysctl{{Name: "kernel.msgmax", Value: "65536"}},
				AppArmorProfile: &manifest.AppArmor{Type: "Unconfined"},
				SELinuxOptions:  &manifest.SELinux{Type: "spc_t"},
				WindowsOptions:  &manifest.WindowsOpts{HostProcess: &hostProcess},
			},
			Containers: []manifest.Container{{
				Name:  "app",
				Image: "example/app:latest",
				Ports: []manifest.ContainerPort{{ContainerPort: 8080, HostPort: 8080}},
				SecurityContext: manifest.SecurityContext{
					Privileged: &privileged,
					ProcMount:  &procMount,
					SeccompProfile: manifest.Seccomp{
						Type: "Unconfined",
					},
					Capabilities: manifest.Capabilities{
						Add: []string{"SYS_ADMIN"},
					},
				},
			}},
		},
	}

	findings := Evaluate(workload)
	findings = append(findings, EvaluateNamespaces(allPSAViolationsNamespaces())...)
	findings = append(findings, allRBACFindings(t)...)
	emitted := make([]string, 0, len(findings))
	for _, finding := range findings {
		emitted = append(emitted, finding.ID)
	}
	sort.Strings(emitted)

	catalog := DefaultCatalog()
	registered := make([]string, 0, len(catalog.Rules))
	seen := make(map[string]struct{})
	definitions := make(map[string]RuleDefinition)
	for _, rule := range catalog.Rules {
		if _, exists := seen[rule.ID]; exists {
			t.Fatalf("duplicate catalog rule %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		definitions[rule.ID] = rule
		registered = append(registered, rule.ID)
	}
	sort.Strings(registered)

	if !reflect.DeepEqual(registered, emitted) {
		t.Fatalf("catalog IDs = %#v, emitted IDs = %#v", registered, emitted)
	}
	for _, finding := range findings {
		definition := definitions[finding.ID]
		if definition.Title != finding.Title || !reflect.DeepEqual(definition.ControlRefs, finding.ControlRefs) {
			t.Fatalf("catalog metadata drift for %s: definition=%#v finding=%#v", finding.ID, definition, finding)
		}
		if definition.Description != finding.Description || definition.Remediation != finding.Remediation {
			t.Fatalf("catalog description/remediation drift for %s", finding.ID)
		}
	}
}

// allPSAViolationsNamespaces triggers every namespace-admission rule exactly
// once across four namespaces, because several PSA states are mutually
// exclusive on a single namespace.
func allRBACFindings(t *testing.T) []model.Finding {
	t.Helper()
	roles := []manifest.RBACRole{{
		Kind: "ClusterRole", Name: "risky",
		Rules: []manifest.RBACRule{
			{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}},
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
			{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
			{APIGroups: []string{""}, Resources: []string{"users"}, Verbs: []string{"impersonate"}},
			{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"bind"}},
			{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}},
		},
	}}
	bindings := []manifest.RBACBinding{{
		Kind: "ClusterRoleBinding", Name: "risky-binding",
		RoleKind: "ClusterRole", RoleName: "risky",
		Subjects: []manifest.RBACSubject{{Kind: "ServiceAccount", Namespace: "payments", Name: "runner"}},
	}}
	findings, err := rbac.Analyze(roles, bindings, rbac.DefaultLimits())
	if err != nil {
		t.Fatalf("Analyze RBAC: %v", err)
	}
	return findings
}

func allPSAViolationsNamespaces() []manifest.Namespace {
	return []manifest.Namespace{
		{
			Name: "no-enforce",
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce-version": "v1.36",
			},
		},
		{
			Name: "bogus-level",
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce":         "unrestricted",
				"pod-security.kubernetes.io/enforce-version": "v1.36",
			},
		},
		{
			Name: "privileged-level",
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce":         "privileged",
				"pod-security.kubernetes.io/enforce-version": "v1.36",
			},
		},
		{
			Name: "weak-audit",
			Labels: map[string]string{
				"pod-security.kubernetes.io/enforce": "restricted",
				"pod-security.kubernetes.io/audit":   "baseline",
			},
		},
	}
}

func TestDefaultCatalogHasVersionedOfficialSources(t *testing.T) {
	catalog := DefaultCatalog()
	if catalog.SchemaVersion != "1" || catalog.ID != "clusterproof-default" || catalog.Version == "" {
		t.Fatalf("unexpected catalog identity: %#v", catalog)
	}
	if len(catalog.Rules) == 0 {
		t.Fatal("catalog has no rules")
	}
	for _, rule := range catalog.Rules {
		if rule.Title == "" || rule.Category == "" || rule.Description == "" || rule.Remediation == "" ||
			len(rule.ControlRefs) == 0 || len(rule.Sources) == 0 || len(rule.OS) == 0 {
			t.Fatalf("incomplete rule definition: %#v", rule)
		}
		for _, os := range rule.OS {
			if os != OSLinux && os != OSWindows {
				t.Fatalf("invalid rule OS for %s: %q", rule.ID, os)
			}
		}
		for _, source := range rule.Sources {
			if source.Name == "" || source.Version == "" || !strings.HasPrefix(source.URL, "https://") {
				t.Fatalf("incomplete source for %s: %#v", rule.ID, source)
			}
			if source.Relationship != RelationshipAligned && source.Relationship != RelationshipSupplemental {
				t.Fatalf("invalid relationship for %s: %q", rule.ID, source.Relationship)
			}
		}
	}
}

func TestDefaultCatalogDeclaresKubernetesVersionContract(t *testing.T) {
	contract := DefaultCatalog().Kubernetes
	if contract.KubernetesMinor == "" || len(contract.SupportedMinors) == 0 {
		t.Fatalf("missing Kubernetes version contract: %#v", contract)
	}
	if !contract.Supports(contract.KubernetesMinor) {
		t.Fatalf("reviewed minor %q is not in supported minors %#v",
			contract.KubernetesMinor, contract.SupportedMinors)
	}
}

func TestCoverageMatrixIsConsistent(t *testing.T) {
	catalog := DefaultCatalog()
	if len(catalog.Coverage) == 0 {
		t.Fatal("catalog has no PSS coverage matrix")
	}

	registered := make(map[string]RuleDefinition)
	for _, rule := range catalog.Rules {
		registered[rule.ID] = rule
	}

	covered := make(map[string]struct{})
	seen := make(map[string]struct{})
	for _, coverage := range catalog.Coverage {
		key := coverage.Profile + "/" + coverage.Control
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate coverage entry %q", key)
		}
		seen[key] = struct{}{}
		if coverage.Profile != "baseline" && coverage.Profile != "restricted" {
			t.Fatalf("invalid coverage profile %q", coverage.Profile)
		}
		if coverage.Status != CoverageComplete && coverage.Status != CoveragePartial {
			t.Fatalf("invalid coverage status for %q: %q", key, coverage.Status)
		}
		if coverage.Status == CoveragePartial && coverage.Note == "" {
			t.Fatalf("partial coverage %q must explain its gap in a note", key)
		}
		if len(coverage.RuleIDs) == 0 {
			t.Fatalf("coverage entry %q lists no rules", key)
		}
		for _, ruleID := range coverage.RuleIDs {
			if _, exists := registered[ruleID]; !exists {
				t.Fatalf("coverage entry %q references unregistered rule %q", key, ruleID)
			}
			covered[ruleID] = struct{}{}
		}
	}

	// Every rule aligned with the PSS source must appear in the matrix.
	for _, rule := range catalog.Rules {
		for _, source := range rule.Sources {
			if source.Name != pssSource.Name || source.Relationship != RelationshipAligned {
				continue
			}
			if _, exists := covered[rule.ID]; !exists {
				t.Fatalf("PSS-aligned rule %s is missing from the coverage matrix", rule.ID)
			}
		}
	}
}

func TestVersionContractValidateVersion(t *testing.T) {
	contract := DefaultCatalog().Kubernetes
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "supported", raw: "1.36", want: "1.36"},
		{name: "supported with v prefix", raw: "v1.35", want: "1.35"},
		{name: "padded", raw: "  1.34 ", want: "1.34"},
		{name: "empty", raw: "", wantErr: true},
		{name: "blank", raw: "   ", wantErr: true},
		{name: "latest is never assumed", raw: "latest", wantErr: true},
		{name: "latest case-insensitive", raw: "LATEST", wantErr: true},
		{name: "unsupported minor", raw: "1.20", wantErr: true},
		{name: "garbage", raw: "not-a-version", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := contract.ValidateVersion(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("ValidateVersion(%q) succeeded with %q", test.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateVersion(%q): %v", test.raw, err)
			}
			if got != test.want {
				t.Fatalf("ValidateVersion(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestCatalogOSMetadataMatchesRuleGating(t *testing.T) {
	catalog := DefaultCatalog()
	windowsApplicable := make(map[string]bool)
	for _, rule := range catalog.Rules {
		for _, os := range rule.OS {
			if os == OSWindows {
				windowsApplicable[rule.ID] = true
			}
		}
	}

	privileged := true
	workload := manifest.Workload{
		Kind: "Pod",
		Name: "all-rules-windows",
		PodSpec: manifest.PodSpec{
			OS:          manifest.PodOS{Name: "windows"},
			HostNetwork: true,
			Volumes: []manifest.Volume{
				{
					Name:     "host",
					HostPath: &manifest.HostPath{Path: "/"},
					Types:    []string{"hostPath"},
				},
				{Name: "legacy", Types: []string{"nfs"}},
			},
			SecurityContext: manifest.SecurityContext{
				Sysctls:         []manifest.Sysctl{{Name: "kernel.msgmax", Value: "65536"}},
				AppArmorProfile: &manifest.AppArmor{Type: "Unconfined"},
				SELinuxOptions:  &manifest.SELinux{Type: "spc_t"},
				WindowsOptions:  &manifest.WindowsOpts{HostProcess: boolPointer(true)},
			},
			Containers: []manifest.Container{{
				Name:  "app",
				Image: "example/app:latest",
				Ports: []manifest.ContainerPort{{ContainerPort: 8080, HostPort: 8080}},
				SecurityContext: manifest.SecurityContext{
					Privileged:     &privileged,
					ProcMount:      stringPointer("Unmasked"),
					SeccompProfile: manifest.Seccomp{Type: "Unconfined"},
					Capabilities:   manifest.Capabilities{Add: []string{"SYS_ADMIN"}},
				},
			}},
		},
	}

	emitted := make(map[string]bool)
	for _, finding := range Evaluate(workload) {
		emitted[finding.ID] = true
	}
	for _, rule := range catalog.Rules {
		if rule.Category == "namespace-admission" || rule.Category == "rbac" {
			continue // evaluated against Namespace metadata or RBAC objects, not workloads
		}
		if emitted[rule.ID] && !windowsApplicable[rule.ID] {
			t.Fatalf("rule %s emitted on windows but cataloged Linux-only", rule.ID)
		}
		if !emitted[rule.ID] && windowsApplicable[rule.ID] {
			t.Fatalf("windows-applicable rule %s not emitted by the all-rules windows workload", rule.ID)
		}
	}
}

func TestDefaultCatalogReturnsIndependentValues(t *testing.T) {
	first := DefaultCatalog()
	first.Rules[0].ControlRefs[0] = "modified"
	first.Rules[0].OS[0] = "modified"
	first.Kubernetes.SupportedMinors[0] = "modified"

	second := DefaultCatalog()
	if second.Rules[0].ControlRefs[0] == "modified" {
		t.Fatal("DefaultCatalog returned shared mutable slices")
	}
	if second.Rules[0].OS[0] == "modified" || second.Kubernetes.SupportedMinors[0] == "modified" {
		t.Fatal("DefaultCatalog returned shared mutable OS or version slices")
	}
}
