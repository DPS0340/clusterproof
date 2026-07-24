package rules

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/manifest"
)

func TestDefaultCatalogCoversEveryNativeFinding(t *testing.T) {
	privileged := true
	workload := manifest.Workload{
		Kind: "Pod",
		Name: "all-rules",
		PodSpec: manifest.PodSpec{
			HostNetwork: true,
			Volumes: []manifest.Volume{{
				Name:     "host",
				HostPath: &manifest.HostPath{Path: "/"},
			}},
			Containers: []manifest.Container{{
				Name:  "app",
				Image: "example/app:latest",
				SecurityContext: manifest.SecurityContext{
					Privileged: &privileged,
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
		if rule.Title == "" || rule.Category == "" || len(rule.ControlRefs) == 0 || len(rule.Sources) == 0 || len(rule.OS) == 0 {
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
			Volumes: []manifest.Volume{{
				Name:     "host",
				HostPath: &manifest.HostPath{Path: "/"},
			}},
			Containers: []manifest.Container{{
				Name:  "app",
				Image: "example/app:latest",
				SecurityContext: manifest.SecurityContext{
					Privileged:     &privileged,
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
