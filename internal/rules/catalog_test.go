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
		if rule.Title == "" || rule.Category == "" || len(rule.ControlRefs) == 0 || len(rule.Sources) == 0 {
			t.Fatalf("incomplete rule definition: %#v", rule)
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

func TestDefaultCatalogReturnsIndependentValues(t *testing.T) {
	first := DefaultCatalog()
	first.Rules[0].ControlRefs[0] = "modified"

	second := DefaultCatalog()
	if second.Rules[0].ControlRefs[0] == "modified" {
		t.Fatal("DefaultCatalog returned shared mutable slices")
	}
}
