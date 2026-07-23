package rules

import "github.com/DPS0340/clusterproof/internal/model"

// Relationship describes how a ClusterProof rule relates to an external source.
type Relationship string

const (
	// RelationshipAligned means the rule implements a check described by the source.
	RelationshipAligned Relationship = "aligned"
	// RelationshipSupplemental means the source informs the rule without defining it.
	RelationshipSupplemental Relationship = "supplemental"
)

// SourceReference identifies the versioned official guidance behind a rule.
type SourceReference struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	URL          string       `json:"url"`
	Relationship Relationship `json:"relationship"`
}

// RuleDefinition is immutable metadata for one native rule.
type RuleDefinition struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Category    string            `json:"category"`
	ControlRefs []string          `json:"control_refs"`
	Sources     []SourceReference `json:"sources"`
}

// Catalog is the versioned native ruleset contract recorded in scan evidence.
type Catalog struct {
	SchemaVersion string           `json:"schema_version"`
	ID            string           `json:"id"`
	Version       string           `json:"version"`
	Rules         []RuleDefinition `json:"rules"`
}

var pssSource = SourceReference{
	Name:         "Kubernetes Pod Security Standards",
	Version:      "v1.36",
	URL:          "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	Relationship: RelationshipAligned,
}

var securityChecklistSource = SourceReference{
	Name:         "Kubernetes Security Checklist",
	Version:      "v1.36",
	URL:          "https://kubernetes.io/docs/concepts/security/security-checklist/",
	Relationship: RelationshipSupplemental,
}

var applicationChecklistSource = SourceReference{
	Name:         "Kubernetes Application Security Checklist",
	Version:      "v1.36",
	URL:          "https://kubernetes.io/docs/concepts/security/application-security-checklist/",
	Relationship: RelationshipSupplemental,
}

var slsaSource = SourceReference{
	Name:         "SLSA Specification",
	Version:      "v1.2",
	URL:          "https://slsa.dev/spec/v1.2/",
	Relationship: RelationshipSupplemental,
}

var defaultCatalog = Catalog{
	SchemaVersion: "1",
	ID:            "clusterproof-default",
	Version:       "1.0.0",
	Rules: []RuleDefinition{
		{
			ID: "CP-K8S-001", Title: "Privileged container", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-002", Title: "Host namespace sharing enabled", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-003", Title: "Host filesystem mounted into workload", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-004", Title: "Privilege escalation is not disabled", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-005", Title: "Non-root execution is not guaranteed", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-006", Title: "Seccomp isolation is not enforced", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-007", Title: "Additional Linux capabilities requested", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-008", Title: "Default Linux capabilities are not dropped", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-009", Title: "Container root filesystem is writable", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:Application-Checklist"},
			Sources:     []SourceReference{applicationChecklistSource},
		},
		{
			ID: "CP-K8S-010", Title: "Service account token is automatically mounted", Category: "kubernetes-posture",
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:Security-Checklist"},
			Sources:     []SourceReference{securityChecklistSource},
		},
		{
			ID: "CP-SUPPLY-001", Title: "Container image uses a mutable latest tag", Category: "supply-chain",
			ControlRefs: []string{"SOC2:CC7", "SLSA:Provenance"},
			Sources:     []SourceReference{slsaSource},
		},
		{
			ID: "CP-SUPPLY-002", Title: "Container image is not digest pinned", Category: "supply-chain",
			ControlRefs: []string{"SOC2:CC7", "SLSA:Provenance"},
			Sources:     []SourceReference{slsaSource},
		},
	},
}

// DefaultCatalog returns an independent copy of the built-in native ruleset.
func DefaultCatalog() Catalog {
	result := defaultCatalog
	result.Rules = make([]RuleDefinition, len(defaultCatalog.Rules))
	for index, rule := range defaultCatalog.Rules {
		result.Rules[index] = rule
		result.Rules[index].ControlRefs = append([]string(nil), rule.ControlRefs...)
		result.Rules[index].Sources = append([]SourceReference(nil), rule.Sources...)
	}
	return result
}

// Reference returns the compact catalog identity recorded in scan reports.
func (c Catalog) Reference() model.RulesetReference {
	return model.RulesetReference{
		ID:             c.ID,
		Version:        c.Version,
		RulesEvaluated: len(c.Rules),
	}
}
