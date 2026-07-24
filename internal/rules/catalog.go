package rules

import (
	"fmt"
	"strings"

	"github.com/DPS0340/clusterproof/internal/model"
)

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

// WorkloadOS identifies one pod operating system a rule applies to.
type WorkloadOS string

const (
	// OSLinux marks a check evaluated for Linux and undeclared workloads.
	OSLinux WorkloadOS = "linux"
	// OSWindows marks a check evaluated for declared Windows workloads.
	OSWindows WorkloadOS = "windows"
)

// VersionContract pins the exact upstream semantics the catalog evaluates.
type VersionContract struct {
	// KubernetesMinor is the exact documented Kubernetes minor the Pod
	// Security Standards alignment was reviewed against, such as "1.36".
	KubernetesMinor string `json:"kubernetes_minor"`
	// SupportedMinors lists every Kubernetes minor whose PSS semantics the
	// catalog is known to match. Versions outside this list are unsupported
	// and must be reported explicitly, never treated as the newest release.
	SupportedMinors []string `json:"supported_minors"`
}

// Supports reports whether an exact "MAJOR.MINOR" version is covered.
func (v VersionContract) Supports(minor string) bool {
	for _, supported := range v.SupportedMinors {
		if supported == minor {
			return true
		}
	}
	return false
}

// ValidateVersion accepts a supported "MAJOR.MINOR" value and rejects
// anything else, including "latest", with an explicit error.
func (v VersionContract) ValidateVersion(raw string) (string, error) {
	minor := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if minor == "" {
		return "", fmt.Errorf(
			"kubernetes version is required; supported minors: %s",
			strings.Join(v.SupportedMinors, ", "),
		)
	}
	if strings.EqualFold(minor, "latest") {
		return "", fmt.Errorf(
			"kubernetes version %q is ambiguous and is never assumed; supported minors: %s",
			raw, strings.Join(v.SupportedMinors, ", "),
		)
	}
	if !v.Supports(minor) {
		return "", fmt.Errorf(
			"kubernetes version %q is not supported by catalog %s; supported minors: %s",
			raw, defaultCatalog.Version, strings.Join(v.SupportedMinors, ", "),
		)
	}
	return minor, nil
}

// RuleDefinition is immutable metadata for one native rule.
type RuleDefinition struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Category    string            `json:"category"`
	Description string            `json:"description"`
	Remediation string            `json:"remediation"`
	OS          []WorkloadOS      `json:"os"`
	ControlRefs []string          `json:"control_refs"`
	Sources     []SourceReference `json:"sources"`
}

// FindRule returns the definition for one rule ID.
func (c Catalog) FindRule(id string) (RuleDefinition, bool) {
	for _, rule := range c.Rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return RuleDefinition{}, false
}

// CoverageStatus describes how completely a PSS control is evaluated.
type CoverageStatus string

const (
	// CoverageComplete means every documented field of the control is checked.
	CoverageComplete CoverageStatus = "complete"
	// CoveragePartial means at least one documented field is not checked.
	// A partial entry must explain the gap in its note.
	CoveragePartial CoverageStatus = "partial"
)

// ControlCoverage maps one upstream PSS control to the native rules
// evaluating it and honestly records any remaining gap.
type ControlCoverage struct {
	Profile string         `json:"profile"`
	Control string         `json:"control"`
	Status  CoverageStatus `json:"status"`
	RuleIDs []string       `json:"rule_ids"`
	Note    string         `json:"note,omitempty"`
}

// Catalog is the versioned native ruleset contract recorded in scan evidence.
type Catalog struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id"`
	Version       string            `json:"version"`
	Kubernetes    VersionContract   `json:"kubernetes"`
	Coverage      []ControlCoverage `json:"pss_coverage"`
	Rules         []RuleDefinition  `json:"rules"`
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

var psaSource = SourceReference{
	Name:         "Kubernetes Pod Security Admission",
	Version:      "v1.36",
	URL:          "https://kubernetes.io/docs/concepts/security/pod-security-admission/",
	Relationship: RelationshipAligned,
}

var slsaSource = SourceReference{
	Name:         "SLSA Specification",
	Version:      "v1.2",
	URL:          "https://slsa.dev/spec/v1.2/",
	Relationship: RelationshipSupplemental,
}

var allOS = []WorkloadOS{OSLinux, OSWindows}
var linuxOnly = []WorkloadOS{OSLinux}

var defaultCatalog = Catalog{
	SchemaVersion: "1",
	ID:            "clusterproof-default",
	Version:       "1.2.0",
	Kubernetes: VersionContract{
		KubernetesMinor: "1.36",
		SupportedMinors: []string{"1.34", "1.35", "1.36"},
	},
	Coverage: []ControlCoverage{
		{Profile: "baseline", Control: "HostProcess", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-017"}},
		{Profile: "baseline", Control: "Host Namespaces", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-002"}},
		{Profile: "baseline", Control: "Privileged Containers", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-001"}},
		{
			Profile: "baseline", Control: "Capabilities", Status: CoverageComplete,
			RuleIDs: []string{"CP-K8S-007"},
			Note:    "Evaluated with the stricter Restricted add-list; every Baseline violation is also reported.",
		},
		{Profile: "baseline", Control: "HostPath Volumes", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-003"}},
		{Profile: "baseline", Control: "Host Ports", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-011"}},
		{
			Profile: "baseline", Control: "AppArmor", Status: CoveragePartial,
			RuleIDs: []string{"CP-K8S-015"},
			Note:    "securityContext.appArmorProfile is evaluated; deprecated container.apparmor.security.beta.kubernetes.io annotations are not parsed.",
		},
		{Profile: "baseline", Control: "SELinux", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-016"}},
		{Profile: "baseline", Control: "/proc Mount Type", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-013"}},
		{Profile: "baseline", Control: "Seccomp", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-006"}},
		{Profile: "baseline", Control: "Sysctls", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-014"}},
		{Profile: "restricted", Control: "Volume Types", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-003", "CP-K8S-012"}},
		{Profile: "restricted", Control: "Privilege Escalation", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-004"}},
		{Profile: "restricted", Control: "Running as Non-root", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-005"}},
		{Profile: "restricted", Control: "Running as Non-root user", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-005"}},
		{Profile: "restricted", Control: "Seccomp", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-006"}},
		{Profile: "restricted", Control: "Capabilities", Status: CoverageComplete, RuleIDs: []string{"CP-K8S-007", "CP-K8S-008"}},
	},
	Rules: []RuleDefinition{
		{
			ID: "CP-K8S-001", Title: "Privileged container", Category: "kubernetes-posture",
			Description: "Privileged containers bypass major isolation controls and can commonly reach the node.",
			Remediation: "Set securityContext.privileged: false and grant only the specific capability required.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-002", Title: "Host namespace sharing enabled", Category: "kubernetes-posture",
			Description: "Sharing host namespaces weakens workload isolation and can expose node-level processes or networking.",
			Remediation: "Disable hostNetwork, hostPID, and hostIPC unless the workload has a reviewed infrastructure exception.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-003", Title: "Host filesystem mounted into workload", Category: "kubernetes-posture",
			Description: "A hostPath volume can expose node files and turn a container compromise into a node compromise.",
			Remediation: "Replace hostPath with a restricted volume type or document and enforce a narrow exception.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-004", Title: "Privilege escalation is not disabled", Category: "kubernetes-posture",
			Description: "The container may gain more privileges than its parent process.",
			Remediation: "Set securityContext.allowPrivilegeEscalation: false.",
			OS:          linuxOnly,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-005", Title: "Non-root execution is not guaranteed", Category: "kubernetes-posture",
			Description: "Root execution increases the impact of a container escape or writable filesystem weakness.",
			Remediation: "Set runAsNonRoot: true and use a non-zero runAsUser where the image requires an explicit UID.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-006", Title: "Seccomp isolation is not enforced", Category: "kubernetes-posture",
			Description: "A missing or unconfined seccomp profile leaves unnecessary kernel syscalls available.",
			Remediation: "Set seccompProfile.type to RuntimeDefault or a reviewed Localhost profile.",
			OS:          linuxOnly,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-007", Title: "Additional Linux capabilities requested", Category: "kubernetes-posture",
			Description: "Powerful Linux capabilities can provide host-level actions without a fully privileged container.",
			Remediation: "Remove added capabilities; if required, allow only NET_BIND_SERVICE after review.",
			OS:          linuxOnly,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-008", Title: "Default Linux capabilities are not dropped", Category: "kubernetes-posture",
			Description: "The runtime capability set is broader than most applications require.",
			Remediation: "Set securityContext.capabilities.drop to [ALL], then add back only reviewed requirements.",
			OS:          linuxOnly,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-009", Title: "Container root filesystem is writable", Category: "kubernetes-posture",
			Description: "A writable image filesystem gives an attacker persistence space inside the running container.",
			Remediation: "Set readOnlyRootFilesystem: true and mount explicit writable volumes where required.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:Application-Checklist"},
			Sources:     []SourceReference{applicationChecklistSource},
		},
		{
			ID: "CP-K8S-010", Title: "Service account token is automatically mounted", Category: "kubernetes-posture",
			Description: "An unnecessary Kubernetes API credential increases the impact of a container compromise.",
			Remediation: "Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:Security-Checklist"},
			Sources:     []SourceReference{securityChecklistSource},
		},
		{
			ID: "CP-K8S-011", Title: "Host port binding requested", Category: "kubernetes-posture",
			Description: "Host ports bind the workload to node network interfaces and bypass Service-level controls.",
			Remediation: "Remove hostPort and expose the workload through a Service or ingress controller.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-012", Title: "Volume type outside the restricted allowlist", Category: "kubernetes-posture",
			Description: "The Restricted profile allows only a fixed set of volume types; other drivers can reach node or network resources.",
			Remediation: "Use configMap, csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, projected, or secret volumes.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Restricted"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-013", Title: "Non-default proc mount requested", Category: "kubernetes-posture",
			Description: "An unmasked /proc filesystem exposes sensitive kernel interfaces to the container.",
			Remediation: "Remove procMount or set it to Default.",
			OS:          linuxOnly,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-014", Title: "Sysctl outside the safe allowlist requested", Category: "kubernetes-posture",
			Description: "Sysctls can disable security mechanisms or affect every workload on the node.",
			Remediation: "Remove the sysctl or keep only entries from the Kubernetes safe sysctl allowlist.",
			OS:          linuxOnly,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-015", Title: "AppArmor profile is overridden to an unconfined state", Category: "kubernetes-posture",
			Description: "Disabling AppArmor removes a mandatory access-control layer expected by the Baseline profile.",
			Remediation: "Set appArmorProfile.type to RuntimeDefault or a reviewed Localhost profile, or remove the override.",
			OS:          linuxOnly,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-016", Title: "Disallowed SELinux options requested", Category: "kubernetes-posture",
			Description: "Custom SELinux users, roles, or types can escape the container security domain.",
			Remediation: "Remove seLinuxOptions.user and role, and keep type unset or one of the allowed container types.",
			OS:          linuxOnly,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-017", Title: "Windows HostProcess pod requested", Category: "kubernetes-posture",
			Description: "HostProcess containers run directly on the Windows host and are equivalent to privileged access.",
			Remediation: "Set windowsOptions.hostProcess to false unless the workload has a reviewed infrastructure exception.",
			OS:          []WorkloadOS{OSWindows},
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSS-Baseline"},
			Sources:     []SourceReference{pssSource},
		},
		{
			ID: "CP-K8S-018", Title: "Namespace has no Pod Security Admission enforce level", Category: "namespace-admission",
			Description: "Without an enforce label, the namespace admits pods that violate every Pod Security Standard.",
			Remediation: "Set pod-security.kubernetes.io/enforce to baseline or restricted on the namespace.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSA"},
			Sources:     []SourceReference{psaSource},
		},
		{
			ID: "CP-K8S-019", Title: "Namespace Pod Security Admission level is not a defined value", Category: "namespace-admission",
			Description: "An unrecognized enforce level is rejected by the admission controller and behaves like no enforcement.",
			Remediation: "Use privileged, baseline, or restricted as the enforce level.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSA"},
			Sources:     []SourceReference{psaSource},
		},
		{
			ID: "CP-K8S-020", Title: "Namespace explicitly enforces the privileged profile", Category: "namespace-admission",
			Description: "The privileged profile is intentionally unrestricted; workloads in this namespace bypass all PSS controls.",
			Remediation: "Confirm the namespace requires privileged workloads or raise the enforce level to baseline.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSA"},
			Sources:     []SourceReference{psaSource},
		},
		{
			ID: "CP-K8S-021", Title: "Pod Security Admission version is not pinned", Category: "namespace-admission",
			Description: "An unpinned or latest policy version silently changes admission behavior on cluster upgrades.",
			Remediation: "Set pod-security.kubernetes.io/enforce-version to the tested Kubernetes minor, such as v1.36.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSA"},
			Sources:     []SourceReference{psaSource},
		},
		{
			ID: "CP-K8S-022", Title: "Audit or warn level is weaker than the enforce level", Category: "namespace-admission",
			Description: "Weaker audit or warn levels hide violations that the next enforce-level increase would reject.",
			Remediation: "Set audit and warn to at least the enforce level.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC6", "Kubernetes:PSA"},
			Sources:     []SourceReference{psaSource},
		},
		{
			ID: "CP-SUPPLY-001", Title: "Container image uses a mutable latest tag", Category: "supply-chain",
			Description: "A mutable tag can resolve to different content without a manifest change or review.",
			Remediation: "Pin the image to an immutable sha256 digest produced by the trusted build pipeline.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC7", "SLSA:Provenance"},
			Sources:     []SourceReference{slsaSource},
		},
		{
			ID: "CP-SUPPLY-002", Title: "Container image is not digest pinned", Category: "supply-chain",
			Description: "Tags are mutable and do not prove which image bytes were reviewed and deployed.",
			Remediation: "Replace the tag with the verified image digest while retaining the tag in deployment metadata if useful.",
			OS:          allOS,
			ControlRefs: []string{"SOC2:CC7", "SLSA:Provenance"},
			Sources:     []SourceReference{slsaSource},
		},
	},
}

// DefaultCatalog returns an independent copy of the built-in native ruleset.
func DefaultCatalog() Catalog {
	result := defaultCatalog
	result.Kubernetes.SupportedMinors = append([]string(nil), defaultCatalog.Kubernetes.SupportedMinors...)
	result.Coverage = make([]ControlCoverage, len(defaultCatalog.Coverage))
	for index, coverage := range defaultCatalog.Coverage {
		result.Coverage[index] = coverage
		result.Coverage[index].RuleIDs = append([]string(nil), coverage.RuleIDs...)
	}
	result.Rules = make([]RuleDefinition, len(defaultCatalog.Rules))
	for index, rule := range defaultCatalog.Rules {
		result.Rules[index] = rule
		result.Rules[index].OS = append([]WorkloadOS(nil), rule.OS...)
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
