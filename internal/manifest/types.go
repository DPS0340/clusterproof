package manifest

import (
	"fmt"

	"github.com/DPS0340/clusterproof/internal/model"
	"gopkg.in/yaml.v3"
)

// Workload is the normalized security-relevant portion of a Kubernetes workload.
type Workload struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	OwnerKinds []string
	// PodLabels are the pod (template) labels used for selector matching.
	PodLabels map[string]string
	Location  model.Location
	PodSpec   PodSpec
}

// Target returns a stable namespace/kind/name resource identity.
func (w Workload) Target() string {
	namespace := w.Namespace
	if namespace == "" {
		namespace = "default"
	}
	return fmt.Sprintf("%s/%s/%s", namespace, w.Kind, w.Name)
}

// PodSpec contains only fields used by the native security rules.
type PodSpec struct {
	HostNetwork                  bool            `yaml:"hostNetwork"`
	HostPID                      bool            `yaml:"hostPID"`
	HostIPC                      bool            `yaml:"hostIPC"`
	AutomountServiceAccountToken *bool           `yaml:"automountServiceAccountToken"`
	ServiceAccountName           string          `yaml:"serviceAccountName"`
	OS                           PodOS           `yaml:"os"`
	SecurityContext              SecurityContext `yaml:"securityContext"`
	Containers                   []Container     `yaml:"containers"`
	InitContainers               []Container     `yaml:"initContainers"`
	EphemeralContainers          []Container     `yaml:"ephemeralContainers"`
	Volumes                      []Volume        `yaml:"volumes"`
}

// PodOS is the declared workload operating system from spec.os.
type PodOS struct {
	Name string `yaml:"name"`
}

// IsWindows reports whether the workload explicitly declares the Kubernetes
// windows OS value. Any other value, including an absent one, keeps the
// stricter Linux evaluation semantics used by Pod Security Admission.
func (o PodOS) IsWindows() bool {
	return o.Name == "windows"
}

// AllContainers returns regular, init, and ephemeral containers.
func (p PodSpec) AllContainers() []Container {
	total := len(p.Containers) + len(p.InitContainers) + len(p.EphemeralContainers)
	containers := make([]Container, 0, total)
	containers = append(containers, p.Containers...)
	containers = append(containers, p.InitContainers...)
	containers = append(containers, p.EphemeralContainers...)
	return containers
}

// SecurityContext contains pod or container execution constraints.
type SecurityContext struct {
	Privileged               *bool        `yaml:"privileged"`
	AllowPrivilegeEscalation *bool        `yaml:"allowPrivilegeEscalation"`
	RunAsNonRoot             *bool        `yaml:"runAsNonRoot"`
	RunAsUser                *int64       `yaml:"runAsUser"`
	ReadOnlyRootFilesystem   *bool        `yaml:"readOnlyRootFilesystem"`
	ProcMount                *string      `yaml:"procMount"`
	SeccompProfile           Seccomp      `yaml:"seccompProfile"`
	AppArmorProfile          *AppArmor    `yaml:"appArmorProfile"`
	SELinuxOptions           *SELinux     `yaml:"seLinuxOptions"`
	WindowsOptions           *WindowsOpts `yaml:"windowsOptions"`
	Sysctls                  []Sysctl     `yaml:"sysctls"`
	Capabilities             Capabilities `yaml:"capabilities"`
}

// Seccomp describes a Kubernetes seccomp profile.
type Seccomp struct {
	Type string `yaml:"type"`
}

// AppArmor describes a Kubernetes AppArmor profile source.
type AppArmor struct {
	Type string `yaml:"type"`
}

// SELinux records requested SELinux user, role, and type labels.
type SELinux struct {
	User string `yaml:"user"`
	Role string `yaml:"role"`
	Type string `yaml:"type"`
}

// WindowsOpts records Windows-specific security options.
type WindowsOpts struct {
	HostProcess *bool `yaml:"hostProcess"`
}

// Sysctl is one requested kernel parameter without its value semantics.
type Sysctl struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// Capabilities describes added and dropped Linux capabilities.
type Capabilities struct {
	Add  []string `yaml:"add"`
	Drop []string `yaml:"drop"`
}

// Container is one security-relevant container.
type Container struct {
	Name            string          `yaml:"name"`
	Image           string          `yaml:"image"`
	Ports           []ContainerPort `yaml:"ports"`
	SecurityContext SecurityContext `yaml:"securityContext"`
}

// ContainerPort records host port bindings without payload data.
type ContainerPort struct {
	ContainerPort int `yaml:"containerPort"`
	HostPort      int `yaml:"hostPort"`
}

// Volume records the requested volume type keys without reading content.
type Volume struct {
	Name     string
	HostPath *HostPath
	// Types lists the volume source keys declared on the volume, such as
	// "hostPath" or "configMap", in document order.
	Types []string
}

// UnmarshalYAML captures the volume name, any hostPath source, and every
// declared volume source key without decoding source payloads.
func (v *Volume) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("volume must be a mapping, got %s", nodeKindName(node.Kind))
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		switch key.Value {
		case "name":
			if err := value.Decode(&v.Name); err != nil {
				return fmt.Errorf("decode volume name: %w", err)
			}
		case "hostPath":
			hostPath := &HostPath{}
			if err := value.Decode(hostPath); err != nil {
				return fmt.Errorf("decode hostPath volume source: %w", err)
			}
			v.HostPath = hostPath
			v.Types = append(v.Types, key.Value)
		default:
			v.Types = append(v.Types, key.Value)
		}
	}
	return nil
}

func nodeKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "unknown"
	}
}

// HostPath is the host path requested by a workload.
type HostPath struct {
	Path string `yaml:"path"`
	Type string `yaml:"type"`
}

// Result contains normalized workloads and a content-hashed input inventory.
type Result struct {
	Workloads []Workload
	// Namespaces holds Namespace metadata collected for Pod Security
	// Admission assessment. Only labels are retained; no payload data.
	Namespaces []Namespace
	// RBACRoles and RBACBindings hold normalized RBAC objects collected by
	// the rbac scope. Rules retain verbs and resource names only.
	RBACRoles    []RBACRole
	RBACBindings []RBACBinding
	// NetworkPolicies and Services hold normalized network objects
	// collected by the network scope.
	NetworkPolicies []NetworkPolicy
	Services        []Service
	Inputs          []model.Input
}

// NetworkPolicy is the normalized selector and direction data of one policy.
type NetworkPolicy struct {
	Namespace string
	Name      string
	// SelectsAllPods is true when podSelector is empty (matches every pod).
	SelectsAllPods bool
	// PodSelectorLabels holds matchLabels of a non-empty selector.
	PodSelectorLabels map[string]string
	// PolicyTypes lists the declared policy directions.
	PolicyTypes []string
	// HasIngressRules and HasEgressRules report whether allow rules exist.
	HasIngressRules bool
	HasEgressRules  bool
	Location        model.Location
}

// Service is the normalized exposure data of one Kubernetes Service.
type Service struct {
	Namespace string
	Name      string
	Type      string // ClusterIP, NodePort, LoadBalancer, ExternalName
	Selector  map[string]string
	Location  model.Location
}

// Namespace is the metadata-only normalization of one Kubernetes Namespace.
type Namespace struct {
	Name     string
	Labels   map[string]string
	Location model.Location
}

// RBACRule is one normalized PolicyRule from a Role or ClusterRole.
type RBACRule struct {
	APIGroups []string
	Resources []string
	Verbs     []string
}

// RBACRole is a normalized Role or ClusterRole without payload data.
type RBACRole struct {
	Kind      string // "Role" or "ClusterRole"
	Namespace string // empty for ClusterRole
	Name      string
	Rules     []RBACRule
	// AggregationSelectors records that the ClusterRole aggregates other
	// roles; matching label content is not retained.
	Aggregates bool
	Location   model.Location
}

// RBACSubject is one subject of a binding.
type RBACSubject struct {
	Kind      string // "User", "Group", or "ServiceAccount"
	Namespace string
	Name      string
}

// RBACBinding is a normalized RoleBinding or ClusterRoleBinding.
type RBACBinding struct {
	Kind      string // "RoleBinding" or "ClusterRoleBinding"
	Namespace string // empty for ClusterRoleBinding
	Name      string
	RoleKind  string // referenced "Role" or "ClusterRole"
	RoleName  string
	Subjects  []RBACSubject
	Location  model.Location
}
