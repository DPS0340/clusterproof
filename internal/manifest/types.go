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
	Location   model.Location
	PodSpec    PodSpec
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
	Inputs    []model.Input
}
