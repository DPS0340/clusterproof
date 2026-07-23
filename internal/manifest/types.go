package manifest

import (
	"fmt"

	"github.com/DPS0340/clusterproof/internal/model"
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
	SecurityContext              SecurityContext `yaml:"securityContext"`
	Containers                   []Container     `yaml:"containers"`
	InitContainers               []Container     `yaml:"initContainers"`
	EphemeralContainers          []Container     `yaml:"ephemeralContainers"`
	Volumes                      []Volume        `yaml:"volumes"`
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
	SeccompProfile           Seccomp      `yaml:"seccompProfile"`
	Capabilities             Capabilities `yaml:"capabilities"`
}

// Seccomp describes a Kubernetes seccomp profile.
type Seccomp struct {
	Type string `yaml:"type"`
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
	SecurityContext SecurityContext `yaml:"securityContext"`
}

// Volume records hostPath usage without reading mounted content.
type Volume struct {
	Name     string    `yaml:"name"`
	HostPath *HostPath `yaml:"hostPath"`
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
