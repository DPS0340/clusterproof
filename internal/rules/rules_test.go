package rules

import (
	"testing"

	"github.com/DPS0340/clusterproof/internal/manifest"
	"github.com/DPS0340/clusterproof/internal/model"
)

func TestEvaluateSecureWorkloadHasNoFindings(t *testing.T) {
	findings := Evaluate(secureWorkload())
	if len(findings) != 0 {
		t.Fatalf("secure workload produced findings: %#v", findings)
	}
}

func TestEvaluateNativeRules(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*manifest.Workload)
		wantID   string
		severity model.Severity
	}{
		{
			name: "privileged container",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.Containers[0].SecurityContext.Privileged = boolPointer(true)
			},
			wantID:   "CP-K8S-001",
			severity: model.SeverityCritical,
		},
		{
			name: "host namespace",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.HostPID = true
			},
			wantID:   "CP-K8S-002",
			severity: model.SeverityHigh,
		},
		{
			name: "host path",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.Volumes = []manifest.Volume{{
					Name: "host",
					HostPath: &manifest.HostPath{
						Path: "/var/run",
					},
				}}
			},
			wantID:   "CP-K8S-003",
			severity: model.SeverityHigh,
		},
		{
			name: "privilege escalation not disabled",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil
			},
			wantID:   "CP-K8S-004",
			severity: model.SeverityHigh,
		},
		{
			name: "explicit root user",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.SecurityContext.RunAsNonRoot = nil
				workload.PodSpec.Containers[0].SecurityContext.RunAsNonRoot = nil
				workload.PodSpec.Containers[0].SecurityContext.RunAsUser = int64Pointer(0)
			},
			wantID:   "CP-K8S-005",
			severity: model.SeverityHigh,
		},
		{
			name: "non-root policy absent",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.SecurityContext.RunAsNonRoot = nil
				workload.PodSpec.Containers[0].SecurityContext.RunAsNonRoot = nil
			},
			wantID:   "CP-K8S-005",
			severity: model.SeverityMedium,
		},
		{
			name: "seccomp absent",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.SecurityContext.SeccompProfile.Type = ""
			},
			wantID:   "CP-K8S-006",
			severity: model.SeverityMedium,
		},
		{
			name: "dangerous capability",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.Containers[0].SecurityContext.Capabilities.Add = []string{"SYS_ADMIN"}
			},
			wantID:   "CP-K8S-007",
			severity: model.SeverityHigh,
		},
		{
			name: "capabilities not dropped",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.Containers[0].SecurityContext.Capabilities.Drop = nil
			},
			wantID:   "CP-K8S-008",
			severity: model.SeverityMedium,
		},
		{
			name: "writable root filesystem",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = nil
			},
			wantID:   "CP-K8S-009",
			severity: model.SeverityMedium,
		},
		{
			name: "service account token automount",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.AutomountServiceAccountToken = boolPointer(true)
			},
			wantID:   "CP-K8S-010",
			severity: model.SeverityMedium,
		},
		{
			name: "latest image tag",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.Containers[0].Image = "ghcr.io/example/api:latest"
			},
			wantID:   "CP-SUPPLY-001",
			severity: model.SeverityHigh,
		},
		{
			name: "image is not digest pinned",
			mutate: func(workload *manifest.Workload) {
				workload.PodSpec.Containers[0].Image = "ghcr.io/example/api:v1.2.3"
			},
			wantID:   "CP-SUPPLY-002",
			severity: model.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workload := secureWorkload()
			tt.mutate(&workload)

			finding, ok := findByID(Evaluate(workload), tt.wantID)
			if !ok {
				t.Fatalf("finding %s not produced", tt.wantID)
			}
			if finding.Severity != tt.severity {
				t.Fatalf("severity = %s, want %s", finding.Severity, tt.severity)
			}
			if finding.Target != workload.Target() {
				t.Fatalf("target = %q, want %q", finding.Target, workload.Target())
			}
			if finding.Remediation == "" || len(finding.ControlRefs) == 0 {
				t.Fatalf("finding lacks remediation or control refs: %#v", finding)
			}
		})
	}
}

func TestEvaluateIncludesInitContainers(t *testing.T) {
	workload := secureWorkload()
	initContainer := workload.PodSpec.Containers[0]
	initContainer.Name = "migration"
	initContainer.SecurityContext.Privileged = boolPointer(true)
	workload.PodSpec.InitContainers = []manifest.Container{initContainer}

	finding, ok := findByID(Evaluate(workload), "CP-K8S-001")
	if !ok {
		t.Fatal("privileged init container was not evaluated")
	}
	if finding.Location.Container != "migration" {
		t.Fatalf("container = %q, want migration", finding.Location.Container)
	}
}

func secureWorkload() manifest.Workload {
	return manifest.Workload{
		APIVersion: "apps/v1",
		Kind:       "Deployment",
		Namespace:  "payments",
		Name:       "api",
		Location: model.Location{
			Path:     "deploy/api.yaml",
			Document: 1,
			Line:     1,
			Resource: "Deployment/api",
		},
		PodSpec: manifest.PodSpec{
			AutomountServiceAccountToken: boolPointer(false),
			SecurityContext: manifest.SecurityContext{
				RunAsNonRoot:   boolPointer(true),
				SeccompProfile: manifest.Seccomp{Type: "RuntimeDefault"},
			},
			Containers: []manifest.Container{{
				Name:  "api",
				Image: "ghcr.io/example/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				SecurityContext: manifest.SecurityContext{
					AllowPrivilegeEscalation: boolPointer(false),
					RunAsNonRoot:             boolPointer(true),
					ReadOnlyRootFilesystem:   boolPointer(true),
					Capabilities: manifest.Capabilities{
						Drop: []string{"ALL"},
					},
				},
			}},
		},
	}
}

func findByID(findings []model.Finding, id string) (model.Finding, bool) {
	for _, finding := range findings {
		if finding.ID == id {
			return finding, true
		}
	}
	return model.Finding{}, false
}

func boolPointer(value bool) *bool {
	return &value
}

func int64Pointer(value int64) *int64 {
	return &value
}
