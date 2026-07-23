package manifest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNormalizesDeploymentPodSpec(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "deployment.yaml")
	data := []byte(`
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: payments
spec:
  template:
    spec:
      hostPID: true
      automountServiceAccountToken: false
      containers:
        - name: api
          image: ghcr.io/example/api:v1
          securityContext:
            runAsNonRoot: true
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result, err := Load(root, DefaultLimits())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(result.Workloads) != 1 {
		t.Fatalf("got %d workloads, want 1", len(result.Workloads))
	}

	workload := result.Workloads[0]
	if workload.Target() != "payments/Deployment/api" {
		t.Fatalf("Target() = %q", workload.Target())
	}
	if !workload.PodSpec.HostPID {
		t.Fatal("HostPID = false, want true")
	}
	if workload.PodSpec.AutomountServiceAccountToken == nil || *workload.PodSpec.AutomountServiceAccountToken {
		t.Fatal("automountServiceAccountToken was not normalized")
	}
	if len(workload.PodSpec.Containers) != 1 || workload.PodSpec.Containers[0].Image != "ghcr.io/example/api:v1" {
		t.Fatalf("unexpected containers: %#v", workload.PodSpec.Containers)
	}
	if len(result.Inputs) != 1 || result.Inputs[0].SHA256 == "" {
		t.Fatalf("input inventory missing hash: %#v", result.Inputs)
	}
}

func TestLoadSupportsCronJob(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "cronjob.yml")
	data := []byte(`
apiVersion: batch/v1
kind: CronJob
metadata: {name: backup}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - {name: backup, image: backup@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	result, err := Load(root, DefaultLimits())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(result.Workloads) != 1 || result.Workloads[0].Kind != "CronJob" {
		t.Fatalf("unexpected workloads: %#v", result.Workloads)
	}
}

func TestLoadSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("kind: Pod\nmetadata: {name: outside}\n"), 0o600); err != nil {
		t.Fatalf("write outside fixture: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked.yaml")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	result, err := Load(root, DefaultLimits())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(result.Workloads) != 0 || len(result.Inputs) != 0 {
		t.Fatalf("symlink was scanned: %#v", result)
	}
}

func TestLoadRejectsOversizedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.yaml"), []byte("kind: Pod\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	limits := DefaultLimits()
	limits.MaxFileBytes = 4

	if _, err := Load(root, limits); err == nil {
		t.Fatal("Load succeeded, want size-limit error")
	}
}

func TestLoadRejectsSymlinkAsRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.yaml")
	link := filepath.Join(root, "root-link.yaml")
	if err := os.WriteFile(target, []byte("kind: Pod\nmetadata: {name: target}\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if _, err := Load(link, DefaultLimits()); err == nil {
		t.Fatal("Load followed a root symlink")
	}
}

func TestLoadBytesExpandsKubernetesList(t *testing.T) {
	data := []byte(`
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: api
      namespace: payments
    spec:
      hostPID: true
      containers:
        - name: api
          image: example/api:latest
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: worker
      namespace: jobs
    spec:
      template:
        spec:
          containers:
            - name: worker
              image: example/worker:v1
`)

	result, err := LoadBytes("cluster:production:all-namespaces", data, DefaultLimits())
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if len(result.Workloads) != 2 {
		t.Fatalf("got %d workloads, want 2", len(result.Workloads))
	}
	if result.Workloads[0].Target() != "payments/Pod/api" {
		t.Fatalf("first target = %q", result.Workloads[0].Target())
	}
	if result.Workloads[1].Target() != "jobs/Deployment/worker" {
		t.Fatalf("second target = %q", result.Workloads[1].Target())
	}
	if len(result.Inputs) != 1 {
		t.Fatalf("got %d inputs, want 1", len(result.Inputs))
	}
	input := result.Inputs[0]
	if input.Path != "cluster:production:all-namespaces" || input.SHA256 == "" || input.Bytes != int64(len(data)) {
		t.Fatalf("unexpected input inventory: %#v", input)
	}
}

func TestLoadBytesRejectsOversizedSnapshot(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFileBytes = 4

	if _, err := LoadBytes("cluster:test", []byte("kind: Pod\n"), limits); err == nil {
		t.Fatal("LoadBytes succeeded, want size-limit error")
	}
}
