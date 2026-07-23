package cluster

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/DPS0340/clusterproof/internal/manifest"
)

func TestWorkloadArgsAreFixedAndValuesAreSeparate(t *testing.T) {
	options := DefaultOptions()
	options.Kubeconfig = "/tmp/config;touch /tmp/pwned"
	options.Context = "-production"
	options.Namespace = "payments"

	got := WorkloadArgs(options)
	want := []string{
		"--kubeconfig", "/tmp/config;touch /tmp/pwned",
		"--context", "-production",
		"get", workloadResources,
		"--namespace", "payments",
		"--output=yaml",
		"--show-managed-fields=false",
		"--request-timeout=30s",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("WorkloadArgs() = %#v, want %#v", got, want)
	}
}

func TestWorkloadArgsDefaultsToAllNamespaces(t *testing.T) {
	options := DefaultOptions()
	options.Kubeconfig = "/tmp/config"

	args := WorkloadArgs(options)
	if !contains(args, "--all-namespaces") {
		t.Fatalf("missing --all-namespaces: %#v", args)
	}
	if contains(args, "--context") || contains(args, "--namespace") {
		t.Fatalf("unexpected optional scope flags: %#v", args)
	}
}

func TestCollectLoadsBoundedKubectlSnapshot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	executable := writeExecutable(t, `#!/bin/sh
printf '%s' 'apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Pod
  metadata: {name: api, namespace: payments}
  spec:
    hostPID: true
    containers:
    - {name: api, image: example/api:latest}
'
`)
	options := DefaultOptions()
	options.Executable = executable
	options.Kubeconfig = filepath.Join(t.TempDir(), "config")

	result, err := Collect(context.Background(), options)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(result.Workloads) != 1 || result.Workloads[0].Target() != "payments/Pod/api" {
		t.Fatalf("unexpected workloads: %#v", result.Workloads)
	}
	if len(result.Inputs) != 1 || result.Inputs[0].Path != "cluster:current-context:all-namespaces" {
		t.Fatalf("unexpected input inventory: %#v", result.Inputs)
	}
}

func TestCollectRemovesControllerOwnedDuplicates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	executable := writeExecutable(t, `#!/bin/sh
printf '%s' 'apiVersion: v1
kind: List
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata: {name: api, namespace: payments}
  spec:
    template:
      spec:
        containers:
        - {name: api, image: example/api:v1}
- apiVersion: v1
  kind: Pod
  metadata:
    name: api-abc
    namespace: payments
    ownerReferences:
    - {apiVersion: apps/v1, kind: ReplicaSet, name: api-abc, controller: true}
  spec:
    containers:
    - {name: api, image: example/api:v1}
- apiVersion: batch/v1
  kind: CronJob
  metadata: {name: backup, namespace: payments}
  spec:
    jobTemplate:
      spec:
        template:
          spec:
            containers:
            - {name: backup, image: example/backup:v1}
- apiVersion: batch/v1
  kind: Job
  metadata:
    name: backup-123
    namespace: payments
    ownerReferences:
    - {apiVersion: batch/v1, kind: CronJob, name: backup, controller: true}
  spec:
    template:
      spec:
        containers:
        - {name: backup, image: example/backup:v1}
'
`)
	options := DefaultOptions()
	options.Executable = executable
	options.Kubeconfig = filepath.Join(t.TempDir(), "config")

	result, err := Collect(context.Background(), options)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(result.Workloads) != 2 {
		t.Fatalf("got %d workloads, want Deployment and CronJob: %#v", len(result.Workloads), result.Workloads)
	}
	if result.Workloads[0].Kind != "Deployment" || result.Workloads[1].Kind != "CronJob" {
		t.Fatalf("unexpected workloads: %#v", result.Workloads)
	}
}

func TestCollectRejectsOversizedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	executable := writeExecutable(t, "#!/bin/sh\nprintf '123456789'\n")
	options := DefaultOptions()
	options.Executable = executable
	options.Kubeconfig = filepath.Join(t.TempDir(), "config")
	options.MaxOutputBytes = 4

	_, err := Collect(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "output exceeds limit") {
		t.Fatalf("Collect error = %v, want output-limit error", err)
	}
}

func TestCollectTimesOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	executable := writeExecutable(t, "#!/bin/sh\nexec sleep 1\n")
	options := DefaultOptions()
	options.Executable = executable
	options.Kubeconfig = filepath.Join(t.TempDir(), "config")
	options.Timeout = 20 * time.Millisecond

	_, err := Collect(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "exceeded timeout") {
		t.Fatalf("Collect error = %v, want timeout error", err)
	}
}

func TestCollectRequiresKubeconfig(t *testing.T) {
	options := DefaultOptions()
	if _, err := Collect(context.Background(), options); err == nil {
		t.Fatal("Collect succeeded without kubeconfig")
	}
}

func TestSnapshotLimitsScaleNodeBudgetForAggregatedLists(t *testing.T) {
	defaults := manifest.DefaultLimits()
	limits := snapshotLimits(25 << 20)

	if limits.MaxFileBytes != 25<<20 || limits.MaxTotalBytes != 25<<20 {
		t.Fatalf("snapshot byte limits = %#v", limits)
	}
	if limits.MaxNodes <= defaults.MaxNodes {
		t.Fatalf("cluster node limit = %d, want greater than repository default %d", limits.MaxNodes, defaults.MaxNodes)
	}
}

func writeExecutable(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-kubectl")
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	return path
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
