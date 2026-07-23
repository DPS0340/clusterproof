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
