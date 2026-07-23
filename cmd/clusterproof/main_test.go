package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DPS0340/clusterproof/internal/model"
)

func TestRunScanReturnsPolicyExitCode(t *testing.T) {
	root := t.TempDir()
	manifest := `
apiVersion: v1
kind: Pod
metadata: {name: dangerous}
spec:
  containers:
    - name: app
      image: example/app:latest
      securityContext: {privileged: true}
`
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", root, "--format", "json", "--fail-on", "high"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr=%s", code, stderr.String())
	}
	var scan model.Report
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if scan.Summary.Critical == 0 || scan.Summary.High == 0 {
		t.Fatalf("expected critical and high findings: %#v", scan.Summary)
	}
}

func TestRunScanCreatesEvidenceBundle(t *testing.T) {
	root := t.TempDir()
	manifest := `
apiVersion: v1
kind: Pod
metadata: {name: safe}
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: app
      image: example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      securityContext:
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        readOnlyRootFilesystem: true
        capabilities: {drop: [ALL]}
`
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	evidence := filepath.Join(t.TempDir(), "evidence")

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--evidence-dir", evidence, root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(evidence, "bundle-manifest.json")); err != nil {
		t.Fatalf("evidence bundle missing: %v", err)
	}
}

func TestRunScanCollectsClusterByKubeconfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	executable := filepath.Join(t.TempDir(), "fake-kubectl")
	script := `#!/bin/sh
printf '%s' 'apiVersion: v1
kind: List
items:
- apiVersion: apps/v1
  kind: Deployment
  metadata: {name: api, namespace: payments}
  spec:
    template:
      spec:
        hostNetwork: true
        containers:
        - {name: api, image: example/api:latest}
'
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	previousExecutable := kubectlExecutable
	kubectlExecutable = executable
	t.Cleanup(func() { kubectlExecutable = previousExecutable })

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan",
		"--kubeconfig", filepath.Join(t.TempDir(), "config"),
		"--context", "production",
		"--namespace", "payments",
		"--format", "json",
		"--fail-on", "high",
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr=%s", code, stderr.String())
	}
	var scan model.Report
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if scan.Target != "cluster:production:payments" {
		t.Fatalf("target = %q, want cluster scope", scan.Target)
	}
	if scan.Summary.High == 0 {
		t.Fatalf("expected high findings: %#v", scan.Summary)
	}
	if strings.Contains(stdout.String(), "kubeconfig") {
		t.Fatalf("report leaked kubeconfig path: %s", stdout.String())
	}
}

func TestParseScanOptionsRequiresExactlyOneTarget(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "neither", args: nil},
		{name: "both", args: []string{"./deploy", "--kubeconfig", "/tmp/config"}},
		{name: "context without cluster", args: []string{"./deploy", "--context", "production"}},
		{name: "namespace without cluster", args: []string{"./deploy", "--namespace", "payments"}},
		{name: "cluster with Trivy", args: []string{"--kubeconfig", "/tmp/config", "--with-trivy"}},
		{name: "cluster with Trivy JSON", args: []string{"--kubeconfig", "/tmp/config", "--trivy-json", "trivy.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := parseScanOptions(test.args); err == nil {
				t.Fatalf("parseScanOptions(%#v) succeeded", test.args)
			}
		})
	}
}
