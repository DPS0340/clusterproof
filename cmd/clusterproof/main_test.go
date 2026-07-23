package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
