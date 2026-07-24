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
	"github.com/DPS0340/clusterproof/internal/rules"
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
	code := run([]string{"scan", root, "--format", "json", "--fail-on", "high"}, strings.NewReader(""), &stdout, &stderr)
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
	if scan.Ruleset == nil || scan.Ruleset.ID != "clusterproof-default" ||
		scan.Ruleset.Version == "" || scan.Ruleset.RulesEvaluated == 0 {
		t.Fatalf("ruleset identity missing: %#v", scan.Ruleset)
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
	code := run([]string{"scan", "--evidence-dir", evidence, root}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(evidence, "bundle-manifest.json")); err != nil {
		t.Fatalf("evidence bundle missing: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"evidence", "verify", evidence}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "verified") {
		t.Fatalf("verify code = %d, stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	if err := os.WriteFile(filepath.Join(evidence, "scan.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("tamper evidence: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"evidence", "verify", evidence}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("tampered verify code = %d, want 1", code)
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
	}, strings.NewReader(""), &stdout, &stderr)
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
		{name: "stdin with path", args: []string{"-", "./deploy"}},
		{name: "stdin with kubeconfig", args: []string{"-", "--kubeconfig", "/tmp/config"}},
		{name: "stdin twice", args: []string{"-", "-"}},
		{name: "stdin with local Trivy run", args: []string{"-", "--with-trivy"}},
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

func TestRunScanImportsPolicyReportWithoutLeakingMessage(t *testing.T) {
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
	policyPath := filepath.Join(t.TempDir(), "policy-report.json")
	policyReport := `{
	  "apiVersion":"wgpolicyk8s.io/v1alpha2",
	  "kind":"PolicyReport",
	  "scope":{"kind":"Pod","namespace":"default","name":"safe"},
	  "results":[{
	    "policy":"require-owner",
	    "rule":"owner-label",
	    "result":"fail",
	    "severity":"medium",
	    "source":"kyverno",
	    "message":"SENSITIVE_POLICY_MESSAGE"
	  }]
	}`
	if err := os.WriteFile(policyPath, []byte(policyReport), 0o600); err != nil {
		t.Fatalf("write PolicyReport: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", root,
		"--policy-report-json", policyPath,
		"--format", "json",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var scan model.Report
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if len(scan.Findings) != 1 || scan.Findings[0].Source != "policyreport:kyverno" {
		t.Fatalf("unexpected findings: %#v", scan.Findings)
	}
	if len(scan.Inputs) != 2 {
		t.Fatalf("inputs = %#v, want manifest and PolicyReport", scan.Inputs)
	}
	if strings.Contains(stdout.String(), "SENSITIVE_POLICY_MESSAGE") {
		t.Fatalf("PolicyReport message leaked: %s", stdout.String())
	}
}

func TestRunRulesetShowJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"ruleset", "show", "--format", "json"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, stderr.String())
	}
	var catalog rules.Catalog
	if err := json.Unmarshal(stdout.Bytes(), &catalog); err != nil {
		t.Fatalf("invalid catalog JSON: %v\n%s", err, stdout.String())
	}
	if catalog.ID != "clusterproof-default" || catalog.Version == "" || len(catalog.Rules) == 0 {
		t.Fatalf("unexpected catalog: %#v", catalog)
	}
	if catalog.Kubernetes.KubernetesMinor == "" || len(catalog.Kubernetes.SupportedMinors) == 0 {
		t.Fatalf("ruleset show does not expose the Kubernetes version contract: %#v", catalog.Kubernetes)
	}
	for _, rule := range catalog.Rules {
		if len(rule.OS) == 0 {
			t.Fatalf("rule %s does not declare applicable workload OS", rule.ID)
		}
	}
}

func TestRunScanReadsBoundedStdin(t *testing.T) {
	stream := `apiVersion: v1
kind: Pod
metadata: {name: piped}
spec:
  containers:
    - name: app
      image: example/app:latest
      securityContext: {privileged: true}
---
apiVersion: v1
kind: Pod
metadata: {name: second}
spec:
  containers:
    - name: app
      image: example/app:latest
`
	var stdout, stderr bytes.Buffer
	code := run(
		[]string{"scan", "-", "--format", "json", "--fail-on", "high"},
		strings.NewReader(stream), &stdout, &stderr,
	)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr=%s", code, stderr.String())
	}
	var scan model.Report
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if scan.Target != "stdin" {
		t.Fatalf("target = %q, want stdin", scan.Target)
	}
	if len(scan.Inputs) != 1 || scan.Inputs[0].Path != "stdin" || scan.Inputs[0].SHA256 == "" {
		t.Fatalf("stdin input inventory missing: %#v", scan.Inputs)
	}
	if scan.Summary.Critical == 0 {
		t.Fatalf("expected privileged finding from piped manifest: %#v", scan.Summary)
	}
	targets := make(map[string]bool)
	for _, finding := range scan.Findings {
		targets[finding.Target] = true
	}
	if !targets["default/Pod/piped"] || !targets["default/Pod/second"] {
		t.Fatalf("multi-document stream was not fully evaluated: %#v", targets)
	}
}

func TestRunScanStdinRejectsEmptyAndMalformedInput(t *testing.T) {
	tests := []struct {
		name   string
		stream string
	}{
		{name: "empty", stream: ""},
		{name: "whitespace only", stream: "   \n\t\n"},
		{name: "malformed YAML", stream: "{unclosed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run([]string{"scan", "-"}, strings.NewReader(test.stream), &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1; stderr=%s", code, stderr.String())
			}
		})
	}
}

func TestRunScanStdinRejectsOversizedStream(t *testing.T) {
	oversized := strings.Repeat("#", (5<<20)+1)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "-"}, strings.NewReader(oversized), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "exceeds limit") {
		t.Fatalf("exit code = %d, stderr = %q; want limit failure", code, stderr.String())
	}
}

func TestRunScanAppliesRepositoryExceptions(t *testing.T) {
	root := t.TempDir()
	manifest := `
apiVersion: v1
kind: Pod
metadata: {name: tokened, namespace: payments}
spec:
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
	exceptions := `schema_version: "1"
exceptions:
  - rule: CP-K8S-010
    target: payments/Pod/tokened
    owner: team-payments
    reason: Workload calls the Kubernetes API; reviewed.
    expires: "2999-12-31"
`
	exceptionPath := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(exceptionPath, []byte(exceptions), 0o600); err != nil {
		t.Fatalf("write exceptions: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", root,
		"--exceptions", exceptionPath,
		"--format", "json",
		"--fail-on", "medium",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	var scan model.Report
	if err := json.Unmarshal(stdout.Bytes(), &scan); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
	}
	if len(scan.Findings) != 0 {
		t.Fatalf("findings remain after exception: %#v", scan.Findings)
	}
	if len(scan.Suppressed) != 1 || scan.Suppressed[0].RuleID != "CP-K8S-010" ||
		scan.Suppressed[0].Owner != "team-payments" {
		t.Fatalf("suppressed identity missing: %#v", scan.Suppressed)
	}
	if scan.Summary.Medium != 0 {
		t.Fatalf("summary counts suppressed findings: %#v", scan.Summary)
	}
}

func TestRunScanExpiredExceptionKeepsFinding(t *testing.T) {
	root := t.TempDir()
	manifest := `
apiVersion: v1
kind: Pod
metadata: {name: tokened, namespace: payments}
spec:
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
	exceptions := `schema_version: "1"
exceptions:
  - rule: CP-K8S-010
    target: payments/Pod/tokened
    owner: team-payments
    reason: Reviewed long ago.
    expires: "2020-01-01"
`
	exceptionPath := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(exceptionPath, []byte(exceptions), 0o600); err != nil {
		t.Fatalf("write exceptions: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"scan", root,
		"--exceptions", exceptionPath,
		"--format", "json",
		"--fail-on", "medium",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; expired exception must not suppress", code)
	}
}

func TestRunScanMalformedExceptionFileFailsClosed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pod.yaml"), []byte("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {containers: [{name: a, image: i:latest}]}\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	exceptionPath := filepath.Join(t.TempDir(), "exceptions.yaml")
	if err := os.WriteFile(exceptionPath, []byte("{unclosed"), 0o600); err != nil {
		t.Fatalf("write exceptions: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", root, "--exceptions", exceptionPath}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "load exceptions") {
		t.Fatalf("exit code = %d, stderr = %q; malformed exception file must fail the scan", code, stderr.String())
	}
}
