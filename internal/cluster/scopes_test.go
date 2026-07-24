package cluster

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestScopeArgsAreFixedPerScope(t *testing.T) {
	options := DefaultOptions()
	options.Kubeconfig = "/tmp/config"
	options.Namespace = "payments"

	workloadArgs := ScopeArgs(options, ScopeWorkloads)
	if !reflect.DeepEqual(workloadArgs, WorkloadArgs(options)) {
		t.Fatalf("workloads scope args diverge from the fixed workload invocation:\n%#v\n%#v",
			workloadArgs, WorkloadArgs(options))
	}

	namespaceArgs := ScopeArgs(options, ScopeNamespaces)
	want := []string{
		"--kubeconfig", "/tmp/config",
		"get", "namespaces",
		"--output=yaml",
		"--show-managed-fields=false",
		"--request-timeout=30s",
	}
	if !reflect.DeepEqual(namespaceArgs, want) {
		t.Fatalf("ScopeArgs(namespaces) = %#v, want %#v", namespaceArgs, want)
	}
	if contains(namespaceArgs, "--namespace") || contains(namespaceArgs, "--all-namespaces") {
		t.Fatalf("namespace scope must be cluster-scoped metadata only: %#v", namespaceArgs)
	}
}

func TestCollectScopesRejectsUnknownAndDuplicateScopes(t *testing.T) {
	options := DefaultOptions()
	options.Kubeconfig = "/tmp/config"

	if _, err := CollectScopes(context.Background(), options, []string{"secrets"}); err == nil ||
		!strings.Contains(err.Error(), "unknown scope") {
		t.Fatalf("unknown scope accepted: %v", err)
	}
	if _, err := CollectScopes(context.Background(), options, []string{"workloads", "workloads"}); err == nil ||
		!strings.Contains(err.Error(), "more than once") {
		t.Fatalf("duplicate scope accepted: %v", err)
	}
	if _, err := CollectScopes(context.Background(), options, nil); err == nil {
		t.Fatal("empty scope list accepted")
	}
}

func TestCollectScopesRecordsDeniedScopeAsPartial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	// The fake kubectl succeeds for workloads and is forbidden for namespaces.
	executable := writeExecutable(t, `#!/bin/sh
case "$*" in
*"get namespaces"*)
  echo 'Error from server (Forbidden): namespaces is forbidden: User "scanner" cannot list resource "namespaces"' >&2
  exit 1
  ;;
*)
  printf '%s' 'apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Pod
  metadata: {name: api, namespace: payments}
  spec:
    containers:
    - {name: api, image: example/api:v1}
'
  ;;
esac
`)
	options := DefaultOptions()
	options.Executable = executable
	options.Kubeconfig = "/tmp/config"

	scoped, err := CollectScopes(context.Background(), options, []string{ScopeWorkloads, ScopeNamespaces})
	if err != nil {
		t.Fatalf("CollectScopes: %v", err)
	}
	if len(scoped.Result.Workloads) != 1 {
		t.Fatalf("workloads = %#v, want 1", scoped.Result.Workloads)
	}
	if len(scoped.Scopes) != 2 {
		t.Fatalf("scopes = %#v, want 2 statuses", scoped.Scopes)
	}
	byScope := make(map[string]ScopeStatus)
	for _, status := range scoped.Scopes {
		byScope[status.Scope] = status
	}
	if byScope[ScopeWorkloads].Status != ScopeStatusCollected {
		t.Fatalf("workloads scope = %#v, want collected", byScope[ScopeWorkloads])
	}
	denied := byScope[ScopeNamespaces]
	if denied.Status != ScopeStatusDenied || denied.Detail == "" || denied.Resources != "namespaces" {
		t.Fatalf("namespaces scope = %#v, want denied with detail", denied)
	}
}

func TestCollectScopesCollectsNamespaceMetadata(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	executable := writeExecutable(t, `#!/bin/sh
printf '%s' 'apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Namespace
  metadata:
    name: payments
    labels:
      pod-security.kubernetes.io/enforce: restricted
      pod-security.kubernetes.io/enforce-version: v1.36
'
`)
	options := DefaultOptions()
	options.Executable = executable
	options.Kubeconfig = "/tmp/config"

	scoped, err := CollectScopes(context.Background(), options, []string{ScopeNamespaces})
	if err != nil {
		t.Fatalf("CollectScopes: %v", err)
	}
	if len(scoped.Result.Namespaces) != 1 {
		t.Fatalf("namespaces = %#v, want 1", scoped.Result.Namespaces)
	}
	namespace := scoped.Result.Namespaces[0]
	if namespace.Name != "payments" ||
		namespace.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		t.Fatalf("namespace metadata not normalized: %#v", namespace)
	}
}

func TestCollectScopesAbortsOnOperationalFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("release targets darwin and linux")
	}
	executable := writeExecutable(t, `#!/bin/sh
echo 'Unable to connect to the server: dial tcp: lookup cluster.example.com: no such host' >&2
exit 1
`)
	options := DefaultOptions()
	options.Executable = executable
	options.Kubeconfig = "/tmp/config"

	if _, err := CollectScopes(context.Background(), options, []string{ScopeWorkloads}); err == nil {
		t.Fatal("connection failure must abort, not degrade to partial assessment")
	}
}
