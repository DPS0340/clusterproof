# Spec: ClusterProof MVP

## Objective

Build a read-only Go CLI for platform and security teams that scans Kubernetes
manifests or a live cluster selected by kubeconfig, optionally enriches repository
results with Trivy output, and produces
machine-readable findings plus a tamper-evident SOC 2 readiness evidence bundle.

The first successful user flow is:

```text
clusterproof scan ./deploy \
  --format sarif \
  --output clusterproof.sarif \
  --evidence-dir evidence \
  --fail-on high
```

The live-cluster flow is:

```text
clusterproof scan --kubeconfig ~/.kube/config \
  --context production \
  --namespace payments \
  --fail-on high
```

The command must find high-signal workload risks, explain remediation, inventory
container image references, preserve evidence about exactly what was scanned, and
exit non-zero when the configured policy threshold is reached.

This is not a compliance certification product. It generates technical evidence
that an organization can map into its auditor-approved control framework.

## Assumptions

1. Users scan checked-out Kubernetes YAML, Helm-rendered YAML, Kustomize output,
   or one explicitly selected kubeconfig/context.
2. Repository scans run offline. Cluster scans contact only the Kubernetes API
   selected by the user's kubeconfig and perform no telemetry.
3. Trivy is an optional executable integration selected explicitly by the user.
4. SOC 2 output uses high-level control-family references such as `SOC2:CC6` and
   `SOC2:CC7`; it does not reproduce licensed Trust Services Criteria text.
5. Automatic fixes, admission control, dashboards, multi-tenancy, and credential
   storage are out of scope.
6. The community core is Apache-2.0 and the release binary is installable as
   `kubectl clusterproof` through krew.

## Product Boundaries

```text
untrusted YAML ──> bounded loader ──> normalized workloads ──> rule engine
                                                              │
read-only kubectl get ──> bounded snapshot ────────────────────┤
                                                              │
optional Trivy JSON ──> bounded decoder ──> normalized findings┤
                                                              │
PolicyReport JSON ──> bounded result-only adapter ─────────────┤
                                                              ▼
                              table / JSON / SARIF / evidence bundle
```

### Included

- Recursive `.yaml` / `.yml` discovery without following symlinks.
- Read-only live workload collection through an explicit kubeconfig, with optional
  context and namespace selection.
- Workload extraction from Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet,
  Job, and CronJob resources.
- Live-scan de-duplication of controller-owned Pods, Deployment-owned ReplicaSets,
  and CronJob-owned Jobs.
- Stable findings for privileged execution, host namespaces, hostPath mounts,
  privilege escalation, root execution, missing seccomp, dangerous capabilities,
  writable root filesystems, service-account token automount, mutable image tags,
  and unpinned images.
- Optional import of Trivy JSON and optional bounded Trivy subprocess execution.
- Bounded import of `wgpolicyk8s.io/v1alpha2` PolicyReport results without
  downloading or executing policy code.
- An independently versioned native catalog with explicit PSS-aligned or
  supplemental source relationships.
- Table, JSON, and SARIF 2.1.0 reports.
- Evidence directory containing report JSON, input inventory with SHA-256 hashes,
  control-family coverage, tool metadata, and a SHA-256 manifest of bundle files.
- Offline evidence verification that rejects missing, modified, extra,
  symlinked, or oversized files.
- Severity threshold exit codes suitable for CI.
- Cross-platform release archives and a krew manifest for `darwin` and `linux`
  on `amd64` and `arm64`.

### Excluded

- Mutating Kubernetes resources or producing an `apply` command.
- Reading Secrets, ConfigMaps, logs, events, or Kubernetes object status.
- Cluster-wide history, rollups, and continuous monitoring.
- Reading live Secret values.
- Uploading findings or telemetry.
- Claiming SOC 2 conformity, audit completion, or certification.
- Reproducing AICPA Trust Services Criteria descriptions.
- Verifying image signatures online in MVP; image digest policy is checked locally.
- CVE database maintenance; vulnerability intelligence remains Trivy's job.
- Paid collaboration services in the community binary; the commercial boundary is
  specified separately in `docs/open-core.md`.

## Threat Model

### Trust boundaries and assets

| Boundary | Assets at risk | Main threats | Mitigations |
| --- | --- | --- | --- |
| YAML files to parser | Availability, terminal output | Alias bombs, huge files, malformed data, secret disclosure | Size/count/document/depth limits, no secret values in output, no symlinks |
| Trivy JSON to decoder | Memory, report integrity | Oversized or malformed output, forged severity | Output cap, strict normalization, source marked as external |
| PolicyReport JSON to decoder | Memory, confidentiality, report integrity | Oversized result sets, forged severity, terminal or secret disclosure | Input/report/result caps, schema allowlist, text normalization, source messages omitted, no policy execution |
| CLI to Trivy process | Host execution, availability | Argument injection, hanging process, unexpected network | No shell, fixed executable, explicit opt-in, timeout, bounded output |
| CLI to kubectl process | Kubeconfig credentials, cluster availability, host execution | Argument injection, mutation, broad data collection, hanging API, kubeconfig exec plugin | No shell, fixed `get` verb/resource allowlist, explicit trusted kubeconfig, request/process timeout, bounded output, no Secret collection |
| Kubernetes API output to parser | Memory, report integrity | Oversized or malformed response, terminal data leakage | Output cap, shared YAML limits, security-relevant workload fields only |
| Report/evidence writes and verification | Existing user files, evidence integrity | Path overwrite, partial bundle, tampering, manifest path confusion | Refuse overwrite by default, restrictive permissions, atomic writes, exact file set, safe relative paths, bounded SHA-256 verification |

### Abuse cases

- A repository contains a symlink to a sensitive directory: skip it.
- A YAML file contains thousands of documents or deeply nested aliases: fail
  closed at the configured resource limits.
- A manifest contains plaintext credentials: never echo values in findings.
- A malicious path begins with `-`: pass it as a positional argument to a process
  only after `--`.
- Trivy hangs or emits unbounded output: terminate on timeout or output cap.
- A context or namespace begins with `-` or contains shell syntax: pass it as the
  value of a separate fixed argument without invoking a shell.
- A kubeconfig grants mutation or Secret access: ClusterProof still invokes only
  `kubectl get` for its fixed workload resource allowlist.
- An untrusted kubeconfig defines an executable credential plugin: this is outside
  ClusterProof's isolation boundary, so users must select only trusted kubeconfigs.
- The API returns an oversized snapshot: terminate collection and fail closed.
- A PolicyReport includes hostile or sensitive result messages: normalize only
  bounded identifiers and metadata; omit source messages.
- An evidence directory contains an untracked file or symlink: reject the whole
  bundle rather than partially verifying it.
- A report path already exists: refuse replacement unless a future explicit
  overwrite option is added.

## Tech Stack

- Go 1.26
- `gopkg.in/yaml.v3`
- Optional local executable: Trivy 0.59+ for repository enrichment
- Required for cluster scans: a compatible `kubectl` executable and an explicit
  kubeconfig path

## Commands

- Build: `go build ./...`
- Test: `go test ./...`
- Format: `gofmt -w .`
- Vet: `go vet ./...`
- Local scan: `go run ./cmd/clusterproof scan ./testdata/insecure`
- Cluster scan: `go run ./cmd/clusterproof scan --kubeconfig ~/.kube/config`

## Project Structure

```text
cmd/clusterproof/       CLI parsing and exit policy
internal/model/         Stable report and finding contracts
internal/manifest/      Bounded discovery and Kubernetes object extraction
internal/cluster/       Read-only, bounded kubectl workload collection
internal/rules/         Native Kubernetes security checks and ruleset catalog
internal/trivy/         Optional Trivy execution and JSON normalization
internal/policyreport/  Bounded external result-only normalization
internal/report/        Table, JSON, SARIF, and evidence writers
internal/evidence/      Readiness bundle writer and verifier
testdata/               Benign and intentionally insecure fixtures
docs/                   Product spec and source notes
tasks/                  Implementation plan and tracked tasks
deploy/krew/            Krew release and local-install instructions
.github/workflows/      Pull-request quality gate and tagged release
.goreleaser.yaml        Reproducible cross-platform release archives
```

## Code Style

```go
func Evaluate(workload model.Workload) []model.Finding {
	var findings []model.Finding
	if workload.HostPID {
		findings = append(findings, hostPIDFinding(workload))
	}
	return findings
}
```

- Prefer explicit domain types over `map[string]any` after parsing.
- Pure rules receive normalized values and return findings without I/O.
- Stable, deterministic ordering is part of the output contract.
- Error messages contain paths and operations, but never document values.

## Testing Strategy

- Unit tests: rule behavior/catalog, severity threshold, Trivy and PolicyReport
  normalization, safe writes and evidence verification.
- Integration tests: recursive YAML and fake-kubectl scans through rendered
  JSON/SARIF/evidence.
- Abuse tests: symlink skip, file/output limits, malformed YAML/JSON, hostile
  PolicyReports, existing output, and evidence path confusion.
- Golden tests only for stable public formats where focused assertions are weaker.
- Every behavior test must fail before its implementation is added.

## Boundaries

- Always: validate inputs, use safe defaults, preserve deterministic output, run
  tests/vet/build, document public formats.
- Ask first: new dependency, network-by-default behavior, live cluster access,
  persistence, authentication, mutation, CI publishing.
- Never: commit secrets, follow symlinks, execute a shell or imported policy,
  expose manifest/policy-result secret values, silently overwrite evidence, or
  claim audit certification.

## Success Criteria

1. The insecure fixture produces findings in all three native domains:
   Kubernetes posture, supply-chain integrity, and vulnerability enrichment.
2. The secure fixture has no high or critical native findings.
3. JSON and SARIF are deterministic and valid; SARIF includes rule help and
   source locations.
4. `--fail-on high` returns the documented policy exit code when a high or
   critical finding exists.
5. Evidence bundle hashes verify and an existing destination is not overwritten.
6. Repository execution performs no network call. Cluster execution uses only the
   selected Kubernetes API and never requests a mutating verb.
7. `go test ./...`, `go vet ./...`, and `go build ./...` pass.
8. A local release archive installs through krew and runs as
   `kubectl clusterproof`.
9. `--kubeconfig` cannot be combined with a repository path or Trivy execution,
   and cluster snapshots are bounded in size and time.
10. Every native rule is present in the versioned catalog, and imported external
    policies are results only.

## Sources and Legal Notes

- Kubernetes Security Checklist:
  https://kubernetes.io/docs/concepts/security/security-checklist/
- Kubernetes Pod Security Standards:
  https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubernetes Pod Security Admission version pinning:
  https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Kubernetes RBAC good practices:
  https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Kubectl get reference:
  https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/
- Kubernetes authorization and `kubectl auth can-i`:
  https://kubernetes.io/docs/reference/access-authn-authz/authorization/
- Trivy Kubernetes scanning:
  https://trivy.dev/docs/latest/guide/target/kubernetes/
- Trivy SBOM support:
  https://trivy.dev/docs/latest/guide/supply-chain/sbom/
- Sigstore policy-controller:
  https://docs.sigstore.dev/policy-controller/overview/
- Kyverno Policy Reports:
  https://kyverno.io/docs/guides/reports/
- OPA Gatekeeper Policy Library:
  https://open-policy-agent.github.io/gatekeeper-library/website/
- NIST OSCAL Assessment Results:
  https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/
- AICPA licensing notice for Trust Services Criteria and SOC marks:
  https://www.aicpa-cima.com/resources/landing/licensing-for-teams
- Krew plugin manifest:
  https://krew.sigs.k8s.io/docs/developer-guide/plugin-manifest/
- Krew release checklist:
  https://krew.sigs.k8s.io/docs/developer-guide/release/new-plugin/

ClusterProof's mappings are implementation-oriented readiness references, not
licensed criteria text and not an auditor opinion.
