# Spec: ClusterProof MVP

## Objective

Build a read-only Go CLI for platform and security teams that scans Kubernetes
manifests, optionally enriches the result with Trivy output, and produces
machine-readable findings plus a tamper-evident SOC 2 readiness evidence bundle.

The first successful user flow is:

```text
clusterproof scan ./deploy \
  --format sarif \
  --output clusterproof.sarif \
  --evidence-dir evidence \
  --fail-on high
```

The command must find high-signal workload risks, explain remediation, inventory
container image references, preserve evidence about exactly what was scanned, and
exit non-zero when the configured policy threshold is reached.

This is not a compliance certification product. It generates technical evidence
that an organization can map into its auditor-approved control framework.

## Assumptions

1. MVP users scan checked-out Kubernetes YAML, Helm-rendered YAML, or Kustomize
   output; direct cluster access comes after the local workflow is trusted.
2. The CLI runs offline by default and performs no telemetry or network calls.
3. Trivy is an optional executable integration selected explicitly by the user.
4. SOC 2 output uses high-level control-family references such as `SOC2:CC6` and
   `SOC2:CC7`; it does not reproduce licensed Trust Services Criteria text.
5. Automatic fixes, admission control, dashboards, multi-tenancy, and credential
   storage are out of scope.

## Product Boundaries

```text
untrusted YAML ──> bounded loader ──> normalized workloads ──> rule engine
                                                              │
optional Trivy JSON ──> bounded decoder ──> normalized findings┤
                                                              ▼
                              table / JSON / SARIF / evidence bundle
```

### Included

- Recursive `.yaml` / `.yml` discovery without following symlinks.
- Workload extraction from Pod, Deployment, StatefulSet, DaemonSet, Job, and
  CronJob resources.
- Stable findings for privileged execution, host namespaces, hostPath mounts,
  privilege escalation, root execution, missing seccomp, dangerous capabilities,
  writable root filesystems, service-account token automount, mutable image tags,
  and unpinned images.
- Optional import of Trivy JSON and optional bounded Trivy subprocess execution.
- Table, JSON, and SARIF 2.1.0 reports.
- Evidence directory containing report JSON, input inventory with SHA-256 hashes,
  control-family coverage, tool metadata, and a SHA-256 manifest of bundle files.
- Severity threshold exit codes suitable for CI.

### Excluded

- Mutating Kubernetes resources or producing an `apply` command.
- Reading live Secret values.
- Uploading findings or telemetry.
- Claiming SOC 2 conformity, audit completion, or certification.
- Reproducing AICPA Trust Services Criteria descriptions.
- Verifying image signatures online in MVP; image digest policy is checked locally.
- CVE database maintenance; vulnerability intelligence remains Trivy's job.

## Threat Model

### Trust boundaries and assets

| Boundary | Assets at risk | Main threats | Mitigations |
| --- | --- | --- | --- |
| YAML files to parser | Availability, terminal output | Alias bombs, huge files, malformed data, secret disclosure | Size/count/document/depth limits, no secret values in output, no symlinks |
| Trivy JSON to decoder | Memory, report integrity | Oversized or malformed output, forged severity | Output cap, strict normalization, source marked as external |
| CLI to Trivy process | Host execution, availability | Argument injection, hanging process, unexpected network | No shell, fixed executable, explicit opt-in, timeout, bounded output |
| Report/evidence writes | Existing user files, evidence integrity | Path overwrite, partial bundle, tampering | Refuse overwrite by default, restrictive permissions, atomic writes, SHA-256 bundle manifest |

### Abuse cases

- A repository contains a symlink to a sensitive directory: skip it.
- A YAML file contains thousands of documents or deeply nested aliases: fail
  closed at the configured resource limits.
- A manifest contains plaintext credentials: never echo values in findings.
- A malicious path begins with `-`: pass it as a positional argument to a process
  only after `--`.
- Trivy hangs or emits unbounded output: terminate on timeout or output cap.
- A report path already exists: refuse replacement unless a future explicit
  overwrite option is added.

## Tech Stack

- Go 1.26
- `gopkg.in/yaml.v3`
- Optional local executables: Trivy 0.59+; no hard runtime dependency for native
  manifest checks

## Commands

- Build: `go build ./...`
- Test: `go test ./...`
- Format: `gofmt -w .`
- Vet: `go vet ./...`
- Local scan: `go run ./cmd/clusterproof scan ./testdata/insecure`

## Project Structure

```text
cmd/clusterproof/       CLI parsing and exit policy
internal/model/         Stable report and finding contracts
internal/manifest/      Bounded discovery and Kubernetes object extraction
internal/rules/         Native Kubernetes security checks
internal/trivy/         Optional Trivy execution and JSON normalization
internal/report/        Table, JSON, SARIF, and evidence writers
testdata/               Benign and intentionally insecure fixtures
docs/                   Product spec and source notes
tasks/                  Implementation plan and tracked tasks
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

- Unit tests: rule behavior, severity threshold, Trivy normalization, safe writes.
- Integration tests: recursive YAML scan through rendered JSON/SARIF/evidence.
- Abuse tests: symlink skip, file/output limits, malformed YAML, existing output.
- Golden tests only for stable public formats where focused assertions are weaker.
- Every behavior test must fail before its implementation is added.

## Boundaries

- Always: validate inputs, use safe defaults, preserve deterministic output, run
  tests/vet/build, document public formats.
- Ask first: new dependency, network-by-default behavior, live cluster access,
  persistence, authentication, mutation, CI publishing.
- Never: commit secrets, follow symlinks, execute a shell, expose manifest secret
  values, silently overwrite evidence, or claim audit certification.

## Success Criteria

1. The insecure fixture produces findings in all three native domains:
   Kubernetes posture, supply-chain integrity, and vulnerability enrichment.
2. The secure fixture has no high or critical native findings.
3. JSON and SARIF are deterministic and valid; SARIF includes rule help and
   source locations.
4. `--fail-on high` returns the documented policy exit code when a high or
   critical finding exists.
5. Evidence bundle hashes verify and an existing destination is not overwritten.
6. Default execution performs no network call and no cluster mutation.
7. `go test ./...`, `go vet ./...`, and `go build ./...` pass.

## Sources and Legal Notes

- Kubernetes Security Checklist:
  https://kubernetes.io/docs/concepts/security/security-checklist/
- Kubernetes Pod Security Standards:
  https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubernetes RBAC good practices:
  https://kubernetes.io/docs/concepts/security/rbac-good-practices/
- Trivy Kubernetes scanning:
  https://trivy.dev/docs/latest/guide/target/kubernetes/
- Trivy SBOM support:
  https://trivy.dev/docs/latest/guide/supply-chain/sbom/
- Sigstore policy-controller:
  https://docs.sigstore.dev/policy-controller/overview/
- AICPA licensing notice for Trust Services Criteria and SOC marks:
  https://www.aicpa-cima.com/resources/landing/licensing-for-teams

ClusterProof's mappings are implementation-oriented readiness references, not
licensed criteria text and not an auditor opinion.
