# ClusterProof Tasks

## Task 1: Report contract and severity policy

- [x] Define finding, location, source, severity, and report types.
- [x] Parse and compare severity thresholds deterministically.
- [x] Verify with focused unit tests.
- Dependencies: none.
- Files: `internal/model/*`, `go.mod`.

## Task 2: Bounded manifest loading

- [x] Discover only regular YAML files without following symlinks.
- [x] Enforce file, document, and aggregate limits.
- [x] Normalize supported Kubernetes workloads and locations.
- [x] Verify safe and abuse fixtures.
- Dependencies: Task 1.
- Files: `internal/manifest/*`, `testdata/*`.

## Task 3: Native security rules

- [x] Detect high-signal Pod Security Standards violations.
- [x] Detect mutable and digest-unpinned images.
- [x] Return stable IDs, remediation, evidence, and control references.
- [x] Verify every rule with table-driven tests.
- Dependencies: Task 2.
- Files: `internal/rules/*`.

## Task 4: Trivy enrichment

- [x] Normalize bounded Trivy JSON into the shared finding contract.
- [x] Run Trivy only when explicitly requested, without a shell.
- [x] Enforce timeout and output limits.
- [x] Verify with fixture and fake-runner tests.
- Dependencies: Task 1.
- Files: `internal/trivy/*`, `testdata/trivy/*`.

## Task 5: Public report formats

- [x] Render deterministic table and JSON.
- [x] Render valid SARIF 2.1.0 with rule metadata and locations.
- [x] Refuse accidental output overwrite.
- [x] Verify formats with focused tests.
- Dependencies: Tasks 1, 3, 4.
- Files: `internal/report/*`.

## Task 6: Evidence bundle

- [x] Record scan metadata and hashed input inventory.
- [x] Generate high-level SOC 2 readiness coverage.
- [x] Hash bundle files and refuse an existing destination.
- [x] Verify bundle integrity in tests.
- Dependencies: Task 5.
- Files: `internal/evidence/*`.

## Task 7: CLI integration

- [x] Implement `scan` with formats, enrichment, evidence, and threshold flags.
- [x] Return exit codes 0/1/2 per the public contract.
- [x] Verify end-to-end with fixtures.
- Dependencies: Tasks 2-6.
- Files: `cmd/clusterproof/*`.

## Task 8: Documentation and final gate

- [x] Document installation, examples, limits, threat model, and disclaimers.
- [x] Document community/commercial boundaries and service-led revenue.
- Dependencies: all product tasks.
- Files: `README.md`, `SECURITY.md`, `docs/open-core.md`.

## Task 9: Krew and release automation

- [x] Build `kubectl-clusterproof` archives for supported OS/architectures.
- [x] Generate checksum-pinned krew manifests from release archives.
- [x] Run tests, vet, and build on pull requests and main.
- [x] Document and perform local krew installation verification.
- Dependencies: Task 7.
- Files: `.goreleaser.yaml`, `deploy/krew/*`, `.github/workflows/*`.

## Task 10: Final gate

- [x] Run `go test ./...`, `go vet ./...`, and `go build ./...`.
- [x] Run a real fixture scan and review the diff for secrets.
- Dependencies: all tasks.
- Files: existing project files.

## Task 11: Kubernetes List normalization

- [x] Parse one bounded in-memory YAML snapshot into the existing workload model.
- [x] Expand Kubernetes `List.items` without weakening YAML limits.
- [x] Hash snapshot metadata without persisting response content.
- Dependencies: Task 2.
- Files: `internal/manifest/*`.

## Task 12: Read-only cluster collection

- [x] Invoke `kubectl get` with a fixed workload resource allowlist and no shell.
- [x] Require kubeconfig and support optional context/namespace selection.
- [x] Enforce request, process, stderr, and stdout bounds.
- [x] Verify command injection, timeout, and oversized output cases.
- Dependencies: Task 11.
- Files: `internal/cluster/*`.

## Task 13: Cluster CLI integration

- [x] Make repository path and kubeconfig mutually exclusive scan targets.
- [x] Reuse reports, evidence, rules, and exit policy for live workloads.
- [x] Reject repository-only Trivy execution during cluster scans.
- [x] Verify end-to-end with a fake kubectl executable.
- Dependencies: Task 12.
- Files: `cmd/clusterproof/*`, `README.md`.

## Task 14: v0.2.0 release

- [x] Record the open-core boundary in an ADR.
- [x] Run tests, vet, build, abuse checks, and code review.
- [x] Publish checksum-pinned archives and update the krew manifest.
- Dependencies: Tasks 11-13.
- Files: `docs/*`, `CHANGELOG.md`, `deploy/krew/*`.

## Task 15: Versioned ruleset catalog

- [x] Define a stable, independently versioned data contract for native rules.
- [x] Record official source version, URL, and alignment relationship.
- [x] Prove every emitted native rule ID is registered exactly once.
- Dependencies: Task 3.
- Files: `internal/rules/*`, `internal/model/*`.

## Task 16: SOC 2 readiness coverage

- [x] Record the exact ruleset in every report and evidence bundle.
- [x] Report assessed references even when no findings are observed.
- [x] Use only `attention_required`, `no_findings_observed`, and `not_assessed`.
- Dependencies: Task 15.
- Files: `internal/evidence/*`, `cmd/clusterproof/*`.

## Task 17: External PolicyReport import

- [x] Parse bounded `wgpolicyk8s.io/v1alpha2` JSON without executing policy code.
- [x] Normalize fail, warn, and error results; omit pass and skip.
- [x] Clean hostile text and reject malformed, oversized, or unsupported input.
- Dependencies: Task 1.
- Files: `internal/policyreport/*`, `cmd/clusterproof/*`.

## Task 18: Evidence verification CLI

- [x] Reject modified, missing, extra, duplicate, symlinked, and oversized files.
- [x] Add `clusterproof evidence verify DIR` with deterministic exit semantics.
- [x] Add `clusterproof ruleset show` in table and JSON formats.
- Dependencies: Tasks 15-16.
- Files: `internal/evidence/*`, `cmd/clusterproof/*`.

## Task 19: v0.3.0 release

- [ ] Document source, licensing, threat-model, and custody boundaries.
- [ ] Run tests, vet, build, race, abuse checks, and code review.
- [ ] Publish checksum-pinned archives and update the krew submission.
- Dependencies: Tasks 15-18.
- Files: `docs/*`, `CHANGELOG.md`, `deploy/krew/*`.
