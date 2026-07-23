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

- [ ] Detect high-signal Pod Security Standards violations.
- [ ] Detect mutable and digest-unpinned images.
- [ ] Return stable IDs, remediation, evidence, and control references.
- [ ] Verify every rule with table-driven tests.
- Dependencies: Task 2.
- Files: `internal/rules/*`.

## Task 4: Trivy enrichment

- [ ] Normalize bounded Trivy JSON into the shared finding contract.
- [ ] Run Trivy only when explicitly requested, without a shell.
- [ ] Enforce timeout and output limits.
- [ ] Verify with fixture and fake-runner tests.
- Dependencies: Task 1.
- Files: `internal/trivy/*`, `testdata/trivy/*`.

## Task 5: Public report formats

- [ ] Render deterministic table and JSON.
- [ ] Render valid SARIF 2.1.0 with rule metadata and locations.
- [ ] Refuse accidental output overwrite.
- [ ] Verify formats with focused tests.
- Dependencies: Tasks 1, 3, 4.
- Files: `internal/report/*`.

## Task 6: Evidence bundle

- [ ] Record scan metadata and hashed input inventory.
- [ ] Generate high-level SOC 2 readiness coverage.
- [ ] Hash bundle files and refuse an existing destination.
- [ ] Verify bundle integrity in tests.
- Dependencies: Task 5.
- Files: `internal/evidence/*`.

## Task 7: CLI integration

- [ ] Implement `scan` with formats, enrichment, evidence, and threshold flags.
- [ ] Return exit codes 0/1/2 per the public contract.
- [ ] Verify end-to-end with fixtures.
- Dependencies: Tasks 2-6.
- Files: `cmd/clusterproof/*`.

## Task 8: Documentation and final gate

- [ ] Document installation, examples, limits, threat model, and disclaimers.
- [ ] Document community/commercial boundaries and service-led revenue.
- Dependencies: all product tasks.
- Files: `README.md`, `SECURITY.md`, `docs/open-core.md`.

## Task 9: Krew and release automation

- [ ] Build `kubectl-clusterproof` archives for supported OS/architectures.
- [ ] Add a krew plugin manifest template with immutable checksums.
- [ ] Run tests, vet, and build on pull requests and main.
- [ ] Document local krew installation verification.
- Dependencies: Task 7.
- Files: `.goreleaser.yaml`, `deploy/krew/*`, `.github/workflows/*`.

## Task 10: Final gate

- [ ] Run `go test ./...`, `go vet ./...`, and `go build ./...`.
- [ ] Run a real fixture scan and review the diff for secrets.
- Dependencies: all tasks.
- Files: existing project files.
