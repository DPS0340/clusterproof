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

- [x] Document source, licensing, threat-model, and custody boundaries.
- [x] Run tests, vet, build, race, abuse checks, and code review.
- [x] Publish checksum-pinned archives and update the krew submission.
- Dependencies: Tasks 15-18.
- Files: `docs/*`, `CHANGELOG.md`, `deploy/krew/*`.

## Task 20: Supported PSS version and OS contract

**Description:** Define exactly which Kubernetes minor versions and Linux/Windows
Pod Security Standard semantics the built-in catalog evaluates.

**Acceptance criteria:**
- [x] Catalog metadata identifies the Kubernetes minor and applicable workload OS.
- [x] Linux-only checks do not apply when `spec.os.name` is `windows`.
- [x] An unsupported or ambiguous version is reported explicitly, never treated as `latest`.

**Verification:**
- [x] Table-driven tests cover supported version/OS combinations and unsupported input.
- [x] `clusterproof ruleset show --format json` exposes the version contract.

**Dependencies:** Task 15
**Files likely touched:** `internal/manifest/*`, `internal/rules/*`, `docs/rulesets.md`
**Estimated scope:** Medium

## Task 21: Complete PSS conformance coverage

**Description:** Fill the remaining PSS Baseline and Restricted gaps and generate
a machine-readable coverage matrix that distinguishes aligned, partial, and
supplemental behavior.

**Acceptance criteria:**
- [x] Every applicable PSS v1.36 field has a conformance fixture and catalog entry.
- [x] Host ports, volume types, proc settings, sysctls, AppArmor/SELinux, and OS-specific behavior are covered.
- [x] The matrix never claims complete coverage while an applicable field is missing.

**Verification:**
- [x] Upstream-aligned allow/deny fixtures pass for Baseline and Restricted.
- [x] Catalog drift tests prove every emitted native rule is registered once.

**Dependencies:** Task 20
**Files likely touched:** `internal/manifest/*`, `internal/rules/*`, `testdata/*`, `docs/*`
**Estimated scope:** Medium

## Task 22: Bounded stream input

**Description:** Accept rendered JSON or YAML from stdin so callers can use Helm
or Kustomize without ClusterProof invoking a renderer.

**Acceptance criteria:**
- [x] `clusterproof scan -` accepts bounded multi-document JSON/YAML.
- [x] Stdin cannot be combined with a repository path or live cluster target.
- [x] Stream byte, document, object, and nesting limits fail closed.

**Verification:**
- [x] CLI tests cover valid streams, empty input, malformed input, and every limit.
- [x] A manual Helm/Kustomize pipe smoke test produces the same findings as a saved render.

**Dependencies:** Task 21
**Files likely touched:** `internal/manifest/*`, `cmd/clusterproof/*`, `README.md`
**Estimated scope:** Medium

## Task 23: Repository-owned local exceptions

**Description:** Add a deterministic Community exception file while reserving
central approval and retained waiver history for paid editions.

**Acceptance criteria:**
- [x] Each exception requires rule, target, owner, reason, and expiry.
- [x] Expired or malformed exceptions do not suppress findings.
- [x] Reports and evidence record suppressed finding identity without source secret values.

**Verification:**
- [x] Tests cover exact matching, non-matching, expiry, duplicates, malformed files, and limits.
- [x] JSON/SARIF/evidence remain deterministic with and without exceptions.

**Dependencies:** Tasks 21-22
**Files likely touched:** `internal/exception/*`, `internal/model/*`, `cmd/clusterproof/*`, `docs/*`
**Estimated scope:** Medium

## Task 24: Public schema lifecycle

**Description:** Publish machine-readable schemas and compatibility fixtures for
the report, ruleset, evidence, and exception contracts.

**Acceptance criteria:**
- [x] Schemas are versioned independently and reject structurally invalid examples.
- [x] Additive minor-version fields remain decodable by the previous supported consumer.
- [x] Breaking changes require a new schema major and migration note.

**Verification:**
- [x] CI validates every fixture against its schema.
- [x] Backward-compatibility tests decode v0.3 fixtures with current code.

**Dependencies:** Task 23
**Files likely touched:** `schemas/*`, `internal/model/*`, `.github/workflows/*`, `docs/*`
**Estimated scope:** Medium

## Task 25: Rule explanation and assessment diagnostics

**Description:** Make every result actionable and distinguish secure, empty,
unsupported, and partially assessed scans.

**Acceptance criteria:**
- [x] `clusterproof explain RULE_ID` shows source, scope, evidence, and remediation.
- [x] Empty and unsupported input cannot produce a misleading clean assessment.
- [x] Partial assessment lists the exact unassessed resource or rule scope.

**Verification:**
- [x] CLI tests cover known/unknown rules and all assessment states.
- [x] Table, JSON, SARIF, and evidence render the same assessment semantics.

**Dependencies:** Tasks 21 and 24
**Files likely touched:** `cmd/clusterproof/*`, `internal/model/*`, `internal/report/*`, `docs/*`
**Estimated scope:** Medium

## Task 26: First-party CI distribution and v0.4

**Description:** Ship a checksum-pinned GitHub Action or reusable workflow and
release the trustworthy daily-use milestone.

**Acceptance criteria:**
- [x] The workflow pins a released binary and verifies SHA-256 before execution.
- [x] Users can upload SARIF and evidence without granting write access to a cluster.
- [x] v0.4 release notes document compatibility and rollback.

**Verification:**
- [ ] A public example repository passes and fails on the expected fixtures.
- [x] Tests, race, vet, static analysis, release archives, and Krew install pass.

**Dependencies:** Tasks 20-25
**Files likely touched:** `action.yml`, `.github/*`, `examples/*`, `docs/*`, `deploy/krew/*`
**Estimated scope:** Medium

## Task 27: Cluster scopes and partial assessment

**Description:** Define opt-in workload, access, and network scope packs with
fixed read allowlists and explicit permission preflight.

**Acceptance criteria:**
- [x] Every scope has a versioned resource/verb allowlist.
- [x] Permission denial is represented as partial or not assessed.
- [x] Default behavior remains the current workload-only read.

**Verification:**
- [x] Fake-kubectl tests assert every exact command and rejected argument.
- [x] Evidence lists collected, denied, absent, and unrequested scopes separately.

**Dependencies:** Tasks 24-25
**Files likely touched:** `internal/cluster/*`, `internal/model/*`, `cmd/clusterproof/*`, `docs/*`
**Estimated scope:** Medium

## Task 28: Namespace Pod Security Admission assessment

**Description:** Assess Namespace Pod Security Admission enforce, audit, and warn
labels together with their pinned policy versions.

**Acceptance criteria:**
- [x] Missing, `latest`, inconsistent, and weaker-than-configured labels are distinguished.
- [x] Namespace exemptions are observations, not automatically labeled vulnerabilities.
- [x] Results map to versioned upstream Pod Security Admission guidance.

**Verification:**
- [x] Fixtures cover all modes, levels, version labels, and namespace edge cases.
- [x] Cluster collection requests Namespace metadata only.

**Dependencies:** Task 27
**Files likely touched:** `internal/cluster/*`, `internal/manifest/*`, `internal/rules/*`, `docs/*`
**Estimated scope:** Medium

## Task 29: Bounded RBAC relationship analysis

**Description:** Build a bounded graph of RBAC grants and service-account usage
to identify high-signal privilege paths.

**Acceptance criteria:**
- [x] Rules cover wildcards, Secrets access, workload creation, `pods/exec`, impersonation, bind, and escalate.
- [x] Findings identify the subject-to-role path without exposing credential data.
- [x] Graph node, edge, depth, and output limits fail closed.

**Verification:**
- [x] Fixtures cover namespaced/cluster bindings, aggregation, groups, and cycles.
- [x] The collector requests only RBAC metadata and workload service-account names.

**Dependencies:** Tasks 27-28
**Files likely touched:** `internal/cluster/*`, `internal/rbac/*`, `internal/model/*`, `cmd/clusterproof/*`
**Estimated scope:** Medium

## Task 30: Network policy and exposure analysis

**Description:** Relate workloads to NetworkPolicies and supported exposure
resources while documenting CNI-dependent limitations.

**Acceptance criteria:**
- [x] Detect absent default-deny coverage and externally exposed sensitive workloads.
- [x] Selector, namespace, ingress, egress, Service, Ingress, and supported Gateway relationships are bounded.
- [x] Results never claim effective packet filtering without a supported CNI signal.

**Verification:**
- [x] Fixtures cover selector overlap, empty selectors, dual-stack data, and unselected workloads.
- [x] Collection and graph-size abuse tests pass.

**Dependencies:** Task 27
**Files likely touched:** `internal/cluster/*`, `internal/network/*`, `internal/model/*`, `cmd/clusterproof/*`
**Estimated scope:** Medium

## Task 31: Deterministic snapshot comparison

**Description:** Compare two local reports or evidence bundles without retaining
history in a service.

**Acceptance criteria:**
- [x] Output classifies new, resolved, unchanged, and severity-changed findings.
- [x] Incompatible schema/ruleset versions fail with a migration-oriented error.
- [x] Comparison is deterministic and contains both input hashes.

**Verification:**
- [x] Tests cover ordering, duplicates, changed locations, and incompatible inputs.
- [x] `clusterproof compare BEFORE AFTER` works for JSON and evidence directories.

**Dependencies:** Tasks 24 and 27
**Files likely touched:** `internal/compare/*`, `internal/model/*`, `cmd/clusterproof/*`, `docs/*`
**Estimated scope:** Medium

## Task 32: Experimental OpenReports adapter

**Description:** Import bounded `openreports.io/v1alpha1` Report and ClusterReport
objects behind an explicit experimental adapter.

**Acceptance criteria:**
- [x] Supported API/kind combinations and resource limits are allowlisted.
- [x] Import never installs CRDs or executes producer policy code.
- [x] Adapter version and input hash are recorded in the report.

**Verification:**
- [x] Tests cover current upstream examples, unknown fields/outcomes, lists, and limits.
- [x] Existing `wgpolicyk8s.io/v1alpha2` behavior remains unchanged.

**Dependencies:** Tasks 24 and 27
**Files likely touched:** `internal/openreports/*`, `internal/model/*`, `cmd/clusterproof/*`, `docs/*`
**Estimated scope:** Medium

## Task 33: v0.5 performance and release gate

**Description:** Establish the broader cluster-scan resource budget and release
the attack-surface milestone.

**Acceptance criteria:**
- [x] A 5,000-workload reference fixture stays under 10 seconds and 512 MiB on documented hardware.
- [x] Missing permissions and resource limits produce complete partial-assessment evidence.
- [x] Release documentation lists the additional Kubernetes read permissions.

**Verification:**
- [ ] Benchmarks, fuzz/abuse tests, race, vet, static analysis, and builds pass.
- [ ] Release archives and a fresh Krew installation report v0.5.

**Dependencies:** Tasks 27-32
**Files likely touched:** `internal/*`, `testdata/*`, `docs/*`, `deploy/krew/*`
**Estimated scope:** Medium

## Task 34: Supply-chain trust policy

**Description:** Define a data-only trust policy for signatures, identities,
issuers, builders, sources, and allowed attestation predicates.

**Acceptance criteria:**
- [x] The contract is versioned, bounded, and contains no private key material.
- [x] Keyless identities require both certificate identity and OIDC issuer.
- [x] Unknown policy fields or unsupported predicates fail closed.

**Verification:**
- [x] Schema and parser tests cover valid, ambiguous, hostile, and oversized policy files.
- [x] `clusterproof trust show` renders the exact effective policy.

**Dependencies:** Task 24
**Files likely touched:** `internal/trust/*`, `internal/model/*`, `schemas/*`, `docs/*`
**Estimated scope:** Medium

## Task 35: Image inventory and digest resolution

**Description:** Export deterministic image inventory and optionally resolve tags
to exact registry digests.

**Acceptance criteria:**
- [x] Offline inventory works without registry access.
- [x] Resolution requires explicit opt-in, timeout, registry allowlist, and output limits.
- [x] Registry credentials and tokens are never persisted or emitted.

**Verification:**
- [x] Fake-registry tests cover digest match, tag movement, auth failure, timeout, and oversized response.
- [x] Evidence records the resolved digest, registry, timestamp, and network use.

**Dependencies:** Task 34
**Files likely touched:** `internal/image/*`, `internal/model/*`, `cmd/clusterproof/*`, `docs/*`
**Estimated scope:** Medium

## Task 36: Sigstore signature verification

**Description:** Verify image signatures and offline bundles against the explicit
trust policy.

**Acceptance criteria:**
- [x] Verification binds the signature payload to the exact image digest.
- [x] Online lookup is opt-in; an offline bundle never triggers hidden network access.
- [x] Wrong identity, issuer, key, digest, expiry, or transparency proof fails.

**Verification:**
- [x] Hermetic fixtures cover key, keyless, offline, malformed, and timeout paths.
- [x] Any subprocess uses fixed arguments, no shell, and bounded stdout/stderr.

**Dependencies:** Tasks 34-35
**Files likely touched:** `internal/sigstore/*`, `internal/model/*`, `cmd/clusterproof/*`, `docs/*`
**Estimated scope:** Medium

## Task 37: SLSA provenance verification

**Description:** Verify SLSA v1.2 provenance subject, builder, and source
expectations against the resolved artifact.

**Acceptance criteria:**
- [x] The subject digest must match the resolved image digest.
- [x] Builder, source repository, and predicate type are checked only against explicit policy.
- [x] Unsupported SLSA versions or incomplete statements fail as not verified.

**Verification:**
- [x] Tests cover valid provenance, wrong subject/builder/source, and oversized statements.
- [x] Findings distinguish missing, invalid, and policy-mismatched provenance.

**Dependencies:** Tasks 34-36
**Files likely touched:** `internal/slsa/*`, `internal/model/*`, `cmd/clusterproof/*`, `docs/*`
**Estimated scope:** Medium

## Task 38: SBOM and VEX import

**Description:** Import bounded SPDX/CycloneDX inventories and VEX status without
turning absence of a vulnerability record into proof of safety.

**Acceptance criteria:**
- [x] Supported schema versions, package counts, strings, and relationships are bounded.
- [x] VEX status applies only to an exact product/package/vulnerability identity.
- [x] Unknown or stale VEX data cannot silently clear a finding.

**Verification:**
- [x] Fixtures cover both SBOM formats, duplicate packages, malformed graphs, and VEX edge cases.
- [x] Input hashes and adapter versions appear in reports and evidence.

**Dependencies:** Tasks 34-35
**Files likely touched:** `internal/sbom/*`, `internal/vex/*`, `internal/model/*`, `cmd/clusterproof/*`
**Estimated scope:** Medium

## Task 39: Evidence authenticity

**Description:** Add signing and signer verification for the existing evidence
manifest while retaining unsigned integrity verification.

**Acceptance criteria:**
- [x] Output distinguishes integrity-verified, signature-verified, and unverified states.
- [x] Signing is explicit and does not make ClusterProof a private-key store.
- [x] Signer identity, issuer/key reference, algorithm, and verification time are recorded.

**Verification:**
- [x] Tests reject modified manifests, wrong signers, expired material, symlinks, and oversized signatures.
- [x] Offline verification succeeds with the complete required trust bundle.

**Dependencies:** Tasks 34 and 36
**Files likely touched:** `internal/evidence/*`, `internal/trust/*`, `cmd/clusterproof/*`, `docs/*`
**Estimated scope:** Medium

## Task 40: v0.6 offline/network abuse gate

**Description:** Validate the full supply-chain mode matrix and release v0.6.

**Acceptance criteria:**
- [x] Offline mode makes no network request and rejects missing remote material explicitly.
- [x] Every online request is opt-in, bounded, allowlisted, and represented in evidence.
- [x] Rollback to the previous supported release preserves readable evidence.

**Verification:**
- [x] Network-denial, malicious-registry, forged-attestation, fuzz, race, vet, static analysis, and build checks pass.
- [x] Release archives and a fresh Krew installation report v0.6.

**Dependencies:** Tasks 34-39
**Files likely touched:** `internal/*`, `testdata/*`, `.github/*`, `docs/*`, `deploy/krew/*`
**Estimated scope:** Medium

## Task 41: Commercial discovery gate

**Description:** Validate repeatable customer pain before specifying or building
the separate Team control plane.

**Acceptance criteria:**
- [ ] Five design-partner interviews and three weekly active teams are documented.
- [ ] Two paid engagements or pilots validate willingness to pay.
- [ ] At least three teams share the same history, baseline, waiver, or rollup problem.

**Verification:**
- [ ] A reviewed commercial spec defines tenants, data custody, auth/RBAC, retention, audit events, and open-core boundaries.
- [ ] No control-plane implementation starts until the gate is explicitly approved.

**Dependencies:** Tasks 26-40 may inform discovery; no technical dependency blocks interviews
**Files likely touched:** `docs/private-product-spec.md` in the private repository, design-partner research records
**Estimated scope:** Medium
