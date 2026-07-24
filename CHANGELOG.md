# Changelog

All notable changes to ClusterProof are documented here.

## [Unreleased]

## [0.6.0] - 2026-07-24

### Added

- Data-only supply-chain trust policy (`clusterproof trust show`) pinning
  keyless identities (subject and OIDC issuer both required), PEM public
  keys, SLSA builder/source expectations, and an explicit predicate-type
  allowlist where an empty list accepts nothing. Private key material and
  unknown fields fail closed; a JSON Schema documents the contract.
- Deterministic offline image inventory (`clusterproof image inventory`)
  and explicit tag-to-digest resolution requiring a registry allowlist,
  performing one anonymous bounded HEAD request, never storing credentials,
  and recording digest, registry, timestamp, and network use.
- Sigstore signature verification through a bounded cosign subprocess with
  fixed arguments and no shell. Floating tags are refused outright, offline
  mode requires a bundle and makes no network request, empty or unparsable
  claims count as unverified, and mode, identity, offline state, network
  use, and failure causes are recorded for evidence.
- SLSA v1 provenance verification binding the attestation subject to the
  exact image digest, checking builder and source only against explicit
  policy pins, and distinguishing verified, missing, invalid, and
  policy_mismatch outcomes with regression tests for forged subjects and
  wrong builders/sources.
- Bounded SPDX 2.2/2.3 and CycloneDX 1.4-1.6 SBOM import with deterministic
  deduplicated inventories, plus OpenVEX import where a status applies only
  to an exact vulnerability/product identity, not_affected requires a
  justification, and stale statements never suppress findings.
- Evidence manifest signing (`clusterproof evidence sign`) with detached
  Ed25519 signatures over the exact manifest bytes and caller-provided
  keys. Verification distinguishes integrity_verified, signature_verified,
  and unverified; an embedded key never proves authenticity without a
  pinned `--signer-key`, and verification works fully offline.

### Network and offline guarantees

- Repository scans, inventory export, provenance verification, SBOM/VEX
  import, and evidence signing/verification make no network request.
- The only network-capable operations are explicit tag resolution (registry
  allowlist required) and cosign verification with `AllowNetwork` opt-in;
  both are recorded in their results.

### Compatibility

- Report schema stays at version 1. The evidence signature file is outside
  the hashed manifest; the legacy strict `evidence verify` path without
  `--signer-key` treats it as untracked, preserving pre-0.6 behavior for
  unsigned bundles, while the signature-aware path accepts and verifies it.

## [0.5.0] - 2026-07-24

### Added

- Opt-in cluster scope packs via `--cluster-scopes`: `workloads` (default),
  `namespaces`, `rbac`, and `network`, each one fixed, versioned read-only
  `kubectl get`. Authorization denial or an absent resource type is recorded
  in the additive `cluster_scopes` report field as `denied`/`absent` partial
  assessment; operational failures still abort the scan.
- Namespace Pod Security Admission assessment (catalog rules CP-K8S-018
  through CP-K8S-022): missing enforce level, undefined levels, explicit
  privileged profile, unpinned or `latest` policy versions, and audit/warn
  modes weaker than enforce. Control-plane namespaces are excluded as an
  operator decision.
- Bounded RBAC privilege-path analysis (CP-RBAC-001 through CP-RBAC-007):
  wildcard grants, Secrets read access, workload creation, `pods/exec`,
  impersonation, bind/escalate, and service-account token minting, each
  identifying the exact subject-to-role path. Roles resolve within their own
  namespace only and dangling references are skipped.
- NetworkPolicy and exposure analysis (CP-NET-001, CP-NET-002): namespaces
  running workloads without all-pod default-deny coverage per direction, and
  NodePort/LoadBalancer Services selecting host-namespace or privileged
  workloads. Findings describe declared policy objects only and never claim
  effective packet filtering.
- Deterministic `clusterproof compare BEFORE AFTER` classifying findings as
  new, resolved, severity-changed, or unchanged with both input hashes;
  incompatible schema or ruleset versions fail with a migration-oriented
  error, and exit code 2 gates CI on new or escalated findings.
- Experimental `openreports.io/v1alpha1` adapter via `--openreports-json`
  with a recorded adapter version and the same boundedness and
  no-policy-execution guarantees as the PolicyReport adapter.
- A 5,000-workload performance gate: parsing plus evaluation completes in
  roughly 0.1 seconds using about 102 MiB of heap on reference hardware
  (Apple M-series), within the documented 10-second / 512 MiB budget.

### Changed

- Catalog version is 1.4.0. Native rules now span workload posture,
  namespace admission, RBAC, network, and supply-chain categories.

### Permissions

- The default cluster scan still requires only `list` on workload resources.
  Optional scopes add `list` on: namespaces (`namespaces`); roles,
  clusterroles, rolebindings, clusterrolebindings (`rbac`); networkpolicies
  and services (`network`). No scope requests Secrets, ConfigMap payloads,
  logs, events, or any mutation.

### Compatibility

- Report schema stays at version 1; `cluster_scopes` is additive and omitted
  for repository scans. v0.3/v0.4 JSON consumers decode v0.5 reports
  unchanged.

## [0.4.0] - 2026-07-24

### Added

- Catalog 1.1.0 with a pinned Kubernetes version contract: the reviewed minor,
  the supported minor list, and per-rule workload OS applicability are exposed
  by `clusterproof ruleset show`. Ambiguous versions such as `latest` are
  rejected explicitly.
- Complete PSS Baseline and Restricted conformance coverage: host ports,
  restricted volume-type allowlist, procMount, safe sysctl allowlist, AppArmor,
  SELinux, and Windows HostProcess checks (CP-K8S-011 through CP-K8S-017),
  plus a machine-readable coverage matrix with `complete` and `partial`
  states enforced by drift tests.
- Bounded stdin input: `clusterproof scan -` accepts rendered multi-document
  YAML/JSON from Helm or Kustomize without executing a renderer.
- Repository-owned exception files via `--exceptions`, requiring rule, target,
  owner, reason, and UTC expiry. Suppressed identities are recorded in the
  report as the additive `suppressed_findings` field.
- Published JSON Schemas for the report and exception contracts, a v0.3
  compatibility fixture, strict-decode compatibility tests, and CI schema
  validation. `docs/contracts.md` defines the additive-only change policy.
- `clusterproof explain RULE_ID` with catalog-backed description, remediation,
  OS scope, sources, and PSS coverage.
- An additive report `assessment` object distinguishing assessed scans from
  `no_workloads_assessed`, so empty input can never present as a clean result.
- A first-party composite GitHub Action (`action.yml`) that downloads a pinned
  release, verifies its SHA-256 before execution, and gates on severity, with
  a copyable example workflow in `examples/`.

### Changed

- Declared Windows workloads (`spec.os.name: windows`) no longer receive
  Linux-only findings for privilege escalation, seccomp, or capabilities,
  matching Pod Security Admission semantics. `runAsUser` alone can no longer
  satisfy the non-root policy for declared Windows workloads.

### Compatibility

- Report schema version stays at `1`. All new report fields are optional and
  omitted when unused; v0.3 JSON consumers decode v0.4 reports unchanged.
  Rollback guidance: v0.4 reports that use `suppressed_findings` or
  `assessment` remain readable by consumers that ignore unknown fields;
  strict consumers should scan without `--exceptions` to reproduce v0.3
  output shape.

## [0.3.0] - 2026-07-23

### Added

- Independently versioned native ruleset catalog with Kubernetes PSS v1.36
  alignment and explicit supplemental checks.
- SOC 2 technical-readiness coverage states for assessed references, including
  no-finding observations without compliance claims.
- Separate native assessed-rule coverage from external finding-rule observations.
- Bounded `wgpolicyk8s.io/v1alpha2` PolicyReport result import.
- `clusterproof ruleset show` and offline `clusterproof evidence verify`.

### Security

- Evidence verification now rejects extra, missing, duplicate, modified,
  symlinked, non-regular, unsafe, and oversized bundle content.

## [0.2.0] - 2026-07-23

### Added

- Read-only live workload scans through an explicit kubeconfig, with optional
  context and namespace scoping.
- Bounded Kubernetes `List` snapshot parsing shared with the manifest rule engine.
- An ADR defining separate Community scanner and commercial control-plane
  repositories.

## [0.1.0] - 2026-07-23

### Added

- Offline Kubernetes manifest checks for workload posture and image integrity.
- Optional bounded Trivy vulnerability, misconfiguration, and secret enrichment.
- Table, JSON, and SARIF reports with CI severity exit codes.
- SHA-256 integrity-checked SOC 2 readiness evidence bundles.
- GoReleaser archives and generated krew plugin manifest support.
- Apache-2.0 community core and documented commercial edition boundary.
