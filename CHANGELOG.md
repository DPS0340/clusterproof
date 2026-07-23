# Changelog

All notable changes to ClusterProof are documented here.

## [Unreleased]

### Added

- Independently versioned native ruleset catalog with Kubernetes PSS v1.36
  alignment and explicit supplemental checks.
- SOC 2 technical-readiness coverage states for assessed references, including
  no-finding observations without compliance claims.
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
