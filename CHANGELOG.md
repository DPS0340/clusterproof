# Changelog

All notable changes to ClusterProof are documented here.

## [Unreleased]

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
- Immutable, SHA-256-verified SOC 2 readiness evidence bundles.
- GoReleaser archives and generated krew plugin manifest support.
- Apache-2.0 community core and documented commercial edition boundary.
