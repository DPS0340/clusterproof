# Implementation Plan: ClusterProof

## Overview

Implement an offline-first Kubernetes security evidence CLI in thin slices. Native
rules provide immediate value without external tools. Trivy remains an optional,
bounded enrichment adapter. All outputs share one stable report contract.

## Architecture Decisions

- Normalize YAML once, then keep rule evaluation pure and deterministic.
- Use dependency inversion for external scanners so tests never require network.
- Treat the evidence bundle as a new, non-overwriting export with bounded
  integrity verification.
- Keep SOC 2 references configurable and high-level; do not embed licensed text.
- Use exit code `0` for policy pass, `2` for findings at/above threshold, and `1`
  for operational errors.

## Dependency Graph

```text
model contract
  ├── manifest loader ──> native rules
  ├── Trivy adapter
  └── reporters ──> CLI policy and evidence bundle
```

## Task List

### Phase 1: Foundation

- [x] Task 1: Initialize module, report contract, and severity policy.
- [x] Task 2: Add bounded manifest discovery and workload normalization.
- [x] Task 3: Add native Kubernetes and image-integrity rules.

### Checkpoint: Native scanner

- [x] Focused and full tests pass.
- [x] Insecure fixture produces deterministic findings.

### Phase 2: Enrichment and Outputs

- [x] Task 4: Add bounded Trivy JSON import and optional subprocess runner.
- [x] Task 5: Add JSON, table, and SARIF reporters.
- [x] Task 6: Add immutable evidence bundle and control-family coverage.
- [x] Task 7: Wire the CLI and CI exit policy.

### Checkpoint: End-to-end

- [x] One command produces SARIF and evidence.
- [x] Threshold exit codes behave as documented.

### Phase 3: Ship Readiness

- [x] Task 8: Add README, examples, security notes, and source attribution.
- [x] Task 9: Add krew packaging, CI, and tagged release automation.
- [x] Task 10: Run tests, vet, build, runtime smoke test, and secret review.

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| False compliance claims | High | Readiness-only language and no criteria text |
| Parser resource exhaustion | High | Hard limits and symlink exclusion |
| Trivy schema drift | Medium | Narrow adapter with fixture tests |
| Rule false positives | Medium | Evidence paths, clear remediation, documented scope |
| Scanner subprocess hangs | Medium | Context timeout and output cap |
| Krew release metadata drift | Medium | Generate archives and checksums from one tag |

### Phase 4: Live Cluster Scan

- [x] Task 11: Add bounded Kubernetes `List` snapshot normalization.
- [x] Task 12: Add a read-only kubectl collector with fixed resources and timeouts.
- [x] Task 13: Add kubeconfig/context/namespace CLI integration.
- [x] Task 14: Document the public/commercial boundary and release v0.2.0.

### Checkpoint: Cluster scanner

- [x] Fake-kubectl integration proves the exact read-only command and report flow.
- [x] Full tests, vet, build, release, and krew install pass.

## Open Questions Deferred Beyond v0.3

- Which customer-supplied control-catalog and OSCAL profiles should the
  commercial adapter support first?
- Which signature identity policy should gate Sigstore verification?

### Phase 5: SOC 2 Technical Readiness

- [x] Task 15: Add a versioned native ruleset catalog grounded in Kubernetes PSS.
- [x] Task 16: Replace finding-only control counts with assessed coverage states.
- [x] Task 17: Add bounded external PolicyReport JSON import.
- [x] Task 18: Harden bundle verification and expose it through the CLI.
- [x] Task 19: Document licensing boundaries and release v0.3.0.

### Checkpoint: Audit-readiness evidence

- [x] No output claims compliance or reproduces licensed criteria text.
- [x] Every native rule is cataloged and every evidence file is integrity checked.
- [x] Full tests, vet, build, race, release, and krew install pass.

## Roadmap Dependency Graph

```text
PSS version/OS contract
  -> complete conformance fixtures
  -> stream input + local exceptions + schema lifecycle
  -> v0.4 trustworthy CI workflow

cluster collection scope contract
  -> PSA / RBAC / NetworkPolicy analyzers
  -> snapshot comparison + OpenReports adapter
  -> v0.5 cluster posture

supply-chain trust policy
  -> image digest resolution
  -> Sigstore + SLSA + SBOM/VEX adapters
  -> signed evidence
  -> v0.6 verifiable supply chain

repeated customer pain + paid pilots
  -> commercial control-plane specification
  -> Team and Enterprise implementation
```

The full product and commercial milestones are in `docs/roadmap.md`. Only the
Community phases and the commercial discovery gate are decomposed below. Team
control-plane implementation must not begin before Task 41 is complete.

### Phase 6: v0.4 Trustworthy Daily Use

- [x] Task 20: Define the supported PSS version and workload OS contract.
- [x] Task 21: Complete PSS Baseline and Restricted conformance coverage.
- [x] Task 22: Add bounded stdin and rendered-manifest input.
- [x] Task 23: Add repository-owned local exception files.
- [x] Task 24: Publish report schemas and compatibility policy.
- [x] Task 25: Add rule explanation and assessment diagnostics.
- [x] Task 26: Ship a checksum-pinned GitHub Action and v0.4 release.

### Checkpoint: Trustworthy CI adoption

- [x] Linux and Windows PSS semantics pass versioned conformance fixtures.
- [x] A rendered manifest can be piped without executing a renderer.
- [x] v0.3 report consumers remain compatible.
- [x] The public quickstart reaches a working CI gate in under 15 minutes.

### Phase 7: v0.5 Cluster Attack Surface

- [ ] Task 27: Define opt-in cluster scopes and partial-assessment evidence.
- [ ] Task 28: Assess namespace Pod Security Admission configuration.
- [ ] Task 29: Add bounded RBAC relationship analysis.
- [ ] Task 30: Add NetworkPolicy and workload-exposure analysis.
- [ ] Task 31: Add deterministic two-snapshot comparison.
- [ ] Task 32: Add an experimental bounded OpenReports adapter.
- [ ] Task 33: Performance-test and release v0.5.

### Checkpoint: Broader read-only cluster posture

- [ ] Every Kubernetes request remains a fixed, tested read.
- [ ] Missing permissions never appear as a successful assessment.
- [ ] No Secret or ConfigMap payload, log, event, or mutation is requested.
- [ ] A 5,000-workload fixture stays within the published resource budget.

### Phase 8: v0.6 Verifiable Supply Chain

- [ ] Task 34: Define the supply-chain trust-policy contract.
- [ ] Task 35: Export image inventory and resolve tags to digests explicitly.
- [ ] Task 36: Verify Sigstore signatures with pinned identities.
- [ ] Task 37: Verify SLSA v1.2 provenance against exact subjects.
- [ ] Task 38: Import bounded SPDX/CycloneDX SBOM and VEX data.
- [ ] Task 39: Sign and authenticate evidence manifests.
- [ ] Task 40: Abuse-test offline and networked modes and release v0.6.

### Checkpoint: Cryptographic evidence

- [ ] Floating tags alone can never satisfy signature or provenance policy.
- [ ] Every network request is opt-in and represented in evidence.
- [ ] Offline verification works from self-contained bundles.
- [ ] Wrong identities, issuers, subjects, builders, and expired material fail.

### Phase 9 Gate: Commercial Discovery

- [ ] Task 41: Validate repeated team workflow pain and write the commercial spec.

### Checkpoint: Authorize Team implementation

- [ ] Five design-partner interviews are complete.
- [ ] Three teams run ClusterProof weekly.
- [ ] Two teams have paid for an engagement or pilot.
- [ ] At least three teams share the same history, baseline, waiver, or rollup pain.
