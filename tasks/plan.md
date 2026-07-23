# Implementation Plan: ClusterProof MVP

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
- [ ] Task 19: Document licensing boundaries and release v0.3.0.

### Checkpoint: Audit-readiness evidence

- [x] No output claims compliance or reproduces licensed criteria text.
- [x] Every native rule is cataloged and every evidence file is integrity checked.
- [ ] Full tests, vet, build, race, release, and krew install pass.
