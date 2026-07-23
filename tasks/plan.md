# Implementation Plan: ClusterProof MVP

## Overview

Implement an offline-first Kubernetes security evidence CLI in thin slices. Native
rules provide immediate value without external tools. Trivy remains an optional,
bounded enrichment adapter. All outputs share one stable report contract.

## Architecture Decisions

- Normalize YAML once, then keep rule evaluation pure and deterministic.
- Use dependency inversion for external scanners so tests never require network.
- Treat the evidence bundle as an immutable export and refuse overwrite.
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

- [ ] Task 1: Initialize module, report contract, and severity policy.
- [ ] Task 2: Add bounded manifest discovery and workload normalization.
- [ ] Task 3: Add native Kubernetes and image-integrity rules.

### Checkpoint: Native scanner

- [ ] Focused and full tests pass.
- [ ] Insecure fixture produces deterministic findings.

### Phase 2: Enrichment and Outputs

- [ ] Task 4: Add bounded Trivy JSON import and optional subprocess runner.
- [ ] Task 5: Add JSON, table, and SARIF reporters.
- [ ] Task 6: Add immutable evidence bundle and control-family coverage.
- [ ] Task 7: Wire the CLI and CI exit policy.

### Checkpoint: End-to-end

- [ ] One command produces SARIF and evidence.
- [ ] Threshold exit codes behave as documented.

### Phase 3: Ship Readiness

- [ ] Task 8: Add README, examples, security notes, and source attribution.
- [ ] Task 9: Add krew packaging, CI, and tagged release automation.
- [ ] Task 10: Run tests, vet, build, runtime smoke test, and secret review.

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| False compliance claims | High | Readiness-only language and no criteria text |
| Parser resource exhaustion | High | Hard limits and symlink exclusion |
| Trivy schema drift | Medium | Narrow adapter with fixture tests |
| Rule false positives | Medium | Evidence paths, clear remediation, documented scope |
| Scanner subprocess hangs | Medium | Context timeout and output cap |
| Krew release metadata drift | Medium | Generate archives and checksums from one tag |

## Open Questions Deferred Beyond MVP

- Which auditor-approved control catalog should customers import?
- Should direct cluster scanning use `client-go` or consume `kubectl` snapshots?
- Which signature identity policy should gate Sigstore verification?
