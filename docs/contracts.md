# Public Contract Lifecycle

ClusterProof's machine-readable outputs are public contracts. This document
defines how they may change.

## Contracts and schemas

| Contract | Schema | Version field |
| --- | --- | --- |
| Scan report | `schemas/report-v1.schema.json` | `schema_version` |
| Repository exceptions | `schemas/exceptions-v1.schema.json` | `schema_version` |
| Ruleset catalog | `schemas/ruleset-v1.schema.json` | `schema_version` |
| Comparison output | `schemas/compare-v1.schema.json` | `schema_version` |
| Trust policy | `schemas/trust-policy-v1.schema.json` | `schema_version` |
| Evidence bundle | verified by `clusterproof evidence verify` | `schema_version` in `metadata.json` |

Schemas are versioned independently of the CLI. The CLI version says what the
binary can do; the schema version says what a consumer can rely on.

## Compatibility policy

- A minor release may only add optional fields. Existing fields never change
  name, type, or meaning within a schema major version.
- New optional fields are omitted from output when their feature is unused,
  so strict consumers that reject unknown fields keep working on unchanged
  workflows. `suppressed_findings` (added in v0.4) follows this rule: it
  appears only when `--exceptions` is used.
- A breaking change requires a new schema major version, a new schema file,
  and a migration note in the changelog. The previous schema remains
  published.
- `testdata/compat/` holds one canonical fixture per released contract
  version. Compatibility tests decode every historical fixture with current
  code; those tests failing means the release is not shippable.

## Rule ID freeze

Finding rule IDs (`CP-*`) are part of the public contract:

- An ID, once released, is never removed and never reused for a different
  rule within a schema major version.
- The append-only registry in `internal/rules/frozen_test.go` enforces this
  in CI: removing or retitling a released rule fails the build.
- Retiring a rule requires a schema-major decision and a migration note; a
  rule that no longer fires stays registered as released history.

## v1.0 stability gate

The roadmap requires two consecutive minor releases with no breaking report
migration before declaring v1 contracts. The measurement is mechanical:

- `testdata/compat/report-v0.3.json` and `testdata/compat/report-v0.6.json`
  must both strict-decode with current code.
- Reports produced without new features must omit every additive field
  (`suppressed_findings`, `assessment`, `cluster_scopes`), keeping the
  unchanged-workflow byte shape stable for strict consumers.
- CI validates live scan, ruleset, and comparison output against their
  published schemas on every commit.

When v0.7 ships with these gates still green, the v0.5→v0.6→v0.7 window
satisfies the two-release criterion and the v1 contract freeze can be
declared by renaming the schemas to their v1 identifiers without content
changes.

## Deprecation policy

- A field is deprecated by documenting it here and in the schema
  `description`; it keeps being emitted for at least two minor releases.
- Removal happens only in a schema major version bump.
- No field is ever reused with a different meaning, mirroring the rule that
  finding IDs are never reused for different rules.
