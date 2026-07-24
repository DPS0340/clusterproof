# Public Contract Lifecycle

ClusterProof's machine-readable outputs are public contracts. This document
defines how they may change.

## Contracts and schemas

| Contract | Schema | Version field |
| --- | --- | --- |
| Scan report | `schemas/report-v1.schema.json` | `schema_version` |
| Repository exceptions | `schemas/exceptions-v1.schema.json` | `schema_version` |
| Ruleset catalog | rendered by `clusterproof ruleset show --format json` | `schema_version` |
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

## Deprecation policy

- A field is deprecated by documenting it here and in the schema
  `description`; it keeps being emitted for at least two minor releases.
- Removal happens only in a schema major version bump.
- No field is ever reused with a different meaning, mirroring the rule that
  finding IDs are never reused for different rules.
