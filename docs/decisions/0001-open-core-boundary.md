# ADR-0001: Separate the Community Scanner from the Commercial Control Plane

## Status

Accepted

## Date

2026-07-23

## Context

ClusterProof needs a useful Apache-2.0 acquisition product and paid capabilities
for teams that need ongoing governance. Keeping proprietary code in public source
behind flags exposes it, while maintaining community and paid branches creates
merge drift and makes security fixes difficult to ship consistently.

The security detections and one-cluster scan are the trust-building product.
Customers pay for organizational state and workflow: history, multi-cluster
rollups, policy distribution, waivers, identity, audit logs, and support.

## Decision

- Keep the CLI, report schema, native detections, one-cluster scanning, Trivy
  integration, and one-run evidence export in the public repository.
- Build the paid product in a separate private repository as a control plane and
  optional companion agent. It consumes versioned ClusterProof JSON rather than
  importing private packages into the public build.
- Keep proprietary policy packs and server code out of public release artifacts.
- Use server-side tenant entitlements for hosted deployments. For air-gapped
  deployments, use short-lived, signed entitlement documents verified locally
  with an embedded public key.
- License gates control commercial workflows and limits, never security fixes or
  the correctness of Community scan results.
- Do not require telemetry or a license server for the Community CLI.

The public report contract starts at schema version `1`. Commercial consumers must
accept additive fields and reject unsupported major schema versions with a clear
error. No compatibility promise is made for Go `internal/` packages.

## Alternatives Considered

### Public code with hidden paid flags

Rejected because the implementation is distributed and the boundary is easy to
bypass. It also makes the Community binary harder to audit.

### Long-lived community and enterprise branches

Rejected because fixes must be cherry-picked and inevitably drift, especially for
security-sensitive parsing and rules.

### Public Go plugin interface loading private modules

Rejected for the initial product because Go plugin portability is limited and
private module imports can break reproducible Community builds. A versioned data
contract is a smaller, language-neutral boundary.

## Consequences

- A Community user can scan any individual repository or cluster without a
  license.
- Paid deployments can aggregate many Community-compatible scan results and add
  workflow without forking the scanner.
- The JSON schema and CLI exit codes require compatibility tests before release.
- The commercial repository needs its own SBOM, signing, access controls, and
  release pipeline.
- Offline licensing needs key rotation, expiry, clock-skew handling, and revocation
  procedures before Enterprise launch.
