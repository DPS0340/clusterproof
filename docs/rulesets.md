# Ruleset Strategy

ClusterProof uses a layered ruleset instead of treating its native checks as a
new security standard.

| Layer | Role | Default behavior |
| --- | --- | --- |
| Kubernetes PSS alignment | Normative upstream baseline for workload isolation | Built in, versioned, offline |
| ClusterProof supplemental checks | Service-account, writable filesystem, and image immutability signals | Built in, clearly marked supplemental |
| External policy results | Organization-specific Kyverno, Gatekeeper, or other engine results | Explicit bounded result import only |

Kubernetes PSS is the primary common vocabulary because it is maintained by
Kubernetes and separates policy definition from enforcement. Gatekeeper and
Kyverno libraries are useful policy implementations, but they are not a single
universal standard and can change independently.

## Kubernetes version and workload OS contract

The native catalog pins the exact Pod Security Standards semantics it
evaluates. `clusterproof ruleset show --format json` exposes the contract in
the `kubernetes` object:

- `kubernetes_minor` is the documented Kubernetes minor the alignment review
  used.
- `supported_minors` lists every minor whose PSS semantics the catalog is
  known to match. A version outside this list is reported as unsupported and
  is never silently treated as the newest release, and `latest` is always
  rejected as ambiguous.

Each rule also declares the workload operating systems it applies to. Pods
that declare `spec.os.name: windows` are not evaluated against Linux-only
controls (privilege escalation, seccomp, and Linux capabilities), matching the
Pod Security Admission exemptions introduced in Kubernetes v1.25. The
Linux-only `runAsUser` field can neither satisfy nor violate the non-root
policy for declared Windows workloads. Any other `spec.os.name` value,
including an absent one, keeps the stricter Linux evaluation semantics.

## PSS coverage matrix

The catalog publishes a machine-readable coverage matrix in the
`pss_coverage` array of `clusterproof ruleset show --format json`. Every PSS
Baseline and Restricted control maps to the exact native rules evaluating it
with one of two statuses:

- `complete`: every documented field of the control is checked.
- `partial`: at least one documented field is not checked, and the `note`
  field states the exact gap.

The matrix never claims complete coverage while an applicable field is
missing; a catalog drift test fails if a PSS-aligned rule is absent from the
matrix or a partial entry omits its gap note. Current partial entries:

- Baseline AppArmor: the `securityContext.appArmorProfile` field is
  evaluated, but the deprecated
  `container.apparmor.security.beta.kubernetes.io` annotations are not
  parsed.

External executable rules are not vendored or fetched at scan time. An
organization that needs them should pin the policy repository commit or artifact
digest in its own delivery process, execute it in the chosen policy engine, and
pass the resulting PolicyReport to ClusterProof.

OSCAL is appropriate for exchanging assessment plans, observations, findings, and
evidence. A conformant OSCAL Assessment Results document requires an Assessment
Plan and system context, so the Community CLI does not emit a misleading partial
OSCAL document. A future commercial adapter can transform ClusterProof's stable
report into a customer-supplied OSCAL plan and licensed control catalog.

CIS Kubernetes Benchmark content and AICPA Trust Services Criteria are not
embedded. Customers may maintain licensed mappings outside the Community binary.
