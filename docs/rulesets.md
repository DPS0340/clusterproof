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
