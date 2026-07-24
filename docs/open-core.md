# ClusterProof Open-Core Model

## Product Thesis

The free product must be good enough that an engineer finds a real risk, fixes it,
and recommends ClusterProof internally. Revenue starts when a team needs repeatable
governance, collaboration, history, and auditor-ready operations.

Do not paywall new vulnerability detections, security fixes, JSON/SARIF output, or
the ability to enforce a severity threshold in CI. Weakening the scanner weakens
the acquisition channel.

## Edition Boundary

The boundary is architectural, not a feature list: Community is local,
single-target, and stateless; Team is centralized, multi-target, and
stateful; Enterprise is regulated operations. Community keeps gaining local
capabilities (deterministic diff, repository exceptions, signed evidence)
without eroding the boundary, because a local CLI structurally cannot hold
central state. In one line: Community makes one scan trustworthy, Team makes
a hundred scans manageable, Enterprise makes them operable in front of an
auditor.

| Capability | Community (Apache-2.0) | Team | Enterprise |
| --- | --- | --- | --- |
| Offline manifest and PSS-oriented checks | Included | Included | Included |
| Read-only scan of one cluster/context per invocation, with opt-in scope packs | Included | Included | Included |
| Trivy enrichment and image integrity checks | Included | Included | Included |
| Versioned native catalog and bounded PolicyReport/OpenReports import | Included | Included | Included |
| JSON, SARIF, verifiable one-run evidence bundle (including local signing) | Included | Included | Included |
| CI severity threshold | Included | Included | Included |
| Local two-snapshot diff (`compare`) | Included | Included | Included |
| Repository-owned exception file with owner/reason/expiry | Included | Included | Included |
| Supply-chain verification against a local trust policy | Included | Included | Included |
| Retained scan history and cross-release posture trends | — | Included | Included |
| Central waiver approval workflow and audit trail | — | Included | Included |
| Organization policy distribution and pinning | — | Included | Included |
| Organization baselines across repositories and clusters | — | Included | Included |
| Evidence history and multi-cluster rollup | — | Included | Included |
| Organization signing-key management and signer policy distribution | — | Included | Included |
| Auditor export templates, OSCAL transform, and licensed/custom control map | — | Included | Included |
| SSO/RBAC/immutable audit log | — | — | Included |
| Air-gapped license and private policy distribution | — | — | Included |
| Support SLA and custom rules | Community | Business hours | Contracted |

The Team and Enterprise capabilities live in a separate private control-plane
repository. They consume the versioned Community JSON report contract; the public
build does not import private packages or contain dormant proprietary
implementation. See
[ADR-0001](decisions/0001-open-core-boundary.md).

## Initial Pricing

Pricing is annual to match security and compliance budgets:

- **Community:** free.
- **Team:** USD 2,400/year, up to 10 clusters and 25 repositories.
- **Scale:** USD 9,600/year, up to 50 clusters and 200 repositories.
- **Enterprise:** starts at USD 25,000/year for air-gapped use, SSO/RBAC, support,
  and contract-specific control mappings.

Avoid per-seat pricing at first. Cluster/repository limits align price with the
surface being protected and do not discourage security participation.

The Team entry price is a hypothesis, not a commitment: validate it against
the first two pilots. Security budgets sometimes reject sub-USD-5,000 line
items as not worth an approval cycle; if pilots show that pattern, raise the
entry tier rather than discounting the engagement fee.

## Service-Led Revenue

The fastest path to revenue is a fixed-scope engagement powered by the community
scanner:

1. **Kubernetes Security Baseline — USD 5,000**
   - One production cluster or one deployment repository.
   - Findings triage, 90-minute review, prioritized remediation plan.
   - Target delivery: 2–3 engineering days.
2. **Supply-Chain Readiness Sprint — USD 8,000**
   - SBOM, digest pinning, Trivy policy, CI/SARIF, and signature-readiness review.
   - Target delivery: 4–5 engineering days.
3. **SOC 2 Technical Evidence Sprint — USD 12,000**
   - Up to five clusters/repositories, evidence workflow, ownership and waiver
     design, auditor handoff pack.
   - Target delivery: 6–8 engineering days.

Credit 50% of the engagement fee toward the first annual Team or Scale license.
This converts consulting into product revenue without discounting the expertise.

## Conversion Loop

```text
krew install
  -> first local finding
  -> CI adoption
  -> repeated baseline/waiver pain
  -> paid readiness sprint
  -> Team license
  -> multi-cluster Enterprise expansion
```

Measure:

- Install-to-first-scan completion.
- Repositories running ClusterProof in CI after 14 days.
- Teams creating manual baselines or spreadsheets for waivers.
- Evidence bundle generation frequency.
- Service engagement to annual-license conversion.

## Licensing and Trust

- Community core: Apache License 2.0.
- Commercial modules: proprietary license, offline signed entitlement supported.
- Hosted entitlements are enforced server-side. Air-gapped entitlements are
  signed, expiring documents; no shared license secret is embedded in a client.
- License gates apply to aggregation and workflow, never to detections, security
  fixes, PolicyReport import, evidence verification, or single-target scan
  correctness.
- No telemetry by default. Optional anonymous metrics require explicit opt-in and
  a published event schema.
- No compliance guarantee. Reports are technical evidence and require customer and
  auditor review.
- AICPA Trust Services Criteria text and SOC marks require appropriate licensing;
  do not bundle their descriptions in the community or paid product without it.
