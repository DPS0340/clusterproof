# ClusterProof Product Roadmap

This roadmap started from the v0.3.0 Community release. It is directional
rather than a date promise: each phase advances only after its exit gate is
met. Phases 1-3 (v0.4 through v0.6) shipped in 2026-07; their sections below
are marked complete and retained as the record of what each release promised.

## North Star

Make a repeat Kubernetes security scan produce evidence that an engineer trusts,
a security lead can operationalize, and an auditor can review without implying
that the scan certifies compliance.

The primary product loop is:

```text
install
  -> scan one repository or cluster
  -> fix or document one finding
  -> repeat in CI
  -> compare posture over time
  -> coordinate exceptions and evidence across a team
```

Community must own scan correctness, local enforcement, open report formats, and
single-target evidence. Revenue begins with centralized workflow, history,
governance, fleet operations, and support.

## Prioritization Rules

1. Accuracy before rule count. A smaller version-aware ruleset is better than a
   large catalog with misleading mappings.
2. Read-only before resident agents. Prefer explicit snapshots and CI-produced
   reports until continuous collection is required by paying users.
3. Data adapters before policy execution. Import standardized results; do not
   invent another policy language or execute downloaded rules.
4. Explicit network access. Registry, transparency-log, and vulnerability
   lookups remain opt-in and are recorded in evidence.
5. Open security value. New detections, security fixes, local CI gates, and
   evidence verification stay in Community.
6. Paid operational leverage. Central approvals, retained history, organization
   mappings, fleet views, SSO/RBAC, and support are commercial.

## Phase 1 — v0.4: Trustworthy Daily Use — SHIPPED 2026-07-24

**Released:** v0.4.0
**Outcome:** engineers can adopt ClusterProof in CI without fighting input
format, false-positive, or report-compatibility problems.

### Deliverables

- Complete, version-pinned Kubernetes PSS Baseline and Restricted coverage for
  supported Pod fields, including Linux/Windows differences.
- A generated coverage matrix that distinguishes complete, partial, and
  supplemental checks for each supported Kubernetes minor version.
- Bounded stdin and multi-document JSON/YAML input so users can pipe output from
  Helm, Kustomize, or another renderer without ClusterProof executing it.
- Repository-owned local exceptions with rule, target, owner, reason, and expiry.
  Community validates the file locally; paid editions later add centralized
  approval and audit history.
- Public JSON schema fixtures, compatibility tests, and a documented
  deprecation policy for report and evidence contracts.
- `clusterproof explain RULE_ID` and clearer diagnostics for unsupported,
  partially assessed, and empty inputs.
- A first-party GitHub Action or reusable workflow that pins a released binary
  and verifies its checksum.

### Exit Gate

- Every built-in rule passes catalog drift and upstream-aligned conformance
  fixtures.
- Windows workloads do not receive Linux-only PSS findings.
- Existing v0.3 JSON consumers continue to decode v0.4 reports.
- A new user can install, scan, suppress one reviewed exception, and add a CI
  gate in under 15 minutes using only public documentation.

## Phase 2 — v0.5: Cluster Attack-Surface Coverage — SHIPPED 2026-07-24

**Released:** v0.5.0
**Outcome:** a cluster scan explains workload isolation, authorization, and
network segmentation without requesting secret values or mutation rights.

### Deliverables

- A versioned cluster-scope contract with fixed resource allowlists and explicit
  permission preflight.
- Partial-assessment reporting when the caller cannot list a requested resource;
  missing permission must never look like `no_findings_observed`.
- Namespace Pod Security Admission label and version-pin checks.
- RBAC graph analysis for wildcard privileges, Secrets access, workload creation,
  `pods/exec`, impersonation, bind/escalate, and risky service-account paths.
- NetworkPolicy and exposure checks covering default-deny gaps, workload
  selection, Services, Ingress, and supported Gateway resources.
- A local two-snapshot `compare` command. Community gets deterministic diff;
  paid editions retain history and coordinate baselines.
- A bounded `openreports.io/v1alpha1` adapter kept explicitly experimental until
  the upstream API reaches a stable contract.

### Exit Gate

- Fake-server tests prove every cluster request is an allowlisted read.
- No scan requests Secret, ConfigMap payload, logs, events, or object mutation.
- Permission-denied and absent-resource cases are distinguishable in evidence.
- A 5,000-workload fixture remains within documented time and memory budgets.

## Phase 3 — v0.6: Verifiable Software Supply Chain — SHIPPED 2026-07-24

**Released:** v0.6.0
**Outcome:** image findings move from naming/tag heuristics to cryptographically
verified identity, provenance, and vulnerability context.

### Deliverables

- Deterministic image inventory export and explicit tag-to-digest resolution.
- A trust-policy file that pins certificate identity, OIDC issuer, key, builder,
  source repository, and allowed predicate types.
- Optional Sigstore signature and attestation verification with bounded
  subprocess or library adapters and recorded network/custody metadata.
- SLSA v1.2 provenance checks that bind the attestation subject to the exact
  image digest and validate customer-selected builder/source expectations.
- Bounded SPDX and CycloneDX SBOM import plus VEX status normalization.
- Signed evidence-manifest support that distinguishes file integrity from signer
  authenticity and preserves offline verification where bundles are available.

### Exit Gate

- Verification never succeeds against a floating tag alone.
- Keyless verification requires both certificate identity and issuer policy.
- Offline bundles can be verified without an implicit network request.
- Forged subject digests, wrong builders, expired material, and oversized
  attestations have regression tests.

## Phase 3.5 — v0.7: Contract Hardening and Field Adoption

**Target horizon:** next 4–8 weeks; deliberately smaller than prior phases
**Outcome:** the public contracts prove themselves stable across real usage,
and the project has its first observable field adoption. v0.7 is the second
of the two consecutive no-breaking-migration releases the v1.0 gate
requires; feature restraint is the point.

### Deliverables

- Zero breaking changes to the report, ruleset, evidence, exception, trust,
  and comparison contracts. Additive fields only, all omit-when-unused.
  The stability gates in `docs/contracts.md` (frozen rule IDs, strict-decode
  fixtures for v0.3 and v0.6, live schema validation in CI) stay green for
  the whole release window.
- Complete the krew-index review (PR #6120) and keep the manifest current
  through the automated release pipeline.
- Wire supply-chain verification into `scan`: an opt-in flag that runs
  signature and provenance verification for digest-pinned images during a
  repository scan, using the trust policy, and records outcomes as findings
  and evidence. The primitives shipped in v0.6; v0.7 makes them one-command.
- Wire SBOM/VEX suppression into `scan`: `--sbom` and `--vex` inputs that
  apply exact-identity VEX suppression to imported vulnerability findings,
  with suppressed identities recorded like exceptions.
- Publish the three focused examples the adoption track requires:
  repository CI, read-only cluster scan, and SOC 2 technical evidence
  handoff, each as a runnable public example directory.
- Fuzz the manifest, exception, trust-policy, SBOM, and VEX parsers with
  Go native fuzzing in CI (bounded corpus time per run).
- A documented upgrade-and-rollback test: v0.5 evidence bundles verify with
  the v0.7 binary, and v0.7 unsigned bundles verify with the v0.5 binary.

### Exit Gate

- v0.5 → v0.6 → v0.7 constitutes two consecutive minor releases with no
  breaking report migration; the v1 contract freeze can be declared.
- The krew-index submission is merged or has a concrete reviewer-driven
  task list.
- At least three external teams have installed a release (download counts
  or direct confirmation; no telemetry).
- Fuzzers run in CI and have produced no unhandled panic for two weeks.

## Phase 4 — v0.8: Team Control Plane

**Target horizon:** demand-gated; no calendar promise
**Outcome:** teams can manage repeated scans and exceptions without spreadsheets.

### Build Gate

Do not build the control plane merely because the CLI exists. Start only after:

- At least five teams have completed a design-partner interview.
- At least three teams run repeated scans weekly.
- At least two teams have paid for a readiness engagement or pilot.
- The same baseline, waiver, or evidence-history pain appears in at least three
  teams.

### Deliverables

- A separate private service consuming the versioned Community JSON contract.
- Explicit report upload with tenant isolation, authentication, organization
  RBAC, encrypted storage, retention controls, and immutable audit events.
- Finding history, deterministic baselines, multi-repository/cluster rollups,
  ownership, comments, and time-bound waiver approvals.
- Organization policy distribution pinned by digest; scanners still execute
  locally under explicit customer configuration.
- Custom control maps and evidence-pack templates without bundling unlicensed
  AICPA or CIS text.
- Signed offline entitlements for self-hosted installations; hosted entitlement
  checks remain server-side.

### Exit Gate

- Cross-tenant authorization tests cover every read and write path.
- Deleting a tenant or applying retention removes the intended data and nothing
  else.
- Audit events identify actor, action, target, timestamp, and prior/new state.
- Community scanning remains fully functional without an account or license.

## Phase 5 — v1.0: Enterprise Evidence Operations

**Target horizon:** adoption-gated; requires the Phase 3.5 stability gate
and at least the Phase 4 build gate conversation to have concluded
**Outcome:** ClusterProof has a stable public contract and can operate in
regulated, multi-cluster, and disconnected environments.

### Deliverables

- Stable v1 report, ruleset, evidence, exception, trust, comparison, and CLI
  contracts. The freeze is a rename of the already-stable v0.7-era schemas,
  not a redesign: contracts that needed changing should have changed before
  this phase.
- A `clusterproof migrate` command for any consumer still on pre-freeze
  report shapes, plus a published schema-change log.
- OIDC/SAML SSO, enterprise RBAC, supportable backup/restore, and high-availability
  deployment guidance.
- Air-gapped artifact, policy, signature, SBOM, and vulnerability-data workflows.
- Customer-supplied catalog/profile mapping and OSCAL Assessment Results
  transformation only when an Assessment Plan and system context are provided.
- Fleet evidence rollups with signed custody records and auditor-scoped export.
- Published support, compatibility, security-response, and deprecation policies.

### Exit Gate

- Two consecutive minor releases require no breaking report migration.
- Upgrade and rollback are tested from the prior supported release.
- At least one self-hosted and one hosted design partner completes an evidence
  review with its auditor or compliance advisor.
- Recovery-point and recovery-time objectives are measured, not aspirational.

## Parallel Adoption and Revenue Track

Product work alone does not validate a business. Run these activities alongside
the technical phases:

- Complete the upstream krew review (PR #6120 open with the v0.6.0 manifest)
  and keep release checksums automated. DONE except reviewer follow-up.
- Publish three focused examples: repository CI, read-only cluster scan, and
  SOC 2 technical evidence handoff. Scheduled inside Phase 3.5.
- Offer the fixed-scope baseline, supply-chain, and evidence readiness services
  described in `open-core.md`.
- Convert repeated consulting artifacts into product workflow only after the same
  pattern appears across customers.
- Add optional telemetry only with explicit opt-in and a public event schema.
  Until then, use release downloads, documentation funnels, and direct
  design-partner interviews.

## Scorecard

| Dimension | Metric | Target before v1.0 |
| --- | --- | --- |
| Activation | Install to first successful scan | Under 5 minutes |
| Adoption | Teams running a weekly repeat scan | 10+ |
| Quality | Cataloged native rules with conformance fixtures | 100% |
| Safety | Secret values or kubeconfig contents emitted | 0 |
| Reliability | Successful supported design-partner scans | 99% |
| Performance | 5,000-workload scan on reference hardware | Under 10 seconds, under 512 MiB |
| Retention | Design partners active after 8 weeks | 60%+ |
| Revenue | Paid readiness engagements | 3+ |
| Conversion | Engagements converted to annual Team pilot | 1+ |

Metrics are decision inputs, not vanity counters. Do not add a hosted dashboard
solely to collect them.

## Explicit Non-Goals for This Roadmap

- Becoming an admission controller or mutating Kubernetes resources.
- Replacing Kyverno, Gatekeeper, Trivy, Sigstore, or an auditor.
- Building a proprietary policy language.
- Collecting Secret values, kubeconfig credentials, logs, or runtime packet data.
- Claiming SOC 2 certification or complete control coverage.
- Shipping a mandatory in-cluster agent or telemetry path.
- Bundling commercial control-framework text without a license.

## Key Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| More checks create more false confidence | High | Versioned coverage matrix, partial-assessment states, conformance fixtures |
| Broader cluster scans demand excessive RBAC | High | Separate opt-in scope packs, permission preflight, fixed read allowlists |
| Signature verification adds hidden network trust | High | Explicit trust policy, offline bundles, recorded network use |
| Hosted evidence contains customer-sensitive metadata | High | Data minimization, tenant isolation, retention/deletion tests |
| Commercial work weakens Community | High | Keep correctness, detections, local gates, diff, and verification open |
| Dashboard built before repeated demand | Medium | Enforce the Phase 4 design-partner build gate |
| External schemas change | Medium | Isolated adapters, pinned versions, compatibility fixtures |

## Standards Watch

- Kubernetes Pod Security Standards and Admission remain the built-in workload
  baseline. Pin a supported Kubernetes minor; never interpret `latest` as
  immutable:
  https://kubernetes.io/docs/concepts/security/pod-security-admission/
- Kubernetes Security Checklist, RBAC good practices, and NetworkPolicy guide the
  read-only cluster posture phases:
  https://kubernetes.io/docs/concepts/security/security-checklist/
  https://kubernetes.io/docs/concepts/security/rbac-good-practices/
  https://kubernetes.io/docs/concepts/services-networking/network-policies/
- OpenReports is the preferred future result interchange adapter, but its current
  API remains `openreports.io/v1alpha1`:
  https://github.com/openreports/reports-api
- SLSA v1.2 is the provenance vocabulary:
  https://slsa.dev/spec/v1.2/
- Sigstore provides signature and attestation verification primitives:
  https://docs.sigstore.dev/cosign/verifying/verify/
- OSCAL Assessment Results require an Assessment Plan and system context:
  https://pages.nist.gov/OSCAL/learn/concepts/layer/assessment/assessment-results/

Review this watch list before each ruleset or adapter release. External version
changes require a catalog version bump and compatibility tests.
