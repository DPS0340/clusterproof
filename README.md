# ClusterProof

Offline-first Kubernetes security scanning and audit-readiness evidence.

```bash
go install github.com/DPS0340/clusterproof/cmd/clusterproof@latest
clusterproof scan --fail-on high ./deploy
```

After the first public release is accepted into krew:

```bash
kubectl krew install clusterproof
kubectl clusterproof scan --format sarif --output clusterproof.sarif ./deploy
```

ClusterProof scans local Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet,
Job, and CronJob YAML, or live workloads selected by an explicit kubeconfig. It
checks privileged execution, host access, security contexts, service-account
tokens, mutable image tags, and digest pinning. Repository scans can also import
Trivy JSON or explicitly run a local Trivy installation.

## Examples

Human-readable local scan:

```bash
clusterproof scan ./deploy
```

Pipe rendered manifests from Helm or Kustomize without ClusterProof executing
a renderer:

```bash
helm template ./chart | clusterproof scan -
kustomize build ./overlays/production | clusterproof scan - --fail-on high
```

Stdin input is bounded by the same byte, document, node, and depth limits as
file scans, and `-` cannot be combined with a repository path or a live
cluster target.

Suppress a reviewed finding with a repository-owned exception file:

```bash
clusterproof scan ./deploy --exceptions .clusterproof-exceptions.yaml
```

```yaml
# .clusterproof-exceptions.yaml
schema_version: "1"
exceptions:
  - rule: CP-K8S-010
    target: payments/Deployment/api
    owner: team-payments
    reason: Workload calls the Kubernetes API; reviewed 2026-07.
    expires: "2026-12-31"
```

Every exception requires an exact rule and target, an owner, a reason, and a
UTC expiry date. Expired or malformed entries never suppress findings — a
malformed file fails the whole scan. Suppressed finding identities stay in
the report under `suppressed_findings`, so evidence never hides what was
waived or by whom.

Understand any rule before fixing or waiving it:

```bash
clusterproof explain CP-K8S-006
```

Reports also carry an `assessment` object. A scan whose input contained no
supported workload reports `no_workloads_assessed`, so an empty or
unsupported input can never look like a clean security result.

Read-only live cluster scan:

```bash
clusterproof scan --kubeconfig "$HOME/.kube/config"

# Pin both context and namespace:
clusterproof scan \
  --kubeconfig "$HOME/.kube/config" \
  --context production \
  --namespace payments \
  --fail-on high
```

Cluster mode executes one fixed `kubectl get` request for Pods, Deployments,
StatefulSets, DaemonSets, ReplicaSets, Jobs, and CronJobs. Controller-owned child
resources are removed from evaluation to avoid duplicate findings. It defaults
to all namespaces and the kubeconfig's current context. It never requests
Secrets, ConfigMaps, logs, events, or mutation. The caller needs `list` access to
the selected workload resources; permissions can be checked with
`kubectl auth can-i list RESOURCE` for each resource type and scope.

Use only a kubeconfig you trust. Kubernetes kubeconfigs can define executable
credential plugins, which `kubectl` may run while authenticating. ClusterProof
does not parse or store kubeconfig credentials, but it cannot prevent behavior
configured inside the selected kubeconfig.

CI gate and SARIF:

```bash
clusterproof scan \
  --format sarif \
  --output clusterproof.sarif \
  --fail-on high \
  ./deploy
```

In GitHub Actions, use the first-party action, which downloads a released
binary and verifies its SHA-256 before executing anything:

```yaml
- uses: DPS0340/clusterproof@v0.4.0
  with:
    version: "0.4.0"
    checksum: "<sha256 from the release checksums.txt>"
    path: ./deploy
    fail-on: high
    sarif-output: clusterproof.sarif
```

A complete workflow, including SARIF upload to code scanning, is in
[examples/github-actions-ci.yml](examples/github-actions-ci.yml). The action
needs no cluster credentials and grants no write access.

Exit codes are `0` for a successful policy pass, `2` when findings meet the
requested threshold, and `1` for operational errors.

Inspect the exact native ruleset, generate technical readiness evidence, and
verify that its file set still matches the bundle manifest:

```bash
clusterproof ruleset show
clusterproof scan --evidence-dir evidence-2026-07-23 ./deploy
clusterproof evidence verify evidence-2026-07-23
```

Import results from a Kyverno or other compatible policy engine without
downloading or executing its policy code:

```bash
kubectl get \
  policyreports.wgpolicyk8s.io,clusterpolicyreports.wgpolicyk8s.io \
  --all-namespaces \
  -o json > policy-report.json

clusterproof scan \
  --policy-report-json policy-report.json \
  --evidence-dir evidence-2026-07-23 \
  ./deploy
```

PolicyReport import currently accepts bounded `wgpolicyk8s.io/v1alpha2` JSON.
It imports `fail`, `warn`, and `error` outcomes, omits `pass` and `skip`, and
deliberately excludes source messages because they can contain sensitive
runtime details.

Explicit Trivy enrichment:

```bash
clusterproof scan --with-trivy ./repository
# or, with a result produced elsewhere:
clusterproof scan --trivy-json trivy.json ./deploy
```

`--with-trivy` may let Trivy update its vulnerability and policy databases.
ClusterProof itself performs no telemetry. Repository scans make no network
request unless Trivy is explicitly enabled; cluster scans contact only the API
server selected by the provided kubeconfig.

## Safety model

- Repository scans are offline by default; cluster scans are explicit and
  read-only.
- Does not follow symlinks.
- Bounds file size, total input, YAML documents, YAML depth, subprocess time,
  and scanner output.
- Never includes Trivy's matched secret value in a report.
- Refuses to overwrite reports or evidence directories.
- Evidence statuses are `attention_required`, `no_findings_observed`, and
  `not_assessed`; they never say `compliant`.
- Does not claim SOC 2 compliance, examination, or certification. The scanner
  observes only a subset of CC6/CC7-related Kubernetes and supply-chain
  mechanisms. Organizational controls require customer and auditor review.
- The SHA-256 bundle manifest detects changes relative to itself. It is not a
  signature and does not prove who created the evidence.

The built-in, independently versioned catalog is aligned to Kubernetes Pod
Security Standards v1.36 and adds clearly labeled ClusterProof checks. It is not
a complete PSS implementation. See
[SOC 2 readiness](docs/soc2-readiness.md) and
[ruleset strategy](docs/rulesets.md) for the exact scope and external-policy
guidance.

## Open core

The Apache-2.0 community edition includes every native detection, the versioned
catalog, bounded PolicyReport import, single-repo and single-cluster scanning,
Trivy enrichment, JSON/SARIF, verifiable one-run evidence, and CI thresholds.
Paid products add organization policy distribution, licensed/custom control
maps, baselines, time-bound waivers, history, multi-cluster rollups, RBAC, and
support.

Paid code is kept in a separate private control-plane repository and consumes
the versioned JSON report contract. The public binary contains no dormant
proprietary code or license check. See [docs/open-core.md](docs/open-core.md) and
[ADR-0001](docs/decisions/0001-open-core-boundary.md).

## Development

```bash
go test ./...
go vet ./...
go build ./...
```

The product spec and threat model are in [docs/spec.md](docs/spec.md).
Product direction and implementation milestones are in
[docs/roadmap.md](docs/roadmap.md).
Release gates and rollback are in [docs/release.md](docs/release.md).
