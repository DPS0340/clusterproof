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

CI gate and SARIF:

```bash
clusterproof scan \
  --format sarif \
  --output clusterproof.sarif \
  --fail-on high \
  ./deploy
```

Exit codes are `0` for a successful policy pass, `2` when findings meet the
requested threshold, and `1` for operational errors.

Generate immutable technical evidence:

```bash
clusterproof scan --evidence-dir evidence-2026-07-23 ./deploy
```

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
- Does not claim SOC 2 certification. Evidence mappings require customer and
  auditor review.

## Open core

The Apache-2.0 community edition includes every native detection, single-repo and
single-cluster scanning, Trivy enrichment, JSON/SARIF, evidence snapshots, and CI
thresholds. Paid products add organization policy packs, baselines, time-bound
waivers, history, multi-cluster rollups, RBAC, and support.

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
Release gates and rollback are in [docs/release.md](docs/release.md).
