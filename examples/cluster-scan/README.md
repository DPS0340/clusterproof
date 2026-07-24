# Example: read-only cluster scan

Scan live workloads with an explicit kubeconfig and the minimum RBAC.
ClusterProof never mutates the cluster and never reads Secret values,
ConfigMap payloads, logs, or events.

## Minimum RBAC per scope

Every scope is one fixed, versioned read-only `kubectl get`. Grant `list`
only for the scopes you request:

| Scope | Resources needing `list` |
| --- | --- |
| `workloads` (default) | pods, deployments, statefulsets, daemonsets, replicasets, jobs, cronjobs |
| `namespaces` | namespaces (metadata only, for PSA labels) |
| `rbac` | roles, clusterroles, rolebindings, clusterrolebindings |
| `network` | networkpolicies, services |

A ready-to-review ClusterRole for all four scopes is in `rbac.yaml`.

## Run

```bash
# Default workload posture scan, all namespaces:
clusterproof scan --kubeconfig "$HOME/.kube/config"

# Full attack-surface scan with PSA, RBAC, and network analysis:
clusterproof scan \
  --kubeconfig "$HOME/.kube/config" \
  --cluster-scopes workloads,namespaces,rbac,network \
  --fail-on high
```

## Expected output

- Findings are grouped by severity with stable rule IDs (`CP-K8S-*`,
  `CP-RBAC-*`, `CP-NET-*`).
- The JSON report's `cluster_scopes` field records each scope as
  `collected`, `denied`, or `absent`. A denied scope is a partial
  assessment, never a clean result — if you see `denied`, the caller lacks
  `list` on that scope's resources.
- Controller-owned children (ReplicaSets of Deployments, Pods of
  ReplicaSets) are deduplicated automatically.
