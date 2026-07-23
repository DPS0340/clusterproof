# Security Policy

Please report suspected vulnerabilities privately to the repository owner before
opening a public issue. Include the affected version, a minimal reproduction, and
the impact. Do not include live credentials or customer manifests.

ClusterProof treats YAML, Kubernetes API output, and Trivy output as hostile. A
security change is not complete until it has a regression test. If a real
credential enters git history, revoke and rotate it before attempting history
cleanup.

Repository scans are local. Live scans require an explicit kubeconfig and execute
only a fixed, read-only `kubectl get` workload request with bounded output and
runtime. ClusterProof does not read Secrets or persist kubeconfig contents. It has
no server, authentication flow, telemetry endpoint, or automatic Kubernetes
mutation.
