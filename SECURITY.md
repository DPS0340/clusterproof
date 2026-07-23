# Security Policy

Please report suspected vulnerabilities privately to the repository owner before
opening a public issue. Include the affected version, a minimal reproduction, and
the impact. Do not include live credentials or customer manifests.

ClusterProof treats YAML, Kubernetes API output, Trivy output, PolicyReport
JSON, and evidence bundles as hostile. A security change is not complete until
it has a regression test. If a real credential enters git history, revoke and
rotate it before attempting history cleanup.

Repository scans are local. Live scans require an explicit kubeconfig and execute
only a fixed, read-only `kubectl get` workload request with bounded output and
runtime. ClusterProof does not read Secrets or persist kubeconfig contents. It has
no server, authentication flow, telemetry endpoint, or automatic Kubernetes
mutation.

Treat kubeconfig files as executable trust inputs: Kubernetes supports credential
plugins that `kubectl` may execute during authentication. Do not point
ClusterProof at an untrusted kubeconfig.

PolicyReport import is a bounded data adapter. It never installs, downloads, or
executes Rego, Kyverno, Gatekeeper, or other external policy code. Imported
result messages are intentionally omitted because policy engines can copy
sensitive resource details into them.

Evidence verification rejects untracked, missing, modified, symlinked,
non-regular, or oversized files. The manifest provides integrity relative to
itself, not authenticity or non-repudiation. Put the manifest in an immutable or
externally signed custody system if evidence provenance must be established.
