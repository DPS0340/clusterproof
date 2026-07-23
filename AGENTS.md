# ClusterProof

## Stack

- Go 1.26
- `gopkg.in/yaml.v3` for bounded, local Kubernetes YAML parsing
- Standard library for CLI, subprocess isolation, cluster collection, JSON,
  SARIF, and hashing

## Commands

- Build: `go build ./...`
- Test: `go test ./...`
- Format: `gofmt -w .`
- Vet: `go vet ./...`
- Run: `go run ./cmd/clusterproof scan ./testdata/insecure`
- Live scan: `go run ./cmd/clusterproof scan --kubeconfig /path/to/config`

## Conventions

- Packages are small and named after their domain.
- Exported APIs have Go doc comments.
- Errors add operation context with `%w`.
- Findings use stable rule IDs. Never reuse an ID for a different rule.
- Tests are colocated with source and use table-driven cases when that improves clarity.

```go
func Scan(path string, limits Limits) (Report, error) {
	if strings.TrimSpace(path) == "" {
		return Report{}, errors.New("scan path is required")
	}
	return scanPath(path, limits)
}
```

## Boundaries

- Always treat manifests and scanner output as untrusted input.
- Always bound file count, file size, YAML document count, subprocess runtime, and output size.
- Always use `exec.CommandContext` with argument arrays; never invoke a shell.
- Always keep the default scan read-only and local-only.
- Live collection must use the fixed workload `kubectl get` allowlist in
  `internal/cluster`; never accept a verb or resource name from user input.
- Ask before adding network services, authentication, a database, or cluster mutation.
- Never transmit scan data, follow symlinks, execute manifest content, or print secret values.
- Never claim that a report certifies SOC 2 compliance.
