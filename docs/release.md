# Release and Rollback

## Release gate

1. Run `go test ./...`, `go vet ./...`, `go build ./...`.
2. Run Trivy against the repository and triage all high or critical findings.
3. Run `goreleaser check`.
4. Tag an immutable semantic version such as `v0.1.0`.
5. Verify the GitHub release contains four archives and `checksums.txt`, then pin
   their hashes in `deploy/krew/clusterproof.yaml`.
6. Install one archive from its public URL with the pinned krew manifest and run both secure and
   insecure fixture scans.
7. Submit or update the manifest in `kubernetes-sigs/krew-index`.

## Rollback

Release artifacts and tags are immutable. Do not replace a bad archive under the
same version.

1. Remove the affected GitHub release from the recommended path and publish a
   patch release with the fix.
2. Update the krew index to the patch version.
3. If exploitation is plausible, publish a GitHub security advisory with affected
   and fixed versions.
4. Users can return to a prior local binary from that version's release archive;
   checksums remain in the corresponding release.

The CLI has no server state, database migration, or remote customer data, so
rollback is binary replacement only.
