# Krew release

GoReleaser generates the checksum-pinned `clusterproof.yaml` plugin manifest in
`dist/` from `.goreleaser.yaml`.

Before the first public release:

1. Tag a semantic version such as `v0.1.0`.
2. Confirm all four release archives and `checksums.txt` exist.
3. Test the generated manifest and a local archive:

   ```bash
   kubectl krew install \
     --manifest=dist/clusterproof.yaml \
     --archive=dist/clusterproof_0.1.0_darwin_arm64.tar.gz
   kubectl clusterproof version
   kubectl krew uninstall clusterproof
   ```

4. Submit `clusterproof.yaml` to `plugins/` in
   `kubernetes-sigs/krew-index`.

Krew requires public open-source code, an OSI license, a semantic version tag,
and a tested release archive before submission.
