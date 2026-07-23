# Krew release

GoReleaser generates a checksum-pinned plugin manifest in `dist/`. The reviewed
manifest for the current public release is committed as `clusterproof.yaml`.

Before the first public release:

1. Tag a semantic version such as `v0.1.0`.
2. Confirm all four release archives and `checksums.txt` exist.
3. Copy the generated version, URLs, and checksums into `clusterproof.yaml`.
4. Test the manifest and a local archive:

   ```bash
   kubectl krew install \
     --manifest=dist/clusterproof.yaml \
     --archive=dist/clusterproof_0.1.0_darwin_arm64.tar.gz
   kubectl clusterproof version
   kubectl krew uninstall clusterproof
   ```

5. Submit `clusterproof.yaml` to `plugins/` in
   `kubernetes-sigs/krew-index`.

Krew requires public open-source code, an OSI license, a semantic version tag,
and a tested release archive before submission.
