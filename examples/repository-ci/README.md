# Example: repository CI gate

Gate pull requests on ClusterProof findings and upload SARIF to code
scanning. Total setup time should be under 15 minutes.

## Steps

1. Copy `workflow.yml` into `.github/workflows/clusterproof.yml` of your
   repository.
2. Pin `version` to a released ClusterProof version and paste the matching
   SHA-256 for `clusterproof_<version>_linux_amd64.tar.gz` from that
   release's `checksums.txt` asset.
3. Adjust `path` to your manifest directory and `fail-on` to your policy.

## What you get

- Pull requests fail (exit 2) when findings meet the severity threshold.
- SARIF appears in the repository's Security tab with stable rule IDs.
- The action downloads a released binary and verifies its checksum before
  executing anything; it needs no cluster credentials and no write access.

## Expected output

Scanning the insecure fixture in the ClusterProof repository produces exit
code 2 with findings such as `CP-K8S-001` (privileged container); the
secure fixture produces exit code 0 with an `assessment` of `assessed`.

## Suppress a reviewed finding

Commit a `.clusterproof-exceptions.yaml` with rule, target, owner, reason,
and expiry, then add `exceptions: .clusterproof-exceptions.yaml` to the
workflow step. Expired or malformed entries never suppress; suppressed
identities remain visible in the report.
