# Example: SOC 2 technical evidence handoff

Produce integrity-verified, signed technical readiness evidence an auditor
can review. ClusterProof output is technical evidence only: it never claims
compliance, an audit opinion, or certification.

## 1. Scan and produce the bundle

```bash
clusterproof scan ./deploy \
  --evidence-dir "evidence-$(date +%Y-%m-%d)" \
  --exceptions .clusterproof-exceptions.yaml \
  --fail-on high
```

The bundle contains `scan.json` (findings and suppressed identities),
`controls.json` (assessed coverage using only `attention_required`,
`no_findings_observed`, and `not_assessed`), `metadata.json`,
`ruleset.json` (the exact versioned catalog), and `bundle-manifest.json`
(SHA-256 of every file).

## 2. Sign the bundle

Generate a signing key once, outside ClusterProof, and keep it in your key
management system:

```bash
openssl genpkey -algorithm ed25519 -out evidence-signer.key
openssl pkey -in evidence-signer.key -pubout -out evidence-signer.pub
```

```bash
clusterproof evidence sign "evidence-$(date +%Y-%m-%d)" \
  --key evidence-signer.key \
  --signer "security-team@example.com"
```

## 3. Hand off and verify

Give the auditor the evidence directory and, separately, the public key.
The auditor verifies offline:

```bash
clusterproof evidence verify evidence-2026-07-24 --signer-key evidence-signer.pub
# -> evidence bundle verified: integrity and signature (signer: security-team@example.com)
```

Verification distinguishes three states: `integrity only (unsigned)`,
`integrity only` with an unpinned signature, and `integrity and signature`.
The embedded key never proves authenticity — only the out-of-band public
key does. Any tampered file fails verification entirely.

## 4. Compare posture across audit periods

```bash
clusterproof compare evidence-2026-06-24 evidence-2026-07-24
```

The comparison classifies new, resolved, severity-changed, and unchanged
findings and records both input hashes, giving the auditor a deterministic
delta between review periods.
