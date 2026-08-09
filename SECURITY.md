# Security policy

## Reporting

Do not open a public issue for a suspected vulnerability. Use this repository's **Security → Report a vulnerability** workflow with the affected version, impact, reproduction steps, and any suggested remediation. We will acknowledge a complete report within three business days.

Never include real credentials, key rings, client manifests, databases, or decrypted values in a report. Use synthetic test material only.

## Supported releases

Security fixes are provided for the latest tagged minor release. Until `1.0`, operators should pin exact image digests and review release notes before upgrading.

## Security invariants

- No secret or encrypted payload is written to logs or audit metadata.
- Production startup fails closed without valid key and client manifests.
- Every ciphertext is authenticated against immutable record context.
- Every protected request is scoped, signed, time-bounded, and replay-checked.
- Mutations require an expected version once a secret exists.
- Key rotation retains the key ID needed to decrypt historical versions.
- Audit verification failure is a readiness failure.
- The signed audit anchor is preserved independently from database snapshots.
- Browser-console client material is memory-only and remote console access requires HTTPS.

The complete attacker model and non-goals are documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
