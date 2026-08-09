# Threat model

## Protected assets

- plaintext secret values and private metadata;
- encryption and audit keys;
- client signing secrets;
- integrity and availability of version history;
- attribution and ordering of audit evidence.

## In-scope attackers

- an unauthenticated network caller;
- a caller with one stolen or over-privileged client secret;
- a read-only database or backup thief;
- a database writer who does not hold encryption or audit keys;
- a contributor or compromised build attempting to publish secret material;
- concurrent legitimate clients producing conflicting updates.

## Controls

| Threat | Control |
|---|---|
| Database disclosure | AES-256-GCM payload encryption; keys stored separately |
| Ciphertext swapping | Record ID, namespace, name, and version bound as AAD |
| Cross-tenant access | Explicit client scopes and namespace allowlist |
| Token replay | Timestamp window plus atomic nonce table retained for the complete acceptance window |
| Lost updates | Required expected version and transactional compare-and-swap |
| Audit rollback/truncation | Separate-key HMAC chain plus independently preserved signed anchor journal |
| Resource exhaustion | Actual body limit, bounded models, post-authentication client token bucket, constant-work readiness |
| Cache disclosure | `no-store`, `Pragma`, and expiry headers on all responses |
| Accidental publication | Broad secret/database ignores plus CI artifact scanner |

## Trust assumptions

- TLS terminates at a trusted local proxy and traffic from that proxy to ECHO Vault is protected by the host or private network.
- The operating system, process identity, and container runtime enforce key/client file permissions.
- Administrators protect and separately back up the key ring.
- Client clocks remain within the configured skew window.
- SQLite resides on a local filesystem with correct locking semantics.
- The audit anchor is stored and replicated outside the database snapshot domain.
- The operator browser and its extensions are trusted while plaintext is intentionally displayed.

## Explicit non-goals

- hardware-backed KMS/HSM custody;
- multi-region consensus or high availability;
- hiding secret names and tags from a database reader;
- preventing a host-root attacker from reading process memory;
- non-repudiation after compromise of the audit key;
- automatic permanent erasure from every backup.
- protection from a browser or host that is already compromised while an operator session is unlocked.

Deployments requiring those properties should integrate a KMS/HSM, external append-only audit sink, database service with replicated transactions, and formal retention controls.

## Security review checklist

- Does every protected route declare the narrowest scope?
- Is namespace authorization checked before storage access?
- Does every mutation require an expected version where applicable?
- Is every ciphertext created with a fresh nonce and correct AAD?
- Can any response, log, error, metric, or audit detail include plaintext?
- Does the operation commit its audit evidence within the same transaction?
- Are every key ID and old backup still recoverable during rotation?
- Do negative tests cover replays, tampering, oversized bodies, and cross-namespace access?
