# Architecture

## Trust boundaries

```text
CLI / workload
  | exact-byte HMAC request, client scope, timestamp, nonce
  v
FastAPI boundary
  | body budget -> identity -> signature -> replay -> namespace policy
  v
Transactional store
  | immutable version + current pointer + chained audit event
  v
SQLite WAL                    Root-only key ring
  | ciphertext, metadata      | encryption keys + separate audit key
  +---------------------------+
```

The service does not infer trust from IP addresses, proxy headers, caller-supplied actor names, or secret names. Actor identity comes from the verified client manifest entry.

## Encryption envelope

Each version is a JSON payload containing the secret, optional username, and private metadata. The payload is encrypted by AES-256-GCM with a fresh 96-bit nonce. The authenticated-but-unencrypted context is canonical JSON containing:

- format identifier;
- immutable numeric secret ID;
- namespace;
- name;
- version.

Changing any of those fields causes authentication failure. The stored envelope contains the key ID, nonce, and ciphertext/tag. Historical key IDs remain loadable until every dependent backup and version has been migrated.

Names and tags remain plaintext so operators can list and route records without decryption. Never place sensitive values in names or tags.

## Request authentication

Protected requests use a client ID plus an HMAC-SHA256 signature over:

```text
echo-vault-hmac-v1
METHOD
PATH
RAW_QUERY
SHA256(EXACT_BODY)
UNIX_TIMESTAMP
NONCE
```

The server checks the client action scope and namespace, timestamp skew, signature, rate budget, and atomic nonce claim. Redirects are not followed by the bundled client because a redirect would change the signed target.

## Persistence model

`secrets` stores identity, current version, tags, and deletion state. `secret_versions` is immutable except for controlled re-encryption of the same authenticated payload. Creation writes version 1 exactly once. Update inserts version N+1 and compare-and-swaps the current pointer in one `BEGIN IMMEDIATE` transaction.

Deletes are soft and retain encrypted history for recovery. Permanent erasure is intentionally absent from the public API; operators must use a documented offline retention process and backup lifecycle.

## Audit chain

Each event records only actor, action, record coordinates, outcome, safe details, previous event hash, and its own HMAC. The audit key is separate from encryption keys. Readiness fails if the chain does not verify.

The chain detects database modification; it does not prevent an attacker who possesses both the database and audit key from rewriting history. Export signed audit roots to independent storage for stronger non-repudiation.
