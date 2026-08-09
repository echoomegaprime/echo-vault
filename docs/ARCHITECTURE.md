# Architecture

## Trust boundaries

```text
Browser console / CLI / workload
  | exact-byte HMAC request, client scope, timestamp, nonce
  v
FastAPI boundary
  | body budget -> signature -> rate budget -> replay -> namespace policy
  v
Transactional store
  | immutable version + current pointer + chained audit event
  v
SQLite WAL                    Root-only key ring
  | ciphertext, metadata      | encryption keys + separate audit key
  +---------------------------+
            |
            +--> separately signed append-only audit anchor
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

The server validates the timestamp and HMAC before charging the resolved client's rate budget. It then atomically claims the nonce and evaluates action plus namespace authorization. This order prevents invalid signatures from starving or probing a known client. Redirects are not followed by the bundled client because a redirect would change the signed target.

The browser console uses the same exact-byte contract through Web Crypto. Client material is imported into a non-exportable `CryptoKey`, retained only in tab memory, never placed in cookies or browser storage, and cleared on lock or page exit.

## Persistence model

`secrets` stores identity, current version, tags, and deletion state. `secret_versions` is immutable except for controlled re-encryption of the same authenticated payload. Creation writes version 1 exactly once. Update inserts version N+1 and compare-and-swaps the current pointer in one `BEGIN IMMEDIATE` transaction.

Deletes are soft and retain encrypted history for recovery. Permanent erasure is intentionally absent from the public API; operators must use a documented offline retention process and backup lifecycle.

## Audit chain

Each event records only actor, action, record coordinates, outcome, safe details, previous event hash, and its own HMAC. The audit key is separate from encryption keys. Every append also writes a signed anchor record containing the database identity, terminal event ID, terminal hash, and timestamp to a separate journal. Readiness compares the database tail with that signed anchor in constant work; the authenticated deep-verification endpoint recomputes every retained link.

The anchor detects tail deletion, an empty-table reset, and restoration of an older database snapshot when the anchor journal is preserved independently. Deep verification detects retained-row modification. Neither control prevents an attacker who possesses the database, anchor, and audit key from rewriting all evidence. Replicate anchor records to independent append-only storage for stronger non-repudiation.
