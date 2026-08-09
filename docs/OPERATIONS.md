# Operations

## Initial provisioning

Run `echo-vault init` on the target host. Move the generated key and client manifests to the runtime's secret mount, restrict them to the service identity, and store an encrypted offline recovery copy separately from the database backup.

The client secret printed by initialization is a bootstrap credential. Create narrower client entries for workloads, verify them, and remove the bootstrap client from the runtime manifest when routine administration no longer needs it.

## Backup and restore

1. Quiesce writes or use SQLite's online backup API.
2. Copy `vault.db` and its WAL consistently.
3. Encrypt the database backup independently.
4. Back up `keys.json` to a separate access domain.
5. Record hashes and the latest verified audit root.
6. Restore into an isolated environment and run `/readyz` plus a synthetic write/read/rotate/delete journey.

A database backup without the matching key ring is intentionally unreadable. A key ring without the database contains no stored secrets but remains sensitive.

## Encryption-key rotation

1. Add a new 32-byte key under a new key ID in the root-only key ring.
2. Restart and verify `/readyz` while the previous active key remains present.
3. Call `POST /v1/admin/rekey/{new-key-id}` with an admin-scoped client.
4. Verify all current and historical versions plus the audit chain.
5. Change `active_key_id` to the new key ID and restart.
6. Keep old keys until all retained backups that reference them expire or have been re-encrypted and restore-tested.

Never rename a key ID or replace its bytes in place.

## Client rotation

Add a new client entry or replace a client's secret, deploy it to the consumer, verify a signed request, then remove the old entry and restart. A client manifest reload currently requires a process restart so rotation is explicit and observable.

## Incident response

If a client secret is exposed, remove that client, restart, inspect audit events for its ID, rotate affected stored credentials, and preserve the database plus independent audit roots. If an encryption key is exposed, add a new key, rekey all versions, rotate every high-value stored credential, and expire backups according to policy.
