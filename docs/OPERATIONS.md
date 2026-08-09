# Operations

## Initial provisioning

Run `echo-vault init` on the target host. Move the generated key and client manifests to the runtime's secret mount, restrict them to the service identity, and store an encrypted offline recovery copy separately from the database backup.

Initialization writes the bootstrap credential to `bootstrap-client.secret` with mode `0600` instead of printing it. Move it into a protected secret store, delete the bootstrap file, create narrower client entries for workloads, verify them, and remove the bootstrap client from the runtime manifest when routine administration no longer needs it. `--print-client-secret` is an explicit, higher-exposure escape hatch.

## Backup and restore

1. Quiesce writes or use SQLite's online backup API.
2. Copy `vault.db` and its WAL consistently.
3. Encrypt the database backup independently.
4. Back up `keys.json` to a separate access domain.
5. Preserve the complete audit-anchor journal separately from the database snapshot and record its hash.
6. Restore into an isolated environment and run `/readyz` plus a synthetic write/read/rotate/delete journey.

A database backup without the matching key ring is intentionally unreadable. A key ring without the database contains no stored secrets but remains sensitive.

## Encryption-key rotation

1. Add a new 32-byte key under a new key ID in the root-only key ring, set it as `active_key_id`, and retain the previous key.
2. Restart and verify `/readyz`; every new write now uses the new active key.
3. Call `POST /v1/admin/rekey/{new-key-id}` with an admin-scoped client. The API refuses a target that is loaded but not active.
4. Verify all current and historical versions plus the audit chain.
5. Repeat the operation until zero historical versions require rekeying.
6. Keep old keys until all retained backups that reference them expire or have been re-encrypted and restore-tested.

Never rename a key ID or replace its bytes in place.

## Client rotation

Add a new client entry or replace a client's secret, deploy it to the consumer, verify a signed request, then remove the old entry and restart. A client manifest reload currently requires a process restart so rotation is explicit and observable.

## Incident response

If a client secret is exposed, remove that client, restart, inspect audit events for its ID, rotate affected stored credentials, and preserve the database plus independent audit roots. If an encryption key is exposed, add a new key, rekey all versions, rotate every high-value stored credential, and expire backups according to policy.

## Audit-anchor custody

Set `ECHO_VAULT_AUDIT_ANCHOR_FILE` to a service-writable file outside the database backup domain. Replicate new journal lines to append-only object storage or a remote log sink. Never restore an older anchor alongside an older database snapshot. Readiness intentionally fails if one side is missing, rolled back, or divergent. A crash between the anchor append and SQLite commit fails closed and requires an operator to compare the last signed anchor with the database before recovery.

## Browser console

Serve `/console` only over HTTPS except for loopback development. Use a narrowly scoped client, lock the tab when leaving the workstation, and clear the clipboard after copying a revealed value. The console does not persist credentials, but browser extensions, endpoint malware, and screen recording remain inside the operator trust boundary.
