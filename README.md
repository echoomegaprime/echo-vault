# ECHO Vault

[![CI](https://github.com/echoomegaprime/echo-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/echoomegaprime/echo-vault/actions/workflows/ci.yml)
[![Security](https://img.shields.io/badge/security-fail--closed-8b5cf6)](SECURITY.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-0ea5e9)](LICENSE)

Self-hosted secrets management for teams that want a small, inspectable system instead of a black box. ECHO Vault encrypts every secret version with AES-256-GCM, binds ciphertext to its identity and version, authenticates clients with signed requests, rejects replays, and records a tamper-evident audit chain.

This repository contains no ECHO production data, credentials, keys, database snapshots, account catalog, or private infrastructure configuration.

## Why it is different

- **Versioned authenticated encryption** — random 96-bit nonces, a key ID on every record, and AAD covering namespace, secret ID, and version.
- **Scoped clients** — each client receives explicit actions and namespace boundaries; no universal shared API key is required.
- **Signed writes and reads** — HMAC-SHA256 covers the method, path, query, exact body, timestamp, and nonce.
- **Replay rejection** — signed nonces are atomically claimed and expire automatically.
- **Safe rotation** — optimistic version checks prevent lost updates; encryption keys rotate without discarding old key IDs.
- **Evidence by default** — metadata-only audit events form an HMAC chain and can be verified through the API or CLI.
- **No secret search index** — names and tags are searchable; plaintext secret values and private metadata are not.
- **Fail-closed startup** — production will not boot without readable key and client manifests.

## Five-minute local start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .

# Writes root-only key/client manifests and prints the one-time client secret.
echo-vault init --directory .local-vault

export ECHO_VAULT_DATA_DIR="$PWD/.local-vault/data"
export ECHO_VAULT_KEYS_FILE="$PWD/.local-vault/keys.json"
export ECHO_VAULT_CLIENTS_FILE="$PWD/.local-vault/clients.json"
export ECHO_VAULT_CLIENT_ID="local-admin"
read -rsp "One-time client secret: " ECHO_VAULT_CLIENT_SECRET; echo
export ECHO_VAULT_CLIENT_SECRET

echo-vault serve
```

In a second terminal with the same client variables:

```bash
printf '%s' 'example-value' | echo-vault put demo database-password --stdin
echo-vault get demo database-password
echo-vault list demo
```

Windows PowerShell uses `$env:NAME='value'` instead of `export NAME=value`.

## API surface

| Method | Path | Required scope | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | public | Process liveness only |
| `GET` | `/readyz` | public | Generic readiness without inventory disclosure |
| `POST` | `/v1/secrets/{namespace}/{name}` | `write` | Create a secret |
| `PATCH` | `/v1/secrets/{namespace}/{name}` | `write` | Add a new version with compare-and-swap |
| `GET` | `/v1/secrets/{namespace}/{name}` | `read` | Retrieve the current decrypted value |
| `GET` | `/v1/secrets` | `read` | List non-secret metadata |
| `GET` | `/v1/secrets/{namespace}/{name}/versions` | `read` | List version metadata |
| `DELETE` | `/v1/secrets/{namespace}/{name}` | `delete` | Soft-delete with compare-and-swap |
| `POST` | `/v1/admin/rekey/{key_id}` | `admin` | Re-encrypt all versions under a loaded key |
| `GET` | `/v1/audit/verify` | `audit` | Verify the audit chain |

Every `/v1` request uses `X-Vault-Client`, `X-Vault-Timestamp`, `X-Vault-Nonce`, and `X-Vault-Signature`. The bundled CLI generates them over the exact request bytes.

## Production deployment

The container runs as a non-root user with a read-only root filesystem. Mount three writable/runtime locations:

1. `/var/lib/echo-vault` for the SQLite database.
2. `/run/secrets/echo_vault_keys` for the root-only key ring.
3. `/run/secrets/echo_vault_clients` for the root-only scoped-client manifest.

Terminate TLS in a trusted reverse proxy. Do not expose the service over plaintext networks. Back up the database and key ring separately, encrypt both backups, and rehearse restoration.

See [Architecture](docs/ARCHITECTURE.md), [Threat model](docs/THREAT_MODEL.md), [Operations](docs/OPERATIONS.md), and [Security policy](SECURITY.md).

## Project status

`0.x` is an early public release. The cryptographic format, migration rules, and API compatibility are covered by tests, but operators should review the threat model against their environment before production use.

## License

Apache License 2.0. Commercial support and ECHO platform integrations are separate from this community edition.
