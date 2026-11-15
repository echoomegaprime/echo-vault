# Changelog

All notable changes to ECHO Vault are documented here. This project follows
[Semantic Versioning](https://semver.org/) from its first public release.

## [0.1.0] - 2026-08-09

### Added

- Self-hosted FastAPI secrets service with SQLite persistence and an operator CLI.
- AES-256-GCM encryption with per-version nonces, key identifiers, and record-bound AAD.
- Scoped HMAC clients, request timestamps, atomic nonce replay rejection, and uniform auth failures.
- Optimistic concurrency, version history, soft deletion, key rotation, and full-database rekeying.
- Metadata-only HMAC audit chain plus a separately signed append-only rollback-detection anchor.
- Constant-work readiness verification and an authenticated deep audit verifier.
- Responsive browser console with a memory-only, non-exportable Web Crypto signing key.
- Non-root container, read-only-root deployment defaults, staging-safe health checks, and Compose example.
- Python 3.11/3.12 CI, real-process CLI E2E, container journey, CodeQL, Gitleaks, and repository-boundary gates.
- Exact-revision Certification Forge journey plus governed conformance receipts for the eight-app ECHO GitHub suite.

### Security

- Production requires POSIX permission enforcement and explicit key/client manifest files.
- The CLI rejects plaintext transport to remote hosts and does not print bootstrap or retrieved secrets by default.
- Protected requests fail closed when the audit integrity checkpoint is unhealthy.
- GitHub Actions and the container base image are pinned to immutable revisions.
- The governed release check fails closed unless Certification Forge returns a signed terminal `PRODUCTION_READY` verdict.

[0.1.0]: https://github.com/echoomegaprime/echo-vault/releases/tag/v0.1.0
