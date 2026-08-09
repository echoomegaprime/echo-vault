# ECHO Vault agent doorway

This is a doorway, not a context library. Load the smallest relevant source, test, and document set for the task.

## Mission

Maintain a public, self-hostable secrets service whose security claims are demonstrated by executable evidence. Preserve compatibility intentionally; never trade away a security invariant to make a test pass.

## Before editing

1. Read `SECURITY.md` and `docs/THREAT_MODEL.md` for security-sensitive work.
2. Search the repository and available code/knowledge indexes for an existing implementation before adding a function or dependency.
3. Use current official documentation for external libraries, APIs, actions, and container images.
4. Inspect the worktree and preserve unrelated changes.

## Absolute boundaries

- Never access or commit a live Vault, database, export, backup, key, token, credential, `.env`, private topology, or client record.
- Tests and examples use synthetic values generated at runtime.
- Do not weaken file-permission checks, namespace scopes, signatures, replay rejection, body budgets, optimistic versions, AEAD context binding, no-store headers, or audit verification.
- Do not introduce plaintext exports, secret-value indexing, caller-supplied actor identity, permissive CORS, silent destructive migration, or fail-open audit behavior.
- A deleted secret remains encrypted and recoverable until an explicit offline retention process erases it and its backups.

## Change protocol

- State the security or behavior invariant being changed.
- Add a negative test that fails without the change.
- Keep migrations forward-only and restore-compatible.
- Treat encryption format, request canonical, key rotation, destructive operations, and audit-chain changes as release-significant.
- Update the threat model, architecture, operations guide, and changelog when their claims change.

## Human interface

- This product has recurring operator journeys, so the browser console is a release requirement rather than an optional demo.
- Keep setup status, metadata browsing, create/reveal/rotate/delete, audit verification, and rekey workflows usable without autonomous tooling.
- Preserve the memory-only client-key model: no cookies, browser storage, analytics, service worker, URL credentials, or permissive cross-origin access.
- Keep the console responsive, keyboard-operable, high contrast, reduced-motion aware, and free of emoji-as-interface.
- Run a real browser journey for every console-affecting release; static rendering alone is insufficient.

## Required verification

Run all of the following before proposing completion:

```bash
python -m compileall -q src tests
ruff format --check .
ruff check .
mypy
python -m pytest
```

For a release, also require:

- hosted GitHub CI green on the exact commit;
- CodeQL and secret scanning green;
- container build green;
- a real loopback server plus signed CLI create/read/list/update/delete/audit journey;
- a clean current-tree and full-history secret scan;
- Certification Forge evidence bound to the exact commit;
- an ECHO GitHub App Suite verdict bound to the same commit.

No badge, certificate, release, migration marker, or `PRODUCTION_READY` claim may be issued before every applicable gate is green. Record the exact commit, test counts, workflow run URLs, hashes, and known limitations in the certificate evidence.

## Legacy provenance

The historical `ECHO-OMEGA-PRIME/echo-master-vault` and `ECHO-OMEGA-PRIME/echo-vault-api` Cloudflare Workers are non-canonical. They may be retained only as clearly quarantined provenance. Never restore their shared deployment target, plaintext storage/export behavior, single universal key, destructive schema reset, or incompatible implementation collision.
