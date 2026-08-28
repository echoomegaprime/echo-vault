# echo-vault — credential vault MCP server

Exposes the ECHO credential vault (`echo.vault.*` caps on the FORGE SDK gate) to
Claude Code as typed MCP tools, with a read-only local-snapshot fallback so reads
survive gate outages. Sibling of `../echo-queue` and `../echo-memory` — same
architecture (FastMCP stdio, circuit breaker, gate → fallback chain, stderr-only
logging).

Built 2026-07-06 on HAMMER per `_specs/echo-vault_spec.md`.

## Tools

| Tool | Notes |
|---|---|
| `vault_get(service, username="")` | fetch a secret. Signed `echo.vault.get` → local snapshot fallback. Returns `{ok, service, username, secret, source: gate\|local}` |
| `vault_put(service, username, secret, note="")` | store/rotate via signed `echo.vault.put`. **No local fallback** — gate down ⇒ `{ok:false, error:"gate_unreachable"}`; retry later |
| `vault_list(prefix="")` | service/username pairs, **names only, never values**. Signed → unsigned → local snapshot |
| `vault_stats()` | `echo.vault.stats` → local snapshot counts (credentials / distinct services / pairs) |
| `vault_health()` | gate LAN+tunnel `/health`, snapshot readability, circuit-breaker state, audit-queue depth, verdict |

## The HMAC detail (tier-2 envelope)

Vault `get`/`put` are **tier-2** caps — the plain envelope the siblings use is not
enough. `gate_invoke_signed()` builds the standard envelope
(`envelope_version:1, capability, params, context:{bypass_reason}`) with **FLAT
params** (no `command`/`options` shape — the signature covers exactly what is
sent), then signs it:

```
canonical = f"v1|{api_key}|{capability}|{stable_json(params)}|{nonce}|{ts}"
hmac      = HMAC_SHA256(key=bytes.fromhex(hmac_secret_hex), msg=canonical).hexdigest()
envelope["auth"] = {"hmac": hmac, "nonce": nonce, "ts": ts}
```

`stable_json` = `json.dumps(params, sort_keys=True, separators=(",", ":"))` —
must byte-match the gate verifier (ported from
`../echo-sovereign/dist/envelope.js`). `nonce = secrets.token_hex(16)` (valid
120 s), `ts = int(time.time())` (must be within ±90 s of the gate) — both are
generated **fresh per endpoint attempt** so a LAN→tunnel retry never replays a
nonce. Signed is used for all four caps (harmless on tier-1 list/stats; there is
an unsigned retry for those two in case the verifier rejects unexpected `auth`).

## Fallback behavior

| op | gate down / circuit open |
|---|---|
| reads (`get`/`list`/`stats`) | served from the **read-only** local snapshot `C:\ECHO_OMEGA_PRIME\SECURE_VAULT\master_vault.db` (`credentials` table, opened `mode=ro`), flagged `source/via: local` + a may-lag note |
| writes (`put`) | **never** fall back or queue — the vault worker is canonical for versioning + audit. Caller gets `gate_unreachable` and retries |

Two consecutive transport failures open a per-endpoint circuit breaker for 120 s
(same as siblings) so a degraded gate doesn't cost ~27 s of timeouts per call.

## Security invariants

- Secret **values never land in stderr logs, the local SQLite queue, or the
  context mirror** — only `service/username` metadata is recorded (redacted
  access-audit rows mirrored to `arcanum_sdk.context_memories`, fire-and-forget
  in a daemon thread; queued locally in `local_queue.db` during outages).
- The audit queue starts an immediate daemon pass and drains every 30 seconds,
  plus opportunistic wakeups after a successful foreground mirror. `mcp.run()`
  never waits for the startup replay, so recovery does not require a new vault
  request or successful foreground write and cannot block MCP startup.
- Retry state is durable: each transient failure increments `attempts`, stores
  a redacted `last_error`, and advances `next_attempt_at` with bounded
  exponential backoff. The default policy is 8 attempts, 5 seconds initial
  delay, and a 300 second ceiling.
- Every queued operation is accounted for. Registered operations dispatch;
  unknown operations, malformed payloads, schema/constraint failures, and
  exhausted retries move transactionally to `dead_letters`. Drains process
  successive batches rather than treating batch size as the total, while each
  pass remains bounded to 200 rows, 20 batches, and a 20-second deadline.
- SQLite leases are claimed under `BEGIN IMMEDIATE`; per-row heartbeats keep a
  live dispatcher fenced from sibling processes, while expired leases recover
  automatically after a crashed process.
- Queue payloads are capped at 16 KiB and total pending-plus-DLQ depth at 10,000
  rows. The DB file is set to owner read/write permissions where supported.
- Mirror `importance` is accepted only as a finite non-boolean number from 0 to
  1 before SQL is assembled. Gate/worker error text scrubs every supplied
  non-empty secret, including 1-3 character values, plus the sovereign key.
- `vault_list`/`vault_stats`/`vault_put` response bodies are defensively
  stripped of any value-bearing keys (`secret`, `password`, `token`, …).
- The snapshot DB is opened read-only; this server can never write it.

## Hard-won gotchas baked in

1. **`subprocess` never inherits the MCP stdin pipe.** Every ssh call passes
   `input=` (payload pipe) — without this the child eats MCP protocol bytes and
   the tool fails ONLY under MCP while working standalone (memory card
   `feedback-systemd-subprocess-stdin-devnull` family).
2. **ssh stdin payloads are LF-only utf-8 bytes** (Windows CRLF corrupts them).
3. **The gate sentinel can flag vault caps `capability_unhealthy` while they
   actually work** — treated as retriable (try the other endpoint, then the
   local snapshot), so `vault_get` still answers on a false-red flag.

## Run / verify

```
python test_client.py                      # health + list + get, secrets MASKED on stdout
python test_client.py <service> [username] # probe a specific credential
```

## Env

| var | default |
|---|---|
| `ECHO_SOVEREIGN_KEY` | (required for gate tier) |
| `ECHO_VAULT_HMAC_SECRET` | the `echo-sovereign` HMAC secret from `.mcp.json` |
| `SDK_GATE` | `http://192.168.1.220:8000` |
| `ECHO_GATE_TUNNEL` | `https://forge.echo-op.com/sdk/invoke` |
| `ECHO_VAULT_DB` | `C:\ECHO_OMEGA_PRIME\SECURE_VAULT\master_vault.db` (ro snapshot) |
| `ECHO_SSH_HOST` | `forge` (audit-mirror tier only) |
| `ECHO_SEAT` | `echo-vault-mcp` |
| `ECHO_VAULT_QUEUE_DRAIN_INTERVAL` | `30` seconds |
| `ECHO_VAULT_QUEUE_BASE_DELAY` | `5` seconds |
| `ECHO_VAULT_QUEUE_MAX_DELAY` | `300` seconds |
| `ECHO_VAULT_QUEUE_MAX_ATTEMPTS` | `8` |
| `ECHO_VAULT_QUEUE_BATCH_SIZE` | `10` |
| `ECHO_VAULT_QUEUE_MAX_PAYLOAD` | `16384` bytes |
| `ECHO_VAULT_QUEUE_MAX_DEPTH` | `10000` rows |

Queue verification is deterministic and uses only temporary SQLite files:

```
python -m unittest -v test_durable_queue.py
```
