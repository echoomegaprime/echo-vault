#!/usr/bin/env python3
"""
ECHO-VAULT - credential vault MCP server (stdio).

Typed tools over the ECHO credential vault (echo.vault.* caps on the SDK gate),
sibling of echo-queue and echo-memory (same architecture, helpers, and style).

Per-call chain:

    Tier A  SDK gate (LAN -> tunnel)     POST /sdk/invoke, sovereign key
            vault get/put are TIER-2 -> HMAC-signed envelope (auth:{hmac,nonce,ts}),
            params FLAT (canonical v1|key|cap|stable_json(params)|nonce|ts)
    Tier B  local read-only snapshot     C:\\ECHO_OMEGA_PRIME\\SECURE_VAULT\\master_vault.db
            (READS ONLY - vault_get/vault_list/vault_stats; writes NEVER fall back:
            the worker is canonical for versioning + audit)

SECURITY INVARIANT: secret VALUES never land in stderr logs, the local SQLite
queue, or the context mirror - only service/username metadata is ever recorded.
Gate/worker error text is scrubbed of the secret + sovereign key before it is
returned or logged.

Gotchas baked in (same family as the siblings):
  - ssh/subprocess stdin is the payload pipe (input=...) - never inherited, so
    the MCP protocol channel on stdin can't be eaten by a child.
  - ssh stdin payloads are LF-only utf-8 bytes.
  - the gate's health sentinel can flag vault caps "capability_unhealthy" while
    they actually work -> treated as retriable; reads always have the local
    snapshot fallback so vault_get answers even when the gate flags itself.
All logging goes to stderr - stdout is the MCP protocol channel.
"""

import hashlib
import hmac as hmac_mod
import json
import os
import secrets as pysecrets
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from mcp.server.fastmcp import FastMCP

# --- configuration -----------------------------------------------------------

HERE = Path(__file__).resolve().parent
SOVEREIGN_KEY = os.environ.get("ECHO_SOVEREIGN_KEY", "")
HMAC_SECRET_HEX = os.environ.get(
    "ECHO_VAULT_HMAC_SECRET",
    "14aa383697852678007ad45b993c89eb6e999ffcf501a504f26d90e36f4fa276")
SDK_GATE = os.environ.get("SDK_GATE", "http://192.168.1.220:8000").rstrip("/")
GATE_ENDPOINTS = [
    (SDK_GATE + "/sdk/invoke", 12.0),
    (os.environ.get("ECHO_GATE_TUNNEL", "https://forge.echo-op.com/sdk/invoke"), 15.0),
]
SSH_HOST = os.environ.get("ECHO_SSH_HOST", "forge")
VAULT_DB = Path(os.environ.get("ECHO_VAULT_DB",
                               r"C:\ECHO_OMEGA_PRIME\SECURE_VAULT\master_vault.db"))
LOCAL_DB = Path(os.environ.get("ECHO_VAULT_QUEUE_DB", str(HERE / "local_queue.db")))
SEAT = os.environ.get("ECHO_SEAT") or os.environ.get("BRAIN_INSTANCE_ID", "echo-vault-mcp")
BYPASS = ("echo-vault MCP server routine credential vault access (get/put/list/stats) "
          "on behalf of an authorized Claude session; secret values are never logged, "
          "queued locally, or mirrored - only service/username metadata is recorded")

_db_lock = threading.Lock()

# keys stripped from any list/stats/put response body before it leaves this server
_SENSITIVE_KEYS = {"secret", "value", "password", "token", "secret_enc",
                   "api_key", "private_key", "client_secret"}


def log(msg: str) -> None:
    print(f"[echo-vault {datetime.now().strftime('%H:%M:%S')}] {msg}",
          file=sys.stderr, flush=True)


def _redact(text: str, *secret_values: str) -> str:
    """Scrub secret values + the sovereign key out of any text that could be
    logged or returned as an error. Never let a vault value ride an error."""
    out = text or ""
    for s in secret_values:
        if s and len(s) >= 4:
            out = out.replace(s, "***REDACTED***")
    if SOVEREIGN_KEY:
        out = out.replace(SOVEREIGN_KEY, "***KEY***")
    return out


def _strip_secrets(obj):
    """Defensively drop value-bearing keys from a gate response (list/stats/put
    bodies must return names/metadata only)."""
    if isinstance(obj, dict):
        return {k: _strip_secrets(v) for k, v in obj.items()
                if k.lower() not in _SENSITIVE_KEYS}
    if isinstance(obj, list):
        return [_strip_secrets(x) for x in obj]
    return obj


# --- local SQLite tier (write queue - REDACTED audit mirrors only, never secrets) --

def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(LOCAL_DB, timeout=10)
    conn.execute("""CREATE TABLE IF NOT EXISTS pending_writes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        op TEXT NOT NULL, payload TEXT NOT NULL,
        created_at TEXT NOT NULL, attempts INTEGER DEFAULT 0, last_error TEXT)""")
    return conn


def queue_write(op: str, payload: dict, error: str) -> dict:
    """Queue a durable-intent write locally. ONLY redacted audit metadata ever
    lands here - vault_put is deliberately NOT queued (worker is canonical)."""
    with _db_lock, _db() as c:
        c.execute("INSERT INTO pending_writes(op,payload,created_at,last_error) VALUES(?,?,?,?)",
                  (op, json.dumps(payload), datetime.now(timezone.utc).isoformat(), error[:500]))
        n = c.execute("SELECT count(*) FROM pending_writes").fetchone()[0]
    log(f"queued {op} locally (queue depth {n})")
    return {"ok": False, "queued_locally": True, "queue_depth": n,
            "note": "cluster unreachable; redacted audit row will replay on next successful mirror",
            "last_error": error[:300]}


# --- local read-only vault snapshot (fallback for READS) -----------------------

def _snapshot() -> sqlite3.Connection:
    # mode=ro: this server must never write the master snapshot
    return sqlite3.connect(f"file:{VAULT_DB.as_posix()}?mode=ro", uri=True, timeout=10)


def snapshot_get(service: str, username: str):
    """(row_dict, None) or (None, err). Empty username = match any, newest row."""
    try:
        with _snapshot() as c:
            if username:
                row = c.execute(
                    "SELECT service, username, secret FROM credentials "
                    "WHERE service=? AND username=? ORDER BY rowid DESC LIMIT 1",
                    (service, username)).fetchone()
            else:
                row = c.execute(
                    "SELECT service, username, secret FROM credentials "
                    "WHERE service=? ORDER BY rowid DESC LIMIT 1", (service,)).fetchone()
        if row:
            return {"service": row[0], "username": row[1] or "", "secret": row[2]}, None
        return None, "no matching row in local snapshot"
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:200]}"


def snapshot_list(prefix: str):
    try:
        with _snapshot() as c:
            if prefix:
                rows = c.execute(
                    "SELECT DISTINCT service, username FROM credentials "
                    "WHERE service LIKE ? || '%' ORDER BY service, username LIMIT 500",
                    (prefix,)).fetchall()
            else:
                rows = c.execute(
                    "SELECT DISTINCT service, username FROM credentials "
                    "ORDER BY service, username LIMIT 500").fetchall()
        return [{"service": r[0], "username": r[1] or ""} for r in rows], None
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:200]}"


def snapshot_stats():
    try:
        with _snapshot() as c:
            total = c.execute("SELECT count(*) FROM credentials").fetchone()[0]
            services = c.execute("SELECT count(DISTINCT service) FROM credentials").fetchone()[0]
            pairs = c.execute(
                "SELECT count(*) FROM (SELECT DISTINCT service, username FROM credentials)"
            ).fetchone()[0]
        return {"credentials": total, "distinct_services": services,
                "distinct_service_username_pairs": pairs}, None
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:200]}"


# --- Tier A: SDK gate (circuit breaker; signed + unsigned invokers) ------------

_shape_cache: dict = {}
CB_THRESHOLD = 2
CB_COOLDOWN_S = 120.0
_cb: dict = {}


def _cb_open(url: str) -> bool:
    st = _cb.get(url)
    return bool(st and time.time() < st.get("skip_until", 0))


def _cb_record(url: str, ok: bool) -> None:
    if ok:
        _cb.pop(url, None)
        return
    st = _cb.setdefault(url, {"fails": 0, "skip_until": 0})
    st["fails"] += 1
    if st["fails"] >= CB_THRESHOLD:
        st["skip_until"] = time.time() + CB_COOLDOWN_S
        log(f"circuit OPEN for {url} ({st['fails']} consecutive failures)")


def _envelope(cap: str, verb: str, payload: dict, shape: str) -> dict:
    if shape == "command":
        p = {**payload, "command": verb}
        params = {**p, "options": dict(p)}
    else:
        params = dict(payload)
    return {"envelope_version": 1, "capability": cap, "params": params,
            "context": {"bypass_reason": BYPASS}}


def _unwrap(out: dict):
    """Gate 'result' -> (body, worker_error_or_None)."""
    res = out.get("result", {})
    body = res.get("body", res) if isinstance(res, dict) else res
    sc = res.get("status_code") if isinstance(res, dict) else None
    if sc and sc >= 400:
        return None, f"worker {sc}: {json.dumps(body)[:300]}"
    return body, None


def gate_invoke(cap: str, verb: str, payload: dict, timeout: float | None = None):
    """UNSIGNED tier-1 invoke (list/stats fallback). (body, None) or (None, err)."""
    if not SOVEREIGN_KEY:
        return None, "no ECHO_SOVEREIGN_KEY in environment"
    errors = []
    shapes = [_shape_cache.get(cap, "raw")]
    shapes.append("command" if shapes[0] == "raw" else "raw")
    for url, tmo in GATE_ENDPOINTS:
        if _cb_open(url):
            errors.append(f"{url} circuit-open, skipped")
            continue
        tmo = timeout or tmo
        for shape in shapes:
            try:
                r = httpx.post(url, json=_envelope(cap, verb, payload, shape),
                               headers={"X-Echo-API-Key": SOVEREIGN_KEY}, timeout=tmo)
                if r.status_code in (400, 422):
                    errors.append(f"{url} [{shape}] {r.status_code}: {r.text[:300]}")
                    continue
                r.raise_for_status()
                out = r.json()
                if out.get("status") != "ok":
                    errors.append(f"{url} [{shape}] gate status={out.get('status')}: "
                                  f"{json.dumps(out)[:300]}")
                    continue
                _shape_cache[cap] = shape
                _cb_record(url, True)
                body, werr = _unwrap(out)
                if werr:
                    errors.append(f"{url} [{shape}] {werr}")
                    continue
                return body, None
            except Exception as e:
                errors.append(f"{url} [{shape}] {type(e).__name__}: {str(e)[:200]}")
                _cb_record(url, False)
                break
    return None, " | ".join(errors)


def _stable_json(params: dict) -> str:
    """Must byte-match the gate verifier + echo-sovereign/dist/envelope.js
    stableStringify: sorted keys, no whitespace."""
    return json.dumps(params, sort_keys=True, separators=(",", ":"))


def gate_invoke_signed(cap: str, params: dict, timeout: float | None = None):
    """SIGNED tier-2 invoke for vault caps. Params stay FLAT (no command/options
    shape - the signature covers exactly what is sent). Fresh nonce + ts per
    endpoint attempt (ts must be within +/-90s of the gate; nonce valid 120s).
    Canonical: v1|api_key|capability|stable_json(params)|nonce|ts, HMAC-SHA256
    keyed with bytes.fromhex(hmac_secret). Returns (body, None) or (None, err)."""
    if not SOVEREIGN_KEY:
        return None, "no ECHO_SOVEREIGN_KEY in environment"
    if not HMAC_SECRET_HEX:
        return None, "no ECHO_VAULT_HMAC_SECRET in environment"
    errors = []
    for url, tmo in GATE_ENDPOINTS:
        if _cb_open(url):
            errors.append(f"{url} circuit-open, skipped")
            continue
        env = {"envelope_version": 1, "capability": cap, "params": dict(params),
               "context": {"bypass_reason": BYPASS}}
        nonce = pysecrets.token_hex(16)
        ts = int(time.time())
        canonical = f"v1|{SOVEREIGN_KEY}|{cap}|{_stable_json(env['params'])}|{nonce}|{ts}"
        sig = hmac_mod.new(bytes.fromhex(HMAC_SECRET_HEX), canonical.encode("utf-8"),
                           hashlib.sha256).hexdigest()
        env["auth"] = {"hmac": sig, "nonce": nonce, "ts": ts}
        try:
            r = httpx.post(url, json=env, headers={"X-Echo-API-Key": SOVEREIGN_KEY},
                           timeout=timeout or tmo)
            if r.status_code in (400, 401, 403, 422):
                errors.append(f"{url} [signed] {r.status_code}: {r.text[:300]}")
                continue
            r.raise_for_status()
            out = r.json()
            if out.get("status") != "ok":
                detail = json.dumps(out)[:300]
                # sentinel false-red: "capability_unhealthy" while the cap works
                # -> retriable; keep trying the other endpoint / local fallback
                tag = " (retriable sentinel flag)" if "capability_unhealthy" in detail else ""
                errors.append(f"{url} [signed] gate status={out.get('status')}{tag}: {detail}")
                continue
            _cb_record(url, True)
            body, werr = _unwrap(out)
            if werr:
                errors.append(f"{url} [signed] {werr}")
                continue
            return body, None
        except Exception as e:
            errors.append(f"{url} [signed] {type(e).__name__}: {str(e)[:200]}")
            _cb_record(url, False)
    return None, " | ".join(errors)


# --- Tier B (audit mirror only): direct Postgres over ssh -----------------------

def _q(s) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _pg_run(sql: str, timeout: int, write: bool):
    flags = "-t -A -q" + (" -v ON_ERROR_STOP=1" if write else "")
    cmd = ["ssh", "-o", "ConnectTimeout=8", "-o", "BatchMode=yes", SSH_HOST,
           f"PGPASSWORD=echo psql -h localhost -U echo -d echo {flags}"]
    try:
        # input= gives the child the payload pipe as stdin (LF-only utf-8 bytes);
        # the MCP protocol pipe is never inherited - load-bearing under MCP.
        proc = subprocess.run(cmd, input=(sql.rstrip(";") + ";\n").encode("utf-8"),
                              capture_output=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = proc.stdout.decode("utf-8", errors="replace").strip()
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        if proc.returncode != 0:
            return None, f"psql rc={proc.returncode}: {err[:300] or 'no stderr'}"
        return out, None
    except subprocess.TimeoutExpired:
        return None, f"ssh psql timeout after {timeout}s"
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:200]}"


def pg_json(sql: str, timeout: int = 20):
    """SELECT (or CTE-wrapped write) that yields ONE json value. (rows, err)."""
    out, err = _pg_run(sql, timeout, write=False)
    if err:
        return None, err
    if not out:
        return None, "empty psql output"
    try:
        return json.loads(out), None
    except Exception:
        return None, f"unparseable psql output: {out[:200]}"


def pg_select(sql: str, timeout: int = 20):
    """Wrap a plain SELECT in json_agg. (rows, err)."""
    return pg_json(f"SELECT COALESCE(json_agg(t), '[]'::json) FROM ({sql.rstrip(';')}) t",
                   timeout)


def pg_exec(sql: str, timeout: int = 20):
    """Write statement. (True, None) or (False, err)."""
    _, err = _pg_run(sql, timeout, write=True)
    return (err is None), err


def _is_permanent_pg_error(err: str) -> bool:
    """True when Postgres refused the row for a reason a retry cannot change.

    Constraint/type/column failures are decisions about the data, not transient
    conditions -- requeuing them builds a queue that can never drain. Connection,
    timeout and lock errors are deliberately NOT listed: those are exactly the
    failures the queue exists to survive.
    """
    e = (err or "").lower()
    return any(s in e for s in (
        "violates check constraint",
        "violates not-null constraint",
        "violates foreign key constraint",
        "invalid input syntax",
        "does not exist",          # missing column/table/type
        "value too long",
    ))


def _mirror_context(kind: str, content: str, tags: list, importance: float = 0.75) -> bool:
    """Best-effort mirror to context_memories (cross-CC audit trail). Content is
    ALWAYS redacted metadata - callers never pass secret values. Never raises."""
    try:
        import hashlib as _h
        chash = _h.sha256(content.encode("utf-8")).hexdigest()
        tags_lit = ("ARRAY[" + ",".join(_q(t) for t in tags) + "]::text[]"
                    if tags else "'{}'::text[]")
        ok, err = pg_exec(
            f"INSERT INTO arcanum_sdk.context_memories "
            f"(content_hash, kind, content, tags, workspace, importance, source, actor) "
            f"VALUES ('{chash}', {_q(kind)}, {_q(content)}, {tags_lit}, 'default', "
            f"{importance}, 'echo-vault-mcp', {_q(SEAT)}) "
            f"ON CONFLICT (content_hash) DO NOTHING", timeout=15)
        if not ok:
            raise RuntimeError(err or "pg_exec failed")
        _drain_audit_queue()
        return True
    except Exception as e:
        log(f"context mirror failed (non-fatal): {_redact(str(e))[:200]}")
        # Only queue failures a retry could plausibly fix. A CHECK/NOT NULL/FK
        # violation is a PERMANENT rejection: the same row will be refused every
        # time, so queuing it builds a pile that can never drain. This exact case
        # sat at 228 rows from 2026-07-07 to 2026-08-04 -- kind='vault_access' is
        # not in context_memories_kind_check -- while `attempts` stayed 0, so
        # nothing backed off or gave up. The authoritative audit trail is the
        # vault's own credential_access_log (521k rows, healthy); this mirror is
        # a convenience copy and must never accumulate.
        if _is_permanent_pg_error(str(e)):
            log("context mirror rejected permanently (schema/constraint) - NOT queued")
            return False
        queue_write("mirror_audit",
                    {"kind": kind, "content": content, "tags": tags,
                     "importance": importance}, str(e))
        return False


def _drain_audit_queue(max_rows: int = 10) -> None:
    """Replay queued (redacted) audit mirrors after a successful pg write."""
    with _db_lock, _db() as c:
        rows = c.execute("SELECT id, payload FROM pending_writes WHERE op='mirror_audit' "
                         "ORDER BY id LIMIT ?", (max_rows,)).fetchall()
    for pid, payload_s in rows:
        p = json.loads(payload_s)
        import hashlib as _h
        chash = _h.sha256(p["content"].encode("utf-8")).hexdigest()
        tags_lit = ("ARRAY[" + ",".join(_q(t) for t in p.get("tags") or []) + "]::text[]"
                    if p.get("tags") else "'{}'::text[]")
        ok, _err = pg_exec(
            f"INSERT INTO arcanum_sdk.context_memories "
            f"(content_hash, kind, content, tags, workspace, importance, source, actor) "
            f"VALUES ('{chash}', {_q(p['kind'])}, {_q(p['content'])}, {tags_lit}, 'default', "
            f"{p.get('importance', 0.6)}, 'echo-vault-mcp', {_q(SEAT)}) "
            f"ON CONFLICT (content_hash) DO NOTHING", timeout=15)
        if not ok:
            break  # cluster went away again; keep the rest queued
        with _db_lock, _db() as c:
            c.execute("DELETE FROM pending_writes WHERE id=?", (pid,))


def _mirror_audit(action: str, service: str, username: str, source: str) -> None:
    """Fire-and-forget redacted access-audit mirror (never blocks a tool call,
    never carries a secret value)."""
    content = (f"vault {action} {service}/{username or '*'} via {source} "
               f"by {SEAT} at {datetime.now(timezone.utc).isoformat()}")
    threading.Thread(target=_mirror_context,
                     args=("vault_access", content, ["vault", action, service], 0.6),
                     daemon=True).start()


# --- response helpers -----------------------------------------------------------

def _extract_secret(body):
    """Pull {secret, username?, service?} out of whatever shape the vault worker
    returns. None if no secret field is recognizable."""
    if isinstance(body, str) and body:
        return {"secret": body, "username": "", "service": ""}
    if not isinstance(body, dict):
        return None
    for k in ("secret", "value", "password", "token"):
        v = body.get(k)
        if isinstance(v, str) and v:
            return {"secret": v,
                    "username": body.get("username") or body.get("user") or "",
                    "service": body.get("service") or ""}
    for k in ("credential", "item", "result", "data", "row"):
        v = body.get(k)
        if isinstance(v, (dict, str)):
            got = _extract_secret(v)
            if got:
                return got
    return None


def _names_from(body):
    """Normalize a vault list response to name rows, secrets stripped."""
    if isinstance(body, dict):
        for k in ("items", "credentials", "result", "rows", "list", "entries"):
            if isinstance(body.get(k), list):
                return _strip_secrets(body[k])
    return _strip_secrets(body)


# --- MCP tools -------------------------------------------------------------------

mcp = FastMCP("echo-vault")


@mcp.tool()
def vault_get(service: str, username: str = "") -> str:
    """Fetch a secret from the ECHO credential vault. Primary: HMAC-signed tier-2
    echo.vault.get via the SDK gate; fallback: the local read-only snapshot
    master_vault.db (so reads survive gate outages / false-red sentinel flags).
    Empty username matches any (newest). Returns {ok, service, username, secret,
    source: gate|local}. The secret value goes to the caller ONLY - it is never
    logged, queued, or mirrored."""
    # The gate's input_schema for every echo.vault.* cap requires a "command"
    # field (jsonschema: required:["command"]); it is validated against
    # envelope.params AND is covered by the HMAC (both sign/verify over the same
    # params), so it must be present in the signed params or the gate returns
    # 422 input_schema_validation_failed. Routing is args_mode-based, so the
    # verb value is metadata only (the vault router ignores it).
    params = {"command": "get", "service": service}
    if username:
        params["username"] = username
    body, gerr = gate_invoke_signed("echo.vault.get", params)
    if body is not None:
        got = _extract_secret(body)
        if got and got.get("secret"):
            uname = username or got.get("username", "")
            _mirror_audit("get", service, uname, "gate")
            return json.dumps({"ok": True, "service": service, "username": uname,
                               "secret": got["secret"], "source": "gate"})
        gerr = ("gate answered but no secret field recognized: "
                + (f"keys={sorted(body)[:10]}" if isinstance(body, dict)
                   else type(body).__name__))
    row, serr = snapshot_get(service, username)
    if row:
        _mirror_audit("get", service, row["username"], "local")
        # ok stays True so existing callers keep working, but `degraded` gives them a
        # field to key on. "may lag" was the wrong risk: measured 2026-08-04 this store
        # is a divergent SUPERSET (5,025 rows vs canonical 4,003) holding 82 services
        # canonical does not have -- so a hit here can be a SUPERSEDED value, not a
        # missing one. A stale secret that authenticates nowhere reads as a live one.
        return json.dumps({"ok": True, "degraded": True, "service": row["service"],
                           "username": row["username"], "secret": row["secret"],
                           "source": "local",
                           "note": "served from the legacy PLAINTEXT snapshot because the gate was "
                                   "unavailable. This store diverges from canonical and may hold a "
                                   "SUPERSEDED value. Verify before trusting an auth failure, and "
                                   "re-read from the gate once it recovers.",
                           "gate_error": _redact(gerr)[:300]})
    return json.dumps({"ok": False, "service": service, "username": username,
                       "errors": {"gate": _redact(gerr)[:400], "local": serr[:300]}})


@mcp.tool()
def vault_put(service: str, username: str, secret: str, note: str = "") -> str:
    """Store or rotate a secret via HMAC-signed tier-2 echo.vault.put. NO local
    fallback for writes - the vault worker is canonical for versioning + audit;
    if the gate is down this returns {ok:false, error:"gate_unreachable"} and the
    caller retries later. The local snapshot is never written. The secret value
    is never logged, queued, or mirrored."""
    # "command" is REQUIRED by the gate's input schema for echo.vault.put and is
    # part of the HMAC-signed params (see vault_get). Omitting it was the bug:
    # the signed envelope passed HMAC but then 422'd on schema validation, which
    # this tool surfaced as {ok:false, error:"gate_unreachable"}.
    params = {"command": "put", "service": service, "username": username,
              "secret": secret}
    if note:
        params["note"] = note
    body, gerr = gate_invoke_signed("echo.vault.put", params, timeout=20.0)
    if body is not None:
        _mirror_audit("put", service, username, "gate")
        safe_body = json.loads(_redact(json.dumps(_strip_secrets(body), default=str), secret))
        return json.dumps({"ok": True, "service": service, "username": username,
                           "source": "gate", "result": safe_body}, default=str)
    return json.dumps({"ok": False, "error": "gate_unreachable",
                       "hint": "vault writes must go through the worker for audit; "
                               "retry when gate is up",
                       "detail": _redact(gerr, secret)[:400]})


@mcp.tool()
def vault_delete(service: str) -> str:
    """Delete a credential (and cascade its version history) via HMAC-signed
    tier-2 echo.vault.delete. Irreversible + audit-logged; the vault worker is
    canonical, so there is NO local fallback (the read-only snapshot is never
    written). Returns {ok, service, source:"gate", result} or {ok:false,
    error:"gate_unreachable"}. Use with care."""
    # echo.vault.delete -> DELETE /vault/credentials/{service} (args_mode=path):
    # the gate substitutes {service} into the URL; "command" satisfies the input
    # schema + rides the HMAC, then is ignored by the router.
    params = {"command": "delete", "service": service}
    body, gerr = gate_invoke_signed("echo.vault.delete", params, timeout=20.0)
    if body is not None:
        _mirror_audit("delete", service, "", "gate")
        return json.dumps({"ok": True, "service": service, "source": "gate",
                           "result": _strip_secrets(body)}, default=str)
    return json.dumps({"ok": False, "error": "gate_unreachable",
                       "hint": "vault deletes must go through the worker for audit; "
                               "retry when gate is up",
                       "detail": _redact(gerr)[:400]})


@mcp.tool()
def vault_list(prefix: str = "") -> str:
    """List credential keys (service/username pairs - NO secret values) via
    echo.vault.list (signed first, unsigned retry, then the local snapshot).
    Optional prefix filters on service name."""
    payload = {"command": "list"}
    if prefix:
        payload["prefix"] = prefix
    body, serr_gate = gate_invoke_signed("echo.vault.list", payload)
    if body is None:
        body, uerr = gate_invoke("echo.vault.list", "list", payload)
        if body is None:
            serr_gate = f"signed: {serr_gate[:250]} | unsigned: {uerr[:250]}"
    if body is not None:
        return json.dumps({"ok": True, "via": "gate", "result": _names_from(body)},
                          default=str)
    rows, lerr = snapshot_list(prefix)
    if rows is not None:
        return json.dumps({"ok": True, "via": "local",
                           "note": "read-only local snapshot; may lag the canonical vault",
                           "gate_error": _redact(serr_gate)[:300],
                           "count": len(rows), "result": rows})
    return json.dumps({"ok": False,
                       "errors": {"gate": _redact(serr_gate)[:400], "local": lerr[:300]}})


@mcp.tool()
def vault_stats() -> str:
    """Vault statistics via echo.vault.stats (signed first, unsigned retry, then
    local snapshot counts: credentials / distinct services / distinct pairs)."""
    body, serr_gate = gate_invoke_signed("echo.vault.stats", {"command": "stats"})
    if body is None:
        body, uerr = gate_invoke("echo.vault.stats", "stats", {"command": "stats"})
        if body is None:
            serr_gate = f"signed: {serr_gate[:250]} | unsigned: {uerr[:250]}"
    if body is not None:
        return json.dumps({"ok": True, "via": "gate", "result": _strip_secrets(body)},
                          default=str)
    stats, lerr = snapshot_stats()
    if stats is not None:
        return json.dumps({"ok": True, "via": "local",
                           "note": "read-only local snapshot counts; may lag the canonical vault",
                           "gate_error": _redact(serr_gate)[:300], "result": stats})
    return json.dumps({"ok": False,
                       "errors": {"gate": _redact(serr_gate)[:400], "local": lerr[:300]}})


@mcp.tool()
def vault_health() -> str:
    """Probe gate LAN/tunnel /health, local snapshot readability, circuit-breaker
    state, and the local (redacted) audit-mirror queue depth."""
    out = {}
    for name, (url, _tmo) in [("gate_lan", GATE_ENDPOINTS[0]),
                              ("gate_tunnel", GATE_ENDPOINTS[1])]:
        hurl = url.replace("/sdk/invoke", "/health")
        t0 = time.time()
        try:
            r = httpx.get(hurl, timeout=6)
            out[name] = {"up": r.status_code == 200, "ms": int((time.time() - t0) * 1000)}
        except Exception as e:
            out[name] = {"up": False, "error": f"{type(e).__name__}: {str(e)[:120]}"}
    try:
        with _snapshot() as c:
            n = c.execute("SELECT count(*) FROM credentials").fetchone()[0]
        out["local_snapshot"] = {"up": True, "path": str(VAULT_DB), "credentials": n}
    except Exception as e:
        out["local_snapshot"] = {"up": False, "path": str(VAULT_DB),
                                 "error": f"{type(e).__name__}: {str(e)[:120]}"}
    out["circuit_breaker"] = {
        url: {"open": _cb_open(url), "consecutive_fails": _cb.get(url, {}).get("fails", 0)}
        for url, _t in GATE_ENDPOINTS}
    try:
        with _db_lock, _db() as c:
            out["local_pending_audit_mirrors"] = c.execute(
                "SELECT count(*) FROM pending_writes").fetchone()[0]
    except Exception as e:
        out["local_pending_audit_mirrors"] = f"error: {str(e)[:120]}"
    out["hmac_secret_loaded"] = bool(HMAC_SECRET_HEX)
    out["sovereign_key_loaded"] = bool(SOVEREIGN_KEY)
    gate_up = out.get("gate_lan", {}).get("up") or out.get("gate_tunnel", {}).get("up")
    local_up = out.get("local_snapshot", {}).get("up")
    out["verdict"] = ("all_green" if gate_up and local_up
                      else "degraded_but_functional" if gate_up or local_up
                      else "offline")
    if not gate_up and local_up:
        out["note"] = "reads served from local snapshot; vault_put unavailable until gate returns"
    return json.dumps(out)


if __name__ == "__main__":
    log(f"starting (gate={GATE_ENDPOINTS[0][0]}, ssh={SSH_HOST}, "
        f"snapshot={VAULT_DB}, seat={SEAT})")
    if not SOVEREIGN_KEY:
        log("WARNING: ECHO_SOVEREIGN_KEY not set - gate tier disabled, local snapshot reads only")
    mcp.run()
