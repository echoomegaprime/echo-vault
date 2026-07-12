#!/usr/bin/env python3
"""
Standalone smoke test for the echo-vault MCP server.

Imports the tool functions straight from server.py (no MCP transport needed)
and exercises vault_health + vault_list + a vault_get for a known harmless
service. Secret values are MASKED before printing - this script never puts a
raw secret on stdout.

Usage:
    python test_client.py [service] [username]     # default service: cloudflare_tunnel_id
Exit 0 = health answered AND at least one of list/get succeeded.
"""

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("echo_vault_server", HERE / "server.py")
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)


def mask(secret: str) -> str:
    if not isinstance(secret, str) or not secret:
        return "(empty)"
    head = secret[:4] if len(secret) > 8 else ""
    return f"{head}{'*' * 8} (len={len(secret)})"


def show(name: str, raw: str) -> dict:
    try:
        data = json.loads(raw)
    except Exception:
        print(f"\n== {name} ==\nUNPARSEABLE: {raw[:300]}")
        return {}
    if isinstance(data, dict) and isinstance(data.get("secret"), str):
        data["secret"] = mask(data["secret"])
    print(f"\n== {name} ==")
    print(json.dumps(data, indent=2, default=str)[:2500])
    return data


def main() -> int:
    # harmless probe credential, present in both the canonical vault and the
    # local snapshot - keeps the smoke green even during a gate outage
    service = sys.argv[1] if len(sys.argv) > 1 else "cloudflare_tunnel_id"
    username = sys.argv[2] if len(sys.argv) > 2 else ""

    health = show("vault_health", srv.vault_health())
    listing = show("vault_list(prefix='cloud')", srv.vault_list("cloud"))
    got = show(f"vault_get({service!r}, {username!r})", srv.vault_get(service, username))

    health_ok = bool(health) and "verdict" in health
    list_ok = bool(listing.get("ok"))
    get_ok = bool(got.get("ok"))

    print(f"\nverdict={health.get('verdict')}  list_ok={list_ok}  get_ok={get_ok} "
          f"(get via {got.get('source', '-')})")
    if health_ok and (list_ok or get_ok):
        print("SMOKE: PASSED")
        return 0
    print("SMOKE: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
