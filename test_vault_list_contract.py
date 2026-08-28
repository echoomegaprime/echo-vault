"""Synthetic parity tests for the echo-vault MCP list boundary."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("echo_vault_list_server", HERE / "server.py")
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


@contextmanager
def _synthetic_snapshot() -> Any:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE credentials (service TEXT NOT NULL, username TEXT, secret TEXT)"
    )
    connection.executemany(
        "INSERT INTO credentials VALUES (?,?,?)",
        [
            ("Alpha.One", "one", "synthetic-one"),
            ("alpha.two", "two", "synthetic-two"),
            ("alpha%literal", "three", "synthetic-three"),
            ("beta.one", "four", "synthetic-four"),
        ],
    )
    try:
        yield connection
    finally:
        connection.close()


def test_snapshot_prefix_is_literal_case_insensitive_and_bounded(monkeypatch: Any) -> None:
    monkeypatch.setattr(server, "_snapshot", _synthetic_snapshot)
    rows, error = server.snapshot_list("ALPHA", 5000)
    assert error is None
    assert {row["service"] for row in rows} == {
        "Alpha.One",
        "alpha.two",
        "alpha%literal",
    }
    literal_rows, error = server.snapshot_list("alpha%", 5000)
    assert error is None
    assert [row["service"] for row in literal_rows] == ["alpha%literal"]
    missing, error = server.snapshot_list("definitely-no-such-service-xyz", 5000)
    assert error is None
    assert missing == []


def test_gate_path_forwards_prefix_and_clamps_limit(monkeypatch: Any) -> None:
    seen: list[dict[str, Any]] = []

    def signed(capability: str, params: dict[str, Any]) -> tuple[dict[str, Any], str]:
        seen.append(params)
        return {"credentials": []}, ""

    monkeypatch.setattr(server, "gate_invoke_signed", signed)
    result = json.loads(server.vault_list("alpha", 5000))
    assert result["ok"] is True
    assert result["via"] == "gate"
    assert result["applied"] == {"prefix": "alpha", "limit": 1000}
    assert seen == [{"command": "list", "limit": 1000, "prefix": "alpha"}]


def test_fallback_identifies_local_path_and_uses_same_arguments(monkeypatch: Any) -> None:
    monkeypatch.setattr(server, "gate_invoke_signed", lambda *args: (None, "offline"))
    monkeypatch.setattr(server, "gate_invoke", lambda *args: (None, "offline"))
    seen: list[tuple[str, int]] = []

    def local(prefix: str, limit: int) -> tuple[list[dict[str, str]], None]:
        seen.append((prefix, limit))
        return [{"service": "alpha.one", "username": "synthetic"}], None

    monkeypatch.setattr(server, "snapshot_list", local)
    result = json.loads(server.vault_list("alpha", 5000))
    assert result["ok"] is True
    assert result["via"] == "local"
    assert result["applied"] == {"prefix": "alpha", "limit": 1000}
    assert seen == [("alpha", 1000)]


def test_oversized_prefix_is_rejected_before_dispatch(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        server,
        "gate_invoke_signed",
        lambda *args: (_ for _ in ()).throw(AssertionError("must not dispatch")),
    )
    result = json.loads(server.vault_list("x" * 513, 1))
    assert result == {
        "ok": False,
        "error": "invalid_prefix",
        "hint": "prefix must be at most 512 characters",
    }
