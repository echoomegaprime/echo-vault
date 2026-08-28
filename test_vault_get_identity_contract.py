"""Fail-closed identity tests for the echo-vault exact-key read boundary."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "echo_vault_identity_server", HERE / "server.py"
)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


def test_exact_gate_identity_is_accepted(monkeypatch):
    monkeypatch.setattr(
        server,
        "gate_invoke_signed",
        lambda *_args: (
            {
                "service": "texasfile",
                "username": "email",
                "secret": "synthetic-exact",
            },
            "",
        ),
    )
    monkeypatch.setattr(
        server,
        "snapshot_get",
        lambda *_args: (_ for _ in ()).throw(AssertionError("no fallback expected")),
    )

    result = json.loads(server.vault_get("texasfile", "email"))

    assert result == {
        "ok": True,
        "service": "texasfile",
        "username": "email",
        "secret": "synthetic-exact",
        "source": "gate",
    }


def test_wrong_gate_username_falls_back_to_exact_snapshot(monkeypatch):
    monkeypatch.setattr(
        server,
        "gate_invoke_signed",
        lambda *_args: (
            {
                "service": "texasfile",
                "username": "password",
                "secret": "synthetic-wrong-row",
            },
            "",
        ),
    )
    monkeypatch.setattr(
        server,
        "snapshot_get",
        lambda service, username: (
            {
                "service": service,
                "username": username,
                "secret": "synthetic-exact-local",
            },
            None,
        ),
    )

    result = json.loads(server.vault_get("texasfile", "email"))

    assert result["ok"] is True
    assert result["source"] == "local"
    assert result["username"] == "email"
    assert result["secret"] == "synthetic-exact-local"
    assert "identity mismatch" in result["gate_error"]


def test_missing_gate_identity_falls_back_instead_of_guessing(monkeypatch):
    monkeypatch.setattr(
        server,
        "gate_invoke_signed",
        lambda *_args: ({"secret": "synthetic-unidentified"}, ""),
    )
    monkeypatch.setattr(server, "snapshot_get", lambda *_args: (None, "not found"))

    result = json.loads(server.vault_get("texasfile", "email"))

    assert result["ok"] is False
    assert result["username"] == "email"
    assert "identity mismatch" in result["errors"]["gate"]
