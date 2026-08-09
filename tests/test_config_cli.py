from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from echo_vault import cli
from echo_vault.config import Settings


def test_nonce_retention_must_cover_complete_timestamp_window(tmp_path: Path) -> None:
    settings = Settings(
        "test",
        tmp_path / "data",
        tmp_path / "keys.json",
        tmp_path / "clients.json",
        timestamp_skew_seconds=90,
        nonce_ttl_seconds=179,
    )
    with pytest.raises(ValueError, match="at least twice"):
        settings.validate()


def test_cli_rejects_remote_plaintext_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ECHO_VAULT_URL", "http://vault.example.test:8080")
    monkeypatch.delenv("ECHO_VAULT_ALLOW_INSECURE_HTTP", raising=False)
    with pytest.raises(SystemExit, match="must use HTTPS"):
        cli._base_url()

    monkeypatch.setenv("ECHO_VAULT_URL", "http://127.0.0.1:8080")
    assert cli._base_url() == "http://127.0.0.1:8080"

    monkeypatch.setenv("ECHO_VAULT_URL", "https://vault.example.test")
    assert cli._base_url() == "https://vault.example.test"


def test_init_keeps_bootstrap_secret_out_of_stdout_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "runtime"
    args = type("Args", (), {"directory": str(target), "print_client_secret": False})()
    cli.command_init(args)
    output = capsys.readouterr().out
    secret_file = target / "bootstrap-client.secret"
    secret = secret_file.read_text(encoding="utf-8").strip()

    assert secret
    assert secret not in output
    assert str(secret_file) in output
    if os.name == "posix":
        assert stat.S_IMODE(secret_file.stat().st_mode) == 0o600


def test_private_output_refuses_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "secret.txt"
    cli._write_private(destination, "synthetic")
    with pytest.raises(FileExistsError):
        cli._write_private(destination, "replacement")
    assert destination.read_text(encoding="utf-8").strip() == "synthetic"
