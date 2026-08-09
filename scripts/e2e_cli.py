#!/usr/bin/env python3
"""Exercise the installed CLI against a real ECHO Vault server process."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _run_cli(
    arguments: list[str],
    env: dict[str, str],
    *,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(  # noqa: S603 - fixed interpreter, module, and test-owned args
        [sys.executable, "-m", "echo_vault.cli", *arguments],
        check=False,
        capture_output=True,
        text=True,
        input=stdin,
        env=env,
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"CLI failed ({' '.join(arguments)}):\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def _wait_until_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited before readiness with code {process.returncode}")
        try:
            response = httpx.get(f"{base_url}/readyz", timeout=0.5)
            if response.status_code == 200 and response.json() == {"status": "ready"}:
                return
        except (httpx.HTTPError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError("server did not become ready within 20 seconds")


def _assert_secret_absent(value: str, *outputs: str) -> None:
    if any(value in output for output in outputs):
        raise AssertionError("a synthetic secret appeared in CLI process output")


def run_journey() -> dict[str, object]:
    port = _free_loopback_port()
    base_url = f"http://127.0.0.1:{port}"

    with tempfile.TemporaryDirectory(prefix="echo-vault-e2e-") as raw_directory:
        root = Path(raw_directory)
        runtime = root / "runtime"
        env = os.environ.copy()

        initialized = _run_cli(["init", "--directory", str(runtime)], env)
        bootstrap_secret_file = runtime / "bootstrap-client.secret"
        client_secret = bootstrap_secret_file.read_text(encoding="utf-8").strip()
        if not client_secret or client_secret in initialized.stdout:
            raise AssertionError("bootstrap secret was empty or leaked during initialization")

        env.update(
            {
                "ECHO_VAULT_ENV": "test",
                "ECHO_VAULT_HOST": "127.0.0.1",
                "ECHO_VAULT_PORT": str(port),
                "ECHO_VAULT_DATA_DIR": str(runtime / "data"),
                "ECHO_VAULT_KEYS_FILE": str(runtime / "keys.json"),
                "ECHO_VAULT_CLIENTS_FILE": str(runtime / "clients.json"),
                "ECHO_VAULT_CLIENT_ID": "local-admin",
                "ECHO_VAULT_CLIENT_SECRET": client_secret,
                "ECHO_VAULT_URL": base_url,
            }
        )

        server = subprocess.Popen(  # noqa: S603 - fixed local module invocation
            [sys.executable, "-m", "echo_vault.cli", "serve"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_until_ready(base_url, server)

            first_value = "cli-e2e-synthetic-v1"
            second_value = "cli-e2e-synthetic-v2"
            put = _run_cli(
                ["put", "demo", "cli-journey", "--stdin", "--tag", "E2E"],
                env,
                stdin=first_value,
            )
            if json.loads(put.stdout)["version"] != 1:
                raise AssertionError("create did not return version 1")

            listed = _run_cli(["list", "demo"], env)
            inventory = json.loads(listed.stdout)
            if len(inventory) != 1 or inventory[0]["name"] != "cli-journey":
                raise AssertionError("inventory did not contain the synthetic secret metadata")

            first_output = root / "first-secret.txt"
            fetched = _run_cli(["get", "demo", "cli-journey", "--output", str(first_output)], env)
            if first_output.read_text(encoding="utf-8").strip() != first_value:
                raise AssertionError("first retrieved value did not match")

            updated = _run_cli(
                [
                    "update",
                    "demo",
                    "cli-journey",
                    "--expected-version",
                    "1",
                    "--stdin",
                ],
                env,
                stdin=second_value,
            )
            if json.loads(updated.stdout)["version"] != 2:
                raise AssertionError("update did not return version 2")

            second_output = root / "second-secret.txt"
            fetched_again = _run_cli(
                ["get", "demo", "cli-journey", "--output", str(second_output)], env
            )
            if second_output.read_text(encoding="utf-8").strip() != second_value:
                raise AssertionError("updated retrieved value did not match")

            audit = _run_cli(["audit"], env)
            audit_result = json.loads(audit.stdout)
            if audit_result.get("valid") is not True or audit_result.get("events", 0) < 3:
                raise AssertionError("deep audit verification did not pass")

            deleted = _run_cli(["delete", "demo", "cli-journey", "--expected-version", "2"], env)
            if not json.loads(deleted.stdout).get("deleted_at"):
                raise AssertionError("delete did not report its completion timestamp")

            final_inventory = json.loads(_run_cli(["list", "demo"], env).stdout)
            if final_inventory:
                raise AssertionError("deleted secret remained in the active inventory")

            visible_outputs = (
                put.stdout,
                put.stderr,
                listed.stdout,
                fetched.stdout,
                fetched_again.stdout,
                updated.stdout,
                audit.stdout,
                deleted.stdout,
            )
            _assert_secret_absent(first_value, *visible_outputs)
            _assert_secret_absent(second_value, *visible_outputs)
            database = (runtime / "data" / "vault.db").read_bytes()
            if first_value.encode() in database or second_value.encode() in database:
                raise AssertionError("plaintext secret appeared in the database")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            server.__exit__(None, None, None)

        return {
            "audit_events": audit_result["events"],
            "database_plaintext_absent": True,
            "journey": "init-put-list-get-update-get-audit-delete-list",
            "secret_process_output_absent": True,
            "status": "pass",
        }


def main() -> None:
    print(json.dumps(run_journey(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
