from __future__ import annotations

import base64
import json
import os
import sqlite3

import pytest
from conftest import VaultHarness

from echo_vault.auth import sign_headers
from echo_vault.crypto import KeyRing


@pytest.mark.asyncio
async def test_health_readiness_and_security_headers(vault: VaultHarness) -> None:
    health = await vault.client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.headers["cache-control"].startswith("no-store")
    assert health.headers["x-content-type-options"] == "nosniff"

    ready = await vault.client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}


@pytest.mark.asyncio
async def test_create_get_update_list_delete_journey(vault: VaultHarness) -> None:
    created = await vault.request(
        "POST",
        "/v1/secrets/demo/database-password",
        payload={
            "secret": "synthetic-v1",
            "username": "service-user",
            "metadata": {"owner": "integration-test"},
            "tags": ["Database", "test"],
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["version"] == 1

    read = await vault.request("GET", "/v1/secrets/demo/database-password")
    assert read.status_code == 200, read.text
    assert read.json()["secret"] == "synthetic-v1"
    assert read.json()["tags"] == ["database", "test"]
    assert read.headers["cache-control"].startswith("no-store")

    listed = await vault.request("GET", "/v1/secrets", query={"namespace": "demo"})
    assert listed.status_code == 200, listed.text
    assert listed.json()[0]["name"] == "database-password"
    assert "secret" not in listed.text

    updated = await vault.request(
        "PATCH",
        "/v1/secrets/demo/database-password",
        payload={
            "secret": "synthetic-v2",
            "username": "service-user",
            "metadata": {},
            "tags": ["database"],
            "expected_version": 1,
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["version"] == 2

    stale = await vault.request(
        "PATCH",
        "/v1/secrets/demo/database-password",
        payload={
            "secret": "must-not-land",
            "metadata": {},
            "tags": [],
            "expected_version": 1,
        },
    )
    assert stale.status_code == 409

    versions = await vault.request("GET", "/v1/secrets/demo/database-password/versions")
    assert versions.status_code == 200
    assert [row["version"] for row in versions.json()] == [2, 1]

    deleted = await vault.request(
        "DELETE",
        "/v1/secrets/demo/database-password",
        payload={"expected_version": 2},
    )
    assert deleted.status_code == 200, deleted.text
    missing = await vault.request("GET", "/v1/secrets/demo/database-password")
    assert missing.status_code == 404

    audit = await vault.request("GET", "/v1/audit/verify")
    assert audit.status_code == 200
    assert audit.json()["valid"] is True
    assert audit.json()["events"] >= 6


@pytest.mark.asyncio
async def test_database_never_contains_plaintext(vault: VaultHarness) -> None:
    marker = "marker-that-must-never-appear-in-the-database"
    response = await vault.request(
        "POST",
        "/v1/secrets/demo/encrypted",
        payload={"secret": marker, "metadata": {"private": marker}, "tags": []},
    )
    assert response.status_code == 201
    raw = vault.settings.database_path.read_bytes()
    assert marker.encode() not in raw


@pytest.mark.asyncio
async def test_exact_signature_and_replay_rejection(vault: VaultHarness) -> None:
    nonce = "a" * 32
    first = await vault.request(
        "POST",
        "/v1/secrets/demo/replay",
        payload={"secret": "synthetic", "metadata": {}, "tags": []},
        nonce=nonce,
    )
    assert first.status_code == 201
    replay = await vault.request(
        "POST",
        "/v1/secrets/demo/replay-two",
        payload={"secret": "synthetic", "metadata": {}, "tags": []},
        nonce=nonce,
    )
    assert replay.status_code == 409

    path = "/v1/secrets/demo/tampered-request"
    signed_body = b'{"secret":"signed","metadata":{},"tags":[]}'
    changed_body = b'{"secret":"changed","metadata":{},"tags":[]}'
    headers = sign_headers(vault.client_id, vault.secret, "POST", path, body=signed_body)
    headers["Content-Type"] = "application/json"
    tampered = await vault.client.post(path, headers=headers, content=changed_body)
    assert tampered.status_code == 401


@pytest.mark.asyncio
async def test_rekey_preserves_plaintext_and_changes_key_id(vault: VaultHarness) -> None:
    created = await vault.request(
        "POST",
        "/v1/secrets/demo/rekey-me",
        payload={"secret": "synthetic", "metadata": {}, "tags": []},
    )
    assert created.status_code == 201
    assert created.json()["key_id"] == "key-1"

    ring_data = json.loads(vault.settings.keys_file.read_text())
    ring_data["keys"]["key-2"] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    vault.settings.keys_file.write_text(json.dumps(ring_data))
    vault.app.state.store.keyring = KeyRing.load(vault.settings.keys_file)

    rekeyed = await vault.request("POST", "/v1/admin/rekey/key-2")
    assert rekeyed.status_code == 200, rekeyed.text
    assert rekeyed.json()["versions_rekeyed"] == 1

    with sqlite3.connect(vault.settings.database_path) as db:
        key_ids = {row[0] for row in db.execute("SELECT key_id FROM secret_versions")}
    assert key_ids == {"key-2"}
    read = await vault.request("GET", "/v1/secrets/demo/rekey-me")
    assert read.status_code == 200
    assert read.json()["secret"] == "synthetic"


@pytest.mark.asyncio
async def test_oversized_body_is_rejected_before_parsing(vault: VaultHarness) -> None:
    response = await vault.request(
        "POST",
        "/v1/secrets/demo/oversized",
        body_override=b"{" + b"x" * 5_000 + b"}",
    )
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_ciphertext_and_audit_tampering_fail_closed(vault: VaultHarness) -> None:
    created = await vault.request(
        "POST",
        "/v1/secrets/demo/tamper",
        payload={"secret": "synthetic", "metadata": {}, "tags": []},
    )
    assert created.status_code == 201

    with sqlite3.connect(vault.settings.database_path) as db:
        row = db.execute("SELECT id, ciphertext_b64 FROM secret_versions LIMIT 1").fetchone()
        changed = row[1][:-1] + ("A" if row[1][-1] != "A" else "B")
        db.execute("UPDATE secret_versions SET ciphertext_b64=? WHERE id=?", (changed, row[0]))
        db.commit()
    broken = await vault.request("GET", "/v1/secrets/demo/tamper")
    assert broken.status_code == 503

    with sqlite3.connect(vault.settings.database_path) as db:
        db.execute("UPDATE audit_events SET outcome='forged' WHERE id=1")
        db.commit()
    ready = await vault.client.get("/readyz")
    assert ready.status_code == 503
    audit = await vault.request("GET", "/v1/audit/verify")
    assert audit.status_code == 200
    assert audit.json()["valid"] is False
    assert audit.json()["first_bad_event_id"] == 1
