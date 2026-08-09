from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import httpx
import pytest

from echo_vault.app import create_app
from echo_vault.auth import canonical_request, sign_headers
from echo_vault.config import Settings
from echo_vault.crypto import create_key_ring


@pytest.mark.asyncio
async def test_namespace_and_action_scopes_are_enforced(tmp_path: Path) -> None:
    keys = tmp_path / "keys.json"
    clients = tmp_path / "clients.json"
    create_key_ring(keys)
    secret = os.urandom(32)
    clients.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "id": "demo-reader",
                        "secret": base64.urlsafe_b64encode(secret).decode().rstrip("="),
                        "scopes": ["read"],
                        "namespaces": ["demo"],
                    }
                ]
            }
        )
    )
    clients.chmod(0o600)
    settings = Settings("test", tmp_path / "data", keys, clients)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            path = "/v1/secrets/demo/value"
            headers = sign_headers("demo-reader", secret, "GET", path)
            allowed = await client.get(path, headers=headers)
            assert allowed.status_code == 404

            denied_path = "/v1/secrets/private/value"
            denied_headers = sign_headers("demo-reader", secret, "GET", denied_path)
            denied = await client.get(denied_path, headers=denied_headers)
            assert denied.status_code == 403

            body = b'{"secret":"synthetic","metadata":{},"tags":[]}'
            write_headers = sign_headers("demo-reader", secret, "POST", path, body=body)
            write_headers["Content-Type"] = "application/json"
            write = await client.post(path, headers=write_headers, content=body)
            assert write.status_code == 403


@pytest.mark.asyncio
async def test_invalid_signature_cannot_exhaust_client_budget_or_probe_scope(
    tmp_path: Path,
) -> None:
    keys = tmp_path / "keys.json"
    clients = tmp_path / "clients.json"
    create_key_ring(keys)
    secret = os.urandom(32)
    clients.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "id": "single-use-reader",
                        "secret": base64.urlsafe_b64encode(secret).decode().rstrip("="),
                        "scopes": ["read"],
                        "namespaces": ["demo"],
                    }
                ]
            }
        )
    )
    clients.chmod(0o600)
    settings = Settings(
        "test",
        tmp_path / "data",
        keys,
        clients,
        rate_capacity=1,
        rate_refill_per_second=1,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            allowed_path = "/v1/secrets/demo/value"
            bad = sign_headers("single-use-reader", secret, "GET", allowed_path)
            bad["X-Vault-Signature"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
            invalid_allowed = await client.get(allowed_path, headers=bad)
            assert invalid_allowed.status_code == 401

            denied_path = "/v1/secrets/private/value"
            bad_denied = sign_headers("single-use-reader", secret, "GET", denied_path)
            bad_denied["X-Vault-Signature"] = base64.urlsafe_b64encode(os.urandom(32)).decode()
            invalid_denied = await client.get(denied_path, headers=bad_denied)
            assert invalid_denied.status_code == 401
            assert invalid_denied.json() == invalid_allowed.json()

            valid = sign_headers("single-use-reader", secret, "GET", allowed_path)
            response = await client.get(allowed_path, headers=valid)
            assert response.status_code == 404


def test_canonical_request_is_exact_byte_bound() -> None:
    left = canonical_request("POST", "/v1/test", "a=1", b'{"v":1}', "1", "n" * 20)
    right = canonical_request("POST", "/v1/test", "a=1", b'{"v":2}', "1", "n" * 20)
    assert left != right
