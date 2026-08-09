from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest

from echo_vault.app import create_app
from echo_vault.auth import create_client_manifest, decode_client_secret, sign_headers
from echo_vault.config import Settings
from echo_vault.crypto import create_key_ring


@dataclass
class VaultHarness:
    client: httpx.AsyncClient
    app: Any
    settings: Settings
    client_id: str
    secret: bytes

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: object | None = None,
        query: dict[str, str] | None = None,
        nonce: str | None = None,
        body_override: bytes | None = None,
    ) -> httpx.Response:
        query_string = urlencode(query or {})
        body = (
            body_override
            if body_override is not None
            else (
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                if payload is not None
                else b""
            )
        )
        headers = sign_headers(
            self.client_id,
            self.secret,
            method,
            path,
            query=query_string,
            body=body,
            nonce=nonce,
        )
        if body:
            headers["Content-Type"] = "application/json"
        target = path + (f"?{query_string}" if query_string else "")
        return await self.client.request(method, target, headers=headers, content=body or None)


@pytest.fixture
async def vault(tmp_path: Path) -> AsyncIterator[VaultHarness]:
    keys = tmp_path / "keys.json"
    clients = tmp_path / "clients.json"
    create_key_ring(keys)
    encoded_secret = create_client_manifest(clients)
    settings = Settings(
        environment="test",
        data_dir=tmp_path / "data",
        keys_file=keys,
        clients_file=clients,
        max_body_bytes=4_096,
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield VaultHarness(
                client=client,
                app=app,
                settings=settings,
                client_id="local-admin",
                secret=decode_client_secret(encoded_secret),
            )
