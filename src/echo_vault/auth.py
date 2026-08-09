"""Scoped HMAC request authentication, replay rejection, and rate limiting."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fastapi import HTTPException, Request, status

from .config import Settings

_CLIENT_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{20,120}$")
_DUMMY_SECRET = b"\x00" * 32


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64url value") from exc


def canonical_request(
    method: str, path: str, query: str, body: bytes, timestamp: str, nonce: str
) -> bytes:
    body_digest = hashlib.sha256(body).hexdigest()
    return "\n".join(
        ("echo-vault-hmac-v1", method.upper(), path, query, body_digest, timestamp, nonce)
    ).encode()


class NonceStore(Protocol):
    async def claim_nonce(self, client_id: str, nonce: str, expires_at: int) -> bool: ...

    async def record_security_event(
        self,
        *,
        actor: str,
        action: str,
        outcome: str,
        details: dict[str, str | int | bool] | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class Principal:
    client_id: str
    secret: bytes
    scopes: frozenset[str]
    namespaces: frozenset[str]

    def allows(self, scope: str, namespace: str | None) -> bool:
        if scope not in self.scopes and "admin" not in self.scopes:
            return False
        if namespace is None:
            return True
        return "*" in self.namespaces or namespace in self.namespaces


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class ClientRegistry:
    def __init__(self, clients: dict[str, Principal]):
        self.clients = clients

    @classmethod
    def load(cls, path: Path) -> ClientRegistry:
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError(f"client manifest permissions are too broad: {path}")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("client manifest is unreadable") from exc
        entries = raw.get("clients") if isinstance(raw, dict) else None
        if not isinstance(entries, list) or not entries:
            raise ValueError("client manifest must contain at least one client")
        clients: dict[str, Principal] = {}
        allowed_scopes = {"read", "write", "delete", "audit", "admin"}
        for row in entries:
            if not isinstance(row, dict):
                raise ValueError("client entry must be an object")
            client_id = row.get("id")
            if not isinstance(client_id, str) or not _CLIENT_ID.fullmatch(client_id):
                raise ValueError("client id is invalid")
            if client_id in clients:
                raise ValueError("client ids must be unique")
            encoded_secret = row.get("secret")
            if not isinstance(encoded_secret, str):
                raise ValueError("client secret is required")
            secret = _b64decode(encoded_secret)
            if len(secret) < 32:
                raise ValueError("client secret must contain at least 32 bytes")
            scopes = row.get("scopes")
            namespaces = row.get("namespaces")
            if not isinstance(scopes, list) or not set(scopes) <= allowed_scopes:
                raise ValueError("client scopes are invalid")
            if not isinstance(namespaces, list) or not all(
                isinstance(item, str) and item for item in namespaces
            ):
                raise ValueError("client namespaces are invalid")
            clients[client_id] = Principal(
                client_id=client_id,
                secret=secret,
                scopes=frozenset(scopes),
                namespaces=frozenset(namespaces),
            )
        return cls(clients)


class Authenticator:
    def __init__(self, registry: ClientRegistry, settings: Settings):
        self.registry = registry
        self.settings = settings
        self._buckets: dict[str, _Bucket] = {}

    def _consume(self, client_id: str) -> None:
        now = time.monotonic()
        bucket = self._buckets.get(client_id)
        if bucket is None:
            bucket = _Bucket(float(self.settings.rate_capacity), now)
            self._buckets[client_id] = bucket
        elapsed = max(0.0, now - bucket.updated)
        bucket.tokens = min(
            float(self.settings.rate_capacity),
            bucket.tokens + elapsed * self.settings.rate_refill_per_second,
        )
        bucket.updated = now
        if bucket.tokens < 1:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded")
        bucket.tokens -= 1

    async def verify(
        self,
        request: Request,
        nonce_store: NonceStore,
        *,
        scope: str,
        namespace: str | None,
    ) -> Principal:
        client_id = request.headers.get("x-vault-client", "")
        timestamp_raw = request.headers.get("x-vault-timestamp", "")
        nonce = request.headers.get("x-vault-nonce", "")
        supplied_signature = request.headers.get("x-vault-signature", "")
        client_id_valid = _CLIENT_ID.fullmatch(client_id) is not None
        nonce_valid = _NONCE.fullmatch(nonce) is not None
        principal = self.registry.clients.get(client_id) if client_id_valid else None
        try:
            timestamp = int(timestamp_raw)
        except ValueError:
            timestamp = 0
        timestamp_valid = abs(int(time.time()) - timestamp) <= self.settings.timestamp_skew_seconds
        body = await request.body()
        canonical = canonical_request(
            request.method,
            request.url.path,
            request.url.query,
            body,
            timestamp_raw,
            nonce,
        )
        signing_secret = principal.secret if principal is not None else _DUMMY_SECRET
        expected = _b64encode(hmac.new(signing_secret, canonical, hashlib.sha256).digest())
        signature_valid = hmac.compare_digest(expected, supplied_signature)
        if not all(
            (client_id_valid, nonce_valid, timestamp_valid, principal is not None, signature_valid)
        ):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid authentication")

        assert principal is not None
        self._consume(client_id)
        receipt_time = int(time.time())
        expires_at = max(
            receipt_time + self.settings.nonce_ttl_seconds,
            timestamp + self.settings.timestamp_skew_seconds + 1,
        )
        if not await nonce_store.claim_nonce(client_id, nonce, expires_at):
            await nonce_store.record_security_event(
                actor=client_id,
                action="auth.replay_rejected",
                outcome="denied",
                details={"scope": scope, "namespace_present": namespace is not None},
            )
            raise HTTPException(status.HTTP_409_CONFLICT, "request replay rejected")
        if not principal.allows(scope, namespace):
            await nonce_store.record_security_event(
                actor=client_id,
                action="auth.scope_denied",
                outcome="denied",
                details={"scope": scope, "namespace_present": namespace is not None},
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "scope denied")
        return principal


def sign_headers(
    client_id: str,
    secret: bytes,
    method: str,
    path: str,
    *,
    query: str = "",
    body: bytes = b"",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    timestamp_raw = str(timestamp if timestamp is not None else int(time.time()))
    nonce_value = nonce or _b64encode(os.urandom(24))
    canonical = canonical_request(method, path, query, body, timestamp_raw, nonce_value)
    signature = _b64encode(hmac.new(secret, canonical, hashlib.sha256).digest())
    return {
        "X-Vault-Client": client_id,
        "X-Vault-Timestamp": timestamp_raw,
        "X-Vault-Nonce": nonce_value,
        "X-Vault-Signature": signature,
    }


def create_client_manifest(path: Path) -> str:
    """Create a local admin client manifest and return its one-time secret."""
    path.parent.mkdir(parents=True, exist_ok=True)
    secret = os.urandom(32)
    body = {
        "format": 1,
        "clients": [
            {
                "id": "local-admin",
                "secret": _b64encode(secret),
                "scopes": ["read", "write", "delete", "audit", "admin"],
                "namespaces": ["*"],
            }
        ],
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(body, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return _b64encode(secret)


def decode_client_secret(value: str) -> bytes:
    secret = _b64decode(value)
    if len(secret) < 32:
        raise ValueError("client secret must contain at least 32 bytes")
    return secret
