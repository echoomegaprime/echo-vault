"""Versioned AES-256-GCM envelopes bound to immutable record context."""

from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultCryptoError(RuntimeError):
    """Raised when key material or ciphertext cannot be safely used."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultCryptoError("invalid base64url value") from exc


def _assert_private_file(path: Path) -> None:
    if os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise VaultCryptoError(f"secret file permissions are too broad: {path}")


def _aad(secret_id: int, namespace: str, name: str, version: int) -> bytes:
    context = {
        "format": "echo-vault-envelope-v1",
        "secret_id": secret_id,
        "namespace": namespace,
        "name": name,
        "version": version,
    }
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True, slots=True)
class Envelope:
    key_id: str
    nonce: str
    ciphertext: str


@dataclass(frozen=True, slots=True)
class KeyRing:
    active_key_id: str
    keys: dict[str, bytes]
    audit_key: bytes

    @classmethod
    def load(cls, path: Path) -> KeyRing:
        _assert_private_file(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VaultCryptoError("key ring is unreadable") from exc
        if not isinstance(raw, dict) or not isinstance(raw.get("keys"), dict):
            raise VaultCryptoError("key ring schema is invalid")
        active = raw.get("active_key_id")
        if not isinstance(active, str) or not active:
            raise VaultCryptoError("active_key_id is required")
        keys: dict[str, bytes] = {}
        for key_id, encoded in raw["keys"].items():
            if not isinstance(key_id, str) or not isinstance(encoded, str):
                raise VaultCryptoError("key ring entries must be strings")
            key = _b64decode(encoded)
            if len(key) != 32:
                raise VaultCryptoError("every encryption key must contain 32 bytes")
            keys[key_id] = key
        if active not in keys:
            raise VaultCryptoError("active_key_id is not present in keys")
        audit_key_raw = raw.get("audit_key")
        if not isinstance(audit_key_raw, str):
            raise VaultCryptoError("audit_key is required")
        audit_key = _b64decode(audit_key_raw)
        if len(audit_key) != 32:
            raise VaultCryptoError("audit_key must contain 32 bytes")
        return cls(active_key_id=active, keys=keys, audit_key=audit_key)

    def encrypt(
        self,
        payload: dict[str, Any],
        *,
        secret_id: int,
        namespace: str,
        name: str,
        version: int,
        key_id: str | None = None,
    ) -> Envelope:
        selected_id = key_id or self.active_key_id
        key = self.keys.get(selected_id)
        if key is None:
            raise VaultCryptoError("requested key is not loaded")
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ciphertext = AESGCM(key).encrypt(
            nonce, plaintext, _aad(secret_id, namespace, name, version)
        )
        return Envelope(selected_id, _b64encode(nonce), _b64encode(ciphertext))

    def decrypt(
        self,
        envelope: Envelope,
        *,
        secret_id: int,
        namespace: str,
        name: str,
        version: int,
    ) -> dict[str, Any]:
        key = self.keys.get(envelope.key_id)
        if key is None:
            raise VaultCryptoError("ciphertext references an unavailable key")
        try:
            plaintext = AESGCM(key).decrypt(
                _b64decode(envelope.nonce),
                _b64decode(envelope.ciphertext),
                _aad(secret_id, namespace, name, version),
            )
            decoded = json.loads(plaintext)
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultCryptoError("ciphertext authentication failed") from exc
        if not isinstance(decoded, dict) or not isinstance(decoded.get("secret"), str):
            raise VaultCryptoError("decrypted payload schema is invalid")
        return decoded


def create_key_ring(path: Path) -> KeyRing:
    """Create a new key ring without overwriting existing material."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "format": 1,
        "active_key_id": "key-1",
        "keys": {"key-1": _b64encode(os.urandom(32))},
        "audit_key": _b64encode(os.urandom(32)),
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(body, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return KeyRing.load(path)
