from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from echo_vault.crypto import Envelope, KeyRing, VaultCryptoError, create_key_ring


def test_envelope_round_trip_and_context_binding(tmp_path: Path) -> None:
    ring = create_key_ring(tmp_path / "keys.json")
    envelope = ring.encrypt(
        {"secret": "synthetic", "metadata": {"purpose": "test"}},
        secret_id=7,
        namespace="demo",
        name="database",
        version=3,
    )
    payload = ring.decrypt(envelope, secret_id=7, namespace="demo", name="database", version=3)
    assert payload["secret"] == "synthetic"

    for changed in (
        {"secret_id": 8, "namespace": "demo", "name": "database", "version": 3},
        {"secret_id": 7, "namespace": "other", "name": "database", "version": 3},
        {"secret_id": 7, "namespace": "demo", "name": "other", "version": 3},
        {"secret_id": 7, "namespace": "demo", "name": "database", "version": 4},
    ):
        with pytest.raises(VaultCryptoError, match="authentication failed"):
            ring.decrypt(envelope, **changed)


def test_ciphertext_tamper_is_rejected(tmp_path: Path) -> None:
    ring = create_key_ring(tmp_path / "keys.json")
    envelope = ring.encrypt(
        {"secret": "synthetic"}, secret_id=1, namespace="demo", name="api", version=1
    )
    raw = bytearray(base64.urlsafe_b64decode(envelope.ciphertext + "=="))
    raw[-1] ^= 1
    tampered = Envelope(
        envelope.key_id,
        envelope.nonce,
        base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("="),
    )
    with pytest.raises(VaultCryptoError, match="authentication failed"):
        ring.decrypt(tampered, secret_id=1, namespace="demo", name="api", version=1)


def test_key_ids_are_versioned(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    create_key_ring(path)
    body = json.loads(path.read_text())
    body["keys"]["key-2"] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    body["active_key_id"] = "key-2"
    path.write_text(json.dumps(body))
    ring = KeyRing.load(path)
    envelope = ring.encrypt(
        {"secret": "synthetic"}, secret_id=1, namespace="demo", name="api", version=1
    )
    assert envelope.key_id == "key-2"
    assert set(ring.keys) == {"key-1", "key-2"}
