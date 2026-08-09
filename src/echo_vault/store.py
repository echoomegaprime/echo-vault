"""Transactional SQLite store, immutable versions, and tamper-evident audit chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite

from .crypto import Envelope, KeyRing, VaultCryptoError


class VaultConflictError(RuntimeError):
    """Optimistic concurrency or uniqueness conflict."""


class VaultNotFoundError(RuntimeError):
    """Requested secret does not exist or has been deleted."""


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    current_version INTEGER NOT NULL,
    tags_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    UNIQUE(namespace, name)
);

CREATE TABLE IF NOT EXISTS secret_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL,
    key_id TEXT NOT NULL,
    nonce_b64 TEXT NOT NULL,
    ciphertext_b64 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    UNIQUE(secret_id, version)
);

CREATE INDEX IF NOT EXISTS secret_versions_lookup
    ON secret_versions(secret_id, version DESC);

CREATE TABLE IF NOT EXISTS request_nonces (
    client_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(client_id, nonce)
);

CREATE INDEX IF NOT EXISTS request_nonces_expiry
    ON request_nonces(expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    namespace TEXT,
    name TEXT,
    outcome TEXT NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS vault_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class VaultStore:
    def __init__(self, database_path: Path, keyring: KeyRing):
        self.database_path = database_path
        self.keyring = keyring

    @asynccontextmanager
    async def _connection(self) -> AsyncIterator[aiosqlite.Connection]:
        connection = await aiosqlite.connect(self.database_path, timeout=30)
        connection.row_factory = aiosqlite.Row
        try:
            await connection.execute("PRAGMA foreign_keys = ON")
            await connection.execute("PRAGMA busy_timeout = 30000")
            yield connection
        finally:
            await connection.close()

    async def bootstrap(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        async with self._connection() as connection:
            await connection.execute("PRAGMA journal_mode = WAL")
            await connection.execute("PRAGMA synchronous = FULL")
            await connection.executescript(_SCHEMA)
            await connection.execute(
                "INSERT OR IGNORE INTO vault_meta(key, value) VALUES('schema_version', '1')"
            )
            await connection.commit()

    async def ping(self) -> bool:
        async with self._connection() as connection:
            cursor = await connection.execute(
                "SELECT value FROM vault_meta WHERE key='schema_version'"
            )
            row = await cursor.fetchone()
            return row is not None and row[0] == "1"

    async def claim_nonce(self, client_id: str, nonce: str, expires_at: int) -> bool:
        async with self._connection() as connection:
            await connection.execute("BEGIN IMMEDIATE")
            await connection.execute(
                "DELETE FROM request_nonces WHERE expires_at < ?", (int(time.time()),)
            )
            try:
                await connection.execute(
                    "INSERT INTO request_nonces(client_id, nonce, expires_at) VALUES(?, ?, ?)",
                    (client_id, nonce, expires_at),
                )
            except aiosqlite.IntegrityError:
                await connection.rollback()
                return False
            await connection.commit()
            return True

    def _audit_hash(
        self,
        *,
        event_id: int,
        occurred_at: str,
        actor: str,
        action: str,
        namespace: str | None,
        name: str | None,
        outcome: str,
        details_json: str,
        previous_hash: str,
    ) -> str:
        payload = json.dumps(
            {
                "id": event_id,
                "occurred_at": occurred_at,
                "actor": actor,
                "action": action,
                "namespace": namespace,
                "name": name,
                "outcome": outcome,
                "details": json.loads(details_json),
                "previous_hash": previous_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hmac.new(self.keyring.audit_key, payload, hashlib.sha256).hexdigest()

    async def _append_audit(
        self,
        connection: aiosqlite.Connection,
        *,
        actor: str,
        action: str,
        namespace: str | None,
        name: str | None,
        outcome: str,
        details: dict[str, Any] | None = None,
    ) -> int:
        row = await (
            await connection.execute(
                "SELECT id, entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            )
        ).fetchone()
        previous_hash = str(row["entry_hash"]) if row else "0" * 64
        next_id = int(row["id"]) + 1 if row else 1
        occurred_at = now_iso()
        details_json = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        entry_hash = self._audit_hash(
            event_id=next_id,
            occurred_at=occurred_at,
            actor=actor,
            action=action,
            namespace=namespace,
            name=name,
            outcome=outcome,
            details_json=details_json,
            previous_hash=previous_hash,
        )
        cursor = await connection.execute(
            """INSERT INTO audit_events
               (occurred_at, actor, action, namespace, name, outcome, details_json,
                previous_hash, entry_hash)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                occurred_at,
                actor,
                action,
                namespace,
                name,
                outcome,
                details_json,
                previous_hash,
                entry_hash,
            ),
        )
        if int(cursor.lastrowid or 0) != next_id:
            raise RuntimeError("audit sequence changed during append")
        return next_id

    async def create(
        self,
        namespace: str,
        name: str,
        payload: dict[str, Any],
        tags: list[str],
        actor: str,
    ) -> dict[str, Any]:
        timestamp = now_iso()
        async with self._connection() as connection:
            await connection.execute("BEGIN IMMEDIATE")
            existing = await (
                await connection.execute(
                    "SELECT id FROM secrets WHERE namespace=? AND name=?", (namespace, name)
                )
            ).fetchone()
            if existing:
                await connection.rollback()
                raise VaultConflictError("secret already exists")
            cursor = await connection.execute(
                """INSERT INTO secrets
                   (namespace, name, current_version, tags_json, created_at, updated_at)
                   VALUES(?, ?, 1, ?, ?, ?)""",
                (namespace, name, json.dumps(tags), timestamp, timestamp),
            )
            secret_id = int(cursor.lastrowid or 0)
            envelope = self.keyring.encrypt(
                payload,
                secret_id=secret_id,
                namespace=namespace,
                name=name,
                version=1,
            )
            await connection.execute(
                """INSERT INTO secret_versions
                   (secret_id, version, key_id, nonce_b64, ciphertext_b64, created_at, created_by)
                   VALUES(?, 1, ?, ?, ?, ?, ?)""",
                (
                    secret_id,
                    envelope.key_id,
                    envelope.nonce,
                    envelope.ciphertext,
                    timestamp,
                    actor,
                ),
            )
            await self._append_audit(
                connection,
                actor=actor,
                action="secret.create",
                namespace=namespace,
                name=name,
                outcome="success",
                details={"version": 1, "key_id": envelope.key_id},
            )
            await connection.commit()
        return {
            "namespace": namespace,
            "name": name,
            "version": 1,
            "key_id": envelope.key_id,
            "updated_at": timestamp,
        }

    async def update(
        self,
        namespace: str,
        name: str,
        payload: dict[str, Any],
        tags: list[str],
        expected_version: int,
        actor: str,
    ) -> dict[str, Any]:
        timestamp = now_iso()
        async with self._connection() as connection:
            await connection.execute("BEGIN IMMEDIATE")
            row = await (
                await connection.execute(
                    """SELECT id, current_version FROM secrets
                       WHERE namespace=? AND name=? AND deleted_at IS NULL""",
                    (namespace, name),
                )
            ).fetchone()
            if not row:
                await connection.rollback()
                raise VaultNotFoundError("secret not found")
            current = int(row["current_version"])
            if current != expected_version:
                await connection.rollback()
                raise VaultConflictError(
                    f"expected version {expected_version}; current is {current}"
                )
            secret_id = int(row["id"])
            version = current + 1
            envelope = self.keyring.encrypt(
                payload,
                secret_id=secret_id,
                namespace=namespace,
                name=name,
                version=version,
            )
            await connection.execute(
                """INSERT INTO secret_versions
                   (secret_id, version, key_id, nonce_b64, ciphertext_b64, created_at, created_by)
                   VALUES(?, ?, ?, ?, ?, ?, ?)""",
                (
                    secret_id,
                    version,
                    envelope.key_id,
                    envelope.nonce,
                    envelope.ciphertext,
                    timestamp,
                    actor,
                ),
            )
            cursor = await connection.execute(
                """UPDATE secrets SET current_version=?, tags_json=?, updated_at=?
                   WHERE id=? AND current_version=? AND deleted_at IS NULL""",
                (version, json.dumps(tags), timestamp, secret_id, current),
            )
            if cursor.rowcount != 1:
                await connection.rollback()
                raise VaultConflictError("concurrent update rejected")
            await self._append_audit(
                connection,
                actor=actor,
                action="secret.update",
                namespace=namespace,
                name=name,
                outcome="success",
                details={
                    "version": version,
                    "previous_version": current,
                    "key_id": envelope.key_id,
                },
            )
            await connection.commit()
        return {
            "namespace": namespace,
            "name": name,
            "version": version,
            "key_id": envelope.key_id,
            "updated_at": timestamp,
        }

    async def get(self, namespace: str, name: str, actor: str) -> dict[str, Any]:
        async with self._connection() as connection:
            await connection.execute("BEGIN IMMEDIATE")
            row = await (
                await connection.execute(
                    """SELECT s.id, s.namespace, s.name, s.current_version, s.tags_json,
                              s.created_at, s.updated_at, v.key_id, v.nonce_b64, v.ciphertext_b64
                       FROM secrets s
                       JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.current_version
                       WHERE s.namespace=? AND s.name=? AND s.deleted_at IS NULL""",
                    (namespace, name),
                )
            ).fetchone()
            if not row:
                await connection.rollback()
                raise VaultNotFoundError("secret not found")
            version = int(row["current_version"])
            try:
                payload = self.keyring.decrypt(
                    Envelope(str(row["key_id"]), str(row["nonce_b64"]), str(row["ciphertext_b64"])),
                    secret_id=int(row["id"]),
                    namespace=namespace,
                    name=name,
                    version=version,
                )
            except VaultCryptoError:
                await connection.rollback()
                raise
            await self._append_audit(
                connection,
                actor=actor,
                action="secret.read",
                namespace=namespace,
                name=name,
                outcome="success",
                details={"version": version, "key_id": str(row["key_id"])},
            )
            await connection.commit()
        return {
            "namespace": namespace,
            "name": name,
            "version": version,
            "key_id": str(row["key_id"]),
            "updated_at": str(row["updated_at"]),
            "secret": payload["secret"],
            "username": payload.get("username"),
            "metadata": payload.get("metadata") or {},
            "tags": json.loads(row["tags_json"]),
        }

    async def list_metadata(self, namespace: str, actor: str) -> list[dict[str, Any]]:
        async with self._connection() as connection:
            await connection.execute("BEGIN IMMEDIATE")
            rows = list(
                await (
                    await connection.execute(
                        """SELECT s.namespace, s.name, s.current_version, s.tags_json,
                              s.created_at, s.updated_at, v.key_id
                       FROM secrets s
                       JOIN secret_versions v ON v.secret_id=s.id AND v.version=s.current_version
                       WHERE s.namespace=? AND s.deleted_at IS NULL ORDER BY s.name""",
                        (namespace,),
                    )
                ).fetchall()
            )
            await self._append_audit(
                connection,
                actor=actor,
                action="secret.list",
                namespace=namespace,
                name=None,
                outcome="success",
                details={"count": len(rows)},
            )
            await connection.commit()
        return [
            {
                "namespace": str(row["namespace"]),
                "name": str(row["name"]),
                "current_version": int(row["current_version"]),
                "tags": json.loads(row["tags_json"]),
                "key_id": str(row["key_id"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ]

    async def list_versions(self, namespace: str, name: str, actor: str) -> list[dict[str, Any]]:
        async with self._connection() as connection:
            await connection.execute("BEGIN IMMEDIATE")
            secret = await (
                await connection.execute(
                    "SELECT id FROM secrets WHERE namespace=? AND name=? AND deleted_at IS NULL",
                    (namespace, name),
                )
            ).fetchone()
            if not secret:
                await connection.rollback()
                raise VaultNotFoundError("secret not found")
            rows = list(
                await (
                    await connection.execute(
                        """SELECT version, key_id, created_at, created_by
                       FROM secret_versions WHERE secret_id=? ORDER BY version DESC""",
                        (int(secret["id"]),),
                    )
                ).fetchall()
            )
            await self._append_audit(
                connection,
                actor=actor,
                action="secret.versions",
                namespace=namespace,
                name=name,
                outcome="success",
                details={"count": len(rows)},
            )
            await connection.commit()
        return [dict(row) for row in rows]

    async def delete(
        self, namespace: str, name: str, expected_version: int, actor: str
    ) -> dict[str, Any]:
        timestamp = now_iso()
        async with self._connection() as connection:
            await connection.execute("BEGIN IMMEDIATE")
            row = await (
                await connection.execute(
                    """SELECT id, current_version FROM secrets
                       WHERE namespace=? AND name=? AND deleted_at IS NULL""",
                    (namespace, name),
                )
            ).fetchone()
            if not row:
                await connection.rollback()
                raise VaultNotFoundError("secret not found")
            current = int(row["current_version"])
            if current != expected_version:
                await connection.rollback()
                raise VaultConflictError(
                    f"expected version {expected_version}; current is {current}"
                )
            cursor = await connection.execute(
                """UPDATE secrets SET deleted_at=?, updated_at=?
                   WHERE id=? AND current_version=? AND deleted_at IS NULL""",
                (timestamp, timestamp, int(row["id"]), current),
            )
            if cursor.rowcount != 1:
                await connection.rollback()
                raise VaultConflictError("concurrent delete rejected")
            await self._append_audit(
                connection,
                actor=actor,
                action="secret.delete",
                namespace=namespace,
                name=name,
                outcome="success",
                details={"version": current, "soft_delete": True},
            )
            await connection.commit()
        return {"namespace": namespace, "name": name, "version": current, "deleted_at": timestamp}

    async def rekey_all(self, target_key_id: str, actor: str) -> dict[str, Any]:
        if target_key_id not in self.keyring.keys:
            raise VaultNotFoundError("target key is not loaded")
        async with self._connection() as connection:
            await connection.execute("BEGIN IMMEDIATE")
            rows = list(
                await (
                    await connection.execute(
                        """SELECT v.id AS version_id, v.secret_id, v.version, v.key_id,
                              v.nonce_b64, v.ciphertext_b64, s.namespace, s.name
                       FROM secret_versions v JOIN secrets s ON s.id=v.secret_id
                       WHERE v.key_id<>? ORDER BY v.id""",
                        (target_key_id,),
                    )
                ).fetchall()
            )
            for row in rows:
                secret_id = int(row["secret_id"])
                version = int(row["version"])
                namespace = str(row["namespace"])
                name = str(row["name"])
                payload = self.keyring.decrypt(
                    Envelope(str(row["key_id"]), str(row["nonce_b64"]), str(row["ciphertext_b64"])),
                    secret_id=secret_id,
                    namespace=namespace,
                    name=name,
                    version=version,
                )
                envelope = self.keyring.encrypt(
                    payload,
                    secret_id=secret_id,
                    namespace=namespace,
                    name=name,
                    version=version,
                    key_id=target_key_id,
                )
                await connection.execute(
                    """UPDATE secret_versions SET key_id=?, nonce_b64=?, ciphertext_b64=?
                       WHERE id=?""",
                    (envelope.key_id, envelope.nonce, envelope.ciphertext, int(row["version_id"])),
                )
            await self._append_audit(
                connection,
                actor=actor,
                action="vault.rekey",
                namespace=None,
                name=None,
                outcome="success",
                details={"target_key_id": target_key_id, "versions_rekeyed": len(rows)},
            )
            await connection.commit()
        return {"target_key_id": target_key_id, "versions_rekeyed": len(rows)}

    async def verify_audit_chain(self) -> dict[str, Any]:
        async with self._connection() as connection:
            rows = list(
                await (
                    await connection.execute("SELECT * FROM audit_events ORDER BY id")
                ).fetchall()
            )
        previous_hash = "0" * 64
        for row in rows:
            if str(row["previous_hash"]) != previous_hash:
                return {"valid": False, "events": len(rows), "first_bad_event_id": int(row["id"])}
            expected = self._audit_hash(
                event_id=int(row["id"]),
                occurred_at=str(row["occurred_at"]),
                actor=str(row["actor"]),
                action=str(row["action"]),
                namespace=row["namespace"],
                name=row["name"],
                outcome=str(row["outcome"]),
                details_json=str(row["details_json"]),
                previous_hash=previous_hash,
            )
            if not hmac.compare_digest(expected, str(row["entry_hash"])):
                return {"valid": False, "events": len(rows), "first_bad_event_id": int(row["id"])}
            previous_hash = str(row["entry_hash"])
        return {"valid": True, "events": len(rows), "first_bad_event_id": None}
