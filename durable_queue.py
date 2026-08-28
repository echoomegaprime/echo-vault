"""SQLite-backed retry queue with bounded backoff and dead-letter handling.

The queue deliberately treats payloads as opaque.  Logs contain only row ids,
operation names, and counters so queued metadata can never be copied into an
operator log by the retry machinery.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Mapping


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def redact_text(text: str, *secret_values: str) -> str:
    """Redact every supplied non-empty value, including 1-3 byte secrets."""
    output = text or ""
    for value in secret_values:
        secret = str(value) if value is not None else ""
        if secret:
            output = output.replace(secret, "***REDACTED***")
    return output


def normalize_importance(value: object, default: float = 0.6) -> float:
    """Return a finite, non-boolean importance in the closed interval [0, 1]."""
    candidate = default if value is None else value
    if isinstance(candidate, bool) or not isinstance(candidate, (int, float)):
        raise ValueError("importance must be a finite numeric value")
    normalized = float(candidate)
    if not math.isfinite(normalized) or not 0.0 <= normalized <= 1.0:
        raise ValueError("importance must be between 0 and 1")
    return normalized


class QueueCapacityError(RuntimeError):
    """A bounded local queue rejected a row without exposing its payload."""


@dataclass(frozen=True)
class RetryPolicy:
    base_delay_s: float = 5.0
    max_delay_s: float = 300.0
    max_attempts: int = 8
    batch_size: int = 10
    max_rows_per_drain: int = 200
    max_batches_per_drain: int = 20
    drain_deadline_s: float = 20.0
    lease_duration_s: float = 60.0
    max_payload_bytes: int = 16_384
    max_queue_depth: int = 10_000

    def delay_for(self, attempts: int) -> float:
        """Return bounded exponential delay after ``attempts`` failures."""
        exponent = max(0, attempts - 1)
        return min(self.max_delay_s, self.base_delay_s * (2**exponent))


@dataclass(frozen=True)
class DispatchResult:
    success: bool
    error: str = ""
    permanent: bool = False


@dataclass
class DrainStats:
    examined: int = 0
    succeeded: int = 0
    retried: int = 0
    dead_lettered: int = 0
    batches: int = 0


Dispatcher = Callable[[dict], DispatchResult]
ErrorClassifier = Callable[[str], bool]
ErrorSanitizer = Callable[[str], str]
Logger = Callable[[str], None]


class DurableQueue:
    """Durable at-least-once queue for a small set of explicit operations."""

    def __init__(
        self,
        path: Path | str,
        *,
        policy: RetryPolicy | None = None,
        now: Callable[[], datetime] = utc_now,
        permanent_error_classifier: ErrorClassifier | None = None,
        sanitize_error: ErrorSanitizer | None = None,
        logger: Logger | None = None,
        owner_id: str | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.path = Path(path)
        self.policy = policy or RetryPolicy()
        positive = (
            self.policy.max_attempts,
            self.policy.batch_size,
            self.policy.max_rows_per_drain,
            self.policy.max_batches_per_drain,
            self.policy.drain_deadline_s,
            self.policy.lease_duration_s,
            self.policy.max_payload_bytes,
            self.policy.max_queue_depth,
        )
        if any(value <= 0 for value in positive):
            raise ValueError("retry, lease, payload, and drain bounds must be positive")
        self._now = now
        self._monotonic = monotonic
        self.owner_id = owner_id or uuid.uuid4().hex
        self._is_permanent = permanent_error_classifier or (lambda _error: False)
        self._sanitize_error = sanitize_error or (lambda error: error)
        self._logger = logger or (lambda _message: None)
        self._db_lock = threading.RLock()
        self._drain_lock = threading.Lock()
        self._wake = threading.Event()
        self._ensure_schema()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db_lock, self.connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS pending_writes(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    op TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    next_attempt_at TEXT,
                    lease_owner TEXT,
                    lease_until TEXT
                )"""
            )
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(pending_writes)")
            }
            if "next_attempt_at" not in columns:
                conn.execute("ALTER TABLE pending_writes ADD COLUMN next_attempt_at TEXT")
            if "lease_owner" not in columns:
                conn.execute("ALTER TABLE pending_writes ADD COLUMN lease_owner TEXT")
            if "lease_until" not in columns:
                conn.execute("ALTER TABLE pending_writes ADD COLUMN lease_until TEXT")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS dead_letters(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_id INTEGER NOT NULL,
                    op TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    last_error TEXT,
                    failed_at TEXT NOT NULL,
                    reason TEXT NOT NULL
                )"""
            )
            due = _iso(self._now())
            conn.execute(
                "UPDATE pending_writes SET next_attempt_at=COALESCE(created_at, ?) "
                "WHERE next_attempt_at IS NULL OR next_attempt_at=''",
                (due,),
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_pending_writes_claimable "
                "ON pending_writes(next_attempt_at, lease_until, id)"
            )
        self._restrict_permissions()

    def _restrict_permissions(self) -> None:
        """Require owner-only queue permissions without changing parent dirs."""
        if os.name != "nt":
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
            return
        domain = os.environ.get("USERDOMAIN", "").strip()
        username = os.environ.get("USERNAME", "").strip()
        principal = f"{domain}\\{username}" if domain and username else username
        if not principal:
            raise PermissionError("cannot determine Windows queue-file owner")
        commands = (
            ["icacls", str(self.path), "/inheritance:r"],
            [
                "icacls", str(self.path), "/grant:r",
                f"{principal}:(F)", "*S-1-5-18:(F)",
            ],
            [
                "icacls", str(self.path), "/remove:g",
                "*S-1-1-0", "*S-1-5-11", "*S-1-5-32-545",
            ],
        )
        for command in commands:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=10, check=False,
            )
            if completed.returncode != 0:
                raise PermissionError("failed to apply owner-only queue-file ACL")

    def enqueue(self, op: str, payload: dict, error: str = "") -> int:
        now = _iso(self._now())
        safe_error = self._safe_error(error)
        payload_json = json.dumps(payload, separators=(",", ":"))
        payload_size = len(payload_json.encode("utf-8"))
        if payload_size > self.policy.max_payload_bytes:
            raise QueueCapacityError("queue payload exceeds configured byte limit")
        with self._db_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            depth = int(
                conn.execute(
                    "SELECT (SELECT count(*) FROM pending_writes) + "
                    "(SELECT count(*) FROM dead_letters)"
                ).fetchone()[0]
            )
            if depth >= self.policy.max_queue_depth:
                raise QueueCapacityError("queue depth exceeds configured row limit")
            cur = conn.execute(
                "INSERT INTO pending_writes"
                "(op,payload,created_at,attempts,last_error,next_attempt_at) "
                "VALUES(?,?,?,0,?,?)",
                (op, payload_json, now, safe_error, now),
            )
            row_id = int(cur.lastrowid)
        self._wake.set()
        self._logger(f"queued op={op} id={row_id}")
        return row_id

    def counts(self) -> dict[str, int]:
        with self._db_lock, self.connect() as conn:
            pending = int(conn.execute("SELECT count(*) FROM pending_writes").fetchone()[0])
            dead = int(conn.execute("SELECT count(*) FROM dead_letters").fetchone()[0])
        return {"pending": pending, "dead_letters": dead}

    def drain(
        self,
        dispatchers: Mapping[str, Dispatcher],
        *,
        batch_size: int | None = None,
        max_rows: int | None = None,
        max_batches: int | None = None,
        deadline_s: float | None = None,
    ) -> DrainStats:
        """Drain every currently due batch while rows make forward progress.

        A transient failure is rescheduled beyond the current instant, allowing
        later rows and later batches to run.  Unknown operations, malformed
        payloads, permanent failures, and exhausted retries are dead-lettered.
        """
        stats = DrainStats()
        if not self._drain_lock.acquire(blocking=False):
            return stats
        size = self.policy.batch_size if batch_size is None else batch_size
        requested_rows = (
            self.policy.max_rows_per_drain if max_rows is None else max_rows
        )
        requested_batches = (
            self.policy.max_batches_per_drain if max_batches is None else max_batches
        )
        requested_deadline = (
            self.policy.drain_deadline_s if deadline_s is None else deadline_s
        )
        row_limit = min(
            requested_rows,
            self.policy.max_rows_per_drain,
        )
        batch_limit = min(
            requested_batches,
            self.policy.max_batches_per_drain,
        )
        deadline_limit = min(
            requested_deadline,
            self.policy.drain_deadline_s,
        )
        if min(size, row_limit, batch_limit, deadline_limit) <= 0:
            raise ValueError("drain bounds must be positive")
        deadline = self._monotonic() + deadline_limit
        try:
            while (
                stats.examined < row_limit
                and stats.batches < batch_limit
                and self._monotonic() < deadline
            ):
                remaining = row_limit - stats.examined
                rows = self._claim_rows(min(size, remaining))
                if not rows:
                    break
                stats.batches += 1
                for row in rows:
                    if self._monotonic() >= deadline:
                        self._release_lease(int(row["id"]))
                        continue
                    stats.examined += 1
                    outcome = self._dispatch_row(row, dispatchers)
                    setattr(stats, outcome, getattr(stats, outcome) + 1)
            if stats.examined:
                self._logger(
                    "drain "
                    f"examined={stats.examined} succeeded={stats.succeeded} "
                    f"retried={stats.retried} dead_lettered={stats.dead_lettered}"
                )
            return stats
        finally:
            self._drain_lock.release()

    def start_worker(
        self,
        dispatchers: Mapping[str, Dispatcher],
        *,
        interval_s: float = 30.0,
        run_immediately: bool = False,
        name: str = "durable-queue-drain",
    ) -> tuple[threading.Event, threading.Thread]:
        """Start an independent daemon that drains on wakeups and periodically."""
        stop = threading.Event()

        def loop() -> None:
            if run_immediately:
                self._drain_guarded(dispatchers, "startup")
            while not stop.is_set():
                self._wake.wait(interval_s)
                self._wake.clear()
                if stop.is_set():
                    break
                self._drain_guarded(dispatchers, "periodic")

        thread = threading.Thread(target=loop, name=name, daemon=True)
        thread.start()
        return stop, thread

    def wake(self) -> None:
        self._wake.set()

    def _drain_guarded(self, dispatchers: Mapping[str, Dispatcher], trigger: str) -> None:
        try:
            self.drain(dispatchers)
        except Exception as exc:  # a retry worker must never take down its host
            safe = self._safe_error(str(exc))
            self._logger(f"{trigger} drain failed ({type(exc).__name__}): {safe[:160]}")

    def _claim_rows(self, limit: int) -> list[sqlite3.Row]:
        """Atomically lease due rows so sibling processes cannot dispatch them."""
        now = _iso(self._now())
        lease_until = _iso(
            self._now() + timedelta(seconds=self.policy.lease_duration_s)
        )
        with self._db_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            ids = [
                int(row[0])
                for row in conn.execute(
                    "SELECT id FROM pending_writes WHERE next_attempt_at<=? "
                    "AND (lease_until IS NULL OR lease_until<=?) ORDER BY id LIMIT ?",
                    (now, now, limit),
                ).fetchall()
            ]
            if not ids:
                return []
            marks = ",".join("?" for _ in ids)
            conn.execute(
                f"UPDATE pending_writes SET lease_owner=?,lease_until=? "
                f"WHERE id IN ({marks}) AND (lease_until IS NULL OR lease_until<=?)",
                (self.owner_id, lease_until, *ids, now),
            )
            return conn.execute(
                "SELECT id,op,payload,created_at,attempts,last_error,next_attempt_at,"
                "lease_owner,lease_until FROM pending_writes "
                f"WHERE lease_owner=? AND id IN ({marks}) ORDER BY id",
                (self.owner_id, *ids),
            ).fetchall()

    def _release_lease(self, row_id: int) -> None:
        with self._db_lock, self.connect() as conn:
            conn.execute(
                "UPDATE pending_writes SET lease_owner=NULL,lease_until=NULL "
                "WHERE id=? AND lease_owner=?",
                (row_id, self.owner_id),
            )

    def _renew_lease(self, row_id: int) -> None:
        lease_until = _iso(
            self._now() + timedelta(seconds=self.policy.lease_duration_s)
        )
        with self._db_lock, self.connect() as conn:
            conn.execute(
                "UPDATE pending_writes SET lease_until=? "
                "WHERE id=? AND lease_owner=?",
                (lease_until, row_id, self.owner_id),
            )

    def _start_lease_heartbeat(
        self, row_id: int
    ) -> tuple[threading.Event, threading.Thread]:
        stop = threading.Event()
        interval = max(0.01, self.policy.lease_duration_s / 3)

        def renew() -> None:
            while not stop.wait(interval):
                try:
                    self._renew_lease(row_id)
                except Exception as exc:
                    safe = self._safe_error(str(exc))
                    self._logger(
                        f"lease renewal failed id={row_id} ({type(exc).__name__}): "
                        f"{safe[:120]}"
                    )

        thread = threading.Thread(
            target=renew,
            name=f"durable-queue-lease-{row_id}",
            daemon=True,
        )
        thread.start()
        return stop, thread

    def _dispatch_row(
        self, row: sqlite3.Row, dispatchers: Mapping[str, Dispatcher]
    ) -> str:
        row_id = int(row["id"])
        attempts = int(row["attempts"] or 0)
        last_error = row["last_error"] or ""
        if last_error and self._is_permanent(last_error):
            self._dead_letter(row, attempts, last_error, "permanent_error")
            return "dead_lettered"
        dispatcher = dispatchers.get(row["op"])
        if dispatcher is None:
            self._dead_letter(
                row,
                attempts + 1,
                f"unsupported operation: {row['op']}",
                "unknown_operation",
            )
            return "dead_lettered"
        try:
            payload = json.loads(row["payload"])
            if not isinstance(payload, dict):
                raise ValueError("payload must decode to an object")
        except Exception as exc:
            self._dead_letter(
                row,
                attempts + 1,
                f"invalid payload: {type(exc).__name__}",
                "invalid_payload",
            )
            return "dead_lettered"
        try:
            lease_stop, lease_thread = self._start_lease_heartbeat(row_id)
            try:
                result = dispatcher(payload)
                if not isinstance(result, DispatchResult):
                    raise TypeError("dispatcher must return DispatchResult")
            finally:
                lease_stop.set()
                lease_thread.join(timeout=1)
        except Exception as exc:
            result = DispatchResult(False, f"{type(exc).__name__}: {exc}")
        if result.success:
            with self._db_lock, self.connect() as conn:
                conn.execute(
                    "DELETE FROM pending_writes WHERE id=? AND lease_owner=?",
                    (row_id, self.owner_id),
                )
            return "succeeded"
        failed_attempts = attempts + 1
        safe_error = self._safe_error(result.error or "dispatch failed")
        if result.permanent or self._is_permanent(safe_error):
            self._dead_letter(row, failed_attempts, safe_error, "permanent_error")
            return "dead_lettered"
        if failed_attempts >= self.policy.max_attempts:
            self._dead_letter(row, failed_attempts, safe_error, "max_attempts")
            return "dead_lettered"
        next_attempt = self._now() + timedelta(
            seconds=self.policy.delay_for(failed_attempts)
        )
        with self._db_lock, self.connect() as conn:
            conn.execute(
                "UPDATE pending_writes SET attempts=?,last_error=?,next_attempt_at=?,"
                "lease_owner=NULL,lease_until=NULL WHERE id=? AND lease_owner=?",
                (
                    failed_attempts,
                    safe_error,
                    _iso(next_attempt),
                    row_id,
                    self.owner_id,
                ),
            )
        return "retried"

    def _dead_letter(
        self,
        row: sqlite3.Row,
        attempts: int,
        error: str,
        reason: str,
    ) -> None:
        safe_error = self._safe_error(error)
        with self._db_lock, self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            deleted = conn.execute(
                "DELETE FROM pending_writes WHERE id=? AND lease_owner=?",
                (int(row["id"]), self.owner_id),
            )
            if deleted.rowcount != 1:
                return
            conn.execute(
                "INSERT INTO dead_letters"
                "(original_id,op,payload,created_at,attempts,last_error,failed_at,reason) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    int(row["id"]),
                    row["op"],
                    row["payload"],
                    row["created_at"],
                    attempts,
                    safe_error,
                    _iso(self._now()),
                    reason,
                ),
            )
        self._logger(f"dead-lettered op={row['op']} id={row['id']} reason={reason}")

    def _safe_error(self, error: str) -> str:
        return self._sanitize_error(error or "")[:500]
