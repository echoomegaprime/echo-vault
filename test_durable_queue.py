import os
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from durable_queue import (
    DispatchResult,
    DurableQueue,
    QueueCapacityError,
    RetryPolicy,
    normalize_importance,
    redact_text,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 5, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


def permanent_pg_error(error: str) -> bool:
    return "violates not-null constraint" in (error or "").lower()


class DurableQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "queue.db"
        self.clock = FakeClock()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def make_queue(self, **overrides) -> DurableQueue:
        defaults = {
            "policy": RetryPolicy(
                base_delay_s=2,
                max_delay_s=8,
                max_attempts=3,
                batch_size=10,
            ),
            "now": self.clock,
            "permanent_error_classifier": permanent_pg_error,
        }
        defaults.update(overrides)
        return DurableQueue(self.db_path, **defaults)

    def pending_row(self) -> sqlite3.Row:
        queue = self.make_queue()
        with queue.connect() as conn:
            row = conn.execute("SELECT * FROM pending_writes ORDER BY id LIMIT 1").fetchone()
        self.assertIsNotNone(row)
        return row

    def test_gate_down_updates_attempt_error_and_bounded_backoff(self) -> None:
        queue = self.make_queue()
        queue.enqueue("mirror_audit", {"kind": "vault_access", "content": "redacted"})

        first = queue.drain(
            {"mirror_audit": lambda _payload: DispatchResult(False, "ssh timeout")}
        )
        self.assertEqual(first.retried, 1)
        row = self.pending_row()
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(row["last_error"], "ssh timeout")
        self.assertEqual(
            datetime.fromisoformat(row["next_attempt_at"]), self.clock() + timedelta(seconds=2)
        )

        self.clock.advance(2)
        queue.drain({"mirror_audit": lambda _payload: DispatchResult(False, "gate down")})
        row = self.pending_row()
        self.assertEqual(row["attempts"], 2)
        self.assertEqual(
            datetime.fromisoformat(row["next_attempt_at"]), self.clock() + timedelta(seconds=4)
        )
        self.assertLessEqual(queue.policy.delay_for(99), 8)

    def test_periodic_worker_recovers_without_foreground_write(self) -> None:
        attempts = 0
        first_failure = threading.Event()
        recovered = threading.Event()

        def dispatch(_payload: dict) -> DispatchResult:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                first_failure.set()
                return DispatchResult(False, "gate unavailable")
            recovered.set()
            return DispatchResult(True)

        queue = DurableQueue(
            self.db_path,
            policy=RetryPolicy(
                base_delay_s=0.02,
                max_delay_s=0.02,
                max_attempts=4,
                batch_size=10,
            ),
        )
        queue.enqueue("mirror_audit", {"kind": "vault_access", "content": "redacted"})
        stop, thread = queue.start_worker(
            {"mirror_audit": dispatch}, interval_s=0.005, run_immediately=True
        )
        try:
            self.assertTrue(first_failure.wait(1), "worker never attempted the down gate")
            self.assertTrue(recovered.wait(1), "periodic drain did not recover independently")
            deadline = time.monotonic() + 1
            while queue.counts()["pending"] and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(queue.counts()["pending"], 0)
        finally:
            stop.set()
            queue.wake()
            thread.join(timeout=1)

    def test_immediate_worker_pass_does_not_block_caller_startup(self) -> None:
        queue = DurableQueue(self.db_path)
        queue.enqueue("mirror_audit", {"kind": "vault_access", "content": "redacted"})
        entered = threading.Event()
        release = threading.Event()

        def blocked_dispatch(_payload: dict) -> DispatchResult:
            entered.set()
            release.wait(1)
            return DispatchResult(True)

        started = time.monotonic()
        stop, thread = queue.start_worker(
            {"mirror_audit": blocked_dispatch},
            interval_s=1,
            run_immediately=True,
        )
        elapsed = time.monotonic() - started
        try:
            self.assertLess(elapsed, 0.1)
            self.assertTrue(entered.wait(1))
        finally:
            release.set()
            stop.set()
            queue.wake()
            thread.join(timeout=1)

    def test_unknown_operation_is_dead_lettered(self) -> None:
        queue = self.make_queue()
        queue.enqueue("future_unregistered_op", {"metadata": "redacted"})

        stats = queue.drain({"mirror_audit": lambda _payload: DispatchResult(True)})

        self.assertEqual(stats.dead_lettered, 1)
        self.assertEqual(queue.counts(), {"pending": 0, "dead_letters": 1})
        with queue.connect() as conn:
            row = conn.execute("SELECT * FROM dead_letters").fetchone()
        self.assertEqual(row["reason"], "unknown_operation")
        self.assertEqual(row["attempts"], 1)

    def test_permanent_failure_is_dead_lettered(self) -> None:
        queue = self.make_queue()
        queue.enqueue("mirror_audit", {"kind": "vault_access", "content": "redacted"})

        stats = queue.drain(
            {
                "mirror_audit": lambda _payload: DispatchResult(
                    False, "violates not-null constraint context_kind_check"
                )
            }
        )

        self.assertEqual(stats.dead_lettered, 1)
        with queue.connect() as conn:
            row = conn.execute("SELECT * FROM dead_letters").fetchone()
        self.assertEqual(row["reason"], "permanent_error")
        self.assertEqual(row["attempts"], 1)

    def test_existing_permanent_classifier_is_preserved_without_redispatch(self) -> None:
        queue = self.make_queue()
        queue.enqueue(
            "mirror_audit",
            {"kind": "vault_access", "content": "redacted"},
            "violates not-null constraint legacy row",
        )
        called = False

        def dispatch(_payload: dict) -> DispatchResult:
            nonlocal called
            called = True
            return DispatchResult(True)

        stats = queue.drain({"mirror_audit": dispatch})

        self.assertFalse(called)
        self.assertEqual(stats.dead_lettered, 1)
        self.assertEqual(queue.counts()["pending"], 0)

    def test_backlog_larger_than_one_batch_drains_completely(self) -> None:
        queue = self.make_queue()
        for index in range(27):
            queue.enqueue(
                "mirror_audit",
                {"kind": "vault_access", "content": f"redacted-{index}"},
            )

        stats = queue.drain(
            {"mirror_audit": lambda _payload: DispatchResult(True)}, batch_size=10
        )

        self.assertEqual(stats.succeeded, 27)
        self.assertEqual(stats.batches, 3)
        self.assertEqual(queue.counts()["pending"], 0)

    def test_max_attempts_moves_row_to_dead_letters(self) -> None:
        queue = self.make_queue()
        queue.enqueue("mirror_audit", {"kind": "vault_access", "content": "redacted"})
        fail = {"mirror_audit": lambda _payload: DispatchResult(False, "temporary")}

        queue.drain(fail)
        self.clock.advance(2)
        queue.drain(fail)
        self.clock.advance(4)
        stats = queue.drain(fail)

        self.assertEqual(stats.dead_lettered, 1)
        with queue.connect() as conn:
            row = conn.execute("SELECT * FROM dead_letters").fetchone()
        self.assertEqual(row["reason"], "max_attempts")
        self.assertEqual(row["attempts"], 3)

    def test_logs_never_contain_payload_values_or_dispatch_errors(self) -> None:
        logs: list[str] = []
        queue = self.make_queue(logger=logs.append, sanitize_error=lambda _error: "redacted")
        queue.enqueue("unknown", {"credential": "DO-NOT-LOG-THIS"}, "SENSITIVE-ERROR")
        queue.drain({})

        joined = "\n".join(logs)
        self.assertNotIn("DO-NOT-LOG-THIS", joined)
        self.assertNotIn("SENSITIVE-ERROR", joined)
        self.assertNotIn("credential", joined)

    def test_legacy_schema_is_migrated_in_place(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """CREATE TABLE pending_writes(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    op TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER DEFAULT 0,
                    last_error TEXT
                )"""
            )
            conn.execute(
                "INSERT INTO pending_writes(op,payload,created_at,last_error) "
                "VALUES('mirror_audit','{}',?,'timeout')",
                (self.clock().isoformat(),),
            )
            conn.commit()

        queue = self.make_queue()

        with queue.connect() as conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(pending_writes)")}
            next_attempt = conn.execute(
                "SELECT next_attempt_at FROM pending_writes"
            ).fetchone()[0]
        self.assertIn("next_attempt_at", columns)
        self.assertIn("lease_owner", columns)
        self.assertIn("lease_until", columns)
        self.assertTrue(next_attempt)

    def test_two_instances_cannot_dispatch_the_same_live_lease(self) -> None:
        policy = RetryPolicy(
            base_delay_s=1,
            max_delay_s=1,
            max_attempts=3,
            batch_size=1,
            lease_duration_s=0.06,
        )
        first = DurableQueue(self.db_path, policy=policy, owner_id="first")
        second = DurableQueue(self.db_path, policy=policy, owner_id="second")
        first.enqueue("mirror_audit", {"kind": "vault_access", "content": "redacted"})
        entered = threading.Event()
        release = threading.Event()
        calls: list[str] = []

        def slow_dispatch(_payload: dict) -> DispatchResult:
            calls.append("first")
            entered.set()
            release.wait(1)
            return DispatchResult(True)

        thread = threading.Thread(
            target=lambda: first.drain({"mirror_audit": slow_dispatch})
        )
        thread.start()
        try:
            self.assertTrue(entered.wait(1))
            time.sleep(0.09)  # beyond the original lease; heartbeat must fence it
            duplicate = second.drain(
                {"mirror_audit": lambda _payload: calls.append("second") or DispatchResult(True)}
            )
            self.assertEqual(duplicate.examined, 0)
        finally:
            release.set()
            thread.join(timeout=1)
        self.assertEqual(calls, ["first"])
        self.assertEqual(first.counts()["pending"], 0)

    def test_expired_lease_is_recovered_by_another_instance(self) -> None:
        policy = RetryPolicy(lease_duration_s=5, batch_size=1)
        first = DurableQueue(
            self.db_path, policy=policy, now=self.clock, owner_id="expired-owner"
        )
        second = DurableQueue(
            self.db_path, policy=policy, now=self.clock, owner_id="recovery-owner"
        )
        first.enqueue("mirror_audit", {"kind": "vault_access", "content": "redacted"})
        self.assertEqual(len(first._claim_rows(1)), 1)
        self.assertEqual(
            second.drain({"mirror_audit": lambda _payload: DispatchResult(True)}).examined,
            0,
        )

        self.clock.advance(6)
        recovered = second.drain(
            {"mirror_audit": lambda _payload: DispatchResult(True)}
        )

        self.assertEqual(recovered.succeeded, 1)
        self.assertEqual(second.counts()["pending"], 0)

    def test_drain_row_bound_is_total_not_batch_size(self) -> None:
        queue = self.make_queue(
            policy=RetryPolicy(batch_size=2, max_rows_per_drain=5, max_batches_per_drain=10)
        )
        for index in range(9):
            queue.enqueue("mirror_audit", {"kind": "vault_access", "content": str(index)})

        stats = queue.drain(
            {"mirror_audit": lambda _payload: DispatchResult(True)},
            batch_size=2,
            max_rows=100,
        )

        self.assertEqual(stats.succeeded, 5)
        self.assertEqual(stats.batches, 3)
        self.assertEqual(queue.counts()["pending"], 4)

    def test_payload_and_depth_caps_fail_closed(self) -> None:
        queue = self.make_queue(
            policy=RetryPolicy(max_payload_bytes=40, max_queue_depth=1)
        )
        with self.assertRaisesRegex(QueueCapacityError, "payload"):
            queue.enqueue("mirror_audit", {"content": "x" * 80})
        queue.enqueue("mirror_audit", {"content": "ok"})
        with self.assertRaisesRegex(QueueCapacityError, "depth"):
            queue.enqueue("mirror_audit", {"content": "second"})
        self.assertEqual(queue.counts()["pending"], 1)

    def test_importance_rejects_bool_nonfinite_out_of_range_and_sql_text(self) -> None:
        invalid = [True, float("nan"), float("inf"), -0.1, 1.1, "0); SELECT 1; --"]
        for value in invalid:
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(ValueError):
                    normalize_importance(value)

        import server as vault_server

        payload = {
            "kind": "vault_access",
            "content": "redacted",
            "tags": [],
            "importance": "0); SELECT pg_sleep(9); --",
        }
        with mock.patch.object(vault_server, "pg_exec") as pg_exec:
            result = vault_server._dispatch_mirror_audit(payload)
        self.assertTrue(result.permanent)
        self.assertFalse(result.success)
        pg_exec.assert_not_called()

    def test_short_supplied_secrets_are_redacted_without_logging_values(self) -> None:
        import server as vault_server

        for length in (1, 2, 3):
            secret = "".join(chr(96 + index) for index in range(1, length + 1))
            for redactor in (redact_text, vault_server._redact):
                actual = redactor(f"before:{secret}:after", secret)
                if secret in actual or "***REDACTED***" not in actual:
                    raise AssertionError("short secret was not fully redacted")

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not enforced on Windows")
    def test_queue_file_is_owner_only_on_posix(self) -> None:
        self.make_queue()
        mode = stat.S_IMODE(self.db_path.stat().st_mode)
        self.assertEqual(mode & (stat.S_IRWXG | stat.S_IRWXO), 0)

    @unittest.skipUnless(os.name == "nt", "Windows ACL check")
    def test_queue_file_has_no_broad_windows_acl(self) -> None:
        self.make_queue()
        result = subprocess.run(
            ["icacls", str(self.db_path)], capture_output=True, text=True,
            timeout=10, check=True,
        )
        acl = result.stdout.lower()
        for broad in ("authenticated users", "builtin\\users", "everyone"):
            self.assertNotIn(broad, acl)


if __name__ == "__main__":
    unittest.main()
