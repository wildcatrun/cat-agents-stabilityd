import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from stability_core.observation_store import (
    ensure_observation_store, load_observation_records, persist_observation_batch,
)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def observation(event, *, observed=990, source="synthetic-fixture", payload="evidence", node="dev-server", generation="g1"):
    return {
        "nodeId": node, "eventId": digest(event), "generationDigest": digest(generation),
        "evidenceDigest": digest(payload), "sourceKind": source,
        "observedAtEpoch": observed, "receivedAtEpoch": 1,
        "rawPayload": "FIXTURE_SECRET_MUST_NOT_PERSIST",
    }


class ObservationStoreTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.path = Path(self._temp.name) / "state.db"
        self.conn = sqlite3.connect(self.path)

    def tearDown(self):
        self.conn.close()
        self._temp.cleanup()

    def test_bounded_idempotent_persistence_survives_reopen_without_payload(self):
        record = observation("event-1")
        first = persist_observation_batch(
            self.conn, [record], now_epoch=1000,
            current_generations={"dev-server": digest("g1")},
        )
        second = persist_observation_batch(
            self.conn, [record], now_epoch=1010,
            current_generations={"dev-server": digest("g1")},
        )
        self.assertEqual(first["summary"]["accepted"], 1)
        self.assertEqual(second["summary"]["duplicatesSuppressed"], 1)
        self.assertFalse(second["actionReplay"])
        self.assertFalse(second["storedPayloads"])
        rows = load_observation_records(self.conn)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["receivedAtEpoch"], 1000.0)
        self.assertNotIn("rawPayload", rows[0])
        self.assertNotIn("FIXTURE_SECRET_MUST_NOT_PERSIST", str(rows))
        self.conn.commit()
        self.conn.close()
        reopened = sqlite3.connect(self.path)
        try:
            self.assertEqual(len(load_observation_records(reopened)), 1)
        finally:
            reopened.close()
        self.conn = sqlite3.connect(self.path)

    def test_source_claim_requires_explicit_allowlist_and_untrusted_claim_is_not_stored(self):
        record = observation("read-only-claim", source="read-only-probe")
        result = persist_observation_batch(
            self.conn, [record], now_epoch=1000,
            current_generations={"dev-server": digest("g1")},
        )
        self.assertEqual(result["summary"]["unauthorizedSourceRejected"], 1)
        self.assertEqual(result["records"], [])
        self.assertEqual(load_observation_records(self.conn), [])

    def test_non_string_source_is_rejected_and_generator_consumption_is_bounded(self):
        invalid = observation("unhashable-source")
        invalid["sourceKind"] = ["synthetic-fixture"]
        consumed = []

        def source():
            for index in range(10):
                consumed.append(index)
                yield observation(f"bounded-input-{index}")

        result = persist_observation_batch(
            self.conn, [invalid], now_epoch=1000,
            current_generations={"dev-server": digest("g1")}, max_records=2,
        )
        self.assertEqual(result["summary"]["unauthorizedSourceRejected"], 1)
        self.assertEqual(consumed, [])

        result = persist_observation_batch(
            self.conn, source(), now_epoch=1000,
            current_generations={"dev-server": digest("g1")}, max_records=2,
        )
        self.assertEqual(consumed, [0, 1, 2, 3, 4])
        self.assertEqual(result["summary"]["inputLimitExceeded"], 1)
        self.assertLessEqual(len(result["records"]), 2)

    def test_conflicting_retry_removes_prior_event_and_ttl_and_size_are_bounded(self):
        first = observation("same-id", observed=990, payload="first")
        persisted = persist_observation_batch(
            self.conn, [first], now_epoch=1000,
            current_generations={"dev-server": digest("g1")},
        )
        self.assertEqual(persisted["summary"]["accepted"], 1)
        conflict = observation("same-id", observed=991, payload="different")
        collided = persist_observation_batch(
            self.conn, [conflict], now_epoch=1001,
            current_generations={"dev-server": digest("g1")},
        )
        self.assertEqual(collided["summary"]["eventConflictsRemoved"], 1)
        self.assertEqual(load_observation_records(self.conn), [])

        batch = [observation(f"bounded-{idx}", observed=100 + idx) for idx in range(4)]
        bounded = persist_observation_batch(
            self.conn, batch, now_epoch=1000,
            current_generations={"dev-server": digest("g1")}, max_records=2, retention_seconds=10,
        )
        self.assertLessEqual(len(load_observation_records(self.conn)), 2)
        self.assertLessEqual(bounded["summary"]["overflowDropped"], 2)
        self.assertGreaterEqual(bounded["summary"]["expiredPruned"], 0)

    def test_failed_insert_rolls_back_delete_and_preserves_prior_snapshot(self):
        persist_observation_batch(self.conn, [observation("stable")], now_epoch=1000,
                                  current_generations={"dev-server": digest("g1")})
        before = load_observation_records(self.conn)
        self.conn.execute(
            f"""CREATE TRIGGER reject_fixture BEFORE INSERT ON stability_observation_events
                WHEN NEW.event_id='{digest('trigger-fail')}'
                BEGIN SELECT RAISE(ABORT,'fixture failure'); END"""
        )
        with self.assertRaises(sqlite3.IntegrityError):
            persist_observation_batch(self.conn, [observation("trigger-fail")], now_epoch=1001,
                                      current_generations={"dev-server": digest("g1")})
        self.assertEqual(load_observation_records(self.conn), before)

    def test_schema_version_and_outer_transaction_are_preserved(self):
        self.conn.execute("CREATE TABLE caller_state (value TEXT)")
        self.conn.execute("INSERT INTO caller_state VALUES('pending')")
        self.assertTrue(self.conn.in_transaction)
        ensure_observation_store(self.conn)
        self.assertTrue(self.conn.in_transaction, "schema helper committed its caller's transaction")
        self.conn.rollback()
        self.assertEqual(self.conn.execute("SELECT value FROM caller_state").fetchall(), [])

    def test_unversioned_partial_schema_is_rejected_without_modification(self):
        self.conn.execute("CREATE TABLE stability_observation_events (event_id TEXT)")
        self.conn.commit()
        before = self.conn.execute("SELECT sql FROM sqlite_master WHERE name='stability_observation_events'").fetchone()
        with self.assertRaisesRegex(ValueError, "partial observation store"):
            ensure_observation_store(self.conn)
        after = self.conn.execute("SELECT sql FROM sqlite_master WHERE name='stability_observation_events'").fetchone()
        self.assertEqual(before, after)
        self.assertIsNone(self.conn.execute("SELECT name FROM sqlite_master WHERE name='stability_observation_schema'").fetchone())


if __name__ == "__main__":
    unittest.main()
