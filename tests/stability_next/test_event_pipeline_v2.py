import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from stability_core.event_pipeline_v2 import EventPipelineV2
from stability_core.event_outbox import EventOutboxError
from stability_core.event_stream_v2 import EventStreamError
from stability_core.action_ledger import ActionLedger


class EventPipelineV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "state.db"
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        info = os.stat(self.path)
        self.identity = (info.st_dev, info.st_ino)
        self.pipeline = None

    def tearDown(self):
        if self.pipeline is not None:
            self.pipeline.close()
        self.connection.close()
        self.tmp.cleanup()

    def open(self, initialize=False):
        self.pipeline = EventPipelineV2(
            self.connection, self.path, self.identity, self.root / "events.jsonl",
            self.root / "archive", initialize=initialize,
            keep_generations=2, keep_archives=2,
        )
        return self.pipeline

    def test_record_uses_one_validated_encoding_and_preserves_receipt(self):
        pipeline = self.open(True)
        events = [{'tsEpoch': 1, 'message': '猫\n"quoted"'}]
        with mock.patch.object(pipeline.core, '_encode_events', wraps=pipeline.core._encode_events) as encode:
            result = pipeline.record(events)
        self.assertEqual(encode.call_count, 1)
        self.assertEqual(result['record'], {'duplicate': False, 'count': 1, 'ordinal': 1})
        self.assertEqual(result['generationOrdinal'], 1)
        self.assertEqual(result['export']['coverage'], 'receipt-clear')
        self.assertEqual(pipeline.stream.latest(), events)

    def test_borrowed_row_factory_pipeline_bounded_retirement_preserves_payloads(self):
        pipeline = self.open(True)
        for n in range(10):
            result = pipeline.record([{"tsEpoch": n, "message": "synthetic", "cycle": n}])
            self.assertEqual(result["export"]["coverage"], "receipt-clear")
        self.assertEqual(pipeline.core.retention_state()["frontiers"], {"stabilityd": 8})
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 2)
        self.assertLessEqual(len(pipeline.core.prunable_archive_requests()), 3)
        self.assertEqual(pipeline.stream.latest(), [{"tsEpoch": n, "message": "synthetic", "cycle": n} for n in range(10)])
        pipeline.close()
        self.assertIs(self.connection.row_factory, sqlite3.Row)
        self.assertEqual(self.connection.execute("SELECT 1").fetchone()[0], 1)

    def test_pending_action_or_invalid_ledger_cannot_authorize_archive_pruning(self):
        pipeline = self.open(True)
        self.connection.execute("CREATE TABLE action_ledger(fixture TEXT)")
        self.connection.execute("INSERT INTO action_ledger VALUES('untouched')")
        self.connection.commit()
        for n in range(8):
            pipeline.record([{"tsEpoch": n, "cycle": n}])
        self.assertEqual(len(pipeline.core.prunable_archive_requests()), 6)
        self.assertEqual(self.connection.execute("SELECT fixture FROM action_ledger").fetchone()[0], "untouched")

    def test_real_available_empty_action_ledger_allows_bounded_archive_pruning(self):
        with ActionLedger(self.path):
            pass
        pipeline = self.open(True)
        for n in range(40):
            pipeline.record([{"tsEpoch": n, "cycle": n}])
        self.assertEqual(len(pipeline.core.prunable_archive_requests()), 3)
        self.assertEqual(pipeline.evidence()["coverage"], "receipt-clear")
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM action_ledger").fetchone()[0], 0)

    def test_real_planned_action_pins_archives_without_changing_ledger(self):
        with ActionLedger(self.path) as ledger:
            ledger.plan_action(idempotency_key="fixture-pending", action_type="fixture",
                               target="synthetic-target", generation="fixture-generation", input_data={})
        before = [tuple(row) for row in self.connection.execute("SELECT * FROM action_ledger")]
        pipeline = self.open(True)
        for n in range(12):
            pipeline.record([{"tsEpoch": n, "cycle": n}])
        self.assertEqual(len(pipeline.core.prunable_archive_requests()), 10)
        self.assertEqual([tuple(row) for row in self.connection.execute("SELECT * FROM action_ledger")], before)

    def test_corrupt_unknown_action_state_never_authorizes_archive_pruning(self):
        with ActionLedger(self.path) as ledger:
            ledger.plan_action(idempotency_key="fixture-corrupt", action_type="fixture",
                               target="fixture", generation="fixture", input_data={})
        self.connection.execute("PRAGMA ignore_check_constraints=ON")
        self.connection.execute("UPDATE action_ledger SET state='unsupported-state'")
        self.connection.commit()
        pipeline = self.open(True)
        for n in range(12):
            pipeline.record([{"tsEpoch": n, "cycle": n}])
        self.assertEqual(len(pipeline.core.prunable_archive_requests()), 10)
        self.assertEqual(self.connection.execute("SELECT state FROM action_ledger").fetchone()[0], "unsupported-state")

    def test_healthy_empty_cycles_retire_without_inventing_events(self):
        pipeline = self.open(True)
        for n in range(140):
            result = pipeline.record([])
            self.assertEqual(result["export"]["coverage"], "receipt-clear")
        # Most daemon cycles have no qualifying findings. They still must not
        # exhaust the generation budget or generate synthetic CLI events.
        self.assertEqual(pipeline.core.retention_state()["frontiers"], {"stabilityd": 138})
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 0)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM event_v2_generations").fetchone()[0], 2)
        self.assertLessEqual(len(pipeline.core.prunable_archive_requests()), 3)
        self.assertEqual(pipeline.stream.latest(), [])
        self.assertEqual(pipeline.record([{"tsEpoch": 141, "message": "first real finding"}])["export"]["coverage"], "receipt-clear")
        self.assertEqual(pipeline.stream.latest(), [{"tsEpoch": 141, "message": "first real finding"}])

    def test_full_4096_record_observation_can_export_and_retire_as_one_archive(self):
        pipeline = self.open(True)
        events = [{"tsEpoch": n, "message": "synthetic"} for n in range(4096)]
        pipeline.record(events)
        for _ in range(43):
            pipeline.record([])
        self.assertEqual(pipeline.evidence()["coverage"], "receipt-clear")
        self.assertGreater(pipeline.core.retention_state()["frontiers"]["stabilityd"], 1)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 0)
        self.assertEqual(pipeline.stream.latest(), events[-50:])

    def test_unarchivable_payload_is_rejected_atomically_before_any_row_is_committed(self):
        pipeline = self.open(True)
        events = [{"tsEpoch": n, "message": "x" * 60000} for n in range(60)]
        with self.assertRaisesRegex(EventOutboxError, "pipeline-record-failed"):
            pipeline.record(events)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 0)
        self.assertIsNone(pipeline.core)
        recovered = self.open()
        self.assertEqual(self.connection.execute("SELECT state FROM event_v2_generations").fetchone()[0], "interrupted")
        recovered.record([{"tsEpoch": 61, "message": "independent valid observation"}])

    def test_export_failure_keeps_durable_batch_and_reports_unknown_without_raw_error(self):
        pipeline = self.open(True)
        with mock.patch.object(pipeline.stream, "drain", side_effect=EventStreamError("PRIVATE_FIXTURE_ERROR")):
            result = pipeline.record([{"tsEpoch": 1, "message": "synthetic"}])
        self.assertEqual(result["export"]["coverage"], "unknown")
        self.assertNotIn("PRIVATE_FIXTURE_ERROR", json.dumps(result))
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 1)

    def test_rejected_batch_ends_context_and_next_context_marks_incomplete_observation(self):
        pipeline = self.open(True)
        with self.assertRaises(EventOutboxError):
            pipeline.record([{"tsEpoch": 1, "invalid": float("nan")}])
        self.assertIsNone(pipeline.core)
        restored = self.open()
        row = self.connection.execute("SELECT state,expected_count FROM event_v2_generations").fetchone()
        self.assertEqual(tuple(row), ("interrupted", None))
        restored.record([{"tsEpoch": 2, "message": "new independent observation"}])


if __name__ == "__main__":
    unittest.main()
