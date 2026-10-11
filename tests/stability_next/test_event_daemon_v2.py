import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("event_daemon_v2_test", ROOT / "bin/cat_agents_stabilityd.py")
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


class EventDaemonV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "state.db"
        self.patches = [mock.patch.object(m, "STATE_DB", self.path),
                        mock.patch.object(m, "EVENTS_JSONL", self.root / "events.jsonl"),
                        mock.patch.object(m, "EVENT_V2_ARCHIVE_ROOT", self.root / "archive"),
                        mock.patch.object(m, "ensure_dirs"),
                        mock.patch.object(m, "EVENT_OUTBOX_ENABLED", False),
                        mock.patch.object(m, "EVENT_OUTBOX_V2_ENABLED", True)]
        for patch in self.patches:
            patch.start()
        self.conn = None

    def tearDown(self):
        if self.conn is not None:
            self.conn.close()
        for patch in reversed(self.patches):
            patch.stop()
        self.tmp.cleanup()

    def test_actual_writer_opener_and_logger_preserve_legacy_payload_and_close_lock(self):
        self.conn = m.init_db()
        payload = {"tsEpoch": 1000, "message": "synthetic"}
        result = m.db_record_event(self.conn, payload)
        self.assertEqual(result["export"]["coverage"], "receipt-clear")
        self.assertEqual([json.loads(line) for line in m.EVENTS_JSONL.read_text().splitlines()], [payload])
        self.assertEqual(self.conn.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.conn.close()
        self.conn = m.init_db()
        self.assertEqual(m.event_pipeline_evidence(self.conn)["mode"], "outbox-v2")

    def test_flag_off_cannot_resume_legacy_writes_to_v2_store(self):
        self.conn = m.init_db()
        m.db_record_event(self.conn, {"tsEpoch": 1000})
        self.conn.close()
        self.conn = None
        with mock.patch.object(m, "EVENT_OUTBOX_V2_ENABLED", False), self.assertRaisesRegex(m.EventOutboxError, "protocol-config-mismatch"):
            m.init_db()
        with sqlite3.connect(self.path) as reader:
            self.assertEqual(reader.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
            self.assertEqual(reader.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 1)

    def test_nonempty_legacy_history_requires_audited_migration(self):
        with mock.patch.object(m, "EVENT_OUTBOX_V2_ENABLED", False):
            self.conn = m.init_db()
            m.db_record_event(self.conn, {"tsEpoch": 1000})
        self.conn.close()
        self.conn = None
        with self.assertRaisesRegex(m.EventOutboxError, "audited-migration-required"):
            m.init_db()
        with sqlite3.connect(self.path) as reader:
            self.assertEqual(reader.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
            self.assertFalse(reader.execute("SELECT 1 FROM sqlite_master WHERE name='event_v2_meta'").fetchone())

    def _synthetic_loop(self):
        snapshot = {"checkedAt": "2026-10-11T00:00:00+00:00", "checkedAtEpoch": 1000}
        findings = [{"key": key, "severity": "high", "component": "fixture", "message": key}
                    for key in ("first", "second")]
        policy = {"mode": "fixture"}
        return snapshot, findings, policy

    def _run_patched_loop(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(m, "ACTUATION_LOCK_PATH", self.root / "actuation.lock"))
            stack.enter_context(mock.patch.object(m, "ACTIONS_JSONL", self.root / "actions.jsonl"))
            stack.enter_context(mock.patch.object(m, "collect_snapshot", side_effect=lambda conn, **kwargs: self._synthetic_loop()))
            stack.enter_context(mock.patch.object(m, "control_plane_backpressure", return_value={}))
            actuator = stack.enter_context(mock.patch.object(m, "actuate_collected_snapshot", return_value=[
                {"tsEpoch": 1000, "actionId": "fixture", "action": "none", "result": "blocked"}]))
            stack.enter_context(mock.patch.object(m, "write_workflow_stability_evidence", return_value={"written": False}))
            stack.enter_context(mock.patch.object(m, "write_legacy_watchdog_health", return_value={}))
            stack.enter_context(mock.patch.object(m, "log_line"))
            stack.enter_context(mock.patch.object(m, "publish_generation", side_effect=lambda snapshot, *args: snapshot))
            result = m.run_once(self.conn, no_action=True)
            actuator.assert_called_once()
            self.assertTrue(actuator.call_args.kwargs["no_action"])
            return result

    def test_actual_run_once_groups_findings_and_persists_independent_actions(self):
        self.conn = m.init_db()
        result = self._run_patched_loop()
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM event_v2_generations").fetchone()[0], 1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 2)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 1)
        self.assertEqual(result["eventPipeline"]["coverage"], "receipt-clear")
        self.assertEqual(m.db_get(self.conn, "event:first"), 1000)

    def test_actual_run_once_export_failure_keeps_action_record_and_reports_unknown(self):
        from stability_core.event_stream_v2 import EventStreamError
        self.conn = m.init_db()
        pipeline = m.event_pipeline_v2(self.conn)
        with mock.patch.object(pipeline.stream, "drain", side_effect=EventStreamError("private-error")):
            result = self._run_patched_loop()
        self.assertEqual(result["eventPipeline"]["coverage"], "unknown")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 2)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 1)
        self.assertNotIn("private-error", json.dumps(result))

    def test_archive_capacity_error_degrades_only_events_and_preserves_action_record(self):
        self.conn = m.init_db()
        pipeline = m.event_pipeline_v2(self.conn)
        with mock.patch.object(pipeline, "maintain", side_effect=m.EventOutboxError("v2-archive-budget")):
            result = self._run_patched_loop()
        self.assertEqual(result["eventPipeline"]["coverage"], "unknown")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 2)

    def test_witness_or_schema_drift_still_blocks_before_collector_or_actuator(self):
        self.conn = m.init_db()
        pipeline = m.event_pipeline_v2(self.conn)
        with mock.patch.object(pipeline, "maintain", side_effect=m.EventOutboxError("v2-restore-frontier-drift")), \
                mock.patch.object(m, "ACTUATION_LOCK_PATH", self.root / "actuation.lock"), \
                mock.patch.object(m, "collect_snapshot") as collector, \
                mock.patch.object(m, "actuate_collected_snapshot") as actuator:
            with self.assertRaisesRegex(m.EventOutboxError, "v2-restore-frontier-drift"):
                m.run_once(self.conn, no_action=True)
        collector.assert_not_called()
        actuator.assert_not_called()

    def test_v1_identity_arguments_are_not_silently_reinterpreted_as_v2_retries(self):
        self.conn = m.init_db()
        with self.assertRaisesRegex(m.EventOutboxError, "batch-handle-required"):
            m.db_record_event(self.conn, {"tsEpoch": 1000}, generation="old-v1-context", seq=0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
