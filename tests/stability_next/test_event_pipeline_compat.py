import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "compat" / "event_pipeline_v1.json"
SPEC = importlib.util.spec_from_file_location("stabilityd_event_pipeline_compat_test",
                                               ROOT / "bin" / "cat_agents_stabilityd.py")
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


def create_event_table(conn):
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, "
        "source TEXT, component TEXT, severity TEXT, key TEXT, payload TEXT NOT NULL)"
    )


def read_event_rows(conn):
    names = ("id", "ts_epoch", "source", "component", "severity", "key", "payload")
    return [dict(zip(names, row)) for row in conn.execute(
        "SELECT id,ts_epoch,source,component,severity,key,payload FROM events ORDER BY id"
    )]


class EventPipelineCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_legacy_writer_database_and_events_cli_match_pinned_pipeline(self):
        self.assertEqual(self.fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "events.db"
            jsonl_path = root / "events.jsonl"
            conn = sqlite3.connect(db_path)
            create_event_table(conn)
            with mock.patch.object(stabilityd, "EVENTS_JSONL", jsonl_path), \
                 mock.patch.object(stabilityd, "epoch", return_value=1791244800):
                for event in self.fixture["inputEvents"]:
                    stabilityd.db_record_event(conn, event)
            rows = read_event_rows(conn)
            conn.close()
            self.assertEqual(rows, self.fixture["expectedRows"])
            self.assertEqual(len(jsonl_path.read_text(encoding="utf-8").splitlines()),
                             self.fixture["eventCount"])

            output = []
            with mock.patch.object(stabilityd, "EVENTS_JSONL", jsonl_path), \
                 mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0), \
                 mock.patch.object(stabilityd, "init_db", side_effect=AssertionError("events CLI must remain read-only")):
                self.assertEqual(stabilityd.main(["events"]), 0)
            self.assertEqual(output, [self.fixture["expectedCliEvents"]])
            self.assertEqual(len(output[0]), self.fixture["cliLimit"])

    def test_jsonl_append_failure_preserves_documented_partial_commit_semantics(self):
        failure = self.fixture["appendFailure"]
        self.assertEqual(failure["exceptionType"], "OSError")
        self.assertEqual(
            failure["semantics"],
            "SQLite commit precedes JSONL append; failure propagates and the event is not CLI-visible",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "events.db"
            jsonl_path = root / "events.jsonl"
            conn = sqlite3.connect(db_path)
            create_event_table(conn)
            with mock.patch.object(stabilityd, "EVENTS_JSONL", jsonl_path), \
                 mock.patch.object(stabilityd, "epoch", return_value=1791244800):
                for event in self.fixture["inputEvents"]:
                    stabilityd.db_record_event(conn, event)
            expected_row_count = self.fixture["eventCount"] + 1
            failed_event = self.fixture["appendFailureEvent"]
            with mock.patch.object(stabilityd, "EVENTS_JSONL", jsonl_path), \
                 mock.patch.object(stabilityd, "append_jsonl",
                                   side_effect=OSError("SYNTHETIC_JSONL_WRITE_FAILURE")):
                with self.assertRaisesRegex(OSError, "SYNTHETIC_JSONL_WRITE_FAILURE"):
                    stabilityd.db_record_event(conn, failed_event)
            conn.close()

            reader = sqlite3.connect(db_path)
            try:
                rows = read_event_rows(reader)
            finally:
                reader.close()
            self.assertEqual(len(rows), expected_row_count)
            self.assertEqual(rows[:-1], self.fixture["expectedRows"])
            self.assertEqual(json.loads(rows[-1]["payload"]), failed_event)
            self.assertEqual(len(jsonl_path.read_text(encoding="utf-8").splitlines()),
                             self.fixture["eventCount"])

            output = []
            with mock.patch.object(stabilityd, "EVENTS_JSONL", jsonl_path), \
                 mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0), \
                 mock.patch.object(stabilityd, "init_db", side_effect=AssertionError("events CLI must remain read-only")):
                self.assertEqual(stabilityd.main(["events"]), 0)
            self.assertEqual(output, [self.fixture["expectedCliEvents"]])
            self.assertNotIn(failed_event, output[0])


if __name__ == "__main__":
    unittest.main()
