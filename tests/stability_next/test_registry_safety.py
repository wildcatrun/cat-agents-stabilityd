import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
SPEC = importlib.util.spec_from_file_location("stabilityd_registry_test", MODULE_PATH)
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


REQUIRED_COLUMNS = (
    "agent_id", "runtime", "status", "platform", "execution_adapter",
    "can_receive_dispatch", "can_start_workflow", "gateway_proxy_allowed", "endpoint_ref",
)


class RegistrySafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = self.root / "workflow.db"
        self.snapshot = self.root / "runtime-agents.snapshot.json"
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(stabilityd, "WORKFLOW_DB", self.db).start()
        mock.patch.object(stabilityd, "WORKFLOW_RUNTIME_AGENTS_SNAPSHOT", self.snapshot).start()

    def write_snapshot(self, records=None, **overrides):
        payload = {
            "schemaVersion": 1,
            "workflowSchemaVersion": 1,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "records": records if records is not None else [self.row()],
        }
        payload.update(overrides)
        self.snapshot.write_text(json.dumps(payload), encoding="utf-8")

    @staticmethod
    def row(**overrides):
        record = {
            "agent_id": "catnose", "agent_key": "hermes_acp:catnose", "runtime": "hermes_acp",
            "status": "active", "platform": "hermes", "execution_adapter": "hermes_acp",
            "can_receive_dispatch": 1, "can_start_workflow": 0, "gateway_proxy_allowed": 0,
            "endpoint_ref": "hermes-profile:catnose", "updated_at": "2026-10-05T00:00:00Z",
        }
        record.update(overrides)
        return record

    def create_db(self, columns=REQUIRED_COLUMNS, rows=None):
        conn = sqlite3.connect(self.db)
        capability_columns = {"can_receive_dispatch", "can_start_workflow", "gateway_proxy_allowed"}
        conn.execute("CREATE TABLE runtime_agents (" + ", ".join(
            f"{column} {'INTEGER' if column in capability_columns else 'TEXT'}" for column in columns
        ) + ")")
        for item in rows or []:
            item = {key: value for key, value in item.items() if key in columns}
            conn.execute(
                "INSERT INTO runtime_agents (" + ", ".join(item) + ") VALUES (" + ", ".join("?" for _ in item) + ")",
                list(item.values()),
            )
        conn.commit()
        conn.close()

    def test_snapshot_is_observation_only_and_missing_capabilities_stay_unknown(self):
        row = self.row()
        del row["can_receive_dispatch"]
        del row["can_start_workflow"]
        self.write_snapshot([row])

        registry = stabilityd.workflow_runtime_registry_records()

        self.assertFalse(registry["writeEligible"])
        self.assertEqual(registry["snapshotHealth"], "incomplete_records")
        self.assertEqual(registry["records"], [])
        self.assertEqual(stabilityd.active_openclaw_agent_ids_from_registry(registry), [])

    def test_stale_future_unversioned_or_bad_timestamp_snapshots_expose_no_targets(self):
        now = int(datetime.now(timezone.utc).timestamp())
        cases = [
            ({"generatedAt": datetime.fromtimestamp(now - 901, timezone.utc).isoformat()}, "stale"),
            ({"generatedAt": datetime.fromtimestamp(now + 301, timezone.utc).isoformat()}, "future_timestamp"),
            ({"generatedAt": "not-a-time"}, "missing_or_invalid_timestamp"),
            ({"generatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": 88}, "unsupported_schema"),
        ]
        for overrides, expected_health in cases:
            with self.subTest(expected_health=expected_health):
                self.write_snapshot(**overrides)
                registry = stabilityd.workflow_runtime_registry_records()
                self.assertEqual(registry["snapshotHealth"], expected_health)
                self.assertEqual(registry["records"], [])
                self.assertEqual(stabilityd.active_openclaw_agent_ids_from_registry(registry), [])
                profiles, meta = stabilityd.hermers_profiles_from_runtime_registry([], registry)
                self.assertEqual(profiles, {})
                self.assertFalse(meta["scopeComplete"])

    def test_mixed_valid_and_malformed_snapshot_records_expose_no_targets(self):
        self.write_snapshot(records=[self.row(), {}])
        registry = stabilityd.workflow_runtime_registry_records()
        self.assertEqual(registry["snapshotHealth"], "incomplete_records")
        self.assertEqual(registry["records"], [])

    def test_snapshot_legacy_runtime_registry_shape_is_not_promoted(self):
        self.write_snapshot(records=[], runtimeRegistry={"hermes_acp": [self.row()]})
        registry = stabilityd.workflow_runtime_registry_records()
        self.assertEqual(registry["source"], "snapshot")
        self.assertEqual(registry["snapshotHealth"], "incomplete_records")
        self.assertFalse(registry["writeEligible"])
        self.assertEqual(registry["records"], [])

    def test_db_missing_uses_snapshot_only_for_observation(self):
        self.write_snapshot()
        registry = stabilityd.workflow_runtime_registry_records()
        self.assertEqual(registry["source"], "snapshot")
        self.assertFalse(registry["writeEligible"])
        profiles, meta = stabilityd.hermers_profiles_from_runtime_registry([], registry)
        self.assertIn("catnose", profiles)
        self.assertFalse(meta["scopeComplete"])

    def test_damaged_database_is_distinct_and_snapshot_never_grants_writes(self):
        original = b"not-a-sqlite-database" * 32
        self.db.write_bytes(original)
        self.write_snapshot()
        registry = stabilityd.workflow_runtime_registry_records()
        self.assertEqual(registry["fallbackReason"], "workflow_db_error")
        self.assertEqual(registry["dbError"], "DatabaseError")
        self.assertFalse(registry["writeEligible"])
        self.assertEqual(self.db.read_bytes(), original)
        _, meta = stabilityd.hermers_profiles_from_runtime_registry([], registry)
        self.assertFalse(meta["scopeComplete"])

    def test_existing_database_without_registry_table_is_distinct(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE unrelated(value TEXT)")
        self.write_snapshot()
        registry = stabilityd.workflow_runtime_registry_records()
        self.assertEqual(registry["fallbackReason"], "runtime_agents_table_missing")
        self.assertEqual(registry["dbError"], "runtime_agents table not found")
        self.assertTrue(registry["exists"])
        self.assertFalse(registry["writeEligible"])
        _, meta = stabilityd.hermers_profiles_from_runtime_registry([], registry)
        self.assertFalse(meta["scopeComplete"])

    def test_valid_empty_db_is_authoritative_and_does_not_restore_snapshot(self):
        self.create_db()
        self.write_snapshot()
        registry = stabilityd.workflow_runtime_registry_records()
        self.assertEqual(registry["source"], "db")
        self.assertTrue(registry["writeEligible"])
        self.assertEqual(registry["records"], [])

    def test_incomplete_db_schema_blocks_scope_without_snapshot_fallback(self):
        self.create_db(columns=("agent_id", "runtime"))
        self.write_snapshot()
        registry = stabilityd.workflow_runtime_registry_records()
        self.assertEqual(registry["source"], "db")
        self.assertFalse(registry["writeEligible"])
        self.assertEqual(registry["records"], [])
        self.assertIn("status", registry["missingRequiredColumns"])

    def test_explicit_null_capability_is_not_dispatch_eligible(self):
        self.create_db(rows=[self.row(can_receive_dispatch=None)])
        registry = stabilityd.workflow_runtime_registry_records()
        self.assertFalse(registry["writeEligible"])
        self.assertEqual(stabilityd.active_openclaw_agent_ids_from_registry(registry), [])


if __name__ == "__main__":
    unittest.main()
