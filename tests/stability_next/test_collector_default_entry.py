"""Exercise the actual default collector route without runtime/network effects."""
import contextlib
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("collector_default_entry_test", ROOT / "bin/cat_agents_stabilityd.py")
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


class CollectorDefaultEntryTests(unittest.TestCase):
    def collect(self, failed=None):
        conn = m.init_memory_kv_db()
        calls = []
        def boundary(name, command, fallback, **kwargs):
            calls.append((name, command, kwargs))
            data = dict(fallback)
            if name == "hermers":
                data["profiles"] = {"synthetic_profile": {}}
            probe = {"component": name, "status": "error" if name == failed else "ok",
                     "source": kwargs["source"], "coverage": name != failed,
                     "durationMs": 1, "budgetMs": kwargs["budget_ms"],
                     "maxOutputBytes": kwargs["max_output_bytes"],
                     "errorClass": "SyntheticProbeFailure" if name == failed else None,
                     "noLiveGroupMemberObserved": True}
            return {"data": data, "probe": probe, "findings": [], "cacheUpdates": {}}
        try:
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(m, "run_component_probe_hard", side_effect=boundary))
                stack.enter_context(mock.patch.object(m, "run_component_probe", side_effect=AssertionError("soft runner selected")))
                stack.enter_context(mock.patch.object(m, "collector_worker_environment", return_value={"FIXTURE": "isolated"}))
                stack.enter_context(mock.patch.object(m, "stabilityd_progress_evidence", return_value={"state": "first_observation"}))
                stack.enter_context(mock.patch.object(m, "_inspection_cache_enabled", False))
                stack.enter_context(mock.patch.object(m, "update_runtime_trends", return_value={}))
                stack.enter_context(mock.patch.object(m, "update_streaks", return_value={}))
                stack.enter_context(mock.patch.object(m, "add_resource_governance_findings"))
                stack.enter_context(mock.patch.object(m, "policy_from_findings", return_value={"mode": "synthetic"}))
                stack.enter_context(mock.patch.object(m, "build_auth_maintenance_plan", return_value={}))
                stack.enter_context(mock.patch.object(m, "run_cmd", side_effect=AssertionError("runtime command forbidden")))
                result = m.collect_snapshot(conn)  # Deliberately no injected runner argument.
            return result, calls
        finally:
            conn.close()

    def test_default_route_resolves_hard_runner_and_preserves_worker_contract(self):
        (snapshot, findings, policy), calls = self.collect()
        names = [row[0] for row in calls]
        self.assertEqual(names, ["gateway", "cron", "session", "channel", "hermers", "auth", "resource", "config", "desired_state"])
        self.assertEqual(set(snapshot["collectorProbes"]), set(names))
        self.assertTrue(all(probe["coverage"] for probe in snapshot["collectorProbes"].values()))
        for name, command, kwargs in calls:
            self.assertEqual(command[:3], [sys.executable, str(ROOT / "bin/cat_agents_stabilityd.py"), "__component_probe_v1"])
            self.assertEqual(command[3], name)
            self.assertEqual(kwargs["env"][m._COMPONENT_PROBE_PARENT_PID_ENV], str(os.getpid()))
            self.assertEqual(kwargs["budget_ms"], m.COLLECTOR_BUDGET_MS)
        self.assertEqual(calls[5][1][4], '["synthetic_profile"]')
        self.assertEqual(policy["mode"], "synthetic")
        self.assertFalse(snapshot.get("collectorFatal", False))

    def test_default_route_incomplete_worker_surfaces_unknown_and_continues_other_components(self):
        (snapshot, findings, _), calls = self.collect(failed="gateway")
        self.assertEqual(len(calls), 9)
        self.assertFalse(snapshot["collectorProbes"]["gateway"]["coverage"])
        self.assertIsNone(snapshot["gateway"]["active"])
        self.assertIn("stability_collector_gateway_probe_failed", [finding["key"] for finding in findings])


if __name__ == "__main__":
    unittest.main()
