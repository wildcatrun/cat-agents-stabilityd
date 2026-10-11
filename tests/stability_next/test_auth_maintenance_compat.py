import importlib.util
import json
import sys
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "compat" / "auth_maintenance_plan_v1.json"
SPEC = importlib.util.spec_from_file_location("stabilityd_auth_maintenance_compat_test",
                                               ROOT / "bin" / "cat_agents_stabilityd.py")
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class AuthMaintenanceCompatibilityTests(unittest.TestCase):
    def test_server_executor_refuses_refresh_even_with_misconfigured_broker_and_real_token(self):
        sentinel = "SYNTHETIC_REAL_REFRESH_MISCONFIGURATION"
        for broker_enabled in (False, True):
            with self.subTest(broker_enabled=broker_enabled), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                conn = sqlite3.connect(str(root / "state.db"))
                conn.execute("CREATE TABLE actions (id INTEGER PRIMARY KEY, ts_epoch INTEGER, "
                             "action_id TEXT, action TEXT, result TEXT, payload TEXT)")
                plan = {"actions": [{"actionId": "fixture-refresh", "target": "codex-cli",
                    "kind": "refresh", "canAutoRun": True, "humanGateRequired": False,
                    "refresh_token": sentinel, "access_token": sentinel}]}
                try:
                    with mock.patch.object(stabilityd, "AUTH_REFRESH_BROKER_ENABLED", broker_enabled), \
                         mock.patch.object(stabilityd, "AUTH_REFRESH_BROKER_LOCK_PATH", root / "broker.lock"), \
                         mock.patch.object(stabilityd, "ACTIONS_JSONL", root / "actions.jsonl"), \
                         mock.patch.object(stabilityd, "run_mac_codex_oauth_mirror",
                                           side_effect=AssertionError("server cannot mirror or refresh")), \
                         mock.patch.object(stabilityd.subprocess, "run",
                                           side_effect=AssertionError("no external command")):
                        result = stabilityd.execute_auth_maintenance_plan(conn, plan)
                    execution = result["executions"][0]
                    self.assertEqual(execution["result"], "blocked")
                    self.assertEqual(execution["blockedReason"],
                        "mac-codex-is-refresh-owner" if broker_enabled else "refresh-broker-disabled")
                    self.assertTrue(execution["tokenValuesRedacted"])
                    row = conn.execute("SELECT result, payload FROM actions").fetchone()
                    self.assertEqual(row[0], "blocked")
                    self.assertNotIn(sentinel, row[1])
                    self.assertNotIn(sentinel, str(result))
                    self.assertNotIn(sentinel, (root / "actions.jsonl").read_text())
                finally:
                    conn.close()

    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_planner_matches_pinned_baseline_projection(self):
        self.assertEqual(self.fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        constants = self.fixture["constants"]
        self.assertFalse(constants["AUTH_REFRESH_BROKER_ENABLED"])
        self.assertFalse(stabilityd.AUTH_REFRESH_BROKER_ENABLED,
                         "dev-server auth refresh broker must remain disabled")
        for case in self.fixture["cases"]:
            with self.subTest(case=case["name"]), \
                 mock.patch.object(stabilityd, "AUTH_WARN_SECONDS", constants["AUTH_WARN_SECONDS"]), \
                 mock.patch.object(stabilityd, "AUTH_CRITICAL_SECONDS", constants["AUTH_CRITICAL_SECONDS"]), \
                 mock.patch.object(stabilityd, "AUTH_OPENAI_PROVIDER_IDS",
                                   set(constants["AUTH_OPENAI_PROVIDER_IDS"])), \
                 mock.patch.object(stabilityd, "AUTH_REFRESH_BROKER_ENABLED",
                                   constants["AUTH_REFRESH_BROKER_ENABLED"]), \
                 mock.patch.object(stabilityd, "SEVERITY_RANK", constants["SEVERITY_RANK"]), \
                 mock.patch.object(stabilityd, "ts", return_value="2026-10-06T00:00:00Z"), \
                 mock.patch.object(stabilityd.time, "time_ns", return_value=1791244800000000000):
                actual = stabilityd.build_auth_maintenance_plan(case["auth"], case["findings"])
            self.assertEqual(actual, case["expectedPlan"])

    def test_refresh_owner_redaction_and_human_gate_invariants(self):
        cases = {case["name"]: case for case in self.fixture["cases"]}
        routed = cases["refresh-owner-and-action-routing"]["expectedPlan"]
        self.assertEqual(routed["macCodexExecutor"]["refreshOwner"], "mac-codex")
        self.assertFalse(routed["refreshBrokerEnabled"])
        actions = {item["actionId"]: item for item in routed["actions"]}
        codex = actions["codex_cli_mirror_required"]
        self.assertEqual(codex["target"], "codex-cli")
        self.assertEqual(codex["blockedReason"], "delegated-to-mac-codex")
        self.assertTrue(codex["localAutomation"]["eligible"])
        self.assertFalse(codex["canAutoRun"])
        self.assertEqual(actions["openclaw_main_required_provider_reauth-2"]["humanGateRequired"], True)
        self.assertTrue(actions["hermers_catheart_reauth_required"]["humanGateRequired"])
        for action in routed["actions"]:
            with self.subTest(action=action["actionId"]):
                self.assertTrue(action["tokenValuesRedacted"])
                self.assertFalse(action["canAutoRun"])

        scoped = cases["incomplete-runtime-scopes-fail-closed"]["expectedPlan"]
        scoped_actions = {item["actionId"]: item for item in scoped["actions"]}
        for action_id in ("openclaw_registry_auth_scope_incomplete",
                          "hermers_runtime_profile_registry_unavailable"):
            with self.subTest(action=action_id):
                self.assertTrue(scoped_actions[action_id]["humanGateRequired"])
                self.assertFalse(scoped_actions[action_id]["canAutoRun"])
                self.assertEqual(scoped_actions[action_id]["kind"], "scope-repair")
        self.assertTrue(all(item["tokenValuesRedacted"] for item in scoped["actions"]))
        expected_plans = [case["expectedPlan"] for case in self.fixture["cases"]]
        self.assertNotIn("SYNTHETIC_TOKEN_SENTINEL", json.dumps(expected_plans, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
