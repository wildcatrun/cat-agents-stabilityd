import contextlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stability_core import generation


ROOT = Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


stabilityd = load_module("stabilityd_cli_compat_test", ROOT / "bin" / "cat_agents_stabilityd.py")
mcp = load_module("stability_mcp_compat_test", ROOT / "scripts" / "cat_agents_stability_mcp.py")
FIXTURES = ROOT / "tests" / "fixtures" / "compat"


class CliCompatibilityTests(unittest.TestCase):
    def test_default_status_is_read_only_and_keeps_summary_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            latest_path, policy_path = Path(tmp) / "latest.json", Path(tmp) / "policy.json"
            latest_path.write_text(json.dumps({"checkedAt": "checked", "completedAt": "done",
                                               "severity": "low", "findings": [{"key": "x"}],
                                               "actions": [{"action": "none"}]}))
            policy_path.write_text(json.dumps({"mode": "observe"}))
            output = []
            with mock.patch.object(stabilityd, "LATEST_PATH", latest_path), \
                 mock.patch.object(stabilityd, "POLICY_PATH", policy_path), \
                 mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0), \
                 mock.patch.object(stabilityd, "init_db", side_effect=AssertionError("status must not open DB")), \
                 mock.patch.object(stabilityd, "gateway_collect", side_effect=AssertionError("status must not probe")):
                self.assertEqual(stabilityd.main([]), 0)
            self.assertEqual(output, [{
                "checkedAt": "checked", "completedAt": "done", "severity": "low", "mode": "observe",
                "policyAgeSeconds": mock.ANY, "findingCount": 1, "lastActions": [{"action": "none"}],
            }])

    def test_cli_status_summary_matches_pinned_baseline_cases(self):
        fixture = json.loads((FIXTURES / "cli_status_summary_v1.json").read_text())
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            latest_path, policy_path = root / "latest.json", root / "policy.json"
            for case in fixture["cases"]:
                with self.subTest(case=case["name"]):
                    latest_path.write_text(json.dumps(case["latest"]))
                    policy_path.write_text(json.dumps(case["policy"]))
                    output = []
                    with mock.patch.object(stabilityd, "LATEST_PATH", latest_path), \
                         mock.patch.object(stabilityd, "POLICY_PATH", policy_path), \
                         mock.patch.object(stabilityd, "epoch", return_value=case["nowEpoch"]), \
                         mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0), \
                         mock.patch.object(stabilityd, "init_db", side_effect=AssertionError("status must not open DB")), \
                         mock.patch.object(stabilityd, "gateway_collect", side_effect=AssertionError("status must not probe")):
                        self.assertEqual(stabilityd.main(["status"]), 0)
                    self.assertEqual(output, [case["expected"]])

    def test_help_retains_commands_and_mcp_only_builds_allowlisted_args(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            stabilityd.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        help_text = stdout.getvalue()
        commands = {"daemon", "once", "status", "snapshot", "policy", "lanes", "auth-readiness",
                    "nodes", "surfaces", "preflight", "recovery", "action-classes",
                    "auth-maintenance", "auth-mirror", "profile-modes", "desired-state", "drift",
                    "findings", "workflow-evidence", "actions", "events", "runbook", "doctor", "repair"}
        self.assertTrue(all(command in help_text for command in commands))
        allowed = {"status", "snapshot", "policy", "lanes", "profile-modes", "desired-state", "drift",
                   "nodes", "surfaces",
                   "preflight", "recovery", "action-classes",
                   "findings", "workflow-evidence", "actions", "events", "runbook", "auth-readiness",
                   "auth-maintenance", "auth-mirror", "doctor", "repair", "once"}
        for action in allowed:
            self.assertEqual(mcp.stability_cli_args(action, {})[0], action)
        self.assertEqual(mcp.stability_cli_args("actions", {"limit": 7}), ["actions", "--limit", "7"])
        self.assertEqual(mcp.stability_cli_args("recovery", {"limit": 7}), ["recovery", "--limit", "7"])
        for invalid_limit in (0, 1001, 1.5, True):
            with self.assertRaises(ValueError):
                mcp.stability_cli_args("recovery", {"limit": invalid_limit})
        with self.assertRaises(ValueError):
            mcp.stability_cli_args("arbitrary-shell", {})
        with mock.patch.dict("os.environ", {"CAT_AGENTS_STABILITY_MCP_ALLOW_AUTH_MIRROR": "0"}):
            self.assertEqual(mcp.stability_cli_args("auth-mirror", {"apply": True}), ["auth-mirror"])
            blocked = mcp.stability_cli_args("auth-maintenance", {"fresh": True, "execute": True, "allowMirror": True})
            self.assertNotIn("--allow-mirror", blocked)
        with mock.patch.dict("os.environ", {"CAT_AGENTS_STABILITY_MCP_ALLOW_AUTH_MIRROR": "1"}):
            self.assertEqual(mcp.stability_cli_args("auth-mirror", {"apply": True}), ["auth-mirror", "--apply"])
            allowed_mirror = mcp.stability_cli_args(
                "auth-maintenance", {"fresh": True, "execute": True, "allowMirror": True})
            self.assertIn("--allow-mirror", allowed_mirror)
        self.assertEqual(mcp.stability_cli_args("doctor", {}), ["doctor", "--no-action"])
        self.assertEqual(mcp.stability_cli_args("once", {}), ["once", "--no-action"])
        self.assertEqual(mcp.stability_cli_args("repair", {}), ["repair", "--dry-run"])

    def test_v1_compatibility_fixtures_remain_supported(self):
        snapshot_path = Path(tempfile.mkdtemp()) / "runtime-agents.json"
        try:
            fixture = json.loads((FIXTURES / "runtime_registry_snapshot_v1.json").read_text())
            self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
            self.assertEqual(stabilityd._registry_snapshot_records(fixture), fixture["expectedRecords"])
            fixture["generatedAt"] = "2000-01-01T00:00:00Z"
            snapshot_path.write_text(json.dumps(fixture))
            with mock.patch.object(stabilityd, "WORKFLOW_RUNTIME_AGENTS_SNAPSHOT", snapshot_path), \
                 mock.patch.object(stabilityd, "epoch", return_value=946684860):
                result = stabilityd.workflow_runtime_registry_snapshot_records()
            self.assertEqual((result["snapshotSchemaVersion"], result["health"], result["writeEligible"]),
                             (1, "observation_only", False))
            self.assertEqual(result["records"][0]["agent_id"], "main")
            self.assertEqual(result["records"][0]["can_receive_dispatch"], 1)

            request_path = Path(tempfile.mkdtemp()) / "repair.json"
            request_path.write_text((FIXTURES / "repair_request_v1.json").read_text())
            request, error, source_schema = stabilityd.load_valid_repair_request(request_path)
            self.assertIsNone(error)
            self.assertEqual((request["jobId"], source_schema), ("fixture-job-1", 1))
        finally:
            shutil.rmtree(snapshot_path.parent, ignore_errors=True)
            if "request_path" in locals():
                shutil.rmtree(request_path.parent, ignore_errors=True)

    def test_wrapper_preserves_local_mirror_special_route(self):
        wrapper = (ROOT / "bin" / "cat-agents-stability").read_text()
        self.assertIn('if [[ "${1-}" == "auth-maintenance-local" ]]', wrapper)
        self.assertIn('scripts/mac_codex_oauth_mirror_maintenance.py', wrapper)

    def test_node_and_surface_commands_are_read_only_and_default_to_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            latest = Path(tmp) / "latest.json"
            latest.write_text("{}")
            output = []
            with mock.patch.object(stabilityd, "LATEST_PATH", latest), \
                 mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0), \
                 mock.patch.object(stabilityd, "init_db", side_effect=AssertionError("must remain read-only")), \
                 mock.patch.object(stabilityd, "gateway_collect", side_effect=AssertionError("must not probe")):
                self.assertEqual(stabilityd.main(["nodes"]), 0)
                self.assertEqual(stabilityd.main(["surfaces"]), 0)
            self.assertEqual(output[0]["coverage"]["observed"], 0)
            self.assertEqual(output[0]["coverage"]["prohibited"], 2)
            self.assertEqual(output[1]["coverage"]["observed"], 0)
            self.assertEqual(output[1]["coverage"]["prohibited"], 1)

    def test_preflight_recovery_and_action_classes_are_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            latest = root / "latest.json"
            policy_path = root / "policy.json"
            db_path = root / "missing.db"
            completed = stabilityd.dt.datetime.now(stabilityd.dt.timezone.utc).isoformat()
            latest.write_text(json.dumps({
                "generationId": "fixture-generation", "completedAt": completed, "severity": "ok",
                "policy": {"generationId": "fixture-generation", "mode": "observe"},
                "nodeObservations": [], "surfaceObservations": [],
            }))
            policy_path.write_text(json.dumps({"generationId": "fixture-generation", "mode": "observe"}))
            output = []
            with mock.patch.object(stabilityd, "LATEST_PATH", latest), \
                 mock.patch.object(stabilityd, "POLICY_PATH", policy_path), \
                 mock.patch.object(stabilityd, "STATE_DB", db_path), \
                 mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0), \
                 mock.patch.object(stabilityd, "init_db", side_effect=AssertionError("read-only command opened writable DB")), \
                 mock.patch.object(stabilityd, "gateway_collect", side_effect=AssertionError("must not probe")):
                self.assertEqual(stabilityd.main(["preflight"]), 0)
                self.assertEqual(stabilityd.main(["recovery"]), 0)
                self.assertEqual(stabilityd.main(["action-classes"]), 0)
            self.assertEqual(output[0]["preflightState"], "reviewable")
            self.assertFalse(output[0]["policy"]["authorizationEvaluated"])
            self.assertEqual(output[1]["ledgerStatus"], "missing")
            self.assertEqual(output[1]["recoveryState"], "unknown")
            self.assertFalse(db_path.exists())
            classes = {item["name"]: item["class"] for item in output[2]["commands"]["commands"]}
            self.assertEqual(classes["preflight"], "read")
            self.assertEqual(classes["workflow-evidence"], "evidence")
            self.assertEqual(classes["repair"], "mutate")

    def test_mcp_preflight_recovery_and_action_class_tools_are_allowlisted(self):
        listed = mcp.handle_request({"id": 1, "method": "tools/list", "params": {}})
        names = {item["name"] for item in listed["result"]["tools"]}
        self.assertTrue({"stability_preflight", "stability_recovery", "stability_action_classes"} <= names)
        for name, handler, action in (
            ("stability_preflight", "preflight", "preflight"),
            ("stability_recovery", "recovery", "recovery"),
            ("stability_action_classes", "action_classes", "action-classes"),
        ):
            with mock.patch.object(mcp, handler, return_value={"ok": True}) as call:
                response = mcp.handle_request({"id": 2, "method": "tools/call",
                                               "params": {"name": name, "arguments": {"source": "local"}}})
            self.assertEqual(response["id"], 2)
            call.assert_called_once_with({"source": "local"})
            self.assertIn("content", response["result"])
            self.assertEqual(mcp.stability_cli_args(action, {"limit": 7})[0], action)

    def test_mcp_tool_schemas_preserve_pinned_baseline_and_only_add_allowlisted_tools(self):
        fixture = json.loads((FIXTURES / "mcp_tools_schema_v1.json").read_text())
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        listed = mcp.handle_request({"id": 1, "method": "tools/list", "params": {}})
        names = [item["name"] for item in listed["result"]["tools"]]
        self.assertEqual(len(names), len(set(names)))
        candidate = {item["name"]: item["inputSchema"] for item in listed["result"]["tools"]}
        baseline = fixture["tools"]
        self.assertEqual(len(candidate), len(baseline) + len(fixture["additiveCandidateTools"]))
        self.assertTrue(set(baseline) <= set(candidate))
        for name, schema in baseline.items():
            with self.subTest(tool=name):
                self.assertEqual(candidate[name], schema)
        self.assertEqual(set(candidate) - set(baseline), set(fixture["additiveCandidateTools"]))
        self.assertTrue(all(schema.get("additionalProperties") is False for schema in candidate.values()))

    def test_mcp_cli_routes_match_pinned_baseline_cases(self):
        fixture = json.loads((FIXTURES / "mcp_cli_routes_v1.json").read_text())
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        for case in fixture["cases"]:
            with self.subTest(action=case["action"], allow=case["allowAuthMirror"]), \
                 mock.patch.dict("os.environ", {"CAT_AGENTS_STABILITY_MCP_ALLOW_AUTH_MIRROR": case["allowAuthMirror"]}):
                actual = mcp.stability_cli_args(case["action"], case["arguments"])
                self.assertEqual(actual, case["expectedArgv"])

    def test_mcp_jsonrpc_error_contract_matches_pinned_baseline(self):
        fixture = json.loads((FIXTURES / "mcp_errors_v1.json").read_text())
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        with mock.patch.object(mcp, "audit"):
            for case in fixture["cases"]:
                with self.subTest(case=case["name"]):
                    self.assertEqual(mcp.handle_request(case["request"]), case["expected"])

    def test_mcp_success_responses_match_pinned_baseline(self):
        fixture = json.loads((FIXTURES / "mcp_success_responses_v1.json").read_text())
        self.assertEqual(fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        expected_requests = {
            "initialize-default-protocol": {"id": "fixture-init-default", "method": "initialize", "params": {}},
            "initialize-explicit-protocol": {
                "id": "fixture-init-explicit", "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
            "tools-call-status-success-envelope": {
                "id": 7, "method": "tools/call",
                "params": {"name": "stability_status", "arguments": {"source": "local"}},
            },
        }
        cases_by_name = {case["name"]: case for case in fixture["cases"]}
        self.assertEqual(set(cases_by_name), set(expected_requests))
        self.assertEqual({name: case["request"] for name, case in cases_by_name.items()}, expected_requests)
        self.assertEqual(
            {name: case.get("handler") for name, case in cases_by_name.items()},
            {"initialize-default-protocol": None, "initialize-explicit-protocol": None,
             "tools-call-status-success-envelope": "status"},
        )
        for case in fixture["cases"]:
            with self.subTest(case=case["name"]), mock.patch.object(mcp, "audit"):
                expected = json.loads(json.dumps(case["expected"]))
                if case["request"].get("method") == "initialize":
                    # Retain the historic response fixture. The reviewed rc.1
                    # release changes only serverInfo.version in this envelope.
                    self.assertEqual(expected["result"]["serverInfo"]["version"], "0.1.0")
                    expected["result"]["serverInfo"]["version"] = "1.0.0-rc.1"
                    self.assertEqual(json.loads((ROOT / "package.json").read_text())["version"], "1.0.0-rc.1")
                    self.assertEqual(json.loads((ROOT / "openclaw.plugin.json").read_text())["version"], "1.0.0-rc.1")
                if case["name"] == "tools-call-status-success-envelope":
                    with mock.patch.object(mcp, "status", return_value=case["payload"]):
                        actual = mcp.handle_request(case["request"])
                else:
                    self.assertNotEqual(case["request"].get("method"), "tools/call")
                    actual = mcp.handle_request(case["request"])
                self.assertEqual(actual, expected)

    def test_cli_readers_ignore_uncommitted_newer_alias_after_partial_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            latest_path, policy_path, lanes_path = root / "latest.json", root / "policy.json", root / "lanes.json"
            old_policy = {"generationId": "g-old", "mode": "observe", "severity": "low",
                          "lanes": {"oldLane": {"status": "ok"}}}
            latest_path.write_text(json.dumps({"generationId": "g-old", "policy": old_policy,
                                               "severity": "low", "findings": [], "actions": []}))
            calls = []
            original = generation.write_json_atomic

            def fail_lanes(path, payload, **kwargs):
                if path == lanes_path:
                    raise OSError("simulated mid-publication crash")
                calls.append(path)
                return original(path, payload, **kwargs)

            new_policy = {"generationId": "g-new", "mode": "restart-storm", "severity": "critical"}
            with mock.patch.object(generation, "write_json_atomic", side_effect=fail_lanes):
                with self.assertRaises(OSError):
                    generation.publish_generation(
                        {"generationId": "g-new", "completedAt": "later"},
                        [(policy_path, new_policy), (lanes_path, {"generationId": "g-new", "newLane": {}})],
                        latest_path,
                    )
            self.assertEqual(calls, [policy_path])
            output = []
            with mock.patch.object(stabilityd, "LATEST_PATH", latest_path), \
                 mock.patch.object(stabilityd, "POLICY_PATH", policy_path), \
                 mock.patch.object(stabilityd, "LANE_POLICY_PATH", lanes_path), \
                 mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0):
                stabilityd.main(["policy"])
                stabilityd.main(["lanes"])
                stabilityd.main(["status"])
                runbook = stabilityd.runbook()
            self.assertEqual(output[0], old_policy)
            self.assertEqual(output[1], old_policy["lanes"])
            self.assertEqual(output[2]["mode"], "observe")
            self.assertEqual(runbook["mode"], "observe")
            self.assertEqual(runbook["lanes"], old_policy["lanes"])

    def test_legacy_latest_cannot_authenticate_generation_stamped_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            latest_path, policy_path = Path(tmp) / "latest.json", Path(tmp) / "policy.json"
            latest_path.write_text(json.dumps({"checkedAt": "2000-01-01T00:00:00Z", "severity": "low"}))
            policy_path.write_text(json.dumps({"generationId": "g-uncommitted", "mode": "restart-storm"}))
            output = []
            with mock.patch.object(stabilityd, "LATEST_PATH", latest_path), \
                 mock.patch.object(stabilityd, "POLICY_PATH", policy_path), \
                 mock.patch.object(stabilityd, "epoch", return_value=946684860), \
                 mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0):
                stabilityd.main(["policy"])
                stabilityd.main(["status"])
            self.assertEqual(output[0], {})
            self.assertIsNone(output[1]["mode"])
            self.assertEqual(output[1]["policyAgeSeconds"], 60)


if __name__ == "__main__":
    unittest.main()
