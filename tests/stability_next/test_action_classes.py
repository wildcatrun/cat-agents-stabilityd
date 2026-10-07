import unittest
import importlib.util
from pathlib import Path

from stability_core.action_classes import COMMAND_CLASSES, classify_action_types, classify_commands

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("action_class_mcp_test", ROOT / "scripts" / "cat_agents_stability_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(mcp)


class ActionClassTests(unittest.TestCase):
    def test_actuator_classes_are_explicit_and_show_effect_authority_boundary(self):
        result = classify_action_types()
        self.assertEqual(result["unknownTypes"], [])
        by_name = {item["name"]: item for item in result["actuators"]}
        self.assertEqual(by_name["openclaw.gateway.restart"]["class"], "mutate")
        self.assertIn("policy", by_name["openclaw.gateway.restart"]["authorization"])
        self.assertEqual(by_name["cron.stale_running_state.repair"]["humanGate"],
                         "recovery-escalation-required")
        self.assertTrue(all(item["dryRun"] == "observation-only-no-simulated-effect"
                            for item in result["actuators"]))

    def test_unknown_action_types_are_prohibited_not_guessed(self):
        result = classify_action_types(["future.restart", "openclaw.session.reset"])
        by_name = {item["name"]: item for item in result["actuators"]}
        self.assertEqual(by_name["future.restart"]["class"], "unknown/prohibited")
        self.assertEqual(by_name["future.restart"]["authorization"], "denied")
        self.assertIn("future.restart", result["unknownTypes"])

    def test_commands_distinguish_read_evidence_and_mutate(self):
        result = classify_commands()
        by_name = {item["name"]: item for item in result["commands"]}
        self.assertEqual(by_name["nodes"]["class"], "read")
        self.assertEqual(by_name["workflow-evidence"]["class"], "evidence")
        self.assertEqual(by_name["repair"]["class"], "mutate")
        self.assertEqual(by_name["auth-mirror"]["authorization"], "separate-human-gate-and-mac-owner")
        self.assertIn("--dry-run", by_name["repair"]["dryRunFlag"])

    def test_unknown_command_is_prohibited(self):
        result = classify_commands(["arbitrary-shell"])
        self.assertEqual(result["commands"][0]["class"], "unknown/prohibited")
        self.assertEqual(result["unknownCommands"], ["arbitrary-shell"])

    def test_command_class_allowlist_covers_every_registered_cli_command(self):
        stabilityd_path = ROOT / "bin" / "cat_agents_stabilityd.py"
        spec = importlib.util.spec_from_file_location("action_class_cli_test", stabilityd_path)
        cli = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(cli)
        commands = {"daemon", "once", "status", "snapshot", "policy", "lanes", "nodes", "surfaces",
                    "preflight", "recovery", "action-classes", "auth-readiness", "auth-maintenance",
                    "auth-mirror", "profile-modes", "desired-state", "drift", "findings", "workflow-evidence",
                    "actions", "events", "runbook", "doctor", "repair"}
        self.assertEqual(set(COMMAND_CLASSES), commands)
        by_name = {item["name"]: item for item in classify_commands()["commands"]}
        self.assertEqual(by_name["snapshot"]["effectBoundary"], "published-generation")
        self.assertEqual(by_name["runbook"]["class"], "read")
        recovery_schema = mcp.TOOLS["stability_recovery"]["inputSchema"]["properties"]["limit"]
        self.assertEqual(recovery_schema, {"type": "integer", "minimum": 1, "maximum": 1000})


if __name__ == "__main__":
    unittest.main()
