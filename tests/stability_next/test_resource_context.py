import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "stabilityd_resource_test", Path(__file__).resolve().parents[2] / "bin/cat_agents_stabilityd.py"
)
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
SPEC.loader.exec_module(stabilityd)


class ResourceContextTest(unittest.TestCase):
    def fixtures(self, root, mode="1"):
        for name, data in {
            "sys/vm/overcommit_memory": mode,
            "pressure/memory": "some avg10=1.0 avg60=0.2 avg300=0.1 total=200\nfull avg10=0.1 avg60=0.0 avg300=0.0 total=20\n",
            "vmstat": "pswpin 8\npswpout 20\npgmajfault 4\noom_kill 2\nnot_requested 100\n",
        }.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)

    def test_overcommit_and_pressure_are_context_not_recent_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixtures(root)
            value = stabilityd.memory_pressure_context(root)
            self.assertEqual(value["status"], "ok")
            self.assertEqual(value["overcommitMode"], 1)
            self.assertEqual(value["vmstatCounters"]["oom_kill"], 2)
            self.assertNotIn("not_requested", value["vmstatCounters"])
            self.assertIn("not evidence", value["counterScope"])
            self.fixtures(root, "2")
            self.assertIn("strict", stabilityd.memory_pressure_context(root)["commitInterpretation"])

    def test_missing_or_malformed_context_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            value = stabilityd.memory_pressure_context(root)
            self.assertEqual(value["status"], "partial")
            self.assertIsNone(value["psi"])
            self.assertEqual(set(value["probeErrors"]), {"overcommit", "psi", "vmstat"})
            self.fixtures(root, "999")
            (root / "pressure/memory").write_text("some avg10=nan avg60=0 avg300=0 total=1\n")
            value = stabilityd.memory_pressure_context(root)
            self.assertIsNone(value["overcommitMode"])
            self.assertIsNone(value["psi"])

    def test_single_commit_indicator_does_not_restart(self):
        conn = stabilityd.init_memory_kv_db()
        try:
            findings = [{"key": "system_commit_saturation", "severity": "critical", "component": "resource"}]
            snapshot = {"gateway": {"active": True, "portOk": True, "startupGraceActive": False}}
            streaks = {"system_commit_saturation": {"count": 100}}
            with mock.patch.object(stabilityd, "SOFT_RESCUE_RESTART_ENABLED", True), mock.patch.object(
                stabilityd, "GATEWAY_RESTART_ENABLED", True
            ):
                policy = stabilityd.policy_from_findings(conn, findings, snapshot, streaks)
            self.assertFalse(policy["restartCandidate"])
            self.assertFalse(policy["canRestartGateway"])
        finally:
            conn.close()

    def test_partial_kernel_fields_remain_explicitly_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixtures(root)
            (root / "pressure/memory").write_text("some avg10=0 avg60=0 avg300=0 total=1\n")
            (root / "vmstat").write_text("pswpin 1\n")
            value = stabilityd.memory_pressure_context(root)
            self.assertEqual(value["status"], "partial")
            self.assertIsNone(value["psi"]["full"])
            self.assertIsNone(value["vmstatCounters"]["oom_kill"])
            self.assertIsNone(value["vmstatCounters"]["pswpout"])
            self.assertEqual(set(value["probeErrors"]), {"psi", "vmstat"})


if __name__ == "__main__":
    unittest.main()
