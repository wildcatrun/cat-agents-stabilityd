import importlib.util
import json
import sqlite3
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("stabilityd_cron_storage_contract", ROOT / "bin" / "cat_agents_stabilityd.py")
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class CronStorageAdapterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((ROOT / "tests" / "fixtures" / "compat" / "cron_storage_adapter_v1.json").read_text())

    def candidate_status(self, case):
        response = SimpleNamespace(
            returncode=case["returnCode"],
            stdout=json.dumps(case["payload"], separators=(",", ":")),
            stderr="",
        )
        with mock.patch.object(stabilityd, "run_cmd", return_value=response) as run_cmd:
            result = stabilityd.collect_cron_storage_status()
        run_cmd.assert_called_once_with(["openclaw", "cron", "status", "--json"], timeout=15)
        return result

    def test_successful_and_nonzero_structured_sqlite_status_match_pinned_adapter(self):
        self.assertEqual(self.fixture["baselineCommit"], "ece4157a38cc60dfbedc0268ca296f7775a956f0")
        for case in self.fixture["cases"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(self.candidate_status(case), case["expected"])
                self.assertEqual(case["expected"]["storage"], "sqlite")
                self.assertEqual(case["expected"]["available"], case["returnCode"] == 0)

    def test_sqlite_storage_blocks_legacy_stale_clear_but_keeps_observation(self):
        case = self.fixture["cases"][0]
        cron_status = self.candidate_status(case)
        with stabilityd.init_memory_kv_db() as conn, \
             mock.patch.object(stabilityd, "epoch", return_value=1791237600), \
             mock.patch.object(stabilityd, "ts", return_value="2026-10-05T22:00:00Z"), \
             mock.patch.object(stabilityd, "recent_restart_history", return_value=[]), \
             mock.patch.object(stabilityd, "recent_hermers_gateway_restart_history", return_value=[]):
            policy = stabilityd.policy_from_findings(
                conn,
                [],
                {
                    "gateway": {"active": True, "portOk": True, "healthOk": True},
                    "cron": {"storageStatus": cron_status},
                },
                {},
            )
            self.assertFalse(policy["canMutateCronState"])
            self.assertEqual(policy["cronMutationBlockedReason"], "openclaw-sqlite-cron-storage")

            snapshot = {"cron": {
                "storageStatus": cron_status,
                "staleRunning": [{"jobId": "fixture-job", "status": "running"}],
                "expiredLeases": [],
            }}
            with mock.patch.object(stabilityd, "cleanup_stale_tmp_files", return_value=[]), \
                 mock.patch.object(stabilityd, "update_repair_queue_status", return_value={}), \
                 mock.patch.object(stabilityd, "governed_clear_stale_running",
                                   side_effect=AssertionError("SQLite legacy stale-clear must not execute")) as clear, \
                 mock.patch.object(stabilityd, "governed_reap_expired_lease",
                                   side_effect=AssertionError("no fixture lease should be reaped")):
                actions = stabilityd.cron_actuate(snapshot, policy, snapshot_generation="fixture-generation")
            clear.assert_not_called()
            self.assertEqual(actions, [{
                "action": "observe_cron_repair_candidates",
                "result": "legacy_jobs_mutation_blocked_by_sqlite_storage",
                "storageStatus": cron_status,
                "staleRunningCount": 1,
                "expiredLeaseCount": 0,
            }])

    def test_nonzero_stderr_is_omitted_and_secret_sentinel_does_not_escape(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        response = SimpleNamespace(returncode=2, stdout="", stderr="错误 Authorization: Bearer " + sentinel)
        with mock.patch.object(stabilityd, "run_cmd", return_value=response):
            result = stabilityd.collect_cron_storage_status()
        self.assertFalse(result["available"])
        self.assertTrue(result["stderrOmitted"])
        self.assertEqual(result["stderrByteCount"], len(response.stderr.encode("utf-8")))
        self.assertNotIn(sentinel, json.dumps(result))
        self.assertNotIn("stderr", result)


if __name__ == "__main__":
    unittest.main()
