import importlib.util
import json
import signal
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
WRAPPER_PATH = ROOT / "remote-scripts" / "openclaw_cron_run_wrapper.py"
SPEC = importlib.util.spec_from_file_location("cron_wrapper_lease_lock_test", WRAPPER_PATH)
wrapper = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(wrapper)

MODULE_PATH = ROOT / "bin" / "cat_agents_stabilityd.py"
STABILITY_SPEC = importlib.util.spec_from_file_location("stabilityd_lease_lock_test", MODULE_PATH)
stabilityd = importlib.util.module_from_spec(STABILITY_SPEC)
assert STABILITY_SPEC and STABILITY_SPEC.loader
STABILITY_SPEC.loader.exec_module(stabilityd)


class CronLeaseLockContractTests(unittest.TestCase):
    def test_ambiguous_nonzero_or_missing_receipt_retains_attempted_lease(self):
        self.assertTrue(wrapper.should_retain_attempted_lease("attempted", 1, True))
        self.assertTrue(wrapper.should_retain_attempted_lease("attempted", None, False))
        self.assertFalse(wrapper.should_retain_attempted_lease("not-dispatched", 1, True))
        self.assertFalse(wrapper.should_retain_attempted_lease("attempted", 0, True))

    def test_uncertain_lease_blocks_same_job_but_not_other_jobs(self):
        with tempfile.TemporaryDirectory() as temp:
            leases = Path(temp)
            lease_path = leases / "uncertain.json"
            lease_path.write_text(json.dumps({"jobId": "job-a", "dispatchState": "attempted"}))
            with mock.patch.object(wrapper, "LEASES_DIR", leases):
                self.assertEqual(wrapper.unresolved_dispatch_lease("job-a")["jobId"], "job-a")
                self.assertIsNone(wrapper.unresolved_dispatch_lease("job-b"))

    def test_legacy_lease_without_dispatch_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            leases = Path(temp)
            (leases / "legacy.json").write_text(json.dumps({"jobId": "job-a", "runId": "legacy"}))
            with mock.patch.object(wrapper, "LEASES_DIR", leases):
                self.assertEqual(wrapper.unresolved_dispatch_lease("job-a")["runId"], "legacy")

    def test_success_receipt_does_not_release_residual_attempted_lease(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            leases = root / "leases"
            runs = root / "runs"
            leases.mkdir()
            runs.mkdir()
            lease = {"jobId": "job-a", "runId": "run-a", "dispatchState": "attempted"}
            (leases / "run-a.json").write_text(json.dumps(lease))
            valid = {"jobId": "job-a", "runId": "run-a", "dispatchState": "attempted",
                     "status": "succeeded", "result": {"returnCode": 0}, "finishedAtMs": 10}
            run_path = runs / "run-a.json"
            run_path.write_text(json.dumps({**valid, "runId": "wrong"}))
            with mock.patch.object(wrapper, "LEASES_DIR", leases), mock.patch.object(wrapper, "BY_RUN_DIR", runs):
                self.assertIsNotNone(wrapper.unresolved_dispatch_lease("job-a"))
                run_path.write_text(json.dumps({**valid, "result": {"returnCode": 1}}))
                self.assertIsNotNone(wrapper.unresolved_dispatch_lease("job-a"))
                run_path.write_text(json.dumps(valid))
                self.assertIsNotNone(wrapper.unresolved_dispatch_lease("job-a"))

    def test_ambiguous_cleanup_preserves_lease_and_blocks_next_reservation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            leases = root / "leases"
            runs = root / "runs"
            leases.mkdir()
            runs.mkdir()
            lease_path = leases / "first.json"
            record = {"runId": "first", "jobId": "job-a", "startedAtMs": 1,
                      "leaseExpiresAtMs": 1000, "leaseOwner": "host:1", "fencingToken": 1,
                      "dispatchState": "attempted", "status": "failed"}
            lease_path.write_text(json.dumps(wrapper.build_lease_record(record)))
            (runs / "first.json").write_text(json.dumps(record))
            with mock.patch.object(wrapper, "LEASES_DIR", leases), mock.patch.object(wrapper, "BY_RUN_DIR", runs):
                self.assertTrue(wrapper.cleanup_dispatch_lease(lease_path, record, 1, True))
                self.assertTrue(lease_path.exists())
                next_record = {"runId": "second", "jobId": "job-a", "startedAtMs": 2,
                               "leaseExpiresAtMs": 1001, "leaseOwner": "host:2", "fencingToken": 2}
                allowed, _ = wrapper.reserve_cron_run(next_record, runs / "second.json", leases / "second.json")
                self.assertFalse(allowed)

    def test_success_bookkeeping_failures_do_not_create_retry_result(self):
        record = {"status": "succeeded", "result": {"returnCode": 0}}
        with mock.patch.object(wrapper, "persist_post_run_admission", side_effect=OSError("disk")), \
             mock.patch.object(wrapper, "write_job_summary", side_effect=RuntimeError("summary")):
            failures = wrapper.post_success_bookkeeping(record, None)
        self.assertEqual(failures, ["OSError", "RuntimeError"])
        self.assertEqual(record["status"], "succeeded")
        self.assertEqual(record["result"]["returnCode"], 0)
        self.assertFalse(wrapper.should_retain_attempted_lease("attempted", 0, True))

    def test_success_lease_unlink_failure_stays_fenced_and_warning_is_nonfatal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            leases = root / "leases"
            runs = root / "runs"
            leases.mkdir()
            runs.mkdir()
            lease_path = leases / "run-a.json"
            lease_path.write_text(json.dumps({"jobId": "job-a", "runId": "run-a", "dispatchState": "attempted"}))
            record = {"jobId": "job-a", "runId": "run-a", "dispatchState": "attempted",
                      "status": "succeeded", "finishedAtMs": 3, "result": {"returnCode": 0}}
            (runs / "run-a.json").write_text(json.dumps(record))
            with mock.patch.object(wrapper, "LEASES_DIR", leases), mock.patch.object(wrapper, "BY_RUN_DIR", runs), \
                 mock.patch.object(Path, "unlink", side_effect=PermissionError("read-only")):
                retained = wrapper.cleanup_dispatch_lease(lease_path, record, 0, True)
                with mock.patch.object(wrapper, "print", side_effect=BrokenPipeError("closed"), create=True):
                    wrapper.emit_safe_warning("sanitized warning")
                self.assertTrue(retained)
                self.assertTrue(lease_path.exists())
                self.assertIsNotNone(wrapper.unresolved_dispatch_lease("job-a"))

    def test_same_job_run_reservation_is_atomic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            leases = root / "leases"
            runs = root / "runs"
            leases.mkdir()
            runs.mkdir()
            outcomes = []
            errors = []

            def reserve(index):
                record = {"runId": f"run-{index}", "jobId": "job-a", "startedAtMs": 1,
                          "leaseExpiresAtMs": 1000, "leaseOwner": f"host:{index}", "fencingToken": index}
                try:
                    outcomes.append(wrapper.reserve_cron_run(record, runs / f"{index}.json", leases / f"{index}.json")[0])
                except Exception as exc:
                    errors.append(exc)

            with mock.patch.object(wrapper, "LEASES_DIR", leases), \
                 mock.patch.object(wrapper, "BY_RUN_DIR", runs), \
                 mock.patch.object(wrapper, "lease_mutation_lock", wraps=wrapper.lease_mutation_lock):
                threads = [threading.Thread(target=reserve, args=(index,)) for index in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=2)
            self.assertFalse(errors)
            self.assertCountEqual(outcomes, [True, False])

    def test_workload_preexec_installs_parent_death_signal_before_exec(self):
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(wrapper.sys, "platform", "linux"), \
             mock.patch.object(wrapper.ctypes, "CDLL", return_value=libc), \
             mock.patch.object(wrapper.os, "getppid", return_value=1234):
            wrapper.install_parent_death_signal(1234)
        libc.prctl.assert_called_once_with(1, signal.SIGKILL, 0, 0, 0)

    def test_workload_preexec_kills_child_if_parent_died_before_prctl_guard(self):
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(wrapper.sys, "platform", "linux"), \
             mock.patch.object(wrapper.ctypes, "CDLL", return_value=libc), \
             mock.patch.object(wrapper.os, "getppid", return_value=999), \
             mock.patch.object(wrapper.os, "getpid", return_value=222), \
             mock.patch.object(wrapper.os, "kill", side_effect=ProcessLookupError) as kill:
            with self.assertRaises(ProcessLookupError):
                wrapper.install_parent_death_signal(1234)
        kill.assert_called_once_with(222, signal.SIGKILL)

    def test_workload_preexec_fails_closed_when_pdeathsig_cannot_be_installed(self):
        libc = mock.Mock()
        libc.prctl.return_value = -1
        with mock.patch.object(wrapper.sys, "platform", "linux"), \
             mock.patch.object(wrapper.ctypes, "CDLL", return_value=libc), \
             mock.patch.object(wrapper.ctypes, "get_errno", return_value=1):
            with self.assertRaises(OSError):
                wrapper.install_parent_death_signal(1234)

    def test_runner_heartbeat_and_stabilityd_reap_share_exclusive_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            leases = Path(directory) / "leases"
            leases.mkdir()
            entered = threading.Event()
            finished = threading.Event()

            def acquire_stability_lock():
                with stabilityd.lease_mutation_lock():
                    entered.set()
                finished.set()

            with mock.patch.object(wrapper, "LEASES_DIR", leases), \
                 mock.patch.object(stabilityd, "LEASE_DIR", leases):
                with wrapper.lease_mutation_lock():
                    thread = threading.Thread(target=acquire_stability_lock, daemon=True)
                    thread.start()
                    time.sleep(0.05)
                    self.assertFalse(entered.is_set(), "stabilityd entered while wrapper held shared lease lock")
                self.assertTrue(entered.wait(1), "stabilityd did not acquire the released wrapper lease lock")
                self.assertTrue(finished.wait(1))
                thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
