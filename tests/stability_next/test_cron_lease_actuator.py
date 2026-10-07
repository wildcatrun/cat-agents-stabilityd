import importlib.util
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
SPEC = importlib.util.spec_from_file_location("stabilityd_cron_lease_actuator_test", MODULE_PATH)
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


def _dead_workload_metadata():
    return {"workloadOwner": {"host": socket.gethostname(), "pid": 987654322},
            "workloadState": "running", "dispatchState": "not-started"}


class CronLeaseActuatorTests(unittest.TestCase):
    def test_legacy_stale_running_state_is_blocked_without_gateway_writer_coordination(self):
        job_id = "cron-fixture"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            jobs_path = root / "cron" / "jobs.json"
            jobs_path.parent.mkdir(parents=True)
            jobs_path.write_text(json.dumps({"jobs": [{
                "id": job_id, "name": "fixture", "runningAtMs": stabilityd.now_ms() - 10_000_000,
            }]}), encoding="utf-8")
            pending_dir = root / "repairs" / "pending"
            processed_dir = root / "repairs" / "processed"
            pending_dir.mkdir(parents=True)
            processed_dir.mkdir(parents=True)
            policy = {"canMutateCronState": True}
            gate = {"status": "ready", "reason": "normal"}
            original = jobs_path.read_bytes()
            candidates = stabilityd.find_stale_running_jobs(json.loads(original))
            with mock.patch.object(stabilityd, "snapshot_jobs") as snapshot:
                result = stabilityd.governed_clear_stale_running(candidates, policy, gate, "fixture-generation")
            self.assertEqual(result["result"], "blocked", result)
            self.assertEqual(result["blockedReason"], "legacy-openclaw-jobs-store-has-uncoordinated-writer")
            snapshot.assert_not_called()
            self.assertEqual(jobs_path.read_bytes(), original)
            jobs = json.loads(jobs_path.read_text(encoding="utf-8"))
            self.assertIn("runningAtMs", jobs["jobs"][0])
            self.assertEqual(list(pending_dir.glob("*.json")), [])

    def test_stale_running_action_aggregate_exposes_native_recovery_block(self):
        job_id = "cron-race"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            jobs_path = root / "cron" / "jobs.json"
            jobs_path.parent.mkdir(parents=True)
            jobs_path.write_text(json.dumps({"jobs": [{
                "id": job_id, "runningAtMs": stabilityd.now_ms() - 10_000_000,
            }]}), encoding="utf-8")
            pending_dir = root / "repairs" / "pending"
            processed_dir = root / "repairs" / "processed"
            pending_dir.mkdir(parents=True)
            processed_dir.mkdir(parents=True)
            policy = {"canMutateCronState": True, "updatedAtEpoch": stabilityd.epoch() - 1,
                      "validUntilEpoch": stabilityd.epoch() + 60}
            gate = {"status": "ready", "reason": "normal"}
            candidates = stabilityd.find_stale_running_jobs(json.loads(jobs_path.read_text(encoding="utf-8")))
            with mock.patch.object(stabilityd, "STATE_DB", root / "action-ledger.db"), \
                 mock.patch.object(stabilityd, "JOBS_PATH", jobs_path), \
                 mock.patch.object(stabilityd, "CRON_DIR", jobs_path.parent), \
                 mock.patch.object(stabilityd, "REPAIR_PENDING_DIR", pending_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PROCESSED_DIR", processed_dir), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"):
                actions = stabilityd.cron_actuate({"generationId": "fixture-generation", "cron": {
                    "staleRunning": candidates,
                }}, {**policy, **{"canMutateCronState": True}})
            action = next(item for item in actions if item["action"] == "clear_stale_running_state")
            self.assertEqual(action["result"], "blocked")
            self.assertEqual(action["blockedReason"], "legacy-openclaw-jobs-store-has-uncoordinated-writer")
            self.assertIn("runningAtMs", json.loads(jobs_path.read_text(encoding="utf-8"))["jobs"][0])
            self.assertEqual(list(pending_dir.glob("*.json")), [])

    def test_expired_lease_uses_durable_per_lease_action_and_postcheck(self):
        job_id, run_id = "job-fixture", "run-fixture"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            lease_dir = root / "leases"
            run_dir = root / "runs"
            job_run_dir = root / "runs-by-job"
            pending_dir = root / "repairs" / "pending"
            processed_dir = root / "repairs" / "processed"
            for directory in (lease_dir, run_dir, job_run_dir, pending_dir, processed_dir):
                directory.mkdir(parents=True, exist_ok=True)
            lease_path = lease_dir / "lease-fixture.json"
            lease_path.write_text(json.dumps({
                "jobId": job_id, "runId": run_id,
                "leaseOwner": f"{socket.gethostname()}:987654321",
                **_dead_workload_metadata(),
                "expiresAtMs": stabilityd.now_ms() - 1000,
            }), encoding="utf-8")
            run_path = run_dir / f"{run_id}.json"
            run_path.write_text(json.dumps({
                "jobId": job_id, "runId": run_id, "status": "running",
                "startedAtMs": stabilityd.now_ms() - 5000, "dispatchState": "not-started",
            }), encoding="utf-8")
            item = {"path": str(lease_path), "jobId": job_id, "runId": run_id}
            policy = {"canReapExpiredLeases": True,
                      "updatedAtEpoch": stabilityd.epoch() - 1,
                      "validUntilEpoch": stabilityd.epoch() + 60}
            gate = {"status": "ready", "reason": "normal"}
            with mock.patch.object(stabilityd, "STATE_DB", root / "action-ledger.db"), \
                 mock.patch.object(stabilityd, "LEASE_DIR", lease_dir), \
                 mock.patch.object(stabilityd, "CRON_DIR", root), \
                 mock.patch.object(stabilityd, "RUNS_BY_RUN_DIR", run_dir), \
                 mock.patch.object(stabilityd, "RUNS_BY_JOB_DIR", job_run_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PENDING_DIR", pending_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PROCESSED_DIR", processed_dir), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"), \
                 mock.patch.object(stabilityd.os, "kill", side_effect=ProcessLookupError):
                result = stabilityd.governed_reap_expired_lease(item, gate, policy, "fixture-generation")
                duplicate = stabilityd.governed_reap_expired_lease(item, gate, policy, "fixture-generation")
            self.assertEqual(result["ledgerState"], "succeeded", result)
            self.assertEqual(result["result"], "ok")
            self.assertFalse(lease_path.exists())
            self.assertEqual(json.loads(run_path.read_text(encoding="utf-8"))["status"], "orphaned")
            self.assertTrue((pending_dir / f"{job_id}__lease_expired.json").exists())
            self.assertEqual(duplicate["blockedReason"], "lease-path-out-of-scope")
            ledger = (root / "action-ledger.db").read_bytes()
            self.assertNotIn(job_id.encode(), ledger)
            self.assertNotIn(run_id.encode(), ledger)

    def test_lease_outside_lease_root_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            policy = {"canReapExpiredLeases": True,
                      "updatedAtEpoch": stabilityd.epoch() - 1,
                      "validUntilEpoch": stabilityd.epoch() + 60}
            with mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"), \
                 mock.patch.object(stabilityd, "LEASE_DIR", root / "leases"):
                result = stabilityd.governed_reap_expired_lease(
                    {"path": str(root / "outside.json"), "jobId": "job", "runId": "run"},
                    {"status": "ready"}, policy, "fixture-generation",
                )
        self.assertEqual(result["result"], "blocked")
        self.assertEqual(result["blockedReason"], "lease-path-out-of-scope")

    def test_expired_lease_with_live_owner_is_not_reaped(self):
        job_id, run_id = "job-live-owner", "run-live-owner"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            lease_dir = root / "leases"
            lease_dir.mkdir()
            lease_path = lease_dir / "live-owner.json"
            lease_path.write_text(json.dumps({
                "jobId": job_id, "runId": run_id,
                "leaseOwner": f"{socket.gethostname()}:{os.getpid()}",
                **_dead_workload_metadata(),
                "dispatchState": "not-started",
                "expiresAtMs": stabilityd.now_ms() - 1000,
            }), encoding="utf-8")
            with mock.patch.object(stabilityd, "STATE_DB", root / "action-ledger.db"), \
                 mock.patch.object(stabilityd, "LEASE_DIR", lease_dir), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"):
                result = stabilityd.governed_reap_expired_lease(
                    {"path": str(lease_path), "jobId": job_id, "runId": run_id},
                    {"status": "ready"},
                    {"canReapExpiredLeases": True, "updatedAtEpoch": stabilityd.epoch() - 1,
                     "validUntilEpoch": stabilityd.epoch() + 60},
                    "fixture-generation",
                )
            self.assertEqual(result["result"], "blocked")
            self.assertEqual(result["blockedReason"], "lease-owner-or-workload-live-or-unverifiable")
            self.assertTrue(lease_path.exists())

    def test_live_workload_blocks_reap_even_when_wrapper_owner_is_gone(self):
        job_id, run_id = "job-live-child", "run-live-child"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            lease_dir = root / "leases"
            lease_dir.mkdir()
            lease_path = lease_dir / "live-child.json"
            lease_path.write_text(json.dumps({
                "jobId": job_id, "runId": run_id,
                "leaseOwner": f"{socket.gethostname()}:987654321",
                "workloadOwner": {"host": socket.gethostname(), "pid": os.getpid()},
                "workloadState": "running",
                "dispatchState": "attempted",
                "expiresAtMs": stabilityd.now_ms() - 1000,
            }), encoding="utf-8")
            with mock.patch.object(stabilityd, "STATE_DB", root / "action-ledger.db"), \
                 mock.patch.object(stabilityd, "LEASE_DIR", lease_dir), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"), \
                 mock.patch.object(stabilityd.os, "kill", side_effect=[ProcessLookupError, None]):
                result = stabilityd.governed_reap_expired_lease(
                    {"path": str(lease_path), "jobId": job_id, "runId": run_id},
                    {"status": "ready"},
                    {"canReapExpiredLeases": True, "updatedAtEpoch": stabilityd.epoch() - 1,
                     "validUntilEpoch": stabilityd.epoch() + 60},
                    "fixture-generation",
                )
            self.assertEqual(result["result"], "blocked")
            self.assertEqual(result["blockedReason"], "lease-owner-or-workload-live-or-unverifiable")
            self.assertTrue(lease_path.exists())

    def test_dispatched_but_ambiguous_run_is_uncertain_and_never_reaped(self):
        job_id, run_id = "job-dispatched", "run-dispatched"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            lease_dir = root / "leases"
            run_dir = root / "runs"
            job_run_dir = root / "runs-by-job"
            pending_dir = root / "repairs" / "pending"
            processed_dir = root / "repairs" / "processed"
            for directory in (lease_dir, run_dir, job_run_dir, pending_dir, processed_dir):
                directory.mkdir(parents=True, exist_ok=True)
            lease_path = lease_dir / "dispatched.json"
            lease_path.write_text(json.dumps({
                "jobId": job_id, "runId": run_id,
                "leaseOwner": f"{socket.gethostname()}:987654321",
                **{**_dead_workload_metadata(), "dispatchState": "attempted"},
                "expiresAtMs": stabilityd.now_ms() - 1000,
            }), encoding="utf-8")
            run_path = run_dir / f"{run_id}.json"
            run_path.write_text(json.dumps({"jobId": job_id, "runId": run_id, "status": "succeeded",
                                            "dispatchState": "attempted", "startedAtMs": 1}), encoding="utf-8")
            item = {"path": str(lease_path), "jobId": job_id, "runId": run_id}
            policy = {"canReapExpiredLeases": True, "updatedAtEpoch": stabilityd.epoch() - 1,
                      "validUntilEpoch": stabilityd.epoch() + 60}
            with mock.patch.object(stabilityd, "STATE_DB", root / "action-ledger.db"), \
                 mock.patch.object(stabilityd, "LEASE_DIR", lease_dir), \
                 mock.patch.object(stabilityd, "CRON_DIR", root), \
                 mock.patch.object(stabilityd, "RUNS_BY_RUN_DIR", run_dir), \
                 mock.patch.object(stabilityd, "RUNS_BY_JOB_DIR", job_run_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PENDING_DIR", pending_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PROCESSED_DIR", processed_dir), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"), \
                 mock.patch.object(stabilityd.os, "kill", side_effect=ProcessLookupError):
                result = stabilityd.governed_reap_expired_lease(item, {"status": "ready"}, policy,
                                                                 "fixture-generation")
                duplicate = stabilityd.governed_reap_expired_lease(item, {"status": "ready"}, policy,
                                                                    "fixture-generation")
            self.assertEqual(result["ledgerState"], "uncertain")
            self.assertEqual(result["failedStage"], "dispatch-outcome-unknown")
            self.assertEqual(duplicate["ledgerDisposition"], "existing")
            self.assertTrue(lease_path.exists())
            self.assertEqual(json.loads(run_path.read_text(encoding="utf-8"))["status"], "succeeded")
            self.assertEqual(list(pending_dir.glob("*.json")), [])

    def test_lease_replaced_after_final_precheck_is_not_deleted_or_orphaned(self):
        job_id, run_id = "job-race", "run-race"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            lease_dir = root / "leases"
            run_dir = root / "runs"
            job_run_dir = root / "runs-by-job"
            pending_dir = root / "repairs" / "pending"
            processed_dir = root / "repairs" / "processed"
            for directory in (lease_dir, run_dir, job_run_dir, pending_dir, processed_dir):
                directory.mkdir(parents=True, exist_ok=True)
            lease_path = lease_dir / "lease-race.json"
            expired = {"jobId": job_id, "runId": run_id,
                       "leaseOwner": f"{socket.gethostname()}:987654321",
                       **_dead_workload_metadata(),
                       "expiresAtMs": stabilityd.now_ms() - 1000}
            lease_path.write_text(json.dumps(expired), encoding="utf-8")
            run_path = run_dir / f"{run_id}.json"
            original_run = {"jobId": job_id, "runId": run_id, "status": "running",
                            "startedAtMs": stabilityd.now_ms() - 5000, "dispatchState": "not-started"}
            run_path.write_text(json.dumps(original_run), encoding="utf-8")
            item = {"path": str(lease_path), "jobId": job_id, "runId": run_id}
            policy = {"canReapExpiredLeases": True,
                      "updatedAtEpoch": stabilityd.epoch() - 1,
                      "validUntilEpoch": stabilityd.epoch() + 60}
            gate = {"status": "ready", "reason": "normal"}
            real_reaper = stabilityd.reap_expired_lease_candidate
            def replace_after_precheck(candidate, active_gate, *, expected_lease_digest=None):
                renewed = {"jobId": job_id, "runId": run_id,
                           "leaseOwner": f"{socket.gethostname()}:987654321",
                           **_dead_workload_metadata(),
                           "expiresAtMs": stabilityd.now_ms() + 60_000}
                lease_path.write_text(json.dumps(renewed), encoding="utf-8")
                return real_reaper(candidate, active_gate, expected_lease_digest=expected_lease_digest)
            with mock.patch.object(stabilityd, "STATE_DB", root / "action-ledger.db"), \
                 mock.patch.object(stabilityd, "LEASE_DIR", lease_dir), \
                 mock.patch.object(stabilityd, "CRON_DIR", root), \
                 mock.patch.object(stabilityd, "RUNS_BY_RUN_DIR", run_dir), \
                 mock.patch.object(stabilityd, "RUNS_BY_JOB_DIR", job_run_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PENDING_DIR", pending_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PROCESSED_DIR", processed_dir), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"), \
                 mock.patch.object(stabilityd.os, "kill", side_effect=ProcessLookupError), \
                 mock.patch.object(stabilityd, "reap_expired_lease_candidate", side_effect=replace_after_precheck):
                result = stabilityd.governed_reap_expired_lease(item, gate, policy, "fixture-generation")
            self.assertEqual(result["ledgerState"], "failed")
            self.assertEqual(result["failedStage"], "lease-generation-check")
            self.assertTrue(lease_path.exists())
            self.assertEqual(json.loads(run_path.read_text(encoding="utf-8")), original_run)
            self.assertEqual(list(pending_dir.glob("*.json")), [])

    def test_lease_renewal_after_run_write_fence_is_marked_uncertain_and_not_unlinked(self):
        job_id, run_id = "job-partial-race", "run-partial-race"
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            lease_dir = root / "leases"
            run_dir = root / "runs"
            job_run_dir = root / "runs-by-job"
            pending_dir = root / "repairs" / "pending"
            processed_dir = root / "repairs" / "processed"
            for directory in (lease_dir, run_dir, job_run_dir, pending_dir, processed_dir):
                directory.mkdir(parents=True, exist_ok=True)
            lease_path = lease_dir / "lease-race.json"
            lease_path.write_text(json.dumps({"jobId": job_id, "runId": run_id,
                                              "leaseOwner": f"{socket.gethostname()}:987654321",
                                              **_dead_workload_metadata(),
                                              "expiresAtMs": stabilityd.now_ms() - 1000}), encoding="utf-8")
            run_path = run_dir / f"{run_id}.json"
            run_path.write_text(json.dumps({"jobId": job_id, "runId": run_id, "status": "running",
                                            "startedAtMs": stabilityd.now_ms() - 5000,
                                            "dispatchState": "not-started"}), encoding="utf-8")
            item = {"path": str(lease_path), "jobId": job_id, "runId": run_id}
            policy = {"canReapExpiredLeases": True,
                      "updatedAtEpoch": stabilityd.epoch() - 1,
                      "validUntilEpoch": stabilityd.epoch() + 60}
            gate = {"status": "ready", "reason": "normal"}
            real_write = stabilityd.write_json_atomic
            def renew_after_run_write_check(path, payload, *args, **kwargs):
                if Path(path) == run_path and payload.get("status") == "orphaned":
                    lease_path.write_text(json.dumps({
                        "jobId": job_id, "runId": run_id,
                        "leaseOwner": f"{socket.gethostname()}:987654321",
                        **_dead_workload_metadata(),
                        "expiresAtMs": stabilityd.now_ms() + 60_000,
                    }), encoding="utf-8")
                return real_write(path, payload, *args, **kwargs)
            with mock.patch.object(stabilityd, "STATE_DB", root / "action-ledger.db"), \
                 mock.patch.object(stabilityd, "LEASE_DIR", lease_dir), \
                 mock.patch.object(stabilityd, "CRON_DIR", root), \
                 mock.patch.object(stabilityd, "RUNS_BY_RUN_DIR", run_dir), \
                 mock.patch.object(stabilityd, "RUNS_BY_JOB_DIR", job_run_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PENDING_DIR", pending_dir), \
                 mock.patch.object(stabilityd, "REPAIR_PROCESSED_DIR", processed_dir), \
                 mock.patch.object(stabilityd, "current_host_generation", return_value="fixture-node:boot"), \
                 mock.patch.object(stabilityd.os, "kill", side_effect=ProcessLookupError), \
                 mock.patch.object(stabilityd, "write_json_atomic", side_effect=renew_after_run_write_check):
                result = stabilityd.governed_reap_expired_lease(item, gate, policy, "fixture-generation")
            self.assertEqual(result["ledgerState"], "uncertain")
            self.assertEqual(result["result"], "uncertain")
            self.assertTrue(lease_path.exists())
            self.assertEqual(json.loads(run_path.read_text(encoding="utf-8"))["status"], "orphaned")
            self.assertEqual(list(pending_dir.glob("*.json")), [])


if __name__ == "__main__":
    unittest.main()
