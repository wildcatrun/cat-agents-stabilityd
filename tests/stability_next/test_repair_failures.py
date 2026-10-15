import importlib.util
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
SPEC = importlib.util.spec_from_file_location("stabilityd_repair_test", MODULE_PATH)
stabilityd = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(stabilityd)


class _MonkeyPatch:
    def setattr(self, target, name, value):
        setattr(target, name, value)


def _configure_paths(monkeypatch, tmp_path):
    cron = tmp_path / "cron"
    values = {
        "CRON_DIR": cron,
        "STATE_DB": cron / "action-ledger.db",
        "LEASE_DIR": cron / "leases",
        "RUNS_BY_RUN_DIR": cron / "runs" / "by-run",
        "RUNS_BY_JOB_DIR": cron / "runs" / "by-job",
        "REPAIR_PENDING_DIR": cron / "repair-requests" / "pending",
        "REPAIR_PROCESSED_DIR": cron / "repair-requests" / "processed",
        "REPAIR_STATUS_PATH": cron / "repair-requests" / "status.json",
        "JOBS_PATH": cron / "jobs.json",
    }
    for name, value in values.items():
        monkeypatch.setattr(stabilityd, name, value)
    for path in values.values():
        (path if path.suffix == "" else path.parent).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(stabilityd, "current_host_generation", lambda: "fixture-node:boot")
    return values


def _policy():
    now = stabilityd.epoch()
    return {"canMutateCronState": True, "canReapExpiredLeases": True,
            "updatedAt": "2026-10-04T00:00:00Z", "updatedAtEpoch": now - 1,
            "validUntilEpoch": now + 60}


def _expired_lease(path: Path, job_id: str, run_id: str = "") -> None:
    payload = {"jobId": job_id, "leaseOwner": f"{socket.gethostname()}:987654321",
               "workloadOwner": {"host": socket.gethostname(), "pid": 987654322},
               "workloadState": "running",
               "dispatchState": "not-started",
               "expiresAtMs": stabilityd.now_ms() - 1000}
    if run_id:
        payload["runId"] = run_id
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_invalid_queue_entries_are_reported_and_preserved_while_valid_entry_updates(monkeypatch, tmp_path):
    paths = _configure_paths(monkeypatch, tmp_path)
    pending = paths["REPAIR_PENDING_DIR"]
    invalid_json = pending / "invalid-json.json"
    invalid_json.write_text("{secret raw parse text", encoding="utf-8")
    array_json = pending / "array.json"
    array_json.write_text('[{"jobId": "do-not-move"}]', encoding="utf-8")
    missing_schema = pending / "missing-schema.json"
    missing_schema.write_text(json.dumps({"jobId": "j2", "reason": "x", "source": "test", "status": "pending"}), encoding="utf-8")
    queued_path = Path(stabilityd.enqueue_repair_request("j1", "lease_expired", "test"))

    summary = stabilityd.update_repair_queue_status(_policy())

    assert summary["schemaVersion"] == 1
    assert summary["pendingCount"] == summary["readyCount"] + summary["blockedCount"] + summary["invalidCount"] == 4
    assert summary["readyCount"] == 1
    assert summary["invalidCount"] == 3
    assert {entry["errorClass"] for entry in summary["invalidEntries"]} == {
        "JSONDecodeError", "InvalidDocumentType", "MissingRequiredFields"
    }
    assert all(entry["status"] == "failed" and entry["queueState"] == "invalid" for entry in summary["invalidEntries"])
    assert invalid_json.read_text(encoding="utf-8") == "{secret raw parse text"
    assert array_json.exists() and missing_schema.exists()
    queued = json.loads(queued_path.read_text(encoding="utf-8"))
    assert queued["schemaVersion"] == 1
    assert queued["queueState"] == "ready"


def test_unlink_failure_is_not_reaped_or_queued_and_records_partial_run_write(monkeypatch, tmp_path):
    paths = _configure_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(stabilityd, "LEASE_REAP_ENABLED", True)
    lease = paths["LEASE_DIR"] / "j1.json"
    _expired_lease(lease, "j1", "r1")
    run = paths["RUNS_BY_RUN_DIR"] / "r1.json"
    run.write_text(json.dumps({"jobId": "j1", "runId": "r1", "status": "running", "startedAtMs": 1,
                               "dispatchState": "not-started"}), encoding="utf-8")
    real_unlink = Path.unlink

    def deny_target(path, *args, **kwargs):
        if path == lease:
            raise PermissionError("sensitive path details must not escape")
        return real_unlink(path, *args, **kwargs)

    snapshot = {"generationId": "fixture-generation", "cron": {"expiredLeases": [{"path": str(lease), "jobId": "j1", "runId": "r1"}]}}
    with mock.patch.object(Path, "unlink", autospec=True, side_effect=deny_target):
        actions = stabilityd.cron_actuate(snapshot, _policy())

    reap = [action for action in actions if action["action"] == "reap_expired_leases"]
    assert len(reap) == 1
    assert reap[0]["result"] == "uncertain"
    assert "reaped" not in reap[0]
    failure = reap[0]["failures"][0]
    assert failure["errorClass"] == "PermissionError"
    assert failure["partialWrites"]["runStateUpdated"] is True
    assert failure["partialWrites"]["runStateBefore"] == "running"
    assert failure["partialWrites"]["leaseRemoved"] is False
    assert "sensitive" not in json.dumps(failure)
    assert lease.exists()
    assert list(paths["REPAIR_PENDING_DIR"].glob("*.json")) == []
    assert json.loads(run.read_text(encoding="utf-8"))["status"] == "orphaned"


def test_completed_run_unlink_failure_is_failed_without_claiming_reap(monkeypatch, tmp_path):
    paths = _configure_paths(monkeypatch, tmp_path)
    monkeypatch.setattr(stabilityd, "LEASE_REAP_ENABLED", True)
    lease = paths["LEASE_DIR"] / "j2.json"
    _expired_lease(lease, "j2", "r2")
    run = paths["RUNS_BY_RUN_DIR"] / "r2.json"
    run.write_text(json.dumps({"jobId": "j2", "runId": "r2", "status": "succeeded",
                               "startedAtMs": 1, "finishedAtMs": 2,
                               "dispatchState": "not-started"}), encoding="utf-8")
    snapshot = {"generationId": "fixture-generation", "cron": {"expiredLeases": [{"path": str(lease), "jobId": "j2", "runId": "r2"}]}}

    with mock.patch.object(Path, "unlink", autospec=True, side_effect=PermissionError("private")):
        actions = stabilityd.cron_actuate(snapshot, _policy())

    reap = [action for action in actions if action["action"] == "reap_expired_leases"][0]
    assert reap["result"] == "failed"
    assert reap["failures"][0]["partialWrites"]["runStateUpdated"] is False
    assert reap["failures"][0]["partialWrites"]["runStateBefore"] == "succeeded"
    assert json.loads(run.read_text(encoding="utf-8"))["status"] == "succeeded"
    assert list(paths["REPAIR_PENDING_DIR"].glob("*.json")) == []


class RepairFailureTests(unittest.TestCase):
    def test_historical_receipts_remain_visible_without_masking_unresolved_batch(self):
        for state, fresh, expected in (("uncertain", True, "uncertain"),
                                       ("executing", True, "uncertain"),
                                       ("succeeded", True, "ok"),
                                       ("uncertain", False, "uncertain"),
                                       ("succeeded", False, "existing")):
            with self.subTest(state=state, fresh=fresh):
                history = dict(result="existing", ledgerState=state,
                               historicalExisting=True, authorizationReused=False)
                results = [history] + ([dict(result="ok")] if fresh else [])
                with mock.patch.object(stabilityd, "cleanup_stale_tmp_files", return_value=0), \
                     mock.patch.object(stabilityd, "update_repair_queue_status", return_value={}), \
                     mock.patch.object(stabilityd, "LEASE_REAP_ENABLED", True), \
                     mock.patch.object(stabilityd, "governed_reap_expired_lease", side_effect=results) as reap:
                    actions = stabilityd.cron_actuate(
                        {"cron": {"expiredLeases": [{} for _ in results]}}, _policy())
                batch = next(a for a in actions if a["action"] == "reap_expired_leases")
                self.assertEqual(batch["result"], expected)
                self.assertEqual(batch["existing"], [history])
                self.assertEqual(batch.get("reaped", []), [{"result": "ok"}] if fresh else [])
                self.assertEqual(reap.call_count, len(results))

    def _run(self, test_function):
        with tempfile.TemporaryDirectory() as directory:
            test_function(_MonkeyPatch(), Path(directory))

    def test_invalid_queue_entries(self):
        self._run(test_invalid_queue_entries_are_reported_and_preserved_while_valid_entry_updates)

    def test_unlink_failure_after_partial_write(self):
        self._run(test_unlink_failure_is_not_reaped_or_queued_and_records_partial_run_write)

    def test_completed_run_unlink_failure(self):
        self._run(test_completed_run_unlink_failure_is_failed_without_claiming_reap)

    def test_audit_append_failure_records_partial_write_and_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _configure_paths(_MonkeyPatch(), Path(directory))
            stabilityd.LEASE_REAP_ENABLED = True
            lease = paths["LEASE_DIR"] / "j1.json"
            _expired_lease(lease, "j1", "r1")
            run = paths["RUNS_BY_RUN_DIR"] / "r1.json"
            run.write_text(json.dumps({"jobId": "j1", "runId": "r1", "status": "running", "startedAtMs": 1,
                                       "dispatchState": "not-started"}))
            snapshot = {"generationId": "fixture-generation", "cron": {"expiredLeases": [{"path": str(lease), "jobId": "j1", "runId": "r1"}]}}
            with mock.patch.object(stabilityd, "append_jsonl", side_effect=PermissionError("private")):
                actions = stabilityd.cron_actuate(snapshot, _policy())
            reap = [a for a in actions if a["action"] == "reap_expired_leases"][0]
            self.assertEqual(reap["result"], "uncertain")
            self.assertEqual(reap["failures"][0]["failedStage"], "run-audit-append")
            self.assertTrue(reap["failures"][0]["partialWrites"]["runStateUpdated"])
            self.assertTrue(lease.exists())
            self.assertEqual(list(paths["REPAIR_PENDING_DIR"].glob("*.json")), [])

    def test_mixed_batch_has_one_non_success_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _configure_paths(_MonkeyPatch(), Path(directory))
            stabilityd.LEASE_REAP_ENABLED = True
            leases = []
            for number in (1, 2):
                lease = paths["LEASE_DIR"] / f"j{number}.json"
                _expired_lease(lease, f"j{number}")
                leases.append({"path": str(lease), "jobId": f"j{number}"})
            real_unlink = Path.unlink
            def fail_second(path, *args, **kwargs):
                if path == Path(leases[1]["path"]):
                    raise PermissionError("private")
                return real_unlink(path, *args, **kwargs)
            with mock.patch.object(Path, "unlink", autospec=True, side_effect=fail_second):
                actions = stabilityd.cron_actuate({"generationId": "fixture-generation", "cron": {"expiredLeases": leases}}, _policy())
            reap = [a for a in actions if a["action"] == "reap_expired_leases"]
            self.assertEqual(len(reap), 1)
            self.assertEqual(reap[0]["result"], "failed")
            self.assertEqual(len(reap[0]["reaped"]), 1)
            self.assertEqual(len(reap[0]["failures"]), 1)

    def test_complete_legacy_queue_shape_migrates_without_dropping_request(self):
        with tempfile.TemporaryDirectory() as directory:
            _configure_paths(_MonkeyPatch(), Path(directory))
            path = Path(stabilityd.enqueue_repair_request("legacy", "lease_expired", "test"))
            payload = json.loads(path.read_text())
            payload.pop("schemaVersion")
            path.write_text(json.dumps(payload))
            summary = stabilityd.update_repair_queue_status(_policy())
            self.assertEqual(summary["migratedLegacyEntries"], 1)
            self.assertEqual(summary["invalidCount"], 0)
            self.assertEqual(summary["readyCount"], 1)
            self.assertEqual(json.loads(path.read_text())["schemaVersion"], 1)

    def test_uncertain_missing_audit_action_is_not_automatically_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _configure_paths(_MonkeyPatch(), Path(directory))
            stabilityd.LEASE_REAP_ENABLED = True
            lease = paths["LEASE_DIR"] / "j1.json"
            _expired_lease(lease, "j1", "r1")
            run = paths["RUNS_BY_RUN_DIR"] / "r1.json"
            run.write_text(json.dumps({"jobId": "j1", "runId": "r1", "status": "running", "startedAtMs": 1,
                                       "dispatchState": "not-started"}))
            snapshot = {"generationId": "fixture-generation", "cron": {"expiredLeases": [{"path": str(lease), "jobId": "j1", "runId": "r1"}]}}
            policy = _policy()
            with mock.patch.object(stabilityd, "append_jsonl", side_effect=PermissionError("private")):
                first = stabilityd.cron_actuate(snapshot, policy)
            self.assertEqual([a for a in first if a["action"] == "reap_expired_leases"][0]["result"], "uncertain")
            run_before = run.read_bytes()
            with mock.patch.object(stabilityd, "reap_expired_lease_candidate", side_effect=AssertionError("historical operation replayed")) as operation:
                second = stabilityd.cron_actuate(snapshot, policy)
            operation.assert_not_called()
            reap = [a for a in second if a["action"] == "reap_expired_leases"][0]
            self.assertEqual(reap["result"], "uncertain")
            history = reap["existing"][0]
            self.assertEqual(history["ledgerDisposition"], "existing")
            self.assertEqual(history["ledgerState"], "uncertain")
            self.assertTrue(history["historicalExisting"])
            self.assertFalse(history["authorizationReused"])
            self.assertEqual(run.read_bytes(), run_before)
            self.assertTrue(lease.exists())
            self.assertFalse((paths["RUNS_BY_JOB_DIR"] / "j1.jsonl").exists())

    def test_existing_same_event_id_with_wrong_payload_cannot_claim_success(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _configure_paths(_MonkeyPatch(), Path(directory))
            stabilityd.LEASE_REAP_ENABLED = True
            lease = paths["LEASE_DIR"] / "j1.json"
            _expired_lease(lease, "j1", "r1")
            run_record = {
                "jobId": "j1", "runId": "r1", "dispatchState": "not-started",
                "status": "orphaned", "startedAtMs": 1, "finishedAtMs": 2, "durationMs": 1,
                "failure": {"class": "lease_expired"},
            }
            (paths["RUNS_BY_RUN_DIR"] / "r1.json").write_text(json.dumps(run_record))
            event_id = stabilityd.ensure_lease_reap_audit("j1", "r1", run_record)
            audit = paths["RUNS_BY_JOB_DIR"] / "j1.jsonl"
            audit.write_text(json.dumps({"eventId": event_id, "jobId": "wrong", "runId": "other", "action": "wrong", "status": "success"}) + "\n")
            actions = stabilityd.cron_actuate(
                {"generationId": "fixture-generation", "cron": {"expiredLeases": [{"path": str(lease), "jobId": "j1", "runId": "r1"}]}}, _policy()
            )
            reap = [a for a in actions if a["action"] == "reap_expired_leases"][0]
            self.assertEqual(reap["result"], "uncertain")
            self.assertEqual(reap["failures"][0]["errorClass"], "LeaseAuditConflict")
            self.assertTrue(lease.exists())
            self.assertEqual(list(paths["REPAIR_PENDING_DIR"].glob("*.json")), [])
            self.assertEqual(len(audit.read_text().splitlines()), 1)
