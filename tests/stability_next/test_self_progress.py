import importlib.util
import io
import json
import signal
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("stabilityd_self_progress_test", ROOT / "bin" / "cat_agents_stabilityd.py")
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class SelfProgressTests(unittest.TestCase):
    def test_prior_generation_freshness_and_clock_anomaly_are_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "latest.json"
            with mock.patch.object(stabilityd, "LATEST_PATH", path):
                self.assertEqual(stabilityd.stabilityd_progress_evidence(1000)["state"], "first_observation")
                path.write_text(json.dumps({"generationId": "g-old", "completedAtEpoch": 950}))
                recent = stabilityd.stabilityd_progress_evidence(1000)
                self.assertEqual(recent["state"], "recent_previous_generation")
                self.assertEqual(recent["previousAgeSeconds"], 50)
                stale = stabilityd.stabilityd_progress_evidence(1000 + stabilityd.STABILITYD_PROGRESS_STALE_SECONDS + 1)
                self.assertEqual(stale["state"], "stale_previous_generation")
                path.write_text(json.dumps({"generationId": "g-future", "completedAtEpoch": 1006}))
                future = stabilityd.stabilityd_progress_evidence(1000)
                self.assertEqual(future["state"], "clock_skew")

    def test_collect_snapshot_turns_stale_prior_generation_into_governance_finding(self):
        runner_calls = []

        def synthetic_runner(name, _command, fallback, **_kwargs):
            runner_calls.append(name)
            return {
                "data": dict(fallback),
                "findings": [],
                "cacheUpdates": {},
                "probe": {"component": name, "status": "ok", "coverage": True, "durationMs": 1},
            }

        stale_evidence = {
            "state": "stale_previous_generation",
            "previousGenerationId": "fixture-previous-generation",
            "previousAgeSeconds": stabilityd.STABILITYD_PROGRESS_STALE_SECONDS + 1,
            "thresholdSeconds": stabilityd.STABILITYD_PROGRESS_STALE_SECONDS,
            "supervision": "existing-daemon-loop",
        }
        with stabilityd.init_memory_kv_db() as conn, \
             mock.patch.object(stabilityd, "epoch", return_value=1791237600), \
             mock.patch.object(stabilityd, "ts", return_value="2026-10-05T22:00:00Z"), \
             mock.patch.object(stabilityd, "stabilityd_progress_evidence", return_value=stale_evidence), \
             mock.patch.object(stabilityd, "update_runtime_trends", return_value={}), \
             mock.patch.object(stabilityd, "update_streaks", return_value={}), \
             mock.patch.object(stabilityd, "add_resource_governance_findings"), \
             mock.patch.object(stabilityd, "policy_from_findings", return_value={"mode": "fixture"}), \
             mock.patch.object(stabilityd, "build_auth_maintenance_plan", return_value={}):
            snapshot, findings, _policy = stabilityd.collect_snapshot(
                conn, component_probe_runner=synthetic_runner,
            )

        self.assertEqual(len(runner_calls), 9)
        self.assertEqual(snapshot["selfProgress"], stale_evidence)
        finding = next(item for item in findings if item["key"] == "stabilityd_progress_stale")
        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(finding["previousGenerationId"], "fixture-previous-generation")
        self.assertEqual(finding["supervision"], "existing-daemon-loop")

    def test_daemon_loop_records_redacted_exception_and_runs_next_interval(self):
        clock = {"now": 0.0}
        run_times = []
        sleep_durations = []
        signal_handlers = {}
        events = []
        log_lines = []
        stop_sent = {"value": False}

        def fake_run_once(_conn, *, no_action):
            self.assertFalse(no_action)
            run_times.append(clock["now"])
            if len(run_times) == 1:
                raise RuntimeError("Authorization: Bearer SYNTHETIC_LOOP_SENTINEL")

        def fake_signal_register(signum, handler):
            signal_handlers[signum] = handler

        def fake_sleep(duration):
            sleep_durations.append(duration)
            clock["now"] += duration
            if len(run_times) == 2 and not stop_sent["value"]:
                stop_sent["value"] = True
                signal_handlers[signal.SIGTERM](signal.SIGTERM, None)

        def fake_time():
            return clock["now"]

        def record_event(_conn, event):
            events.append(event)

        with tempfile.TemporaryDirectory() as tmp:
            lock_handle = (Path(tmp) / "daemon.lock").open("a+", encoding="utf-8")
            lock_path = mock.Mock()
            lock_path.open.return_value = lock_handle
            with mock.patch.object(stabilityd, "ensure_dirs"), \
                 mock.patch.object(stabilityd, "LOCK_PATH", lock_path), \
                 mock.patch.object(stabilityd.fcntl, "flock") as flock, \
                 mock.patch.object(stabilityd.signal, "signal", side_effect=fake_signal_register), \
                 mock.patch.object(stabilityd, "INTERVAL_SECONDS", 2), \
                 mock.patch.object(stabilityd, "init_db", return_value=object()), \
                 mock.patch.object(stabilityd, "run_once", side_effect=fake_run_once) as run_once, \
                 mock.patch.object(stabilityd, "db_record_event", side_effect=record_event), \
                 mock.patch.object(stabilityd, "log_line", side_effect=log_lines.append), \
                 mock.patch.object(stabilityd, "ts", return_value="2026-10-05T00:00:00Z"), \
                 mock.patch.object(stabilityd, "epoch", return_value=1791158400), \
                 mock.patch.object(stabilityd.time, "time", side_effect=fake_time), \
                 mock.patch.object(stabilityd.time, "sleep", side_effect=fake_sleep):
                result = stabilityd.daemon_loop()

        self.assertEqual(result, 0)
        self.assertTrue(lock_handle.closed)
        self.assertEqual(run_once.call_count, 2)
        self.assertEqual(run_times, [0.0, 2.0])
        self.assertEqual(sleep_durations, [1, 1, 1])
        flock.assert_called_once()
        self.assertEqual(set(signal_handlers), {signal.SIGTERM, signal.SIGINT})
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["key"], "stabilityd_loop_error")
        self.assertEqual(event["evidence"], {"errorClass": "RuntimeError", "stage": "daemon-loop"})
        self.assertNotIn("SYNTHETIC_LOOP_SENTINEL", json.dumps(event))
        self.assertNotIn("SYNTHETIC_LOOP_SENTINEL", "\n".join(log_lines))
        self.assertIn("loop_error stage=daemon-loop errorClass=RuntimeError", log_lines)
        self.assertEqual(log_lines[-1], "daemon stopped")

    def test_daemon_loop_closes_lock_when_another_instance_holds_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_handle = (Path(tmp) / "daemon.lock").open("a+", encoding="utf-8")
            lock_path = mock.Mock()
            lock_path.open.return_value = lock_handle
            stderr = io.StringIO()
            with mock.patch.object(stabilityd, "ensure_dirs"), \
                 mock.patch.object(stabilityd, "LOCK_PATH", lock_path), \
                 mock.patch.object(stabilityd.fcntl, "flock",
                                   side_effect=BlockingIOError(stabilityd.errno.EAGAIN, "lock busy")), \
                 mock.patch.object(stabilityd, "init_db") as init_db, \
                 mock.patch.object(stabilityd.signal, "signal") as signal_register, \
                 mock.patch.object(stabilityd.sys, "stderr", stderr):
                result = stabilityd.daemon_loop()

        self.assertEqual(result, 1)
        self.assertTrue(lock_handle.closed)
        self.assertEqual(stderr.getvalue().strip(), "cat-agents-stabilityd is already running")
        init_db.assert_not_called()
        signal_register.assert_not_called()

    def test_daemon_loop_event_write_failure_exits_and_closes_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock_handle = (Path(tmp) / "daemon.lock").open("a+", encoding="utf-8")
            lock_path = mock.Mock()
            lock_path.open.return_value = lock_handle
            log_lines = []
            run_once = mock.Mock(side_effect=RuntimeError("SYNTHETIC_RUN_FAILURE"))
            stderr = io.StringIO()
            with mock.patch.object(stabilityd, "ensure_dirs"), \
                 mock.patch.object(stabilityd, "LOCK_PATH", lock_path), \
                 mock.patch.object(stabilityd.fcntl, "flock"), \
                 mock.patch.object(stabilityd.signal, "signal"), \
                 mock.patch.object(stabilityd, "init_db", return_value=object()), \
                 mock.patch.object(stabilityd, "run_once", run_once), \
                 mock.patch.object(stabilityd, "db_record_event",
                                   side_effect=sqlite3.OperationalError("SYNTHETIC_EVENT_WRITE_SENTINEL")), \
                 mock.patch.object(stabilityd, "log_line", side_effect=log_lines.append), \
                 mock.patch.object(stabilityd.time, "sleep") as sleep, \
                 mock.patch.object(stabilityd.sys, "stderr", stderr):
                result = stabilityd.main(["daemon"])

        self.assertEqual(result, 2)
        self.assertTrue(lock_handle.closed)
        run_once.assert_called_once_with(mock.ANY, no_action=False)
        sleep.assert_not_called()
        self.assertFalse(any("SYNTHETIC_RUN_FAILURE" in line for line in log_lines))
        self.assertNotIn("SYNTHETIC_EVENT_WRITE_SENTINEL", stderr.getvalue())
        self.assertNotIn("SYNTHETIC_RUN_FAILURE", stderr.getvalue())
        self.assertEqual(stderr.getvalue().strip(), "cat-agents-stabilityd: loop_error_evidence_write_failed")
        self.assertNotIn("daemon stopped", log_lines)


if __name__ == "__main__":
    unittest.main()
