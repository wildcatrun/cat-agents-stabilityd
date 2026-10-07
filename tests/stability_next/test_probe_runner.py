import importlib.util
import json
import os
import signal
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stability_core.probe_runner import run_component_probe, run_component_probe_hard
import stability_core.probe_runner as probe_runner


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
SPEC = importlib.util.spec_from_file_location("stabilityd_probe_runner_test", MODULE_PATH)
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class ProbeRunnerTests(unittest.TestCase):
    def setUp(self):
        # The macOS sandbox denies process-table enumeration and process-group
        # signals. Keep unit tests deterministic; Linux integration tests use
        # the real /proc enumerator and process groups.
        self._group_probe_patch = None
        self._killpg_patch = None
        if sys.platform == "darwin" and probe_runner._process_group_members(os.getpgrp()) is None:
            self._group_probe_patch = mock.patch.object(probe_runner, "_process_group_members", return_value=set())
            self._group_probe_patch.start()
            real_killpg = os.killpg
            def sandbox_safe_killpg(pgid, sig):
                if sig == signal.SIGTERM:
                    return None
                return real_killpg(pgid, sig)
            self._killpg_patch = mock.patch.object(probe_runner.os, "killpg", side_effect=sandbox_safe_killpg)
            self._killpg_patch.start()

    def tearDown(self):
        if self._group_probe_patch:
            self._group_probe_patch.stop()
        if self._killpg_patch:
            self._killpg_patch.stop()

    def test_exception_output_limit_and_budget_overrun_return_fallback(self):
        fallback = {"status": "unknown"}
        raised = run_component_probe("x", lambda: (_ for _ in ()).throw(RuntimeError("secret")), fallback, source="test")
        self.assertEqual(raised["data"], fallback)
        self.assertEqual(raised["probe"]["errorClass"], "RuntimeError")
        self.assertNotIn("secret", str(raised))
        large = run_component_probe("x", lambda: {"large": "x" * 100}, fallback,
                                    source="test", max_output_bytes=10)
        self.assertEqual(large["data"], fallback)
        self.assertEqual(large["probe"]["errorClass"], "OutputBudgetExceeded", large["probe"])
        clock_values = iter((1.0, 1.2))
        slow = run_component_probe("x", lambda: {"ok": True}, fallback, source="test",
                                   budget_ms=100, monotonic=lambda: next(clock_values))
        self.assertEqual(slow["data"], fallback)
        self.assertEqual(slow["probe"]["errorClass"], "ProbeBudgetExceeded")

    @unittest.skipUnless(os.name == "posix", "hard probe runner is POSIX-only")
    def test_hard_runner_returns_bounded_envelope_and_rejects_bad_or_oversize(self):
        fallback = {"status": "unknown"}
        ok = run_component_probe_hard(
            "fixture", [sys.executable, "-c",
                        "import json; print(json.dumps({'data': {'ok': True}, 'findings': [{'key':'fixture'}]}))"],
            fallback, source="test", budget_ms=2_000,
        )
        self.assertEqual(ok["data"], {"ok": True})
        self.assertEqual(ok["findings"], [{"key": "fixture"}])
        self.assertTrue(ok["probe"]["coverage"])

        bad = run_component_probe_hard(
            "fixture", [sys.executable, "-c", "import sys; print('private-detail', file=sys.stderr); sys.exit(4)"],
            fallback, source="test", budget_ms=2_000,
        )
        self.assertEqual(bad["data"], fallback)
        self.assertEqual(bad["findings"], [])
        self.assertIn(bad["probe"]["errorClass"], {"ProbeFailed", "ProbeCleanupFailed"})
        self.assertNotIn("private-detail", str(bad))

        large = run_component_probe_hard(
            "fixture", [sys.executable, "-c", "print('x' * 100)"], fallback,
            source="test", max_output_bytes=16, budget_ms=2_000,
        )
        self.assertEqual(large["data"], fallback)
        if large["probe"]["errorClass"] == "ProbeCleanupFailed":
            self.assertTrue(large["probe"]["fatal"])
            self.assertTrue(large["probe"]["leaderReaped"])
            self.assertFalse(large["probe"]["noLiveGroupMemberObserved"])
        else:
            self.assertEqual(large["probe"]["errorClass"], "OutputBudgetExceeded")

        stderr_large = run_component_probe_hard(
            "fixture", [sys.executable, "-c",
                        "import json,sys; print('x' * 100, file=sys.stderr); print(json.dumps({'data': {'ok': True}, 'findings': []}))"],
            fallback, source="test", max_stderr_bytes=16, budget_ms=2_000,
        )
        self.assertEqual(stderr_large["data"], fallback)
        self.assertIn(stderr_large["probe"]["errorClass"], {"OutputBudgetExceeded", "ProbeCleanupFailed"})

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin",
                         "process-group descendant integration requires Linux or macOS")
    def test_hard_timeout_kills_worker_process_group_and_discards_partial_findings(self):
        if self._group_probe_patch:
            self.skipTest("sandbox denies process-table/signaling integration")
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = os.path.join(temp_dir, "child-terminated")
            child_code = (
                "import signal,time; "
                f"signal.signal(signal.SIGTERM, lambda *_: (open({marker!r}, 'w').close(), exit(0))); "
                "time.sleep(30)"
            )
            parent_code = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                "print('partial-result', flush=True); time.sleep(30)"
            )
            timed_out = run_component_probe_hard(
                "fixture", [sys.executable, "-c", parent_code], {"status": "unknown"},
                source="test", budget_ms=1_500, terminate_grace_ms=100,
            )
            self.assertEqual(timed_out["data"], {"status": "unknown"})
            self.assertEqual(timed_out["findings"], [])
            if timed_out["probe"]["errorClass"] == "ProbeCleanupFailed":
                self.assertTrue(timed_out["probe"]["fatal"])
                self.assertFalse(timed_out["probe"]["noLiveGroupMemberObserved"])
                return
            self.assertEqual(timed_out["probe"]["errorClass"], "ProbeTimeout", timed_out["probe"])
            self.assertTrue(os.path.exists(marker), "TERM should reach the descendant in the worker process group")

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin",
                         "process-group SIGKILL integration requires Linux or macOS")
    def test_hard_timeout_escalates_to_kill_when_descendant_ignores_term(self):
        if self._group_probe_patch:
            self.skipTest("sandbox denies process-table/signaling integration")
        with tempfile.TemporaryDirectory() as temp_dir:
            pid_path = os.path.join(temp_dir, "child.pid")
            child_code = (
                "import os,signal,time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f"open({pid_path!r}, 'w').write(str(os.getpid()))\n"
                f"f=open({pid_path!r}, 'a')\n"
                "while True:\n f.write('x')\n f.flush()\n time.sleep(0.02)\n"
            )
            parent_code = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                "time.sleep(30)"
            )
            timed_out = run_component_probe_hard(
                "fixture", [sys.executable, "-c", parent_code], {"status": "unknown"},
                source="test", budget_ms=1_500, terminate_grace_ms=100,
            )
            self.assertEqual(timed_out["probe"]["errorClass"], "ProbeTimeout")
            self.assertTrue(os.path.exists(pid_path))
            size_after_cleanup = os.path.getsize(pid_path)
            time.sleep(0.15)
            self.assertEqual(os.path.getsize(pid_path), size_after_cleanup,
                             "descendant continued running after its process group was killed")

    @unittest.skipUnless(os.name == "posix", "hard probe runner is POSIX-only")
    def test_hard_runner_rejects_invalid_request_and_invalid_envelope(self):
        fallback = {"status": "unknown"}
        invalid = run_component_probe_hard("x", "echo unsafe", fallback, source="test")
        self.assertEqual(invalid["probe"]["errorClass"], "InvalidProbeRequest")
        malformed = run_component_probe_hard(
            "x", [sys.executable, "-c", "print('{}')"], fallback, source="test", budget_ms=2_000,
        )
        self.assertEqual(malformed["data"], fallback)
        self.assertEqual(malformed["findings"], [])
        self.assertEqual(malformed["probe"]["errorClass"], "InvalidWorkerResult")
        self.assertTrue(malformed["probe"]["leaderReaped"])
        self.assertTrue(malformed["probe"]["noLiveGroupMemberObserved"])
        nonfinite = run_component_probe_hard(
            "x", [sys.executable, "-c", "print('{\"data\":{\"x\":NaN},\"findings\":[]}')"],
            fallback, source="test", budget_ms=2_000,
        )
        self.assertEqual(nonfinite["probe"]["errorClass"], "InvalidWorkerResult")

    def test_linux_process_group_scan_is_bounded_and_parses_group_identity(self):
        if self._group_probe_patch:
            self._group_probe_patch.stop()
            self._group_probe_patch = None
        class Entries:
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def __iter__(self): return iter([type("Entry", (), {"name": "123"})()])

        with mock.patch.object(probe_runner.sys, "platform", "linux"), \
             mock.patch.object(probe_runner.os, "scandir", return_value=Entries()), \
             mock.patch("builtins.open", mock.mock_open(read_data="123 (fixture) S 1 42 0")):
            self.assertEqual(probe_runner._process_group_members(42), {(123, "S")})

        class TooManyEntries(Entries):
            def __iter__(self):
                return (type("Entry", (), {"name": "not-a-pid"})() for _ in range(100_001))

        with mock.patch.object(probe_runner.sys, "platform", "linux"), \
             mock.patch.object(probe_runner.os, "scandir", return_value=TooManyEntries()):
            self.assertIsNone(probe_runner._process_group_members(42))

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin",
                         "requires Linux/macOS process-group cleanup semantics")
    def test_nonzero_worker_cannot_leave_closed_stdio_descendant_running(self):
        if self._group_probe_patch:
            self.skipTest("sandbox denies process-table/signaling integration")
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = os.path.join(temp_dir, "descendant.log")
            child_code = (
                "import time\n"
                f"f=open({marker!r}, 'a', buffering=1)\n"
                "while True: f.write('x'); time.sleep(.01)\n"
            )
            parent_code = (
                "import os,subprocess,sys,time\n"
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}], stdin=subprocess.DEVNULL, "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                f"deadline=time.monotonic()+2;\nwhile not os.path.exists({marker!r}) and time.monotonic()<deadline: time.sleep(.01)\n"
                "sys.exit(7)\n"
            )
            outcome = run_component_probe_hard(
                "fixture", [sys.executable, "-c", parent_code], {"status": "unknown"},
                source="test", budget_ms=5_000, terminate_grace_ms=50,
            )
            self.assertEqual(outcome["probe"]["errorClass"], "ProbeFailed")
            before = os.path.getsize(marker)
            time.sleep(.1)
            self.assertEqual(os.path.getsize(marker), before)

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin",
                         "requires Linux/macOS process-group cleanup semantics")
    def test_successful_worker_cannot_leave_closed_stdio_descendant_running(self):
        if self._group_probe_patch:
            self.skipTest("sandbox denies process-table/signaling integration")
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = os.path.join(temp_dir, "descendant.log")
            child_code = (
                "import time\n"
                f"f=open({marker!r}, 'a', buffering=1)\n"
                "while True: f.write('x'); time.sleep(.01)\n"
            )
            parent_code = (
                "import json,os,subprocess,sys,time\n"
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}], stdin=subprocess.DEVNULL, "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                f"deadline=time.monotonic()+2;\nwhile not os.path.exists({marker!r}) and time.monotonic()<deadline: time.sleep(.01)\n"
                "print(json.dumps({'data': {'ok': True}, 'findings': []}))\n"
            )
            outcome = run_component_probe_hard(
                "fixture", [sys.executable, "-c", parent_code], {"status": "unknown"},
                source="test", budget_ms=5_000, terminate_grace_ms=50,
            )
            self.assertEqual(outcome["probe"]["errorClass"], None, outcome["probe"])
            self.assertTrue(outcome["probe"]["noLiveGroupMemberObserved"])
            before = os.path.getsize(marker)
            time.sleep(.1)
            self.assertEqual(os.path.getsize(marker), before)

    @unittest.skipUnless(os.name == "posix", "hard probe runner is POSIX-only")
    def test_hard_runner_uses_explicit_or_minimal_environment(self):
        fallback = {"status": "unknown"}
        with mock.patch.dict(os.environ, {"STABILITY_PROBE_SENTINEL": "DO_NOT_INHERIT"}):
            minimal = run_component_probe_hard(
                "fixture", [sys.executable, "-c",
                            "import json,os; print(json.dumps({'data': {'sentinel': os.getenv('STABILITY_PROBE_SENTINEL')}, 'findings': []}))"],
                fallback, source="test", budget_ms=2_000,
            )
        self.assertIsNone(minimal["data"]["sentinel"])
        explicit = run_component_probe_hard(
            "fixture", [sys.executable, "-c",
                        "import json,os; print(json.dumps({'data': {'mode': os.getenv('FIXTURE_MODE'), 'sentinel': os.getenv('STABILITY_PROBE_SENTINEL')}, 'findings': []}))"],
            fallback, source="test", budget_ms=2_000,
            env={"PATH": os.defpath, "FIXTURE_MODE": "allowlisted"},
        )
        self.assertEqual(explicit["data"], {"mode": "allowlisted", "sentinel": None})

    def test_collect_snapshot_discards_failed_component_findings_and_continues(self):
        calls = []

        def broken_gateway(findings):
            findings.append({"key": "gateway_service_down", "severity": "critical", "component": "gateway",
                             "message": "partial and invalid"})
            raise RuntimeError("sensitive detail")

        def good(name):
            def collect(*_args, **_kwargs):
                calls.append(name)
                return {"status": "fixture"}
            return collect

        safe_policy = {"canRestartGateway": False, "mode": "healthy", "severity": "ok"}
        def local_probe_runner(name, command, fallback, **kwargs):
            component_name = command[3]
            profiles = json.loads(command[4])
            component_findings = []
            def collect():
                data = stabilityd._run_component_collector(component_name, mock.Mock(), component_findings, profiles)
                return {"data": data, "findings": component_findings}
            outcome = run_component_probe(name, collect, fallback, source=kwargs["source"],
                                          max_output_bytes=kwargs["max_output_bytes"], budget_ms=kwargs["budget_ms"])
            if outcome["probe"]["status"] == "ok":
                payload = outcome["data"]
                outcome["data"], outcome["findings"] = payload["data"], payload["findings"]
            else:
                outcome["findings"] = []
            return outcome
        with mock.patch.object(stabilityd, "gateway_collect", side_effect=broken_gateway), \
             mock.patch.object(stabilityd, "cron_collect", side_effect=good("cron")), \
             mock.patch.object(stabilityd, "session_collect", side_effect=good("session")), \
             mock.patch.object(stabilityd, "channel_collect", side_effect=good("channel")), \
             mock.patch.object(stabilityd, "hermers_collect", side_effect=good("hermers")), \
             mock.patch.object(stabilityd, "auth_collect", side_effect=good("auth")), \
             mock.patch.object(stabilityd, "resource_collect", side_effect=good("resource")), \
             mock.patch.object(stabilityd, "config_collect", side_effect=good("config")), \
             mock.patch.object(stabilityd, "desired_state_drift", return_value={"drifts": []}), \
             mock.patch.object(stabilityd, "update_runtime_trends", return_value={}), \
             mock.patch.object(stabilityd, "update_streaks", return_value={}), \
             mock.patch.object(stabilityd, "add_resource_governance_findings"), \
             mock.patch.object(stabilityd, "policy_from_findings", return_value=safe_policy), \
             mock.patch.object(stabilityd, "build_auth_maintenance_plan", return_value={}):
            snapshot, findings, policy = stabilityd.collect_snapshot(
                mock.Mock(), component_probe_runner=local_probe_runner,
            )
        self.assertEqual(snapshot["gateway"].get("status"), "unknown")
        self.assertEqual(snapshot["collectorProbes"]["gateway"]["status"], "error")
        self.assertFalse(any(item.get("key") == "gateway_service_down" for item in findings))
        self.assertIn("stability_collector_gateway_probe_failed", {item.get("key") for item in findings})
        self.assertEqual(set(calls), {"cron", "session", "channel", "hermers", "auth", "resource", "config"})
        self.assertFalse(policy["canRestartGateway"])

    def test_component_worker_dispatch_is_allowlisted_and_preserves_finding_shape(self):
        calls = []
        with mock.patch.object(stabilityd, "gateway_collect", side_effect=lambda findings: calls.append("gateway") or {"active": True}), \
             mock.patch.object(stabilityd, "cron_collect", side_effect=lambda findings: calls.append("cron") or {"jobs": []}), \
             mock.patch.object(stabilityd, "session_collect", side_effect=lambda findings: calls.append("session") or {}), \
             mock.patch.object(stabilityd, "channel_collect", side_effect=lambda findings: calls.append("channel") or {}), \
             mock.patch.object(stabilityd, "hermers_collect", side_effect=lambda conn, findings, **kwargs: calls.append("hermers") or {}), \
             mock.patch.object(stabilityd, "auth_collect", side_effect=lambda conn, findings, profiles, **kwargs: calls.append(("auth", profiles)) or {}), \
             mock.patch.object(stabilityd, "resource_collect", side_effect=lambda findings: calls.append("resource") or {}), \
             mock.patch.object(stabilityd, "config_collect", side_effect=lambda findings: calls.append("config") or {}), \
             mock.patch.object(stabilityd, "desired_state_drift", side_effect=lambda: calls.append("desired_state") or {}):
            for name in sorted(stabilityd._COMPONENT_PROBE_NAMES):
                findings = []
                conn = mock.Mock() if name in stabilityd._COMPONENT_PROBE_DB_NAMES else None
                data = stabilityd._run_component_collector(name, conn, findings, ["catbody"])
                self.assertIsInstance(data, dict)
        self.assertIn(("auth", ["catbody"]), calls)
        self.assertIn("desired_state", calls)
        with self.assertRaisesRegex(ValueError, "unknown component"):
            stabilityd._run_component_collector("shell", None, [])

    def test_component_worker_db_opens_separate_existing_connection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "state.db"
            parent = sqlite3.connect(db_path)
            parent.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)")
            parent.execute("INSERT INTO kv VALUES('worker', 'parent', 1)")
            parent.commit()
            try:
                with mock.patch.object(stabilityd, "STATE_DB", db_path), \
                     mock.patch.dict(os.environ, {stabilityd._COMPONENT_PROBE_STATE_DB_ENV: str(db_path)}):
                    worker = stabilityd._open_component_probe_db()
                    try:
                        self.assertIsNot(worker, parent)
                        self.assertEqual(worker.execute("SELECT value FROM kv WHERE key='worker'").fetchone()[0], "parent")
                        with self.assertRaises(sqlite3.OperationalError):
                            worker.execute("UPDATE kv SET value='child' WHERE key='worker'")
                    finally:
                        worker.close()
                self.assertEqual(parent.execute("SELECT value FROM kv WHERE key='worker'").fetchone()[0], "parent")
                stabilityd.persist_component_cache_updates(parent, {
                    "hermers_lsp_idle_state": {"catbody:99": {"lastSeenEpoch": 10}},
                    "auth:openclaw:main": {"checkedAtEpoch": 10},
                })
                self.assertEqual(parent.execute("SELECT value FROM kv WHERE key='worker'").fetchone()[0], "parent")
                self.assertEqual(json.loads(parent.execute(
                    "SELECT value FROM kv WHERE key='hermers_lsp_idle_state'"
                ).fetchone()[0]), {"catbody:99": {"lastSeenEpoch": 10}})
                with self.assertRaisesRegex(ValueError, "allowlist"):
                    stabilityd.persist_component_cache_updates(parent, {"untrusted:key": {"x": 1}})
            finally:
                parent.close()

    def test_worker_result_encoder_enforces_output_limit_and_rejects_nonfinite(self):
        original_limit = stabilityd.COLLECTOR_OUTPUT_MAX_BYTES
        stabilityd.COLLECTOR_OUTPUT_MAX_BYTES = 64
        try:
            self.assertIsNone(stabilityd._encode_component_probe_result({"large": "x" * 1_000_000}, []))
            with self.assertRaises(ValueError):
                stabilityd._encode_component_probe_result({"invalid": float("nan")}, [])
            encoded = stabilityd._encode_component_probe_result({"ok": True}, [])
            self.assertEqual(json.loads(encoded), {"data": {"ok": True}, "findings": [], "cacheUpdates": {}})
        finally:
            stabilityd.COLLECTOR_OUTPUT_MAX_BYTES = original_limit

    def test_worker_environment_is_explicit_and_drops_secret_variables(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
             mock.patch.object(stabilityd, "STATE_DB", Path(temp_dir) / "missing.db"), \
             mock.patch.dict(os.environ, {
                 "PATH": "/bin:/usr/bin", "OPENCLAW_HOME_DIR": "/tmp/openclaw",
                 "OPENAI_API_KEY": "must-not-copy", "CAT_AGENTS_STABILITY_AUTH_MIRROR_TOKEN": "must-not-copy",
                 "HTTP_PROXY": "http://proxy-user:proxy-password@127.0.0.1:7890",
                 "HTTPS_PROXY": "http://127.0.0.1:7890", "NO_PROXY": "localhost,127.0.0.1",
                 "OPENCLAW_STABILITY_HEALTH_PROXY": "https://proxy.local/?token=must-not-copy",
             }, clear=True):
            worker_env = stabilityd.collector_worker_environment()
        self.assertEqual(worker_env["PATH"], "/bin:/usr/bin")
        self.assertEqual(worker_env["OPENCLAW_HOME_DIR"], "/tmp/openclaw")
        self.assertNotIn("OPENAI_API_KEY", worker_env)
        self.assertNotIn("CAT_AGENTS_STABILITY_AUTH_MIRROR_TOKEN", worker_env)
        self.assertNotIn("CAT_AGENTS_STABILITY_COMPONENT_STATE_DB", worker_env)
        self.assertNotIn("HTTP_PROXY", worker_env)
        self.assertEqual(worker_env["HTTPS_PROXY"], "http://127.0.0.1:7890")
        self.assertEqual(worker_env["NO_PROXY"], "localhost,127.0.0.1")
        self.assertNotIn("OPENCLAW_STABILITY_HEALTH_PROXY", worker_env)

    def test_cache_proposals_commit_only_when_all_component_outputs_are_complete(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            conn = sqlite3.connect(Path(temp_dir) / "state.db")
            conn.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)")
            conn.commit()
            safe_policy = {"canRestartGateway": False, "mode": "healthy", "severity": "ok"}

            def run_generation(fail_auth):
                def runner(name, _command, fallback, **kwargs):
                    if fail_auth and name == "auth":
                        return {"data": fallback, "findings": [], "cacheUpdates": {},
                                "probe": {"component": name, "status": "error", "coverage": False,
                                          "errorClass": "ProbeTimeout"}}
                    updates = {"hermers_lsp_idle_state": {"catbody:99": {"lastSeenEpoch": 10}}} if name == "hermers" else {}
                    return {"data": fallback, "findings": [], "cacheUpdates": updates,
                            "probe": {"component": name, "status": "ok", "coverage": True,
                                      "errorClass": None}}

                with mock.patch.object(stabilityd, "update_runtime_trends", return_value={}), \
                     mock.patch.object(stabilityd, "update_streaks", return_value={}), \
                     mock.patch.object(stabilityd, "add_resource_governance_findings"), \
                     mock.patch.object(stabilityd, "policy_from_findings", return_value=safe_policy), \
                     mock.patch.object(stabilityd, "build_auth_maintenance_plan", return_value={}):
                    return stabilityd.collect_snapshot(conn, component_probe_runner=runner)

            try:
                run_generation(fail_auth=True)
                self.assertIsNone(conn.execute("SELECT 1 FROM kv WHERE key='hermers_lsp_idle_state'").fetchone())
                run_generation(fail_auth=False)
                row = conn.execute("SELECT value FROM kv WHERE key='hermers_lsp_idle_state'").fetchone()
                self.assertEqual(json.loads(row[0]), {"catbody:99": {"lastSeenEpoch": 10}})
            finally:
                conn.close()

    def test_linux_worker_parent_death_guard_is_installed_before_collector(self):
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(stabilityd.sys, "platform", "linux"), \
             mock.patch.object(stabilityd.ctypes, "CDLL", return_value=libc), \
             mock.patch.object(stabilityd.os, "getppid", return_value=1234), \
             mock.patch.object(stabilityd.signal, "signal") as signal_install:
            self.assertTrue(stabilityd.install_component_probe_parent_death_guard(1234))
        libc.prctl.assert_called_once_with(1, stabilityd.signal.SIGTERM, 0, 0, 0)
        signal_install.assert_called_once_with(stabilityd.signal.SIGTERM, mock.ANY)

    def test_unverified_process_cleanup_aborts_snapshot_before_other_components(self):
        calls = []

        def fatal_runner(name, _command, fallback, **kwargs):
            calls.append(name)
            return {"data": fallback, "findings": [], "cacheUpdates": {},
                    "probe": {"component": name, "status": "error", "coverage": False,
                              "fatal": True, "noLiveGroupMemberObserved": False,
                              "errorClass": "ProbeCleanupFailed"}}

        with sqlite3.connect(":memory:") as conn, self.assertRaises(stabilityd.CollectorProcessCleanupFailure):
            stabilityd.collect_snapshot(conn, component_probe_runner=fatal_runner)
        self.assertEqual(calls, ["gateway"])
        with self.assertRaises(stabilityd.CollectorProcessCleanupFailure), \
             mock.patch.object(stabilityd, "ensure_dirs"), \
             mock.patch.object(stabilityd, "collect_snapshot", side_effect=stabilityd.CollectorProcessCleanupFailure), \
             mock.patch.object(stabilityd, "actuate") as actuate:
            stabilityd._run_once_body(mock.Mock())
        actuate.assert_not_called()

    def test_cleanup_blocked_cli_commands_return_nonzero(self):
        for args in (["once"], ["doctor"], ["repair"]):
            with self.subTest(args=args):
                output = []
                with mock.patch.object(stabilityd, "init_db", return_value=mock.Mock()), \
                     mock.patch.object(stabilityd, "run_once", side_effect=stabilityd.CollectorProcessCleanupFailure()), \
                     mock.patch.object(stabilityd, "print_json", side_effect=lambda value: output.append(value) or 0):
                    self.assertEqual(stabilityd.main(list(args)), 2)
                self.assertEqual(output, [{"status": "blocked", "reason": "collector-process-cleanup-unverified"}])

    def test_collector_cache_commit_failure_suppresses_actuators(self):
        with mock.patch.object(stabilityd, "actuate") as actuate:
            actions = stabilityd.actuate_collected_snapshot(
                mock.Mock(), {"collectorFatal": True}, {"canRestartGateway": True},
            )
        actuate.assert_not_called()
        self.assertEqual(actions, [{"action": "none", "result": "blocked", "reason": "collector-cache-commit-failed"}])


if __name__ == "__main__":
    unittest.main()
