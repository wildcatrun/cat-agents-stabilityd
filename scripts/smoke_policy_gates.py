#!/usr/bin/env python3
"""Fast smoke checks for high-risk stabilityd policy gates."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
from pathlib import Path


def load_stabilityd(tmp: str):
    os.environ["OPENCLAW_HOME_DIR"] = tmp
    os.environ["CAT_AGENTS_WORKFLOW_DB"] = str(Path(tmp) / "missing-tracking.db")
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", None)
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_MANAGED", None)
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_PROFILE_PROTECTED_IDS", None)
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_PROTECTED", None)
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTUATE", None)
    os.environ.pop("CAT_AGENTS_STABILITY_REAP_HERMERS_IDLE_LSP", None)
    os.environ.pop("CAT_AGENTS_STABILITY_HERMERS_LSP_IDLE_SECONDS", None)
    module_path = Path(__file__).resolve().parents[1] / "bin" / "cat_agents_stabilityd.py"
    spec = importlib.util.spec_from_file_location("cat_agents_stabilityd_smoke", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cat-stability-gates-") as tmp:
        stabilityd = load_stabilityd(tmp)
        now_s = stabilityd.epoch()

        checks = {}

        checks["lifecycle_allowlist_default_empty"] = stabilityd.HERMERS_PROFILE_LIFECYCLE_ALLOWLIST == set()
        checks["unallowlisted_profile_blocked"] = not stabilityd.hermers_profile_lifecycle_allowed(
            "catears", ["cat_ears"], protected=False
        )
        stabilityd.HERMERS_PROFILE_LIFECYCLE_ALLOWLIST = {"catears"}
        checks["explicit_lifecycle_allowlist_allowed"] = stabilityd.hermers_profile_lifecycle_allowed(
            "catears", ["cat_ears"], protected=False
        )
        checks["protected_profile_blocked"] = not stabilityd.hermers_profile_lifecycle_allowed(
            "catheart", ["cat_heart"], protected=True
        )
        checks["protected_default_contains_catheart"] = "catheart" in stabilityd.HERMERS_PROFILE_PROTECTED_IDS

        missing_profile = stabilityd.hermers_profile_safe_to_hibernate(
            "catears", {"safeToHibernate": True, "updated_at": stabilityd.ts()}, now_s
        )
        mismatch = stabilityd.hermers_profile_safe_to_hibernate(
            "catears", {"profile": "catbody", "safeToHibernate": True, "updated_at": stabilityd.ts()}, now_s
        )
        false_flag = stabilityd.hermers_profile_safe_to_hibernate(
            "catears", {"profile": "catears", "safeToHibernate": False, "updated_at": stabilityd.ts()}, now_s
        )
        true_flag = stabilityd.hermers_profile_safe_to_hibernate(
            "catears", {"profile": "catears", "safeToHibernate": True, "updated_at": stabilityd.ts()}, now_s
        )
        checks["safe_missing_profile_blocks"] = missing_profile == (False, "runtime-state-profile-missing")
        checks["safe_profile_mismatch_blocks"] = mismatch == (False, "runtime-state-profile-mismatch")
        checks["safe_false_blocks"] = false_flag == (False, "runtime-safe-to-hibernate-missing")
        checks["safe_true_allows"] = true_flag == (True, "runtime-safe-to-hibernate")

        findings = []
        profiles, meta = stabilityd.hermers_profiles_from_runtime_registry(findings)
        checks["registry_missing_fail_closed"] = (
            profiles == {}
            and meta.get("source") == "runtime_agents"
            and any(item.get("key") == "hermers_profile_registry_unavailable" for item in findings)
        )
        checks["hermers_restart_disabled_by_default"] = not stabilityd.HERMERS_GATEWAY_RESTART_ENABLED
        checks["hermers_idle_lsp_reap_enabled_by_default"] = stabilityd.HERMERS_LSP_IDLE_REAP_ENABLED
        checks["hermers_idle_lsp_default_threshold_4h"] = stabilityd.HERMERS_LSP_IDLE_SECONDS == 4 * 3600
        prefixed_json = """[state-migrations] Legacy state migration warnings:
- Left plugin install index in place because shared SQLite state has conflicting plugin install metadata for: acpx
{"enabled": true, "storage": "sqlite", "sqlitePath": "/tmp/openclaw.sqlite"}"""
        payload, diagnostics, error = stabilityd.extract_json_payload(prefixed_json)
        checks["openclaw_prefixed_json_parse_ok"] = isinstance(payload, dict) and payload.get("storage") == "sqlite" and error is None
        checks["openclaw_state_migration_diagnostics_detected"] = bool(stabilityd.openclaw_state_migration_diagnostics(diagnostics))
        deep = stabilityd.parse_gateway_deep_status(
            """Connectivity probe: failed
Probe target: ws://0.0.0.0:23466
  connect failed: SECURITY ERROR: Cannot connect to "0.0.0.0" over plaintext ws://. Both credentials and chat data would be exposed to network interception.
Runtime: running (pid 123, state active, sub running, last exit 0, reason 0)
Port 23466 is already in use.
- pid 123 flashcat: /usr/bin/node /usr/lib/node_modules/openclaw/dist/index.js gateway --port 23466 (*:23466)
Listening: *:23466
Plugin version drift: 1 active official plugins not on gateway 2026.6.8
- acpx: 2026.6.1 (npm) → expected 2026.6.8
"""
        )
        checks["gateway_deep_insecure_probe_detected"] = deep.get("connectivityProbeFailed") and deep.get("insecurePlaintextWsBlocked")
        checks["gateway_deep_plugin_drift_detected"] = deep.get("pluginVersionDrift") == [{"id": "acpx", "current": "2026.6.1", "expected": "2026.6.8"}]
        cli_jobs = stabilityd.jobs_from_cron_cli_status(
            {
                "available": True,
                "byJob": {
                    "job-1": {
                        "jobId": "job-1",
                        "name": "main heartbeat",
                        "agentId": "main",
                        "enabled": True,
                        "lastStatus": "succeeded",
                        "runningAtMs": 123,
                        "timeoutSeconds": 60,
                    }
                },
            }
        )
        checks["cron_cli_jobs_fallback_builds_jobs"] = stabilityd.job_items(cli_jobs)[0][0] == "job-1"
        checks["cron_cli_jobs_fallback_preserves_running"] = stabilityd.job_items(cli_jobs)[0][1].get("runningAtMs") == 123
        stale_cli_jobs = stabilityd.jobs_from_cron_cli_status(
            {
                "available": True,
                "byJob": {
                    "stale-job": {
                        "jobId": "stale-job",
                        "name": "stale from cli",
                        "runningAtMs": stabilityd.now_ms() - (stabilityd.MIN_STALE_RUNNING_SECONDS + 5) * 1000,
                        "timeoutSeconds": 60,
                    }
                },
            }
        )
        checks["cron_cli_jobs_fallback_stale_detection"] = (
            stabilityd.find_stale_running_jobs(stale_cli_jobs)[0].get("jobId") == "stale-job"
        )
        original_run_cmd = stabilityd.run_cmd
        class FakeProc:
            returncode = 0
            stdout = """[state-migrations] Legacy state migration warnings:
- Left plugin install index in place because shared SQLite state has conflicting plugin install metadata for: acpx
{"registry":{"source":"persisted"},"plugins":[{"id":"acpx","version":"2026.6.8","enabled":true,"status":"loaded","origin":"npm"}]}"""
            stderr = ""
        try:
            stabilityd.run_cmd = lambda *_args, **_kwargs: FakeProc()
            plugin_status = stabilityd.collect_plugins_status()
        finally:
            stabilityd.run_cmd = original_run_cmd
        checks["plugins_status_prefixed_json_parse_ok"] = plugin_status.get("available") and plugin_status.get("enabledPluginCount") == 1
        checks["plugins_status_state_migration_diagnostics"] = bool(plugin_status.get("stateMigrationDiagnostics"))

        conn = stabilityd.init_db()
        stabilityd.ensure_dirs()
        lease_path = stabilityd.LEASE_DIR / "job-lease.json"
        run_path = stabilityd.RUNS_BY_RUN_DIR / "run-1.json"
        stabilityd.write_json_atomic(
            lease_path,
            {"jobId": "job-1", "runId": "run-1", "expiresAtMs": stabilityd.now_ms() - 1000},
        )
        stabilityd.write_json_atomic(
            run_path,
            {"jobId": "job-1", "runId": "run-1", "status": "running", "startedAtMs": stabilityd.now_ms() - 5000},
        )
        cron_actions = stabilityd.cron_actuate(
            {
                "cron": {
                    "storageStatus": {"storage": "sqlite"},
                    "staleRunning": [{"jobId": "job-1", "ageMs": 999999, "thresholdMs": 1}],
                    "expiredLeases": [{"path": str(lease_path), "jobId": "job-1", "runId": "run-1"}],
                }
            },
            {"canMutateCronState": False, "cronMutationBlockedReason": "openclaw-sqlite-cron-storage"},
        )
        checks["sqlite_cron_blocks_legacy_job_mutation"] = any(
            item.get("result") == "legacy_jobs_mutation_blocked_by_sqlite_storage" for item in cron_actions
        )
        checks["sqlite_cron_still_reaps_expired_leases"] = any(item.get("action") == "reap_expired_leases" for item in cron_actions) and not lease_path.exists()
        stabilityd.HERMERS_LSP_IDLE_SECONDS = 10
        lsp_process = {
            "pid": "12345",
            "ppid": "100",
            "profile": "catnose",
            "cmd": "node /home/flashcat/.hermes/profiles/catnose/lsp/bin/pyright-langserver --stdio",
            "ageSeconds": 120,
            "cpuTicks": 100,
        }
        lsp_rows = [
            {
                "pid": "12345",
                "ppid": "100",
                "stat": "Sl",
                "etime": "05:00:00",
                "rssKb": "250000",
                "cmd": lsp_process["cmd"],
            }
        ]
        checks["idle_lsp_empty_registry_collects_none"] = stabilityd.hermers_lsp_processes(lsp_rows, []) == []
        checks["idle_lsp_registry_scope_collects_known"] = len(stabilityd.hermers_lsp_processes(lsp_rows, ["catnose"])) == 1
        first_lsp = stabilityd.update_hermers_lsp_idle_state(conn, [lsp_process])[0]
        checks["idle_lsp_first_observation_not_candidate"] = not first_lsp.get("idleCandidate")
        stabilityd.db_set(
            conn,
            "hermers_lsp_idle_state",
            {
                "catnose:12345": {
                    "profile": "catnose",
                    "pid": "12345",
                    "cmd": lsp_process["cmd"],
                    "cpuTicks": 100,
                    "idleSinceEpoch": now_s - 11,
                    "lastSeenEpoch": now_s - 1,
                }
            },
        )
        idle_lsp = stabilityd.update_hermers_lsp_idle_state(conn, [lsp_process])[0]
        checks["idle_lsp_unchanged_cpu_candidate"] = bool(idle_lsp.get("idleCandidate"))
        active_lsp = stabilityd.update_hermers_lsp_idle_state(conn, [{**lsp_process, "cpuTicks": 101}])[0]
        checks["idle_lsp_cpu_advance_resets_candidate"] = not active_lsp.get("idleCandidate")
        missing_baseline_lsp = stabilityd.update_hermers_lsp_idle_state(conn, [{**lsp_process, "cpuTicks": -1}])[0]
        checks["idle_lsp_missing_cpu_baseline_not_candidate"] = not missing_baseline_lsp.get("idleCandidate")
        verify_rows = [
            lsp_rows[0],
            {
                "pid": "100",
                "ppid": "1",
                "stat": "Ssl",
                "etime": "10:00:00",
                "rssKb": "500000",
                "cmd": "/home/flashcat/hermes-agent/venv/bin/python -m hermes_cli.main --profile catnose gateway run --replace",
            },
        ]
        original_proc_cpu_ticks = stabilityd.proc_cpu_ticks
        try:
            stabilityd.proc_cpu_ticks = lambda _pid: 1
            checks["idle_lsp_zero_baseline_cpu_advance_blocks"] = stabilityd.verify_hermers_idle_lsp(
                12345,
                "catnose",
                {**lsp_process, "cpuTicks": 0, "idleObservedSeconds": 11},
                verify_rows,
            ) == (False, "cpu-advanced-after-snapshot")
            stabilityd.proc_cpu_ticks = lambda _pid: 0
            checks["idle_lsp_zero_baseline_unchanged_allows_verify"] = stabilityd.verify_hermers_idle_lsp(
                12345,
                "catnose",
                {**lsp_process, "cpuTicks": 0, "idleObservedSeconds": 11},
                verify_rows,
            ) == (True, "verified-idle-lsp")
        finally:
            stabilityd.proc_cpu_ticks = original_proc_cpu_ticks
        conn.close()

        failed = [name for name, ok in checks.items() if not ok]
        print(json.dumps({"ok": not failed, "checks": checks, "failed": failed}, indent=2, sort_keys=True))
        return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
