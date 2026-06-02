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

        conn = stabilityd.init_db()
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
