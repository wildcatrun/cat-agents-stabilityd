#!/usr/bin/env python3
"""Hermers-side read-only stability probe for cat-agents-stability.

This probe is intentionally observational. It does not start profiles, kill
workers, change Telegram consumers, or mutate workflow state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import Any


HOME = Path(os.environ.get("HOME", "/home/flashcat"))
HERMES_HOME = Path(os.environ.get("HERMES_HOME", str(HOME / ".hermes")))
WORKFLOW_DB = Path(
    os.environ.get(
        "CAT_AGENTS_WORKFLOW_DB",
        str(HOME / "multi-agent-hedge-fund-framework" / "trading-agents-workflow" / "tracking.db"),
    )
)
DEFAULT_PROFILES = ""


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def run(cmd: list[str], timeout: int = 8) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
    except Exception as exc:
        return subprocess.CompletedProcess(cmd, 127, "", f"{type(exc).__name__}: {exc}")


def systemctl_user_show(unit: str) -> dict[str, Any]:
    props = "ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp"
    out = run(["systemctl", "--user", "show", unit, f"--property={props}", "--no-pager"])
    data: dict[str, Any] = {"unit": unit, "ok": out.returncode == 0}
    if out.returncode != 0:
        data["stderr"] = out.stderr.strip()[-500:]
    for line in out.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"MainPID", "NRestarts"}:
            try:
                data[key] = int(value or "0")
            except ValueError:
                data[key] = value
        else:
            data[key] = value
    return data


def ps_rows() -> list[dict[str, str]]:
    out = run(["ps", "-eo", "pid=,ppid=,etimes=,rss=,command="], timeout=8)
    rows = []
    for line in out.stdout.splitlines():
        parts = line.strip().split(None, 4)
        if len(parts) < 5:
            continue
        pid, ppid, etimes, rss, cmd = parts
        rows.append({"pid": pid, "ppid": ppid, "etimes": etimes, "rssKb": rss, "cmd": cmd})
    return rows


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def runtime_summary(agent_id: str, profile: str) -> dict[str, Any]:
    summary: dict[str, Any] = {"dbFile": str(WORKFLOW_DB), "exists": WORKFLOW_DB.exists()}
    if not WORKFLOW_DB.exists():
        return summary
    try:
        conn = sqlite3.connect(str(WORKFLOW_DB))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT runtime_run_id, dispatch_id, workflow_id, runtime, agent_id, adapter,
                   status, failure_type, started_at, completed_at, substr(COALESCE(error,''),1,240) AS error
            FROM runtime_runs
            WHERE agent_id=? OR acp_agent=? OR payload_json LIKE ?
            ORDER BY COALESCE(completed_at, started_at) DESC
            LIMIT 5
            """,
            (agent_id, profile, f"%{profile}%"),
        ).fetchall()
        summary["recentRuntimeRuns"] = [dict(row) for row in rows]
        conn.close()
    except Exception as exc:
        summary["error"] = f"{type(exc).__name__}: {exc}"
    return summary


def profile_to_agent_id(profile: str) -> str:
    if profile.startswith("cat") and "_" not in profile:
        rest = profile[3:]
        return "cat_" + rest
    return profile


def runtime_record_can_receive(record: dict[str, Any]) -> bool:
    value = record.get("can_receive_dispatch")
    if value is None:
        return True
    return str(value).lower() in {"1", "true", "yes", "on"}


def runtime_record_adapter_values(record: dict[str, Any]) -> set[str]:
    return {
        str(record.get("runtime") or ""),
        str(record.get("platform") or ""),
        str(record.get("execution_adapter") or ""),
        str(record.get("workflow_ingress_adapter") or ""),
    }


def runtime_record_profile(record: dict[str, Any]) -> str:
    endpoint = str(record.get("endpoint_ref") or "")
    for prefix in ("hermers-profile:", "hermes-profile:", "profile:"):
        if endpoint.startswith(prefix):
            return endpoint.split(":", 1)[1].strip()
    return ""


def runtime_record_is_hermers_dispatch_profile(record: dict[str, Any]) -> bool:
    values = runtime_record_adapter_values(record)
    endpoint_profile = runtime_record_profile(record)
    hermers_like = bool(
        {"hermers", "hermes", "hermes_acp", "hermers_acp"} & values
        or endpoint_profile
    )
    acp_like = bool(
        {"acp", "hermes_acp", "hermers_acp"} & values
        or endpoint_profile
    )
    return hermers_like and acp_like


def profiles_from_runtime_registry() -> tuple[list[str], dict[str, Any]]:
    meta: dict[str, Any] = {"source": "runtime_agents", "dbFile": str(WORKFLOW_DB), "exists": WORKFLOW_DB.exists()}
    if not WORKFLOW_DB.exists():
        meta["error"] = "workflow db missing"
        return [], meta
    try:
        conn = sqlite3.connect(str(WORKFLOW_DB))
        conn.row_factory = sqlite3.Row
        columns = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(runtime_agents)").fetchall()
            if row["name"]
        }
        wanted = [
            "agent_id",
            "runtime",
            "status",
            "platform",
            "workflow_ingress_adapter",
            "execution_adapter",
            "can_receive_dispatch",
            "endpoint_ref",
        ]
        select_cols = [name for name in wanted if name in columns]
        if not select_cols:
            conn.close()
            meta["error"] = "runtime_agents has no supported columns"
            return [], meta
        order_col = "agent_id" if "agent_id" in columns else "runtime" if "runtime" in columns else select_cols[0]
        rows = conn.execute(
            """
            SELECT {columns}
            FROM runtime_agents
            ORDER BY {order_col}
            """.format(columns=", ".join(select_cols), order_col=order_col)
        ).fetchall()
        conn.close()
    except Exception as exc:
        meta["error"] = f"{type(exc).__name__}: {exc}"
        return [], meta
    profiles: list[str] = []
    for row in rows:
        record = dict(row)
        if str(record.get("status") or "") != "active":
            continue
        if not runtime_record_can_receive(record):
            continue
        if not runtime_record_is_hermers_dispatch_profile(record):
            continue
        profile = runtime_record_profile(record)
        if profile and profile not in profiles:
            profiles.append(profile)
    meta["profileCount"] = len(profiles)
    return profiles, meta


def probe_profile(profile: str, rows: list[dict[str, str]]) -> dict[str, Any]:
    agent_id = profile_to_agent_id(profile)
    unit = f"hermes-gateway-{profile}.service"
    service = systemctl_user_show(unit)
    active = service.get("ActiveState") == "active" and service.get("SubState") == "running"
    state_path = HERMES_HOME / "profiles" / profile / "gateway_state.json"
    state = load_json(state_path)
    gateway_processes = [
        row for row in rows
        if "hermes_cli.main" in row.get("cmd", "") and f"--profile {profile} gateway run" in row.get("cmd", "")
    ]
    acp_workers = [
        row for row in rows
        if " acp" in row.get("cmd", "") and re.search(rf"(?:^|\s)-p\s+{re.escape(profile)}\s+acp(?:\s|$)", row.get("cmd", ""))
    ]
    findings = []
    if not active:
        findings.append({"severity": "high", "key": "hermers_profile_gateway_inactive", "message": f"{unit} is not active"})
    if active and not gateway_processes:
        findings.append({"severity": "warning", "key": "hermers_gateway_process_not_seen", "message": "systemd reports active but process scan did not find gateway run command"})
    for worker in acp_workers:
        if worker.get("ppid") == "1":
            findings.append({"severity": "warning", "key": "hermers_acp_worker_orphan_observed", "message": "ACP worker has parent pid 1", "pid": worker.get("pid")})
    return {
        "checkedAt": now_iso(),
        "profile": profile,
        "agentId": agent_id,
        "ready": bool(active),
        "liveness": "ok" if active else "blocked",
        "readiness": "ok" if active and not findings else "degraded",
        "service": service,
        "statePath": str(state_path),
        "statePresent": isinstance(state, dict),
        "state": state if isinstance(state, dict) else {},
        "gatewayProcesses": gateway_processes,
        "acpWorkers": acp_workers,
        "runtime": runtime_summary(agent_id, profile),
        "im": {
            "telegramConsumer": "unknown",
            "duplicateConsumerDetected": False,
            "note": "IM ownership probe is scaffolded; token/webhook migration is out of scope.",
        },
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Hermers read-only stability probe")
    parser.add_argument("--profiles", default=os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILES", DEFAULT_PROFILES))
    args = parser.parse_args()
    requested_profiles = [item.strip() for item in args.profiles.split(",") if item.strip()]
    registry_profiles, registry_meta = profiles_from_runtime_registry()
    profiles = requested_profiles or registry_profiles
    rows = ps_rows()
    results = [probe_profile(profile, rows) for profile in profiles]
    payload = {
        "checkedAt": now_iso(),
        "probe": "hermers_stability_probe",
        "readOnly": True,
        "profileSource": "explicit" if requested_profiles else "runtime_agents",
        "runtimeRegistry": registry_meta,
        "profileCount": len(results),
        "readyCount": sum(1 for item in results if item.get("ready")),
        "profiles": results,
        "findings": [finding | {"profile": item.get("profile"), "agentId": item.get("agentId")} for item in results for finding in item.get("findings", [])],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
