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
import sys
import time
import selectors
import stat
import signal
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
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stability_core.redaction import redact_sensitive_text

DEFAULT_PROFILES = ""
PROFILE_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
MAX_OUTPUT = 131072
STATE_TTL = 90
PROBE_DEADLINE = None
REGISTRY_AGENTS: dict[str, str] = {}

def valid_profile(profile):
    return isinstance(profile, str) and bool(PROFILE_RE.fullmatch(profile))

def readonly_db():
    conn = sqlite3.connect(WORKFLOW_DB.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.25)
    conn.execute("PRAGMA query_only=ON")
    deadline = time.monotonic() + 0.25
    conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    return conn


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def run(cmd: list[str], timeout: int = 8) -> subprocess.CompletedProcess[str]:
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        output = {"out": bytearray(), "err": bytearray()}
        deadline = min(time.monotonic() + timeout, PROBE_DEADLINE or float("inf"))
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ, "out")
            selector.register(proc.stderr, selectors.EVENT_READ, "err")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("command deadline")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output[key.data].extend(chunk)
                    if sum(map(len, output.values())) > MAX_OUTPUT:
                        raise ValueError("command output budget")
        code = proc.wait(timeout=max(0.01, deadline-time.monotonic()))
        return subprocess.CompletedProcess([], code, output["out"].decode("utf-8", "replace"),
                                           output["err"].decode("utf-8", "replace"))
    except Exception as exc:
        return subprocess.CompletedProcess([], 127, "", type(exc).__name__)
    finally:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=1)
            proc.stdout.close()
            proc.stderr.close()


def systemctl_user_show(unit: str) -> dict[str, Any]:
    props = "ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp"
    out = run(["systemctl", "--user", "show", unit, f"--property={props}", "--no-pager"])
    data: dict[str, Any] = {"unit": unit, "ok": out.returncode == 0}
    if out.returncode != 0:
        data["stderr"] = redact_sensitive_text(out.stderr, 240)
    for line in out.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"MainPID", "NRestarts"}:
            try:
                data[key] = int(value or "0")
            except ValueError:
                data[key] = None
                data["numericFieldError"] = "numeric-field-invalid"
        elif key in {"ActiveState", "SubState", "ExecMainStartTimestamp"}:
            data[key] = redact_sensitive_text(value, 128)
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
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    descriptor = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_OUTPUT:
            return None
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        opened = os.fstat(descriptor)
        if identity(opened) != identity(before):
            return None
        raw = bytearray()
        while len(raw) <= MAX_OUTPUT:
            part = os.read(descriptor, min(8192, MAX_OUTPUT + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        if len(raw) > MAX_OUTPUT or identity(os.fstat(descriptor)) != identity(opened):
            return None
        if identity(path.lstat()) != identity(opened):
            return None
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (OSError, ValueError, RecursionError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def runtime_summary(agent_id: str, profile: str) -> dict[str, Any]:
    summary: dict[str, Any] = {"dbFile": str(WORKFLOW_DB), "exists": WORKFLOW_DB.exists()}
    if not WORKFLOW_DB.exists():
        return summary
    conn = None
    try:
        conn = readonly_db()
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
        summary["recentRuntimeRuns"] = [{key: redact_sensitive_text(value, 240) for key, value in dict(row).items() if key != "error"} for row in rows]
        conn.close()
    except Exception as exc:
        summary["error"] = type(exc).__name__
    finally:
        if conn is not None:
            conn.close()
    return summary


def profile_to_agent_id(profile: str) -> str:
    if profile.startswith("cat") and "_" not in profile:
        rest = profile[3:]
        return "cat_" + rest
    return profile


def runtime_record_can_receive(record: dict[str, Any]) -> bool:
    value = record.get("can_receive_dispatch")
    if value is None:
        return False
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
    REGISTRY_AGENTS.clear()
    if not WORKFLOW_DB.exists():
        meta["status"] = "missing"
        meta["error"] = "workflow db missing"
        return [], meta
    conn = None
    try:
        conn = readonly_db()
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
        if not {"agent_id", "runtime", "status", "endpoint_ref", "can_receive_dispatch"}.issubset(columns):
            conn.close()
            meta["error"] = "runtime_agents has no supported columns"
            return [], meta
        order_col = "agent_id" if "agent_id" in columns else "runtime" if "runtime" in columns else select_cols[0]
        rows = conn.execute(
            """
            SELECT {columns}
            FROM runtime_agents
            ORDER BY {order_col}
            LIMIT 257
            """.format(columns=", ".join(select_cols), order_col=order_col)
        ).fetchall()
        conn.close()
    except Exception as exc:
        meta["status"] = "unknown"
        meta["error"] = type(exc).__name__
        return [], meta
    finally:
        if conn is not None:
            conn.close()
    if len(rows) > 256:
        meta["status"] = "unknown"
        meta["error"] = "registry-row-budget"
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
        agent = record.get("agent_id")
        if not valid_profile(profile) or not valid_profile(agent):
            meta["status"] = "unknown"
            meta["error"] = "registry-identity-invalid"
            REGISTRY_AGENTS.clear()
            return [], meta
        if profile in REGISTRY_AGENTS and REGISTRY_AGENTS[profile] != agent:
            meta["status"] = "unknown"
            meta["error"] = "registry-profile-conflict"
            REGISTRY_AGENTS.clear()
            return [], meta
        REGISTRY_AGENTS[profile] = agent
        if profile not in profiles:
            profiles.append(profile)
    if len(profiles) > 16:
        REGISTRY_AGENTS.clear()
        meta["status"] = "unknown"
        meta["error"] = "profile-budget"
        return [], meta
    meta["status"] = "ready" if profiles else "empty"
    meta["profileCount"] = len(profiles)
    return profiles, meta


def probe_profile(profile: str, rows: list[dict[str, str]]) -> dict[str, Any]:
    if not valid_profile(profile) or profile not in REGISTRY_AGENTS:
        return {"profile": profile if valid_profile(profile) else "invalid", "ready": False, "liveness": "unknown", "readiness": "unknown", "findings": [], "reason": "profile-not-registered"}
    agent_id = REGISTRY_AGENTS[profile]
    unit = f"hermes-gateway-{profile}.service"
    service = systemctl_user_show(unit)
    service_known = service.get("ok") is True
    active = service_known and service.get("ActiveState") == "active" and service.get("SubState") == "running"
    state_path = HERMES_HOME / "profiles" / profile / "gateway_state.json"
    root = (HERMES_HOME / "profiles" / profile).resolve()
    if root.parent != (HERMES_HOME / "profiles").resolve() or state_path.resolve().parent != root:
        state = None
    else:
        state = load_json(state_path)
    state = state if isinstance(state, dict) else {}
    platforms = state.get("platforms")
    telegram = platforms.get("telegram", {}) if isinstance(platforms, dict) else {}
    telegram = telegram if isinstance(telegram, dict) else {}
    updated = state.get("updated_at")
    try:
        stamp = dt.datetime.fromisoformat(updated.replace("Z", "+00:00"))
        age = (dt.datetime.now(dt.timezone.utc) - stamp).total_seconds()
        fresh = 0 <= age <= STATE_TTL
    except (AttributeError, TypeError, ValueError, OverflowError):
        age, fresh = None, False
    pid = service.get("MainPID")
    identities = (type(pid) is int and pid > 0 and type(state.get("pid")) is int and
                  state["pid"] == pid and type(telegram.get("writer_pid")) is int and telegram["writer_pid"] == pid)
    if "start_time" in state or "writer_start_time" in telegram:
        identities = identities and type(state.get("start_time")) is int and state["start_time"] > 0 and type(telegram.get("writer_start_time")) is int and telegram["writer_start_time"] > 0 and state["start_time"] == telegram["writer_start_time"]
    connected = telegram.get("state") == "connected"
    ready = active and fresh and identities and state.get("gateway_state") == "running" and connected
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
    if active and not ready:
        findings.append({"severity": "warning", "key": "hermers_telegram_connectivity_unverified",
                         "message": "Fresh running gateway, process identity and connected Telegram are not all verified"})
    for worker in acp_workers:
        if worker.get("ppid") == "1":
            findings.append({"severity": "warning", "key": "hermers_acp_worker_orphan_observed", "message": "ACP worker has parent pid 1", "pid": worker.get("pid")})
    return {
        "checkedAt": now_iso(),
        "profile": profile,
        "agentId": agent_id,
        "ready": bool(ready),
        "liveness": "unknown" if not service_known else "ok" if active else "blocked",
        "readiness": "unknown" if not service_known else "ok" if ready else "degraded" if active else "blocked",
        "schemaVersion": 2, "readinessScope": "local-gateway-telegram-connectivity",
        "semanticExecutionVerified": False, "actuatorQualification": False,
        "service": service,
        "statePath": str(state_path),
        "statePresent": bool(state),
        "state": {"gateway_state": state.get("gateway_state") if isinstance(state.get("gateway_state"), str) and state.get("gateway_state") in {"running", "stopped", "starting"} else "unknown",
                  "pid": state.get("pid") if type(state.get("pid")) is int else None,
                  "updated_at": updated if fresh else None, "fresh": fresh, "ageSeconds": age},
        "gatewayProcesses": [{k: r[k] for k in ("pid", "ppid", "etimes", "rssKb") if k in r} for r in gateway_processes],
        "acpWorkers": [{k: r[k] for k in ("pid", "ppid", "etimes", "rssKb") if k in r} for r in acp_workers],
        "runtime": runtime_summary(agent_id, profile),
        "im": {
            "telegramConsumer": "connected" if ready else "unknown" if not telegram else "degraded",
            "state": telegram.get("state") if isinstance(telegram.get("state"), str) and telegram.get("state") in {"connected", "disconnected", "connecting"} else "unknown",
            "identityVerified": identities, "consumerLiveness": "unknown", "semanticReadiness": "unknown",
            "duplicateConsumerDetected": None,
            "note": "Local connectivity only; semantic reply and duplicate ownership are unverified.",
        },
        "findings": findings,
    }


def main() -> int:
    global PROBE_DEADLINE
    PROBE_DEADLINE = time.monotonic() + 20
    parser = argparse.ArgumentParser(description="Hermers read-only stability probe")
    parser.add_argument("--profiles", default=os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILES", DEFAULT_PROFILES))
    args = parser.parse_args()
    requested_profiles = [item.strip() for item in args.profiles.split(",") if item.strip()]
    registry_profiles, registry_meta = profiles_from_runtime_registry()
    invalid = [p for p in requested_profiles if not valid_profile(p) or p not in registry_profiles]
    profiles = [p for p in registry_profiles if not requested_profiles or p in requested_profiles]
    if invalid:
        registry_meta["selectionError"] = "requested-profile-not-registered"
        profiles = []
    rows = ps_rows()
    results = [probe_profile(profile, rows) for profile in profiles]
    payload = {
        "checkedAt": now_iso(),
        "probe": "hermers_stability_probe",
        "readOnly": True,
        "profileSource": "runtime_agents",
        "selection": "explicit-filter" if requested_profiles else "all-registered",
        "schemaVersion": 2, "readinessScope": "local-gateway-telegram-connectivity",
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
