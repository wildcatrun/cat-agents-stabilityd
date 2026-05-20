#!/usr/bin/env python3

import fcntl
import json
import os
import shutil
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Optional


HOME = Path("/home/flashcat")
OPENCLAW_HOME = HOME / ".openclaw"
CRON_DIR = OPENCLAW_HOME / "cron"
JOBS_PATH = CRON_DIR / "jobs.json"
RUNS_DIR = CRON_DIR / "runs"
BY_RUN_DIR = RUNS_DIR / "by-run"
BY_JOB_DIR = RUNS_DIR / "by-job"
LEASES_DIR = CRON_DIR / "leases"
RUNTIME_DIR = CRON_DIR / "runtime"
SLOTS_DIR = RUNTIME_DIR / "slots"
QUEUE_DIR = RUNTIME_DIR / "queue"
SLOT_LOCK_PATH = RUNTIME_DIR / "slot-scheduler.lock"
WATCHDOG_HEALTH_PATH = CRON_DIR / "health" / "gateway-watchdog.json"
ADMISSION_STATE_PATH = RUNTIME_DIR / "admission-state.json"
ADMISSION_STATUS_PATH = RUNTIME_DIR / "admission-status.json"
LANE_POLICY_PATH = OPENCLAW_HOME / "stability" / "lane-policy.json"
DEFERRED_SUMMARY_PATH = RUNTIME_DIR / "deferred-summary.json"
DEFERRED_JSONL_PATH = RUNTIME_DIR / "deferred-runs.jsonl"

REAL_OPENCLAW = os.environ.get("OPENCLAW_BIN") or shutil.which("openclaw") or "/usr/bin/openclaw"
LEASE_HEARTBEAT_INTERVAL_SECONDS = 15
QUEUE_POLL_INTERVAL_SECONDS = int(os.environ.get("OPENCLAW_CRON_QUEUE_POLL_INTERVAL_SECONDS", "5"))
QUEUE_LOG_INTERVAL_SECONDS = int(os.environ.get("OPENCLAW_CRON_QUEUE_LOG_INTERVAL_SECONDS", "30"))
MAX_ACTIVE_CRON_RUNS = max(1, int(os.environ.get("OPENCLAW_MAX_ACTIVE_CRON_RUNS", "2")))
MAX_ACTIVE_HEARTBEATS = max(1, int(os.environ.get("OPENCLAW_MAX_ACTIVE_HEARTBEATS", "1")))
MAX_ACTIVE_RUNS_PER_AGENT = max(1, int(os.environ.get("OPENCLAW_MAX_ACTIVE_RUNS_PER_AGENT", "1")))
MAX_ACTIVE_BULK_RUNS = max(1, int(os.environ.get("OPENCLAW_MAX_ACTIVE_BULK_RUNS", "1")))
DEFAULT_SETTLE_SECONDS = max(0, int(os.environ.get("OPENCLAW_DEFAULT_SETTLE_SECONDS", "45")))
BULK_SETTLE_SECONDS = max(DEFAULT_SETTLE_SECONDS, int(os.environ.get("OPENCLAW_BULK_SETTLE_SECONDS", "180")))
AGENT_START_INTERVAL_SECONDS = max(0, int(os.environ.get("OPENCLAW_AGENT_START_INTERVAL_SECONDS", "20")))
DEFAULT_START_INTERVAL_SECONDS = max(0, int(os.environ.get("OPENCLAW_DEFAULT_START_INTERVAL_SECONDS", "15")))
BULK_START_INTERVAL_SECONDS = max(
    DEFAULT_START_INTERVAL_SECONDS,
    int(os.environ.get("OPENCLAW_BULK_START_INTERVAL_SECONDS", "180")),
)
ADMISSION_HISTORY_RETENTION_SECONDS = max(
    BULK_START_INTERVAL_SECONDS * 2,
    int(os.environ.get("OPENCLAW_ADMISSION_HISTORY_RETENTION_SECONDS", "7200")),
)
COALESCE_DEFAULT_FAMILIES = os.environ.get("OPENCLAW_COALESCE_DEFAULT_FAMILIES", "1") != "0"
COALESCE_BULK_FAMILIES = os.environ.get("OPENCLAW_COALESCE_BULK_FAMILIES", "1") != "0"
FAILURE_WINDOW_SECONDS = max(60, int(os.environ.get("OPENCLAW_FAILURE_WINDOW_SECONDS", "1800")))
HEARTBEAT_FAILURE_THRESHOLD = max(1, int(os.environ.get("OPENCLAW_HEARTBEAT_FAILURE_THRESHOLD", "2")))
DEFAULT_FAILURE_THRESHOLD = max(1, int(os.environ.get("OPENCLAW_DEFAULT_FAILURE_THRESHOLD", "2")))
BULK_FAILURE_THRESHOLD = max(1, int(os.environ.get("OPENCLAW_BULK_FAILURE_THRESHOLD", "1")))
HEARTBEAT_QUARANTINE_SECONDS = max(60, int(os.environ.get("OPENCLAW_HEARTBEAT_QUARANTINE_SECONDS", "1800")))
DEFAULT_QUARANTINE_SECONDS = max(60, int(os.environ.get("OPENCLAW_DEFAULT_QUARANTINE_SECONDS", "1800")))
BULK_QUARANTINE_SECONDS = max(60, int(os.environ.get("OPENCLAW_BULK_QUARANTINE_SECONDS", "3600")))
CONTROL_PLANE_HEAVY_JOB_IDS = {
    item.strip()
    for item in os.environ.get(
        "OPENCLAW_CONTROL_PLANE_HEAVY_JOBS",
        "afd4bb03-7481-4d92-947f-845a3f112039,dd3ec67e-b157-4030-95a2-337d35cc791a",
    ).split(",")
    if item.strip()
}
CRITICAL_JOB_IDS = {
    item.strip()
    for item in os.environ.get("OPENCLAW_CRITICAL_CRON_JOBS", "").split(",")
    if item.strip()
}

EXEC_MESSAGE_RE = re.compile(r"^\s*执行\s+(\S+)\s*$")
TRAILING_TIME_RE = re.compile(r"^(.*?)-\d{1,2}:\d{2}$")


def now_ms() -> int:
    return int(time.time() * 1000)


def ensure_dirs() -> None:
    for path in (BY_RUN_DIR, BY_JOB_DIR, LEASES_DIR, SLOTS_DIR, QUEUE_DIR):
        path.mkdir(parents=True, exist_ok=True)


def load_jobs() -> dict:
    if not JOBS_PATH.exists():
        return {"jobs": []}
    with JOBS_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def find_job(job_id: str) -> dict:
    data = load_jobs()
    for job in data.get("jobs", []):
        if job.get("id") == job_id:
            return job
    return {}


def write_json_atomic(path: Path, payload: dict) -> None:
    tmp_path = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    tmp_path.replace(path)


def append_jsonl(path: Path, payload: dict) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False))
        fh.write("\n")


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def is_heartbeat_job(job: dict) -> bool:
    return "heartbeat" in str(job.get("name") or "").lower()


def is_critical_job(job: dict) -> bool:
    job_id = str(job.get("id") or "")
    return job_id in CRITICAL_JOB_IDS or is_heartbeat_job(job)


def is_control_plane_heavy_job(job: dict) -> bool:
    job_id = str(job.get("id") or "")
    name = str(job.get("name") or "").lower()
    agent_id = str(job.get("agentId") or "")
    timeout_seconds = resolve_timeout_seconds(job)
    if job_id in CONTROL_PLANE_HEAVY_JOB_IDS:
        return True
    return agent_id == "main" and "report" in name and timeout_seconds >= 600


def load_lane_policy() -> dict:
    if not LANE_POLICY_PATH.exists():
        return {}
    try:
        policy = load_json(LANE_POLICY_PATH)
    except Exception:
        return {}
    valid_until = int(policy.get("validUntilEpoch") or 0)
    if valid_until and valid_until < int(time.time()):
        policy["_expired"] = True
    return policy


def lane_policy_active(policy: dict) -> bool:
    return bool(policy) and not policy.get("_expired")


def slot_path_for_run(run_id: str) -> Path:
    return SLOTS_DIR / f"{run_id}.json"


def queue_path_for_run(run_id: str) -> Path:
    return QUEUE_DIR / f"{run_id}.json"


def process_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def acquire_slot_lock() -> object:
    lock_fh = SLOT_LOCK_PATH.open("a+", encoding="utf-8")
    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
    return lock_fh


def release_slot_lock(lock_fh: object) -> None:
    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
    lock_fh.close()


def cleanup_stale_slots() -> list[str]:
    removed = []
    for path in sorted(SLOTS_DIR.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            path.unlink(missing_ok=True)
            removed.append(path.name)
            continue
        owner_pid = int(payload.get("ownerPid") or 0)
        run_id = str(payload.get("runId") or "")
        run_path = BY_RUN_DIR / f"{run_id}.json"
        if not run_id or not process_alive(owner_pid):
            path.unlink(missing_ok=True)
            removed.append(path.name)
            continue
        if run_path.exists():
            try:
                with run_path.open("r", encoding="utf-8") as fh:
                    run_payload = json.load(fh)
            except Exception:
                run_payload = {}
            if run_payload.get("status") not in {"running"}:
                path.unlink(missing_ok=True)
                removed.append(path.name)
    return removed


def cleanup_stale_queue_entries() -> list[str]:
    removed = []
    for path in sorted(QUEUE_DIR.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            path.unlink(missing_ok=True)
            removed.append(path.name)
            continue
        owner_pid = int(payload.get("ownerPid") or 0)
        run_id = str(payload.get("runId") or "")
        run_path = BY_RUN_DIR / f"{run_id}.json"
        if not run_id or not process_alive(owner_pid):
            path.unlink(missing_ok=True)
            removed.append(path.name)
            continue
        if run_path.exists():
            try:
                with run_path.open("r", encoding="utf-8") as fh:
                    run_payload = json.load(fh)
            except Exception:
                run_payload = {}
            if run_payload.get("status") not in {"running"}:
                path.unlink(missing_ok=True)
                removed.append(path.name)
    return removed


def active_slot_records() -> list[dict]:
    slots = []
    for path in sorted(SLOTS_DIR.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            continue
        payload["_path"] = str(path)
        slots.append(payload)
    return slots


def queued_run_records() -> list[dict]:
    records = []
    for path in sorted(QUEUE_DIR.glob("*.json")):
        try:
            with path.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            continue
        payload["_path"] = str(path)
        records.append(payload)
    records.sort(
        key=lambda item: (
            int(item.get("priorityOrder", 99)),
            int(item.get("queueEnteredAtMs", 0)),
            str(item.get("runId") or ""),
        )
    )
    return records


def write_slot_record(path: Path, payload: dict) -> None:
    write_json_atomic(path, payload)


def write_queue_record(path: Path, payload: dict) -> None:
    write_json_atomic(path, payload)


def load_watchdog_health() -> dict:
    if not WATCHDOG_HEALTH_PATH.exists():
        return {}
    try:
        return load_json(WATCHDOG_HEALTH_PATH)
    except Exception:
        return {}


def classify_gateway_pressure(health: dict) -> dict:
    if not health:
        return {
            "tier": "elevated",
            "mode": "unknown",
            "reason": "watchdog-health-unavailable",
        }
    mode = str(health.get("mode") or "unknown").lower()
    reason = str(health.get("reason") or mode or "unknown")
    if (
        mode in {"congested", "restarting", "restart-storm", "starting"}
        or health.get("isRunning") is False
        or health.get("hasListener") is False
        or health.get("tcpProbeOk") is False
    ):
        tier = "severe"
    elif (
        mode == "cooldown"
        or health.get("needsRestart") is True
        or health.get("healthOk") is False
        or int(health.get("healthFailures") or 0) > 0
        or int(health.get("congestionStreak") or 0) > 0
        or health.get("errorStorm") is True
    ):
        tier = "elevated"
    else:
        tier = "normal"
    return {
        "tier": tier,
        "mode": mode,
        "reason": reason,
    }


def trim_recent_starts(entries: list[dict]) -> list[dict]:
    cutoff_ms = now_ms() - (ADMISSION_HISTORY_RETENTION_SECONDS * 1000)
    trimmed = []
    for item in entries:
        started_at_ms = int(item.get("startedAtMs") or 0)
        if started_at_ms < cutoff_ms:
            continue
        trimmed.append(item)
    trimmed.sort(key=lambda item: int(item.get("startedAtMs") or 0))
    return trimmed


def trim_recent_failures(entries: list[dict]) -> list[dict]:
    cutoff_ms = now_ms() - (FAILURE_WINDOW_SECONDS * 1000)
    trimmed = []
    for item in entries:
        failed_at_ms = int(item.get("failedAtMs") or 0)
        if failed_at_ms < cutoff_ms:
            continue
        trimmed.append(item)
    trimmed.sort(key=lambda item: int(item.get("failedAtMs") or 0))
    return trimmed


def trim_quarantines(quarantines: dict) -> dict:
    current_ms = now_ms()
    active = {}
    for key, payload in (quarantines or {}).items():
        until_ms = int((payload or {}).get("untilMs") or 0)
        if until_ms <= current_ms:
            continue
        active[str(key)] = payload
    return active


def load_admission_state(pressure: dict) -> dict:
    current_ms = now_ms()
    if ADMISSION_STATE_PATH.exists():
        try:
            state = load_json(ADMISSION_STATE_PATH)
        except Exception:
            state = {}
    else:
        state = {}
    previous_tier = str(state.get("pressureTier") or "")
    recent_starts = trim_recent_starts(list(state.get("recentStarts") or []))
    recent_failures = trim_recent_failures(list(state.get("recentFailures") or []))
    quarantines = trim_quarantines(dict(state.get("quarantines") or {}))
    state["pressureTier"] = pressure["tier"]
    state["pressureMode"] = pressure["mode"]
    state["pressureReason"] = pressure["reason"]
    state["recentStarts"] = recent_starts
    state["recentFailures"] = recent_failures
    state["quarantines"] = quarantines
    if previous_tier != pressure["tier"]:
        state["pressureChangedAtMs"] = current_ms
        if pressure["tier"] == "normal":
            state["stableSinceMs"] = current_ms
        else:
            state["stableSinceMs"] = None
    elif pressure["tier"] == "normal":
        state["stableSinceMs"] = int(state.get("stableSinceMs") or current_ms)
    else:
        state["stableSinceMs"] = None
    state["updatedAtMs"] = current_ms
    return state


def save_admission_state(state: dict) -> None:
    write_json_atomic(ADMISSION_STATE_PATH, state)


def effective_limits(pressure: dict, lane_policy: Optional[dict] = None) -> dict:
    if pressure["tier"] in {"elevated", "severe"}:
        limits = {
            "active": 1,
            "heartbeats": 1,
            "perAgent": 1,
            "bulk": 0,
        }
    else:
        limits = {
            "active": MAX_ACTIVE_CRON_RUNS,
            "heartbeats": MAX_ACTIVE_HEARTBEATS,
            "perAgent": MAX_ACTIVE_RUNS_PER_AGENT,
            "bulk": MAX_ACTIVE_BULK_RUNS,
        }
    if lane_policy_active(lane_policy or {}):
        cron_policy = dict((lane_policy or {}).get("cron") or {})
        max_concurrency = cron_policy.get("maxConcurrency")
        if isinstance(max_concurrency, int):
            limits["active"] = max(0, min(limits["active"], max_concurrency))
        if cron_policy.get("heartbeatAllowed") is False:
            limits["heartbeats"] = 0
        if cron_policy.get("nonCriticalPaused") or cron_policy.get("admission") in {"closed", "critical-only"}:
            limits["bulk"] = 0
    return limits


def derive_admission_key(job: dict) -> str:
    agent_id = str(job.get("agentId") or "unknown")
    if is_heartbeat_job(job):
        return f"heartbeat:{agent_id}"
    payload = job.get("payload") or {}
    message = str(payload.get("message") or "").strip()
    match = EXEC_MESSAGE_RE.match(message)
    if match:
        return f"command:{match.group(1)}"
    name = str(job.get("name") or job.get("id") or "job")
    trailing_match = TRAILING_TIME_RE.match(name)
    if trailing_match:
        return f"family:{agent_id}:{trailing_match.group(1)}"
    return f"job:{job.get('id') or name}"


def resolve_timeout_seconds(job: dict) -> int:
    timeout_seconds = (
        ((job.get("execution") or {}).get("timeoutSeconds"))
        or ((job.get("payload") or {}).get("timeoutSeconds"))
        or 300
    )
    try:
        timeout_seconds = int(timeout_seconds)
    except (TypeError, ValueError):
        timeout_seconds = 300
    return max(timeout_seconds, 60)


def classify_queue_profile(job: dict) -> tuple[int, str]:
    name = str(job.get("name") or "").lower()
    timeout_seconds = resolve_timeout_seconds(job)
    if is_heartbeat_job(job):
        return 0, "heartbeat"
    if (
        timeout_seconds >= 600
        or "trading-futures" in name
        or "memory dreaming" in name
        or "backup" in name
        or "daily log" in name
    ):
        return 2, "bulk"
    return 1, "default"


def lane_preflight(job: dict, lane_policy: dict) -> tuple[bool, str]:
    if not lane_policy_active(lane_policy):
        return True, "lane-policy-unavailable"
    cron_policy = dict(lane_policy.get("cron") or {})
    control_policy = dict(lane_policy.get("controlPlane") or {})
    admission = str(cron_policy.get("admission") or "open")
    if control_policy.get("heavyReports") == "defer" and is_control_plane_heavy_job(job):
        return False, "control-plane-heavy-report-deferred"
    if admission == "closed":
        return False, "cron-admission-closed"
    if admission == "critical-only" and not is_critical_job(job):
        return False, "cron-critical-only"
    return True, "lane-admitted"


def required_settle_seconds(queue_class: str) -> int:
    if queue_class == "heartbeat":
        return 0
    if queue_class == "bulk":
        return BULK_SETTLE_SECONDS
    return DEFAULT_SETTLE_SECONDS


def required_start_interval_seconds(queue_class: str) -> int:
    if queue_class == "heartbeat":
        return 0
    if queue_class == "bulk":
        return BULK_START_INTERVAL_SECONDS
    return DEFAULT_START_INTERVAL_SECONDS


def last_recent_start_ms(
    admission_state: dict,
    *,
    agent_id: Optional[str] = None,
    admission_key: Optional[str] = None,
) -> int:
    for item in reversed(list(admission_state.get("recentStarts") or [])):
        if agent_id and str(item.get("agentId") or "") != agent_id:
            continue
        if admission_key and str(item.get("admissionKey") or "") != admission_key:
            continue
        return int(item.get("startedAtMs") or 0)
    return 0


def write_admission_status(
    *,
    pressure: dict,
    lane_policy: dict,
    admission_state: dict,
    limits: dict,
    active_slots: list[dict],
    queued_runs: list[dict],
    next_eligible_run_id: Optional[str],
) -> None:
    queue_classes: dict[str, int] = {}
    for item in queued_runs:
        queue_class = str(item.get("queueClass") or "default")
        queue_classes[queue_class] = queue_classes.get(queue_class, 0) + 1
    payload = {
        "updatedAtMs": now_ms(),
        "pressureTier": pressure["tier"],
        "pressureMode": pressure["mode"],
        "pressureReason": pressure["reason"],
        "lanePolicyActive": lane_policy_active(lane_policy),
        "lanePolicyUpdatedAtEpoch": lane_policy.get("updatedAtEpoch"),
        "lanePolicyValidUntilEpoch": lane_policy.get("validUntilEpoch"),
        "laneCronAdmission": ((lane_policy.get("cron") or {}).get("admission") if lane_policy else None),
        "laneCronMaxConcurrency": ((lane_policy.get("cron") or {}).get("maxConcurrency") if lane_policy else None),
        "laneControlPlaneHeavyReports": ((lane_policy.get("controlPlane") or {}).get("heavyReports") if lane_policy else None),
        "stableSinceMs": admission_state.get("stableSinceMs"),
        "pressureChangedAtMs": admission_state.get("pressureChangedAtMs"),
        "limits": limits,
        "activeCount": len(active_slots),
        "queuedCount": len(queued_runs),
        "queuedByClass": queue_classes,
        "nextEligibleRunId": next_eligible_run_id,
        "recentStartCount": len(list(admission_state.get("recentStarts") or [])),
        "recentFailureCount": len(list(admission_state.get("recentFailures") or [])),
        "activeQuarantineCount": len(dict(admission_state.get("quarantines") or {})),
        "activeQuarantines": dict(admission_state.get("quarantines") or {}),
    }
    write_json_atomic(ADMISSION_STATUS_PATH, payload)


def failure_threshold_for_class(queue_class: str) -> int:
    if queue_class == "heartbeat":
        return HEARTBEAT_FAILURE_THRESHOLD
    if queue_class == "bulk":
        return BULK_FAILURE_THRESHOLD
    return DEFAULT_FAILURE_THRESHOLD


def quarantine_duration_for_class(queue_class: str) -> int:
    if queue_class == "heartbeat":
        return HEARTBEAT_QUARANTINE_SECONDS
    if queue_class == "bulk":
        return BULK_QUARANTINE_SECONDS
    return DEFAULT_QUARANTINE_SECONDS


def active_quarantine_for_key(admission_state: dict, admission_key: str) -> dict:
    if not admission_key:
        return {}
    return dict((admission_state.get("quarantines") or {}).get(admission_key) or {})


def note_run_failure(admission_state: dict, run_record: dict, queue_class: str, admission_key: str) -> dict:
    failed_at_ms = now_ms()
    recent_failures = trim_recent_failures(
        list(admission_state.get("recentFailures") or [])
        + [
            {
                "failedAtMs": failed_at_ms,
                "runId": run_record.get("runId"),
                "jobId": run_record.get("jobId"),
                "jobName": run_record.get("jobName"),
                "agentId": run_record.get("agentId"),
                "queueClass": queue_class,
                "admissionKey": admission_key,
                "failureClass": ((run_record.get("failure") or {}).get("class") or "unknown"),
                "returnCode": ((run_record.get("failure") or {}).get("returnCode")),
            }
        ]
    )
    admission_state["recentFailures"] = recent_failures
    if not admission_key:
        return admission_state
    matching = [item for item in recent_failures if str(item.get("admissionKey") or "") == admission_key]
    if len(matching) < failure_threshold_for_class(queue_class):
        return admission_state
    duration_seconds = quarantine_duration_for_class(queue_class)
    admission_state["quarantines"] = dict(admission_state.get("quarantines") or {})
    admission_state["quarantines"][admission_key] = {
        "admissionKey": admission_key,
        "queueClass": queue_class,
        "jobId": run_record.get("jobId"),
        "jobName": run_record.get("jobName"),
        "agentId": run_record.get("agentId"),
        "activatedAtMs": failed_at_ms,
        "untilMs": failed_at_ms + (duration_seconds * 1000),
        "failureCount": len(matching),
        "failureWindowSeconds": FAILURE_WINDOW_SECONDS,
        "durationSeconds": duration_seconds,
        "lastFailureClass": ((run_record.get("failure") or {}).get("class") or "unknown"),
        "lastReturnCode": ((run_record.get("failure") or {}).get("returnCode")),
    }
    return admission_state


def note_run_success(admission_state: dict, admission_key: str) -> dict:
    if not admission_key:
        return admission_state
    admission_state["recentFailures"] = [
        item
        for item in list(admission_state.get("recentFailures") or [])
        if str(item.get("admissionKey") or "") != admission_key
    ]
    quarantines = dict(admission_state.get("quarantines") or {})
    quarantines.pop(admission_key, None)
    admission_state["quarantines"] = quarantines
    return admission_state


def update_quarantined(run_record: dict, reason: str, quarantine: dict) -> dict:
    finished = now_ms()
    run_record["status"] = "quarantined"
    run_record["finishedAtMs"] = finished
    run_record["durationMs"] = finished - run_record["startedAtMs"]
    run_record["result"] = {
        "quarantined": True,
        "reason": reason,
        "untilMs": quarantine.get("untilMs"),
        "failureCount": quarantine.get("failureCount"),
    }
    run_record["failure"] = None
    return run_record


def is_family_coalescable(entry: dict) -> bool:
    queue_class = str(entry.get("queueClass") or "default")
    admission_key = str(entry.get("admissionKey") or "")
    if not admission_key or admission_key.startswith("heartbeat:") or admission_key.startswith("job:"):
        return False
    if queue_class == "bulk":
        return COALESCE_BULK_FAMILIES
    if queue_class == "default":
        return COALESCE_DEFAULT_FAMILIES
    return False


def latest_family_queue_run_ids(queued_runs: list[dict]) -> dict[str, str]:
    latest: dict[str, str] = {}
    for entry in queued_runs:
        if not is_family_coalescable(entry):
            continue
        admission_key = str(entry.get("admissionKey") or "")
        run_id = str(entry.get("runId") or "")
        if admission_key and run_id:
            latest[admission_key] = run_id
    return latest


def update_coalesced(run_record: dict, reason: str, replacement_run_id: str) -> dict:
    finished = now_ms()
    run_record["status"] = "coalesced"
    run_record["finishedAtMs"] = finished
    run_record["durationMs"] = finished - run_record["startedAtMs"]
    run_record["result"] = {
        "coalesced": True,
        "reason": reason,
        "replacementRunId": replacement_run_id,
    }
    run_record["failure"] = None
    return run_record


def update_deferred(run_record: dict, reason: str, lane_policy: dict) -> dict:
    finished = now_ms()
    run_record["status"] = "deferred"
    run_record["finishedAtMs"] = finished
    run_record["durationMs"] = finished - run_record["startedAtMs"]
    run_record["result"] = {
        "deferred": True,
        "reason": reason,
        "lanePolicyUpdatedAtEpoch": lane_policy.get("updatedAtEpoch"),
        "lanePolicyValidUntilEpoch": lane_policy.get("validUntilEpoch"),
        "cronAdmission": ((lane_policy.get("cron") or {}).get("admission") if lane_policy else None),
        "controlPlaneHeavyReports": ((lane_policy.get("controlPlane") or {}).get("heavyReports") if lane_policy else None),
    }
    run_record["failure"] = None
    record_deferred_run(run_record, reason, lane_policy)
    return run_record


def record_deferred_run(run_record: dict, reason: str, lane_policy: dict) -> None:
    current_ms = now_ms()
    event = {
        "ts": current_ms,
        "runId": run_record.get("runId"),
        "jobId": run_record.get("jobId"),
        "jobName": run_record.get("jobName"),
        "agentId": run_record.get("agentId"),
        "reason": reason,
        "cronAdmission": ((lane_policy.get("cron") or {}).get("admission") if lane_policy else None),
        "controlPlaneHeavyReports": ((lane_policy.get("controlPlane") or {}).get("heavyReports") if lane_policy else None),
    }
    append_jsonl(DEFERRED_JSONL_PATH, event)
    try:
        summary = load_json(DEFERRED_SUMMARY_PATH) if DEFERRED_SUMMARY_PATH.exists() else {}
    except Exception:
        summary = {}
    by_reason = dict(summary.get("byReason") or {})
    by_job = dict(summary.get("byJob") or {})
    by_reason[reason] = int(by_reason.get(reason) or 0) + 1
    job_key = str(run_record.get("jobId") or "unknown")
    job_bucket = dict(by_job.get(job_key) or {})
    job_bucket["jobId"] = job_key
    job_bucket["jobName"] = run_record.get("jobName")
    job_bucket["agentId"] = run_record.get("agentId")
    job_bucket["count"] = int(job_bucket.get("count") or 0) + 1
    job_bucket["lastReason"] = reason
    job_bucket["lastDeferredAtMs"] = current_ms
    by_job[job_key] = job_bucket
    recent = list(summary.get("recent") or [])
    recent.append(event)
    recent = recent[-50:]
    payload = {
        "updatedAtMs": current_ms,
        "totalDeferred": int(summary.get("totalDeferred") or 0) + 1,
        "byReason": by_reason,
        "byJob": by_job,
        "recent": recent,
    }
    write_json_atomic(DEFERRED_SUMMARY_PATH, payload)


def can_run_entry(
    entry: dict,
    active_slots: list[dict],
    pressure: dict,
    lane_policy: dict,
    admission_state: dict,
) -> tuple[bool, str]:
    limits = effective_limits(pressure, lane_policy)
    if len(active_slots) >= limits["active"]:
        return False, "active-limit"
    entry_class = str(entry.get("queueClass") or "default")
    lane_admission = str(((lane_policy or {}).get("cron") or {}).get("admission") or "open")
    if lane_policy_active(lane_policy):
        if lane_admission == "closed":
            return False, "lane-cron-closed"
        if lane_admission == "critical-only" and entry_class != "heartbeat":
            return False, "lane-critical-only"
    agent_id = str(entry.get("agentId") or "")
    admission_key = str(entry.get("admissionKey") or "")
    active_heartbeats = sum(1 for slot in active_slots if slot.get("queueClass") == "heartbeat")
    active_bulk = sum(1 for slot in active_slots if slot.get("queueClass") == "bulk")
    active_same_agent = sum(1 for slot in active_slots if str(slot.get("agentId") or "") == agent_id and agent_id)
    if pressure["tier"] == "severe" and entry_class != "heartbeat":
        return False, f"gateway-{pressure['tier']}"
    if entry_class == "heartbeat" and active_heartbeats >= limits["heartbeats"]:
        return False, "heartbeat-limit"
    if entry_class == "bulk":
        if limits["bulk"] <= 0:
            return False, "bulk-paused"
        if active_bulk >= limits["bulk"]:
            return False, "bulk-limit"
    if agent_id and active_same_agent >= limits["perAgent"]:
        return False, "per-agent-limit"
    settle_seconds = required_settle_seconds(entry_class)
    if settle_seconds > 0:
        stable_since_ms = admission_state.get("stableSinceMs")
        if not isinstance(stable_since_ms, int):
            return False, "gateway-not-stable"
        if now_ms() - stable_since_ms < (settle_seconds * 1000):
            return False, "gateway-settling"
    start_interval_seconds = required_start_interval_seconds(entry_class)
    if start_interval_seconds > 0 and admission_key:
        last_family_start_ms = last_recent_start_ms(
            admission_state,
            admission_key=admission_key,
        )
        if last_family_start_ms and now_ms() - last_family_start_ms < (start_interval_seconds * 1000):
            return False, "family-cooldown"
    if entry_class != "heartbeat" and AGENT_START_INTERVAL_SECONDS > 0 and agent_id:
        last_agent_start_ms = last_recent_start_ms(
            admission_state,
            agent_id=agent_id,
        )
        if last_agent_start_ms and now_ms() - last_agent_start_ms < (AGENT_START_INTERVAL_SECONDS * 1000):
            return False, "agent-cooldown"
    return True, "ready"


def acquire_execution_slot(run_record: dict, job: dict, run_path: Path) -> Optional[Path]:
    queue_entered_at_ms = now_ms()
    last_log_at_ms = queue_entered_at_ms
    priority_order, queue_class = classify_queue_profile(job)
    admission_key = derive_admission_key(job)
    queue_path = queue_path_for_run(run_record["runId"])
    write_queue_record(
        queue_path,
        {
            "runId": run_record["runId"],
            "jobId": run_record["jobId"],
            "jobName": run_record.get("jobName"),
            "agentId": run_record.get("agentId"),
            "ownerPid": os.getpid(),
            "queueEnteredAtMs": queue_entered_at_ms,
            "priorityOrder": priority_order,
            "queueClass": queue_class,
            "admissionKey": admission_key,
        },
    )
    while True:
        wait_reason = "unknown"
        lock_fh = acquire_slot_lock()
        try:
            cleanup_stale_slots()
            cleanup_stale_queue_entries()
            active_slots = active_slot_records()
            queued_runs = queued_run_records()
            health = load_watchdog_health()
            pressure = classify_gateway_pressure(health)
            lane_policy = load_lane_policy()
            admission_state = load_admission_state(pressure)
            limits = effective_limits(pressure, lane_policy)
            quarantine = active_quarantine_for_key(admission_state, admission_key)
            if quarantine:
                write_admission_status(
                    pressure=pressure,
                    lane_policy=lane_policy,
                    admission_state=admission_state,
                    limits=limits,
                    active_slots=active_slots,
                    queued_runs=queued_runs,
                    next_eligible_run_id=None,
                )
                run_record["scheduler"] = {
                    "queueEnteredAtMs": queue_entered_at_ms,
                    "queueWaitMs": now_ms() - queue_entered_at_ms,
                    "priorityOrder": priority_order,
                    "queueClass": queue_class,
                    "admissionKey": admission_key,
                    "pressureTier": pressure["tier"],
                    "pressureMode": pressure["mode"],
                    "pressureReason": pressure["reason"],
                    "state": "quarantined",
                    "waitReason": "failure-quarantine",
                    "quarantineUntilMs": quarantine.get("untilMs"),
                    "quarantineFailureCount": quarantine.get("failureCount"),
                }
                run_record = update_quarantined(
                    run_record,
                    "failure-quarantine",
                    quarantine,
                )
                write_json_atomic(run_path, run_record)
                write_job_summary(run_record)
                return None
            latest_family_runs = latest_family_queue_run_ids(queued_runs)
            current_family_run_id = latest_family_runs.get(admission_key)
            if (
                current_family_run_id
                and current_family_run_id != run_record["runId"]
                and is_family_coalescable(
                    {
                        "queueClass": queue_class,
                        "admissionKey": admission_key,
                    }
                )
            ):
                run_record["scheduler"] = {
                    "queueEnteredAtMs": queue_entered_at_ms,
                    "queueWaitMs": now_ms() - queue_entered_at_ms,
                    "priorityOrder": priority_order,
                    "queueClass": queue_class,
                    "admissionKey": admission_key,
                    "pressureTier": pressure["tier"],
                    "pressureMode": pressure["mode"],
                    "pressureReason": pressure["reason"],
                    "state": "coalesced",
                    "waitReason": "superseded-by-newer-family-run",
                    "replacementRunId": current_family_run_id,
                }
                run_record = update_coalesced(
                    run_record,
                    "superseded-by-newer-family-run",
                    current_family_run_id,
                )
                write_json_atomic(run_path, run_record)
                write_job_summary(run_record)
                return None
            next_eligible_run_id = None
            for entry in queued_runs:
                allowed, reason = can_run_entry(
                    entry,
                    active_slots,
                    pressure,
                    lane_policy,
                    admission_state,
                )
                if entry.get("runId") == run_record["runId"]:
                    wait_reason = reason
                if allowed:
                    next_eligible_run_id = str(entry.get("runId") or "")
                    break
            write_admission_status(
                pressure=pressure,
                lane_policy=lane_policy,
                admission_state=admission_state,
                limits=limits,
                active_slots=active_slots,
                queued_runs=queued_runs,
                next_eligible_run_id=next_eligible_run_id,
            )
            if next_eligible_run_id == run_record["runId"]:
                acquired_at_ms = now_ms()
                admission_state["recentStarts"] = trim_recent_starts(
                    list(admission_state.get("recentStarts") or [])
                    + [
                        {
                            "runId": run_record["runId"],
                            "jobId": run_record["jobId"],
                            "jobName": run_record.get("jobName"),
                            "agentId": run_record.get("agentId"),
                            "queueClass": queue_class,
                            "admissionKey": admission_key,
                            "startedAtMs": acquired_at_ms,
                        }
                    ]
                )
                save_admission_state(admission_state)
                run_record["scheduler"] = {
                    "queueEnteredAtMs": queue_entered_at_ms,
                    "queueWaitMs": acquired_at_ms - queue_entered_at_ms,
                    "acquiredSlotAtMs": acquired_at_ms,
                    "activeRunLimit": limits["active"],
                    "activeHeartbeatLimit": limits["heartbeats"],
                    "activeRunsPerAgentLimit": limits["perAgent"],
                    "activeBulkRunLimit": limits["bulk"],
                    "priorityOrder": priority_order,
                    "queueClass": queue_class,
                    "admissionKey": admission_key,
                    "pressureTier": pressure["tier"],
                    "pressureMode": pressure["mode"],
                    "pressureReason": pressure["reason"],
                    "stableSinceMs": admission_state.get("stableSinceMs"),
                }
                write_json_atomic(run_path, run_record)
                slot_path = slot_path_for_run(run_record["runId"])
                write_slot_record(
                    slot_path,
                    {
                        "runId": run_record["runId"],
                        "jobId": run_record["jobId"],
                        "jobName": run_record.get("jobName"),
                        "agentId": run_record.get("agentId"),
                        "priorityOrder": priority_order,
                        "queueClass": queue_class,
                        "admissionKey": admission_key,
                        "ownerPid": os.getpid(),
                        "queueEnteredAtMs": queue_entered_at_ms,
                        "acquiredAtMs": acquired_at_ms,
                    },
                )
                return slot_path
        finally:
            release_slot_lock(lock_fh)
        current_ms = now_ms()
        if current_ms - last_log_at_ms >= QUEUE_LOG_INTERVAL_SECONDS * 1000:
            health = load_watchdog_health()
            pressure = classify_gateway_pressure(health)
            lane_policy = load_lane_policy()
            limits = effective_limits(pressure, lane_policy)
            stable_since_ms = None
            if ADMISSION_STATE_PATH.exists():
                try:
                    stable_since_ms = load_json(ADMISSION_STATE_PATH).get("stableSinceMs")
                except Exception:
                    stable_since_ms = None
            run_record["scheduler"] = {
                "queueEnteredAtMs": queue_entered_at_ms,
                "queueWaitMs": current_ms - queue_entered_at_ms,
                "activeRunLimit": limits["active"],
                "activeHeartbeatLimit": limits["heartbeats"],
                "activeRunsPerAgentLimit": limits["perAgent"],
                "activeBulkRunLimit": limits["bulk"],
                "priorityOrder": priority_order,
                "queueClass": queue_class,
                "admissionKey": admission_key,
                "pressureTier": pressure["tier"],
                "pressureMode": pressure["mode"],
                "pressureReason": pressure["reason"],
                "lanePolicyActive": lane_policy_active(lane_policy),
                "laneCronAdmission": ((lane_policy.get("cron") or {}).get("admission") if lane_policy else None),
                "stableSinceMs": stable_since_ms,
                "state": "waiting-for-slot",
                "waitReason": wait_reason,
            }
            write_json_atomic(run_path, run_record)
            last_log_at_ms = current_ms
        time.sleep(max(1, QUEUE_POLL_INTERVAL_SECONDS))


def build_run_record(job: dict, job_id: str, run_id: str, argv: list[str]) -> dict:
    started = now_ms()
    timeout_seconds = resolve_timeout_seconds(job)

    return {
        "runId": run_id,
        "jobId": job_id,
        "jobName": job.get("name"),
        "attempt": 1,
        "status": "running",
        "trigger": "cli-cron-run",
        "createdAtMs": started,
        "startedAtMs": started,
        "finishedAtMs": None,
        "durationMs": None,
        "leaseOwner": f"{socket.gethostname()}:{os.getpid()}",
        "leaseExpiresAtMs": started + (timeout_seconds * 1000),
        "fencingToken": started,
        "timeoutSeconds": timeout_seconds,
        "sessionTarget": job.get("sessionTarget"),
        "agentId": job.get("agentId"),
        "admissionKey": derive_admission_key(job),
        "command": [REAL_OPENCLAW, *argv],
        "result": None,
        "failure": None,
    }


def build_lease_record(run_record: dict) -> dict:
    return {
        "runId": run_record["runId"],
        "jobId": run_record["jobId"],
        "leaseOwner": run_record["leaseOwner"],
        "fencingToken": run_record["fencingToken"],
        "acquiredAtMs": run_record["startedAtMs"],
        "heartbeatAtMs": run_record["startedAtMs"],
        "expiresAtMs": run_record["leaseExpiresAtMs"],
        "phase": "running",
    }


def refresh_lease(run_record: dict, lease_path: Path) -> None:
    current = now_ms()
    lease_record = {
        "runId": run_record["runId"],
        "jobId": run_record["jobId"],
        "leaseOwner": run_record["leaseOwner"],
        "fencingToken": run_record["fencingToken"],
        "acquiredAtMs": run_record["startedAtMs"],
        "heartbeatAtMs": current,
        "expiresAtMs": current + (run_record["timeoutSeconds"] * 1000),
        "phase": run_record["status"],
    }
    run_record["leaseExpiresAtMs"] = lease_record["expiresAtMs"]
    write_json_atomic(lease_path, lease_record)
    write_json_atomic(BY_RUN_DIR / f"{run_record['runId']}.json", run_record)


def lease_heartbeat_loop(
    run_record: dict,
    lease_path: Path,
    stop_event: threading.Event,
) -> None:
    while not stop_event.wait(LEASE_HEARTBEAT_INTERVAL_SECONDS):
        try:
            refresh_lease(run_record, lease_path)
        except Exception:
            # Keep the wrapped cron invocation running even if heartbeat persistence fails.
            continue


def update_success(run_record: dict, returncode: int) -> dict:
    finished = now_ms()
    run_record["status"] = "succeeded" if returncode == 0 else "failed"
    run_record["finishedAtMs"] = finished
    run_record["durationMs"] = finished - run_record["startedAtMs"]
    if returncode == 0:
        run_record["result"] = {"returnCode": returncode}
        run_record["failure"] = None
    else:
        run_record["result"] = None
        run_record["failure"] = {"class": "cli_exit_nonzero", "returnCode": returncode}
    return run_record


def write_job_summary(run_record: dict) -> None:
    summary = {
        "ts": now_ms(),
        "jobId": run_record["jobId"],
        "runId": run_record["runId"],
        "action": "wrapped-cli-run",
        "status": run_record["status"],
        "durationMs": run_record["durationMs"],
        "startedAtMs": run_record["startedAtMs"],
        "finishedAtMs": run_record["finishedAtMs"],
        "returnCode": (
            (run_record.get("result") or {}).get("returnCode")
            if run_record.get("result")
            else (run_record.get("failure") or {}).get("returnCode")
        ),
    }
    append_jsonl(BY_JOB_DIR / f"{run_record['jobId']}.jsonl", summary)


def persist_post_run_admission(run_record: dict, slot_path: Optional[Path]) -> None:
    queue_class = str(((run_record.get("scheduler") or {}).get("queueClass")) or "default")
    admission_key = str(run_record.get("admissionKey") or ((run_record.get("scheduler") or {}).get("admissionKey")) or "")
    lock_fh = acquire_slot_lock()
    try:
        cleanup_stale_slots()
        cleanup_stale_queue_entries()
        pressure = classify_gateway_pressure(load_watchdog_health())
        lane_policy = load_lane_policy()
        admission_state = load_admission_state(pressure)
        if run_record.get("status") == "succeeded":
            admission_state = note_run_success(admission_state, admission_key)
        elif run_record.get("status") == "failed":
            admission_state = note_run_failure(admission_state, run_record, queue_class, admission_key)
        save_admission_state(admission_state)
        active_slots = active_slot_records()
        queued_runs = queued_run_records()
        current_slot = str(slot_path) if slot_path is not None else ""
        if current_slot:
            active_slots = [slot for slot in active_slots if str(slot.get("_path") or "") != current_slot]
        write_admission_status(
            pressure=pressure,
            lane_policy=lane_policy,
            admission_state=admission_state,
            limits=effective_limits(pressure, lane_policy),
            active_slots=active_slots,
            queued_runs=queued_runs,
            next_eligible_run_id=None,
        )
    finally:
        release_slot_lock(lock_fh)


def main() -> int:
    argv = sys.argv[1:]
    if len(argv) < 3 or argv[0] != "cron" or argv[1] != "run":
        os.execv(REAL_OPENCLAW, [REAL_OPENCLAW, *argv])
    job_id = argv[2]
    ensure_dirs()
    job = find_job(job_id)
    run_id = str(uuid.uuid4())
    run_path = BY_RUN_DIR / f"{run_id}.json"
    lease_path = LEASES_DIR / f"{run_id}.json"

    run_record = build_run_record(job, job_id, run_id, argv)
    lease_record = build_lease_record(run_record)

    write_json_atomic(run_path, run_record)
    write_json_atomic(lease_path, lease_record)

    env = os.environ.copy()
    env["OPENCLAW_CRON_RUN_ID"] = run_id
    env["OPENCLAW_CRON_JOB_ID"] = job_id

    stop_event = threading.Event()
    heartbeat_thread = threading.Thread(
        target=lease_heartbeat_loop,
        args=(run_record, lease_path, stop_event),
        daemon=True,
    )
    heartbeat_thread.start()
    slot_path = None
    queue_path = queue_path_for_run(run_id)
    try:
        lane_policy = load_lane_policy()
        lane_allowed, lane_reason = lane_preflight(job, lane_policy)
        if not lane_allowed:
            run_record["scheduler"] = {
                "state": "deferred-by-lane-policy",
                "waitReason": lane_reason,
                "lanePolicyActive": lane_policy_active(lane_policy),
                "lanePolicyUpdatedAtEpoch": lane_policy.get("updatedAtEpoch"),
                "lanePolicyValidUntilEpoch": lane_policy.get("validUntilEpoch"),
                "cronAdmission": ((lane_policy.get("cron") or {}).get("admission") if lane_policy else None),
                "controlPlaneHeavyReports": ((lane_policy.get("controlPlane") or {}).get("heavyReports") if lane_policy else None),
            }
            run_record = update_deferred(run_record, lane_reason, lane_policy)
            write_json_atomic(run_path, run_record)
            write_job_summary(run_record)
            return 0
        slot_path = acquire_execution_slot(run_record, job, run_path)
        if slot_path is None:
            return 0
        proc = subprocess.run([REAL_OPENCLAW, *argv], env=env)
        run_record = update_success(run_record, proc.returncode)
        write_json_atomic(run_path, run_record)
        persist_post_run_admission(run_record, slot_path)
        write_job_summary(run_record)
        return proc.returncode
    finally:
        stop_event.set()
        heartbeat_thread.join(timeout=1)
        queue_path.unlink(missing_ok=True)
        if slot_path is not None:
            slot_path.unlink(missing_ok=True)
        lease_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
