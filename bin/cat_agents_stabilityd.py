#!/usr/bin/env python3
"""Cat agents stability control plane.

This daemon replaces independent watchdog/guard/controller scripts with a
single policy engine and actuator surface for the OpenClaw cloud runtime.
It intentionally uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import errno
import fcntl
import glob
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


HOME = Path(os.environ.get("OPENCLAW_HOME_DIR", "/home/flashcat"))
OPENCLAW = HOME / ".openclaw"
HERMES_HOME = HOME / ".hermes"
HERMES_CLI = os.environ.get("CAT_AGENTS_STABILITY_HERMES_CLI", str(HOME / ".local/bin/hermes"))


def default_workflow_root() -> Path:
    configured = os.environ.get("CAT_AGENTS_WORKFLOW_ROOT")
    if configured:
        return Path(configured)
    primary = HOME / "multi-agent-hedge-fund-framework" / "trading-agents-workflow"
    mac_primary = Path("/Users/Flashcat/multi-agent-hedge-fund-framework/trading-agents-workflow")
    if primary.exists():
        return primary
    if mac_primary.exists():
        return mac_primary
    return primary


WORKFLOW_ROOT = default_workflow_root()
WORKFLOW_DB = Path(os.environ.get("CAT_AGENTS_WORKFLOW_DB", str(WORKFLOW_ROOT / "tracking.db")))
WORKFLOW_RUNTIME_AGENTS_SNAPSHOT = Path(
    os.environ.get(
        "CAT_AGENTS_WORKFLOW_RUNTIME_AGENTS_SNAPSHOT",
        str(WORKFLOW_ROOT / "registry" / "runtime-agents.snapshot.json"),
    )
)
WORKFLOW_GOVERNANCE_LOG_DIR = WORKFLOW_ROOT / "governance-logs"
SCRIPTS = HOME / "scripts"
STABILITY_DIR = OPENCLAW / "stability"
LOG_DIR = OPENCLAW / "logs"
CRON_DIR = OPENCLAW / "cron"
AGENTS_DIR = OPENCLAW / "agents"
TELEGRAM_DIR = OPENCLAW / "telegram"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]

LATEST_PATH = STABILITY_DIR / "latest.json"
POLICY_PATH = STABILITY_DIR / "policy.json"
EVENTS_JSONL = STABILITY_DIR / "events.jsonl"
ACTIONS_JSONL = STABILITY_DIR / "actions.jsonl"
STATE_DB = STABILITY_DIR / "state.db"
LOCK_PATH = STABILITY_DIR / "stabilityd.lock"
LOG_PATH = STABILITY_DIR / "stabilityd.log"
RESOURCE_EVIDENCE_DIR = STABILITY_DIR / "resource-evidence"
RESOURCE_HUMAN_GATE_DIR = STABILITY_DIR / "human-gate"
RESOURCE_INCIDENT_DIR = STABILITY_DIR / "incidents"
RESOURCE_INCIDENT_LATEST = RESOURCE_INCIDENT_DIR / "gateway-resource-pressure-latest.json"
CONTROL_PLANE_BACKPRESSURE_PATH = STABILITY_DIR / "control-plane-backpressure.json"
LANE_POLICY_PATH = STABILITY_DIR / "lane-policy.json"
HERMERS_PROFILE_MODES_PATH = STABILITY_DIR / "hermers-profile-modes.json"
WORKFLOW_STABILITY_EVIDENCE_JSON = WORKFLOW_GOVERNANCE_LOG_DIR / "stability-evidence-latest.json"
WORKFLOW_STABILITY_EVIDENCE_MD = WORKFLOW_GOVERNANCE_LOG_DIR / "stability-evidence-latest.md"
DESIRED_STATE_PATH = Path(
    os.environ.get("CAT_AGENTS_STABILITY_DESIRED_STATE", str(PACKAGE_ROOT / "policies" / "desired-state.json"))
)
CODEX_CONFIG_PATH = Path(os.environ.get("CAT_AGENTS_STABILITY_CODEX_CONFIG", "/Users/Flashcat/.codex/config.toml"))

LEGACY_WATCHDOG_HEALTH = CRON_DIR / "health" / "gateway-watchdog.json"
CRON_AUDIT_PATH = CRON_DIR / "health" / "cron-audit-latest.json"
SESSION_GUARD_LATEST = OPENCLAW / "health" / "session-guard-latest.json"
OLD_HEALTH_CONTROLLER_LATEST = OPENCLAW / "health" / "openclaw-health-controller-latest.json"
JOBS_PATH = CRON_DIR / "jobs.json"
LEASE_DIR = CRON_DIR / "leases"
RUNS_BY_RUN_DIR = CRON_DIR / "runs" / "by-run"
RUNS_BY_JOB_DIR = CRON_DIR / "runs" / "by-job"
ORPHAN_RUNS_BY_JOB_DIR = CRON_DIR / "runs" / "orphaned-by-job"
REPAIR_DIR = CRON_DIR / "repair-requests"
REPAIR_PENDING_DIR = REPAIR_DIR / "pending"
REPAIR_PROCESSED_DIR = REPAIR_DIR / "processed"
REPAIR_STATUS_PATH = REPAIR_DIR / "status.json"
GATEWAY_ERR_LOG = LOG_DIR / "gateway.err.log"

PORT = int(os.environ.get("OPENCLAW_GATEWAY_PORT", "23466"))
INTERVAL_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_INTERVAL_SECONDS", "30"))
POLICY_TTL_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_POLICY_TTL_SECONDS", "180"))
LOG_PRESSURE_WINDOW_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_LOG_PRESSURE_WINDOW_SECONDS", "900"))
TREND_WINDOW_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_TREND_WINDOW_SECONDS", "1800"))
TREND_SAMPLE_LIMIT = int(os.environ.get("OPENCLAW_STABILITY_TREND_SAMPLE_LIMIT", "240"))
MEMORY_GROWTH_WARN_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_MEMORY_GROWTH_WARN_GB", "0.75")) * 1024**3)
CHILD_GROWTH_WARN_COUNT = int(os.environ.get("OPENCLAW_STABILITY_CHILD_GROWTH_WARN", "4"))
CRON_AUDIT_FRESH_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_CRON_AUDIT_FRESH_SECONDS", "3600"))
LEGACY_CRON_AUDIT_REQUIRED = os.environ.get("OPENCLAW_STABILITY_LEGACY_CRON_AUDIT_REQUIRED", "0") == "1"
CRON_HISTORY_WINDOW_DAYS = int(os.environ.get("OPENCLAW_STABILITY_CRON_HISTORY_DAYS", "7"))
CRON_HEARTBEAT_WARN_MS = int(os.environ.get("OPENCLAW_STABILITY_CRON_HEARTBEAT_WARN_MS", "60000"))
CRON_LONG_RUN_WARN_MS = int(os.environ.get("OPENCLAW_STABILITY_CRON_LONG_RUN_WARN_MS", str(15 * 60 * 1000)))
CRON_TIMEOUT_NEAR_MISS_MS = int(os.environ.get("OPENCLAW_STABILITY_CRON_TIMEOUT_NEAR_MISS_MS", "2000"))
CRON_MAX_CONCURRENCY_NORMAL = int(os.environ.get("OPENCLAW_STABILITY_CRON_MAX_CONCURRENCY_NORMAL", "3"))
CRON_MAX_CONCURRENCY_DEGRADED = int(os.environ.get("OPENCLAW_STABILITY_CRON_MAX_CONCURRENCY_DEGRADED", "1"))
CRON_RECOVERY_LIMITED_HEALTHY_STREAK = int(os.environ.get("OPENCLAW_STABILITY_CRON_RECOVERY_LIMITED_STREAK", "5"))
CRON_RECOVERY_OPEN_HEALTHY_STREAK = int(os.environ.get("OPENCLAW_STABILITY_CRON_RECOVERY_OPEN_STREAK", "10"))
RESTART_COOLDOWN_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_RESTART_COOLDOWN_SECONDS", "1800"))
RESTART_WINDOW_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_RESTART_WINDOW_SECONDS", str(6 * 3600)))
MAX_RESTARTS_PER_WINDOW = int(os.environ.get("OPENCLAW_STABILITY_MAX_RESTARTS", "2"))
ACTION_STREAK_THRESHOLD = int(os.environ.get("OPENCLAW_STABILITY_ACTION_STREAK", "2"))
STARTUP_GRACE_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_STARTUP_GRACE_SECONDS", "240"))
MEMORY_WARN_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_MEMORY_WARN_GB", "5.0")) * 1024**3)
MEMORY_CRIT_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_MEMORY_CRIT_GB", "6.5")) * 1024**3)
SWAP_WARN_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SWAP_WARN_GB", "0.8")) * 1024**3)
SWAP_CRIT_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SWAP_CRIT_GB", "1.8")) * 1024**3)
SYSTEM_MEMORY_AVAILABLE_WARN_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_MEM_AVAILABLE_WARN_GB", "1.0")) * 1024**3)
SYSTEM_MEMORY_AVAILABLE_CRIT_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_MEM_AVAILABLE_CRIT_GB", "0.5")) * 1024**3)
SYSTEM_SWAP_WARN_RATIO = float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_SWAP_WARN_RATIO", "0.50"))
SYSTEM_SWAP_CRIT_RATIO = float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_SWAP_CRIT_RATIO", "0.90"))
SYSTEM_COMMIT_WARN_RATIO = float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_COMMIT_WARN_RATIO", "0.95"))
SYSTEM_COMMIT_CRIT_RATIO = float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_COMMIT_CRIT_RATIO", "1.10"))
RESOURCE_INCIDENT_STREAK_THRESHOLD = int(os.environ.get("OPENCLAW_STABILITY_RESOURCE_INCIDENT_STREAK", "3"))
RESOURCE_EVIDENCE_CAPTURE_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_RESOURCE_EVIDENCE_SECONDS", "600"))
RESOURCE_HUMAN_GATE_REFRESH_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_RESOURCE_HUMAN_GATE_SECONDS", "300"))
BACKUP_HEADROOM_WARN_RATIO = float(os.environ.get("OPENCLAW_STABILITY_BACKUP_HEADROOM_WARN_RATIO", "1.20"))
BACKUP_KEEP_COUNT = int(os.environ.get("OPENCLAW_STABILITY_BACKUP_KEEP_COUNT", "3"))

HERMERS_PROFILE_FALLBACKS: List[str] = []
HERMERS_ACP_ORPHAN_REAP_ENABLED = os.environ.get(
    "CAT_AGENTS_STABILITY_REAP_HERMERS_ACP_ORPHANS",
    os.environ.get("OPENCLAW_STABILITY_REAP_HERMERS_ACP_ORPHANS", "1"),
) != "0"
HERMERS_GATEWAY_RESTART_ENABLED = os.environ.get(
    "CAT_AGENTS_STABILITY_RESTART_HERMERS_GATEWAY",
    os.environ.get("OPENCLAW_STABILITY_RESTART_HERMERS_GATEWAY", "0"),
) == "1"
HERMERS_GATEWAY_RESTART_LIMIT = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_GATEWAY_RESTART_LIMIT", str(MAX_RESTARTS_PER_WINDOW)))
HERMERS_ACP_ORPHAN_MIN_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_ACP_ORPHAN_SECONDS", "120"))
HERMERS_ACP_LONG_RUNNING_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_ACP_LONG_SECONDS", "600"))
HERMERS_LSP_IDLE_REAP_ENABLED = os.environ.get("CAT_AGENTS_STABILITY_REAP_HERMERS_IDLE_LSP", "1") != "0"
HERMERS_LSP_IDLE_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_LSP_IDLE_SECONDS", str(4 * 3600)))
HERMERS_LSP_IDLE_STATE_TTL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_LSP_IDLE_STATE_TTL_SECONDS", str(24 * 3600)))
HERMERS_FAILURE_WINDOW_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_FAILURE_WINDOW_SECONDS", "1800"))
HERMERS_FAILURE_BURST_THRESHOLD = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_FAILURE_BURST", "5"))
HERMERS_STALE_SENT_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_STALE_SENT_SECONDS", "600"))
HERMERS_PROFILE_MODE_ENABLED = os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ENABLED", "1") != "0"
HERMERS_PROFILE_MODE_ACTUATE_ENABLED = os.environ.get(
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTUATE",
    os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_ACTUATE", "0"),
) != "0"
HERMERS_PROFILE_MODE_START_ENABLED = os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_START", "1") != "0"
HERMERS_PROFILE_LIFECYCLE_ALLOWLIST = {
    item.strip()
    for item in os.environ.get(
        "CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST",
        os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_MANAGED", ""),
    ).split(",")
    if item.strip()
}
HERMERS_PROFILE_COLD_IDLE_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_COLD_IDLE_SECONDS", str(30 * 60)))
HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS", str(8 * 3600)))
HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS = int(
    os.environ.get(
        "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTION_COOLDOWN_SECONDS",
        os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS", "600"),
    )
)
HERMERS_PROFILE_PROTECTED_IDS = {
    item.strip()
    for item in os.environ.get(
        "CAT_AGENTS_STABILITY_HERMERS_PROFILE_PROTECTED_IDS",
        os.environ.get("CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_PROTECTED", "main,cat_heart,catheart,cat_claw"),
    ).split(",")
    if item.strip()
}

TMP_FILE_MAX_AGE_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_TMP_MAX_AGE_SECONDS", "3600"))
ORPHAN_RUN_LOG_MIN_AGE_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_ORPHAN_RUN_LOG_MIN_AGE_SECONDS", "3600"))
MIN_STALE_RUNNING_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_MIN_STALE_RUNNING_SECONDS", "1800"))
STALE_RUNNING_TIMEOUT_MULTIPLIER = int(os.environ.get("OPENCLAW_STABILITY_STALE_RUNNING_MULTIPLIER", "4"))
LEASE_REAP_ENABLED = os.environ.get("OPENCLAW_STABILITY_REAP_LEASES", "1") != "0"
SESSION_RESET_ENABLED = os.environ.get("OPENCLAW_STABILITY_RESET_SESSIONS", "1") != "0"
CRON_MUTATION_ENABLED = os.environ.get("OPENCLAW_STABILITY_MUTATE_CRON", "1") != "0"
GATEWAY_RESTART_ENABLED = os.environ.get("OPENCLAW_STABILITY_RESTART_GATEWAY", "1") != "0"
GATEWAY_RESTART_ACTUATOR_SUPPORTED = True
SOFT_GATEWAY_RESTART_ENABLED = os.environ.get("OPENCLAW_STABILITY_SOFT_RESTART_GATEWAY", "0") == "1"
SOFT_RESCUE_RESTART_ENABLED = os.environ.get("OPENCLAW_STABILITY_SOFT_RESCUE_RESTART", "1") != "0"
SOFT_RESCUE_STREAK_THRESHOLD = int(os.environ.get("OPENCLAW_STABILITY_SOFT_RESCUE_STREAK", "20"))

SESSION_RESET_COOLDOWN_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_SESSION_RESET_COOLDOWN_SECONDS", str(6 * 3600)))
SESSION_FAIL_WINDOW_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_SESSION_FAIL_WINDOW_SECONDS", "1800"))
SESSION_OVERFLOW_WINDOW_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_SESSION_OVERFLOW_WINDOW_SECONDS", "900"))
SESSION_FAIL_THRESHOLD = int(os.environ.get("OPENCLAW_STABILITY_SESSION_FAIL_THRESHOLD", "3"))
SESSION_OVERFLOW_THRESHOLD = int(os.environ.get("OPENCLAW_STABILITY_SESSION_OVERFLOW_THRESHOLD", "3"))
ACTIVE_PROGRESS_WINDOW_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_SESSION_ACTIVE_WINDOW_SECONDS", "300"))
ACTIVE_PROGRESS_EVENT_THRESHOLD = int(os.environ.get("OPENCLAW_STABILITY_SESSION_ACTIVE_EVENTS", "2"))
HEAVY_TASK_WINDOW_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_HEAVY_WINDOW_SECONDS", "1800"))
HEAVY_TASK_EVENT_THRESHOLD = int(os.environ.get("OPENCLAW_STABILITY_HEAVY_EVENTS", "3"))
CONTROL_PLANE_HEAVY_JOB_IDS = {
    item.strip()
    for item in os.environ.get("OPENCLAW_STABILITY_CONTROL_PLANE_HEAVY_JOBS", "afd4bb03-7481-4d92-947f-845a3f112039").split(",")
    if item.strip()
}
CONTROL_PLANE_HEARTBEAT_JOB_IDS = {
    item.strip()
    for item in os.environ.get("OPENCLAW_STABILITY_CONTROL_PLANE_HEARTBEAT_JOBS", "d68d571d-3c38-4a5e-9c5c-7f5a4d00371d").split(",")
    if item.strip()
}
CONTROL_PLANE_DIRECT_SESSION_KEYS = {
    item.strip()
    for item in os.environ.get("OPENCLAW_STABILITY_CONTROL_PLANE_DIRECT_SESSIONS", "agent:main:telegram:direct:8390724843").split(",")
    if item.strip()
}
CONTROL_PLANE_BACKPRESSURE_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_CONTROL_PLANE_BACKPRESSURE_SECONDS", "1800"))

SEVERITY_RANK = {"ok": 0, "info": 1, "warning": 2, "high": 3, "critical": 4}
EVENT_TYPES_ACTIVE = {"message", "tool_call", "tool_result", "patch", "exec", "custom"}
MESSAGE_ROLES_ACTIVE = {"assistant", "toolResult"}
HEAVY_TOOL_NAMES = {"read", "write", "edit", "patch", "exec", "bash", "grep", "glob", "ls", "sessions_spawn", "sessions_send", "sessions_yield", "web_fetch", "memory_search", "memory_get"}
HEAVY_TASK_TOKENS = {"trading_sim", "git ", "pytest", "npm ", "docker", ".py", ".js", ".ts", ".html", "apply_patch", "toolName", "build", "compile", "session", "cron", "memory", "diff --git"}

FAIL_MARKERS = (
    "LLM request timed out",
    "surface_error reason=timeout",
    "decision=fallback_model reason=timeout",
    "decision=surface_error reason=timeout",
    "network connection error",
    "fetch failed",
    "The AI service is temporarily overloaded",
    "overloaded_error",
    "provider unavailable",
    "gateway timeout",
    "app-server timeout",
    "stuck session:",
)

OVERFLOW_MARKERS = (
    "[context-overflow-diag]",
    "context overflow detected",
    "estimated context size exceeds safe threshold",
    "context length exceeded",
    "context_length_exceeded",
    "maximum context length",
    "context overflow",
)

IGNORED_ORPHAN_RUN_IDS = {"invalid-job-id"}
IGNORED_ORPHAN_RUN_PREFIXES = ("test-",)

RESOURCE_PRESSURE_KEYS = {
    "gateway_resource_incident",
    "gateway_resource_saturation",
    "gateway_resource_pressure",
    "gateway_swap_saturation",
    "gateway_swap_pressure",
    "gateway_memory_growth",
    "system_memory_saturation",
    "system_memory_pressure",
    "system_swap_saturation",
    "system_swap_pressure",
    "system_commit_saturation",
    "system_commit_pressure",
    "disk_pressure",
}

RESOURCE_INCIDENT_IMMEDIATE_KEYS = {
    "gateway_resource_saturation",
    "gateway_swap_saturation",
    "system_memory_saturation",
    "system_swap_saturation",
    "system_commit_saturation",
    "disk_pressure",
}

RESOURCE_INCIDENT_SUSTAINED_KEYS = {
    "gateway_resource_pressure",
    "gateway_swap_pressure",
    "gateway_memory_growth",
    "system_memory_pressure",
    "system_swap_pressure",
    "system_commit_pressure",
}


def epoch() -> int:
    return int(time.time())


def now_ms() -> int:
    return int(time.time() * 1000)


def ts() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z")


def ensure_dirs() -> None:
    for path in (
        STABILITY_DIR,
        LOG_DIR,
        CRON_DIR / "health",
        CRON_DIR / "guard",
        LEASE_DIR,
        RUNS_BY_RUN_DIR,
        RUNS_BY_JOB_DIR,
        ORPHAN_RUNS_BY_JOB_DIR,
        REPAIR_PENDING_DIR,
        REPAIR_PROCESSED_DIR,
        RESOURCE_EVIDENCE_DIR,
        RESOURCE_HUMAN_GATE_DIR,
        RESOURCE_INCIDENT_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)


def log_line(message: str) -> None:
    ensure_dirs()
    line = f"{ts()} {message}\n"
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(line)


def load_json(path: Path, default: Any = None) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default
    except Exception:
        return default


def write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{int(time.time() * 1000)}.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    tmp.replace(path)


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False, sort_keys=False))
        fh.write("\n")


def tail_text(path: Path, max_bytes: int = 4_000_000) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
            return fh.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def file_age_seconds(path: Path) -> Optional[int]:
    try:
        return max(0, int(time.time() - path.stat().st_mtime))
    except FileNotFoundError:
        return None
    except Exception:
        return None


def parse_iso_epoch(value: Any) -> Optional[int]:
    if not value:
        return None
    if isinstance(value, (int, float)):
        if value > 10_000_000_000:
            return int(value / 1000)
        return int(value)
    if not isinstance(value, str):
        return None
    try:
        return int(dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except Exception:
        pass
    systemd_match = re.search(r"^[A-Za-z]{3}\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\S+$", value)
    if systemd_match:
        value = systemd_match.group(1)
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            return int(dt.datetime.strptime(value, fmt).timestamp())
        except Exception:
            continue
    return None


def run_cmd(cmd: List[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)


def run_user_cmd(cmd: List[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, env=env)


def run_hermes_profile_gateway_cmd(profile: str, command: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    if command not in {"start", "stop", "restart", "status"}:
        raise ValueError(f"unsupported Hermers gateway command: {command}")
    cmd = [HERMES_CLI, "-p", profile, "gateway", command]
    return run_user_cmd(cmd, timeout=timeout)


def command_probe(cmd: List[str], timeout: int = 5, max_chars: int = 16_000) -> Dict[str, Any]:
    started = time.time()
    try:
        proc = run_cmd(cmd, timeout=timeout)
        duration = int((time.time() - started) * 1000)
        return {
            "cmd": cmd,
            "exitCode": proc.returncode,
            "durationMs": duration,
            "stdout": proc.stdout[-max_chars:],
            "stderr": proc.stderr[-max_chars:],
        }
    except Exception as exc:
        duration = int((time.time() - started) * 1000)
        return {
            "cmd": cmd,
            "exitCode": -1,
            "durationMs": duration,
            "error": f"{type(exc).__name__}: {exc}",
        }


def extract_json_payload(text: str) -> Tuple[Optional[Any], List[str], Optional[str]]:
    """Parse CLI JSON while preserving OpenClaw diagnostic preambles."""
    diagnostics: List[str] = []
    if not text:
        return None, diagnostics, "empty"
    starts = sorted(idx for idx, char in enumerate(text) if char in "{[")
    if not starts:
        return None, [line for line in text.splitlines() if line.strip()][:20], "json_start_missing"
    decoder = json.JSONDecoder()
    first_error: Optional[str] = None
    for start in starts:
        prefix = text[:start].strip()
        payload_text = text[start:].strip()
        try:
            payload, _ = decoder.raw_decode(payload_text)
            if prefix:
                diagnostics = [line for line in prefix.splitlines() if line.strip()][:40]
            try:
                return json.loads(payload_text), diagnostics, None
            except Exception as exc:
                return payload, diagnostics, f"trailing_non_json_ignored: {exc}"
        except Exception as exc:
            if first_error is None:
                first_error = str(exc)
            continue
    prefix_lines = [line for line in text.splitlines() if line.strip()][:40]
    return None, prefix_lines, f"json_parse_failed: {first_error or 'unknown'}"


def openclaw_state_migration_diagnostics(diagnostics: Iterable[str]) -> List[str]:
    return [line for line in diagnostics if "state-migrations" in line or "Legacy state migration" in line or "plugin install index" in line]


def parse_openclaw_version(text: str) -> Dict[str, Any]:
    match = re.search(r"OpenClaw\s+([^\s]+)(?:\s+\(([^)]+)\))?", text or "")
    if not match:
        return {"raw": (text or "").strip()}
    return {
        "raw": (text or "").strip(),
        "version": match.group(1),
        "commit": match.group(2),
    }


def collect_openclaw_version() -> Dict[str, Any]:
    probe = command_probe(["openclaw", "--version"], timeout=8, max_chars=2000)
    version = parse_openclaw_version(str(probe.get("stdout") or probe.get("stderr") or ""))
    version["probe"] = {k: v for k, v in probe.items() if k not in {"stdout", "stderr"}}
    return version


def parse_gateway_deep_status(text: str) -> Dict[str, Any]:
    lines = [line.rstrip() for line in (text or "").splitlines()]
    joined = "\n".join(lines)
    plugin_drifts = []
    drift_re = re.compile(r"^-\s+([^:]+):\s+([^\s]+)\s+\([^)]+\)\s+→\s+expected\s+([^\s]+)")
    for line in lines:
        match = drift_re.search(line.strip())
        if match:
            plugin_drifts.append({"id": match.group(1).strip(), "current": match.group(2), "expected": match.group(3)})
    runtime_match = re.search(r"Runtime:\s+(\S+)(?:\s+\(pid\s+(\d+),\s+state\s+([^,]+),\s+sub\s+([^,]+))?", joined)
    service_match = re.search(r"Service:\s+(.+)", joined)
    bind_match = re.search(r"Gateway:\s+bind=([^,]+),\s+port=(\d+)", joined)
    client_match = re.search(r"Established clients:\s+(\d+)", joined)
    return {
        "rawSample": joined[-4000:],
        "runtimeState": runtime_match.group(1) if runtime_match else None,
        "runtimePid": int(runtime_match.group(2)) if runtime_match and runtime_match.group(2) else None,
        "systemdState": runtime_match.group(3).strip() if runtime_match and runtime_match.group(3) else None,
        "systemdSubState": runtime_match.group(4).strip() if runtime_match and runtime_match.group(4) else None,
        "service": service_match.group(1).strip() if service_match else None,
        "bind": bind_match.group(1).strip() if bind_match else None,
        "port": int(bind_match.group(2)) if bind_match else None,
        "connectivityProbeFailed": "Connectivity probe: failed" in joined,
        "insecurePlaintextWsBlocked": "SECURITY ERROR: Cannot connect to \"0.0.0.0\" over plaintext ws://" in joined,
        "portInUse": "Port 23466 is already in use" in joined or f"Port {PORT} is already in use" in joined,
        "listening": "Listening:" in joined,
        "pluginVersionDrift": plugin_drifts,
        "establishedClients": int(client_match.group(1)) if client_match else None,
    }


def collect_gateway_deep_status() -> Dict[str, Any]:
    probe = command_probe(["openclaw", "gateway", "status", "--deep"], timeout=18, max_chars=20_000)
    text = "\n".join(str(probe.get(key) or "") for key in ("stdout", "stderr"))
    parsed = parse_gateway_deep_status(text)
    parsed["probe"] = {k: v for k, v in probe.items() if k not in {"stdout", "stderr"}}
    return parsed


def collect_cron_storage_status() -> Dict[str, Any]:
    try:
        out = run_cmd(["openclaw", "cron", "status", "--json"], timeout=15)
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    text = "\n".join([out.stdout or "", out.stderr or ""])
    payload, diagnostics, error = extract_json_payload(text)
    result: Dict[str, Any] = {
        "available": out.returncode == 0 and isinstance(payload, dict),
        "exitCode": out.returncode,
        "diagnostics": diagnostics,
    }
    if error:
        result["parseWarning"] = error
    if isinstance(payload, dict):
        result.update(
            {
                "enabled": payload.get("enabled"),
                "storePath": payload.get("storePath"),
                "storage": payload.get("storage"),
                "sqlitePath": payload.get("sqlitePath"),
                "jobs": payload.get("jobs"),
                "nextWakeAtMs": payload.get("nextWakeAtMs"),
            }
        )
    elif out.returncode != 0:
        result["stderr"] = out.stderr[-1000:]
    return result


def collect_plugins_status() -> Dict[str, Any]:
    try:
        out = run_cmd(["openclaw", "plugins", "list", "--json"], timeout=20)
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    text = "\n".join([out.stdout or "", out.stderr or ""])
    payload, diagnostics, error = extract_json_payload(text)
    result: Dict[str, Any] = {
        "available": out.returncode == 0 and isinstance(payload, dict),
        "exitCode": out.returncode,
        "diagnostics": diagnostics,
        "stateMigrationDiagnostics": openclaw_state_migration_diagnostics(diagnostics),
    }
    if error:
        result["parseWarning"] = error
    if isinstance(payload, dict):
        plugins = payload.get("plugins") if isinstance(payload.get("plugins"), list) else []
        enabled = [item for item in plugins if isinstance(item, dict) and item.get("enabled") is True]
        result.update(
            {
                "registry": payload.get("registry"),
                "pluginCount": len([item for item in plugins if isinstance(item, dict)]),
                "enabledPluginCount": len(enabled),
                "enabledPlugins": [
                    {
                        "id": item.get("id"),
                        "version": item.get("version"),
                        "status": item.get("status"),
                        "origin": item.get("origin"),
                    }
                    for item in enabled[:50]
                ],
            }
        )
    elif out.returncode != 0:
        result["stderr"] = out.stderr[-1000:]
    return result


def meminfo_bytes() -> Dict[str, int]:
    data: Dict[str, int] = {}
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
    except Exception:
        return data
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        parts = raw.strip().split()
        if not parts:
            continue
        with contextlib.suppress(Exception):
            value = int(parts[0])
            unit = parts[1].lower() if len(parts) > 1 else "b"
            data[key] = value * 1024 if unit == "kb" else value
    return data


def resource_pressure_active(keys: set[str]) -> bool:
    return bool(RESOURCE_PRESSURE_KEYS & keys)


def etime_seconds(value: Any) -> int:
    raw = str(value or "").strip()
    if not raw:
        return 0
    days = 0
    if "-" in raw:
        day_part, raw = raw.split("-", 1)
        with contextlib.suppress(Exception):
            days = int(day_part)
    parts = raw.split(":")
    try:
        if len(parts) == 3:
            hours, minutes, seconds = [int(part) for part in parts]
        elif len(parts) == 2:
            hours = 0
            minutes, seconds = [int(part) for part in parts]
        else:
            hours = 0
            minutes = 0
            seconds = int(parts[0])
        return days * 86400 + hours * 3600 + minutes * 60 + seconds
    except Exception:
        return 0


def init_db() -> sqlite3.Connection:
    ensure_dirs()
    conn = sqlite3.connect(str(STATE_DB))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, source TEXT, component TEXT, severity TEXT, key TEXT, payload TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, action_id TEXT, action TEXT, result TEXT, payload TEXT NOT NULL)"
    )
    conn.commit()
    return conn


def db_get(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    if not row:
        return default
    try:
        return json.loads(row[0])
    except Exception:
        return default


def db_set(conn: sqlite3.Connection, key: str, value: Any) -> None:
    conn.execute(
        "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (key, json.dumps(value, ensure_ascii=False), epoch()),
    )
    conn.commit()


def db_record_event(conn: sqlite3.Connection, event: Dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO events(ts_epoch, source, component, severity, key, payload) VALUES(?, ?, ?, ?, ?, ?)",
        (
            int(event.get("tsEpoch") or epoch()),
            event.get("source"),
            event.get("component"),
            event.get("severity"),
            event.get("key"),
            json.dumps(event, ensure_ascii=False),
        ),
    )
    conn.commit()
    append_jsonl(EVENTS_JSONL, event)


def db_record_action(conn: sqlite3.Connection, action: Dict[str, Any]) -> None:
    conn.execute(
        "INSERT INTO actions(ts_epoch, action_id, action, result, payload) VALUES(?, ?, ?, ?, ?)",
        (
            int(action.get("tsEpoch") or epoch()),
            action.get("actionId"),
            action.get("action"),
            action.get("result"),
            json.dumps(action, ensure_ascii=False),
        ),
    )
    conn.commit()
    append_jsonl(ACTIONS_JSONL, action)


def add_finding(
    findings: List[Dict[str, Any]],
    key: str,
    severity: str,
    component: str,
    message: str,
    **extra: Any,
) -> None:
    payload = {
        "key": key,
        "severity": severity,
        "component": component,
        "message": message,
    }
    payload.update(extra)
    findings.append(payload)


def max_severity(findings: Iterable[Dict[str, Any]]) -> str:
    highest = "ok"
    for item in findings:
        sev = str(item.get("severity") or "ok")
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(highest, 0):
            highest = sev
    return highest


def load_desired_state() -> Dict[str, Any]:
    state = load_json(DESIRED_STATE_PATH, {}) or {}
    if not isinstance(state, dict):
        return {}
    return state


def desired_state_required_files(state: Dict[str, Any]) -> List[str]:
    surfaces = state.get("packageSurfaces") if isinstance(state.get("packageSurfaces"), dict) else {}
    files = surfaces.get("requiredFiles") if isinstance(surfaces.get("requiredFiles"), list) else []
    return [str(item) for item in files if str(item).strip()]


def _snapshot_bool(value: Any, fallback: int = 1) -> int:
    if value is None or value == "":
        return fallback
    if isinstance(value, bool):
        return 1 if value else 0
    text = str(value).strip().lower()
    if text in {"0", "false", "no", "off", "disabled"}:
        return 0
    if text in {"1", "true", "yes", "on", "enabled"}:
        return 1
    return fallback


def _registry_snapshot_records(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    records = snapshot.get("records") if isinstance(snapshot.get("records"), list) else []
    if not records and isinstance(snapshot.get("runtimeRegistry"), dict):
        for agents in snapshot["runtimeRegistry"].values():
            if isinstance(agents, list):
                records.extend(item for item in agents if isinstance(item, dict))
    normalized = []
    for item in records:
        if not isinstance(item, dict):
            continue
        runtime = str(item.get("runtime") or "").strip()
        agent_id = str(item.get("agent_id") or item.get("agentId") or "").strip()
        if not agent_id:
            continue
        agent_key = str(item.get("agent_key") or item.get("agentKey") or "").strip()
        if not agent_key and runtime:
            agent_key = f"{runtime}:{agent_id}"
        normalized.append(
            {
                "agent_key": agent_key,
                "agent_id": agent_id,
                "runtime": runtime,
                "display_name": item.get("display_name") or item.get("displayName") or "",
                "role": item.get("role") or "",
                "status": item.get("status") or "",
                "platform": item.get("platform") or "",
                "execution_adapter": item.get("execution_adapter") or item.get("executionAdapter") or "",
                "im_ingress_owner": item.get("im_ingress_owner") or item.get("imIngressOwner") or "",
                "im_ingress_adapter": item.get("im_ingress_adapter") or item.get("imIngressAdapter") or "",
                "workflow_ingress_adapter": item.get("workflow_ingress_adapter") or item.get("workflowIngressAdapter") or "",
                "can_receive_dispatch": _snapshot_bool(item.get("can_receive_dispatch", item.get("canReceiveDispatch")), 1),
                "can_start_workflow": _snapshot_bool(item.get("can_start_workflow", item.get("canStartWorkflow")), 1),
                "gateway_proxy_allowed": _snapshot_bool(item.get("gateway_proxy_allowed", item.get("gatewayProxyAllowed")), 1),
                "endpoint_ref": item.get("endpoint_ref") or item.get("endpointRef") or "",
                "updated_at": item.get("updated_at") or item.get("updatedAt") or snapshot.get("generatedAt") or "",
            }
        )
    return normalized


def workflow_runtime_registry_snapshot_records(reason: str = "") -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "source": "snapshot",
        "snapshotFile": str(WORKFLOW_RUNTIME_AGENTS_SNAPSHOT),
        "snapshotExists": WORKFLOW_RUNTIME_AGENTS_SNAPSHOT.exists(),
        "records": [],
    }
    if reason:
        payload["fallbackReason"] = reason
    if not WORKFLOW_RUNTIME_AGENTS_SNAPSHOT.exists():
        payload["error"] = "runtime_agents snapshot not found"
        return payload
    snapshot = load_json(WORKFLOW_RUNTIME_AGENTS_SNAPSHOT, {}) or {}
    if not isinstance(snapshot, dict):
        payload["error"] = "runtime_agents snapshot is not an object"
        return payload
    payload["snapshotGeneratedAt"] = snapshot.get("generatedAt") or ""
    payload["workflowSchemaVersion"] = snapshot.get("workflowSchemaVersion")
    payload["records"] = _registry_snapshot_records(snapshot)
    if not payload["records"]:
        payload["error"] = "runtime_agents snapshot has no supported records"
    return payload


def workflow_runtime_registry_records() -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "source": "db",
        "dbFile": str(WORKFLOW_DB),
        "exists": WORKFLOW_DB.exists(),
        "snapshotFile": str(WORKFLOW_RUNTIME_AGENTS_SNAPSHOT),
        "snapshotExists": WORKFLOW_RUNTIME_AGENTS_SNAPSHOT.exists(),
        "records": [],
    }
    if not WORKFLOW_DB.exists():
        fallback = workflow_runtime_registry_snapshot_records("workflow_db_missing")
        if fallback.get("records"):
            fallback["dbFile"] = str(WORKFLOW_DB)
            fallback["exists"] = False
            return fallback
        return payload
    try:
        conn = sqlite3.connect(str(WORKFLOW_DB))
        conn.row_factory = sqlite3.Row
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='runtime_agents'"
        ).fetchone()
        if not table:
            payload["error"] = "runtime_agents table not found"
            conn.close()
            return payload
        columns = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(runtime_agents)").fetchall()
            if row["name"]
        }
        wanted = [
            "agent_key",
            "agent_id",
            "runtime",
            "display_name",
            "role",
            "status",
            "platform",
            "execution_adapter",
            "im_ingress_owner",
            "im_ingress_adapter",
            "workflow_ingress_adapter",
            "can_receive_dispatch",
            "can_start_workflow",
            "gateway_proxy_allowed",
            "endpoint_ref",
            "updated_at",
        ]
        select_cols = [name for name in wanted if name in columns]
        if not select_cols:
            payload["error"] = "runtime_agents has no supported columns"
            conn.close()
            return payload
        order_cols = [name for name in ("agent_id", "runtime") if name in columns]
        if not order_cols:
            order_cols = [select_cols[0]]
        rows = conn.execute(
            """
            SELECT {columns}
            FROM runtime_agents
            ORDER BY {order_cols}
            """.format(columns=", ".join(select_cols), order_cols=", ".join(order_cols))
        ).fetchall()
        payload["records"] = [dict(row) for row in rows]
        conn.close()
    except Exception as exc:
        payload["error"] = f"{type(exc).__name__}: {exc}"
        fallback = workflow_runtime_registry_snapshot_records("workflow_db_error")
        if fallback.get("records"):
            fallback["dbFile"] = str(WORKFLOW_DB)
            fallback["exists"] = WORKFLOW_DB.exists()
            fallback["dbError"] = payload["error"]
            return fallback
    return payload


def record_matches_expected(record: Dict[str, Any], expected: Dict[str, Any]) -> bool:
    if str(record.get("agent_id") or "") != str(expected.get("agentId") or ""):
        return False
    allowed_runtimes = expected.get("allowedRuntimes")
    if not isinstance(allowed_runtimes, list):
        runtime = expected.get("runtime")
        allowed_runtimes = [runtime] if runtime else []
    if allowed_runtimes and str(record.get("runtime") or "") not in {str(item) for item in allowed_runtimes}:
        return False
    allowed_statuses = expected.get("allowedStatuses")
    if not isinstance(allowed_statuses, list):
        status = expected.get("status")
        allowed_statuses = [status] if status else []
    if allowed_statuses and str(record.get("status") or "") not in {str(item) for item in allowed_statuses}:
        return False
    allowed_endpoint_refs = expected.get("allowedEndpointRefs")
    if not isinstance(allowed_endpoint_refs, list):
        endpoint_ref = expected.get("endpointRef")
        allowed_endpoint_refs = [endpoint_ref] if endpoint_ref else []
    if allowed_endpoint_refs and str(record.get("endpoint_ref") or "") not in {str(item) for item in allowed_endpoint_refs}:
        return False
    return True


def codex_mcp_config_check(state: Dict[str, Any]) -> Dict[str, Any]:
    codex = state.get("localCodex") if isinstance(state.get("localCodex"), dict) else {}
    required = codex.get("requiredMcpServers") if isinstance(codex.get("requiredMcpServers"), list) else []
    payload: Dict[str, Any] = {
        "configPath": str(CODEX_CONFIG_PATH),
        "exists": CODEX_CONFIG_PATH.exists(),
        "requiredMcpServers": required,
        "missing": [],
        "skipped": False,
    }
    if not required:
        return payload
    if not CODEX_CONFIG_PATH.exists():
        payload["skipped"] = True
        payload["reason"] = "codex config not present on this host"
        return payload
    try:
        text = CODEX_CONFIG_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        payload["error"] = f"{type(exc).__name__}: {exc}"
        return payload
    missing = []
    for name in required:
        plain = f"[mcp_servers.{name}]"
        quoted = f"[mcp_servers.\"{name}\"]"
        if plain not in text and quoted not in text:
            missing.append(name)
    payload["missing"] = missing
    return payload


def desired_state_drift() -> Dict[str, Any]:
    state = load_desired_state()
    drifts: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    if not state:
        drifts.append(
            {
                "key": "desired_state_missing",
                "severity": "warning",
                "component": "desired-state",
                "message": "Desired state registry is missing or invalid",
                "path": str(DESIRED_STATE_PATH),
            }
        )
        return {
            "checkedAt": ts(),
            "desiredStatePath": str(DESIRED_STATE_PATH),
            "exists": DESIRED_STATE_PATH.exists(),
            "ok": False,
            "severity": max_severity(drifts),
            "driftCount": len(drifts),
            "observationCount": 0,
            "drifts": drifts,
            "observations": observations,
        }

    required_files = desired_state_required_files(state)
    missing_files = [item for item in required_files if not (PACKAGE_ROOT / item).exists()]
    if missing_files:
        drifts.append(
            {
                "key": "package_required_files_missing",
                "severity": "warning",
                "component": "desired-state",
                "message": "Required cat-agents-stability package files are missing",
                "missingFiles": missing_files,
            }
        )

    codex_check = codex_mcp_config_check(state)
    if codex_check.get("missing"):
        drifts.append(
            {
                "key": "local_codex_mcp_missing",
                "severity": "warning",
                "component": "desired-state",
                "message": "Local Codex config is missing required MCP server registrations",
                "missingMcpServers": codex_check.get("missing"),
                "configPath": codex_check.get("configPath"),
            }
        )
    elif codex_check.get("skipped"):
        observations.append(
            {
                "key": "local_codex_config_not_on_host",
                "component": "desired-state",
                "message": "Local Codex MCP config check skipped on this host",
                "configPath": codex_check.get("configPath"),
            }
        )

    registry_state = state.get("runtimeRegistry") if isinstance(state.get("runtimeRegistry"), dict) else {}
    required_records = registry_state.get("requiredRecords") if isinstance(registry_state.get("requiredRecords"), list) else []
    forbidden_agent_ids = {
        str(item)
        for item in registry_state.get("forbiddenAgentIds", [])
        if str(item).strip()
    }
    temporary_records = registry_state.get("temporaryAllowedRecords") if isinstance(registry_state.get("temporaryAllowedRecords"), list) else []
    registry = workflow_runtime_registry_records()
    records = registry.get("records") if isinstance(registry.get("records"), list) else []
    if registry.get("error"):
        drifts.append(
            {
                "key": "runtime_registry_probe_failed",
                "severity": "warning",
                "component": "desired-state",
                "message": "Runtime registry drift probe failed",
                "error": registry.get("error"),
                "dbFile": registry.get("dbFile"),
            }
        )
    elif not registry.get("exists"):
        observations.append(
            {
                "key": "runtime_registry_db_missing_on_host",
                "component": "desired-state",
                "message": "Runtime registry database is not present on this host",
                "dbFile": registry.get("dbFile"),
            }
        )
    else:
        for expected in required_records:
            if not isinstance(expected, dict):
                continue
            matches = [record for record in records if record_matches_expected(record, expected)]
            if not matches:
                drifts.append(
                    {
                        "key": "runtime_registry_required_record_missing",
                        "severity": str(expected.get("severity") or "warning"),
                        "component": "desired-state",
                        "message": "Required runtime_agents record is missing or has unexpected status",
                        "expected": expected,
                    }
                )
                continue
            preferred_runtime = expected.get("preferredRuntime") or expected.get("runtime")
            preferred_endpoint_ref = expected.get("preferredEndpointRef") or expected.get("endpointRef")
            for match in matches:
                if preferred_runtime and str(match.get("runtime") or "") != str(preferred_runtime):
                    observations.append(
                        {
                            "key": "runtime_registry_preferred_runtime_not_reached",
                            "component": "desired-state",
                            "message": "Runtime registry record matches a migration-phase alias instead of the preferred runtime",
                            "preferredRuntime": preferred_runtime,
                            "record": match,
                        }
                    )
                if preferred_endpoint_ref and str(match.get("endpoint_ref") or "") != str(preferred_endpoint_ref):
                    observations.append(
                        {
                            "key": "runtime_registry_preferred_endpoint_not_reached",
                            "component": "desired-state",
                            "message": "Runtime registry record matches a migration-phase endpoint alias instead of the preferred endpoint",
                            "preferredEndpointRef": preferred_endpoint_ref,
                            "record": match,
                        }
                    )
        for record in records:
            if str(record.get("agent_id") or "") in forbidden_agent_ids:
                drifts.append(
                    {
                        "key": "runtime_registry_forbidden_agent_present",
                        "severity": "high",
                        "component": "desired-state",
                        "message": "Forbidden runtime agent id is present in runtime_agents",
                        "record": record,
                    }
                )
        for expected in temporary_records:
            if not isinstance(expected, dict):
                continue
            matches = [record for record in records if record_matches_expected(record, expected)]
            if matches:
                observations.append(
                    {
                        "key": "runtime_registry_temporary_record_present",
                        "component": "desired-state",
                        "message": "Temporary allowed runtime registry record is still present",
                        "expected": expected,
                        "matches": matches[:3],
                    }
                )

    target = registry_state.get("targetAfterHermersImCutover") if isinstance(registry_state.get("targetAfterHermersImCutover"), dict) else {}
    if target:
        observations.append(
            {
                "key": "future_hermers_im_cutover_target_declared",
                "component": "desired-state",
                "message": "Hermers IM cutover target is declared but not enforced in the current phase",
                "target": target,
            }
        )

    return {
        "checkedAt": ts(),
        "desiredStatePath": str(DESIRED_STATE_PATH),
        "exists": DESIRED_STATE_PATH.exists(),
        "schemaVersion": state.get("schemaVersion"),
        "version": state.get("version"),
        "enforcementPhase": state.get("enforcementPhase"),
        "ok": not drifts,
        "severity": max_severity(drifts),
        "driftCount": len(drifts),
        "observationCount": len(observations),
        "drifts": drifts,
        "observations": observations,
        "checks": {
            "packageRoot": str(PACKAGE_ROOT),
            "requiredFileCount": len(required_files),
            "codexMcp": codex_check,
            "runtimeRegistry": {
                "dbFile": registry.get("dbFile"),
                "exists": registry.get("exists"),
                "recordCount": len(records),
            },
        },
    }


def build_workflow_stability_evidence(snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    latest = snapshot if isinstance(snapshot, dict) else (load_json(LATEST_PATH, {}) or {})
    policy = latest.get("policy") if isinstance(latest.get("policy"), dict) else (load_json(POLICY_PATH, {}) or {})
    lanes = policy.get("lanes") if isinstance(policy.get("lanes"), dict) else (load_json(LANE_POLICY_PATH, {}) or {})
    desired = latest.get("desiredState") if isinstance(latest.get("desiredState"), dict) else desired_state_drift()
    findings = latest.get("findings") if isinstance(latest.get("findings"), list) else []
    actions = latest.get("actions") if isinstance(latest.get("actions"), list) else []
    resource_human_gate = load_json(RESOURCE_HUMAN_GATE_DIR / "gateway-resource-pressure-latest.json", {}) or {}
    current_keys = {str(item.get("key")) for item in findings if isinstance(item, dict)}
    resource_gate_active = bool(resource_pressure_active(current_keys))
    return {
        "schemaVersion": 1,
        "generatedAt": ts(),
        "source": "cat-agents-stabilityd",
        "workflowRoot": str(WORKFLOW_ROOT),
        "stability": {
            "checkedAt": latest.get("checkedAt"),
            "completedAt": latest.get("completedAt"),
            "severity": latest.get("severity"),
            "mode": policy.get("mode"),
            "findingCount": len(findings),
            "actionCount": len(actions),
        },
        "policy": {
            "mode": policy.get("mode"),
            "severity": policy.get("severity"),
            "reasons": policy.get("reasons") or [],
            "canRestartGateway": bool(policy.get("canRestartGateway")),
            "shouldPauseNonCriticalCron": bool(policy.get("shouldPauseNonCriticalCron")),
            "deferControlPlaneHeavyReports": bool(policy.get("deferControlPlaneHeavyReports")),
        },
        "lanes": lanes,
        "desiredState": {
            "ok": desired.get("ok"),
            "severity": desired.get("severity"),
            "driftCount": desired.get("driftCount"),
            "observationCount": desired.get("observationCount"),
            "enforcementPhase": desired.get("enforcementPhase"),
            "drifts": desired.get("drifts") or [],
            "observations": desired.get("observations") or [],
        },
        "topFindings": findings[:20],
        "recentActions": actions[:20],
        "resourceHumanGate": {
            "active": resource_gate_active,
            "status": resource_human_gate.get("status") if resource_gate_active else None,
            "generatedAt": resource_human_gate.get("generatedAt"),
            "severity": resource_human_gate.get("severity"),
            "mode": resource_human_gate.get("mode"),
            "triggerKeys": resource_human_gate.get("triggerKeys") or [],
            "jsonPath": str(RESOURCE_HUMAN_GATE_DIR / "gateway-resource-pressure-latest.json"),
            "markdownPath": str(RESOURCE_HUMAN_GATE_DIR / "gateway-resource-pressure-latest.md"),
            "incidentPath": str(RESOURCE_INCIDENT_LATEST),
        },
        "catBrainConsumption": {
            "agentId": "main",
            "heartbeatUse": "Read this evidence before 30min semantic governance checks and before deciding whether to ask cat_claw for Human Gate submission.",
            "doNotUseFor": "This evidence does not authorize Gateway restart, runtime migration, trading actions, or Human Gate completion by itself.",
        },
    }


def render_workflow_stability_evidence_md(evidence: Dict[str, Any]) -> str:
    stability = evidence.get("stability") or {}
    desired = evidence.get("desiredState") or {}
    policy = evidence.get("policy") or {}
    findings = evidence.get("topFindings") or []
    observations = desired.get("observations") or []
    resource_gate = evidence.get("resourceHumanGate") if isinstance(evidence.get("resourceHumanGate"), dict) else {}
    lines = [
        "# Cat Agents Stability Evidence",
        "",
        f"- generatedAt: {evidence.get('generatedAt')}",
        f"- checkedAt: {stability.get('checkedAt')}",
        f"- severity: {stability.get('severity')}",
        f"- mode: {stability.get('mode')}",
        f"- findingCount: {stability.get('findingCount')}",
        f"- desiredState.ok: {desired.get('ok')}",
        f"- desiredState.driftCount: {desired.get('driftCount')}",
        f"- desiredState.observationCount: {desired.get('observationCount')}",
        f"- policy.reasons: {', '.join(policy.get('reasons') or []) or 'none'}",
        "",
        "## Top Findings",
    ]
    if findings:
        for item in findings[:20]:
            lines.append(f"- [{item.get('severity')}] {item.get('component')}::{item.get('key')} - {item.get('message')}")
    else:
        lines.append("- none")
    lines.extend(["", "## Desired-State Observations"])
    if observations:
        for item in observations[:20]:
            lines.append(f"- {item.get('key')}: {item.get('message')}")
    else:
        lines.append("- none")
    lines.extend(["", "## Resource Human Gate"])
    if resource_gate.get("status"):
        lines.append(f"- status: {resource_gate.get('status')}")
        lines.append(f"- generatedAt: {resource_gate.get('generatedAt')}")
        lines.append(f"- severity: {resource_gate.get('severity')}")
        lines.append(f"- mode: {resource_gate.get('mode')}")
        lines.append(f"- triggerKeys: {', '.join(resource_gate.get('triggerKeys') or []) or 'none'}")
        lines.append(f"- markdownPath: {resource_gate.get('markdownPath')}")
    else:
        lines.append("- none")
    lines.extend([
        "",
        "## Cat-Brain Use",
        "- 猫之脑 main 应在 30min semantic governance checks 中读取本证据。",
        "- 本证据只提供治理事实，不自动授权 Gateway restart、runtime migration、交易动作或 Human Gate 完成。",
        "",
    ])
    return "\n".join(lines)


def write_workflow_stability_evidence(snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    evidence = build_workflow_stability_evidence(snapshot)
    if not WORKFLOW_ROOT.exists():
        evidence["written"] = False
        evidence["reason"] = "workflow root missing"
        return evidence
    WORKFLOW_GOVERNANCE_LOG_DIR.mkdir(parents=True, exist_ok=True)
    write_json_atomic(WORKFLOW_STABILITY_EVIDENCE_JSON, evidence)
    WORKFLOW_STABILITY_EVIDENCE_MD.write_text(render_workflow_stability_evidence_md(evidence), encoding="utf-8")
    evidence["written"] = True
    evidence["jsonPath"] = str(WORKFLOW_STABILITY_EVIDENCE_JSON)
    evidence["markdownPath"] = str(WORKFLOW_STABILITY_EVIDENCE_MD)
    return evidence


def tcp_ok(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            return True
    except OSError:
        return False


def http_ok(url: str, timeout: int = 8) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as res:
            return 200 <= int(res.status) < 400
    except Exception:
        return False


def gateway_http_health(port: int, timeout: int = 8) -> Dict[str, Any]:
    health_url = f"http://127.0.0.1:{port}/health"
    readyz_url = f"http://127.0.0.1:{port}/readyz"
    health_ok = http_ok(health_url, timeout=timeout)
    readyz_ok = http_ok(readyz_url, timeout=timeout)
    return {
        "healthUrl": health_url,
        "readyzUrl": readyz_url,
        "healthOk": health_ok,
        "readyzOk": readyz_ok,
        "ok": health_ok and readyz_ok,
    }


def systemctl_show_gateway() -> Dict[str, Any]:
    props = "ActiveState,SubState,MainPID,ExecMainStartTimestamp,ExecMainStartTimestampMonotonic,NRestarts"
    try:
        out = run_cmd(["systemctl", "show", "openclaw-gateway.service", f"--property={props}"], timeout=8)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    data: Dict[str, Any] = {"exitCode": out.returncode}
    if out.returncode != 0:
        data["stderr"] = out.stderr[-800:]
    for line in out.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"MainPID", "NRestarts"}:
            with contextlib.suppress(Exception):
                data[key] = int(value or "0")
                continue
        data[key] = value
    return data


def proc_status_bytes(pid: int, field: str) -> int:
    if pid <= 0:
        return 0
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    for line in text.splitlines():
        if not line.startswith(field + ":"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            with contextlib.suppress(Exception):
                return int(parts[1]) * 1024
    return 0


def cgroup_bytes(name: str, metric: str) -> int:
    candidates = [
        Path("/sys/fs/cgroup/system.slice") / name / metric,
        Path("/sys/fs/cgroup") / "system.slice" / name / metric,
    ]
    for path in candidates:
        try:
            value = path.read_text(encoding="utf-8").strip()
            if value == "max":
                return 0
            return int(value)
        except Exception:
            continue
    return 0


def ps_rows() -> List[Dict[str, str]]:
    try:
        out = run_cmd(["ps", "-eo", "pid=,ppid=,stat=,etime=,rss=,cmd="], timeout=8).stdout
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue
        rows.append(
            {
                "pid": parts[0],
                "ppid": parts[1],
                "stat": parts[2],
                "etime": parts[3],
                "rssKb": parts[4],
                "cmd": parts[5],
            }
        )
    return rows


def child_process_summary(root_pid: int) -> Dict[str, Any]:
    rows = ps_rows()
    by_parent: Dict[str, List[Dict[str, str]]] = {}
    for row in rows:
        by_parent.setdefault(row["ppid"], []).append(row)
    seen: set[str] = set()
    queue = [str(root_pid)] if root_pid else []
    children: List[Dict[str, str]] = []
    while queue:
        parent = queue.pop(0)
        for row in by_parent.get(parent, []):
            pid = row["pid"]
            if pid in seen:
                continue
            seen.add(pid)
            children.append(row)
            queue.append(pid)
    codex_app_servers = [r for r in children if "codex app-server" in r["cmd"]]
    openclaw_children = [r for r in children if "openclaw" in r["cmd"]]
    return {
        "count": len(children),
        "codexAppServers": len(codex_app_servers),
        "openclawChildren": len(openclaw_children),
        "sample": children[:20],
    }


def gateway_collect(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    version = collect_openclaw_version()
    service = systemctl_show_gateway()
    active = service.get("ActiveState") == "active" and service.get("SubState") == "running"
    pid = int(service.get("MainPID") or 0)
    port_ok = tcp_ok(PORT)
    http_health = gateway_http_health(PORT, timeout=8) if port_ok else {"healthOk": False, "readyzOk": False, "ok": False}
    health_ok = bool(http_health.get("ok"))
    service_age = None
    start_epoch = parse_iso_epoch(service.get("ExecMainStartTimestamp"))
    if start_epoch:
        service_age = max(0, epoch() - start_epoch)
    in_grace = service_age is not None and service_age < STARTUP_GRACE_SECONDS
    memory = cgroup_bytes("openclaw-gateway.service", "memory.current") or proc_status_bytes(pid, "VmRSS")
    swap = cgroup_bytes("openclaw-gateway.service", "memory.swap.current") or proc_status_bytes(pid, "VmSwap")
    children = child_process_summary(pid)
    deep_status = collect_gateway_deep_status()
    deep_runtime_running = deep_status.get("runtimeState") == "running"
    deep_insecure_probe_only = bool(
        deep_status.get("connectivityProbeFailed")
        and deep_status.get("insecurePlaintextWsBlocked")
        and active
        and port_ok
        and (health_ok or deep_runtime_running or deep_status.get("portInUse"))
    )
    if deep_insecure_probe_only:
        deep_status["connectivityProbeInterpretation"] = "ignored_insecure_0_0_0_0_plaintext_ws_probe"

    if not active:
        add_finding(findings, "gateway_service_down", "critical", "gateway", "openclaw-gateway.service is not active", service=service)
    if not port_ok:
        add_finding(
            findings,
            "gateway_port_down" if not in_grace else "gateway_starting",
            "critical" if not in_grace else "warning",
            "gateway",
            f"gateway port {PORT} is not listening",
            serviceAgeSeconds=service_age,
        )
    elif not health_ok:
        add_finding(
            findings,
            "gateway_health_endpoint_failed" if not in_grace else "gateway_starting",
            "critical" if not in_grace else "warning",
            "gateway",
            "gateway health endpoint failed",
            serviceAgeSeconds=service_age,
        )
    if memory >= MEMORY_CRIT_BYTES:
        add_finding(findings, "gateway_resource_saturation", "critical", "resource", "gateway memory is critically high", memoryBytes=memory)
    elif memory >= MEMORY_WARN_BYTES:
        add_finding(findings, "gateway_resource_pressure", "high", "resource", "gateway memory is high", memoryBytes=memory)
    if swap >= SWAP_CRIT_BYTES:
        add_finding(findings, "gateway_swap_saturation", "critical", "resource", "gateway swap usage is critically high", swapBytes=swap)
    elif swap >= SWAP_WARN_BYTES:
        add_finding(findings, "gateway_swap_pressure", "high", "resource", "gateway swap usage is high", swapBytes=swap)
    if children["codexAppServers"] > 4 or children["openclawChildren"] > 16:
        add_finding(findings, "gateway_child_accumulation", "high", "resource", "gateway child process accumulation detected", children=children)
    plugin_drifts = deep_status.get("pluginVersionDrift") if isinstance(deep_status.get("pluginVersionDrift"), list) else []
    if plugin_drifts:
        add_finding(
            findings,
            "openclaw_plugin_version_drift",
            "warning",
            "config",
            "OpenClaw official plugin versions differ from the Gateway version",
            openclawVersion=version.get("version"),
            pluginVersionDrift=plugin_drifts,
        )
    if deep_status.get("connectivityProbeFailed") and not deep_insecure_probe_only and not in_grace:
        add_finding(
            findings,
            "gateway_deep_connectivity_probe_failed",
            "warning",
            "gateway",
            "OpenClaw deep status connectivity probe failed outside the known insecure 0.0.0.0 plaintext probe case",
            deepStatus={k: v for k, v in deep_status.items() if k != "rawSample"},
        )

    return {
        "openclawVersion": version,
        "service": service,
        "active": active,
        "pid": pid,
        "port": PORT,
        "portOk": port_ok,
        "healthOk": health_ok,
        "httpHealth": http_health,
        "serviceAgeSeconds": service_age,
        "startupGraceActive": bool(in_grace),
        "memoryBytes": memory,
        "swapBytes": swap,
        "children": children,
        "deepStatus": deep_status,
    }


def systemctl_user_show(unit: str) -> Dict[str, Any]:
    props = "ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp,MemoryCurrent,TasksCurrent"
    try:
        out = run_user_cmd(["systemctl", "--user", "show", unit, f"--property={props}"], timeout=8)
    except Exception as exc:
        return {"unit": unit, "error": f"{type(exc).__name__}: {exc}"}
    data: Dict[str, Any] = {"unit": unit, "exitCode": out.returncode}
    if out.returncode != 0:
        data["stderr"] = out.stderr[-800:]
    for line in out.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in {"MainPID", "NRestarts", "MemoryCurrent", "TasksCurrent"}:
            with contextlib.suppress(Exception):
                data[key] = int(value or "0")
                continue
        data[key] = value
    return data


def hermers_gateway_processes(rows: List[Dict[str, str]], profile: str) -> List[Dict[str, Any]]:
    needle = f"--profile {profile} gateway run"
    results = []
    for row in rows:
        if "hermes_cli.main" not in row.get("cmd", ""):
            continue
        if needle not in row.get("cmd", ""):
            continue
        item = dict(row)
        item["ageSeconds"] = etime_seconds(row.get("etime"))
        with contextlib.suppress(Exception):
            item["rssBytes"] = int(row.get("rssKb") or "0") * 1024
        results.append(item)
    return results


def hermers_acp_workers(rows: List[Dict[str, str]], known_profiles: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    workers = []
    known_source = HERMERS_PROFILE_FALLBACKS if known_profiles is None else known_profiles
    known = {str(item) for item in known_source if str(item)}
    for row in rows:
        cmd = row.get("cmd", "")
        if " acp" not in cmd or "/hermes" not in cmd or " --accept-hooks" not in cmd:
            continue
        profile = ""
        match = re.search(r"(?:^|\s)-p\s+([A-Za-z0-9_-]+)\s+acp(?:\s|$)", cmd)
        if match:
            profile = match.group(1)
        if known and profile and profile not in known:
            continue
        item = dict(row)
        item["profile"] = profile
        item["ageSeconds"] = etime_seconds(row.get("etime"))
        item["orphan"] = str(row.get("ppid") or "") == "1"
        with contextlib.suppress(Exception):
            item["rssBytes"] = int(row.get("rssKb") or "0") * 1024
        workers.append(item)
    return workers


def proc_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def proc_cpu_ticks(pid: int) -> int:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        end = text.rfind(")")
        if end < 0:
            return -1
        fields = text[end + 2 :].split()
        # /proc/<pid>/stat fields after comm start at field 3; utime/stime are fields 14/15.
        return int(fields[11]) + int(fields[12])
    except Exception:
        return -1


def hermers_lsp_processes(rows: List[Dict[str, str]], known_profiles: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    processes: List[Dict[str, Any]] = []
    known = {str(item) for item in (known_profiles or []) if str(item)}
    if known_profiles is not None and not known:
        return processes
    pattern = re.compile(r"/\.hermes/profiles/([A-Za-z0-9_-]+)/lsp/.*/pyright-langserver(?:\s|$)")
    for row in rows:
        cmd = row.get("cmd", "")
        if "pyright-langserver" not in cmd or "--stdio" not in cmd:
            continue
        match = pattern.search(cmd)
        if not match:
            continue
        profile = match.group(1)
        if known and profile not in known:
            continue
        try:
            pid = int(row.get("pid") or 0)
        except Exception:
            pid = 0
        if pid <= 1:
            continue
        item = dict(row)
        item["profile"] = profile
        item["processType"] = "pyright-langserver"
        item["ageSeconds"] = etime_seconds(row.get("etime"))
        item["cpuTicks"] = proc_cpu_ticks(pid)
        with contextlib.suppress(Exception):
            item["rssBytes"] = int(row.get("rssKb") or "0") * 1024
        processes.append(item)
    return processes


def update_hermers_lsp_idle_state(conn: sqlite3.Connection, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    now_s = epoch()
    previous = db_get(conn, "hermers_lsp_idle_state", {}) or {}
    if not isinstance(previous, dict):
        previous = {}
    updated: Dict[str, Any] = {}
    enriched: List[Dict[str, Any]] = []
    for item in processes:
        pid = str(item.get("pid") or "")
        profile = str(item.get("profile") or "")
        key = f"{profile}:{pid}"
        cpu_ticks = int(item.get("cpuTicks") or 0)
        old = previous.get(key) if isinstance(previous.get(key), dict) else {}
        old_ticks = int(old.get("cpuTicks") or -1)
        if old and old_ticks == cpu_ticks:
            idle_since = int(old.get("idleSinceEpoch") or now_s)
        else:
            idle_since = now_s
        idle_observed = max(0, now_s - idle_since)
        state_item = {
            "profile": profile,
            "pid": pid,
            "cmd": item.get("cmd") or "",
            "cpuTicks": cpu_ticks,
            "idleSinceEpoch": idle_since,
            "lastSeenEpoch": now_s,
        }
        updated[key] = state_item
        enriched_item = dict(item)
        enriched_item["idleSinceEpoch"] = idle_since
        enriched_item["idleObservedSeconds"] = idle_observed
        enriched_item["idleThresholdSeconds"] = HERMERS_LSP_IDLE_SECONDS
        enriched_item["idleCandidate"] = (
            cpu_ticks >= 0
            and idle_observed >= HERMERS_LSP_IDLE_SECONDS
            and int(enriched_item.get("ageSeconds") or 0) >= HERMERS_LSP_IDLE_SECONDS
        )
        enriched.append(enriched_item)
    for key, old in previous.items():
        if key in updated or not isinstance(old, dict):
            continue
        last_seen = int(old.get("lastSeenEpoch") or 0)
        if last_seen and now_s - last_seen < HERMERS_LSP_IDLE_STATE_TTL_SECONDS:
            updated[key] = old
    db_set(conn, "hermers_lsp_idle_state", updated)
    return enriched


def hermers_profile_agent_ids(profile: str) -> set[str]:
    return set()


def runtime_record_can_receive(record: Dict[str, Any]) -> bool:
    value = record.get("can_receive_dispatch")
    if value is None:
        return True
    return str(value).lower() in {"1", "true", "yes", "on"}


def runtime_record_adapter_values(record: Dict[str, Any]) -> set[str]:
    return {
        str(record.get("runtime") or ""),
        str(record.get("platform") or ""),
        str(record.get("execution_adapter") or ""),
        str(record.get("workflow_ingress_adapter") or ""),
    }


def runtime_record_hermers_profile(record: Dict[str, Any]) -> str:
    endpoint_ref = str(record.get("endpoint_ref") or "")
    for prefix in ("hermers-profile:", "hermes-profile:", "profile:"):
        if endpoint_ref.startswith(prefix):
            return endpoint_ref.split(":", 1)[1].strip()
    return ""


def runtime_record_is_hermers_dispatch_profile(record: Dict[str, Any]) -> bool:
    values = runtime_record_adapter_values(record)
    endpoint_profile = runtime_record_hermers_profile(record)
    hermers_like = bool(
        {"hermers", "hermes", "hermes_acp", "hermers_acp"} & values
        or endpoint_profile
    )
    acp_like = bool(
        {"acp", "hermes_acp", "hermers_acp"} & values
        or endpoint_profile
    )
    return hermers_like and acp_like


def hermers_profiles_from_runtime_registry(findings: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    registry = workflow_runtime_registry_records()
    records = registry.get("records") if isinstance(registry.get("records"), list) else []
    profiles: Dict[str, Dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        status = str(record.get("status") or "")
        if status != "active":
            continue
        if not runtime_record_can_receive(record):
            continue
        if not runtime_record_is_hermers_dispatch_profile(record):
            continue
        profile = runtime_record_hermers_profile(record)
        if not profile:
            add_finding(
                findings,
                "hermers_profile_endpoint_unparseable",
                "warning",
                "hermers",
                "Active Hermers dispatch-capable runtime_agents row has no parseable runtime-owned profile endpoint",
                record=record,
            )
            continue
        item = profiles.setdefault(
            profile,
            {
                "profile": profile,
                "agentIds": set(),
                "registryRecords": [],
                "source": "runtime_agents",
            },
        )
        agent_id = str(record.get("agent_id") or "")
        if agent_id:
            item["agentIds"].add(agent_id)
        item["registryRecords"].append(record)

    if profiles:
        for item in profiles.values():
            item["agentIds"] = sorted(item.get("agentIds") or [])
        return profiles, {
            "source": "runtime_agents",
            "dbFile": registry.get("dbFile"),
            "recordCount": len(records),
            "profileCount": len(profiles),
        }

    reason = registry.get("error") or "no active hermers profiles found in runtime_agents"
    add_finding(
        findings,
        "hermers_profile_registry_unavailable",
        "warning",
        "hermers",
        "Hermers profile observation did not derive any dispatch-capable profile from runtime_agents",
        reason=reason,
        dbFile=registry.get("dbFile"),
    )
    return {}, {
        "source": "runtime_agents",
        "dbFile": registry.get("dbFile"),
        "reason": reason,
        "profileCount": 0,
    }


def hermers_profile_workflow_activity(profile_records: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    activity: Dict[str, Dict[str, Any]] = {
        profile: {
            "profile": profile,
            "probeOk": True,
            "agentIds": sorted(set(item.get("agentIds") or [])),
            "activeRuntimeCount": 0,
            "activeDispatchCount": 0,
            "lastActivityEpoch": None,
            "lastActivityAt": None,
            "sample": [],
        }
        for profile, item in profile_records.items()
    }
    if not WORKFLOW_DB.exists():
        for item in activity.values():
            item["probeOk"] = False
            item["error"] = "workflow db missing"
        return activity

    def matches_profile(profile: str, row: Dict[str, Any]) -> bool:
        agent_id = str(row.get("agent_id") or "")
        adapter = str(row.get("adapter") or "")
        acp_agent = str(row.get("acp_agent") or "")
        payload_json = str(row.get("payload_json") or "")
        agent_ids = set(activity.get(profile, {}).get("agentIds") or [])
        if agent_id in agent_ids:
            return True
        if acp_agent == profile or acp_agent.endswith(f" -p {profile} acp --accept-hooks"):
            return True
        return f'"profile": "{profile}"' in payload_json or f'"profile":"{profile}"' in payload_json

    def record(profile: str, row: Dict[str, Any], when_raw: Any, active: bool, kind: str) -> None:
        item = activity.setdefault(profile, {"profile": profile})
        when_epoch = parse_iso_epoch(when_raw)
        if when_epoch is not None:
            last_epoch = item.get("lastActivityEpoch")
            if last_epoch is None or int(when_epoch) > int(last_epoch):
                item["lastActivityEpoch"] = int(when_epoch)
                item["lastActivityAt"] = when_raw
        if active:
            if kind == "runtime":
                item["activeRuntimeCount"] = int(item.get("activeRuntimeCount") or 0) + 1
            else:
                item["activeDispatchCount"] = int(item.get("activeDispatchCount") or 0) + 1
        sample = item.setdefault("sample", [])
        if isinstance(sample, list) and len(sample) < 5:
            sample.append({k: row.get(k) for k in ("kind", "dispatch_id", "status", "agent_id", "adapter", "started_at", "completed_at", "updated_at", "sent_at") if k in row})

    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(str(WORKFLOW_DB))
        conn.row_factory = sqlite3.Row
        runtime_rows = conn.execute(
            """
            SELECT 'runtime' AS kind, rr.dispatch_id, rr.agent_id, rr.adapter, rr.acp_agent, rr.status,
                   rr.attempt, rr.started_at, rr.completed_at, rr.payload_json
            FROM runtime_runs rr
            WHERE rr.runtime IN ('hermes_acp', 'hermes', 'hermers')
              AND NOT (
                rr.status = 'started'
                AND rr.started_at IS NOT NULL
                AND rr.started_at != ''
                AND EXISTS (
                  SELECT 1
                  FROM runtime_runs terminal
                  WHERE terminal.dispatch_id = rr.dispatch_id
                    AND terminal.runtime_run_id != rr.runtime_run_id
                    AND terminal.runtime = rr.runtime
                    AND terminal.agent_id = rr.agent_id
                    AND terminal.status IN ('acked', 'failed', 'retry_scheduled')
                    AND terminal.completed_at IS NOT NULL
                    AND terminal.completed_at != ''
                    AND terminal.completed_at >= rr.started_at
                    AND (
                      terminal.attempt = rr.attempt
                      OR (
                        terminal.adapter = 'stale_dispatch_reconcile'
                        AND terminal.failure_type = 'runtime_stale'
                        AND terminal.started_at = rr.started_at
                      )
                    )
                )
              )
            ORDER BY COALESCE(rr.completed_at, rr.started_at) DESC
            LIMIT 500
            """
        ).fetchall()
        for sqlite_row in runtime_rows:
            row = dict(sqlite_row)
            status = str(row.get("status") or "").lower()
            active = status in {"queued", "pending", "sent", "started", "running", "in_progress"}
            when_raw = row.get("completed_at") or row.get("started_at")
            for profile in profile_records:
                if matches_profile(profile, row):
                    record(profile, row, when_raw, active, "runtime")

        dispatch_rows = conn.execute(
            """
            SELECT 'dispatch' AS kind, agent_id, runtime, status, updated_at, sent_at, payload_json
            FROM mixed_meeting_dispatches
            WHERE runtime IN ('hermes_acp', 'hermes', 'hermers')
            ORDER BY COALESCE(updated_at, sent_at) DESC
            LIMIT 500
            """
        ).fetchall()
        for sqlite_row in dispatch_rows:
            row = dict(sqlite_row)
            status = str(row.get("status") or "").lower()
            active = status in {"queued", "pending", "sent", "started", "running", "in_progress"}
            when_raw = row.get("updated_at") or row.get("sent_at")
            for profile in profile_records:
                if matches_profile(profile, row):
                    record(profile, row, when_raw, active, "dispatch")
    except Exception as exc:
        for item in activity.values():
            item["probeOk"] = False
            item["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
    return activity


def hermers_profile_is_protected(profile: str, agent_ids: Iterable[str]) -> bool:
    candidates = {profile, *[str(agent_id) for agent_id in agent_ids if str(agent_id)]}
    return bool(candidates & HERMERS_PROFILE_PROTECTED_IDS)


def hermers_profile_lifecycle_allowed(profile: str, agent_ids: Iterable[str], protected: bool) -> bool:
    if protected:
        return False
    candidates = {profile, *[str(agent_id) for agent_id in agent_ids if str(agent_id)]}
    return "*" in HERMERS_PROFILE_LIFECYCLE_ALLOWLIST or bool(candidates & HERMERS_PROFILE_LIFECYCLE_ALLOWLIST)


def hermers_profile_safe_to_hibernate(profile: str, state: Dict[str, Any], now_s: int) -> Tuple[bool, str]:
    if not isinstance(state, dict):
        return False, "missing-runtime-state"
    state_profile = str(state.get("profile") or state.get("profileId") or state.get("profile_id") or "")
    if not state_profile:
        return False, "runtime-state-profile-missing"
    if state_profile != profile:
        return False, "runtime-state-profile-mismatch"
    timestamp_candidates = [
        state.get("safeToHibernateAt"),
        state.get("safe_to_hibernate_at"),
        state.get("updated_at"),
        state.get("updatedAt"),
        (state.get("stability") or {}).get("safeToHibernateAt") if isinstance(state.get("stability"), dict) else None,
        (state.get("stability") or {}).get("safe_to_hibernate_at") if isinstance(state.get("stability"), dict) else None,
        (state.get("stability") or {}).get("updated_at") if isinstance(state.get("stability"), dict) else None,
        (state.get("stability") or {}).get("updatedAt") if isinstance(state.get("stability"), dict) else None,
        (state.get("idle") or {}).get("safeToHibernateAt") if isinstance(state.get("idle"), dict) else None,
        (state.get("idle") or {}).get("safe_to_hibernate_at") if isinstance(state.get("idle"), dict) else None,
        (state.get("idle") or {}).get("updated_at") if isinstance(state.get("idle"), dict) else None,
        (state.get("idle") or {}).get("updatedAt") if isinstance(state.get("idle"), dict) else None,
    ]
    updated_epoch = next((parse_iso_epoch(value) for value in timestamp_candidates if parse_iso_epoch(value)), None)
    max_age = HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS
    if updated_epoch is None:
        return False, "runtime-safe-to-hibernate-timestamp-missing"
    if now_s - int(updated_epoch) > max_age:
        return False, "runtime-safe-to-hibernate-stale"
    candidates = [
        state.get("safeToHibernate"),
        state.get("safe_to_hibernate"),
        (state.get("stability") or {}).get("safeToHibernate") if isinstance(state.get("stability"), dict) else None,
        (state.get("stability") or {}).get("safe_to_hibernate") if isinstance(state.get("stability"), dict) else None,
        (state.get("idle") or {}).get("safeToHibernate") if isinstance(state.get("idle"), dict) else None,
        (state.get("idle") or {}).get("safe_to_hibernate") if isinstance(state.get("idle"), dict) else None,
    ]
    if any(value is True for value in candidates):
        return True, "runtime-safe-to-hibernate"
    return False, "runtime-safe-to-hibernate-missing"


def build_hermers_profile_modes(
    conn: sqlite3.Connection,
    profiles: Dict[str, Any],
    acp_workers: List[Dict[str, Any]],
    workflow_activity: Dict[str, Dict[str, Any]],
    profile_registry: Dict[str, Dict[str, Any]],
    registry_meta: Dict[str, Any],
) -> Dict[str, Any]:
    now_s = epoch()
    profile_modes: Dict[str, Any] = {}
    for profile, profile_snapshot in profiles.items():
        service = profile_snapshot.get("service") if isinstance(profile_snapshot.get("service"), dict) else {}
        state = profile_snapshot.get("state") if isinstance(profile_snapshot.get("state"), dict) else {}
        active = bool(profile_snapshot.get("active"))
        registry_item = profile_registry.get(profile) if isinstance(profile_registry.get(profile), dict) else {}
        profile_workers = [item for item in acp_workers if item.get("profile") == profile]
        workflow = workflow_activity.get(profile) or {}
        agent_ids = sorted(set(registry_item.get("agentIds") or []) | set(workflow.get("agentIds") or []))
        protected = hermers_profile_is_protected(profile, agent_ids)
        lifecycle_allowed = hermers_profile_lifecycle_allowed(profile, agent_ids, protected)
        planned = db_get(conn, f"hermers_profile_mode:planned:{profile}", {}) or {}
        planned_mode = str(planned.get("targetMode") or planned.get("observedMode") or "") if isinstance(planned, dict) else ""
        workflow_probe_ok = bool(workflow.get("probeOk", True))
        active_work = bool(profile_workers) or int(workflow.get("activeRuntimeCount") or 0) > 0 or int(workflow.get("activeDispatchCount") or 0) > 0
        safe_to_hibernate, safe_reason = hermers_profile_safe_to_hibernate(profile, state, now_s)

        last_activity_epoch = workflow.get("lastActivityEpoch")
        if last_activity_epoch is None and active:
            last_activity_epoch = parse_iso_epoch(service.get("ActiveEnterTimestamp"))
        idle_seconds = max(0, now_s - int(last_activity_epoch)) if last_activity_epoch is not None else None

        observed_mode = "warm"
        reason = "lifecycle-not-allowlisted"
        expected_active = True
        if not HERMERS_PROFILE_MODE_ENABLED:
            reason = "profile-mode-disabled"
        elif protected:
            reason = "protected-profile"
        elif not lifecycle_allowed:
            reason = "lifecycle-not-allowlisted"
        elif not workflow_probe_ok:
            reason = "workflow-activity-unavailable"
        elif active_work:
            observed_mode = "hot"
            reason = "active-work"
        elif not active and planned_mode == "hibernate":
            observed_mode = "hibernate"
            expected_active = False
            reason = "planned-hibernate-inactive"
        elif not active:
            reason = "inactive-unplanned"
        elif idle_seconds is not None and idle_seconds >= HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS:
            observed_mode = "hibernate"
            expected_active = False
            reason = "idle-hibernate-threshold"
        elif idle_seconds is not None and idle_seconds >= HERMERS_PROFILE_COLD_IDLE_SECONDS:
            observed_mode = "cold"
            reason = "idle-cold-threshold"
        else:
            reason = "recent-or-unknown-activity"

        profile_modes[profile] = {
            "profile": profile,
            "agentIds": agent_ids,
            "registrySource": registry_item.get("source") or registry_meta.get("source"),
            "registryRecords": registry_item.get("registryRecords") or [],
            "managed": bool(lifecycle_allowed),
            "lifecycleAllowedByStabilityd": bool(lifecycle_allowed),
            "protected": bool(protected),
            "active": active,
            "activeWork": active_work,
            "workerCount": len(profile_workers),
            "observedMode": observed_mode,
            "readinessObservation": observed_mode,
            "targetMode": observed_mode,
            "expectedActive": expected_active,
            "safeToHibernate": bool(safe_to_hibernate),
            "safeToHibernateReason": safe_reason,
            "lifecycleActionAllowed": bool(safe_to_hibernate or observed_mode == "hot"),
            "reason": reason,
            "idleSeconds": idle_seconds,
            "lastActivityEpoch": last_activity_epoch,
            "lastActivityAt": workflow.get("lastActivityAt") or service.get("ActiveEnterTimestamp"),
            "unit": profile_snapshot.get("unit"),
            "workflow": workflow,
        }

    counts: Dict[str, int] = {}
    for item in profile_modes.values():
        mode = str(item.get("observedMode") or "unknown")
        counts[mode] = counts.get(mode, 0) + 1
    return {
        "schemaVersion": 1,
        "updatedAt": ts(),
        "updatedAtEpoch": now_s,
        "enabled": bool(HERMERS_PROFILE_MODE_ENABLED),
        "actuateEnabled": bool(HERMERS_PROFILE_MODE_ACTUATE_ENABLED),
        "startEnabled": bool(HERMERS_PROFILE_MODE_START_ENABLED),
        "controlMode": "stabilityd-coordinated-hermers-adapter" if HERMERS_PROFILE_MODE_ACTUATE_ENABLED else "observe-only",
        "lifecycleAllowlist": sorted(HERMERS_PROFILE_LIFECYCLE_ALLOWLIST),
        "managedIds": sorted(HERMERS_PROFILE_LIFECYCLE_ALLOWLIST),
        "protectedIds": sorted(HERMERS_PROFILE_PROTECTED_IDS),
        "registrySource": registry_meta.get("source"),
        "registry": registry_meta,
        "coldIdleSeconds": HERMERS_PROFILE_COLD_IDLE_SECONDS,
        "hibernateIdleSeconds": HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS,
        "actionCooldownSeconds": HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS,
        "counts": counts,
        "profiles": profile_modes,
    }


def hermers_workflow_summary() -> Dict[str, Any]:
    if not WORKFLOW_DB.exists():
        return {"dbFile": str(WORKFLOW_DB), "exists": False}
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=HERMERS_FAILURE_WINDOW_SECONDS)
    cutoff_iso = cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    stale_cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=HERMERS_STALE_SENT_SECONDS)
    stale_cutoff_iso = stale_cutoff.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    summary: Dict[str, Any] = {
        "dbFile": str(WORKFLOW_DB),
        "exists": True,
        "failureWindowSeconds": HERMERS_FAILURE_WINDOW_SECONDS,
        "staleSentSeconds": HERMERS_STALE_SENT_SECONDS,
    }
    try:
        conn = sqlite3.connect(str(WORKFLOW_DB))
        conn.row_factory = sqlite3.Row
        failures = conn.execute(
            """
            SELECT COALESCE(NULLIF(failure_type,''), 'unknown') AS failure_type, COUNT(*) AS count
            FROM runtime_runs
            WHERE runtime IN ('hermes_acp', 'hermes', 'hermers')
              AND status='failed'
              AND COALESCE(completed_at, started_at) >= ?
            GROUP BY COALESCE(NULLIF(failure_type,''), 'unknown')
            ORDER BY count DESC
            """,
            (cutoff_iso,),
        ).fetchall()
        failure_sample = conn.execute(
            """
            SELECT runtime_run_id, dispatch_id, workflow_id, agent_id, adapter,
                   COALESCE(NULLIF(failure_type,''), 'unknown') AS failure_type,
                   started_at, completed_at, substr(COALESCE(error, ''), 1, 240) AS error
            FROM runtime_runs
            WHERE runtime IN ('hermes_acp', 'hermes', 'hermers')
              AND status='failed'
              AND COALESCE(completed_at, started_at) >= ?
            ORDER BY COALESCE(completed_at, started_at) DESC
            LIMIT 10
            """,
            (cutoff_iso,),
        ).fetchall()
        stale_sent = conn.execute(
            """
            SELECT dispatch_id, meeting_id, agent_id, updated_at, sent_at
            FROM mixed_meeting_dispatches
            WHERE runtime IN ('hermes_acp', 'hermes', 'hermers')
              AND status='sent'
              AND updated_at < ?
            ORDER BY updated_at
            LIMIT 20
            """,
            (stale_cutoff_iso,),
        ).fetchall()
        summary["recentFailures"] = [dict(row) for row in failures]
        summary["recentFailureSample"] = [dict(row) for row in failure_sample]
        summary["recentFailureCount"] = sum(int(row["count"] or 0) for row in failures)
        summary["staleSentCount"] = len(stale_sent)
        summary["staleSentSample"] = [dict(row) for row in stale_sent[:10]]
        conn.close()
    except Exception as exc:
        summary["error"] = f"{type(exc).__name__}: {exc}"
    return summary


def hermers_collect(conn: sqlite3.Connection, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows = ps_rows()
    profiles: Dict[str, Any] = {}
    down = []
    pid_mismatches = []
    profile_registry, registry_meta = hermers_profiles_from_runtime_registry(findings)
    for profile in sorted(profile_registry):
        unit = f"hermes-gateway-{profile}.service"
        service = systemctl_user_show(unit)
        active = service.get("ActiveState") == "active" and service.get("SubState") == "running"
        pid = int(service.get("MainPID") or 0)
        state_path = HERMES_HOME / "profiles" / profile / "gateway_state.json"
        state = load_json(state_path, {}) or {}
        state_pid = int(state.get("pid") or 0) if isinstance(state, dict) else 0
        procs = hermers_gateway_processes(rows, profile)
        if not active:
            down.append({"profile": profile, "unit": unit, "service": service})
        if active and state_pid and pid and state_pid != pid:
            pid_mismatches.append({"profile": profile, "servicePid": pid, "statePid": state_pid, "statePath": str(state_path)})
        profiles[profile] = {
            "unit": unit,
            "service": service,
            "active": active,
            "pid": pid,
            "statePath": str(state_path),
            "state": state,
            "gatewayProcesses": procs,
        }

    acp_workers = hermers_acp_workers(rows, profile_registry.keys())
    if profile_registry:
        lsp_processes = update_hermers_lsp_idle_state(conn, hermers_lsp_processes(rows, profile_registry.keys()))
    else:
        db_set(conn, "hermers_lsp_idle_state", {})
        lsp_processes = []
    workflow_activity = hermers_profile_workflow_activity(profile_registry)
    profile_modes = build_hermers_profile_modes(conn, profiles, acp_workers, workflow_activity, profile_registry, registry_meta)
    orphan_workers = [
        item for item in acp_workers
        if item.get("orphan") and int(item.get("ageSeconds") or 0) >= HERMERS_ACP_ORPHAN_MIN_SECONDS
    ]
    long_workers = [
        item for item in acp_workers
        if int(item.get("ageSeconds") or 0) >= HERMERS_ACP_LONG_RUNNING_SECONDS
    ]
    idle_lsp_processes = [
        item for item in lsp_processes
        if bool(item.get("idleCandidate"))
    ]
    workflow = hermers_workflow_summary()
    recent_failure_count = int(workflow.get("recentFailureCount") or 0)
    stale_sent_count = int(workflow.get("staleSentCount") or 0)

    unexpected_down = [
        item for item in down
        if bool(((profile_modes.get("profiles") or {}).get(item.get("profile")) or {}).get("expectedActive", True))
    ]
    expected_inactive = [
        item for item in down
        if not bool(((profile_modes.get("profiles") or {}).get(item.get("profile")) or {}).get("expectedActive", True))
    ]
    if unexpected_down:
        add_finding(findings, "hermers_gateway_service_down", "critical", "hermers", "Hermers gateway user services are not active", count=len(unexpected_down), sample=unexpected_down[:10])
    if expected_inactive:
        add_finding(findings, "hermers_gateway_expected_inactive", "info", "hermers", "Hermers gateway user services are inactive by profile-mode policy", count=len(expected_inactive), sample=expected_inactive[:10])
    if pid_mismatches:
        add_finding(findings, "hermers_gateway_state_pid_mismatch", "warning", "hermers", "Hermers gateway state pid differs from systemd main pid", count=len(pid_mismatches), sample=pid_mismatches[:10])
    if orphan_workers:
        add_finding(findings, "hermers_acp_orphan_workers", "high", "hermers", "Hermers ACP workers are orphaned from their workflow parent", count=len(orphan_workers), sample=orphan_workers[:10])
    if long_workers:
        add_finding(findings, "hermers_acp_long_running_workers", "warning", "hermers", "Hermers ACP workers exceeded the long-running threshold", count=len(long_workers), sample=long_workers[:10])
    if idle_lsp_processes:
        add_finding(
            findings,
            "hermers_lsp_idle_processes",
            "warning",
            "hermers",
            "Hermers profile LSP helpers exceeded the idle threshold and are eligible for controlled reap",
            count=len(idle_lsp_processes),
            idleThresholdSeconds=HERMERS_LSP_IDLE_SECONDS,
            sample=idle_lsp_processes[:10],
        )
    if recent_failure_count >= HERMERS_FAILURE_BURST_THRESHOLD:
        add_finding(
            findings,
            "hermers_runtime_failure_burst",
            "high",
            "hermers",
            "Hermers runtime failures exceeded burst threshold",
            count=recent_failure_count,
            failures=workflow.get("recentFailures") or [],
            sample=workflow.get("recentFailureSample") or [],
        )
    elif recent_failure_count > 0:
        add_finding(
            findings,
            "hermers_runtime_recent_failures",
            "warning",
            "hermers",
            "Hermers runtime reported recent failed runs below burst threshold",
            count=recent_failure_count,
            failures=workflow.get("recentFailures") or [],
            sample=workflow.get("recentFailureSample") or [],
        )
    if stale_sent_count > 0:
        add_finding(findings, "hermers_stale_sent_dispatches", "high", "hermers", "Hermers dispatches are stuck in sent state without terminal runtime receipt", count=stale_sent_count, sample=workflow.get("staleSentSample") or [])
    if workflow.get("error"):
        add_finding(findings, "hermers_workflow_db_probe_failed", "warning", "hermers", "Hermers workflow DB probe failed", error=workflow.get("error"))
    activity_probe_errors = [
        {"profile": profile, "error": item.get("error")}
        for profile, item in workflow_activity.items()
        if isinstance(item, dict) and not bool(item.get("probeOk", True))
    ]
    if activity_probe_errors:
        add_finding(
            findings,
            "hermers_profile_activity_probe_unavailable",
            "warning",
            "hermers",
            "Hermers profile activity probe is unavailable; idle/readiness observations are incomplete",
            count=len(activity_probe_errors),
            sample=activity_probe_errors[:10],
        )

    return {
        "profiles": profiles,
        "profileCount": len(profiles),
        "profileRegistry": registry_meta,
        "activeProfileCount": sum(1 for item in profiles.values() if item.get("active")),
        "acpWorkers": acp_workers,
        "orphanAcpWorkers": orphan_workers,
        "longRunningAcpWorkers": long_workers,
        "lspProcesses": lsp_processes,
        "idleLspProcesses": idle_lsp_processes,
        "workflow": workflow,
        "profileModes": profile_modes,
        "reapOrphanAcpWorkersEnabled": bool(HERMERS_ACP_ORPHAN_REAP_ENABLED),
        "reapIdleLspEnabled": bool(HERMERS_LSP_IDLE_REAP_ENABLED),
        "lspIdleSeconds": HERMERS_LSP_IDLE_SECONDS,
        "gatewayRestartEnabled": bool(HERMERS_GATEWAY_RESTART_ENABLED),
    }


def active_openclaw_agent_ids_from_registry(registry: Dict[str, Any]) -> List[str]:
    records = registry.get("records") if isinstance(registry.get("records"), list) else []
    agent_ids = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        status = str(record.get("status") or "").strip()
        runtime = str(record.get("runtime") or "").strip()
        platform = str(record.get("platform") or "").strip()
        can_receive = _snapshot_bool(record.get("can_receive_dispatch"), 1)
        if status != "active":
            continue
        if runtime == "openclaw_route_shell":
            continue
        if runtime != "openclaw" and platform != "openclaw":
            continue
        if can_receive == 0:
            continue
        agent_id = str(record.get("agent_id") or "").strip()
        if agent_id:
            agent_ids.add(agent_id)
    return sorted(agent_ids)


def session_store_agent_id(store_path: Path) -> str:
    try:
        return store_path.relative_to(AGENTS_DIR).parts[0]
    except Exception:
        return ""


def session_key_agent_id(session_key: str) -> str:
    match = re.match(r"^agent:([^:]+):", str(session_key or ""))
    return match.group(1) if match else ""


def iter_session_store_paths(agent_ids: Optional[Iterable[str]] = None) -> List[Path]:
    paths = []
    allowed = {str(item) for item in agent_ids or [] if str(item)}
    scoped = agent_ids is not None
    if not AGENTS_DIR.exists():
        return paths
    for path in sorted(AGENTS_DIR.glob("*/sessions/sessions.json")):
        if path.is_file() and (not scoped or session_store_agent_id(path) in allowed):
            paths.append(path)
    return paths


def parse_log_ts(line: str) -> Optional[int]:
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)", line)
    if not m:
        return None
    value = m.group(1)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    if re.search(r"[+-]\d{4}$", value):
        value = value[:-5] + value[-5:-2] + ":" + value[-2:]
    try:
        return int(dt.datetime.fromisoformat(value).timestamp())
    except Exception:
        return None


def collect_gateway_log_summary() -> Dict[str, Any]:
    text = tail_text(GATEWAY_ERR_LOG, 4_000_000)
    current_epoch = epoch()
    cutoff = current_epoch - LOG_PRESSURE_WINDOW_SECONDS
    counters = {
        "wsTimeouts": 0,
        "wsClosedBeforeConnect": 0,
        "laneWaitExceeded": 0,
        "laneTaskError": 0,
        "memoryCronUnavailable": 0,
        "memoryJsonParseFailures": 0,
        "memoryScopeFailures": 0,
        "providerOverloaded": 0,
        "unknownCronJobId": 0,
    }
    for line in text.splitlines():
        line_epoch = parse_log_ts(line)
        if line_epoch is not None and line_epoch < cutoff:
            continue
        if "[ws] handshake timeout" in line or "handshake timeout" in line:
            counters["wsTimeouts"] += 1
        if "WebSocket was closed before the connection was established" in line:
            counters["wsClosedBeforeConnect"] += 1
        if "lane wait exceeded" in line or "laneWaitExceeded" in line:
            counters["laneWaitExceeded"] += 1
        if "lane task error" in line or "laneTaskError" in line:
            counters["laneTaskError"] += 1
        if "memory cron unavailable" in line or "memoryCronUnavailable" in line:
            counters["memoryCronUnavailable"] += 1
        if "memory json parse" in line or "memoryJsonParse" in line:
            counters["memoryJsonParseFailures"] += 1
        if "memory scope" in line or "memoryScope" in line:
            counters["memoryScopeFailures"] += 1
        if "provider overloaded" in line:
            counters["providerOverloaded"] += 1
        if "unknown cron job id" in line:
            counters["unknownCronJobId"] += 1
    counters["windowSeconds"] = LOG_PRESSURE_WINDOW_SECONDS
    return counters


def collect_channel_log_summary(account_ids: Iterable[str]) -> Dict[str, Any]:
    text = tail_text(GATEWAY_ERR_LOG, 4_000_000)
    current_epoch = epoch()
    cutoff = current_epoch - LOG_PRESSURE_WINDOW_SECONDS
    accounts = {str(account_id): {"channelStopExceeded": 0, "lastSeenEpoch": None} for account_id in account_ids}
    totals = {
        "telegramNetworkFailures": 0,
        "telegramWebhookCleanupFailures": 0,
        "telegramCommandFailures": 0,
        "telegramChannelStopExceeded": 0,
        "telegramChannelStopped": 0,
        "telegramRestartLimitHits": 0,
        "windowSeconds": LOG_PRESSURE_WINDOW_SECONDS,
    }
    for line in text.splitlines():
        line_epoch = parse_log_ts(line)
        if line_epoch is not None and line_epoch < cutoff:
            continue
        lower = line.lower()
        if "[telegram]" not in lower and "telegram" not in lower:
            continue
        if "network request" in lower and "failed" in lower:
            totals["telegramNetworkFailures"] += 1
        if "webhook cleanup failed" in lower or "deletewebhook failed" in lower:
            totals["telegramWebhookCleanupFailures"] += 1
        if "deletemycommands failed" in lower or "setmycommands failed" in lower:
            totals["telegramCommandFailures"] += 1
        if "channel stop exceeded" in lower:
            totals["telegramChannelStopExceeded"] += 1
        if "health-monitor: restarting (reason: stopped)" in lower:
            totals["telegramChannelStopped"] += 1
        if "health-monitor: hit" in lower and "restarts/hour limit" in lower:
            totals["telegramRestartLimitHits"] += 1
        for account_id, item in accounts.items():
            if account_id and account_id in line:
                item["lastSeenEpoch"] = max(int(item.get("lastSeenEpoch") or 0), int(line_epoch or current_epoch))
                if "channel stop exceeded" in lower:
                    item["channelStopExceeded"] = int(item.get("channelStopExceeded") or 0) + 1
                if "health-monitor: restarting (reason: stopped)" in lower:
                    item["channelStopped"] = int(item.get("channelStopped") or 0) + 1
                if "health-monitor: hit" in lower and "restarts/hour limit" in lower:
                    item["restartLimitHits"] = int(item.get("restartLimitHits") or 0) + 1
    return {"totals": totals, "accounts": accounts}


def configured_timeout_ms(job: Dict[str, Any]) -> int:
    execution = job.get("execution") if isinstance(job.get("execution"), dict) else {}
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    raw = execution.get("timeoutSeconds", payload.get("timeoutSeconds", 300))
    try:
        seconds = int(raw)
    except Exception:
        seconds = 300
    return max(seconds, 60) * 1000


def load_jobs() -> Dict[str, Any]:
    data = load_json(JOBS_PATH, {})
    if isinstance(data, dict):
        return data
    return {}


def job_items(data: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    jobs = data.get("jobs")
    if isinstance(jobs, list):
        rows = []
        for job in jobs:
            if not isinstance(job, dict):
                continue
            job_id = str(job.get("id") or job.get("jobId") or "")
            if job_id:
                rows.append((job_id, job))
        return rows
    if isinstance(jobs, dict):
        return [(str(k), v) for k, v in jobs.items() if isinstance(v, dict)]
    return [(str(k), v) for k, v in data.items() if isinstance(v, dict) and ("runningAtMs" in v or "schedule" in v)]


def active_job_ids(data: Dict[str, Any]) -> set[str]:
    return {job_id for job_id, _ in job_items(data)}


def find_stale_running_jobs(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    current = now_ms()
    stale: List[Dict[str, Any]] = []
    for job_id, job in job_items(data):
        running_at = job.get("runningAtMs") or job.get("state", {}).get("runningAtMs") if isinstance(job.get("state"), dict) else job.get("runningAtMs")
        if not isinstance(running_at, int):
            continue
        timeout_ms = configured_timeout_ms(job)
        threshold_ms = max(MIN_STALE_RUNNING_SECONDS * 1000, timeout_ms * STALE_RUNNING_TIMEOUT_MULTIPLIER)
        age_ms = current - running_at
        if age_ms >= threshold_ms:
            stale.append(
                {
                    "jobId": job_id,
                    "name": job.get("name") or job.get("title") or job_id,
                    "runningAtMs": running_at,
                    "ageMs": age_ms,
                    "thresholdMs": threshold_ms,
                }
            )
    return stale


def load_recent_job_runs(job_id: str, cutoff_ms: int) -> List[Dict[str, Any]]:
    path = RUNS_BY_JOB_DIR / f"{job_id}.jsonl"
    if not path.exists():
        return []
    runs: List[Dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(Exception):
                    record = json.loads(line)
                    if isinstance(record, dict) and int(record.get("ts") or 0) >= cutoff_ms:
                        runs.append(record)
    except Exception:
        return runs
    return runs


def latest_success_run_after(runs: List[Dict[str, Any]], lower_bound_ms: int) -> Optional[Dict[str, Any]]:
    successes = []
    for run in runs:
        if run.get("status") != "succeeded":
            continue
        run_ts = int(run.get("finishedAtMs") or run.get("ts") or 0)
        if run_ts > lower_bound_ms:
            successes.append((run_ts, run))
    if not successes:
        return None
    return max(successes, key=lambda item: item[0])[1]


def classify_cron_heartbeat(state: Dict[str, Any], timeout_ms: int) -> str:
    last_status = str(state.get("lastStatus") or "unknown")
    consecutive_errors = int(state.get("consecutiveErrors") or 0)
    duration_ms = int(state.get("lastDurationMs") or 0)
    if last_status == "error" or consecutive_errors > 0:
        return "unhealthy"
    if duration_ms >= max(timeout_ms - CRON_TIMEOUT_NEAR_MISS_MS, CRON_HEARTBEAT_WARN_MS):
        return "near-timeout"
    if duration_ms >= CRON_HEARTBEAT_WARN_MS:
        return "slow"
    return "ok"


def collect_cron_cli_status() -> Dict[str, Any]:
    """Read OpenClaw's computed cron status when the installed CLI exposes it."""
    try:
        out = run_cmd(["openclaw", "cron", "list", "--json"], timeout=15)
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    if out.returncode != 0:
        return {"available": False, "exitCode": out.returncode, "stderr": out.stderr[-1000:]}
    payload, diagnostics, error = extract_json_payload("\n".join([out.stdout or "", out.stderr or ""]))
    if payload is None:
        return {"available": False, "error": error or "json_parse_failed", "stdoutSample": out.stdout[:1000], "diagnostics": diagnostics}
    jobs = payload.get("jobs") if isinstance(payload, dict) else payload
    if not isinstance(jobs, list):
        return {"available": False, "error": "missing_jobs_array", "diagnostics": diagnostics}
    by_job: Dict[str, Dict[str, Any]] = {}
    status_counts: Dict[str, int] = {}
    samples: Dict[str, List[Dict[str, Any]]] = {}
    for job in jobs:
        if not isinstance(job, dict):
            continue
        job_id = str(job.get("id") or "")
        if not job_id:
            continue
        status = str(job.get("status") or "unknown")
        status_counts[status] = int(status_counts.get(status, 0)) + 1
        item = {
            "jobId": job_id,
            "status": status,
            "name": job.get("name") or job_id,
            "agentId": job.get("agentId"),
            "enabled": job.get("enabled") is not False,
        }
        state = job.get("state") if isinstance(job.get("state"), dict) else {}
        if state:
            item["lastRunAtMs"] = state.get("lastRunAtMs")
            item["lastStatus"] = state.get("lastStatus") or state.get("lastRunStatus")
            item["consecutiveErrors"] = state.get("consecutiveErrors")
            item["lastError"] = state.get("lastError")
            item["runningAtMs"] = state.get("runningAtMs")
            item["lastDurationMs"] = state.get("lastDurationMs")
        if item.get("runningAtMs") is None:
            item["runningAtMs"] = job.get("runningAtMs")
        execution = job.get("execution") if isinstance(job.get("execution"), dict) else {}
        payload_cfg = job.get("payload") if isinstance(job.get("payload"), dict) else {}
        timeout_seconds = execution.get("timeoutSeconds", payload_cfg.get("timeoutSeconds", job.get("timeoutSeconds")))
        if timeout_seconds is not None:
            item["timeoutSeconds"] = timeout_seconds
        by_job[job_id] = item
        if status not in {"ok", "idle", "running", "disabled"}:
            samples.setdefault(status, []).append(item)
    return {
        "available": True,
        "jobCount": len(by_job),
        "statusCounts": status_counts,
        "byJob": by_job,
        "nonOkSamples": {key: value[:10] for key, value in samples.items()},
        "diagnostics": diagnostics,
        "parseWarning": error,
    }


def jobs_from_cron_cli_status(cli_status: Dict[str, Any]) -> Dict[str, Any]:
    by_job = cli_status.get("byJob") if isinstance(cli_status.get("byJob"), dict) else {}
    jobs = []
    for job_id, item in by_job.items():
        if not isinstance(item, dict):
            continue
        state = {
            "lastRunAtMs": item.get("lastRunAtMs"),
            "lastStatus": item.get("lastStatus"),
            "consecutiveErrors": item.get("consecutiveErrors"),
            "lastError": item.get("lastError"),
            "runningAtMs": item.get("runningAtMs"),
            "lastDurationMs": item.get("lastDurationMs"),
        }
        job = {
            "id": str(item.get("jobId") or job_id),
            "name": item.get("name") or job_id,
            "agentId": item.get("agentId"),
            "enabled": item.get("enabled") is not False,
            "state": {key: value for key, value in state.items() if value is not None},
        }
        if item.get("runningAtMs") is not None:
            job["runningAtMs"] = item.get("runningAtMs")
        if item.get("timeoutSeconds") is not None:
            job["execution"] = {"timeoutSeconds": item.get("timeoutSeconds")}
        jobs.append(job)
    return {"jobs": jobs}


def find_recent_orphan_run_logs(active_ids: set[str], cutoff_ms: int) -> List[Dict[str, Any]]:
    orphans: List[Dict[str, Any]] = []
    if not RUNS_BY_JOB_DIR.exists():
        return orphans
    for path in sorted(RUNS_BY_JOB_DIR.glob("*.jsonl")):
        job_id = path.stem
        if job_id in active_ids:
            continue
        try:
            stat = path.stat()
        except FileNotFoundError:
            continue
        if int(stat.st_mtime * 1000) < cutoff_ms:
            continue
        ignored = job_id in IGNORED_ORPHAN_RUN_IDS or any(job_id.startswith(prefix) for prefix in IGNORED_ORPHAN_RUN_PREFIXES)
        recent_runs = load_recent_job_runs(job_id, cutoff_ms)
        orphans.append(
            {
                "jobId": job_id,
                "recentRunCount": len(recent_runs),
                "ageSeconds": max(0, int(time.time() - stat.st_mtime)),
                "updatedAt": dt.datetime.fromtimestamp(stat.st_mtime).astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
                "sizeBytes": stat.st_size,
                "ignored": ignored,
            }
        )
    return orphans


def build_cron_runtime_summary(data: Dict[str, Any], cli_status: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    cutoff_ms = now_ms() - CRON_HISTORY_WINDOW_DAYS * 24 * 60 * 60 * 1000
    agents: Dict[str, Dict[str, Any]] = {}
    active_ids = active_job_ids(data)
    cli_by_job = (cli_status or {}).get("byJob") if isinstance(cli_status, dict) else {}
    if not isinstance(cli_by_job, dict):
        cli_by_job = {}
    totals = {
        "recentRunCount": 0,
        "recentFailureCount": 0,
        "timeoutLikeFailureCount": 0,
        "heartbeatIssueCount": 0,
        "unhealthyHeartbeatCount": 0,
        "longRunningJobCount": 0,
        "slowJobCount": 0,
        "errorJobCount": 0,
        "cliStatusErrorCount": 0,
        "staleCliStatusErrorCount": 0,
        "cliStatusSkippedCount": 0,
    }

    def bucket_for(agent_id: str) -> Dict[str, Any]:
        return agents.setdefault(
            agent_id,
            {
                "jobCount": 0,
                "recentRunCount": 0,
                "recentFailureCount": 0,
                "timeoutLikeFailureCount": 0,
                "heartbeatCount": 0,
                "heartbeatIssues": [],
                "errorJobs": [],
                "longRunningJobs": [],
                "slowJobs": [],
                "maxDurationMs": 0,
            },
        )

    for job_id, job in job_items(data):
        job_name = str(job.get("name") or job.get("title") or job_id)
        agent_id = str(job.get("agentId") or "system")
        state = job.get("state") if isinstance(job.get("state"), dict) else {}
        cli_job = cli_by_job.get(job_id) if isinstance(cli_by_job.get(job_id), dict) else {}
        cli_status_value = str(cli_job.get("status") or "")
        timeout_ms = configured_timeout_ms(job)
        last_duration_ms = int(state.get("lastDurationMs") or 0)
        recent_runs = load_recent_job_runs(job_id, cutoff_ms)
        recent_failures = [run for run in recent_runs if run.get("status") != "succeeded"]
        timeout_like = [
            run
            for run in recent_failures
            if int(run.get("durationMs") or 0) >= max(timeout_ms - CRON_TIMEOUT_NEAR_MISS_MS, 0)
        ]

        bucket = bucket_for(agent_id)
        bucket["jobCount"] += 1
        bucket["recentRunCount"] += len(recent_runs)
        bucket["recentFailureCount"] += len(recent_failures)
        bucket["timeoutLikeFailureCount"] += len(timeout_like)
        bucket["maxDurationMs"] = max(int(bucket["maxDurationMs"]), last_duration_ms)

        totals["recentRunCount"] += len(recent_runs)
        totals["recentFailureCount"] += len(recent_failures)
        totals["timeoutLikeFailureCount"] += len(timeout_like)

        consecutive_errors = int(state.get("consecutiveErrors") or 0)
        cli_last_run_at_ms = int(cli_job.get("lastRunAtMs") or 0)
        stale_cli_error_success = latest_success_run_after(recent_runs, cli_last_run_at_ms) if cli_status_value == "error" else None
        cli_error_active = cli_status_value == "error" and stale_cli_error_success is None
        if state.get("lastStatus") == "error" or consecutive_errors > 0 or cli_error_active:
            bucket["errorJobs"].append(
                {
                    "jobId": job_id,
                    "jobName": job_name,
                    "status": cli_status_value or None,
                    "lastStatus": state.get("lastStatus"),
                    "consecutiveErrors": consecutive_errors,
                    "lastDurationMs": last_duration_ms,
                    "lastError": state.get("lastError"),
                    "staleCliStatusClearedByRun": stale_cli_error_success,
                }
            )
            totals["errorJobCount"] += 1
        if cli_error_active:
            totals["cliStatusErrorCount"] += 1
        elif cli_status_value == "error":
            totals["staleCliStatusErrorCount"] += 1
        if cli_status_value == "skipped":
            totals["cliStatusSkippedCount"] += 1

        if "heartbeat" in job_name.lower():
            risk = classify_cron_heartbeat(state, timeout_ms)
            bucket["heartbeatCount"] += 1
            if risk != "ok":
                issue = {
                    "jobId": job_id,
                    "jobName": job_name,
                    "risk": risk,
                    "lastStatus": state.get("lastStatus"),
                    "lastDurationMs": last_duration_ms,
                    "consecutiveErrors": consecutive_errors,
                    "timeoutMs": timeout_ms,
                }
                bucket["heartbeatIssues"].append(issue)
                totals["heartbeatIssueCount"] += 1
                if risk == "unhealthy":
                    totals["unhealthyHeartbeatCount"] += 1

        if last_duration_ms >= CRON_LONG_RUN_WARN_MS:
            bucket["longRunningJobs"].append(
                {
                    "jobId": job_id,
                    "jobName": job_name,
                    "lastDurationMs": last_duration_ms,
                    "timeoutMs": timeout_ms,
                    "lastStatus": state.get("lastStatus"),
                }
            )
            totals["longRunningJobCount"] += 1
        elif last_duration_ms >= CRON_HEARTBEAT_WARN_MS and "heartbeat" not in job_name.lower():
            bucket["slowJobs"].append(
                {
                    "jobId": job_id,
                    "jobName": job_name,
                    "lastDurationMs": last_duration_ms,
                    "timeoutMs": timeout_ms,
                    "lastStatus": state.get("lastStatus"),
                }
            )
            totals["slowJobCount"] += 1

    for bucket in agents.values():
        bucket["heartbeatIssues"] = sorted(bucket["heartbeatIssues"], key=lambda item: (-int(item["consecutiveErrors"]), -int(item["lastDurationMs"]), item["jobName"]))[:10]
        bucket["errorJobs"] = sorted(bucket["errorJobs"], key=lambda item: (-int(item["consecutiveErrors"]), -int(item["lastDurationMs"]), item["jobName"]))[:10]
        bucket["longRunningJobs"] = sorted(bucket["longRunningJobs"], key=lambda item: (-int(item["lastDurationMs"]), item["jobName"]))[:10]
        bucket["slowJobs"] = sorted(bucket["slowJobs"], key=lambda item: (-int(item["lastDurationMs"]), item["jobName"]))[:10]

    orphan_logs = find_recent_orphan_run_logs(active_ids, cutoff_ms)
    active_orphans = [item for item in orphan_logs if not item.get("ignored")]
    return {
        "windowDays": CRON_HISTORY_WINDOW_DAYS,
        "activeJobCount": len(active_ids),
        "agents": agents,
        "totals": totals,
        "cliStatus": cli_status or {"available": False},
        "orphanRunLogs": orphan_logs[:50],
        "activeOrphanRunLogCount": len(active_orphans),
    }


def cron_collect(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    cron_storage = collect_cron_storage_status()
    cli_status = collect_cron_cli_status()
    jobs = load_jobs()
    legacy_jobs_missing = not bool(job_items(jobs))
    if legacy_jobs_missing and bool(cli_status.get("available")):
        jobs = jobs_from_cron_cli_status(cli_status)
    items = job_items(jobs)
    stale = find_stale_running_jobs(jobs)
    leases = sorted(LEASE_DIR.glob("*.json")) if LEASE_DIR.exists() else []
    expired_leases = []
    current_ms = now_ms()
    for lease_path in leases:
        lease = load_json(lease_path, {})
        if not isinstance(lease, dict):
            continue
        expires = lease.get("expiresAtMs")
        if isinstance(expires, int) and current_ms >= expires:
            expired_leases.append({"path": str(lease_path), "jobId": lease.get("jobId"), "runId": lease.get("runId"), "expiresAtMs": expires})

    audit = load_json(CRON_AUDIT_PATH, {}) or {}
    audit_age = file_age_seconds(CRON_AUDIT_PATH)
    audit_findings = audit.get("findings") if isinstance(audit.get("findings"), list) else []
    audit_fresh = audit_age is not None and audit_age <= CRON_AUDIT_FRESH_SECONDS
    high_audit = [f for f in audit_findings if str(f.get("severity")) == "high"] if audit_fresh else []
    gateway_log = collect_gateway_log_summary()
    runtime = build_cron_runtime_summary(jobs, cli_status)
    totals = runtime.get("totals") if isinstance(runtime.get("totals"), dict) else {}
    state_migration_diags = openclaw_state_migration_diagnostics(
        list(cron_storage.get("diagnostics") or []) + list(cli_status.get("diagnostics") or [])
    )

    if stale:
        add_finding(findings, "cron_stale_running_state", "high", "cron", "stale running cron state detected", count=len(stale), sample=stale[:10])
    if expired_leases:
        add_finding(findings, "cron_expired_leases", "high", "cron", "expired cron leases detected", count=len(expired_leases), sample=expired_leases[:10])
    if audit_age is None and LEGACY_CRON_AUDIT_REQUIRED:
        add_finding(findings, "cron_audit_missing", "warning", "cron", "cron audit report is missing")
    elif audit_age is not None and not audit_fresh and LEGACY_CRON_AUDIT_REQUIRED:
        add_finding(findings, "cron_audit_stale", "warning", "cron", "cron audit report is stale", auditAgeSeconds=audit_age, freshSeconds=CRON_AUDIT_FRESH_SECONDS)
    if high_audit:
        add_finding(findings, "cron_audit_high_findings", "high", "cron", "cron audit contains high severity findings", count=len(high_audit), auditFindings=high_audit[:5])
    if int(totals.get("unhealthyHeartbeatCount") or 0) > 0:
        heartbeat_issues = []
        for agent in (runtime.get("agents") or {}).values():
            if isinstance(agent, dict):
                heartbeat_issues.extend([item for item in agent.get("heartbeatIssues") or [] if item.get("risk") == "unhealthy"])
        add_finding(
            findings,
            "cron_heartbeat_unhealthy",
            "high",
            "cron",
            "cron heartbeat jobs are unhealthy",
            count=int(totals.get("unhealthyHeartbeatCount") or 0),
            sample=heartbeat_issues[:10],
        )
    elif int(totals.get("heartbeatIssueCount") or 0) > 0:
        heartbeat_issues = []
        for agent in (runtime.get("agents") or {}).values():
            if isinstance(agent, dict):
                heartbeat_issues.extend(agent.get("heartbeatIssues") or [])
        add_finding(
            findings,
            "cron_heartbeat_slow",
            "warning",
            "cron",
            "cron heartbeat jobs are slow or near timeout",
            count=int(totals.get("heartbeatIssueCount") or 0),
            sample=heartbeat_issues[:10],
        )
    if int(totals.get("longRunningJobCount") or 0) > 0:
        long_jobs = []
        for agent in (runtime.get("agents") or {}).values():
            if isinstance(agent, dict):
                long_jobs.extend(agent.get("longRunningJobs") or [])
        add_finding(findings, "cron_long_running_jobs", "warning", "cron", "cron jobs have long recent durations", count=int(totals.get("longRunningJobCount") or 0), sample=long_jobs[:10])
    if int(totals.get("timeoutLikeFailureCount") or 0) >= 3:
        add_finding(
            findings,
            "cron_timeout_like_failures",
            "warning",
            "cron",
            "cron jobs have timeout-like failures in the history window",
            count=int(totals.get("timeoutLikeFailureCount") or 0),
            windowDays=runtime.get("windowDays"),
        )
    if int(totals.get("cliStatusErrorCount") or 0) > 0:
        add_finding(
            findings,
            "cron_cli_status_error_jobs",
            "warning",
            "cron",
            "OpenClaw cron CLI reports jobs in error status",
            count=int(totals.get("cliStatusErrorCount") or 0),
            statusCounts=(runtime.get("cliStatus") or {}).get("statusCounts"),
            sample=((runtime.get("cliStatus") or {}).get("nonOkSamples") or {}).get("error", [])[:10],
        )
    elif int(totals.get("staleCliStatusErrorCount") or 0) > 0:
        add_finding(
            findings,
            "cron_cli_status_stale_error_observations",
            "info",
            "cron",
            "OpenClaw cron CLI error statuses appear stale after newer successful run records",
            count=int(totals.get("staleCliStatusErrorCount") or 0),
            statusCounts=(runtime.get("cliStatus") or {}).get("statusCounts"),
        )
    if int(totals.get("cliStatusSkippedCount") or 0) >= 3:
        add_finding(
            findings,
            "cron_cli_status_skipped_jobs",
            "warning",
            "cron",
            "OpenClaw cron CLI reports repeated skipped jobs",
            count=int(totals.get("cliStatusSkippedCount") or 0),
            statusCounts=(runtime.get("cliStatus") or {}).get("statusCounts"),
            sample=((runtime.get("cliStatus") or {}).get("nonOkSamples") or {}).get("skipped", [])[:10],
        )
    if int(runtime.get("activeOrphanRunLogCount") or 0) > 0:
        add_finding(
            findings,
            "cron_orphan_run_logs",
            "warning",
            "cron",
            "orphan by-job run logs exist for inactive job ids",
            count=int(runtime.get("activeOrphanRunLogCount") or 0),
            sample=[item for item in runtime.get("orphanRunLogs") or [] if not item.get("ignored")][:10],
        )
    if gateway_log["laneWaitExceeded"] >= 5:
        add_finding(findings, "gateway_congestion_logs", "high", "gateway", "gateway congestion markers found in logs", gatewayLog=gateway_log)
    elif gateway_log["laneTaskError"] >= 5 or gateway_log["unknownCronJobId"] >= 1:
        add_finding(
            findings,
            "gateway_task_reconcile_observations",
            "warning",
            "gateway",
            "gateway task reconciliation or lane task error markers found in logs",
            gatewayLog=gateway_log,
        )
    if gateway_log["wsClosedBeforeConnect"] >= 20 or gateway_log["wsTimeouts"] >= 3:
        add_finding(findings, "gateway_ws_instability", "high", "gateway", "gateway websocket instability markers found in logs", gatewayLog=gateway_log)
    if gateway_log["memoryCronUnavailable"] >= 10:
        add_finding(findings, "memory_core_unavailable", "high", "runtime", "memory core unavailable markers found in logs", gatewayLog=gateway_log)
    if state_migration_diags:
        add_finding(
            findings,
            "openclaw_state_migration_observations",
            "info",
            "config",
            "OpenClaw CLI emitted legacy state migration diagnostics",
            diagnostics=state_migration_diags[:20],
        )

    return {
        "jobsPath": str(JOBS_PATH),
        "legacyJobsPathExists": JOBS_PATH.exists(),
        "legacyJobsMissingFallback": bool(legacy_jobs_missing and cli_status.get("available")),
        "storageStatus": cron_storage,
        "jobCount": len(items),
        "staleRunning": stale,
        "leaseCount": len(leases),
        "expiredLeases": expired_leases,
        "auditAgeSeconds": audit_age,
        "auditFresh": bool(audit_fresh),
        "auditFreshSeconds": CRON_AUDIT_FRESH_SECONDS,
        "auditFindingCount": len(audit_findings),
        "highAuditFindings": high_audit[:20],
        "runtime": runtime,
        "gatewayLog": gateway_log,
    }


def discover_telegram_accounts() -> Dict[str, Dict[str, Any]]:
    accounts: Dict[str, Dict[str, Any]] = {}
    config = load_json(OPENCLAW / "openclaw.json", {}) or {}

    def add_account(account_id: str, token: Optional[str] = None) -> None:
        if not account_id:
            return
        item = accounts.setdefault(account_id, {})
        if token:
            item["token"] = token

    channels = config.get("channels") if isinstance(config, dict) else {}
    telegram_cfg = channels.get("telegram") if isinstance(channels, dict) else {}
    telegram_accounts = telegram_cfg.get("accounts") if isinstance(telegram_cfg, dict) else {}
    if isinstance(telegram_accounts, dict):
        for account_id, account_cfg in telegram_accounts.items():
            token = None
            if isinstance(account_cfg, dict):
                raw = account_cfg.get("botToken") or account_cfg.get("token")
                if isinstance(raw, str):
                    token = raw
            add_account(str(account_id), token)

    bindings = config.get("bindings") if isinstance(config, dict) else []
    if isinstance(bindings, list):
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            match = binding.get("match") if isinstance(binding.get("match"), dict) else {}
            if match.get("channel") == "telegram":
                add_account(str(match.get("accountId") or telegram_cfg.get("defaultAccount") or "default"))

    def scan(obj: Any, prefix: str = "default") -> None:
        if isinstance(obj, dict):
            if "telegram" in obj and isinstance(obj["telegram"], dict):
                tg = obj["telegram"]
                token = tg.get("botToken") or tg.get("token")
                account_raw = tg.get("accountId") or obj.get("accountId") or obj.get("id")
                if isinstance(token, str) or account_raw:
                    account_id = str(account_raw or prefix)
                    add_account(account_id, token if isinstance(token, str) else None)
            for key, value in obj.items():
                if key.lower() in {"token", "bottoken", "secret"}:
                    continue
                scan(value, str(key))
        elif isinstance(obj, list):
            for idx, value in enumerate(obj):
                scan(value, f"{prefix}-{idx}")

    scan(config)

    if TELEGRAM_DIR.exists():
        for path in TELEGRAM_DIR.glob("**/*"):
            name = path.name
            if name.endswith(".offset") or name.endswith("offset.json") or name == "offset":
                account_id = path.parent.name if path.parent != TELEGRAM_DIR else path.stem.replace(".offset", "")
                add_account(account_id)

    env_accounts = os.environ.get("OPENCLAW_STABILITY_TELEGRAM_ACCOUNTS", "")
    for raw in env_accounts.split(","):
        raw = raw.strip()
        if raw:
            add_account(raw)
    return accounts


def read_offset(account_id: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    candidates = [
        TELEGRAM_DIR / f"update-offset-{account_id}.json",
        TELEGRAM_DIR / account_id / "offset.json",
        TELEGRAM_DIR / account_id / "offset",
        TELEGRAM_DIR / f"{account_id}.offset",
        TELEGRAM_DIR / f"{account_id}.json",
    ]
    for path in candidates:
        if not path.exists():
            continue
        value: Optional[int] = None
        data = load_json(path, None)
        if isinstance(data, dict):
            for key in ("lastUpdateId", "offset", "update_id", "last_update_id"):
                if isinstance(data.get(key), int):
                    value = int(data[key])
                    break
            if value is None:
                nested = data.get("state") if isinstance(data.get("state"), dict) else {}
                for key in ("lastUpdateId", "offset", "update_id", "last_update_id"):
                    if isinstance(nested.get(key), int):
                        value = int(nested[key])
                        break
        elif isinstance(data, int):
            value = data
        if value is None:
            try:
                text = path.read_text(encoding="utf-8").strip()
                value = int(text)
            except Exception:
                value = None
        return value, file_age_seconds(path), str(path)
    return None, None, None


def telegram_api(token: str, method: str, query: str = "") -> Dict[str, Any]:
    if not token:
        return {"ok": False, "description": "missing token"}
    url = f"https://api.telegram.org/bot{token}/{method}{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "cat-agents-stabilityd/1"})
    proxy_url = os.environ.get("OPENCLAW_STABILITY_HEALTH_PROXY", "http://127.0.0.1:7890")
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=18) as res:
            return json.loads(res.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8", errors="replace"))
        except Exception:
            return {"ok": False, "description": str(exc)}
    except Exception as exc:
        return {"ok": False, "description": f"{type(exc).__name__}: {exc}"}


def channel_collect(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    accounts = discover_telegram_accounts()
    result: Dict[str, Any] = {}
    warn_seconds = int(os.environ.get("OPENCLAW_STABILITY_CHANNEL_WARN_SECONDS", "300"))
    crit_seconds = int(os.environ.get("OPENCLAW_STABILITY_CHANNEL_CRIT_SECONDS", "600"))
    probe_api = os.environ.get("OPENCLAW_STABILITY_TELEGRAM_API_PROBE", "0") == "1"
    stale_offset_legacy_finding = os.environ.get("OPENCLAW_STABILITY_STALE_TELEGRAM_OFFSET_FINDING", "0") == "1"
    for account_id, meta in accounts.items():
        token = meta.get("token")
        last_update_id, offset_age, offset_path = read_offset(account_id)
        pending_count: Optional[int] = None
        pending_oldest_age: Optional[int] = None
        error = None
        if token and probe_api:
            # Never call getUpdates during normal stability checks. Gateway owns
            # Telegram long polling; a second getUpdates caller causes 409
            # conflicts and can make live sessions look unresponsive.
            getme = telegram_api(token, "getMe")
            if not getme.get("ok"):
                error = getme.get("description") or "getMe failed"
        if error:
            add_finding(findings, f"telegram_{account_id}_api_error", "high", "channel", f"telegram account {account_id} API probe failed", error=error)
        if offset_age is not None:
            if pending_count and pending_count > 0 and offset_age >= crit_seconds:
                add_finding(
                    findings,
                    f"telegram_{account_id}_consumer_lag",
                    "critical",
                    "channel",
                    f"telegram account {account_id} has pending updates and stale offset",
                    offsetAgeSeconds=offset_age,
                    pendingCount=pending_count,
                    pendingOldestAgeSeconds=pending_oldest_age,
                )
            elif stale_offset_legacy_finding and offset_age >= crit_seconds * 6:
                add_finding(
                    findings,
                    f"telegram_{account_id}_offset_stale",
                    "warning",
                    "channel",
                    f"telegram account {account_id} offset file is stale",
                    offsetAgeSeconds=offset_age,
                    pendingCount=pending_count,
                )
            elif offset_age >= warn_seconds and pending_count and pending_count > 0:
                add_finding(
                    findings,
                    f"telegram_{account_id}_consumer_lag_warn",
                    "high",
                    "channel",
                    f"telegram account {account_id} pending updates are accumulating",
                    offsetAgeSeconds=offset_age,
                    pendingCount=pending_count,
                )
        result[account_id] = {
            "lastUpdateId": last_update_id,
            "offsetAgeSeconds": offset_age,
            "offsetPath": offset_path,
            "pendingCount": pending_count,
            "pendingOldestAgeSeconds": pending_oldest_age,
            "error": error,
            "hasToken": bool(token),
            "apiProbeEnabled": bool(probe_api),
        }
    log_summary = collect_channel_log_summary(accounts.keys())
    totals = (log_summary.get("totals") or {}) if isinstance(log_summary, dict) else {}
    if int(totals.get("telegramNetworkFailures") or 0) >= 10:
        add_finding(
            findings,
            "telegram_provider_network_errors",
            "high",
            "channel",
            "telegram provider network failures are elevated in gateway logs",
            channelLog=log_summary,
        )
    elif int(totals.get("telegramRestartLimitHits") or 0) > 0:
        add_finding(
            findings,
            "telegram_channel_restart_limited",
            "high",
            "channel",
            "telegram channel providers hit health-monitor restart limits",
            channelLog=log_summary,
        )
    elif int(totals.get("telegramChannelStopped") or 0) >= 6:
        add_finding(
            findings,
            "telegram_channel_restart_churn",
            "high",
            "channel",
            "telegram channel providers are repeatedly stopping and restarting",
            channelLog=log_summary,
        )
    elif int(totals.get("telegramChannelStopExceeded") or 0) > 0:
        add_finding(
            findings,
            "telegram_channel_stop_slow",
            "warning",
            "channel",
            "telegram channel shutdown exceeded expected time in gateway logs",
            channelLog=log_summary,
        )
    result["_logSummary"] = log_summary
    return result


def parse_session_problems_from_logs() -> Dict[str, Dict[str, Any]]:
    text = tail_text(GATEWAY_ERR_LOG, 4_000_000)
    fail_cutoff = epoch() - SESSION_FAIL_WINDOW_SECONDS
    overflow_cutoff = epoch() - SESSION_OVERFLOW_WINDOW_SECONDS
    problems: Dict[str, Dict[str, Any]] = {}
    stuck_pat = re.compile(r"stuck session: sessionId=([^ ]+) sessionKey=([^ ]+) state=([^ ]+) age=(\d+)s")
    key_pat = re.compile(r"(agent:[^\s,'\"\\]+)")
    for line in text.splitlines():
        line_epoch = parse_log_ts(line)
        if line_epoch is None:
            continue
        lower = line.lower()
        m = stuck_pat.search(line)
        if m:
            if line_epoch < fail_cutoff:
                continue
            session_key = m.group(2)
            bucket = problems.setdefault(session_key, {"failures": [], "overflowCount": 0, "stuckCount": 0, "sample": []})
            bucket["stuckCount"] += 1
            bucket["failures"].append({"kind": "stuck", "line": line[-500:]})
            bucket["sample"].append(line[-500:])
            continue
        if not any(marker in lower for marker in FAIL_MARKERS + OVERFLOW_MARKERS):
            continue
        keys = key_pat.findall(line)
        for session_key in keys:
            bucket = problems.setdefault(session_key, {"failures": [], "overflowCount": 0, "stuckCount": 0, "sample": []})
            if any(marker in lower for marker in OVERFLOW_MARKERS):
                if line_epoch >= overflow_cutoff:
                    bucket["overflowCount"] += 1
            if any(marker in lower for marker in FAIL_MARKERS):
                if line_epoch >= fail_cutoff:
                    bucket["failures"].append({"kind": "failure", "line": line[-500:]})
            bucket["sample"].append(line[-500:])
            bucket["sample"] = bucket["sample"][-5:]
    return problems


def analyze_session_activity(entry: Dict[str, Any]) -> Dict[str, Any]:
    session_id = entry.get("sessionId")
    store_hint = entry.get("sessionFile") or entry.get("path") or entry.get("transcriptPath")
    candidates: List[Path] = []
    if isinstance(store_hint, str):
        candidates.append(Path(store_hint))
    if isinstance(session_id, str):
        for store in iter_session_store_paths():
            candidates.extend(store.parent.glob(f"{session_id}.jsonl"))
            candidates.extend(store.parent.glob(f"{session_id}.trajectory.jsonl"))
    current_ms = now_ms()
    active_count = 0
    heavy_count = 0
    for path in candidates[:8]:
        if not path.exists() or not path.is_file():
            continue
        text = tail_text(path, 500_000)
        for line in text.splitlines()[-300:]:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            event_ms = None
            for key in ("timestamp", "ts", "createdAt", "updatedAt"):
                if key in obj:
                    parsed = parse_iso_epoch(obj[key])
                    if parsed is not None:
                        event_ms = parsed * 1000
                        break
            if event_ms is None:
                event_ms = int(path.stat().st_mtime * 1000)
            age_ms = current_ms - event_ms
            if age_ms <= ACTIVE_PROGRESS_WINDOW_SECONDS * 1000:
                event_type = str(obj.get("type") or obj.get("event") or "")
                role = str(obj.get("role") or "")
                if event_type in EVENT_TYPES_ACTIVE or role in MESSAGE_ROLES_ACTIVE:
                    active_count += 1
            if age_ms <= HEAVY_TASK_WINDOW_SECONDS * 1000:
                payload_text = json.dumps(obj, ensure_ascii=False)[:1500].lower()
                msg = obj.get("message") if isinstance(obj.get("message"), dict) else {}
                tool_name = str(msg.get("toolName") or obj.get("toolName") or "")
                if any(name in payload_text for name in HEAVY_TOOL_NAMES) or tool_name in HEAVY_TOOL_NAMES or any(token in payload_text for token in HEAVY_TASK_TOKENS):
                    heavy_count += 1
    return {
        "active": active_count >= ACTIVE_PROGRESS_EVENT_THRESHOLD,
        "heavy": heavy_count >= HEAVY_TASK_EVENT_THRESHOLD,
        "activeCount": active_count,
        "heavyCount": heavy_count,
        "reason": "recent_progress" if active_count >= ACTIVE_PROGRESS_EVENT_THRESHOLD else "insufficient_recent_progress",
    }


def find_session_entry(session_key: str, agent_ids: Optional[Iterable[str]] = None) -> Tuple[Optional[Path], Optional[Dict[str, Any]]]:
    for store_path in iter_session_store_paths(agent_ids):
        store = load_json(store_path, {})
        if not isinstance(store, dict) or session_key not in store:
            continue
        entry = store.get(session_key)
        if isinstance(entry, dict):
            return store_path, entry
    return None, None


def session_collect(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    registry = workflow_runtime_registry_records()
    registry_records = registry.get("records") if isinstance(registry.get("records"), list) else []
    scope_available = bool(registry_records) and not registry.get("error")
    active_openclaw_agent_ids = active_openclaw_agent_ids_from_registry(registry) if scope_available else []
    stores = iter_session_store_paths(active_openclaw_agent_ids if scope_available else [])
    total_entries = 0
    stale_entries = []
    for store_path in stores:
        data = load_json(store_path, {})
        if not isinstance(data, dict):
            continue
        total_entries += len(data)
        for session_key, entry in data.items():
            if not isinstance(entry, dict):
                continue
            status = str(entry.get("status") or entry.get("state") or "")
            updated = parse_iso_epoch(entry.get("updatedAt") or entry.get("endedAt") or entry.get("createdAt"))
            if updated is None:
                for key in ("updatedAtMs", "endedAtMs", "createdAtMs", "runningAtMs", "startedAtMs"):
                    raw = entry.get(key)
                    if isinstance(raw, int):
                        updated = int(raw / 1000) if raw > 10_000_000_000 else raw
                        break
            age = epoch() - updated if updated else None
            if status in {"timeout", "error", "failed", "aborted"} and age is not None and age >= 3600:
                stale_entries.append({"storePath": str(store_path), "sessionKey": session_key, "status": status, "ageSeconds": age, "sessionId": entry.get("sessionId")})
    problems = parse_session_problems_from_logs()
    reset_candidates = []
    stale_log_candidates = []
    protected_candidates = []
    active_openclaw_agent_set = set(active_openclaw_agent_ids)
    for key, meta in problems.items():
        if scope_available:
            key_agent_id = session_key_agent_id(key)
            if key_agent_id and key_agent_id not in active_openclaw_agent_set:
                continue
        failure_count = len(meta.get("failures") or [])
        overflow_count = int(meta.get("overflowCount") or 0)
        stuck_count = int(meta.get("stuckCount") or 0)
        if failure_count >= SESSION_FAIL_THRESHOLD or overflow_count >= SESSION_OVERFLOW_THRESHOLD or stuck_count >= SESSION_FAIL_THRESHOLD:
            item = {
                "sessionKey": key,
                "failureCount": failure_count,
                "overflowCount": overflow_count,
                "stuckCount": stuck_count,
                "sample": (meta.get("sample") or [])[-3:],
            }
            store_path, entry = find_session_entry(key, active_openclaw_agent_ids if scope_available else [])
            if not entry:
                stale_log_candidates.append(item)
                continue
            activity = analyze_session_activity(entry)
            item["storePath"] = str(store_path)
            item["sessionId"] = entry.get("sessionId")
            item["activity"] = activity
            if activity.get("active") or activity.get("heavy"):
                protected_candidates.append(item)
                continue
            reset_candidates.append(item)
    main_candidates = [r for r in reset_candidates if r["sessionKey"].startswith("agent:main:") or ":main:" in r["sessionKey"]]
    if not scope_available:
        add_finding(
            findings,
            "session_registry_scope_unavailable",
            "warning",
            "session",
            "workflow runtime_agents registry unavailable; session scanner did not fall back to OpenClaw agent directories",
            registry=registry,
        )
    if stale_entries:
        add_finding(findings, "session_stale_entries", "info", "session", "stale failed session entries detected", count=len(stale_entries), sample=stale_entries[:10])
    if stale_log_candidates:
        add_finding(
            findings,
            "session_problem_stale_log_observations",
            "warning",
            "session",
            "session problem log entries no longer map to live session store entries",
            count=len(stale_log_candidates),
            sample=stale_log_candidates[:10],
        )
    if protected_candidates:
        add_finding(
            findings,
            "session_problem_protected_active",
            "warning",
            "session",
            "session problem log entries map to active or heavy sessions and are protected from reset",
            count=len(protected_candidates),
            sample=protected_candidates[:10],
        )
    if reset_candidates:
        sev = "high" if len(reset_candidates) < 8 and len(main_candidates) < 2 else "critical"
        add_finding(
            findings,
            "session_problem_backlog",
            sev,
            "session",
            "session problem backlog detected",
            count=len(reset_candidates),
            mainCount=len(main_candidates),
            sample=reset_candidates[:10],
        )
    return {
        "storeCount": len(stores),
        "entryCount": total_entries,
        "scope": {
            "source": registry.get("source") or "",
            "dbFile": registry.get("dbFile") or "",
            "snapshotFile": registry.get("snapshotFile") or "",
            "snapshotGeneratedAt": registry.get("snapshotGeneratedAt") or "",
            "registryRecordCount": len(registry_records),
            "activeOpenClawAgentIds": active_openclaw_agent_ids,
            "scopedByRuntimeAgents": scope_available,
        },
        "staleEntries": stale_entries[:50],
        "problemCount": len(problems),
        "resetCandidates": reset_candidates[:50],
        "staleLogCandidates": stale_log_candidates[:50],
        "protectedCandidates": protected_candidates[:50],
        "mainResetCandidateCount": len(main_candidates),
    }


def backup_disk_summary() -> Dict[str, Any]:
    backup_dir = OPENCLAW / "backups"
    backups = []
    if backup_dir.exists():
        for path in sorted(backup_dir.glob("openclaw-backup-*.tar.gz")):
            with contextlib.suppress(Exception):
                stat = path.stat()
                backups.append(
                    {
                        "path": str(path),
                        "name": path.name,
                        "sizeBytes": stat.st_size,
                        "mtimeEpoch": int(stat.st_mtime),
                    }
                )
    backups.sort(key=lambda item: int(item["mtimeEpoch"]), reverse=True)
    latest_size = int(backups[0]["sizeBytes"]) if backups else 0
    total_size = sum(int(item["sizeBytes"]) for item in backups)
    return {
        "backupDir": str(backup_dir),
        "keepCount": BACKUP_KEEP_COUNT,
        "backupCount": len(backups),
        "totalBackupBytes": total_size,
        "latestBackupBytes": latest_size,
        "latestBackups": backups[:BACKUP_KEEP_COUNT],
    }


def resource_collect(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    statvfs = os.statvfs(str(OPENCLAW))
    free = statvfs.f_bavail * statvfs.f_frsize
    total = statvfs.f_blocks * statvfs.f_frsize
    used_ratio = 1 - (free / total) if total else 0
    if used_ratio >= 0.92:
        add_finding(findings, "disk_pressure", "critical", "resource", "disk usage is critically high", usedRatio=used_ratio, freeBytes=free)
    elif used_ratio >= 0.85:
        add_finding(findings, "disk_pressure", "high", "resource", "disk usage is high", usedRatio=used_ratio, freeBytes=free)
    logs_size = 0
    for path in LOG_DIR.glob("*.log"):
        with contextlib.suppress(Exception):
            logs_size += path.stat().st_size
    backups = backup_disk_summary()
    latest_backup_size = int(backups.get("latestBackupBytes") or 0)
    if latest_backup_size > 0:
        required = int(latest_backup_size * BACKUP_HEADROOM_WARN_RATIO)
        if free < required:
            add_finding(
                findings,
                "backup_disk_headroom_low",
                "warning",
                "resource",
                "free disk headroom is low for the next OpenClaw backup",
                freeBytes=free,
                latestBackupBytes=latest_backup_size,
                recommendedFreeBytes=required,
                backupKeepCount=BACKUP_KEEP_COUNT,
            )
    meminfo = meminfo_bytes()
    mem_total = int(meminfo.get("MemTotal") or 0)
    mem_available = int(meminfo.get("MemAvailable") or 0)
    swap_total = int(meminfo.get("SwapTotal") or 0)
    swap_free = int(meminfo.get("SwapFree") or 0)
    swap_used = max(0, swap_total - swap_free)
    swap_used_ratio = (swap_used / swap_total) if swap_total else 0
    commit_limit = int(meminfo.get("CommitLimit") or 0)
    committed_as = int(meminfo.get("Committed_AS") or 0)
    commit_ratio = (committed_as / commit_limit) if commit_limit else 0
    if mem_available and mem_available <= SYSTEM_MEMORY_AVAILABLE_CRIT_BYTES:
        add_finding(
            findings,
            "system_memory_saturation",
            "critical",
            "resource",
            "system available memory is critically low",
            memAvailableBytes=mem_available,
            memTotalBytes=mem_total,
        )
    elif mem_available and mem_available <= SYSTEM_MEMORY_AVAILABLE_WARN_BYTES:
        add_finding(
            findings,
            "system_memory_pressure",
            "high",
            "resource",
            "system available memory is low",
            memAvailableBytes=mem_available,
            memTotalBytes=mem_total,
        )
    if swap_total and (swap_used >= SWAP_CRIT_BYTES or swap_used_ratio >= SYSTEM_SWAP_CRIT_RATIO):
        add_finding(
            findings,
            "system_swap_saturation",
            "critical",
            "resource",
            "system swap usage is critically high",
            swapUsedBytes=swap_used,
            swapTotalBytes=swap_total,
            swapUsedRatio=swap_used_ratio,
        )
    elif swap_total and (swap_used >= SWAP_WARN_BYTES or swap_used_ratio >= SYSTEM_SWAP_WARN_RATIO):
        add_finding(
            findings,
            "system_swap_pressure",
            "high",
            "resource",
            "system swap usage is high",
            swapUsedBytes=swap_used,
            swapTotalBytes=swap_total,
            swapUsedRatio=swap_used_ratio,
        )
    if commit_limit and commit_ratio >= SYSTEM_COMMIT_CRIT_RATIO:
        add_finding(
            findings,
            "system_commit_saturation",
            "critical",
            "resource",
            "system committed memory exceeds safe commit headroom",
            committedBytes=committed_as,
            commitLimitBytes=commit_limit,
            commitRatio=commit_ratio,
        )
    elif commit_limit and commit_ratio >= SYSTEM_COMMIT_WARN_RATIO:
        add_finding(
            findings,
            "system_commit_pressure",
            "high",
            "resource",
            "system committed memory is near commit limit",
            committedBytes=committed_as,
            commitLimitBytes=commit_limit,
            commitRatio=commit_ratio,
        )
    return {
        "diskFreeBytes": free,
        "diskTotalBytes": total,
        "diskUsedRatio": used_ratio,
        "topLevelLogBytes": logs_size,
        "backups": backups,
        "memory": {
            "memTotalBytes": mem_total,
            "memAvailableBytes": mem_available,
            "swapTotalBytes": swap_total,
            "swapUsedBytes": swap_used,
            "swapUsedRatio": swap_used_ratio,
            "committedBytes": committed_as,
            "commitLimitBytes": commit_limit,
            "commitRatio": commit_ratio,
        },
    }


def config_collect(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    plugins_status = collect_plugins_status()
    checks = {
        "openclawJsonExists": (OPENCLAW / "openclaw.json").exists(),
        "gatewayServiceExists": Path("/etc/systemd/system/openclaw-gateway.service").exists(),
        "stabilityServiceExists": Path("/etc/systemd/system/cat-agents-stabilityd.service").exists(),
        "plugins": plugins_status,
    }
    if not checks["openclawJsonExists"]:
        add_finding(findings, "openclaw_config_missing", "critical", "config", "openclaw.json is missing")
    if plugins_status.get("stateMigrationDiagnostics"):
        add_finding(
            findings,
            "openclaw_plugin_state_migration_observations",
            "info",
            "config",
            "OpenClaw plugin CLI emitted legacy state migration diagnostics",
            diagnostics=(plugins_status.get("stateMigrationDiagnostics") or [])[:20],
        )
    return checks


def update_streaks(conn: sqlite3.Connection, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    prev = db_get(conn, "streaks", {}) or {}
    current_keys = {f["key"]: f for f in findings}
    updated: Dict[str, Any] = {}
    now_s = epoch()
    for key, finding in current_keys.items():
        old = prev.get(key) if isinstance(prev.get(key), dict) else {}
        updated[key] = {
            "count": int(old.get("count") or 0) + 1,
            "firstSeen": int(old.get("firstSeen") or now_s),
            "lastSeen": now_s,
            "severity": finding.get("severity"),
            "component": finding.get("component"),
        }
    db_set(conn, "streaks", updated)
    return updated


def update_runtime_trends(conn: sqlite3.Connection, snapshot: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    now_s = int(snapshot.get("checkedAtEpoch") or epoch())
    gateway = snapshot.get("gateway") if isinstance(snapshot.get("gateway"), dict) else {}
    hermers = snapshot.get("hermers") if isinstance(snapshot.get("hermers"), dict) else {}
    resource = snapshot.get("resource") if isinstance(snapshot.get("resource"), dict) else {}
    system_memory = resource.get("memory") if isinstance(resource.get("memory"), dict) else {}
    children = gateway.get("children") if isinstance(gateway.get("children"), dict) else {}
    hermers_workflow = hermers.get("workflow") if isinstance(hermers.get("workflow"), dict) else {}
    sample = {
        "tsEpoch": now_s,
        "gatewayMemoryBytes": int(gateway.get("memoryBytes") or 0),
        "gatewaySwapBytes": int(gateway.get("swapBytes") or 0),
        "systemMemAvailableBytes": int(system_memory.get("memAvailableBytes") or 0),
        "systemSwapUsedBytes": int(system_memory.get("swapUsedBytes") or 0),
        "systemSwapUsedRatio": float(system_memory.get("swapUsedRatio") or 0),
        "systemCommitRatio": float(system_memory.get("commitRatio") or 0),
        "gatewayChildCount": int(children.get("count") or 0),
        "hermersAcpWorkers": len(hermers.get("acpWorkers") or []),
        "hermersOrphanAcpWorkers": len(hermers.get("orphanAcpWorkers") or []),
        "hermersRecentFailureCount": int(hermers_workflow.get("recentFailureCount") or 0),
        "hermersStaleSentCount": int(hermers_workflow.get("staleSentCount") or 0),
        "codexAppServers": int(children.get("codexAppServers") or 0),
        "openclawChildren": int(children.get("openclawChildren") or 0),
        "diskFreeBytes": int(resource.get("diskFreeBytes") or 0),
        "diskUsedRatio": float(resource.get("diskUsedRatio") or 0),
    }
    previous = db_get(conn, "runtime_trend_samples", []) or []
    if not isinstance(previous, list):
        previous = []
    cutoff = now_s - max(TREND_WINDOW_SECONDS * 2, 3600)
    samples = [item for item in previous if isinstance(item, dict) and int(item.get("tsEpoch") or 0) >= cutoff]
    samples.append(sample)
    samples = samples[-TREND_SAMPLE_LIMIT:]
    db_set(conn, "runtime_trend_samples", samples)

    window_samples = [item for item in samples if int(item.get("tsEpoch") or 0) >= now_s - TREND_WINDOW_SECONDS]
    baseline = window_samples[0] if window_samples else sample
    memory_delta = int(sample["gatewayMemoryBytes"]) - int(baseline.get("gatewayMemoryBytes") or 0)
    child_delta = int(sample["gatewayChildCount"]) - int(baseline.get("gatewayChildCount") or 0)
    disk_free_delta = int(sample["diskFreeBytes"]) - int(baseline.get("diskFreeBytes") or 0)
    trend = {
        "windowSeconds": TREND_WINDOW_SECONDS,
        "sampleCount": len(window_samples),
        "baselineEpoch": baseline.get("tsEpoch"),
        "current": sample,
        "deltas": {
            "gatewayMemoryBytes": memory_delta,
            "gatewayChildCount": child_delta,
            "diskFreeBytes": disk_free_delta,
        },
    }
    if len(window_samples) >= 3 and memory_delta >= MEMORY_GROWTH_WARN_BYTES and sample["gatewayMemoryBytes"] >= MEMORY_WARN_BYTES * 0.8:
        add_finding(
            findings,
            "gateway_memory_growth",
            "warning",
            "resource",
            "gateway memory is growing quickly within the trend window",
            trend=trend,
        )
    if len(window_samples) >= 3 and child_delta >= CHILD_GROWTH_WARN_COUNT:
        add_finding(
            findings,
            "gateway_child_growth",
            "warning",
            "resource",
            "gateway child process count is growing within the trend window",
            trend=trend,
        )
    return trend


def add_resource_governance_findings(
    findings: List[Dict[str, Any]],
    snapshot: Dict[str, Any],
    streaks: Dict[str, Any],
) -> None:
    keys = {str(f.get("key")) for f in findings}
    finding_by_key = {str(f.get("key")): f for f in findings if isinstance(f, dict)}
    immediate = sorted(
        key
        for key in (RESOURCE_INCIDENT_IMMEDIATE_KEYS & keys)
        if SEVERITY_RANK.get(str((finding_by_key.get(key) or {}).get("severity")), 0) >= SEVERITY_RANK["critical"]
    )
    sustained_keys = [
        key
        for key in sorted(RESOURCE_INCIDENT_SUSTAINED_KEYS & keys)
        if sustained(streaks, key, RESOURCE_INCIDENT_STREAK_THRESHOLD)
    ]
    if not immediate and not sustained_keys:
        return
    gateway = snapshot.get("gateway") if isinstance(snapshot.get("gateway"), dict) else {}
    resource = snapshot.get("resource") if isinstance(snapshot.get("resource"), dict) else {}
    system_memory = resource.get("memory") if isinstance(resource.get("memory"), dict) else {}
    streak_counts = {
        key: int((streaks.get(key) or {}).get("count") or 0)
        for key in sorted((RESOURCE_INCIDENT_IMMEDIATE_KEYS | RESOURCE_INCIDENT_SUSTAINED_KEYS) & keys)
    }
    add_finding(
        findings,
        "gateway_resource_incident",
        "critical",
        "resource",
        "resource pressure requires incident handling and Human Gate options",
        immediateKeys=immediate,
        sustainedKeys=sustained_keys,
        streakCounts=streak_counts,
        gatewayMemoryBytes=int(gateway.get("memoryBytes") or 0),
        gatewaySwapBytes=int(gateway.get("swapBytes") or 0),
        systemMemAvailableBytes=int(system_memory.get("memAvailableBytes") or 0),
        systemSwapUsedBytes=int(system_memory.get("swapUsedBytes") or 0),
        systemSwapUsedRatio=float(system_memory.get("swapUsedRatio") or 0),
        systemCommitRatio=float(system_memory.get("commitRatio") or 0),
        humanGateRequired=True,
        recommendedOptions=["controlled_gateway_restart", "load_shed_and_observe", "rollback_or_hold_runtime_changes"],
    )


def recent_restart_history(conn: sqlite3.Connection) -> List[int]:
    history = db_get(conn, "stabilityd_gateway_restart_history", []) or []
    cutoff = epoch() - RESTART_WINDOW_SECONDS
    return [int(x) for x in history if int(x) >= cutoff]


def record_restart_time(conn: sqlite3.Connection) -> None:
    history = recent_restart_history(conn)
    now_s = epoch()
    history.append(now_s)
    db_set(conn, "stabilityd_gateway_restart_history", history)
    db_set(conn, "stabilityd_last_gateway_restart_at", now_s)


def recent_hermers_gateway_restart_history(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    history = db_get(conn, "stabilityd_hermers_gateway_restart_history", []) or []
    cutoff = epoch() - RESTART_WINDOW_SECONDS
    normalized = []
    for item in history:
        try:
            if isinstance(item, dict):
                ts_epoch = int(item.get("tsEpoch") or 0)
                profile = str(item.get("profile") or "")
            else:
                ts_epoch = int(item or 0)
                profile = ""
        except Exception:
            continue
        if ts_epoch >= cutoff:
            normalized.append({"tsEpoch": ts_epoch, "profile": profile})
    return normalized


def record_hermers_gateway_restart_time(conn: sqlite3.Connection, profile: str) -> None:
    history = recent_hermers_gateway_restart_history(conn)
    now_s = epoch()
    history.append({"tsEpoch": now_s, "profile": profile})
    db_set(conn, "stabilityd_hermers_gateway_restart_history", history)
    db_set(conn, "stabilityd_last_hermers_gateway_restart_at", now_s)


def hot(streaks: Dict[str, Any], key: str) -> bool:
    return int(streaks.get(key, {}).get("count") or 0) >= ACTION_STREAK_THRESHOLD


def sustained(streaks: Dict[str, Any], key: str, threshold: int) -> bool:
    return int(streaks.get(key, {}).get("count") or 0) >= threshold


def update_lane_recovery(conn: sqlite3.Connection, now_s: int, pressures: Dict[str, bool]) -> Dict[str, Any]:
    previous = db_get(conn, "lane_recovery_state", {}) or {}
    previous_domains = previous.get("domains") if isinstance(previous.get("domains"), dict) else previous
    domains: Dict[str, Any] = {}
    for domain in ("cron", "session", "channel", "hermers", "resource"):
        old = previous_domains.get(domain) if isinstance(previous_domains.get(domain), dict) else {}
        pressure = bool(pressures.get(domain))
        pressure_streak = int(old.get("pressureStreak") or 0)
        healthy_streak = int(old.get("healthyStreak") or 0)
        if pressure:
            pressure_streak += 1
            healthy_streak = 0
        else:
            healthy_streak += 1
            pressure_streak = 0
        domains[domain] = {
            "pressure": pressure,
            "pressureStreak": pressure_streak,
            "healthyStreak": healthy_streak,
            "updatedAtEpoch": now_s,
        }
    cron_healthy = int(domains["cron"]["healthyStreak"])
    if pressures.get("cron") or pressures.get("resource") or pressures.get("channel"):
        cron_next = "critical-only"
    elif cron_healthy >= CRON_RECOVERY_OPEN_HEALTHY_STREAK:
        cron_next = "open"
    elif cron_healthy >= CRON_RECOVERY_LIMITED_HEALTHY_STREAK:
        cron_next = "limited"
    else:
        cron_next = "hold"
    payload = {
        "schemaVersion": 1,
        "updatedAt": ts(),
        "updatedAtEpoch": now_s,
        "cronRecoveryLimitedHealthyStreak": CRON_RECOVERY_LIMITED_HEALTHY_STREAK,
        "cronRecoveryOpenHealthyStreak": CRON_RECOVERY_OPEN_HEALTHY_STREAK,
        "domains": domains,
        "cronNextAdmissionWhenGlobalGatesAllow": cron_next,
    }
    db_set(conn, "lane_recovery_state", payload)
    return payload


def build_lane_policy(
    *,
    now_s: int,
    mode: str,
    severity: str,
    keys: set[str],
    streaks: Dict[str, Any],
    gateway: Dict[str, Any],
    can_mutate_cron: bool,
    can_reset_session: bool,
    should_pause_cron: bool,
    should_defer_control_plane_heavy: bool,
    control_plane_defer_until: int,
    restart_storm: bool,
    cooldown_active: bool,
    recovery: Dict[str, Any],
    hermers_profile_modes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    gateway_unavailable = mode == "gateway-unreachable" or not gateway.get("active") or not gateway.get("portOk")
    resource_pressure = resource_pressure_active(keys) or mode == "resource-pressure"
    cron_pressure = bool({"cron_stale_running_state", "cron_expired_leases", "gateway_congestion_logs", "cron_heartbeat_unhealthy"} & keys)
    session_pressure = "session_problem_backlog" in keys
    channel_pressure = bool(
        {"telegram_provider_network_errors", "telegram_channel_restart_limited", "telegram_channel_restart_churn"} & keys
    ) or any(k.endswith("_consumer_lag") or k.endswith("_consumer_lag_warn") for k in keys)
    hermers_pressure = bool(
        {
            "hermers_gateway_service_down",
            "hermers_acp_orphan_workers",
            "hermers_runtime_failure_burst",
            "hermers_stale_sent_dispatches",
        } & keys
    )
    direct_pressure = gateway_unavailable or "gateway_congestion_logs" in keys or channel_pressure or resource_pressure or restart_storm

    direct_admission = "open"
    if gateway_unavailable:
        direct_admission = "closed"
    elif restart_storm or cooldown_active or direct_pressure:
        direct_admission = "priority-only"

    if gateway_unavailable:
        cron_max_concurrency = 0
    elif restart_storm or cooldown_active:
        cron_max_concurrency = CRON_MAX_CONCURRENCY_DEGRADED
    elif should_pause_cron or resource_pressure:
        cron_max_concurrency = CRON_MAX_CONCURRENCY_DEGRADED
    elif severity in {"high", "critical"}:
        cron_max_concurrency = CRON_MAX_CONCURRENCY_DEGRADED
    else:
        cron_max_concurrency = CRON_MAX_CONCURRENCY_NORMAL

    if gateway_unavailable:
        channel_probe_mode = "disabled"
    elif channel_pressure:
        channel_probe_mode = "passive-offset-only"
    elif os.environ.get("OPENCLAW_STABILITY_TELEGRAM_API_PROBE", "0") == "1":
        channel_probe_mode = "non-consuming-api-probe"
    else:
        channel_probe_mode = "passive"

    session_reset_allowed = bool(can_reset_session)
    main_session_reset_allowed = session_reset_allowed and not ("session_problem_backlog" in keys and severity == "critical")
    cron_evidence = sorted(k for k in keys if k in {"cron_stale_running_state", "cron_expired_leases", "gateway_congestion_logs", "cron_heartbeat_unhealthy"})
    cron_observations = sorted(
        k
        for k in keys
        if k
        in {
            "cron_audit_high_findings",
            "cron_audit_stale",
            "cron_audit_missing",
            "cron_heartbeat_slow",
            "cron_long_running_jobs",
            "cron_timeout_like_failures",
            "cron_orphan_run_logs",
            "cron_cli_status_error_jobs",
            "cron_cli_status_skipped_jobs",
            "gateway_task_reconcile_observations",
        }
    )
    session_evidence = sorted(k for k in keys if k in {"session_problem_backlog"})
    session_observations = sorted(k for k in keys if k in {"session_stale_entries", "session_problem_stale_log_observations", "session_problem_protected_active"})
    channel_evidence = sorted(
        k
        for k in keys
        if k.startswith("telegram_")
        and (
            k.endswith("_consumer_lag")
            or k.endswith("_consumer_lag_warn")
            or k in {"telegram_provider_network_errors", "telegram_channel_restart_limited", "telegram_channel_restart_churn"}
        )
    )
    channel_observations = sorted(k for k in keys if k.startswith("telegram_") and k not in set(channel_evidence))
    hermers_evidence = sorted(
        k
        for k in keys
        if k
        in {
            "hermers_gateway_service_down",
            "hermers_acp_orphan_workers",
            "hermers_runtime_failure_burst",
            "hermers_stale_sent_dispatches",
        }
    )
    hermers_observations = sorted(k for k in keys if k.startswith("hermers_") and k not in set(hermers_evidence))
    streak_counts = {key: int((streaks.get(key) or {}).get("count") or 0) for key in sorted(keys)}
    profile_modes = hermers_profile_modes if isinstance(hermers_profile_modes, dict) else {}
    profile_mode_profiles = profile_modes.get("profiles") if isinstance(profile_modes.get("profiles"), dict) else {}
    profile_mode_counts = profile_modes.get("counts") if isinstance(profile_modes.get("counts"), dict) else {}

    cron_recovery = ((recovery.get("domains") or {}).get("cron") or {}) if isinstance(recovery, dict) else {}
    cron_healthy_streak = int(cron_recovery.get("healthyStreak") or 0)
    active_cron_pause = bool(should_pause_cron and (cron_pressure or resource_pressure or gateway_unavailable or channel_pressure))
    if cron_max_concurrency == 0:
        cron_admission = "closed"
    elif active_cron_pause:
        cron_admission = "critical-only"
    elif restart_storm or cooldown_active or cron_max_concurrency < CRON_MAX_CONCURRENCY_NORMAL:
        cron_admission = "limited"
    elif cron_healthy_streak < CRON_RECOVERY_OPEN_HEALTHY_STREAK:
        cron_admission = "limited"
    else:
        cron_admission = "open"
    cron_state = "blocked" if cron_admission == "closed" else "constrained" if cron_admission != "open" else "normal"
    session_state = "constrained" if session_pressure else "normal"
    channel_state = "blocked" if channel_probe_mode == "disabled" else "constrained" if channel_pressure else "normal"
    hermers_state = "blocked" if "hermers_gateway_service_down" in keys else "constrained" if hermers_pressure else "normal"

    return {
        "schemaVersion": 1,
        "updatedAt": ts(),
        "updatedAtEpoch": now_s,
        "validUntilEpoch": now_s + POLICY_TTL_SECONDS,
        "primaryPressureDomains": {
            "cron": bool(cron_pressure),
            "session": bool(session_pressure),
            "channel": bool(channel_pressure),
            "hermers": bool(hermers_pressure),
        },
        "secondaryPressureDomains": {
            "gateway": bool(gateway_unavailable or "gateway_congestion_logs" in keys),
            "resource": bool(resource_pressure),
        },
        "direct": {
            "admission": direct_admission,
            "priority": "highest",
            "protectDirectSessions": True,
            "reasons": sorted(
                r
                for r in [
                    "gateway-unavailable" if gateway_unavailable else "",
                    "restart-storm" if restart_storm else "",
                    "cooldown" if cooldown_active else "",
                    "gateway-congestion" if "gateway_congestion_logs" in keys else "",
                    "channel-pressure" if channel_pressure else "",
                    "resource-pressure" if resource_pressure else "",
                ]
                if r
            ),
        },
        "controlPlane": {
            "heavyReports": "defer" if should_defer_control_plane_heavy else "run",
            "deferUntilEpoch": int(control_plane_defer_until or 0),
            "heartbeat": "run",
            "directSessions": "protect-priority",
        },
        "recovery": recovery,
        "domains": {
            "cron": {
                "state": cron_state,
                "pressure": bool(cron_pressure),
                "evidenceKeys": cron_evidence,
                "observationKeys": cron_observations,
                "streakCounts": {k: streak_counts[k] for k in cron_evidence if k in streak_counts},
                "governanceAction": "pause-non-critical" if active_cron_pause else "limit-concurrency" if cron_max_concurrency < CRON_MAX_CONCURRENCY_NORMAL else "observe",
                "stabilizationGoal": "reduce cron queue age, stale running state, expired leases, heartbeat failure, and retry density without interrupting critical heartbeat work",
            },
            "session": {
                "state": session_state,
                "pressure": bool(session_pressure),
                "evidenceKeys": session_evidence,
                "observationKeys": session_observations,
                "streakCounts": {k: streak_counts[k] for k in session_evidence if k in streak_counts},
                "governanceAction": "reset-eligible-inactive-sessions" if session_reset_allowed and session_pressure else "protect-and-observe" if session_pressure else "observe",
                "stabilizationGoal": "reduce stuck or failed session backlog while protecting active, direct, and heavy-but-progressing sessions",
            },
            "channel": {
                "state": channel_state,
                "pressure": bool(channel_pressure),
                "evidenceKeys": channel_evidence,
                "observationKeys": channel_observations,
                "streakCounts": {k: streak_counts[k] for k in channel_evidence if k in streak_counts},
                "governanceAction": "passive-backoff" if channel_pressure else "passive-observe",
                "stabilizationGoal": "keep provider delivery healthy without competing with the Gateway consumer",
            },
            "hermers": {
                "state": hermers_state,
                "pressure": bool(hermers_pressure),
                "evidenceKeys": hermers_evidence,
                "observationKeys": hermers_observations,
                "streakCounts": {k: streak_counts[k] for k in hermers_evidence if k in streak_counts},
                "governanceAction": "reap-orphan-acp-workers" if "hermers_acp_orphan_workers" in keys and HERMERS_ACP_ORPHAN_REAP_ENABLED else "operator-review-orphan-acp-workers" if "hermers_acp_orphan_workers" in keys else "reap-idle-lsp" if "hermers_lsp_idle_processes" in keys and HERMERS_LSP_IDLE_REAP_ENABLED else "operator-review-idle-lsp" if "hermers_lsp_idle_processes" in keys else "profile-mode-adjust" if int(profile_mode_counts.get("hibernate") or 0) > 0 and HERMERS_PROFILE_MODE_ACTUATE_ENABLED else "profile-readiness-observe" if int(profile_mode_counts.get("hibernate") or 0) > 0 else ("restart-hermers-gateway" if HERMERS_GATEWAY_RESTART_ENABLED else "restart-hermers-gateway-disabled-observe") if "hermers_gateway_service_down" in keys else "observe",
                "stabilizationGoal": "keep Hermers profile gateways, ACP workers, runtime receipts, and workflow-facing execution readiness healthy without masking runtime failures as workflow success",
                "profileRuntimeModes": {
                    "enabled": bool(profile_modes.get("enabled")),
                    "actuateEnabled": bool(profile_modes.get("actuateEnabled")),
                    "controlMode": profile_modes.get("controlMode"),
                    "registrySource": profile_modes.get("registrySource"),
                    "coldIdleSeconds": profile_modes.get("coldIdleSeconds"),
                    "hibernateIdleSeconds": profile_modes.get("hibernateIdleSeconds"),
                    "counts": profile_mode_counts,
                    "profiles": profile_mode_profiles,
                },
            },
        },
        "cron": {
            "maxConcurrency": int(cron_max_concurrency),
            "nonCriticalPaused": bool(active_cron_pause),
            "mutateStateAllowed": bool(can_mutate_cron),
            "bulkAllowed": mode == "healthy" and severity in {"ok", "info"},
            "admission": cron_admission,
            "pressure": bool(cron_pressure),
            "criticalJobsAllowed": not gateway_unavailable,
            "heartbeatAllowed": not gateway_unavailable,
        },
        "channel": {
            "probeMode": channel_probe_mode,
            "consumeUpdates": False,
            "providerBackoff": "increase" if channel_pressure else "normal",
            "pressure": bool(channel_pressure),
        },
        "session": {
            "resetAllowed": session_reset_allowed,
            "ordinaryResetAllowed": session_reset_allowed,
            "mainResetAllowed": main_session_reset_allowed,
            "pressure": bool(session_pressure),
            "protectedDirectSessionKeys": sorted(CONTROL_PLANE_DIRECT_SESSION_KEYS),
        },
        "hermers": {
            "pressure": bool(hermers_pressure),
            "reapOrphanAcpWorkersAllowed": bool(HERMERS_ACP_ORPHAN_REAP_ENABLED),
            "reapIdleLspAllowed": bool(HERMERS_LSP_IDLE_REAP_ENABLED),
            "lspIdleSeconds": HERMERS_LSP_IDLE_SECONDS,
            "gatewayRestartAllowed": bool(HERMERS_GATEWAY_RESTART_ENABLED),
            "gatewayRestartDefault": "policy-gated" if HERMERS_GATEWAY_RESTART_ENABLED else "disabled",
            "profileModeEnabled": bool(profile_modes.get("enabled")),
            "profileModeActuateAllowed": bool(profile_modes.get("actuateEnabled")),
            "profileModes": {
                "controlMode": profile_modes.get("controlMode"),
                "registrySource": profile_modes.get("registrySource"),
                "coldIdleSeconds": profile_modes.get("coldIdleSeconds"),
                "hibernateIdleSeconds": profile_modes.get("hibernateIdleSeconds"),
                "counts": profile_mode_counts,
            },
        },
    }


def policy_from_findings(conn: sqlite3.Connection, findings: List[Dict[str, Any]], snapshot: Dict[str, Any], streaks: Dict[str, Any]) -> Dict[str, Any]:
    severity = max_severity(findings)
    keys = {str(f.get("key")) for f in findings}
    components = {str(f.get("component")) for f in findings}
    reasons = [str(f.get("key")) for f in findings if SEVERITY_RANK.get(str(f.get("severity")), 0) >= SEVERITY_RANK["high"]]
    mode = "healthy"
    if severity != "ok":
        mode = "degraded"
    if {"gateway_service_down", "gateway_port_down", "gateway_health_endpoint_failed"} & keys:
        mode = "gateway-unreachable"
    elif any(k.endswith("_consumer_lag") for k in keys):
        mode = "channel-stalled"
    elif {"telegram_provider_network_errors", "telegram_channel_restart_limited", "telegram_channel_restart_churn"} & keys:
        mode = "delivery-failing"
    elif "cron_stale_running_state" in keys or "cron_expired_leases" in keys:
        mode = "cron-state-corrupt"
    elif "gateway_congestion_logs" in keys or "cron_heartbeat_unhealthy" in keys:
        mode = "cron-congested"
    elif "session_problem_backlog" in keys:
        mode = "session-stuck"
    elif "hermers_gateway_service_down" in keys:
        mode = "hermers-unavailable"
    elif {"hermers_acp_orphan_workers", "hermers_runtime_failure_burst", "hermers_stale_sent_dispatches"} & keys:
        mode = "hermers-degraded"
    elif resource_pressure_active(keys):
        mode = "resource-pressure"

    now_s = epoch()
    last_restart = int(db_get(conn, "stabilityd_last_gateway_restart_at", 0) or 0)
    cooldown_until = last_restart + RESTART_COOLDOWN_SECONDS if last_restart else 0
    cooldown_active = cooldown_until > now_s
    restart_history = recent_restart_history(conn)
    restart_storm = len(restart_history) >= MAX_RESTARTS_PER_WINDOW
    restart_storm_clears_at = min(restart_history) + RESTART_WINDOW_SECONDS if restart_storm and restart_history else 0
    if restart_storm:
        mode = "restart-storm"
        severity = "critical"
        reasons.append("restart_storm")
    elif cooldown_active and mode != "healthy":
        mode = "cooldown"

    restart_candidate = False
    can_restart = False
    restart_reason = "no-actionable-streak"
    restart_blocked_reasons: List[str] = []
    gateway = snapshot.get("gateway") or {}
    hermers = snapshot.get("hermers") if isinstance(snapshot.get("hermers"), dict) else {}
    hermers_profile_modes = hermers.get("profileModes") if isinstance(hermers.get("profileModes"), dict) else {}
    hermers_profile_mode_items = hermers_profile_modes.get("profiles") if isinstance(hermers_profile_modes.get("profiles"), dict) else {}
    hermers_profiles = hermers.get("profiles") if isinstance(hermers.get("profiles"), dict) else {}
    hermers_gateway_restart_profiles = [
        {"profile": str(profile), "unit": str((item or {}).get("unit") or f"hermes-gateway-{profile}.service")}
        for profile, item in sorted(hermers_profiles.items())
        if isinstance(item, dict) and not bool(item.get("active"))
        and bool((hermers_profile_mode_items.get(profile) or {}).get("expectedActive", True))
    ]
    hermers_last_restart = int(db_get(conn, "stabilityd_last_hermers_gateway_restart_at", 0) or 0)
    hermers_cooldown_until = hermers_last_restart + RESTART_COOLDOWN_SECONDS if hermers_last_restart else 0
    hermers_cooldown_active = hermers_cooldown_until > now_s
    hermers_restart_history = recent_hermers_gateway_restart_history(conn)
    hermers_restart_storm = len(hermers_restart_history) >= MAX_RESTARTS_PER_WINDOW
    hermers_restart_candidate = bool(hermers_gateway_restart_profiles and hot(streaks, "hermers_gateway_service_down"))
    hermers_restart_remaining = max(0, MAX_RESTARTS_PER_WINDOW - len(hermers_restart_history))
    hermers_restart_limit = min(HERMERS_GATEWAY_RESTART_LIMIT, hermers_restart_remaining)
    hermers_restart_blocked_reasons: List[str] = []
    if hermers_restart_candidate:
        if hermers_restart_storm:
            hermers_restart_blocked_reasons.append("restart-storm")
        elif hermers_cooldown_active:
            hermers_restart_blocked_reasons.append("cooldown")
        if not HERMERS_GATEWAY_RESTART_ENABLED:
            hermers_restart_blocked_reasons.append("restart-actuator-disabled")
        if HERMERS_GATEWAY_RESTART_LIMIT <= 0:
            hermers_restart_blocked_reasons.append("restart-limit-zero")
        elif hermers_restart_limit <= 0:
            hermers_restart_blocked_reasons.append("restart-budget-exhausted")
    can_restart_hermers_gateway = bool(hermers_restart_candidate and HERMERS_GATEWAY_RESTART_ENABLED and not hermers_restart_blocked_reasons)
    hermers_restart_decisions = hermers_gateway_restart_profiles[:hermers_restart_limit] if can_restart_hermers_gateway else []
    if hermers_restart_storm and not restart_storm:
        mode = "restart-storm"
        severity = "critical"
        reasons.append("hermers_restart_storm")
    elif hermers_cooldown_active and mode in {"hermers-unavailable", "hermers-degraded"}:
        mode = "cooldown"
    hard_fault_candidate = hot(streaks, "gateway_service_down") or hot(streaks, "gateway_port_down") or hot(streaks, "gateway_health_endpoint_failed")
    if hard_fault_candidate:
        restart_candidate = True
        restart_reason = "gateway-basic-health-failed"
    if not restart_candidate and not restart_storm and not cooldown_active and not gateway.get("startupGraceActive"):
        if SOFT_GATEWAY_RESTART_ENABLED:
            for key in keys:
                if key.startswith("telegram_") and key.endswith("_consumer_lag") and hot(streaks, key):
                    restart_candidate = True
                    restart_reason = key
                    break
            if not restart_candidate and hot(streaks, "session_problem_backlog") and (
                hot(streaks, "gateway_resource_saturation")
                or hot(streaks, "gateway_resource_pressure")
                or hot(streaks, "gateway_child_accumulation")
            ):
                restart_candidate = True
                restart_reason = "stuck-sessions-with-resource-pressure"
            if not restart_candidate and hot(streaks, "cron_audit_high_findings") and hot(streaks, "session_problem_backlog"):
                restart_candidate = True
                restart_reason = "cron-and-session-pressure"
        if not restart_candidate and SOFT_RESCUE_RESTART_ENABLED:
            resource_exhausted = (
                sustained(streaks, "gateway_resource_saturation", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "gateway_swap_saturation", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "system_memory_saturation", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "system_swap_saturation", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "system_commit_saturation", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "disk_pressure", SOFT_RESCUE_STREAK_THRESHOLD)
            )
            cron_blocked = (
                sustained(streaks, "cron_stale_running_state", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "cron_expired_leases", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "cron_heartbeat_unhealthy", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "cron_audit_high_findings", SOFT_RESCUE_STREAK_THRESHOLD)
            )
            session_blocked = sustained(streaks, "session_problem_backlog", SOFT_RESCUE_STREAK_THRESHOLD)
            runtime_blocked = cron_blocked and session_blocked
            gateway_congested = sustained(streaks, "gateway_congestion_logs", SOFT_RESCUE_STREAK_THRESHOLD)
            channel_blocked = any(
                key.startswith("telegram_")
                and key.endswith("_consumer_lag")
                and sustained(streaks, key, SOFT_RESCUE_STREAK_THRESHOLD)
                for key in keys
            )
            provider_broken = (
                sustained(streaks, "telegram_provider_network_errors", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "telegram_channel_restart_limited", SOFT_RESCUE_STREAK_THRESHOLD)
                or sustained(streaks, "telegram_channel_restart_churn", SOFT_RESCUE_STREAK_THRESHOLD)
            )
            if severity == "critical" and (
                (runtime_blocked and (resource_exhausted or gateway_congested))
                or (channel_blocked and resource_exhausted)
                or (provider_broken and channel_blocked and gateway_congested)
            ):
                restart_candidate = True
                restart_reason = "soft-pressure-rescue"
    if restart_storm:
        restart_blocked_reasons.append("restart-storm")
    elif cooldown_active:
        restart_blocked_reasons.append("cooldown")
    elif gateway.get("startupGraceActive"):
        restart_blocked_reasons.append("startup-grace")

    if restart_candidate and not GATEWAY_RESTART_ENABLED:
        restart_blocked_reasons.append("restart-actuator-disabled")
    if restart_candidate and not GATEWAY_RESTART_ACTUATOR_SUPPORTED:
        restart_blocked_reasons.append("restart-actuator-unavailable")
    can_restart = bool(restart_candidate and GATEWAY_RESTART_ENABLED and GATEWAY_RESTART_ACTUATOR_SUPPORTED and not restart_blocked_reasons)

    cron_snapshot = snapshot.get("cron") if isinstance(snapshot.get("cron"), dict) else {}
    cron_storage = cron_snapshot.get("storageStatus") if isinstance(cron_snapshot.get("storageStatus"), dict) else {}
    cron_uses_sqlite_storage = str(cron_storage.get("storage") or "").lower() == "sqlite"
    can_mutate_cron = (
        CRON_MUTATION_ENABLED
        and not cron_uses_sqlite_storage
        and not restart_storm
        and not can_restart
        and mode not in {"gateway-unreachable", "channel-stalled", "resource-pressure", "restart-storm"}
    )
    can_reset_session = SESSION_RESET_ENABLED and not restart_storm and mode not in {"gateway-unreachable", "resource-pressure", "restart-storm"}
    should_pause_cron = mode in {"channel-stalled", "delivery-failing", "cron-congested", "hermers-unavailable", "hermers-degraded", "resource-pressure", "cooldown", "restart-storm"}
    should_defer_control_plane_heavy = mode in {"cooldown", "cron-congested", "resource-pressure", "restart-storm"} or (
        severity == "critical" and "session_problem_backlog" in keys
    )
    control_plane_defer_until = 0
    if should_defer_control_plane_heavy:
        control_plane_defer_until = max(
            cooldown_until if cooldown_active else 0,
            hermers_cooldown_until if hermers_cooldown_active else 0,
            now_s + CONTROL_PLANE_BACKPRESSURE_SECONDS,
        )
    gateway_unavailable = mode == "gateway-unreachable" or not gateway.get("active") or not gateway.get("portOk")
    resource_pressure = resource_pressure_active(keys) or mode == "resource-pressure"
    recovery = update_lane_recovery(
        conn,
        now_s,
        {
            "cron": bool({"cron_stale_running_state", "cron_expired_leases", "gateway_congestion_logs", "cron_heartbeat_unhealthy"} & keys) or gateway_unavailable,
            "session": "session_problem_backlog" in keys,
            "channel": bool(
                {"telegram_provider_network_errors", "telegram_channel_restart_limited", "telegram_channel_restart_churn"} & keys
            ) or any(k.endswith("_consumer_lag") or k.endswith("_consumer_lag_warn") for k in keys),
            "hermers": bool(
                {
                    "hermers_gateway_service_down",
                    "hermers_acp_orphan_workers",
                    "hermers_runtime_failure_burst",
                    "hermers_stale_sent_dispatches",
                } & keys
            ),
            "resource": resource_pressure,
        },
    )
    lanes = build_lane_policy(
        now_s=now_s,
        mode=mode,
        severity=severity,
        keys=keys,
        streaks=streaks,
        gateway=gateway,
        can_mutate_cron=bool(can_mutate_cron),
        can_reset_session=bool(can_reset_session),
        should_pause_cron=bool(should_pause_cron),
        should_defer_control_plane_heavy=bool(should_defer_control_plane_heavy),
        control_plane_defer_until=control_plane_defer_until,
        restart_storm=bool(restart_storm),
        cooldown_active=bool(cooldown_active or hermers_cooldown_active),
        recovery=recovery,
        hermers_profile_modes=hermers_profile_modes,
    )
    policy = {
        "schemaVersion": 1,
        "updatedAt": ts(),
        "updatedAtEpoch": now_s,
        "validUntilEpoch": now_s + POLICY_TTL_SECONDS,
        "mode": mode,
        "severity": severity,
        "canMutateCronState": bool(can_mutate_cron),
        "cronMutationBlockedReason": "openclaw-sqlite-cron-storage" if cron_uses_sqlite_storage else "",
        "canResetSession": bool(can_reset_session),
        "gatewayRestartEnabled": bool(GATEWAY_RESTART_ENABLED),
        "gatewayRestartActuatorSupported": bool(GATEWAY_RESTART_ACTUATOR_SUPPORTED),
        "hermersGatewayRestartEnabled": bool(HERMERS_GATEWAY_RESTART_ENABLED),
        "hermersGatewayRestartCandidate": bool(hermers_restart_candidate),
        "hermersGatewayRestartBlockedReasons": hermers_restart_blocked_reasons,
        "canRestartHermersGateway": bool(can_restart_hermers_gateway),
        "canReapHermersOrphanWorkers": bool(HERMERS_ACP_ORPHAN_REAP_ENABLED),
        "canReapHermersIdleLsp": bool(HERMERS_LSP_IDLE_REAP_ENABLED),
        "hermersLspIdleSeconds": HERMERS_LSP_IDLE_SECONDS,
        "hermersGatewayRestartLimit": HERMERS_GATEWAY_RESTART_LIMIT,
        "hermersGatewayRestartRemaining": hermers_restart_remaining,
        "hermersGatewayRestartProfiles": hermers_restart_decisions,
        "hermersGatewayRestartCandidateProfiles": hermers_gateway_restart_profiles,
        "hermersGatewayRestartReason": "hermers-gateway-service-down" if hermers_restart_candidate else "no-actionable-streak",
        "restartCandidate": bool(restart_candidate),
        "restartBlockedReasons": restart_blocked_reasons,
        "restartBlockedReason": ",".join(restart_blocked_reasons),
        "canRestartGateway": bool(can_restart),
        "canRunBulkCron": mode == "healthy" and severity in {"ok", "info"},
        "shouldPauseNonCriticalCron": bool(should_pause_cron),
        "deferControlPlaneHeavyReports": bool(should_defer_control_plane_heavy),
        "controlPlaneBackpressureUntilEpoch": control_plane_defer_until,
        "cooldownUntilEpoch": cooldown_until if cooldown_active else 0,
        "restartReason": restart_reason,
        "softRescueRestartEnabled": bool(SOFT_RESCUE_RESTART_ENABLED),
        "softRescueStreakThreshold": SOFT_RESCUE_STREAK_THRESHOLD,
        "restartStorm": bool(restart_storm),
        "restartStormClearsAtEpoch": restart_storm_clears_at,
        "recentRestartCount": len(restart_history),
        "restartHistorySource": "cat-agents-stabilityd-owned-restarts-only",
        "hermersRestartStorm": bool(hermers_restart_storm),
        "hermersRestartStormClearsAtEpoch": min(item["tsEpoch"] for item in hermers_restart_history) + RESTART_WINDOW_SECONDS if hermers_restart_storm and hermers_restart_history else 0,
        "hermersGatewayCooldownUntilEpoch": hermers_cooldown_until if hermers_cooldown_active else 0,
        "recentHermersGatewayRestartCount": len(hermers_restart_history),
        "hermersRestartHistorySource": "cat-agents-stabilityd-owned-hermers-gateway-restarts-only",
        "restartWindowSeconds": RESTART_WINDOW_SECONDS,
        "maxRestarts": MAX_RESTARTS_PER_WINDOW,
        "lanes": lanes,
        "reasons": sorted(set(reasons)),
    }
    return policy


def control_plane_backpressure(snapshot: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    active = bool(policy.get("deferControlPlaneHeavyReports"))
    jobs = load_jobs()
    if not job_items(jobs):
        cron = snapshot.get("cron") if isinstance(snapshot.get("cron"), dict) else {}
        runtime = cron.get("runtime") if isinstance(cron.get("runtime"), dict) else {}
        cli_status = runtime.get("cliStatus") if isinstance(runtime.get("cliStatus"), dict) else {}
        jobs = jobs_from_cron_cli_status(cli_status)
    job_lookup = {job_id: job for job_id, job in job_items(jobs)}
    heavy_jobs = []
    for job_id in sorted(CONTROL_PLANE_HEAVY_JOB_IDS):
        job = job_lookup.get(job_id) or {}
        heavy_jobs.append(
            {
                "jobId": job_id,
                "name": job.get("name") or job_id,
                "agentId": job.get("agentId"),
                "enabled": job.get("enabled") is not False,
                "timeoutSeconds": ((job.get("payload") or {}).get("timeoutSeconds") if isinstance(job.get("payload"), dict) else None),
                "action": "defer-heavy-report" if active else "run-normally",
            }
        )
    heartbeat_jobs = []
    for job_id in sorted(CONTROL_PLANE_HEARTBEAT_JOB_IDS):
        job = job_lookup.get(job_id) or {}
        heartbeat_jobs.append(
            {
                "jobId": job_id,
                "name": job.get("name") or job_id,
                "agentId": job.get("agentId"),
                "enabled": job.get("enabled") is not False,
                "action": "run-normally",
            }
        )
    payload = {
        "schemaVersion": 1,
        "updatedAt": ts(),
        "updatedAtEpoch": epoch(),
        "active": active,
        "mode": policy.get("mode"),
        "severity": policy.get("severity"),
        "deferHeavyReports": active,
        "deferUntilEpoch": int(policy.get("controlPlaneBackpressureUntilEpoch") or 0),
        "reasons": policy.get("reasons") or [],
        "heavyReportJobs": heavy_jobs,
        "heartbeatJobs": heartbeat_jobs,
        "directSessionKeys": sorted(CONTROL_PLANE_DIRECT_SESSION_KEYS),
        "directSessionAction": "protect-priority",
        "instruction": (
            "When active, control-plane heavy reports should write a short deferred note and exit. "
            "Heartbeat jobs and direct sessions are not deferred."
        ),
    }
    return payload


def clear_stale_running_state(data: Dict[str, Any], stale: List[Dict[str, Any]]) -> int:
    stale_ids = {item["jobId"] for item in stale}
    changed = 0
    for job_id, job in job_items(data):
        if job_id not in stale_ids:
            continue
        if "runningAtMs" in job:
            job.pop("runningAtMs", None)
            changed += 1
        state = job.get("state")
        if isinstance(state, dict) and "runningAtMs" in state:
            state.pop("runningAtMs", None)
            changed += 1
        job["lastRecoveredAtMs"] = now_ms()
        job["lastRecoveryReason"] = "stale_running_state"
    return changed


def snapshot_jobs() -> Optional[str]:
    if not JOBS_PATH.exists():
        return None
    snapshot_dir = CRON_DIR / "snapshots" / "jobs"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    dest = snapshot_dir / f"jobs.before-stabilityd-{stamp}.json"
    shutil.copy2(JOBS_PATH, dest)
    return str(dest)


def cleanup_stale_tmp_files() -> List[str]:
    removed = []
    cutoff = time.time() - TMP_FILE_MAX_AGE_SECONDS
    for path in JOBS_PATH.parent.glob("jobs.json.*.tmp"):
        try:
            if path.stat().st_mtime >= cutoff:
                continue
            path.unlink(missing_ok=True)
            removed.append(str(path))
        except Exception:
            continue
    return removed


def build_repair_gate_from_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    can_mutate = bool(policy.get("canMutateCronState"))
    blocked = []
    if not can_mutate:
        blocked.append(str(policy.get("mode") or "cron-mutation-disabled"))
    if policy.get("restartBlockedReasons"):
        blocked.extend(str(item) for item in policy.get("restartBlockedReasons") or [])
    return {
        "status": "ready" if can_mutate else "blocked",
        "reason": "normal" if can_mutate else ",".join(sorted(set(blocked))) or "cron-mutation-blocked",
        "observedAt": ts(),
        "policyUpdatedAt": policy.get("updatedAt"),
        "policyValidUntilEpoch": policy.get("validUntilEpoch"),
    }


def enqueue_repair_request(
    job_id: str,
    reason: str,
    source: str,
    run_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    gate: Optional[Dict[str, Any]] = None,
) -> str:
    safe_reason = reason.replace("/", "-").replace(" ", "-")
    path = REPAIR_PENDING_DIR / f"{job_id}__{safe_reason}.json"
    current_ms = now_ms()
    existing = load_json(path, {}) if path.exists() else {}
    active_gate = gate or {}
    payload = {
        "jobId": job_id,
        "runId": run_id,
        "reason": reason,
        "source": source,
        "status": "pending",
        "queueState": active_gate.get("status") or "ready",
        "firstDetectedAtMs": int(existing.get("firstDetectedAtMs", current_ms)) if isinstance(existing, dict) else current_ms,
        "lastDetectedAtMs": current_ms,
        "count": int(existing.get("count", 0)) + 1 if isinstance(existing, dict) else 1,
        "details": details or {},
        "gate": active_gate,
    }
    write_json_atomic(path, payload)
    return str(path)


def update_repair_queue_status(policy: Dict[str, Any]) -> Dict[str, Any]:
    gate = build_repair_gate_from_policy(policy)
    pending = 0
    blocked = 0
    ready = 0
    updated = 0
    for request_path in sorted(REPAIR_PENDING_DIR.glob("*.json")):
        pending += 1
        payload = load_json(request_path, {}) or {}
        if not isinstance(payload, dict):
            continue
        payload["queueState"] = gate["status"]
        payload["gate"] = gate
        write_json_atomic(request_path, payload)
        updated += 1
        if gate["status"] == "ready":
            ready += 1
        else:
            blocked += 1
    summary = {
        "updatedAt": ts(),
        "updatedAtEpoch": epoch(),
        "queueMode": gate["status"],
        "reason": gate["reason"],
        "pendingCount": pending,
        "readyCount": ready,
        "blockedCount": blocked,
        "processedCount": len(list(REPAIR_PROCESSED_DIR.glob("*.json"))),
        "updatedPendingEntries": updated,
        "policyUpdatedAt": policy.get("updatedAt"),
    }
    write_json_atomic(REPAIR_STATUS_PATH, summary)
    return summary


def cron_actuate(snapshot: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    cron = snapshot.get("cron") or {}
    storage_status = cron.get("storageStatus") if isinstance(cron.get("storageStatus"), dict) else {}
    sqlite_cron_storage = str(storage_status.get("storage") or "").lower() == "sqlite"
    sqlite_legacy_mutation_blocked = (
        sqlite_cron_storage
        and not bool(policy.get("canMutateCronState"))
        and policy.get("cronMutationBlockedReason") == "openclaw-sqlite-cron-storage"
    )
    removed_tmp = cleanup_stale_tmp_files()
    if removed_tmp:
        actions.append({"action": "cleanup_stale_tmp_files", "result": "ok", "removed": removed_tmp})
    repair_queue = update_repair_queue_status(policy)
    if repair_queue.get("pendingCount") or repair_queue.get("updatedPendingEntries"):
        actions.append({"action": "update_repair_queue_status", "result": "ok", "repairQueue": repair_queue})
    if not policy.get("canMutateCronState") and not sqlite_legacy_mutation_blocked:
        if (snapshot.get("cron") or {}).get("staleRunning") or (snapshot.get("cron") or {}).get("expiredLeases"):
            actions.append(
                {
                    "action": "observe_cron_repair_candidates",
                    "result": "mutation_blocked_by_policy",
                    "staleRunningCount": len((snapshot.get("cron") or {}).get("staleRunning") or []),
                    "expiredLeaseCount": len((snapshot.get("cron") or {}).get("expiredLeases") or []),
                }
            )
        return actions
    stale = cron.get("staleRunning") or []
    gate = build_repair_gate_from_policy(policy)
    if sqlite_legacy_mutation_blocked and (stale or cron.get("expiredLeases")):
        actions.append(
            {
                "action": "observe_cron_repair_candidates",
                "result": "legacy_jobs_mutation_blocked_by_sqlite_storage",
                "storageStatus": storage_status,
                "staleRunningCount": len(stale),
                "expiredLeaseCount": len(cron.get("expiredLeases") or []),
            }
        )
        gate = {**gate, "status": "ready", "reason": "sqlite-storage-lease-hygiene"}
    if stale and not sqlite_cron_storage:
        data = load_jobs()
        snap_path = snapshot_jobs()
        changed = clear_stale_running_state(data, stale)
        if changed:
            write_json_atomic(JOBS_PATH, data)
            repair_paths = []
            for item in stale:
                repair_paths.append(
                    enqueue_repair_request(
                        str(item["jobId"]),
                        "stale_running_state",
                        "cat-agents-stabilityd",
                        details={"ageMs": item.get("ageMs"), "thresholdMs": item.get("thresholdMs")},
                        gate=gate,
                    )
                )
            actions.append(
                {
                    "action": "clear_stale_running_state",
                    "result": "ok",
                    "changed": changed,
                    "snapshotPath": snap_path,
                    "repairRequests": repair_paths,
                }
            )
    if LEASE_REAP_ENABLED:
        reaped = []
        for item in cron.get("expiredLeases") or []:
            lease_path = Path(str(item.get("path") or ""))
            run_id = item.get("runId")
            job_id = item.get("jobId")
            if not lease_path.exists() or not job_id:
                continue
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            lease_backup_path = None
            run_backup_path = None
            backup_dir = CRON_DIR / "snapshots" / "lease-reap"
            backup_dir.mkdir(parents=True, exist_ok=True)
            with contextlib.suppress(Exception):
                lease_backup = backup_dir / f"{lease_path.name}.before-reap-{stamp}.bak"
                shutil.copy2(lease_path, lease_backup)
                lease_backup_path = str(lease_backup)
            run_path = RUNS_BY_RUN_DIR / f"{run_id}.json" if run_id else None
            if run_path and run_path.exists():
                run_record = load_json(run_path, {}) or {}
                if run_record.get("status") == "running":
                    with contextlib.suppress(Exception):
                        run_backup = backup_dir / f"{run_path.name}.before-reap-{stamp}.bak"
                        shutil.copy2(run_path, run_backup)
                        run_backup_path = str(run_backup)
                    finished = now_ms()
                    started = int(run_record.get("startedAtMs", finished) or finished)
                    run_record["status"] = "orphaned"
                    run_record["finishedAtMs"] = finished
                    run_record["durationMs"] = max(0, finished - started)
                    run_record["failure"] = {"class": "lease_expired", "message": "Lease expired without completion update."}
                    run_record["result"] = None
                    write_json_atomic(run_path, run_record)
                    append_jsonl(
                        RUNS_BY_JOB_DIR / f"{job_id}.jsonl",
                        {
                            "ts": finished,
                            "jobId": job_id,
                            "runId": run_id,
                            "action": "orphan-reaped",
                            "status": "orphaned",
                            "durationMs": run_record["durationMs"],
                        },
                    )
            with contextlib.suppress(Exception):
                lease_path.unlink(missing_ok=True)
            repair = enqueue_repair_request(str(job_id), "lease_expired", "cat-agents-stabilityd", run_id=str(run_id) if run_id else None, gate=gate)
            reaped.append(
                {
                    "jobId": job_id,
                    "runId": run_id,
                    "leasePath": str(lease_path),
                    "leaseBackupPath": lease_backup_path,
                    "runBackupPath": run_backup_path,
                    "repairRequestPath": repair,
                }
            )
        if reaped:
            actions.append({"action": "reap_expired_leases", "result": "ok", "reaped": reaped})
    return actions


def reset_session(session_key: str, reason: str, conn: sqlite3.Connection) -> Dict[str, Any]:
    last_key = f"session_reset:{session_key}"
    last_reset = int(db_get(conn, last_key, 0) or 0)
    if last_reset and epoch() - last_reset < SESSION_RESET_COOLDOWN_SECONDS:
        return {"sessionKey": session_key, "result": "cooldown_skip", "reason": reason}
    for store_path in iter_session_store_paths():
        store = load_json(store_path, {})
        if not isinstance(store, dict) or session_key not in store:
            continue
        entry = store.get(session_key)
        if not isinstance(entry, dict):
            return {"sessionKey": session_key, "result": "invalid_entry", "storePath": str(store_path)}
        session_id = entry.get("sessionId")
        if not session_id:
            return {"sessionKey": session_key, "result": "missing_session_id", "storePath": str(store_path)}
        activity = analyze_session_activity(entry)
        if activity.get("heavy"):
            return {"sessionKey": session_key, "result": "heavy_task_skip", "activity": activity, "storePath": str(store_path), "sessionId": session_id}
        if activity.get("active"):
            return {"sessionKey": session_key, "result": "active_skip", "activity": activity, "storePath": str(store_path), "sessionId": session_id}
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        backup_dir = store_path.parent / "manual-backups"
        backup_dir.mkdir(exist_ok=True)
        shutil.copy2(store_path, backup_dir / f"sessions.json.before-stabilityd-{session_id}-{stamp}.bak")
        for path in store_path.parent.glob(f"{session_id}*"):
            if path.is_file():
                shutil.copy2(path, backup_dir / f"{path.name}.before-stabilityd-{stamp}.bak")
        store.pop(session_key, None)
        write_json_atomic(store_path, store)
        archived = []
        for path in list(store_path.parent.glob(f"{session_id}*")):
            if not path.is_file():
                continue
            new_path = path.with_name(path.name + f".stabilityd-reset-{stamp}")
            path.rename(new_path)
            archived.append(str(new_path))
        db_set(conn, last_key, epoch())
        return {
            "sessionKey": session_key,
            "result": "reset",
            "reason": reason,
            "storePath": str(store_path),
            "sessionId": session_id,
            "archivedFiles": archived,
        }
    db_set(conn, last_key, epoch())
    return {"sessionKey": session_key, "result": "not_found", "reason": reason}


def session_actuate(conn: sqlite3.Connection, snapshot: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    if not policy.get("canResetSession"):
        if (snapshot.get("session") or {}).get("resetCandidates"):
            actions.append(
                {
                    "action": "observe_session_repair_candidates",
                    "result": "reset_blocked_by_policy",
                    "candidateCount": len((snapshot.get("session") or {}).get("resetCandidates") or []),
                    "sample": ((snapshot.get("session") or {}).get("resetCandidates") or [])[:10],
                }
            )
        return actions
    candidates = (snapshot.get("session") or {}).get("resetCandidates") or []
    results = []
    for item in candidates[:10]:
        session_key = str(item.get("sessionKey") or "")
        if not session_key:
            continue
        last_key = f"session_reset:{session_key}"
        last_seen = int(db_get(conn, last_key, 0) or 0)
        if last_seen and epoch() - last_seen < SESSION_RESET_COOLDOWN_SECONDS:
            continue
        reason = "context_overflow" if int(item.get("overflowCount") or 0) >= SESSION_OVERFLOW_THRESHOLD else "repeated_failures"
        results.append(reset_session(session_key, reason, conn))
    if results:
        actions.append({"action": "reset_unhealthy_sessions", "result": "ok", "results": results})
    return actions


def gateway_restart(conn: sqlite3.Connection, reason: str) -> Dict[str, Any]:
    action_id = f"gateway-restart-{int(time.time())}"
    started = time.time()
    cmd = ["sudo", "-n", "systemctl", "restart", "openclaw-gateway.service"]
    try:
        proc = run_cmd(cmd, timeout=60)
        duration = int((time.time() - started) * 1000)
        result = "ok" if proc.returncode == 0 else "failed"
        payload = {
            "actionId": action_id,
            "ts": ts(),
            "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd",
            "component": "gateway",
            "action": "restart_gateway",
            "result": result,
            "reason": reason,
            "exitCode": proc.returncode,
            "durationMs": duration,
            "stderr": proc.stderr[-1200:],
        }
        if proc.returncode == 0:
            record_restart_time(conn)
        return payload
    except Exception as exc:
        return {
            "actionId": action_id,
            "ts": ts(),
            "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd",
            "component": "gateway",
            "action": "restart_gateway",
            "result": "failed",
            "reason": reason,
            "exitCode": -1,
            "error": f"{type(exc).__name__}: {exc}",
        }


def hermers_gateway_restart(conn: sqlite3.Connection, profile: str, unit: str, reason: str) -> Dict[str, Any]:
    action_id = f"hermers-gateway-restart-{profile}-{int(time.time())}"
    if not re.match(r"^[A-Za-z0-9_.@-]+$", profile):
        return {
            "actionId": action_id,
            "ts": ts(),
            "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd",
            "component": "hermers",
            "action": "restart_hermers_gateway",
            "result": "blocked",
            "profile": profile,
            "unit": unit,
            "reason": reason,
            "blockedReason": "invalid-profile",
        }
    expected_unit = f"hermes-gateway-{profile}.service"
    if unit != expected_unit:
        return {
            "actionId": action_id,
            "ts": ts(),
            "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd",
            "component": "hermers",
            "action": "restart_hermers_gateway",
            "result": "blocked",
            "profile": profile,
            "unit": unit,
            "reason": reason,
            "blockedReason": "unit-profile-mismatch",
            "expectedUnit": expected_unit,
        }
    last_key = f"hermers_gateway_restart:{profile}"
    last_restart = int(db_get(conn, last_key, 0) or 0)
    now_s = epoch()
    restart_history = recent_hermers_gateway_restart_history(conn)
    if len(restart_history) >= MAX_RESTARTS_PER_WINDOW:
        return {
            "actionId": action_id,
            "ts": ts(),
            "tsEpoch": now_s,
            "source": "cat-agents-stabilityd",
            "component": "hermers",
            "action": "restart_hermers_gateway",
            "result": "blocked",
            "profile": profile,
            "unit": unit,
            "reason": reason,
            "blockedReason": "restart-storm",
            "recentRestartCount": len(restart_history),
            "maxRestarts": MAX_RESTARTS_PER_WINDOW,
        }
    if last_restart and now_s - last_restart < RESTART_COOLDOWN_SECONDS:
        return {
            "actionId": action_id,
            "ts": ts(),
            "tsEpoch": now_s,
            "source": "cat-agents-stabilityd",
            "component": "hermers",
            "action": "restart_hermers_gateway",
            "result": "cooldown_skip",
            "profile": profile,
            "unit": unit,
            "reason": reason,
            "cooldownUntilEpoch": last_restart + RESTART_COOLDOWN_SECONDS,
        }
    started = time.time()
    try:
        proc = run_hermes_profile_gateway_cmd(profile, "restart", timeout=60)
        duration = int((time.time() - started) * 1000)
        result = "ok" if proc.returncode == 0 else "failed"
        payload = {
            "actionId": action_id,
            "ts": ts(),
            "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd",
            "component": "hermers",
            "action": "restart_hermers_gateway",
            "result": result,
            "profile": profile,
            "unit": unit,
            "reason": reason,
            "operation": "hermes-gateway-restart",
            "adapter": "hermes-cli",
            "command": [HERMES_CLI, "-p", profile, "gateway", "restart"],
            "exitCode": proc.returncode,
            "durationMs": duration,
            "stderr": proc.stderr[-1200:],
        }
        if proc.returncode == 0:
            db_set(conn, last_key, epoch())
            record_hermers_gateway_restart_time(conn, profile)
        return payload
    except Exception as exc:
        return {
            "actionId": action_id,
            "ts": ts(),
            "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd",
            "component": "hermers",
            "action": "restart_hermers_gateway",
            "result": "failed",
            "profile": profile,
            "unit": unit,
            "reason": reason,
            "exitCode": -1,
            "error": f"{type(exc).__name__}: {exc}",
        }


def resource_trigger_keys(snapshot: Dict[str, Any]) -> List[str]:
    findings = snapshot.get("findings") if isinstance(snapshot.get("findings"), list) else []
    keys = {str(item.get("key")) for item in findings if isinstance(item, dict)}
    triggers = set(keys & RESOURCE_PRESSURE_KEYS)
    triggers.update(keys & {"gateway_service_down", "gateway_port_down", "gateway_health_endpoint_failed"})
    return sorted(triggers)


def capture_resource_evidence(snapshot: Dict[str, Any], policy: Dict[str, Any], trigger_keys: List[str]) -> Dict[str, Any]:
    stamp = time.strftime("%Y%m%dT%H%M%S%z")
    evidence_path = RESOURCE_EVIDENCE_DIR / f"resource-evidence-{stamp}.json"
    latest_path = RESOURCE_EVIDENCE_DIR / "latest.json"
    probes = {
        "date": command_probe(["date", "-Is"], timeout=3, max_chars=2_000),
        "loadavg": command_probe(["cat", "/proc/loadavg"], timeout=3, max_chars=2_000),
        "meminfo": command_probe(["cat", "/proc/meminfo"], timeout=3, max_chars=8_000),
        "memoryPressure": command_probe(["cat", "/proc/pressure/memory"], timeout=3, max_chars=4_000),
        "free": command_probe(["free", "-h"], timeout=3, max_chars=4_000),
        "gatewayService": command_probe(
            [
                "systemctl",
                "show",
                "openclaw-gateway.service",
                "--property=MainPID,ExecMainStartTimestamp,MemoryCurrent,MemoryPeak,CPUUsageNSec,TasksCurrent,NRestarts,ActiveState,SubState",
            ],
            timeout=5,
            max_chars=6_000,
        ),
        "journaldAndSnapd": command_probe(
            [
                "systemctl",
                "show",
                "systemd-journald.service",
                "snapd.service",
                "--property=Id,MainPID,ExecMainStartTimestamp,MemoryCurrent,MemoryPeak,CPUUsageNSec,TasksCurrent,NRestarts,ActiveState,SubState",
            ],
            timeout=5,
            max_chars=8_000,
        ),
        "topMem": command_probe(["bash", "-lc", "ps aux --sort=-%mem | head -40"], timeout=5, max_chars=12_000),
        "topCpu": command_probe(["bash", "-lc", "ps aux --sort=-%cpu | head -40"], timeout=5, max_chars=12_000),
        "recentKernelMemory": command_probe(
            ["bash", "-lc", "journalctl -k --since '-30 min' --no-pager | grep -Ei 'memory pressure|oom|Out of memory|Killed process|watchdog' | tail -120"],
            timeout=5,
            max_chars=16_000,
        ),
    }
    payload = {
        "schemaVersion": 1,
        "capturedAt": ts(),
        "capturedAtEpoch": epoch(),
        "source": "cat-agents-stabilityd",
        "triggerKeys": trigger_keys,
        "policyMode": policy.get("mode"),
        "policySeverity": policy.get("severity"),
        "policyReasons": policy.get("reasons") or [],
        "gateway": snapshot.get("gateway") or {},
        "resource": snapshot.get("resource") or {},
        "trends": snapshot.get("trends") or {},
        "topFindings": (snapshot.get("findings") or [])[:20],
        "probes": probes,
    }
    write_json_atomic(evidence_path, payload)
    write_json_atomic(latest_path, payload)
    return {"path": str(evidence_path), "latestPath": str(latest_path), "payload": payload}


def render_resource_human_gate_md(payload: Dict[str, Any]) -> str:
    evidence = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
    gateway = payload.get("gateway") if isinstance(payload.get("gateway"), dict) else {}
    resource = payload.get("resource") if isinstance(payload.get("resource"), dict) else {}
    memory = resource.get("memory") if isinstance(resource.get("memory"), dict) else {}
    trigger_keys = ", ".join(payload.get("triggerKeys") or []) or "none"
    options = payload.get("options") if isinstance(payload.get("options"), list) else []
    lines = [
        "# Gateway Resource Human Gate Package",
        "",
        f"- generatedAt: {payload.get('generatedAt')}",
        f"- severity: {payload.get('severity')}",
        f"- mode: {payload.get('mode')}",
        f"- triggerKeys: {trigger_keys}",
        f"- evidencePath: {evidence.get('path')}",
        "",
        "## Current Resource Facts",
        f"- gatewayMemoryBytes: {gateway.get('memoryBytes')}",
        f"- gatewaySwapBytes: {gateway.get('swapBytes')}",
        f"- systemMemAvailableBytes: {memory.get('memAvailableBytes')}",
        f"- systemSwapUsedBytes: {memory.get('swapUsedBytes')}",
        f"- systemSwapUsedRatio: {memory.get('swapUsedRatio')}",
        f"- systemCommitRatio: {memory.get('commitRatio')}",
        "",
        "## Human Gate Options",
    ]
    for item in options:
        lines.extend(
            [
                f"### {item.get('label')}",
                f"- decisionId: {item.get('decisionId')}",
                f"- action: {item.get('action')}",
                f"- boundary: {item.get('boundary')}",
                f"- rollback: {item.get('rollback')}",
                "",
            ]
        )
    lines.extend(
        [
            "## Secretary Notes",
            "- 本包只准备 Human Gate 证据，不自动重启 Gateway。",
            "- 猫之脑应结合最新 workflow readiness、dispatch/receipt 和 Gateway health 判断是否提交给猫爪。",
            "- 猫爪提交给闪电猫时必须保留三套以上可批准方案，并等待闪电猫原话确认。",
            "",
        ]
    )
    return "\n".join(lines)


def write_resource_human_gate_package(
    snapshot: Dict[str, Any],
    policy: Dict[str, Any],
    trigger_keys: List[str],
    evidence: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    evidence_meta = evidence or {}
    payload = {
        "schemaVersion": 1,
        "generatedAt": ts(),
        "generatedAtEpoch": epoch(),
        "source": "cat-agents-stabilityd",
        "status": "pending_human_gate",
        "severity": policy.get("severity"),
        "mode": policy.get("mode"),
        "triggerKeys": trigger_keys,
        "restartCandidate": bool(policy.get("restartCandidate")),
        "restartBlockedReasons": policy.get("restartBlockedReasons") or [],
        "gateway": snapshot.get("gateway") or {},
        "resource": snapshot.get("resource") or {},
        "trends": snapshot.get("trends") or {},
        "evidence": {
            "path": evidence_meta.get("path"),
            "latestPath": evidence_meta.get("latestPath"),
        },
        "options": [
            {
                "decisionId": "A",
                "label": "A. 受控重启 Gateway",
                "action": "在保留当前证据、确认 active checkout 和回滚分支后，由闪电猫批准一次手工 Gateway restart，并做 health/readiness/smoke 复核。",
                "boundary": "只重启 OpenClaw Gateway，不改模型路由、不改 profile、不改交易相关状态。",
                "rollback": "如重启后 Gateway health/readiness 或 workflow smoke 失败，回到最近确认可用 checkout 或暂停 workflow 派发。",
            },
            {
                "decisionId": "B",
                "label": "B. 降载观察",
                "action": "暂停非关键 cron 和重报告，保留心跳与直接控制面，持续采集资源快照，等待内存/Swap 回落。",
                "boundary": "不重启、不删除、不迁移，只做 admission/backpressure 和证据采集。",
                "rollback": "若 swap 或 memory pressure 继续恶化，升级到方案 A 或 C。",
            },
            {
                "decisionId": "C",
                "label": "C. 暂停变更并回退候选代码",
                "action": "冻结新 workflow/plugin 变更，必要时将 active checkout 回到已登记 rollback 分支，再重新评估 Gateway 内存趋势。",
                "boundary": "只处理代码版本风险，不触碰生产交易、账号、密钥或业务数据。",
                "rollback": "如回退后问题仍存在，说明根因更偏长期 Gateway/运行态内存膨胀，应转入 A 或容量治理。",
            },
        ],
        "pauseOption": {
            "label": "暂停工作流",
            "action": "暂停本轮资源处置工作流，继续只读观察。",
        },
        "terminateOption": {
            "label": "终止工作流",
            "action": "认为当前资源 incident 已收口，归档证据并停止升级。",
        },
    }
    json_path = RESOURCE_HUMAN_GATE_DIR / "gateway-resource-pressure-latest.json"
    md_path = RESOURCE_HUMAN_GATE_DIR / "gateway-resource-pressure-latest.md"
    write_json_atomic(json_path, payload)
    md_path.write_text(render_resource_human_gate_md(payload), encoding="utf-8")
    write_json_atomic(RESOURCE_INCIDENT_LATEST, payload)
    return {
        "jsonPath": str(json_path),
        "markdownPath": str(md_path),
        "incidentPath": str(RESOURCE_INCIDENT_LATEST),
    }


def resource_actuate(conn: sqlite3.Connection, snapshot: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    trigger_keys = resource_trigger_keys(snapshot)
    if not trigger_keys:
        return actions
    now_s = epoch()
    last_capture = int(db_get(conn, "resource_evidence_last_capture_at", 0) or 0)
    capture_due = not last_capture or now_s - last_capture >= RESOURCE_EVIDENCE_CAPTURE_SECONDS
    incident_active = "gateway_resource_incident" in trigger_keys or bool(RESOURCE_INCIDENT_IMMEDIATE_KEYS & set(trigger_keys))
    evidence_meta: Optional[Dict[str, Any]] = None
    if capture_due:
        evidence = capture_resource_evidence(snapshot, policy, trigger_keys)
        evidence_meta = {k: v for k, v in evidence.items() if k != "payload"}
        db_set(conn, "resource_evidence_last_capture_at", now_s)
        actions.append(
            {
                "action": "capture_resource_evidence",
                "result": "ok",
                "triggerKeys": trigger_keys,
                "resourceEvidencePath": evidence_meta.get("path"),
                "resourceEvidenceLatestPath": evidence_meta.get("latestPath"),
            }
        )
    elif (RESOURCE_EVIDENCE_DIR / "latest.json").exists():
        evidence_meta = {
            "path": str(RESOURCE_EVIDENCE_DIR / "latest.json"),
            "latestPath": str(RESOURCE_EVIDENCE_DIR / "latest.json"),
        }
    if incident_active:
        last_gate = int(db_get(conn, "resource_human_gate_last_prepare_at", 0) or 0)
        if not last_gate or now_s - last_gate >= RESOURCE_HUMAN_GATE_REFRESH_SECONDS:
            package = write_resource_human_gate_package(snapshot, policy, trigger_keys, evidence_meta)
            db_set(conn, "resource_human_gate_last_prepare_at", now_s)
            actions.append(
                {
                    "action": "prepare_resource_human_gate",
                    "result": "ok",
                    "triggerKeys": trigger_keys,
                    "requiresHumanGate": True,
                    **package,
                }
            )
    return actions


def hermers_profile_mode_actuate(conn: sqlite3.Connection, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    if not HERMERS_PROFILE_MODE_ENABLED or not HERMERS_PROFILE_MODE_ACTUATE_ENABLED:
        return actions
    hermers = snapshot.get("hermers") if isinstance(snapshot.get("hermers"), dict) else {}
    modes = hermers.get("profileModes") if isinstance(hermers.get("profileModes"), dict) else {}
    profiles = modes.get("profiles") if isinstance(modes.get("profiles"), dict) else {}
    now_s = epoch()
    for profile, item in profiles.items():
        if not isinstance(item, dict):
            continue
        if item.get("protected") or not item.get("managed"):
            continue
        if item.get("activeWork"):
            continue
        target_mode = str(item.get("targetMode") or item.get("observedMode") or "warm")
        active = bool(item.get("active"))
        unit = str(item.get("unit") or f"hermes-gateway-{profile}.service")
        expected_unit = f"hermes-gateway-{profile}.service"
        if unit != expected_unit:
            actions.append(
                {
                    "action": "set_hermers_profile_mode",
                    "result": "blocked",
                    "profile": profile,
                    "unit": unit,
                    "targetMode": target_mode,
                    "blockedReason": "unit-profile-mismatch",
                    "expectedUnit": expected_unit,
                }
            )
            continue
        action_key = f"hermers_profile_mode:{profile}:{target_mode}"
        last_action = int(db_get(conn, action_key, 0) or 0)
        if last_action and now_s - last_action < HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS:
            continue
        if target_mode == "hibernate" and active:
            if not item.get("safeToHibernate"):
                actions.append(
                    {
                        "action": "set_hermers_profile_mode",
                        "result": "blocked",
                        "profile": profile,
                        "unit": unit,
                        "targetMode": target_mode,
                        "reason": item.get("reason"),
                        "blockedReason": item.get("safeToHibernateReason") or "runtime-safe-to-hibernate-missing",
                    }
                )
                continue
            started = time.time()
            try:
                proc = run_hermes_profile_gateway_cmd(profile, "stop", timeout=30)
                duration_ms = int((time.time() - started) * 1000)
                result = "ok" if proc.returncode == 0 else "failed"
                actions.append(
                    {
                        "action": "set_hermers_profile_mode",
                        "result": result,
                        "profile": profile,
                        "unit": unit,
                        "targetMode": target_mode,
                        "reason": item.get("reason"),
                        "idleSeconds": item.get("idleSeconds"),
                        "operation": "hermes-gateway-stop",
                        "adapter": "hermes-cli",
                        "command": [HERMES_CLI, "-p", profile, "gateway", "stop"],
                        "exitCode": proc.returncode,
                        "durationMs": duration_ms,
                        "stderr": proc.stderr[-1200:],
                    }
                )
                db_set(conn, action_key, now_s)
                if proc.returncode == 0:
                    db_set(
                        conn,
                        f"hermers_profile_mode:planned:{profile}",
                        {
                            "profile": profile,
                            "targetMode": target_mode,
                            "unit": unit,
                            "reason": item.get("reason"),
                            "setAt": ts(),
                            "setAtEpoch": now_s,
                            "source": "cat-agents-stabilityd",
                        },
                    )
            except Exception as exc:
                db_set(conn, action_key, now_s)
                actions.append(
                    {
                        "action": "set_hermers_profile_mode",
                        "result": "failed",
                        "profile": profile,
                        "unit": unit,
                        "targetMode": target_mode,
                        "reason": item.get("reason"),
                        "operation": "hermes-gateway-stop",
                        "adapter": "hermes-cli",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
        elif target_mode == "hot" and not active and HERMERS_PROFILE_MODE_START_ENABLED:
            started = time.time()
            try:
                proc = run_hermes_profile_gateway_cmd(profile, "start", timeout=30)
                duration_ms = int((time.time() - started) * 1000)
                result = "ok" if proc.returncode == 0 else "failed"
                actions.append(
                    {
                        "action": "set_hermers_profile_mode",
                        "result": result,
                        "profile": profile,
                        "unit": unit,
                        "targetMode": target_mode,
                        "reason": item.get("reason"),
                        "operation": "hermes-gateway-start",
                        "adapter": "hermes-cli",
                        "command": [HERMES_CLI, "-p", profile, "gateway", "start"],
                        "exitCode": proc.returncode,
                        "durationMs": duration_ms,
                        "stderr": proc.stderr[-1200:],
                    }
                )
                db_set(conn, action_key, now_s)
            except Exception as exc:
                db_set(conn, action_key, now_s)
                actions.append(
                    {
                        "action": "set_hermers_profile_mode",
                        "result": "failed",
                        "profile": profile,
                        "unit": unit,
                        "targetMode": target_mode,
                        "reason": item.get("reason"),
                        "operation": "hermes-gateway-start",
                        "adapter": "hermes-cli",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
    return actions


def verify_hermers_orphan_worker(pid: int, profile: str, rows: List[Dict[str, str]]) -> Tuple[bool, str]:
    current = None
    for row in rows:
        try:
            row_pid = int(row.get("pid") or 0)
        except Exception:
            row_pid = 0
        if row_pid == pid:
            current = row
            break
    if not current:
        return False, "pid-not-found"
    cmd = current.get("cmd", "")
    if "/hermes" not in cmd or " acp" not in cmd or "--accept-hooks" not in cmd:
        return False, "cmd-not-hermers-acp"
    if profile and f" -p {profile} " not in cmd and f"--profile {profile}" not in cmd:
        return False, "profile-mismatch"
    try:
        ppid = int(current.get("ppid") or 0)
    except Exception:
        ppid = 0
    if ppid > 1:
        return False, "worker-has-live-parent"
    return True, "verified-orphan"


def verify_hermers_idle_lsp(pid: int, profile: str, item: Dict[str, Any], rows: List[Dict[str, str]]) -> Tuple[bool, str]:
    current = None
    for row in rows:
        try:
            row_pid = int(row.get("pid") or 0)
        except Exception:
            row_pid = 0
        if row_pid == pid:
            current = row
            break
    if not current:
        return False, "pid-not-found"
    cmd = proc_cmdline(pid) or current.get("cmd", "")
    if "pyright-langserver" not in cmd or "--stdio" not in cmd:
        return False, "cmd-not-pyright-lsp"
    if f"/.hermes/profiles/{profile}/lsp/" not in cmd:
        return False, "profile-path-mismatch"
    try:
        ppid = int(current.get("ppid") or 0)
    except Exception:
        ppid = 0
    if ppid <= 1:
        return False, "missing-live-hermers-parent"
    parent_cmd = proc_cmdline(ppid)
    if not parent_cmd:
        for row in rows:
            if str(row.get("pid") or "") == str(ppid):
                parent_cmd = row.get("cmd", "")
                break
    if "hermes_cli.main" not in parent_cmd or f"--profile {profile}" not in parent_cmd or "gateway run" not in parent_cmd:
        return False, "parent-not-profile-gateway"
    if int(item.get("ageSeconds") or 0) < HERMERS_LSP_IDLE_SECONDS:
        return False, "process-younger-than-idle-threshold"
    if int(item.get("idleObservedSeconds") or 0) < HERMERS_LSP_IDLE_SECONDS:
        return False, "idle-observation-below-threshold"
    try:
        expected_ticks = int(item.get("cpuTicks"))
    except Exception:
        return False, "missing-cpu-baseline"
    if expected_ticks < 0:
        return False, "missing-cpu-baseline"
    current_ticks = proc_cpu_ticks(pid)
    if current_ticks != expected_ticks:
        return False, "cpu-advanced-after-snapshot"
    return True, "verified-idle-lsp"


def hermers_actuate(conn: sqlite3.Connection, snapshot: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    hermers = snapshot.get("hermers") if isinstance(snapshot.get("hermers"), dict) else {}
    workers = hermers.get("orphanAcpWorkers") if isinstance(hermers.get("orphanAcpWorkers"), list) else []
    if workers and policy.get("canReapHermersOrphanWorkers"):
        killed = []
        current_rows = ps_rows()
        for item in workers[:20]:
            try:
                pid = int(item.get("pid") or 0)
            except Exception:
                pid = 0
            if pid <= 1:
                continue
            profile = str(item.get("profile") or "")
            verified, verify_reason = verify_hermers_orphan_worker(pid, profile, current_rows)
            if not verified:
                killed.append({"pid": pid, "profile": profile, "result": "blocked", "reason": verify_reason})
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                killed.append({"pid": pid, "profile": profile, "ageSeconds": item.get("ageSeconds"), "signal": "SIGTERM", "verified": verify_reason})
            except ProcessLookupError:
                killed.append({"pid": pid, "profile": profile, "result": "already_exited"})
            except Exception as exc:
                killed.append({"pid": pid, "profile": profile, "result": "failed", "error": f"{type(exc).__name__}: {exc}"})
        if killed:
            actions.append({"action": "reap_hermers_acp_orphan_workers", "result": "ok", "workers": killed})
    elif workers:
        actions.append(
            {
                "action": "observe_hermers_acp_orphan_workers",
                "result": "reap_blocked_by_policy",
                "workers": workers[:20],
            }
        )
    idle_lsps = hermers.get("idleLspProcesses") if isinstance(hermers.get("idleLspProcesses"), list) else []
    if idle_lsps and policy.get("canReapHermersIdleLsp"):
        reaped = []
        current_rows = ps_rows()
        for item in idle_lsps[:20]:
            try:
                pid = int(item.get("pid") or 0)
            except Exception:
                pid = 0
            if pid <= 1:
                continue
            profile = str(item.get("profile") or "")
            verified, verify_reason = verify_hermers_idle_lsp(pid, profile, item, current_rows)
            if not verified:
                reaped.append({"pid": pid, "profile": profile, "result": "blocked", "reason": verify_reason})
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                reaped.append(
                    {
                        "pid": pid,
                        "profile": profile,
                        "processType": item.get("processType") or "pyright-langserver",
                        "ageSeconds": item.get("ageSeconds"),
                        "idleObservedSeconds": item.get("idleObservedSeconds"),
                        "rssBytes": item.get("rssBytes"),
                        "signal": "SIGTERM",
                        "verified": verify_reason,
                    }
                )
            except ProcessLookupError:
                reaped.append({"pid": pid, "profile": profile, "result": "already_exited"})
            except Exception as exc:
                reaped.append({"pid": pid, "profile": profile, "result": "failed", "error": f"{type(exc).__name__}: {exc}"})
        if reaped:
            actions.append({"action": "reap_hermers_idle_lsp_processes", "result": "ok", "processes": reaped})
    elif idle_lsps:
        actions.append(
            {
                "action": "observe_hermers_idle_lsp_processes",
                "result": "reap_blocked_by_policy",
                "processes": idle_lsps[:20],
            }
        )
    actions.extend(hermers_profile_mode_actuate(conn, snapshot))
    profiles = hermers.get("profiles") if isinstance(hermers.get("profiles"), dict) else {}
    modes = ((hermers.get("profileModes") or {}).get("profiles") or {}) if isinstance(hermers.get("profileModes"), dict) else {}
    down_profiles = [
        {"profile": profile, "unit": str((item or {}).get("unit") or f"hermes-gateway-{profile}.service")}
        for profile, item in profiles.items()
        if isinstance(item, dict) and not bool(item.get("active"))
        and bool((modes.get(profile) or {}).get("expectedActive", True))
    ]
    restart_profiles = policy.get("hermersGatewayRestartProfiles") if isinstance(policy.get("hermersGatewayRestartProfiles"), list) else []
    if restart_profiles and policy.get("canRestartHermersGateway"):
        for item in restart_profiles:
            actions.append(
                hermers_gateway_restart(
                    conn,
                    str(item.get("profile") or ""),
                    str(item.get("unit") or ""),
                    str(policy.get("hermersGatewayRestartReason") or "hermers-gateway-service-down"),
                )
            )
        if len(down_profiles) > len(restart_profiles):
            actions.append(
                {
                    "action": "restart_hermers_gateway",
                    "result": "limit_skip",
                    "reason": "restart-limit-per-loop",
                    "candidateCount": len(down_profiles),
                    "limit": len(restart_profiles),
                }
            )
    elif down_profiles:
        actions.append(
            {
                "action": "observe_hermers_gateway_restart_candidate",
                "result": "restart_actuator_blocked",
                "candidateCount": len(down_profiles),
                "candidate": bool(policy.get("hermersGatewayRestartCandidate")),
                "blockedReasons": policy.get("hermersGatewayRestartBlockedReasons") or [],
                "sample": down_profiles[:10],
            }
        )
    return actions


def actuate(conn: sqlite3.Connection, snapshot: Dict[str, Any], policy: Dict[str, Any], no_action: bool = False) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    if no_action:
        return [{"action": "none", "result": "dry_run", "reason": "no_action"}]
    for action in resource_actuate(conn, snapshot, policy):
        action.update({"actionId": f"{action['action']}-{int(time.time() * 1000)}", "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd", "component": "resource"})
        actions.append(action)
    for action in cron_actuate(snapshot, policy):
        action.update({"actionId": f"{action['action']}-{int(time.time() * 1000)}", "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd", "component": "cron"})
        actions.append(action)
    for action in session_actuate(conn, snapshot, policy):
        action.update({"actionId": f"{action['action']}-{int(time.time() * 1000)}", "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd", "component": "session"})
        actions.append(action)
    for action in hermers_actuate(conn, snapshot, policy):
        action.update({"actionId": f"{action['action']}-{int(time.time() * 1000)}", "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd", "component": "hermers"})
        actions.append(action)
    if policy.get("canRestartGateway"):
        actions.append(gateway_restart(conn, str(policy.get("restartReason") or "policy")))
    elif policy.get("restartCandidate"):
        actions.append(
            {
                "action": "observe_gateway_restart_candidate",
                "result": "restart_actuator_blocked",
                "reason": str(policy.get("restartReason") or "policy"),
                "blockedReasons": policy.get("restartBlockedReasons") or [],
            }
        )
    return actions or [{"action": "none", "result": "ok", "reason": policy.get("restartReason") or "no-action"}]


def write_legacy_watchdog_health(snapshot: Dict[str, Any], policy: Dict[str, Any]) -> None:
    gateway = snapshot.get("gateway") or {}
    control_plane = snapshot.get("controlPlane") or {}
    payload = {
        "updatedAt": policy.get("updatedAt"),
        "updatedAtEpoch": policy.get("updatedAtEpoch"),
        "mode": policy.get("mode"),
        "reason": ",".join(policy.get("reasons") or []) or policy.get("restartReason") or policy.get("mode"),
        "needsRestart": bool(policy.get("canRestartGateway")),
        "restartAllowed": bool(policy.get("canRestartGateway")),
        "recentRestarts": policy.get("recentRestartCount"),
        "lastRestartAtEpoch": int(policy.get("cooldownUntilEpoch") or 0) - RESTART_COOLDOWN_SECONDS if policy.get("cooldownUntilEpoch") else 0,
        "restartWindowSeconds": RESTART_WINDOW_SECONDS,
        "maxRestarts": MAX_RESTARTS_PER_WINDOW,
        "startupGraceSeconds": STARTUP_GRACE_SECONDS,
        "startupGraceActive": bool(gateway.get("startupGraceActive")),
        "isRunning": bool(gateway.get("active")),
        "hasListener": bool(gateway.get("portOk")),
        "tcpProbeOk": bool(gateway.get("portOk")),
        "healthOk": bool(gateway.get("healthOk")),
        "errorStorm": "gateway_congestion_logs" in set(policy.get("reasons") or []),
        "laneCongested": "gateway_congestion_logs" in set(policy.get("reasons") or []),
        "wsUnstable": "gateway_ws_instability" in set(policy.get("reasons") or []),
        "canMutateCronState": bool(policy.get("canMutateCronState")),
        "canRunBulkJobs": bool(policy.get("canRunBulkCron")),
        "shouldPauseCron": bool(policy.get("shouldPauseNonCriticalCron")),
        "deferControlPlaneHeavyReports": bool(policy.get("deferControlPlaneHeavyReports")),
        "controlPlaneBackpressureUntilEpoch": int(policy.get("controlPlaneBackpressureUntilEpoch") or 0),
        "controlPlaneBackpressureActive": bool(control_plane.get("active")),
        "source": "cat-agents-stabilityd",
    }
    write_json_atomic(LEGACY_WATCHDOG_HEALTH, payload)


def collect_snapshot(conn: sqlite3.Connection) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    snapshot: Dict[str, Any] = {
        "schemaVersion": 1,
        "checkedAt": ts(),
        "checkedAtEpoch": epoch(),
    }
    snapshot["gateway"] = gateway_collect(findings)
    snapshot["cron"] = cron_collect(findings)
    snapshot["session"] = session_collect(findings)
    snapshot["channel"] = channel_collect(findings)
    snapshot["hermers"] = hermers_collect(conn, findings)
    snapshot["resource"] = resource_collect(findings)
    snapshot["config"] = config_collect(findings)
    snapshot["desiredState"] = desired_state_drift()
    for drift in snapshot["desiredState"].get("drifts") or []:
        add_finding(
            findings,
            str(drift.get("key") or "desired_state_drift"),
            str(drift.get("severity") or "warning"),
            "desired-state",
            str(drift.get("message") or "Desired state drift detected"),
            evidence={k: v for k, v in drift.items() if k not in {"key", "severity", "component", "message"}},
        )
    snapshot["trends"] = update_runtime_trends(conn, snapshot, findings)
    streaks = update_streaks(conn, findings)
    add_resource_governance_findings(findings, snapshot, streaks)
    findings.sort(key=lambda item: (-SEVERITY_RANK.get(str(item.get("severity")), 0), str(item.get("component")), str(item.get("key"))))
    snapshot["findings"] = findings
    snapshot["severity"] = max_severity(findings)
    snapshot["streaks"] = streaks
    policy = policy_from_findings(conn, findings, snapshot, streaks)
    snapshot["policy"] = policy
    return snapshot, findings, policy


def run_once(conn: sqlite3.Connection, no_action: bool = False) -> Dict[str, Any]:
    ensure_dirs()
    snapshot, findings, policy = collect_snapshot(conn)
    snapshot["controlPlane"] = control_plane_backpressure(snapshot, policy)
    actions = actuate(conn, snapshot, policy, no_action=no_action)
    snapshot["actions"] = actions
    snapshot["completedAt"] = ts()
    snapshot["completedAtEpoch"] = epoch()
    write_json_atomic(POLICY_PATH, policy)
    write_json_atomic(LATEST_PATH, snapshot)
    write_json_atomic(LANE_POLICY_PATH, policy.get("lanes") or {})
    write_json_atomic(HERMERS_PROFILE_MODES_PATH, ((snapshot.get("hermers") or {}).get("profileModes") or {}))
    write_json_atomic(CONTROL_PLANE_BACKPRESSURE_PATH, snapshot["controlPlane"])
    snapshot["workflowEvidence"] = write_workflow_stability_evidence(snapshot)
    write_legacy_watchdog_health(snapshot, policy)
    for finding in findings:
        if SEVERITY_RANK.get(str(finding.get("severity")), 0) >= SEVERITY_RANK["high"]:
            event_key = f"event:{finding.get('key')}"
            last_event_at = int(db_get(conn, event_key, 0) or 0)
            if last_event_at and snapshot["checkedAtEpoch"] - last_event_at < 300:
                continue
            event = {
                "ts": snapshot["checkedAt"],
                "tsEpoch": snapshot["checkedAtEpoch"],
                "source": "cat-agents-stabilityd",
                "component": finding.get("component"),
                "severity": finding.get("severity"),
                "key": finding.get("key"),
                "message": finding.get("message"),
                "policyMode": policy.get("mode"),
                "evidence": {k: v for k, v in finding.items() if k not in {"key", "severity", "component", "message"}},
            }
            db_record_event(conn, event)
            db_set(conn, event_key, snapshot["checkedAtEpoch"])
    for action in actions:
        db_record_action(conn, action)
    log_line(
        "severity={} mode={} findings={} actions={}".format(
            snapshot.get("severity"),
            policy.get("mode"),
            len(findings),
            ",".join(str(a.get("action")) for a in actions),
        )
    )
    return snapshot


class StopSignal(Exception):
    pass


def daemon_loop(no_action: bool = False) -> int:
    ensure_dirs()
    lock_fh = LOCK_PATH.open("a+", encoding="utf-8")
    try:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            print("cat-agents-stabilityd is already running", file=sys.stderr)
            return 1
        raise

    stopping = {"value": False}

    def handle_signal(_signum: int, _frame: Any) -> None:
        stopping["value"] = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    conn = init_db()
    log_line(f"daemon started interval={INTERVAL_SECONDS}s no_action={no_action}")
    while not stopping["value"]:
        started = time.time()
        try:
            run_once(conn, no_action=no_action)
        except Exception as exc:
            err = {
                "ts": ts(),
                "tsEpoch": epoch(),
                "source": "cat-agents-stabilityd",
                "component": "daemon",
                "severity": "critical",
                "key": "stabilityd_loop_error",
                "message": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc()[-4000:],
            }
            db_record_event(conn, err)
            log_line(f"loop_error {type(exc).__name__}: {exc}")
        elapsed = time.time() - started
        sleep_for = max(1, INTERVAL_SECONDS - elapsed)
        end = time.time() + sleep_for
        while time.time() < end and not stopping["value"]:
            time.sleep(min(1, end - time.time()))
    log_line("daemon stopped")
    return 0


def read_json_or_empty(path: Path) -> Any:
    return load_json(path, {})


def print_json(payload: Any) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def tail_jsonl(path: Path, limit: int = 20) -> List[Any]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except Exception:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except Exception:
            out.append({"raw": line})
    return out


def runbook() -> Dict[str, Any]:
    latest = load_json(LATEST_PATH, {}) or {}
    policy = load_json(POLICY_PATH, {}) or {}
    lanes = load_json(LANE_POLICY_PATH, {}) or policy.get("lanes") or {}
    findings = latest.get("findings") or []
    commands = [
        "systemctl status cat-agents-stabilityd.service --no-pager",
        "systemctl status openclaw-gateway.service --no-pager",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability status",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability lanes",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability findings",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability drift",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability actions --limit 20",
        "tail -n 100 /home/flashcat/.openclaw/stability/events.jsonl",
    ]
    if policy.get("mode") == "restart-storm":
        commands.insert(0, "systemctl cat cat-agents-stabilityd.service")
    return {
        "generatedAt": ts(),
        "mode": policy.get("mode"),
        "severity": policy.get("severity"),
        "policy": policy,
        "lanes": lanes,
        "topFindings": findings[:10],
        "recommendedCommands": commands,
        "rollback": [
            "pause cat-agents-stabilityd evidence consumption if it is producing misleading findings",
            "keep legacy gateway/cron/session controllers disabled unless Flashcat explicitly approves a documented rollback",
            "route runtime-state repair through the owning OpenClaw/Hermers runtime adapter or an explicit operator action",
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Cat agents stability control plane")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("daemon")
    once_p = sub.add_parser("once")
    once_p.add_argument("--no-action", action="store_true")
    sub.add_parser("status")
    sub.add_parser("snapshot")
    sub.add_parser("policy")
    sub.add_parser("lanes")
    sub.add_parser("profile-modes")
    sub.add_parser("desired-state")
    sub.add_parser("drift")
    sub.add_parser("findings")
    evidence_p = sub.add_parser("workflow-evidence")
    evidence_p.add_argument("--no-write", action="store_true")
    actions_p = sub.add_parser("actions")
    actions_p.add_argument("--limit", type=int, default=20)
    sub.add_parser("events")
    sub.add_parser("runbook")
    doctor_p = sub.add_parser("doctor")
    doctor_p.add_argument("--no-action", action="store_true")
    repair_p = sub.add_parser("repair")
    repair_p.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    cmd = args.cmd or "status"
    if cmd == "daemon":
        return daemon_loop(no_action=False)
    if cmd == "once":
        conn = init_db()
        return print_json(run_once(conn, no_action=args.no_action))
    if cmd == "status":
        latest = load_json(LATEST_PATH, {}) or {}
        policy = load_json(POLICY_PATH, {}) or {}
        return print_json(
            {
                "checkedAt": latest.get("checkedAt"),
                "completedAt": latest.get("completedAt"),
                "severity": latest.get("severity"),
                "mode": policy.get("mode"),
                "policyAgeSeconds": file_age_seconds(POLICY_PATH),
                "findingCount": len(latest.get("findings") or []),
                "lastActions": latest.get("actions"),
            }
        )
    if cmd == "snapshot":
        return print_json(read_json_or_empty(LATEST_PATH))
    if cmd == "policy":
        return print_json(read_json_or_empty(POLICY_PATH))
    if cmd == "lanes":
        lanes = load_json(LANE_POLICY_PATH, {}) or (load_json(POLICY_PATH, {}) or {}).get("lanes") or {}
        return print_json(lanes)
    if cmd == "profile-modes":
        return print_json(read_json_or_empty(HERMERS_PROFILE_MODES_PATH))
    if cmd == "desired-state":
        return print_json(load_desired_state())
    if cmd == "drift":
        return print_json(desired_state_drift())
    if cmd == "findings":
        latest = load_json(LATEST_PATH, {}) or {}
        return print_json(latest.get("findings") or [])
    if cmd == "workflow-evidence":
        evidence = build_workflow_stability_evidence()
        if not args.no_write:
            evidence = write_workflow_stability_evidence()
        return print_json(evidence)
    if cmd == "actions":
        return print_json(tail_jsonl(ACTIONS_JSONL, limit=args.limit))
    if cmd == "events":
        return print_json(tail_jsonl(EVENTS_JSONL, limit=50))
    if cmd == "runbook":
        return print_json(runbook())
    if cmd == "doctor":
        conn = init_db()
        snap = run_once(conn, no_action=args.no_action)
        return print_json({"severity": snap.get("severity"), "policy": snap.get("policy"), "findings": snap.get("findings"), "actions": snap.get("actions")})
    if cmd == "repair":
        conn = init_db()
        snap = run_once(conn, no_action=args.dry_run)
        return print_json({"dryRun": args.dry_run, "actions": snap.get("actions"), "policy": snap.get("policy")})
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
