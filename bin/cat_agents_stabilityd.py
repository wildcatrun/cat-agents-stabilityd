#!/usr/bin/env python3
"""Cat agents stability control plane.

This daemon replaces independent watchdog/guard/controller scripts with a
single policy engine and actuator surface for the OpenClaw cloud runtime.
It intentionally uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import datetime as dt
import errno
import ctypes
import fcntl
import glob
import hashlib
import json
import math
import os
import platform
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

_CODE_ROOT = Path(__file__).resolve().parents[1]
if str(_CODE_ROOT) not in sys.path:
    sys.path.insert(0, str(_CODE_ROOT))
from stability_core.actuation_lock import ActuationBusy, ActuationLock
from stability_core.process_identity import identities_match, read_process_identity, terminate_process_instance
from stability_core.probe_runner import run_component_probe
from stability_core.protected_scope import is_protected_identity, resolve_protection_scope
from stability_core.generation import artifact_metadata, publish_generation, write_json_atomic, write_text_atomic
from stability_core.redaction import redact_sensitive_text, safe_error_category
from stability_core.node_inventory import evaluate_inventory
from stability_core.surface_contracts import evaluate_surface_observations
from stability_core.config import (
    RUNTIME_INTEGER_DEFAULTS,
    parse_actuator_environment_settings, parse_integer_settings, parse_hermers_profile_lifecycle_settings,
    parse_restart_actuator_settings, parse_hermers_gateway_restart_limit, startup_grace_active,
)
from stability_core.action_ledger import ActionLedger
from stability_core.action_classes import classify_action_types, classify_commands
from stability_core.preflight_recovery import (
    build_preflight_summary, build_recovery_summary, load_action_ledger_readonly,
)
from stability_core.action_executor import (
    ActionExecutor, ActionSpec, BoundaryCheck, OperationResult, PostcheckResult,
)
from stability_core.authorization import (
    EligibilityProof, STANDING_RULES, TrustedPolicyAuthorizer, policy_reference,
)


HOME = Path(os.environ.get("OPENCLAW_HOME_DIR", str(Path.home())))
OPENCLAW = HOME / ".openclaw"
HERMES_HOME = HOME / ".hermes"
HERMES_CLI = os.environ.get("CAT_AGENTS_STABILITY_HERMES_CLI", str(HOME / ".local/bin/hermes"))
CODEX_HOME = Path(os.environ.get("CAT_AGENTS_STABILITY_CODEX_HOME", str(HOME / ".codex")))
CODEX_AUTH_PATH = Path(os.environ.get("CAT_AGENTS_STABILITY_CODEX_AUTH_PATH", str(CODEX_HOME / "auth.json")))


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
WORKFLOW_RUNTIME_SNAPSHOT_MAX_AGE_SECONDS = 900
WORKFLOW_RUNTIME_SNAPSHOT_MAX_FUTURE_SKEW_SECONDS = 300
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
ACTUATION_LOCK_PATH = STABILITY_DIR / "actuation.lock"
COLLECTOR_OUTPUT_MAX_BYTES = 1_000_000
COLLECTOR_BUDGET_MS = 60_000
COLLECTOR_ENV_ALLOWLIST = frozenset({
    "CAT_AGENTS_STABILITY_VERSION_PROBE_TTL_SECONDS", "CAT_AGENTS_STABILITY_DEEP_PROBE_TTL_SECONDS",
    "CAT_AGENTS_STABILITY_PLUGINS_PROBE_TTL_SECONDS", "CAT_AGENTS_STABILITY_CRON_READONLY_RPC",
    "HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
    "OPENCLAW_HOME_DIR", "CAT_AGENTS_WORKFLOW_ROOT", "CAT_AGENTS_WORKFLOW_DB",
    "CAT_AGENTS_WORKFLOW_RUNTIME_AGENTS_SNAPSHOT", "CAT_AGENTS_STABILITY_DESIRED_STATE",
    "CAT_AGENTS_STABILITY_CODEX_HOME", "CAT_AGENTS_STABILITY_CODEX_AUTH_PATH",
    "CAT_AGENTS_STABILITY_CODEX_CONFIG", "CAT_AGENTS_STABILITY_HERMES_CLI",
    "CAT_AGENTS_STABILITY_AUTH_CRITICAL_SECONDS", "CAT_AGENTS_STABILITY_AUTH_EVIDENCE_FRESH_SECONDS",
    "CAT_AGENTS_STABILITY_AUTH_OPENAI_PROVIDERS", "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_IDS",
    "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_LIMIT", "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_ERROR_SECONDS",
    "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_NEAR_SECONDS", "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_SECONDS",
    "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_TIMEOUT_SECONDS",
    "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_URGENT_SECONDS",
    "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_URGENT_WINDOW_SECONDS",
    "CAT_AGENTS_STABILITY_AUTH_OPENCLAW_REQUIRED_PROVIDERS", "CAT_AGENTS_STABILITY_AUTH_WARN_SECONDS",
    "CAT_AGENTS_STABILITY_HERMERS_ACP_LONG_SECONDS", "CAT_AGENTS_STABILITY_HERMERS_ACP_ORPHAN_SECONDS",
    "CAT_AGENTS_STABILITY_HERMERS_FAILURE_BURST", "CAT_AGENTS_STABILITY_HERMERS_FAILURE_WINDOW_SECONDS",
    "CAT_AGENTS_STABILITY_HERMERS_GATEWAY_RESTART_LIMIT", "CAT_AGENTS_STABILITY_HERMERS_LSP_IDLE_SECONDS",
    "CAT_AGENTS_STABILITY_HERMERS_LSP_IDLE_STATE_TTL_SECONDS", "CAT_AGENTS_STABILITY_HERMERS_PROFILE_ACTUATE",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_COLD_IDLE_SECONDS",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_LIFECYCLE_ALLOWLIST",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ENABLED", "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_MANAGED",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTUATE",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_ACTION_COOLDOWN_SECONDS",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_PROTECTED", "CAT_AGENTS_STABILITY_HERMERS_PROFILE_MODE_START",
    "CAT_AGENTS_STABILITY_HERMERS_PROFILE_PROTECTED_IDS", "CAT_AGENTS_STABILITY_HERMERS_STALE_SENT_SECONDS",
    "CAT_AGENTS_STABILITY_REAP_HERMERS_ACP_ORPHANS", "CAT_AGENTS_STABILITY_REAP_HERMERS_IDLE_LSP",
    "CAT_AGENTS_STABILITY_RESTART_HERMERS_GATEWAY",
    "OPENCLAW_STABILITY_ACTION_STREAK", "OPENCLAW_STABILITY_BACKUP_HEADROOM_WARN_RATIO",
    "OPENCLAW_STABILITY_BACKUP_KEEP_COUNT", "OPENCLAW_STABILITY_CHANNEL_CRIT_SECONDS",
    "OPENCLAW_STABILITY_CHANNEL_WARN_SECONDS", "OPENCLAW_STABILITY_CHILD_GROWTH_WARN",
    "OPENCLAW_STABILITY_CONTROL_PLANE_BACKPRESSURE_SECONDS",
    "OPENCLAW_STABILITY_CONTROL_PLANE_DIRECT_SESSIONS", "OPENCLAW_STABILITY_CONTROL_PLANE_HEARTBEAT_JOBS",
    "OPENCLAW_STABILITY_CONTROL_PLANE_HEAVY_JOBS", "OPENCLAW_STABILITY_CRON_AUDIT_FRESH_SECONDS",
    "OPENCLAW_STABILITY_CRON_HEARTBEAT_WARN_MS", "OPENCLAW_STABILITY_CRON_HISTORY_DAYS",
    "OPENCLAW_STABILITY_CRON_LONG_RUN_WARN_MS", "OPENCLAW_STABILITY_CRON_MAX_CONCURRENCY_DEGRADED",
    "OPENCLAW_STABILITY_CRON_MAX_CONCURRENCY_NORMAL", "OPENCLAW_STABILITY_CRON_RECOVERY_LIMITED_STREAK",
    "OPENCLAW_STABILITY_CRON_RECOVERY_OPEN_STREAK", "OPENCLAW_STABILITY_CRON_TIMEOUT_NEAR_MISS_MS",
    "OPENCLAW_STABILITY_HEALTH_PROXY", "OPENCLAW_STABILITY_HEAVY_EVENTS",
    "OPENCLAW_STABILITY_HEAVY_WINDOW_SECONDS", "OPENCLAW_STABILITY_LEGACY_CRON_AUDIT_REQUIRED",
    "OPENCLAW_STABILITY_LOG_PRESSURE_WINDOW_SECONDS", "OPENCLAW_STABILITY_MEMORY_CRIT_GB",
    "OPENCLAW_STABILITY_MEMORY_GROWTH_WARN_GB", "OPENCLAW_STABILITY_MEMORY_WARN_GB",
    "OPENCLAW_STABILITY_MIN_STALE_RUNNING_SECONDS", "OPENCLAW_STABILITY_ORPHAN_RUN_LOG_MIN_AGE_SECONDS",
    "OPENCLAW_STABILITY_RESOURCE_EVIDENCE_SECONDS", "OPENCLAW_STABILITY_RESOURCE_HUMAN_GATE_SECONDS",
    "OPENCLAW_STABILITY_RESOURCE_INCIDENT_STREAK", "OPENCLAW_STABILITY_SESSION_ACTIVE_EVENTS",
    "OPENCLAW_STABILITY_SESSION_ACTIVE_WINDOW_SECONDS", "OPENCLAW_STABILITY_SESSION_FAIL_THRESHOLD",
    "OPENCLAW_STABILITY_SESSION_FAIL_WINDOW_SECONDS", "OPENCLAW_STABILITY_SESSION_OVERFLOW_THRESHOLD",
    "OPENCLAW_STABILITY_SESSION_OVERFLOW_WINDOW_SECONDS", "OPENCLAW_STABILITY_SESSION_RESET_COOLDOWN_SECONDS",
    "OPENCLAW_STABILITY_STALE_RUNNING_MULTIPLIER", "OPENCLAW_STABILITY_STALE_TELEGRAM_OFFSET_FINDING",
    "OPENCLAW_STABILITY_SWAP_CRIT_GB", "OPENCLAW_STABILITY_SWAP_WARN_GB",
    "OPENCLAW_STABILITY_SYSTEM_COMMIT_CRIT_RATIO", "OPENCLAW_STABILITY_SYSTEM_COMMIT_WARN_RATIO",
    "OPENCLAW_STABILITY_SYSTEM_MEM_AVAILABLE_CRIT_GB", "OPENCLAW_STABILITY_SYSTEM_MEM_AVAILABLE_WARN_GB",
    "OPENCLAW_STABILITY_SYSTEM_SWAP_CRIT_GB", "OPENCLAW_STABILITY_SYSTEM_SWAP_CRIT_RATIO",
    "OPENCLAW_STABILITY_SYSTEM_SWAP_WARN_GB", "OPENCLAW_STABILITY_SYSTEM_SWAP_WARN_RATIO",
    "OPENCLAW_STABILITY_TELEGRAM_ACCOUNTS", "OPENCLAW_STABILITY_TELEGRAM_API_PROBE",
    "OPENCLAW_STABILITY_STARTUP_GRACE_SECONDS", "OPENCLAW_STABILITY_TMP_MAX_AGE_SECONDS", "OPENCLAW_STABILITY_TREND_SAMPLE_LIMIT",
    "OPENCLAW_STABILITY_TREND_WINDOW_SECONDS",
}) | frozenset(RUNTIME_INTEGER_DEFAULTS)
LOG_PATH = STABILITY_DIR / "stabilityd.log"
RESOURCE_EVIDENCE_DIR = STABILITY_DIR / "resource-evidence"
RESOURCE_HUMAN_GATE_DIR = STABILITY_DIR / "human-gate"
RESOURCE_INCIDENT_DIR = STABILITY_DIR / "incidents"
RESOURCE_INCIDENT_LATEST = RESOURCE_INCIDENT_DIR / "gateway-resource-pressure-latest.json"
CONTROL_PLANE_BACKPRESSURE_PATH = STABILITY_DIR / "control-plane-backpressure.json"
LANE_POLICY_PATH = STABILITY_DIR / "lane-policy.json"
HERMERS_PROFILE_MODES_PATH = STABILITY_DIR / "hermers-profile-modes.json"
AUTH_MAINTENANCE_PLAN_PATH = STABILITY_DIR / "auth-maintenance-plan-latest.json"
AUTH_REFRESH_BROKER_LOCK_PATH = STABILITY_DIR / "auth-refresh-broker.lock"
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

RUNTIME_INTEGER_SETTINGS = parse_integer_settings(os.environ, RUNTIME_INTEGER_DEFAULTS)
PORT = RUNTIME_INTEGER_SETTINGS["OPENCLAW_GATEWAY_PORT"]
INTERVAL_SECONDS = RUNTIME_INTEGER_SETTINGS["OPENCLAW_STABILITY_INTERVAL_SECONDS"]
STABILITYD_PROGRESS_STALE_SECONDS = max(90, INTERVAL_SECONDS * 3)
POLICY_TTL_SECONDS = RUNTIME_INTEGER_SETTINGS["OPENCLAW_STABILITY_POLICY_TTL_SECONDS"]
# Only daemon observations are cached; one-shot CLI/MCP diagnostics stay fresh.
_inspection_settings = parse_integer_settings(os.environ, {
    "CAT_AGENTS_STABILITY_VERSION_PROBE_TTL_SECONDS": 900,
    "CAT_AGENTS_STABILITY_DEEP_PROBE_TTL_SECONDS": 120,
    "CAT_AGENTS_STABILITY_PLUGINS_PROBE_TTL_SECONDS": 300,
})
INSPECTION_VERSION_TTL_SECONDS = max(0, _inspection_settings["CAT_AGENTS_STABILITY_VERSION_PROBE_TTL_SECONDS"])
INSPECTION_DEEP_TTL_SECONDS = max(0, _inspection_settings["CAT_AGENTS_STABILITY_DEEP_PROBE_TTL_SECONDS"])
INSPECTION_PLUGINS_TTL_SECONDS = max(0, _inspection_settings["CAT_AGENTS_STABILITY_PLUGINS_PROBE_TTL_SECONDS"])
_inspection_cache_enabled = False
_inspection_cache: Dict[str, Any] = {}
_inspection_gateway_context: Tuple[int, bool] = (0, False)
CRON_READONLY_RPC_ENABLED = os.environ.get("CAT_AGENTS_STABILITY_CRON_READONLY_RPC", "1") == "1"
_cron_rpc_cycle: Optional[Dict[str, Any]] = None
_cron_rpc_retry_after = 0.0
_INSPECTION_WORKER_ENV = "CAT_AGENTS_STABILITY_INTERNAL_INSPECTION_STATE"
_INSPECTION_WORKER_FIELD = "_inspectionWorkerState"
_INSPECTION_STATE_MAX_BYTES = 32768
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
RESTART_ACTUATOR_SETTINGS = parse_restart_actuator_settings(os.environ)
RESTART_COOLDOWN_SECONDS = RESTART_ACTUATOR_SETTINGS["RESTART_COOLDOWN_SECONDS"]
RESTART_WINDOW_SECONDS = RESTART_ACTUATOR_SETTINGS["RESTART_WINDOW_SECONDS"]
MAX_RESTARTS_PER_WINDOW = RESTART_ACTUATOR_SETTINGS["MAX_RESTARTS_PER_WINDOW"]
ACTION_STREAK_THRESHOLD = RESTART_ACTUATOR_SETTINGS["ACTION_STREAK_THRESHOLD"]
STARTUP_GRACE_SECONDS = RESTART_ACTUATOR_SETTINGS["STARTUP_GRACE_SECONDS"]
MEMORY_WARN_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_MEMORY_WARN_GB", "5.0")) * 1024**3)
MEMORY_CRIT_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_MEMORY_CRIT_GB", "6.5")) * 1024**3)
SWAP_WARN_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SWAP_WARN_GB", "0.8")) * 1024**3)
SWAP_CRIT_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SWAP_CRIT_GB", "1.8")) * 1024**3)
SYSTEM_MEMORY_AVAILABLE_WARN_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_MEM_AVAILABLE_WARN_GB", "1.0")) * 1024**3)
SYSTEM_MEMORY_AVAILABLE_CRIT_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_MEM_AVAILABLE_CRIT_GB", "0.5")) * 1024**3)
SYSTEM_SWAP_WARN_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_SWAP_WARN_GB", "0")) * 1024**3)
SYSTEM_SWAP_CRIT_BYTES = int(float(os.environ.get("OPENCLAW_STABILITY_SYSTEM_SWAP_CRIT_GB", "0")) * 1024**3)
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
ACTUATOR_ENVIRONMENT_SETTINGS = parse_actuator_environment_settings(os.environ)
HERMERS_ACP_ORPHAN_REAP_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["HERMERS_ACP_ORPHAN_REAP_ENABLED"]
HERMERS_GATEWAY_RESTART_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["HERMERS_GATEWAY_RESTART_ENABLED"]
HERMERS_GATEWAY_RESTART_LIMIT = parse_hermers_gateway_restart_limit(os.environ, MAX_RESTARTS_PER_WINDOW)
HERMERS_ACP_ORPHAN_MIN_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_ACP_ORPHAN_SECONDS", "120"))
HERMERS_ACP_LONG_RUNNING_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_ACP_LONG_SECONDS", "600"))
HERMERS_LSP_IDLE_REAP_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["HERMERS_LSP_IDLE_REAP_ENABLED"]
HERMERS_LSP_IDLE_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_LSP_IDLE_SECONDS", str(4 * 3600)))
HERMERS_LSP_IDLE_STATE_TTL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_LSP_IDLE_STATE_TTL_SECONDS", str(24 * 3600)))
HERMERS_FAILURE_WINDOW_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_FAILURE_WINDOW_SECONDS", "1800"))
HERMERS_FAILURE_BURST_THRESHOLD = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_FAILURE_BURST", "5"))
HERMERS_STALE_SENT_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_HERMERS_STALE_SENT_SECONDS", "600"))
HERMERS_PROFILE_LIFECYCLE_SETTINGS = parse_hermers_profile_lifecycle_settings(os.environ)
HERMERS_PROFILE_MODE_ENABLED = HERMERS_PROFILE_LIFECYCLE_SETTINGS["modeEnabled"]
HERMERS_PROFILE_MODE_ACTUATE_ENABLED = HERMERS_PROFILE_LIFECYCLE_SETTINGS["actuateEnabled"]
HERMERS_PROFILE_MODE_START_ENABLED = HERMERS_PROFILE_LIFECYCLE_SETTINGS["startEnabled"]
HERMERS_PROFILE_LIFECYCLE_ALLOWLIST = HERMERS_PROFILE_LIFECYCLE_SETTINGS["lifecycleAllowlist"]
HERMERS_PROFILE_COLD_IDLE_SECONDS = HERMERS_PROFILE_LIFECYCLE_SETTINGS["coldIdleSeconds"]
HERMERS_PROFILE_HIBERNATE_IDLE_SECONDS = HERMERS_PROFILE_LIFECYCLE_SETTINGS["hibernateIdleSeconds"]
HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS = HERMERS_PROFILE_LIFECYCLE_SETTINGS["lifecycleCooldownSeconds"]
HERMERS_PROFILE_PROTECTED_IDS = HERMERS_PROFILE_LIFECYCLE_SETTINGS["protectedIds"]
AUTH_WARN_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_WARN_SECONDS", str(72 * 3600)))
AUTH_CRITICAL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_CRITICAL_SECONDS", str(24 * 3600)))
AUTH_OPENCLAW_PROBE_TTL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_SECONDS", str(15 * 60)))
AUTH_OPENCLAW_PROBE_NEAR_TTL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_NEAR_SECONDS", "60"))
AUTH_OPENCLAW_PROBE_URGENT_TTL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_URGENT_SECONDS", "30"))
AUTH_OPENCLAW_PROBE_URGENT_WINDOW_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_URGENT_WINDOW_SECONDS", str(15 * 60)))
AUTH_OPENCLAW_PROBE_ERROR_TTL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_ERROR_SECONDS", "60"))
AUTH_OPENCLAW_PROBE_TIMEOUT_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_PROBE_TIMEOUT_SECONDS", "8"))
AUTH_OPENCLAW_AGENT_LIMIT = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_LIMIT", "32"))
AUTH_OPENCLAW_AGENT_IDS = [
    item.strip()
    for item in os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_AGENT_IDS", "").split(",")
    if item.strip()
]
AUTH_OPENAI_PROVIDER_IDS = {
    item.strip()
    for item in os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENAI_PROVIDERS", "openai-codex,openai").split(",")
    if item.strip()
}
AUTH_PROFILE_PROVIDER_ID_ALLOWLIST = frozenset({"openai", "openai-codex"})
AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS = {
    item.strip()
    for item in os.environ.get("CAT_AGENTS_STABILITY_AUTH_OPENCLAW_REQUIRED_PROVIDERS", "openai-codex,openai").split(",")
    if item.strip()
}
AUTH_REFRESH_BROKER_ENABLED = False
AUTH_MIRROR_SCRIPT = Path(
    os.environ.get("CAT_AGENTS_STABILITY_AUTH_MIRROR_SCRIPT", str(PACKAGE_ROOT / "scripts" / "mac_codex_oauth_mirror.py"))
)
AUTH_MIRROR_TIMEOUT_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_MIRROR_TIMEOUT_SECONDS", "180"))
AUTH_MIRROR_MIN_TTL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_MIRROR_MIN_TTL_SECONDS", "300"))
AUTH_MIRROR_ACTION_KINDS = {"mirror-from-mac-codex", "reauth-or-sync", "sync-or-refresh"}
AUTH_EVIDENCE_FRESH_SECONDS = int(
    os.environ.get("CAT_AGENTS_STABILITY_AUTH_EVIDENCE_FRESH_SECONDS", str(max(POLICY_TTL_SECONDS, AUTH_OPENCLAW_PROBE_TTL_SECONDS)))
)

TMP_FILE_MAX_AGE_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_TMP_MAX_AGE_SECONDS", "3600"))
ORPHAN_RUN_LOG_MIN_AGE_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_ORPHAN_RUN_LOG_MIN_AGE_SECONDS", "3600"))
MIN_STALE_RUNNING_SECONDS = int(os.environ.get("OPENCLAW_STABILITY_MIN_STALE_RUNNING_SECONDS", "1800"))
STALE_RUNNING_TIMEOUT_MULTIPLIER = int(os.environ.get("OPENCLAW_STABILITY_STALE_RUNNING_MULTIPLIER", "4"))
LEASE_REAP_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["LEASE_REAP_ENABLED"]
SESSION_RESET_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["SESSION_RESET_ENABLED"]
CRON_MUTATION_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["CRON_MUTATION_ENABLED"]
GATEWAY_RESTART_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["GATEWAY_RESTART_ENABLED"]
GATEWAY_RESTART_ACTUATOR_SUPPORTED = True
SOFT_GATEWAY_RESTART_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["SOFT_GATEWAY_RESTART_ENABLED"]
SOFT_RESCUE_RESTART_ENABLED = ACTUATOR_ENVIRONMENT_SETTINGS["SOFT_RESCUE_RESTART_ENABLED"]
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
    line = f"{ts()} {redact_sensitive_text(message, 4000)}\n"
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


def generation_compatible_payload(path: Path, latest: Dict[str, Any], embedded: Any = None) -> Dict[str, Any]:
    """Prefer the committed latest snapshot; reject mismatched fixed-path aliases."""
    if isinstance(embedded, dict):
        return embedded
    payload = load_json(path, {}) or {}
    if not isinstance(payload, dict):
        return {}
    committed_generation = latest.get("generationId")
    payload_generation = payload.get("generationId")
    if committed_generation:
        if payload_generation != committed_generation:
            return {}
    elif payload_generation is not None:
        # A legacy latest pointer cannot authenticate a newly versioned alias.
        return {}
    return payload


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


def iso_from_epoch(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    try:
        return dt.datetime.fromtimestamp(int(value), dt.timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def decode_jwt_payload(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, str) or value.count(".") < 2:
        return None
    try:
        part = value.split(".", 2)[1]
        part += "=" * ((4 - len(part) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part.encode("utf-8")))
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def token_kind_from_path(path: str) -> str:
    lowered = path.lower()
    if "refresh_token" in lowered:
        return "refresh"
    if "access_token" in lowered:
        return "access"
    if "id_token" in lowered:
        return "id"
    if "token" in lowered:
        return "token"
    if "api_key" in lowered or lowered.endswith(".key") or "secret" in lowered:
        return "secret"
    return "other"


def iter_token_fields(payload: Any, prefix: str = "") -> Iterable[Tuple[str, str, Any]]:
    if isinstance(payload, dict):
        for key, value in payload.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            yield from iter_token_fields(value, child_prefix)
        return
    if isinstance(payload, list):
        for index, value in enumerate(payload):
            child_prefix = f"{prefix}[{index}]" if prefix else f"[{index}]"
            yield from iter_token_fields(value, child_prefix)
        return
    kind = token_kind_from_path(prefix)
    if kind in {"access", "refresh", "id", "token", "secret"}:
        yield prefix, kind, payload


def summarize_auth_json(path: Path) -> Dict[str, Any]:
    file_age = file_age_seconds(path)
    summary: Dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "ageSeconds": file_age,
        "mode": None,
        "mtimeEpoch": None,
        "mtime": None,
        "topKeys": [],
        "authMode": None,
        "activeProvider": None,
        "providerKeys": [],
        "credentialPoolKeys": [],
        "accessTokenCount": 0,
        "refreshTokenCount": 0,
        "idTokenCount": 0,
        "secretFieldCount": 0,
        "jwtCount": 0,
        "accessTokens": [],
        "freshestAccessTokenExpiresEpoch": None,
        "freshestAccessTokenExpiresAt": None,
        "freshestAccessTokenSecondsRemaining": None,
        "oldestAccessTokenExpiresEpoch": None,
        "oldestAccessTokenExpiresAt": None,
        "expiredAccessTokenCount": 0,
        "hasAccessToken": False,
        "hasRefreshToken": False,
    }
    try:
        stat = path.stat()
        summary["mode"] = oct(stat.st_mode & 0o777)
        summary["mtimeEpoch"] = int(stat.st_mtime)
        summary["mtime"] = iso_from_epoch(int(stat.st_mtime))
    except Exception:
        pass
    payload = load_json(path, None)
    if not isinstance(payload, dict):
        if path.exists():
            summary["error"] = "json-unreadable"
        return summary

    summary["topKeys"] = sorted(str(key) for key in payload.keys())[:50]
    summary["authMode"] = payload.get("auth_mode") or payload.get("authMode")
    summary["activeProvider"] = payload.get("active_provider") or payload.get("activeProvider") or payload.get("active")
    providers = payload.get("providers") if isinstance(payload.get("providers"), dict) else {}
    credential_pool = payload.get("credential_pool") if isinstance(payload.get("credential_pool"), dict) else {}
    summary["providerKeys"] = sorted(str(key) for key in providers.keys())[:50]
    summary["credentialPoolKeys"] = sorted(str(key) for key in credential_pool.keys())[:50]

    access_expiries: List[int] = []
    access_tokens: List[Dict[str, Any]] = []
    current_epoch = epoch()
    for token_path, kind, value in iter_token_fields(payload):
        if kind == "access":
            summary["accessTokenCount"] += 1
            summary["hasAccessToken"] = True
        elif kind == "refresh":
            summary["refreshTokenCount"] += 1
            summary["hasRefreshToken"] = True
        elif kind == "id":
            summary["idTokenCount"] += 1
        elif kind == "secret":
            summary["secretFieldCount"] += 1
        jwt_payload = decode_jwt_payload(value)
        if jwt_payload:
            summary["jwtCount"] += 1
            exp_epoch = parse_iso_epoch(jwt_payload.get("exp"))
            iat_epoch = parse_iso_epoch(jwt_payload.get("iat"))
            if kind == "access" and exp_epoch is not None:
                access_expiries.append(int(exp_epoch))
                access_tokens.append(
                    {
                        "path": token_path,
                        "expiresEpoch": int(exp_epoch),
                        "expiresAt": iso_from_epoch(int(exp_epoch)),
                        "secondsRemaining": int(exp_epoch) - current_epoch,
                        "issuedAt": iso_from_epoch(iat_epoch),
                        "issuer": jwt_payload.get("iss"),
                        "audience": jwt_payload.get("aud"),
                    }
                )

    if access_expiries:
        freshest = max(access_expiries)
        oldest = min(access_expiries)
        summary["freshestAccessTokenExpiresEpoch"] = freshest
        summary["freshestAccessTokenExpiresAt"] = iso_from_epoch(freshest)
        summary["freshestAccessTokenSecondsRemaining"] = freshest - current_epoch
        summary["oldestAccessTokenExpiresEpoch"] = oldest
        summary["oldestAccessTokenExpiresAt"] = iso_from_epoch(oldest)
        summary["expiredAccessTokenCount"] = sum(1 for item in access_expiries if item <= current_epoch)
        summary["accessTokenExpirySpreadSeconds"] = freshest - oldest
    summary["accessTokens"] = sorted(access_tokens, key=lambda item: int(item.get("expiresEpoch") or 0), reverse=True)[:10]
    return summary


def auth_token_status(summary: Dict[str, Any]) -> str:
    if not bool(summary.get("exists")):
        return "missing"
    if not bool(summary.get("hasAccessToken")):
        return "access-missing"
    if not bool(summary.get("hasRefreshToken")):
        return "refresh-missing"
    remaining = summary.get("freshestAccessTokenSecondsRemaining")
    if remaining is None:
        return "access-expiry-unknown"
    remaining_int = int(remaining)
    if remaining_int <= 0:
        return "access-expired"
    if remaining_int <= AUTH_CRITICAL_SECONDS:
        return "access-critical"
    if remaining_int <= AUTH_WARN_SECONDS:
        return "access-warning"
    return "ok"


def parse_openclaw_auth_list(text: str, agent_id: str) -> Dict[str, Any]:
    profiles: List[Dict[str, Any]] = []
    unparsed_profile_lines: List[str] = []
    current_epoch = epoch()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("- "):
            continue
        if "oauth" not in line.lower() and "expires" not in line.lower():
            continue
        match = re.match(r"^-\s+([^\s]+)(?:\s+\([^)]*\))?\s+\[([^]]+)\]", line)
        if not match:
            unparsed_profile_lines.append("unparsed_oauth_profile_line")
            continue
        raw_profile_id = match.group(1)
        meta = match.group(2)
        provider = meta.split("/", 1)[0].split(";", 1)[0].strip()
        if provider not in AUTH_PROFILE_PROVIDER_ID_ALLOWLIST:
            provider = "unknown"
        profile_kind = provider
        expires_match = re.search(r"\bexpires(?:\s+at)?\s*[:=]?\s+([^;\]]+)", meta, re.IGNORECASE)
        cooldown_match = re.search(r"\bcooldown\s+until\s*[:=]?\s+([^;\]]+)", meta, re.IGNORECASE)
        expires_epoch = parse_iso_epoch(expires_match.group(1).strip()) if expires_match else None
        cooldown_epoch = parse_iso_epoch(cooldown_match.group(1).strip()) if cooldown_match else None
        profiles.append(
            {
                "agentId": agent_id,
                "profileKind": profile_kind,
                "provider": provider or profile_kind,
                "profileLabel": f"{profile_kind}:[redacted]",
                "authKind": meta.split(";", 1)[0].strip().lower()
                if meta.split(";", 1)[0].strip().lower() in {"oauth", "api_key", "token"}
                else "unknown",
                "expiresEpoch": expires_epoch,
                "expiresAt": iso_from_epoch(expires_epoch),
                "secondsRemaining": int(expires_epoch) - current_epoch if expires_epoch is not None else None,
                "cooldownUntilEpoch": cooldown_epoch,
                "cooldownUntil": iso_from_epoch(cooldown_epoch),
                "expiryParseOk": expires_epoch is not None,
            }
        )
    return {
        "agentId": agent_id,
        "profiles": profiles,
        "profileCount": len(profiles),
        "unparsedProfileLines": unparsed_profile_lines[:10],
        "unparsedProfileLineCount": len(unparsed_profile_lines),
    }


def openclaw_auth_probe_cache_ttl(cached: Dict[str, Any], *, now_epoch: Optional[int] = None) -> int:
    """Use a slower auth probe normally and tighten it as token expiry approaches."""
    now_epoch = int(now_epoch or epoch())
    if cached.get("available") is not True:
        return max(1, AUTH_OPENCLAW_PROBE_ERROR_TTL_SECONDS)
    try:
        checked_epoch = int(cached.get("checkedAtEpoch") or now_epoch)
    except (TypeError, ValueError):
        checked_epoch = now_epoch
    age = max(0, now_epoch - checked_epoch)
    profiles = cached.get("profiles") if isinstance(cached.get("profiles"), list) else []
    provider_remaining: Dict[str, List[int]] = {}
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        provider = str(profile.get("provider") or profile.get("profileKind") or "")
        if provider not in AUTH_OPENAI_PROVIDER_IDS:
            continue
        try:
            expires_epoch = int(profile.get("expiresEpoch"))
        except (TypeError, ValueError):
            try:
                provider_remaining.setdefault(provider, []).append(int(profile.get("secondsRemaining")) - age)
            except (TypeError, ValueError):
                continue
        else:
            provider_remaining.setdefault(provider, []).append(expires_epoch - now_epoch)
    # Stale copies for the same provider must not force urgent probes while a
    # fresher usable profile remains valid; the plan is routed by that winner.
    remaining_values = [max(values) for values in provider_remaining.values() if values]
    if any(value <= max(1, AUTH_OPENCLAW_PROBE_URGENT_WINDOW_SECONDS) for value in remaining_values):
        return max(1, AUTH_OPENCLAW_PROBE_URGENT_TTL_SECONDS)
    if any(value <= AUTH_CRITICAL_SECONDS for value in remaining_values):
        return max(1, AUTH_OPENCLAW_PROBE_NEAR_TTL_SECONDS)
    return max(1, AUTH_OPENCLAW_PROBE_TTL_SECONDS)


def cached_openclaw_auth_probe(
    conn: sqlite3.Connection, agent_id: str, *, force: bool = False,
    persist: bool = True, cache_updates: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    cache_key = f"auth:openclaw:{agent_id}"
    cached = db_get(conn, cache_key, {}) or {}
    cached_epoch = int(cached.get("checkedAtEpoch") or 0) if isinstance(cached, dict) else 0
    now_epoch = epoch()
    cache_ttl = openclaw_auth_probe_cache_ttl(cached, now_epoch=now_epoch) if isinstance(cached, dict) else AUTH_OPENCLAW_PROBE_TTL_SECONDS
    if not force and cached_epoch and now_epoch - cached_epoch < cache_ttl:
        result = dict(cached)
        result["profiles"] = [dict(item) if isinstance(item, dict) else item for item in (cached.get("profiles") or [])]
        for profile in result["profiles"]:
            if isinstance(profile, dict) and profile.get("expiresEpoch") is not None:
                try:
                    profile["secondsRemaining"] = int(profile["expiresEpoch"]) - now_epoch
                except (TypeError, ValueError):
                    pass
        result["cached"] = True
        result["cacheTtlSeconds"] = cache_ttl
        result["nextProbeDueAtEpoch"] = cached_epoch + cache_ttl
        return result
    try:
        out = run_cmd(["openclaw", "models", "auth", "list", "--agent", agent_id], timeout=AUTH_OPENCLAW_PROBE_TIMEOUT_SECONDS)
        text = "\n".join([out.stdout or "", out.stderr or ""])
        parsed = parse_openclaw_auth_list(text, agent_id)
        result = {
            "agentId": agent_id,
            "checkedAt": ts(),
            "checkedAtEpoch": epoch(),
            "cached": False,
            "available": out.returncode == 0,
            "exitCode": out.returncode,
            "profileCount": parsed.get("profileCount"),
            "profiles": parsed.get("profiles") or [],
            "unparsedProfileLineCount": parsed.get("unparsedProfileLineCount") or 0,
            "unparsedProfileLines": parsed.get("unparsedProfileLines") or [],
        }
        result["cacheTtlSeconds"] = openclaw_auth_probe_cache_ttl(result, now_epoch=result["checkedAtEpoch"])
        result["nextProbeDueAtEpoch"] = result["checkedAtEpoch"] + result["cacheTtlSeconds"]
        if out.returncode != 0:
            result["error"] = redact_auth_text(out.stderr or out.stdout or "", 1000)
    except Exception as exc:
        result = {
            "agentId": agent_id,
            "checkedAt": ts(),
            "checkedAtEpoch": epoch(),
            "cached": False,
            "available": False,
            "error": redact_auth_text(type(exc).__name__, 1000),
            "profileCount": 0,
            "profiles": [],
        }
    if persist:
        db_set(conn, cache_key, result)
    elif cache_updates is not None:
        cache_updates[cache_key] = result
    return result


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
            "cmd": [Path(cmd[0]).name] if cmd else [],
            "exitCode": proc.returncode,
            "durationMs": duration,
            "stdout": redact_sensitive_text(proc.stdout, max_chars),
            "stderr": redact_sensitive_text(proc.stderr, max_chars),
        }
    except Exception as exc:
        duration = int((time.time() - started) * 1000)
        return {
            "cmd": [Path(cmd[0]).name] if cmd else [],
            "exitCode": -1,
            "durationMs": duration,
            "errorClass": type(exc).__name__,
        }


def extract_json_payload(text: str) -> Tuple[Optional[Any], List[str], Optional[str]]:
    """Parse CLI JSON while preserving only allowlisted diagnostic categories."""
    diagnostics: List[str] = []
    if not text:
        return None, diagnostics, "empty"
    lowered = text.lower()
    if "state-migrations" in lowered or "legacy state migration" in lowered:
        diagnostics.append("state_migration_warning")
    if "plugin install index" in lowered:
        diagnostics.append("plugin_install_index_warning")
    if "warning" in lowered or "error" in lowered:
        diagnostics.append("non_json_diagnostic_preamble")
    starts = sorted(idx for idx, char in enumerate(text) if char in "{[")
    if not starts:
        return None, diagnostics or ["non_json_output"], "json_start_missing"
    decoder = json.JSONDecoder()
    first_error: Optional[str] = None
    for start in starts:
        prefix = text[:start].strip()
        payload_text = text[start:].strip()
        try:
            payload, _ = decoder.raw_decode(payload_text)
            try:
                return json.loads(payload_text), diagnostics, None
            except Exception as exc:
                return payload, diagnostics, f"trailing_non_json_ignored:{type(exc).__name__}"
        except Exception as exc:
            if first_error is None:
                first_error = type(exc).__name__
            continue
    return None, diagnostics or ["non_json_output"], f"json_parse_failed:{first_error or 'unknown'}"


def openclaw_state_migration_diagnostics(diagnostics: Iterable[str]) -> List[str]:
    return [
        code for code in diagnostics
        if code in {"state_migration_warning", "plugin_install_index_warning"}
    ]


def parse_openclaw_version(text: str) -> Dict[str, Any]:
    match = re.search(r"\bOpenClaw\s+(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)(?:\s+\(([0-9a-fA-F]{7,64})\))?", text or "")
    if not match:
        return {"raw": "unparsed_version_output", "version": None, "commit": None}
    return {
        "raw": f"OpenClaw {match.group(1)}",
        "version": match.group(1),
        "commit": match.group(2),
    }


def inspection_revision() -> Tuple[Any, ...]:
    """Cheap invalidation evidence, without loading CLI/plugin code or credentials."""
    paths = [OPENCLAW / "openclaw.json", OPENCLAW / "extensions", OPENCLAW / "plugin-dev", OPENCLAW / "npm" / "projects"]
    command = shutil.which("openclaw")
    if command:
        paths.append(Path(command).resolve())
    revisions = []
    for path in paths:
        try:
            stat = path.stat()
            revisions.append((str(path), stat.st_ino, stat.st_size, stat.st_mtime_ns))
        except OSError:
            revisions.append((str(path), None))
    return tuple(revisions)


def inspection_worker_state() -> Dict[str, Any]:
    """Parent-owned ephemeral cache; never an authorization or persistent KV."""
    now, wall = time.monotonic(), time.time()
    state = {"enabled": _inspection_cache_enabled,
             "context": list(_inspection_gateway_context),
             "retryAfter": wall + max(0, _cron_rpc_retry_after - now) if _cron_rpc_retry_after else 0,
             "cache": copy.deepcopy(_inspection_cache)}
    # Python monotonic origins are not portable across fresh interpreters on
    # every supported host. Transport wall coordinates, then rebase locally.
    # A backwards clock yields a future local sample, which cannot hit the cache.
    for entry in state["cache"].values():
        entry["monotonic"] = wall - (now - entry["monotonic"])
    encoded = json.dumps(state, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > _INSPECTION_STATE_MAX_BYTES:
        state["cache"] = {}
    return state


def accept_inspection_worker_state(state: Any, component: str) -> None:
    """Validate bounded observation state and update only its component owner."""
    global _inspection_cache, _inspection_gateway_context, _cron_rpc_retry_after
    if not isinstance(state, dict) or set(state) != {"enabled", "context", "retryAfter", "cache"}:
        raise ValueError("invalid inspection state")
    if len(json.dumps(state, allow_nan=False, separators=(",", ":")).encode("utf-8")) > _INSPECTION_STATE_MAX_BYTES:
        raise ValueError("oversized inspection state")
    context, retry, cache = state["context"], state["retryAfter"], state["cache"]
    def finite_clock(value: Any) -> bool:
        # Bound integers before conversion; malformed JSON can carry huge ints.
        return type(value) in (int, float) and abs(value) <= 1e15 and math.isfinite(value)
    if (type(state["enabled"]) is not bool or not isinstance(context, list) or len(context) != 2
            or type(context[0]) is not int or context[0] < 0 or type(context[1]) is not bool
            or not finite_clock(retry) or retry < 0
            or not isinstance(cache, dict) or not set(cache).issubset({"version", "deep-status", "plugins"})):
        raise ValueError("invalid inspection state fields")
    def tuples(value: Any) -> Any:
        return tuple(tuples(item) for item in value) if isinstance(value, list) else value
    for entry in cache.values():
        if (not isinstance(entry, dict) or set(entry) != {"revision", "monotonic", "checkedAtEpoch", "value"}
                or not isinstance(entry["revision"], (list, tuple))
                or not isinstance(entry["value"], dict)
                or any(not finite_clock(entry[key])
                       for key in ("monotonic", "checkedAtEpoch"))):
            raise ValueError("invalid inspection cache entry")
        entry["revision"] = tuples(entry["revision"])
        entry["monotonic"] = time.monotonic() - (time.time() - entry["monotonic"])
    if component in {"gateway", "input"}:
        _inspection_cache = copy.deepcopy(cache)
        _inspection_gateway_context = (context[0], context[1])
    if component in {"cron", "input"}:
        _cron_rpc_retry_after = time.monotonic() + min(300, max(0, retry - time.time())) if retry else 0


def cached_inspection(name: str, loader: Any, ttl: int, *, force: bool = False) -> Dict[str, Any]:
    """Cache successful low-frequency observations; never cache failed probes."""
    if not _inspection_cache_enabled or ttl <= 0:
        return loader()
    revision = (_inspection_gateway_context[0], inspection_revision())
    now = time.monotonic()
    saved = _inspection_cache.get(name)
    if not force and saved and saved["revision"] == revision and 0 <= now - saved["monotonic"] < ttl:
        result = copy.deepcopy(saved["value"])
        result["inspectionCache"] = {"cached": True, "checkedAtEpoch": saved["checkedAtEpoch"], "ageSeconds": round(now - saved["monotonic"], 3), "ttlSeconds": ttl}
        return result
    # Discard the prior success before trying: a failure must never fall back to it.
    _inspection_cache.pop(name, None)
    result = loader()
    probe = result.get("probe") or {}
    successful = result.get("available") is True or (probe.get("exitCode") == 0 and not probe.get("error"))
    # CLI deep status can exit zero with a failed network probe; do not reuse it,
    # except for the explicitly classified local plaintext refusal on a healthy runtime.
    if result.get("connectivityProbeFailed") and not (result.get("insecurePlaintextWsBlocked") and result.get("runtimeState") == "running" and _inspection_gateway_context[1]):
        successful = False
    if name == "deep-status" and (result.get("runtimeState") != "running" or result.get("pluginVersionDrift")):
        successful = False
    if name == "plugins" and any(item.get("status") == "error" for item in result.get("enabledPlugins", [])):
        successful = False
    finished = time.monotonic()
    checked = epoch()
    if successful:
        _inspection_cache[name] = {"revision": revision, "monotonic": finished, "checkedAtEpoch": checked, "value": copy.deepcopy(result)}
    result["inspectionCache"] = {"cached": False, "checkedAtEpoch": checked, "ageSeconds": 0, "ttlSeconds": ttl}
    return result


def collect_openclaw_version() -> Dict[str, Any]:
    return cached_inspection("version", _collect_openclaw_version, INSPECTION_VERSION_TTL_SECONDS)


def _collect_openclaw_version() -> Dict[str, Any]:
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
    return cached_inspection("deep-status", _collect_gateway_deep_status, INSPECTION_DEEP_TTL_SECONDS, force=not _inspection_gateway_context[1])


def _collect_gateway_deep_status() -> Dict[str, Any]:
    probe = command_probe(["openclaw", "gateway", "status", "--deep"], timeout=18, max_chars=20_000)
    text = "\n".join(str(probe.get(key) or "") for key in ("stdout", "stderr"))
    parsed = parse_gateway_deep_status(text)
    parsed["probe"] = {k: v for k, v in probe.items() if k not in {"stdout", "stderr"}}
    return parsed


def prepare_cron_readonly_rpc() -> None:
    """One fresh read-only SDK process per daemon cycle; CLI remains the fallback."""
    global _cron_rpc_cycle, _cron_rpc_retry_after
    _cron_rpc_cycle = None
    if not _inspection_cache_enabled or not CRON_READONLY_RPC_ENABLED:
        return
    if not _inspection_gateway_context[1]:
        return
    if time.monotonic() < _cron_rpc_retry_after:
        return
    try:
        command = shutil.which("openclaw")
        node = shutil.which("node")
        if not command or not node:
            raise RuntimeError("sdk-runtime-unavailable")
        resolved = Path(command).resolve()
        root = next((parent for parent in resolved.parents if (parent / "package.json").is_file() and load_json(parent / "package.json", {}).get("name") == "openclaw"), None)
        if root is None:
            raise RuntimeError("sdk-package-unavailable")
        proc = run_cmd([node, str(PACKAGE_ROOT / "scripts" / "gateway_cron_readonly.mjs"), str(root)], timeout=12)
        payload, _, _ = extract_json_payload(proc.stdout)
        if proc.returncode != 0 or not isinstance(payload, dict) or payload.get("schemaVersion") != 1 or payload.get("ok") is not True or not isinstance(payload.get("status"), dict) or not isinstance(payload.get("inventory"), dict) or not isinstance(payload["inventory"].get("jobs"), list):
            raise RuntimeError("sdk-query-unavailable")
        _cron_rpc_cycle = payload
        _cron_rpc_cycle["observedMonotonic"] = time.monotonic()
    except Exception:
        # Failed auth/API/schema attempts must not become a per-cycle spawn storm.
        # Every cycle still queries the full CLI freshly during this backoff.
        _cron_rpc_retry_after = time.monotonic() + 300


def cron_readonly_rpc_payload(key: str) -> Optional[Dict[str, Any]]:
    if _inspection_cache_enabled and _cron_rpc_cycle and 0 <= time.monotonic() - _cron_rpc_cycle["observedMonotonic"] < 12:
        return _cron_rpc_cycle.get(key)
    return None


def collect_cron_storage_status() -> Dict[str, Any]:
    payload = cron_readonly_rpc_payload("status")
    if payload is not None:
        return {"available": True, "exitCode": 0, "diagnostics": [], "inspectionTransport": "gateway-sdk-read-only", **{key: payload.get(key) for key in ("enabled", "storePath", "storage", "sqlitePath", "jobs", "nextWakeAtMs")}}
    result = _collect_cron_storage_status_cli()
    if _inspection_cache_enabled:
        result["inspectionTransport"] = "cli-fallback" if CRON_READONLY_RPC_ENABLED else "cli"
    return result


def _collect_cron_storage_status_cli() -> Dict[str, Any]:
    try:
        out = run_cmd(["openclaw", "cron", "status", "--json"], timeout=15)
    except Exception as exc:
        return {"available": False, "error": type(exc).__name__}
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
        result["stderrOmitted"] = True
        result["stderrByteCount"] = len((out.stderr or "").encode("utf-8"))
    return result


def collect_plugins_status() -> Dict[str, Any]:
    return cached_inspection("plugins", _collect_plugins_status, INSPECTION_PLUGINS_TTL_SECONDS, force=not _inspection_gateway_context[1])


def _collect_plugins_status() -> Dict[str, Any]:
    try:
        out = run_cmd(["openclaw", "plugins", "list", "--json"], timeout=20)
    except Exception as exc:
        return {"available": False, "error": type(exc).__name__}
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
        result["stderrOmitted"] = True
        result["stderrByteCount"] = len(out.stderr or "")
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


def init_memory_kv_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)"
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


def _snapshot_bool(value: Any, fallback: Optional[int] = None) -> Optional[int]:
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
                "can_receive_dispatch": _snapshot_bool(item.get("can_receive_dispatch", item.get("canReceiveDispatch"))),
                "can_start_workflow": _snapshot_bool(item.get("can_start_workflow", item.get("canStartWorkflow"))),
                "gateway_proxy_allowed": _snapshot_bool(item.get("gateway_proxy_allowed", item.get("gatewayProxyAllowed"))),
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
        "health": "unavailable",
        "writeEligible": False,
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
    snapshot_schema = snapshot.get("schemaVersion")
    payload["snapshotSchemaVersion"] = snapshot_schema
    candidate_records = _registry_snapshot_records(snapshot)
    raw_records = snapshot.get("records") if isinstance(snapshot.get("records"), list) else []
    generated_epoch = parse_iso_epoch(payload["snapshotGeneratedAt"]) if payload["snapshotGeneratedAt"] else None
    now_s = epoch()
    payload["snapshotAgeSeconds"] = now_s - generated_epoch if generated_epoch is not None else None
    snapshot_agent_ids = [str(item.get("agent_id") or "").strip() for item in candidate_records]
    duplicate_agent_ids = {value for value in snapshot_agent_ids if value and snapshot_agent_ids.count(value) > 1}
    payload["duplicateAgentIds"] = sorted(duplicate_agent_ids)
    snapshot_valid = (
        snapshot_schema == 1
        and isinstance(snapshot.get("records"), list)
        and bool(candidate_records)
        and len(candidate_records) == len(raw_records)
        and generated_epoch is not None
        and generated_epoch <= now_s + WORKFLOW_RUNTIME_SNAPSHOT_MAX_FUTURE_SKEW_SECONDS
        and now_s - generated_epoch <= WORKFLOW_RUNTIME_SNAPSHOT_MAX_AGE_SECONDS
        and all(
            item.get("agent_id") and item.get("runtime") and item.get("status")
            and item.get("platform") and item.get("endpoint_ref")
            and item.get("can_receive_dispatch") in (0, 1)
            and item.get("can_start_workflow") in (0, 1)
            and item.get("gateway_proxy_allowed") in (0, 1)
            for item in candidate_records
        )
        and not duplicate_agent_ids
    )
    payload["records"] = candidate_records if snapshot_valid else []
    payload["health"] = "observation_only" if snapshot_valid else "invalid"
    payload["writeEligible"] = False
    payload["error"] = "snapshot is observation-only; cannot establish mutation eligibility"
    if generated_epoch is None:
        payload["snapshotHealth"] = "missing_or_invalid_timestamp"
    elif generated_epoch > epoch() + 300:
        payload["snapshotHealth"] = "future_timestamp"
    elif now_s - generated_epoch > WORKFLOW_RUNTIME_SNAPSHOT_MAX_AGE_SECONDS:
        payload["snapshotHealth"] = "stale"
    elif snapshot_schema != 1:
        payload["snapshotHealth"] = "unsupported_schema"
    elif not snapshot_valid:
        payload["snapshotHealth"] = "incomplete_records"
    else:
        payload["snapshotHealth"] = "fresh_valid_observation_only"
    return payload


def workflow_runtime_registry_records() -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "source": "db",
        "dbFile": str(WORKFLOW_DB),
        "exists": WORKFLOW_DB.exists(),
        "snapshotFile": str(WORKFLOW_RUNTIME_AGENTS_SNAPSHOT),
        "snapshotExists": WORKFLOW_RUNTIME_AGENTS_SNAPSHOT.exists(),
        "records": [],
        "health": "unavailable",
        "writeEligible": False,
    }
    if not WORKFLOW_DB.exists():
        fallback = workflow_runtime_registry_snapshot_records("workflow_db_missing")
        fallback["dbFile"] = str(WORKFLOW_DB)
        fallback["exists"] = False
        return fallback
    try:
        conn = sqlite3.connect(str(WORKFLOW_DB))
        conn.row_factory = sqlite3.Row
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='runtime_agents'"
        ).fetchone()
        if not table:
            payload["error"] = "runtime_agents table not found"
            conn.close()
            fallback = workflow_runtime_registry_snapshot_records("runtime_agents_table_missing")
            fallback["dbFile"] = str(WORKFLOW_DB)
            fallback["exists"] = True
            fallback["dbError"] = payload["error"]
            return fallback
        columns = {
            str(row["name"])
            for row in conn.execute("PRAGMA table_info(runtime_agents)").fetchall()
            if row["name"]
        }
        required = {
            "agent_id", "runtime", "status", "platform", "execution_adapter",
            "can_receive_dispatch", "can_start_workflow", "gateway_proxy_allowed", "endpoint_ref",
        }
        missing_required = sorted(required - columns)
        payload["requiredColumns"] = sorted(required)
        payload["missingRequiredColumns"] = missing_required
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
            fallback = workflow_runtime_registry_snapshot_records("runtime_agents_columns_missing")
            fallback["dbFile"] = str(WORKFLOW_DB)
            fallback["exists"] = True
            fallback["dbError"] = payload["error"]
            return fallback
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
        identities = [str(item.get("agent_id") or "").strip() for item in payload["records"]]
        complete_rows = all(
            identity
            and str(item.get("runtime") or "").strip()
            and str(item.get("status") or "").strip()
            and str(item.get("platform") or "").strip()
            and str(item.get("execution_adapter") or "").strip()
            and str(item.get("endpoint_ref") or "").strip()
            and all(item.get(key) in (0, 1, False, True) for key in (
                "can_receive_dispatch", "can_start_workflow", "gateway_proxy_allowed"
            ))
            for item in payload["records"]
        )
        payload["duplicateAgentIds"] = sorted({value for value in identities if value and identities.count(value) > 1})
        payload["writeEligible"] = not missing_required and complete_rows and not payload["duplicateAgentIds"]
        payload["health"] = "healthy" if payload["writeEligible"] else "incomplete"
        if not payload["writeEligible"]:
            payload["error"] = "runtime_agents schema or records are incomplete for lifecycle scope"
        conn.close()
    except Exception as exc:
        payload["error"] = type(exc).__name__
        fallback = workflow_runtime_registry_snapshot_records("workflow_db_error")
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
        payload["error"] = type(exc).__name__
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
    policy = generation_compatible_payload(POLICY_PATH, latest, latest.get("policy"))
    lanes = generation_compatible_payload(LANE_POLICY_PATH, latest, policy.get("lanes"))
    desired = latest.get("desiredState") if isinstance(latest.get("desiredState"), dict) else desired_state_drift()
    findings = latest.get("findings") if isinstance(latest.get("findings"), list) else []
    actions = latest.get("actions") if isinstance(latest.get("actions"), list) else []
    auth = latest.get("auth") if isinstance(latest.get("auth"), dict) else {}
    auth_maintenance = generation_compatible_payload(AUTH_MAINTENANCE_PLAN_PATH, latest, latest.get("authMaintenance"))
    resource_human_gate = load_json(RESOURCE_HUMAN_GATE_DIR / "gateway-resource-pressure-latest.json", {}) or {}
    current_keys = {str(item.get("key")) for item in findings if isinstance(item, dict)}
    resource_gate_active = bool(resource_pressure_active(current_keys))
    resource_gate_generated_at = resource_human_gate.get("generatedAt")
    return {
        "schemaVersion": 1,
        "generationId": latest.get("generationId"),
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
            "status": resource_human_gate.get("status") if resource_gate_active else "inactive",
            "generatedAt": resource_gate_generated_at if resource_gate_active else None,
            "lastGeneratedAt": resource_gate_generated_at,
            "severity": resource_human_gate.get("severity") if resource_gate_active else None,
            "mode": resource_human_gate.get("mode") if resource_gate_active else None,
            "triggerKeys": (resource_human_gate.get("triggerKeys") or []) if resource_gate_active else [],
            "inactiveReason": None if resource_gate_active else "no_current_resource_pressure",
            "jsonPath": str(RESOURCE_HUMAN_GATE_DIR / "gateway-resource-pressure-latest.json"),
            "markdownPath": str(RESOURCE_HUMAN_GATE_DIR / "gateway-resource-pressure-latest.md"),
            "incidentPath": str(RESOURCE_INCIDENT_LATEST),
        },
        "authReadiness": {
            "checkedAt": auth.get("checkedAt"),
            "warnSeconds": auth.get("warnSeconds"),
            "criticalSeconds": auth.get("criticalSeconds"),
            "codexCli": {
                "exists": ((auth.get("codexCli") or {}).get("exists") if isinstance(auth.get("codexCli"), dict) else None),
                "freshestAccessTokenExpiresAt": ((auth.get("codexCli") or {}).get("freshestAccessTokenExpiresAt") if isinstance(auth.get("codexCli"), dict) else None),
                "freshestAccessTokenSecondsRemaining": ((auth.get("codexCli") or {}).get("freshestAccessTokenSecondsRemaining") if isinstance(auth.get("codexCli"), dict) else None),
                "hasRefreshToken": ((auth.get("codexCli") or {}).get("hasRefreshToken") if isinstance(auth.get("codexCli"), dict) else None),
            },
            "hermersProfileCount": (((auth.get("hermers") or {}).get("profileCount")) if isinstance(auth.get("hermers"), dict) else None),
            "openclawAgentCount": (((auth.get("openclaw") or {}).get("agentCount")) if isinstance(auth.get("openclaw"), dict) else None),
        },
        "authMaintenance": {
            "generatedAt": auth_maintenance.get("generatedAt"),
            "status": auth_maintenance.get("status"),
            "severity": auth_maintenance.get("severity"),
            "refreshBrokerEnabled": bool(auth_maintenance.get("refreshBrokerEnabled")),
            "actionCount": auth_maintenance.get("actionCount"),
            "humanGateActionCount": auth_maintenance.get("humanGateActionCount"),
            "blockedActionCount": auth_maintenance.get("blockedActionCount"),
        },
        "catBrainConsumption": {
            "agentId": "main",
            "heartbeatUse": "Read this evidence before 30min semantic governance checks, daily-report, and 8H report; OAuth/auth readiness is part of stability governance.",
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
    auth_readiness = evidence.get("authReadiness") if isinstance(evidence.get("authReadiness"), dict) else {}
    auth_maintenance = evidence.get("authMaintenance") if isinstance(evidence.get("authMaintenance"), dict) else {}
    lines = [
        "# Cat Agents Stability Evidence",
        "",
        f"- generationId: {evidence.get('generationId')}",
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
    lines.extend(["", "## OAuth / Auth Readiness"])
    if auth_readiness:
        codex_cli = auth_readiness.get("codexCli") if isinstance(auth_readiness.get("codexCli"), dict) else {}
        lines.append(f"- checkedAt: {auth_readiness.get('checkedAt')}")
        lines.append(f"- codexCli.exists: {codex_cli.get('exists')}")
        lines.append(f"- codexCli.hasRefreshToken: {codex_cli.get('hasRefreshToken')}")
        lines.append(f"- codexCli.freshestAccessTokenExpiresAt: {codex_cli.get('freshestAccessTokenExpiresAt')}")
        lines.append(f"- hermersProfileCount: {auth_readiness.get('hermersProfileCount')}")
        lines.append(f"- openclawAgentCount: {auth_readiness.get('openclawAgentCount')}")
    else:
        lines.append("- none")
    lines.extend(["", "## OAuth / Auth Maintenance"])
    if auth_maintenance:
        lines.append(f"- generatedAt: {auth_maintenance.get('generatedAt')}")
        lines.append(f"- status: {auth_maintenance.get('status')}")
        lines.append(f"- severity: {auth_maintenance.get('severity')}")
        lines.append(f"- refreshBrokerEnabled: {auth_maintenance.get('refreshBrokerEnabled')}")
        lines.append(f"- actionCount: {auth_maintenance.get('actionCount')}")
        lines.append(f"- humanGateActionCount: {auth_maintenance.get('humanGateActionCount')}")
        lines.append(f"- blockedActionCount: {auth_maintenance.get('blockedActionCount')}")
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
    evidence["written"] = True
    evidence["jsonPath"] = str(WORKFLOW_STABILITY_EVIDENCE_JSON)
    evidence["markdownPath"] = str(WORKFLOW_STABILITY_EVIDENCE_MD)
    markdown_meta = write_text_atomic(WORKFLOW_STABILITY_EVIDENCE_MD, render_workflow_stability_evidence_md(evidence))
    evidence["markdownSha256"] = markdown_meta["sha256"]
    # JSON is the evidence commit marker and is replaced only after Markdown is durable.
    write_json_atomic(WORKFLOW_STABILITY_EVIDENCE_JSON, evidence)
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
        return {"error": type(exc).__name__}
    data: Dict[str, Any] = {"exitCode": out.returncode}
    if out.returncode != 0:
        data["stderrOmitted"] = True
        data["stderrByteCount"] = len(out.stderr or "")
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


def _process_argv(command: str) -> List[str]:
    """Parse ps command text conservatively; malformed quoting is not executable evidence."""
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return []


def _codex_process_class(command: str) -> Dict[str, Optional[str]]:
    """Classify a direct Codex executable invocation without matching argument text."""
    argv = _process_argv(command)
    if not argv:
        return {"kind": "other", "executable": None, "launcher": None}

    executable_index = 0
    launcher = "native"
    executable = os.path.basename(argv[0])
    if executable in {"node", "nodejs"}:
        launcher = "node"
        node_value_options = {
            "-r", "--require", "--loader", "--experimental-loader", "--import",
            "-C", "--conditions", "--inspect-port", "--debug-port",
        }
        node_boolean_options = {
            "--enable-source-maps", "--no-warnings", "--trace-warnings",
            "--inspect", "--inspect-brk", "--inspect-wait", "--experimental-strip-types",
        }
        index = 1
        while index < len(argv) and argv[index].startswith("-"):
            option = argv[index]
            if option.split("=", 1)[0] in {"-e", "--eval", "-p", "--print", "-c", "--check", "--test"}:
                return {"kind": "other", "executable": executable, "launcher": launcher}
            if option in node_value_options:
                index += 2
            elif option in node_boolean_options or option.startswith("--") and "=" in option:
                index += 1
            else:
                return {"kind": "other", "executable": executable, "launcher": launcher}
        executable_index = index
        if executable_index >= len(argv) or os.path.basename(argv[executable_index]) not in {
            "codex.js", "codex.mjs", "codex.cjs",
        }:
            return {"kind": "other", "executable": executable, "launcher": launcher}
    elif executable not in {"codex", "codex-cli"}:
        return {"kind": "other", "executable": executable, "launcher": None}

    codex_executable = argv[executable_index]
    args = argv[executable_index + 1 :]
    value_options = {
        "-c", "--config", "-m", "--model", "-p", "--profile",
        "-s", "--sandbox", "-a", "--ask-for-approval", "-C", "--cd",
        "--enable", "--disable", "--add-dir", "--local-provider",
    }
    boolean_options = {
        "--oss", "--search", "--no-alt-screen", "--full-auto",
        "--dangerously-bypass-approvals-and-sandbox", "--dangerously-bypass-hook-trust",
    }
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-"):
            break
        if arg in value_options:
            index += 2
        elif arg in boolean_options or "=" in arg:
            index += 1
        else:
            return {"kind": "codex_helper", "executable": codex_executable, "launcher": launcher}

    kind = "codex_app_server" if index < len(args) and args[index] == "app-server" else "codex_helper"
    return {"kind": kind, "executable": codex_executable, "launcher": launcher}


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
    classified = [(row, _codex_process_class(row["cmd"])) for row in children]
    codex_app_servers = [row for row, item in classified if item["kind"] == "codex_app_server"]
    codex_helpers = [row for row, item in classified if item["kind"] == "codex_helper"]
    openclaw_children = [r for r in children if "openclaw" in r["cmd"]]
    owner_candidates = [
        {
            "pid": row["pid"],
            "ppid": row["ppid"],
            "kind": item["kind"],
            "executable": os.path.basename(item["executable"] or "") or None,
            "launcher": item["launcher"],
        }
        for row, item in classified
        if item["kind"] in {"codex_app_server", "codex_helper"}
    ]
    public_children = []
    for row, classification in classified:
        public_children.append({
            "pid": row["pid"], "ppid": row["ppid"], "stat": row["stat"],
            "etime": row["etime"], "rssKb": row["rssKb"],
            "processKind": classification["kind"],
            "executable": os.path.basename(classification.get("executable") or "") or None,
            "launcher": classification.get("launcher"),
        })
    return {
        "count": len(children),
        "codexAppServers": len(codex_app_servers),
        "openclawChildren": len(openclaw_children),
        "processClassCounts": {
            "codexAppServer": len(codex_app_servers),
            "codexHelper": len(codex_helpers),
            "other": len(children) - len(codex_app_servers) - len(codex_helpers),
        },
        "ownerCandidates": owner_candidates,
        "classification": "argv executable plus first Codex subcommand; shell and search argument text are excluded",
        "sample": public_children[:20],
    }


def gateway_collect(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    global _inspection_gateway_context
    service = systemctl_show_gateway()
    active = service.get("ActiveState") == "active" and service.get("SubState") == "running"
    pid = int(service.get("MainPID") or 0)
    port_ok = tcp_ok(PORT)
    http_health = gateway_http_health(PORT, timeout=8) if port_ok else {"healthOk": False, "readyzOk": False, "ok": False}
    health_ok = bool(http_health.get("ok"))
    _inspection_gateway_context = (pid, bool(active and port_ok and health_ok))
    version = collect_openclaw_version()
    service_age = None
    start_epoch = parse_iso_epoch(service.get("ExecMainStartTimestamp"))
    if start_epoch:
        service_age = max(0, epoch() - start_epoch)
    in_grace = startup_grace_active(service_age, STARTUP_GRACE_SECONDS)
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
        "nodeGeneration": current_host_generation(),
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


def current_host_generation() -> Optional[str]:
    """Return a boot-bound local node generation; unavailable platforms fail closed."""
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        node = platform.node().strip()
    except (OSError, UnicodeError):
        return None
    if not node or not re.fullmatch(r"[0-9a-fA-F-]{16,64}", boot_id):
        return None
    return f"{node}:{boot_id.lower()}"


def systemctl_user_show(unit: str) -> Dict[str, Any]:
    props = "ActiveState,SubState,MainPID,NRestarts,ExecMainStartTimestamp,MemoryCurrent,TasksCurrent"
    try:
        out = run_user_cmd(["systemctl", "--user", "show", unit, f"--property={props}"], timeout=8)
    except Exception as exc:
        return {"unit": unit, "error": type(exc).__name__}
    data: Dict[str, Any] = {"unit": unit, "exitCode": out.returncode}
    if out.returncode != 0:
        data["stderrOmitted"] = True
        data["stderrByteCount"] = len(out.stderr or "")
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
        item = {key: row.get(key) for key in ("pid", "ppid", "stat", "etime", "rssKb")}
        item["processType"] = "hermes-gateway"
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
        item = {key: row.get(key) for key in ("pid", "ppid", "stat", "etime", "rssKb")}
        item["profile"] = profile
        item["ageSeconds"] = etime_seconds(row.get("etime"))
        item["orphan"] = str(row.get("ppid") or "") == "1"
        try:
            item["processIdentity"] = read_process_identity(int(row.get("pid") or 0))
        except (TypeError, ValueError):
            item["processIdentity"] = {"status": "unknown", "reason": "invalid-pid"}
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
        item = {key: row.get(key) for key in ("pid", "ppid", "stat", "etime", "rssKb")}
        item["profile"] = profile
        item["processType"] = "pyright-langserver"
        item["ageSeconds"] = etime_seconds(row.get("etime"))
        item["cpuTicks"] = proc_cpu_ticks(pid)
        item["processIdentity"] = read_process_identity(pid)
        with contextlib.suppress(Exception):
            item["rssBytes"] = int(row.get("rssKb") or "0") * 1024
        processes.append(item)
    return processes


def update_hermers_lsp_idle_state(
    conn: sqlite3.Connection, processes: List[Dict[str, Any]], *, persist: bool = True,
    cache_updates: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
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
            updated[key] = {
                field: old.get(field)
                for field in ("profile", "pid", "cpuTicks", "idleSinceEpoch", "lastSeenEpoch")
                if field in old
            }
    if persist:
        db_set(conn, "hermers_lsp_idle_state", updated)
    elif cache_updates is not None:
        cache_updates["hermers_lsp_idle_state"] = updated
    return enriched


def hermers_profile_agent_ids(profile: str) -> set[str]:
    return set()


def runtime_record_can_receive(record: Dict[str, Any]) -> bool:
    value = record.get("can_receive_dispatch")
    if value is None:
        return False
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
    if "openclaw_route_shell" in values:
        return False
    hermers_like = bool({"hermers", "hermes", "hermes_acp", "hermers_acp"} & values)
    acp_like = bool({"acp", "hermes_acp", "hermers_acp"} & values or (endpoint_profile and hermers_like))
    return hermers_like and acp_like


def hermers_profiles_from_runtime_registry(
    findings: List[Dict[str, Any]], registry: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    registry = registry if isinstance(registry, dict) else workflow_runtime_registry_records()
    records = registry.get("records") if isinstance(registry.get("records"), list) else []
    profiles: Dict[str, Dict[str, Any]] = {}
    unparseable_record_count = 0
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
        if not profile or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", profile):
            unparseable_record_count += 1
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
            "available": True,
            "scopeComplete": bool(registry.get("writeEligible")) and registry.get("source") == "db" and unparseable_record_count == 0,
            "writeEligible": bool(registry.get("writeEligible")) and registry.get("source") == "db",
            "unparseableRecordCount": unparseable_record_count,
            "reason": (
                "active-hermers-endpoint-unparseable" if unparseable_record_count
                else (registry.get("error") or "registry-observation-only") if not registry.get("writeEligible") or registry.get("source") != "db"
                else None
            ),
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
        "available": False,
        "scopeComplete": False,
        "unparseableRecordCount": unparseable_record_count,
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
            item["error"] = type(exc).__name__
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.close()
    return activity


def hermers_profile_is_protected(profile: str, agent_ids: Iterable[str]) -> bool:
    return is_protected_identity({profile, *[str(agent_id) for agent_id in agent_ids if str(agent_id)]}, HERMERS_PROFILE_PROTECTED_IDS)


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
        lifecycle_allowed = (
            hermers_profile_lifecycle_allowed(profile, agent_ids, protected)
            and registry_meta.get("source") == "db"
            and bool(registry_meta.get("writeEligible"))
        )
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
        summary["error"] = type(exc).__name__
    return summary


def hermers_collect(
    conn: sqlite3.Connection, findings: List[Dict[str, Any]], *, persist_cache: bool = True,
    cache_updates: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
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
    for item in acp_workers:
        registry_item = profile_registry.get(str(item.get("profile") or "")) or {}
        item["agentIds"] = sorted(set(registry_item.get("agentIds") or []))
        item["registryProfile"] = str(item.get("profile") or "")
        item["registryProfileMatched"] = bool(registry_item.get("registryRecords"))
        item["registryScopeComplete"] = bool(registry_meta.get("scopeComplete")) and item["registryProfileMatched"]
    if profile_registry:
        lsp_processes = update_hermers_lsp_idle_state(
            conn, hermers_lsp_processes(rows, profile_registry.keys()),
            persist=persist_cache, cache_updates=cache_updates,
        )
        for item in lsp_processes:
            registry_item = profile_registry.get(str(item.get("profile") or "")) or {}
            item["agentIds"] = sorted(set(registry_item.get("agentIds") or []))
            item["registryProfile"] = str(item.get("profile") or "")
            item["registryProfileMatched"] = bool(registry_item.get("registryRecords"))
            item["registryScopeComplete"] = bool(registry_meta.get("scopeComplete")) and item["registryProfileMatched"]
    else:
        if persist_cache:
            db_set(conn, "hermers_lsp_idle_state", {})
        elif cache_updates is not None:
            cache_updates["hermers_lsp_idle_state"] = {}
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
        adapter = str(record.get("execution_adapter") or "").strip()
        can_receive = _snapshot_bool(record.get("can_receive_dispatch"))
        if status != "active":
            continue
        if "openclaw_route_shell" in runtime_record_adapter_values(record):
            continue
        if runtime != "openclaw" or platform != "openclaw" or adapter != "openclaw":
            continue
        if can_receive != 1:
            continue
        agent_id = str(record.get("agent_id") or "").strip()
        if agent_id:
            agent_ids.add(agent_id)
    return sorted(agent_ids)


def openclaw_auth_scope_from_registry(registry: Dict[str, Any]) -> Tuple[List[str], List[Dict[str, Any]]]:
    records = registry.get("records") if isinstance(registry.get("records"), list) else []
    agent_ids = set()
    unaddressable: List[Dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if str(record.get("status") or "").strip() != "active":
            continue
        values = runtime_record_adapter_values(record)
        if "openclaw_route_shell" in values:
            continue
        if (str(record.get("runtime") or "").strip() != "openclaw"
                or str(record.get("platform") or "").strip() != "openclaw"
                or str(record.get("execution_adapter") or "").strip() != "openclaw"):
            continue
        if _snapshot_bool(record.get("can_receive_dispatch")) != 1:
            continue
        agent_id = str(record.get("agent_id") or "").strip()
        endpoint_ref = str(record.get("endpoint_ref") or "").strip()
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", agent_id)
            or endpoint_ref != f"openclaw-agent:{agent_id}"
        ):
            unaddressable.append({
                "agentId": agent_id or None,
                "endpointRef": endpoint_ref or None,
                "runtime": record.get("runtime"),
                "platform": record.get("platform"),
            })
            continue
        agent_ids.add(agent_id)
    return sorted(agent_ids), unaddressable


def add_auth_summary_findings(
    findings: List[Dict[str, Any]],
    *,
    prefix: str,
    component: str,
    label: str,
    summary: Dict[str, Any],
    require_when_active_provider: bool = True,
) -> None:
    status = auth_token_status(summary)
    active_provider = str(summary.get("activeProvider") or "")
    openai_active = active_provider in AUTH_OPENAI_PROVIDER_IDS if active_provider else True
    if require_when_active_provider and active_provider and not openai_active:
        return

    evidence = {
        "label": label,
        "path": summary.get("path"),
        "mode": summary.get("mode"),
        "mtime": summary.get("mtime"),
        "activeProvider": summary.get("activeProvider"),
        "providerKeys": summary.get("providerKeys"),
        "credentialPoolKeys": summary.get("credentialPoolKeys"),
        "accessTokenCount": summary.get("accessTokenCount"),
        "refreshTokenCount": summary.get("refreshTokenCount"),
        "freshestAccessTokenExpiresAt": summary.get("freshestAccessTokenExpiresAt"),
        "freshestAccessTokenSecondsRemaining": summary.get("freshestAccessTokenSecondsRemaining"),
        "expiredAccessTokenCount": summary.get("expiredAccessTokenCount"),
    }
    if status == "missing":
        add_finding(findings, f"{prefix}_oauth_missing", "warning", component, f"{label} OAuth auth file is missing", **evidence)
    elif status == "access-missing":
        add_finding(findings, f"{prefix}_oauth_access_missing", "high", component, f"{label} has no access token", **evidence)
    elif status == "refresh-missing":
        add_finding(findings, f"{prefix}_oauth_refresh_missing", "high", component, f"{label} has no refresh token for durable OAuth", **evidence)
    elif status == "access-expired":
        add_finding(findings, f"{prefix}_oauth_access_expired", "warning", component, f"{label} access token is expired; refresh transaction must be healthy", **evidence)
    elif status == "access-critical":
        add_finding(findings, f"{prefix}_oauth_expires_critical", "warning", component, f"{label} access token expires within {AUTH_CRITICAL_SECONDS}s", **evidence)
    elif status == "access-warning":
        add_finding(findings, f"{prefix}_oauth_expires_soon", "info", component, f"{label} access token expires within {AUTH_WARN_SECONDS}s", **evidence)
    elif status == "access-expiry-unknown":
        add_finding(findings, f"{prefix}_oauth_expiry_unknown", "warning", component, f"{label} access token expiry could not be decoded", **evidence)


def openclaw_oauth_provider_groups(profiles: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, Dict[str, Any]] = {}
    for profile in profiles or []:
        if not isinstance(profile, dict):
            continue
        provider = str(profile.get("provider") or profile.get("profileKind") or "")
        if provider not in AUTH_OPENAI_PROVIDER_IDS:
            continue
        group = groups.setdefault(provider, {"provider": provider, "profiles": []})
        group["profiles"].append(profile)

    for provider, group in groups.items():
        parsed = [item for item in group["profiles"] if item.get("secondsRemaining") is not None]
        parsed.sort(key=lambda item: int(item.get("secondsRemaining") or 0), reverse=True)
        freshest = parsed[0] if parsed else None
        stale_expired = [
            item for item in parsed[1:]
            if int(item.get("secondsRemaining") or 0) <= 0
        ]
        unparseable = [
            item for item in group["profiles"]
            if not bool(item.get("expiryParseOk", True)) or item.get("secondsRemaining") is None
        ]
        group["freshest"] = freshest
        group["staleExpiredProfiles"] = stale_expired
        group["unparseableProfiles"] = unparseable
        group["profileCount"] = len(group["profiles"])
    return groups


def hermers_openai_auth_candidate(summary: Dict[str, Any]) -> bool:
    active_provider = str(summary.get("activeProvider") or "")
    if active_provider:
        return active_provider in AUTH_OPENAI_PROVIDER_IDS
    provider_keys = {str(item) for item in (summary.get("providerKeys") or [])}
    if provider_keys:
        return bool(provider_keys & AUTH_OPENAI_PROVIDER_IDS)
    return True


def openclaw_required_provider_present(required: Iterable[str], available: Iterable[str]) -> bool:
    available_ids = {str(item) for item in available}
    aliases = {"openai-codex": "openai", "openai": "openai-codex"}
    for provider in required:
        provider_id = str(provider)
        if provider_id in available_ids or aliases.get(provider_id) in available_ids:
            return True
    return False


def auth_finding_is_pressure(key: str) -> bool:
    if not key.startswith(("codex_cli_oauth_", "openclaw_oauth_", "hermers_oauth_", "hermers_cat")):
        return False
    if key in {"openclaw_oauth_profile_expires_soon", "openclaw_oauth_stale_profile_copies"}:
        return False
    return not key.endswith("_expires_soon")


def auth_collect(
    conn: sqlite3.Connection,
    findings: List[Dict[str, Any]],
    hermers_profiles: Optional[Iterable[str]] = None,
    *,
    force_openclaw_probe: bool = False,
    persist_probe_cache: bool = True,
    cache_updates: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    codex_cli = summarize_auth_json(CODEX_AUTH_PATH)
    add_auth_summary_findings(
        findings,
        prefix="codex_cli",
        component="auth",
        label="Codex CLI",
        summary=codex_cli,
        require_when_active_provider=False,
    )

    registry = workflow_runtime_registry_records()
    hermers_registry_profiles, hermers_registry_meta = hermers_profiles_from_runtime_registry(findings, registry)
    profile_names = sorted(hermers_registry_profiles)
    requested_hermers_profiles = sorted({str(item) for item in hermers_profiles or [] if str(item)})
    unregistered_hermers_profiles = sorted(set(requested_hermers_profiles) - set(profile_names))
    if unregistered_hermers_profiles:
        add_finding(
            findings,
            "hermers_auth_requested_profile_not_in_registry",
            "warning",
            "auth",
            "Hermers auth inspection input contains profiles outside the active runtime_agents registry",
            profileIds=unregistered_hermers_profiles,
            registrySource=registry.get("source"),
        )
    hermers_auth: Dict[str, Any] = {}
    hermers_drift_samples: List[Dict[str, Any]] = []
    for profile in profile_names:
        auth_path = HERMES_HOME / "profiles" / profile / "auth.json"
        summary = summarize_auth_json(auth_path)
        hermers_auth[profile] = summary
        add_auth_summary_findings(
            findings,
            prefix=f"hermers_{profile}",
            component="auth",
            label=f"Hermers profile {profile}",
            summary=summary,
        )
        spread = int(summary.get("accessTokenExpirySpreadSeconds") or 0)
        expired_count = int(summary.get("expiredAccessTokenCount") or 0)
        access_count = int(summary.get("accessTokenCount") or 0)
        if access_count > 1 and (spread > 3600 or expired_count > 0):
            hermers_drift_samples.append(
                {
                    "profile": profile,
                    "accessTokenCount": access_count,
                    "expiredAccessTokenCount": expired_count,
                    "oldestAccessTokenExpiresAt": summary.get("oldestAccessTokenExpiresAt"),
                    "freshestAccessTokenExpiresAt": summary.get("freshestAccessTokenExpiresAt"),
                    "spreadSeconds": spread,
                }
            )
    if hermers_drift_samples:
        add_finding(
            findings,
            "hermers_oauth_token_copy_drift",
            "warning",
            "auth",
            "Hermers profile auth files contain multiple openai-codex token copies with divergent expiry",
            count=len(hermers_drift_samples),
            sample=hermers_drift_samples[:10],
        )

    registry_openclaw_agent_ids, unaddressable_openclaw_rows = openclaw_auth_scope_from_registry(registry)
    if unaddressable_openclaw_rows:
        add_finding(
            findings,
            "openclaw_auth_registry_rows_unaddressable",
            "warning",
            "auth",
            "Active OpenClaw runtime_agents rows without a valid runtime-owned endpoint were excluded from auth targets",
            rows=unaddressable_openclaw_rows[:20],
            registrySource=registry.get("source"),
        )
    if "main" not in registry_openclaw_agent_ids:
        add_finding(
            findings,
            "openclaw_auth_registry_missing_main",
            "warning",
            "auth",
            "OpenClaw main is missing from the active runtime_agents auth scope",
            registryAgentIds=registry_openclaw_agent_ids,
            registrySource=registry.get("source"),
        )
    if "main" in registry_openclaw_agent_ids:
        openclaw_agent_ids = ["main", *[item for item in registry_openclaw_agent_ids if item != "main"]]
    else:
        openclaw_agent_ids = list(registry_openclaw_agent_ids)
    requested_openclaw_agent_count = len(openclaw_agent_ids)
    unregistered_requested_ids = sorted(set(AUTH_OPENCLAW_AGENT_IDS) - set(registry_openclaw_agent_ids))
    if unregistered_requested_ids:
        add_finding(
            findings,
            "openclaw_auth_requested_agent_not_in_registry",
            "warning",
            "auth",
            "Explicit OpenClaw auth monitor IDs are not present in the active runtime_agents registry",
            agentIds=unregistered_requested_ids,
            registrySource=registry.get("source"),
        )
    if not openclaw_agent_ids:
        add_finding(
            findings,
            "openclaw_auth_registry_unavailable",
            "warning",
            "auth",
            "OpenClaw auth scope could not be derived from active runtime_agents rows",
            registrySource=registry.get("source"),
            registryError=registry.get("error"),
        )
    requested_openclaw_agent_ids = list(openclaw_agent_ids)
    openclaw_agent_ids = openclaw_agent_ids[: max(1, AUTH_OPENCLAW_AGENT_LIMIT)]
    omitted_openclaw_agent_ids = sorted(set(requested_openclaw_agent_ids) - set(openclaw_agent_ids))
    if omitted_openclaw_agent_ids:
        add_finding(
            findings,
            "openclaw_oauth_probe_scope_truncated",
            "warning",
            "auth",
            "OpenClaw auth probe limit excludes active runtime_agents targets",
            omittedAgentIds=omitted_openclaw_agent_ids,
            requestedAgentCount=requested_openclaw_agent_count,
            probeLimit=AUTH_OPENCLAW_AGENT_LIMIT,
        )
    openclaw_auth: Dict[str, Any] = {}
    expired_profiles: List[Dict[str, Any]] = []
    expiring_profiles: List[Dict[str, Any]] = []
    stale_profile_copies: List[Dict[str, Any]] = []
    missing_codex_profiles: List[Dict[str, Any]] = []
    unparsed_profiles: List[Dict[str, Any]] = []
    for agent_id in openclaw_agent_ids:
        probe = cached_openclaw_auth_probe(
            conn, agent_id, force=force_openclaw_probe,
            persist=persist_probe_cache, cache_updates=cache_updates,
        )
        openclaw_auth[agent_id] = probe
        if not bool(probe.get("available")):
            add_finding(
                findings,
                "openclaw_oauth_probe_failed",
                "warning",
                "auth",
                "OpenClaw auth profile probe failed",
                agentId=agent_id,
                error=probe.get("error"),
                cached=probe.get("cached"),
            )
            continue
        if int(probe.get("unparsedProfileLineCount") or 0) > 0:
            unparsed_profiles.append(
                {
                    "agentId": agent_id,
                    "count": int(probe.get("unparsedProfileLineCount") or 0),
                    "sample": probe.get("unparsedProfileLines") or [],
                    "cached": probe.get("cached"),
                }
            )
        provider_groups = openclaw_oauth_provider_groups(probe.get("profiles") or [])
        if agent_id == "main" and AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS and not openclaw_required_provider_present(AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS, provider_groups):
            missing_codex_profiles.append({"agentId": agent_id, "requiredProviders": sorted(AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS), "providers": sorted(provider_groups)})
        for group in provider_groups.values():
            for item in group.get("unparseableProfiles") or []:
                unparsed_profiles.append(
                    {
                        "agentId": agent_id,
                        "provider": item.get("provider"),
                        "profileKind": item.get("profileKind"),
                        "reason": "expiry-unparseable",
                        "cached": probe.get("cached"),
                    }
                )
            item = group.get("freshest")
            if not isinstance(item, dict):
                continue
            remaining = item.get("secondsRemaining")
            sample = {
                "agentId": agent_id,
                "provider": item.get("provider"),
                "profileKind": item.get("profileKind"),
                "expiresAt": item.get("expiresAt"),
                "secondsRemaining": remaining,
                "cooldownUntil": item.get("cooldownUntil"),
                "cached": probe.get("cached"),
                "profileCount": group.get("profileCount"),
                "staleExpiredProfileCount": len(group.get("staleExpiredProfiles") or []),
            }
            if remaining is not None and int(remaining) <= 0:
                expired_profiles.append(sample)
            elif remaining is not None and int(remaining) <= AUTH_WARN_SECONDS:
                expiring_profiles.append(sample)
            elif group.get("staleExpiredProfiles"):
                stale_profile_copies.append(
                    {
                        **sample,
                    }
                )
    if missing_codex_profiles:
        add_finding(
            findings,
            "openclaw_oauth_required_provider_missing",
            "warning",
            "auth",
            "OpenClaw main has no required OAuth provider profile",
            count=len(missing_codex_profiles),
            sample=missing_codex_profiles[:10],
        )
    if unparsed_profiles:
        add_finding(
            findings,
            "openclaw_oauth_profile_parse_incomplete",
            "warning",
            "auth",
            "OpenClaw OAuth profile output was partially unparseable",
            count=len(unparsed_profiles),
            sample=unparsed_profiles[:10],
        )
    if expired_profiles:
        add_finding(
            findings,
            "openclaw_oauth_profile_expired",
            "high",
            "auth",
            "OpenClaw OAuth profiles are expired",
            count=len(expired_profiles),
            sample=expired_profiles[:10],
        )
    if expiring_profiles:
        add_finding(
            findings,
            "openclaw_oauth_profile_expires_soon",
            "warning",
            "auth",
            "OpenClaw OAuth profiles expire soon",
            count=len(expiring_profiles),
            sample=expiring_profiles[:10],
        )
    if stale_profile_copies:
        add_finding(
            findings,
            "openclaw_oauth_stale_profile_copies",
            "warning",
            "auth",
            "OpenClaw OAuth has stale expired profile copies but the freshest provider token is still valid",
            count=len(stale_profile_copies),
            sample=stale_profile_copies[:10],
        )

    return {
        "schemaVersion": 1,
        "checkedAt": ts(),
        "warnSeconds": AUTH_WARN_SECONDS,
        "criticalSeconds": AUTH_CRITICAL_SECONDS,
        "codexCli": codex_cli,
        "hermers": {
            "profileSource": "runtime_agents",
            "profileRegistry": hermers_registry_meta,
            "registryAgentProfiles": profile_names,
            "scopeComplete": bool(hermers_registry_meta.get("scopeComplete"))
            and not unregistered_hermers_profiles,
            "unregisteredRequestedProfiles": unregistered_hermers_profiles,
            "profileCount": len(hermers_auth),
            "profiles": hermers_auth,
        },
        "openclaw": {
            "agentCount": len(openclaw_auth),
            "requestedAgentCount": requested_openclaw_agent_count,
            "registryAgentIds": requested_openclaw_agent_ids,
            "unaddressableRegistryRows": unaddressable_openclaw_rows,
            "probeAgentIds": openclaw_agent_ids,
            "omittedAgentIds": omitted_openclaw_agent_ids,
            "scopeComplete": bool(requested_openclaw_agent_ids)
            and registry.get("source") == "db"
            and bool(registry.get("writeEligible"))
            and "main" in requested_openclaw_agent_ids
            and not omitted_openclaw_agent_ids
            and not unregistered_requested_ids
            and not unparsed_profiles
            and all(
                isinstance(openclaw_auth.get(agent_id), dict)
                and openclaw_auth[agent_id].get("available") is True
                for agent_id in openclaw_agent_ids
            ),
            "scopeIncompleteReason": (
                "main-not-registered" if "main" not in requested_openclaw_agent_ids
                else "runtime-registry-not-write-eligible" if registry.get("source") != "db" or not registry.get("writeEligible")
                else "probe-limit-exceeded" if omitted_openclaw_agent_ids
                else "unregistered-requested-target" if unregistered_requested_ids
                else "openclaw-probe-unavailable-or-partial" if unparsed_profiles
                or any(
                    not isinstance(openclaw_auth.get(agent_id), dict)
                    or openclaw_auth[agent_id].get("available") is not True
                    for agent_id in openclaw_agent_ids
                )
                else None
            ),
            "agentLimit": AUTH_OPENCLAW_AGENT_LIMIT,
            "agents": openclaw_auth,
            "registrySource": registry.get("source"),
            "registryDbFile": registry.get("dbFile"),
            "probeTtlSeconds": AUTH_OPENCLAW_PROBE_TTL_SECONDS,
            "nearExpiryProbeTtlSeconds": AUTH_OPENCLAW_PROBE_NEAR_TTL_SECONDS,
            "urgentProbeTtlSeconds": AUTH_OPENCLAW_PROBE_URGENT_TTL_SECONDS,
            "urgentProbeWindowSeconds": AUTH_OPENCLAW_PROBE_URGENT_WINDOW_SECONDS,
            "probeErrorTtlSeconds": AUTH_OPENCLAW_PROBE_ERROR_TTL_SECONDS,
            "probeTimeoutSeconds": AUTH_OPENCLAW_PROBE_TIMEOUT_SECONDS,
            "requiredProviders": sorted(AUTH_OPENCLAW_REQUIRED_PROVIDER_IDS),
        },
    }


def auth_maintenance_action(
    actions: List[Dict[str, Any]],
    *,
    action_id: str,
    target: str,
    kind: str,
    severity: str,
    reason: str,
    can_auto_run: bool = False,
    human_gate_required: bool = False,
    mac_mirror_eligible: bool = False,
    evidence: Optional[Dict[str, Any]] = None,
) -> None:
    base_action_id = action_id
    existing = {str(item.get("actionId") or "") for item in actions}
    suffix = 2
    while action_id in existing:
        action_id = f"{base_action_id}-{suffix}"
        suffix += 1
    server_can_auto_run = bool(can_auto_run and AUTH_REFRESH_BROKER_ENABLED)
    blocked_reason = (
        ""
        if server_can_auto_run
        else "delegated-to-mac-codex"
        if mac_mirror_eligible and not human_gate_required
        else "refresh-broker-disabled"
        if can_auto_run
        else "manual-or-runtime-owned"
    )
    actions.append(
        {
            "actionId": action_id,
            "source": "cat-agents-stabilityd.auth-maintenance",
            "target": target,
            "kind": kind,
            "severity": severity,
            "reason": reason,
            "canAutoRun": server_can_auto_run,
            "blockedReason": blocked_reason,
            "humanGateRequired": bool(human_gate_required),
            "localAutomation": {
                "eligible": bool(mac_mirror_eligible and not human_gate_required),
                "owner": "mac-codex",
                "mode": "access-id-token-mirror",
            },
            "tokenValuesRedacted": True,
            "evidence": evidence or {},
        }
    )


def build_auth_maintenance_plan(auth: Dict[str, Any], findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    finding_items = [item for item in findings if isinstance(item, dict) and item.get("component") == "auth"]
    finding_keys = {str(item.get("key") or "") for item in finding_items}
    actions: List[Dict[str, Any]] = []
    codex_cli = auth.get("codexCli") if isinstance(auth.get("codexCli"), dict) else {}
    codex_status = auth_token_status(codex_cli)
    if codex_status in {"access-expired", "access-critical"} and codex_cli.get("hasRefreshToken"):
        auth_maintenance_action(
            actions,
            action_id="codex_cli_mirror_required",
            target="codex-cli",
            kind="mirror-from-mac-codex",
            severity="high" if codex_status == "access-expired" else "warning",
            reason=f"Codex CLI OAuth status is {codex_status}; mirror a fresh access/id token from mac-codex",
            can_auto_run=False,
            human_gate_required=False,
            mac_mirror_eligible=True,
            evidence={
                "freshestAccessTokenExpiresAt": codex_cli.get("freshestAccessTokenExpiresAt"),
                "freshestAccessTokenSecondsRemaining": codex_cli.get("freshestAccessTokenSecondsRemaining"),
                "authPath": codex_cli.get("path"),
                "refreshOwner": "mac-codex",
            },
        )
    elif codex_status in {"missing", "access-missing", "refresh-missing", "access-expiry-unknown"}:
        auth_maintenance_action(
            actions,
            action_id="codex_cli_reauth_required",
            target="codex-cli",
            kind="reauth",
            severity="high",
            reason=f"Codex CLI OAuth status is {codex_status}",
            can_auto_run=False,
            human_gate_required=True,
            evidence={"authPath": codex_cli.get("path"), "status": codex_status},
        )

    openclaw = auth.get("openclaw") if isinstance(auth.get("openclaw"), dict) else {}
    openclaw_agents = openclaw.get("agents") if isinstance(openclaw.get("agents"), dict) else {}
    if openclaw.get("scopeComplete") is False:
        auth_maintenance_action(
            actions,
            action_id="openclaw_registry_auth_scope_incomplete",
            target="openclaw:runtime-registry-scope",
            kind="scope-repair",
            severity="warning",
            reason="OpenClaw auth targets are incomplete relative to the active runtime_agents registry",
            can_auto_run=False,
            human_gate_required=True,
            evidence={
                "registryAgentIds": openclaw.get("registryAgentIds"),
                "probeAgentIds": openclaw.get("probeAgentIds"),
                "omittedAgentIds": openclaw.get("omittedAgentIds"),
                "unaddressableRegistryRows": openclaw.get("unaddressableRegistryRows"),
                "scopeIncompleteReason": openclaw.get("scopeIncompleteReason"),
                "registrySource": openclaw.get("registrySource"),
            },
        )
    hermers_auth_scope = auth.get("hermers") if isinstance(auth.get("hermers"), dict) else {}
    hermers_registry = hermers_auth_scope.get("profileRegistry")
    if hermers_auth_scope.get("scopeComplete") is False:
        auth_maintenance_action(
            actions,
            action_id="hermers_runtime_profile_registry_unavailable",
            target="hermers:runtime-registry",
            kind="scope-repair",
            severity="warning",
            reason="Hermers OAuth profile targets could not be derived from active runtime_agents rows",
            can_auto_run=False,
            human_gate_required=True,
            evidence={
                "registrySource": hermers_registry.get("source") if isinstance(hermers_registry, dict) else None,
                "registryError": hermers_registry.get("reason") if isinstance(hermers_registry, dict) else None,
                "dbFile": hermers_registry.get("dbFile") if isinstance(hermers_registry, dict) else None,
                "unparseableRecordCount": hermers_registry.get("unparseableRecordCount") if isinstance(hermers_registry, dict) else None,
                "registryAgentProfiles": hermers_auth_scope.get("registryAgentProfiles"),
                "unregisteredRequestedProfiles": hermers_auth_scope.get("unregisteredRequestedProfiles"),
            },
        )
    for agent_id, probe in sorted(openclaw_agents.items()):
        if not isinstance(probe, dict):
            continue
        if not probe.get("available"):
            auth_maintenance_action(
                actions,
                action_id=f"openclaw_{agent_id}_auth_probe_repair",
                target=f"openclaw:{agent_id}",
                kind="probe-repair",
                severity="warning",
                reason="OpenClaw auth probe failed",
                can_auto_run=False,
                human_gate_required=False,
                evidence={"error": probe.get("error")},
            )
            continue
        for provider, group in openclaw_oauth_provider_groups(probe.get("profiles") or []).items():
            profile = group.get("freshest")
            if not isinstance(profile, dict):
                continue
            remaining = profile.get("secondsRemaining")
            if remaining is None or int(remaining) <= AUTH_CRITICAL_SECONDS:
                auth_maintenance_action(
                    actions,
                    action_id=f"openclaw_{agent_id}_{provider}_reauth_or_sync",
                    target=f"openclaw:{agent_id}:{provider}",
                    kind="reauth-or-sync",
                    severity="high" if remaining is not None and int(remaining) <= 0 else "warning",
                    reason="OpenClaw OAuth profile is expired or nearing expiry",
                    can_auto_run=False,
                    human_gate_required=remaining is None,
                    mac_mirror_eligible=remaining is not None and provider in AUTH_OPENAI_PROVIDER_IDS,
                    evidence={
                        "expiresAt": profile.get("expiresAt"),
                        "secondsRemaining": remaining,
                        "cooldownUntil": profile.get("cooldownUntil"),
                        "profileCount": group.get("profileCount"),
                        "staleExpiredProfileCount": len(group.get("staleExpiredProfiles") or []),
                    },
                )

    hermers = auth.get("hermers") if isinstance(auth.get("hermers"), dict) else {}
    hermers_profiles = hermers.get("profiles") if isinstance(hermers.get("profiles"), dict) else {}
    for profile, summary in sorted(hermers_profiles.items()):
        if not isinstance(summary, dict):
            continue
        status = auth_token_status(summary)
        if not hermers_openai_auth_candidate(summary):
            continue
        if status in {"access-expired", "access-critical"} and summary.get("hasRefreshToken"):
            auth_maintenance_action(
                actions,
                action_id=f"hermers_{profile}_token_sync_or_refresh",
                target=f"hermers:{profile}",
                kind="sync-or-refresh",
                severity="warning" if status != "access-expired" else "high",
                reason=f"Hermers profile OAuth status is {status}; refresh token is present",
                can_auto_run=False,
                human_gate_required=False,
                mac_mirror_eligible=True,
                evidence={
                    "activeProvider": summary.get("activeProvider"),
                    "freshestAccessTokenExpiresAt": summary.get("freshestAccessTokenExpiresAt"),
                    "freshestAccessTokenSecondsRemaining": summary.get("freshestAccessTokenSecondsRemaining"),
                },
            )
        elif status in {"missing", "access-missing", "refresh-missing", "access-expiry-unknown"}:
            auth_maintenance_action(
                actions,
                action_id=f"hermers_{profile}_reauth_required",
                target=f"hermers:{profile}",
                kind="reauth",
                severity="high",
                reason=f"Hermers profile OAuth status is {status}",
                can_auto_run=False,
                human_gate_required=True,
                evidence={"activeProvider": summary.get("activeProvider"), "authPath": summary.get("path"), "status": status},
            )

    for finding in finding_items:
        if finding.get("key") != "openclaw_oauth_required_provider_missing":
            continue
        for sample in (finding.get("sample") or [])[:10]:
            if not isinstance(sample, dict):
                continue
            agent_id = str(sample.get("agentId") or "unknown")
            auth_maintenance_action(
                actions,
                action_id=f"openclaw_{agent_id}_required_provider_reauth",
                target=f"openclaw:{agent_id}:required-provider",
                kind="reauth",
                severity="warning",
                reason="OpenClaw required OAuth provider profile is missing",
                can_auto_run=False,
                human_gate_required=True,
                evidence={
                    "requiredProviders": sample.get("requiredProviders"),
                    "providers": sample.get("providers"),
                    "findingKey": "openclaw_oauth_required_provider_missing",
                },
            )

    if "hermers_oauth_token_copy_drift" in finding_keys:
        auth_maintenance_action(
            actions,
            action_id="hermers_token_copy_drift_cleanup",
            target="hermers:*",
            kind="deduplicate-token-copies",
            severity="warning",
            reason="Hermers auth files contain divergent token copies",
            can_auto_run=False,
            human_gate_required=False,
            evidence={"findingKey": "hermers_oauth_token_copy_drift"},
        )

    severity = max_severity(actions)
    status = "action-required" if actions else "ok"
    blocked_count = sum(1 for item in actions if item.get("blockedReason"))
    human_gate_count = sum(1 for item in actions if item.get("humanGateRequired"))
    mirror_targets: Dict[str, Any] = {
        "codexCli": codex_cli.get("exists") is True,
        "hermersProfiles": sorted(
            str(profile)
            for profile, summary in hermers_profiles.items()
            if isinstance(summary, dict) and hermers_openai_auth_candidate(summary)
        ),
        "openclawTargets": [],
    }
    for agent_id, probe in sorted(openclaw_agents.items()):
        if not isinstance(probe, dict) or probe.get("available") is not True:
            continue
        for provider in sorted(openclaw_oauth_provider_groups(probe.get("profiles") or [])):
            mirror_targets["openclawTargets"].append({"agentId": str(agent_id), "profileKind": provider})
    return {
        "schemaVersion": 1,
        "generatedAt": ts(),
        "generatedAtEpochNs": time.time_ns(),
        "status": status,
        "severity": severity,
        "refreshBrokerEnabled": bool(AUTH_REFRESH_BROKER_ENABLED),
        "macCodexExecutor": {
            "supported": True,
            "refreshOwner": "mac-codex",
            "mirrorMode": "access-id-token-mirror",
            "refreshBrokerEnabled": False,
            "targets": mirror_targets,
            "scopeWarnings": {
                "openclawUnaddressableRegistryRows": openclaw.get("unaddressableRegistryRows") or [],
                "hermersUnparseableRegistryRecords": hermers_registry.get("unparseableRecordCount", 0)
                if isinstance(hermers_registry, dict) else 0,
            },
        },
        "tokenValuesRedacted": True,
        "actionCount": len(actions),
        "blockedActionCount": blocked_count,
        "humanGateActionCount": human_gate_count,
        "findingKeys": sorted(finding_keys),
        "actions": actions,
        "notes": [
            "Default mode is observe-only; no device-code login, token copy, or credential mutation is executed by this plan.",
            "mac-codex is the canonical OAuth refresh owner; dev-server runtimes should receive access/id-token mirrors, not reusable refresh tokens.",
            "Mirror candidates marked localAutomation.eligible are executed by the mac-codex adapter; dev-server stabilityd never owns or rotates the refresh token.",
        ],
    }


def redact_auth_text(text: Any, max_chars: int = 2000) -> str:
    return redact_sensitive_text(text, max_chars)

def compact_mirror_summary(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "schemaVersion": value.get("schemaVersion"),
        "status": value.get("status"),
        "artifact": value.get("artifact"),
        "generatedAt": value.get("generatedAt"),
        "targets": value.get("targets"),
        "tokenValuesRedacted": bool(value.get("tokenValuesRedacted", True)),
        "refreshOwner": value.get("refreshOwner"),
        "remoteRefreshTokenStored": value.get("remoteRefreshTokenStored"),
        "accessExpiresAt": value.get("accessExpiresAt"),
        "resultCount": len(value.get("results") or []) if isinstance(value.get("results"), list) else None,
    }


def run_mac_codex_oauth_mirror(
    *,
    apply: bool = True,
    action_ids: str = "",
    target_scope: Optional[Dict[str, Any]] = None,
    codex_auth: str = "",
    mirror_operation_id: str = "",
    protect_operation_ids: str = "",
) -> Dict[str, Any]:
    if apply and platform.system() != "Darwin":
        return {
            "action": "mac_codex_oauth_mirror",
            "result": "blocked",
            "blockedReason": "mac-codex-refresh-owner-host-required",
            "tokenValuesRedacted": True,
        }
    script = AUTH_MIRROR_SCRIPT
    if not script.exists():
        return {
            "action": "mac_codex_oauth_mirror",
            "result": "failed",
            "reason": "mirror-script-missing",
            "script": str(script),
            "tokenValuesRedacted": True,
        }
    cmd = [
        sys.executable,
        str(script),
        "--min-ttl-seconds",
        str(AUTH_MIRROR_MIN_TTL_SECONDS),
        "--json-only",
    ]
    if codex_auth:
        cmd.extend(["--codex-auth", codex_auth])
    if mirror_operation_id:
        cmd.extend(["--mirror-operation-id", mirror_operation_id])
    if protect_operation_ids:
        cmd.extend(["--protect-operation-ids", protect_operation_ids])
    if apply:
        cmd.append("--apply")
    else:
        cmd.append("--local-preflight")
    if action_ids:
        cmd.extend(["--action-ids", action_ids])
    if target_scope is not None:
        if not bool(target_scope.get("codexCli")):
            cmd.append("--no-codex-cli")
        if not bool(target_scope.get("hermersProfiles")):
            cmd.append("--no-hermers")
        elif isinstance(target_scope.get("hermersProfiles"), list):
            cmd.extend(["--hermers-profiles", ",".join(str(x) for x in target_scope["hermersProfiles"])])
        if isinstance(target_scope.get("openclawTargets"), list) and target_scope["openclawTargets"]:
            encoded_targets = ",".join(
                f"{item['agentId']}:{item['profileKind']}"
                for item in target_scope["openclawTargets"]
            )
            cmd.extend(["--openclaw-targets", encoded_targets])
        elif target_scope.get("openclawAgents"):
            cmd.extend(["--openclaw-agents", ",".join(str(x) for x in target_scope["openclawAgents"])])
            if target_scope.get("openclawProfileKinds"):
                cmd.extend(["--openclaw-profile-kinds", ",".join(str(x) for x in target_scope["openclawProfileKinds"])])
        else:
            cmd.append("--no-openclaw")
    try:
        proc = run_cmd(cmd, timeout=AUTH_MIRROR_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {
            "action": "mac_codex_oauth_mirror",
            "result": "failed",
            "reason": "timeout",
            "script": str(script),
            "timeoutSeconds": AUTH_MIRROR_TIMEOUT_SECONDS,
            "tokenValuesRedacted": True,
        }
    parsed = None
    try:
        parsed = json.loads(proc.stdout or "")
    except Exception:
        parsed = None
    return {
        "action": "mac_codex_oauth_mirror",
        "result": (compact_mirror_summary(parsed).get("status") or ("applied" if apply else "dry-run")) if proc.returncode == 0 else "failed",
        "script": str(script),
        "exitCode": proc.returncode,
        "stdout": redact_auth_text(proc.stdout, 4000),
        "stderr": redact_auth_text(proc.stderr, 4000),
        "summary": compact_mirror_summary(parsed),
        "tokenValuesRedacted": True,
    }


def execute_auth_maintenance_plan(
    conn: sqlite3.Connection,
    plan: Dict[str, Any],
    *,
    action_id: str = "",
    dry_run: bool = False,
    allow_mirror: bool = False,
) -> Dict[str, Any]:
    selected = [
        item for item in plan.get("actions") or []
        if isinstance(item, dict) and (not action_id or str(item.get("actionId")) == action_id)
    ]
    if action_id and not selected:
        return {
            "generatedAt": ts(),
            "status": "not-found",
            "requestedActionId": action_id,
            "refreshBrokerEnabled": bool(AUTH_REFRESH_BROKER_ENABLED),
            "executions": [],
        }
    executions: List[Dict[str, Any]] = []
    AUTH_REFRESH_BROKER_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUTH_REFRESH_BROKER_LOCK_PATH.open("a+", encoding="utf-8") as lock_fh:
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return {
                    "generatedAt": ts(),
                    "status": "locked",
                    "requestedActionId": action_id,
                    "refreshBrokerEnabled": bool(AUTH_REFRESH_BROKER_ENABLED),
                    "executions": [],
                }
            raise

        for item in selected:
            item_id = str(item.get("actionId") or "")
            kind = str(item.get("kind") or "")
            mirrorable = kind in AUTH_MIRROR_ACTION_KINDS
            if dry_run:
                result = {
                    "action": "auth_refresh_broker",
                    "result": "dry_run",
                    "actionId": item_id,
                    "target": item.get("target"),
                    "wouldRun": False,
                    "blockedReason": "mac-codex-local-executor-required" if allow_mirror and mirrorable else item.get("blockedReason"),
                    "mirrorAllowed": bool(allow_mirror),
                    "mirrorable": bool(mirrorable),
                    "delegatedToMacCodex": bool((item.get("localAutomation") or {}).get("eligible")),
                    "tokenValuesRedacted": True,
                }
            elif bool(item.get("humanGateRequired")):
                result = {
                    "action": "auth_refresh_broker",
                    "result": "blocked",
                    "actionId": item_id,
                    "target": item.get("target"),
                    "kind": kind,
                    "blockedReason": "human-gate-required",
                    "mirrorAllowed": bool(allow_mirror),
                    "mirrorable": bool(mirrorable),
                    "tokenValuesRedacted": True,
                }
            elif allow_mirror and mirrorable:
                result = {
                    "action": "auth_refresh_broker",
                    "result": "blocked",
                    "actionId": item_id,
                    "target": item.get("target"),
                    "kind": kind,
                    "mirrorAllowed": True,
                    "blockedReason": "mac-codex-local-executor-required",
                    "delegatedToMacCodex": bool((item.get("localAutomation") or {}).get("eligible")),
                    "tokenValuesRedacted": True,
                }
            elif not AUTH_REFRESH_BROKER_ENABLED:
                result = {
                    "action": "auth_refresh_broker",
                    "result": "blocked",
                    "actionId": item_id,
                    "target": item.get("target"),
                    "blockedReason": "refresh-broker-disabled",
                    "tokenValuesRedacted": True,
                }
            elif not bool(item.get("canAutoRun")):
                result = {
                    "action": "auth_refresh_broker",
                    "result": "blocked",
                    "actionId": item_id,
                    "target": item.get("target"),
                    "blockedReason": item.get("blockedReason") or "manual-or-runtime-owned",
                    "tokenValuesRedacted": True,
                }
            else:
                result = {
                    "action": "auth_refresh_broker",
                    "result": "blocked",
                    "actionId": item_id,
                    "target": item.get("target"),
                    "blockedReason": "mac-codex-is-refresh-owner",
                    "tokenValuesRedacted": True,
                }
            executions.append(result)
            db_record_action(
                conn,
                {
                    "ts": ts(),
                    "tsEpoch": epoch(),
                    "actionId": f"auth:{item_id or 'unknown'}",
                    "action": "auth_refresh_broker",
                    "result": result.get("result"),
                    "payload": result,
                },
            )

    return {
        "generatedAt": ts(),
        "status": "executed" if executions else "no-actions",
        "requestedActionId": action_id,
        "refreshBrokerEnabled": bool(AUTH_REFRESH_BROKER_ENABLED),
        "dryRun": bool(dry_run),
        "executionCount": len(executions),
        "executions": executions,
    }


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
    """Read fresh cron evidence through the SDK or CLI-compatible fallback."""
    payload = cron_readonly_rpc_payload("inventory")
    if payload is not None:
        diagnostics, error = [], None
        transport = "gateway-sdk-read-only"
    else:
        transport = "cli-fallback" if _inspection_cache_enabled and CRON_READONLY_RPC_ENABLED else "cli"
        try:
            out = run_cmd(["openclaw", "cron", "list", "--json"], timeout=15)
        except Exception as exc:
            return {"available": False, "error": type(exc).__name__, "inspectionTransport": transport}
        if out.returncode != 0:
            return {"available": False, "exitCode": out.returncode, "stderrOmitted": True, "stderrByteCount": len(out.stderr or ""), "inspectionTransport": transport}
        payload, diagnostics, error = extract_json_payload("\n".join([out.stdout or "", out.stderr or ""]))
    if payload is None:
        return {"available": False, "error": error or "json_parse_failed",
                "stdoutOmitted": True, "stdoutByteCount": len(out.stdout or ""), "diagnostics": diagnostics}
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
            item["lastError"] = safe_error_category(state.get("lastError")) if state.get("lastError") else None
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
        "inspectionTransport": transport,
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
            "lastError": safe_error_category(item.get("lastError")) if item.get("lastError") else None,
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
                    "lastError": safe_error_category(state.get("lastError")) if state.get("lastError") else None,
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
    prepare_cron_readonly_rpc()
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
            payload = json.loads(exc.read().decode("utf-8", errors="replace"))
            if isinstance(payload, dict) and "description" in payload:
                payload["description"] = redact_sensitive_text(payload["description"], 500)
            return payload
        except Exception:
            return {"ok": False, "description": f"HTTPError:{exc.code}"}
    except Exception as exc:
        # urllib exceptions often embed the request URL, which contains the bot token.
        return {"ok": False, "description": type(exc).__name__}


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
    scope_available = registry.get("source") == "db" and bool(registry.get("writeEligible"))
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


def system_swap_pressure_level(swap_used: int, swap_total: int) -> str:
    if not swap_total:
        return ""
    swap_used_ratio = swap_used / swap_total
    critical_by_bytes = SYSTEM_SWAP_CRIT_BYTES > 0 and swap_used >= SYSTEM_SWAP_CRIT_BYTES
    warning_by_bytes = SYSTEM_SWAP_WARN_BYTES > 0 and swap_used >= SYSTEM_SWAP_WARN_BYTES
    if critical_by_bytes or swap_used_ratio >= SYSTEM_SWAP_CRIT_RATIO:
        return "critical"
    if warning_by_bytes or swap_used_ratio >= SYSTEM_SWAP_WARN_RATIO:
        return "high"
    return ""


def memory_pressure_context(proc_root: Path = Path("/proc")) -> Dict[str, Any]:
    """Read bounded Linux context; absent probes remain unknown, never healthy."""
    context: Dict[str, Any] = {
        "overcommitMode": None, "psi": None, "vmstatCounters": None,
        "counterScope": "cumulative since boot; not evidence of a recent OOM or swap burst",
        "probeErrors": {},
    }
    sources = {
        "overcommit": proc_root / "sys" / "vm" / "overcommit_memory",
        "psi": proc_root / "pressure" / "memory",
        "vmstat": proc_root / "vmstat",
    }
    for name, path in sources.items():
        try:
            with path.open(encoding="utf-8") as handle:
                text = handle.read(32_769)
            if len(text) > 32_768:
                raise ValueError("probe output exceeds budget")
            if name == "overcommit":
                mode = int(text.strip())
                if mode not in {0, 1, 2}:
                    raise ValueError("unknown overcommit mode")
                context["overcommitMode"] = mode
            elif name == "vmstat":
                counters = {}
                for line in text.splitlines():
                    fields = line.split()
                    if len(fields) == 2 and fields[0] in {"pswpin", "pswpout", "pgmajfault", "oom_kill"}:
                        value = int(fields[1])
                        if value < 0:
                            raise ValueError("negative counter")
                        counters[fields[0]] = value
                if not counters:
                    raise ValueError("no supported counters")
                expected = {"pswpin", "pswpout", "pgmajfault", "oom_kill"}
                context["vmstatCounters"] = {key: counters.get(key) for key in sorted(expected)}
                if set(counters) != expected:
                    context["probeErrors"]["vmstat"] = "MissingCounters"
            else:
                pressure = {}
                for line in text.splitlines():
                    fields = line.split()
                    if not fields or fields[0] not in {"some", "full"}:
                        continue
                    values = {}
                    for field in fields[1:]:
                        key, value = field.split("=", 1)
                        if key not in {"avg10", "avg60", "avg300", "total"}:
                            continue
                        number = int(value) if key == "total" else float(value)
                        if not math.isfinite(number) or number < 0:
                            raise ValueError("invalid pressure value")
                        values[key] = number
                    if set(values) != {"avg10", "avg60", "avg300", "total"}:
                        raise ValueError("incomplete pressure line")
                    pressure[fields[0]] = values
                if "some" not in pressure:
                    raise ValueError("no supported pressure lines")
                context["psi"] = pressure
                if "full" not in pressure:
                    context["psi"]["full"] = None
                    context["probeErrors"]["psi"] = "MissingFullPressure"
        except (OSError, ValueError, UnicodeError, OverflowError) as exc:
            context["probeErrors"][name] = type(exc).__name__
    context["commitInterpretation"] = (
        "strict commit accounting; reservation ratio still does not prove runtime failure"
        if context["overcommitMode"] == 2
        else "reservation ratio is not proof of OOM; corroborate PSI, memory, rates and readiness"
    )
    context["status"] = "partial" if context["probeErrors"] else "ok"
    return context


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
    swap_pressure_level = system_swap_pressure_level(swap_used, swap_total)
    commit_limit = int(meminfo.get("CommitLimit") or 0)
    committed_as = int(meminfo.get("Committed_AS") or 0)
    commit_ratio = (committed_as / commit_limit) if commit_limit else 0
    pressure_context = memory_pressure_context()
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
    if swap_pressure_level == "critical":
        add_finding(
            findings,
            "system_swap_saturation",
            "critical",
            "resource",
            "system swap usage is critically high",
            swapUsedBytes=swap_used,
            swapTotalBytes=swap_total,
            swapUsedRatio=swap_used_ratio,
            swapWarnBytes=SYSTEM_SWAP_WARN_BYTES,
            swapCritBytes=SYSTEM_SWAP_CRIT_BYTES,
            swapWarnRatio=SYSTEM_SWAP_WARN_RATIO,
            swapCritRatio=SYSTEM_SWAP_CRIT_RATIO,
        )
    elif swap_pressure_level == "high":
        add_finding(
            findings,
            "system_swap_pressure",
            "high",
            "resource",
            "system swap usage is high",
            swapUsedBytes=swap_used,
            swapTotalBytes=swap_total,
            swapUsedRatio=swap_used_ratio,
            swapWarnBytes=SYSTEM_SWAP_WARN_BYTES,
            swapCritBytes=SYSTEM_SWAP_CRIT_BYTES,
            swapWarnRatio=SYSTEM_SWAP_WARN_RATIO,
            swapCritRatio=SYSTEM_SWAP_CRIT_RATIO,
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
            overcommitMode=pressure_context["overcommitMode"],
            interpretation=pressure_context["commitInterpretation"],
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
            overcommitMode=pressure_context["overcommitMode"],
            interpretation=pressure_context["commitInterpretation"],
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
            "pressureContext": pressure_context,
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
    auth_pressure = any(auth_finding_is_pressure(key) for key in keys)
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
    auth_evidence = sorted(
        k
        for k in keys
        if k.startswith(("codex_cli_oauth_", "openclaw_oauth_", "hermers_oauth_", "hermers_cat"))
        and (
            k.endswith("_missing")
            or k.endswith("_expired")
            or k.endswith("_refresh_missing")
            or k.endswith("_access_missing")
            or k == "openclaw_oauth_profile_expired"
        )
    )
    auth_observations = sorted(
        k
        for k in keys
        if k.startswith(("codex_cli_oauth_", "openclaw_oauth_", "hermers_oauth_", "hermers_cat"))
        and k not in set(auth_evidence)
    )
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
    auth_state = "constrained" if auth_pressure else "normal"
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
            "auth": bool(auth_pressure),
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
            "auth": {
                "state": auth_state,
                "pressure": bool(auth_pressure),
                "evidenceKeys": auth_evidence,
                "observationKeys": auth_observations,
                "streakCounts": {k: streak_counts[k] for k in auth_evidence if k in streak_counts},
                "governanceAction": "human-gate-reauth" if any(k.endswith("_refresh_missing") or k.endswith("_access_missing") or k.endswith("_missing") for k in auth_evidence) else "refresh-broker-needed" if auth_pressure else "observe",
                "stabilizationGoal": "keep Codex CLI, OpenClaw openai-codex, and Hermers profile OAuth credentials refreshable without leaking tokens or requiring repeated manual login",
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
        "auth": {
            "pressure": bool(auth_pressure),
            "warnSeconds": AUTH_WARN_SECONDS,
            "criticalSeconds": AUTH_CRITICAL_SECONDS,
            "openclawProbeTtlSeconds": AUTH_OPENCLAW_PROBE_TTL_SECONDS,
            "openclawNearExpiryProbeTtlSeconds": AUTH_OPENCLAW_PROBE_NEAR_TTL_SECONDS,
            "openclawUrgentProbeTtlSeconds": AUTH_OPENCLAW_PROBE_URGENT_TTL_SECONDS,
            "openclawUrgentProbeWindowSeconds": AUTH_OPENCLAW_PROBE_URGENT_WINDOW_SECONDS,
            "tokenValuesRedacted": True,
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
    if SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["warning"]:
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
    elif any(auth_finding_is_pressure(key) for key in keys):
        mode = "auth-degraded"
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
            "auth": any(auth_finding_is_pressure(key) for key in keys),
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
        "canReapExpiredLeases": bool(LEASE_REAP_ENABLED and (can_mutate_cron or cron_uses_sqlite_storage)),
        "canResetSession": bool(can_reset_session),
        "gatewayRestartEnabled": bool(GATEWAY_RESTART_ENABLED),
        "gatewayRestartActuatorSupported": bool(GATEWAY_RESTART_ACTUATOR_SUPPORTED),
        "hermersGatewayRestartEnabled": bool(HERMERS_GATEWAY_RESTART_ENABLED),
        "hermersGatewayRestartCandidate": bool(hermers_restart_candidate),
        "hermersGatewayRestartBlockedReasons": hermers_restart_blocked_reasons,
        "canRestartHermersGateway": bool(can_restart_hermers_gateway),
        "canReapHermersOrphanWorkers": bool(HERMERS_ACP_ORPHAN_REAP_ENABLED),
        "canReapHermersIdleLsp": bool(HERMERS_LSP_IDLE_REAP_ENABLED),
        "hermersProfileModeEnabled": bool(HERMERS_PROFILE_MODE_ENABLED),
        "hermersLspIdleSeconds": HERMERS_LSP_IDLE_SECONDS,
        "hermersGatewayRestartLimit": HERMERS_GATEWAY_RESTART_LIMIT,
        "hermersGatewayRestartRemaining": hermers_restart_remaining,
        "hermersGatewayRestartProfiles": hermers_restart_decisions,
        "hermersGatewayRestartCandidateProfiles": hermers_gateway_restart_profiles,
        "hermersGatewayRestartReason": "hermers-gateway-service-down" if hermers_restart_candidate else "no-actionable-streak",
        "hermersProfileModeActuateEnabled": bool(HERMERS_PROFILE_MODE_ENABLED and HERMERS_PROFILE_MODE_ACTUATE_ENABLED),
        "hermersProfileModeStartEnabled": bool(HERMERS_PROFILE_MODE_START_ENABLED),
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


REPAIR_REQUEST_SCHEMA_VERSION = 1
REPAIR_REQUEST_REQUIRED_FIELDS = {"schemaVersion", "jobId", "reason", "source", "status"}
LEGACY_REPAIR_REQUEST_REQUIRED_FIELDS = {
    "jobId", "reason", "source", "status", "firstDetectedAtMs",
    "lastDetectedAtMs", "count", "queueState", "gate",
}


def load_valid_repair_request(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[int]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, type(exc).__name__, None
    if not isinstance(payload, dict):
        return None, "InvalidDocumentType", None
    source_schema = payload.get("schemaVersion")
    if source_schema is None and LEGACY_REPAIR_REQUEST_REQUIRED_FIELDS <= set(payload):
        # Recognize only the old producer's full shape, never arbitrary partial JSON.
        if not all(type(payload.get(key)) is int and payload[key] >= 0 for key in ("firstDetectedAtMs", "lastDetectedAtMs", "count")) or not isinstance(payload.get("gate"), dict):
            return None, "InvalidLegacyDocument", None
        source_schema = 0
        payload["schemaVersion"] = REPAIR_REQUEST_SCHEMA_VERSION
    missing = sorted(REPAIR_REQUEST_REQUIRED_FIELDS - set(payload))
    if missing:
        return None, "MissingRequiredFields", None
    if type(payload.get("schemaVersion")) is not int or payload.get("schemaVersion") != REPAIR_REQUEST_SCHEMA_VERSION:
        return None, "UnsupportedSchemaVersion", None
    if not all(isinstance(payload.get(key), str) and payload[key].strip() for key in ("jobId", "reason", "source", "status")):
        return None, "InvalidRequiredField", None
    return payload, None, source_schema


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
        "schemaVersion": REPAIR_REQUEST_SCHEMA_VERSION,
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
    invalid = 0
    updated = 0
    migrated = 0
    invalid_entries = []
    for request_path in sorted(REPAIR_PENDING_DIR.glob("*.json")):
        payload, validation_error, source_schema = load_valid_repair_request(request_path)
        if validation_error:
            invalid += 1
            invalid_entries.append(
                {
                    "path": str(request_path),
                    "queueState": "invalid",
                    "status": "failed",
                    "errorClass": validation_error,
                }
            )
            continue
        assert payload is not None
        payload["queueState"] = gate["status"]
        payload["gate"] = gate
        write_json_atomic(request_path, payload)
        updated += 1
        migrated += int(source_schema == 0)
        if gate["status"] == "ready":
            ready += 1
        else:
            blocked += 1
    pending = ready + blocked + invalid
    summary = {
        "schemaVersion": REPAIR_REQUEST_SCHEMA_VERSION,
        "updatedAt": ts(),
        "updatedAtEpoch": epoch(),
        "queueMode": gate["status"],
        "reason": gate["reason"],
        "pendingCount": pending,
        "readyCount": ready,
        "blockedCount": blocked,
        "invalidCount": invalid,
        "invalidEntries": invalid_entries,
        "processedCount": len(list(REPAIR_PROCESSED_DIR.glob("*.json"))),
        "updatedPendingEntries": updated,
        "migratedLegacyEntries": migrated,
        "policyUpdatedAt": policy.get("updatedAt"),
    }
    write_json_atomic(REPAIR_STATUS_PATH, summary)
    return summary


def governed_clear_stale_running(
    candidates: List[Dict[str, Any]], policy: Dict[str, Any], gate: Dict[str, Any], snapshot_generation: str,
) -> Dict[str, Any]:
    # OpenClaw owns the legacy jobs.json store and writes it independently.
    # There is no shared lock/CAS API for this mutation, so a stabilityd-side
    # read/hash/rename sequence can still overwrite a concurrent Gateway update.
    # Keep the finding visible and defer recovery to OpenClaw's native store path.
    job_ids = sorted({str(item.get("jobId") or "") for item in candidates if isinstance(item, dict)})
    job_digests = sorted(hashlib.sha256(job_id.encode()).hexdigest() for job_id in job_ids)
    target_ref = "stale-jobs:" + hashlib.sha256("".join(job_digests).encode()).hexdigest()[:16]
    return {
        "targetRef": target_ref,
        "result": "blocked",
        "blockedReason": "legacy-openclaw-jobs-store-has-uncoordinated-writer",
        "candidateCount": len(job_ids),
    }


def cron_actuate(
    snapshot: Dict[str, Any], policy: Dict[str, Any], *, snapshot_generation: str = "",
) -> List[Dict[str, Any]]:
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
        stale_action = governed_clear_stale_running(
            stale, policy, gate, str(snapshot_generation or snapshot.get("generationId") or ""),
        )
        stale_action["action"] = "clear_stale_running_state"
        actions.append(stale_action)
    if LEASE_REAP_ENABLED and policy.get("canReapExpiredLeases") is True:
        results = [governed_reap_expired_lease(
            item, gate, policy, str(snapshot_generation or snapshot.get("generationId") or ""),
        ) for item in cron.get("expiredLeases") or []]
        reaped = [item for item in results if item["result"] == "ok"]
        failures = [item for item in results if item["result"] in {"blocked", "failed", "uncertain"}]
        if reaped or failures:
            outcome = "uncertain" if any(item["result"] == "uncertain" for item in failures) else \
                "failed" if any(item["result"] == "failed" for item in failures) else \
                "blocked" if failures else "ok"
            action = {"action": "reap_expired_leases", "result": outcome}
            if reaped:
                action["reaped"] = reaped
            if failures:
                action["failures"] = failures
            actions.append(action)
    return actions


class LeaseAuditConflict(ValueError):
    pass


def ensure_lease_reap_audit(job_id: str, run_id: str, run_record: Dict[str, Any]) -> str:
    if not all(type(run_record.get(key)) is int and run_record[key] >= 0 for key in ("finishedAtMs", "durationMs")):
        raise ValueError("lease audit requires valid completion timestamp and duration")
    event_id = "lease-reap-" + hashlib.sha256(
        json.dumps([job_id, run_id, run_record.get("startedAtMs"), run_record.get("finishedAtMs")], separators=(",", ":")).encode()
    ).hexdigest()
    canonical = {
        "eventId": event_id, "ts": run_record.get("finishedAtMs"), "jobId": job_id,
        "runId": run_id, "action": "orphan-reaped", "status": "orphaned",
        "durationMs": run_record.get("durationMs"),
    }
    path = RUNS_BY_JOB_DIR / f"{job_id}.jsonl"
    found = False
    for line in tail_text(path, max_bytes=1_000_000).splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(event, dict) and event.get("eventId") == event_id:
            if not all(type(event.get(key)) is type(value) and event.get(key) == value for key, value in canonical.items()):
                raise LeaseAuditConflict("audit event identity conflicts with canonical run evidence")
            found = True
    if not found:
        append_jsonl(path, canonical)
    return event_id


def reap_expired_lease_candidate(
    item: Dict[str, Any], gate: Dict[str, Any], *, expected_lease_digest: Optional[str] = None,
) -> Dict[str, Any]:
    """Report every partial step; never let one target hide another target's outcome."""
    lease_path = Path(str(item.get("path") or ""))
    run_id, job_id = item.get("runId"), item.get("jobId")
    result: Dict[str, Any] = {"jobId": job_id, "runId": run_id, "leasePath": str(lease_path)}
    partial = {
        "runStateBefore": None, "runStateWriteAttempted": False, "runStateUpdated": False,
        "runAuditAppended": False, "leaseDeleteAttempted": False, "leaseRemoved": False,
        "repairRequestAttempted": False, "repairRequestQueued": False,
    }
    result.update({"leaseBackupPath": None, "runBackupPath": None})
    stage = "candidate-check"
    def expected_lease_is_current() -> bool:
        if expected_lease_digest is None:
            return True
        try:
            if lease_path.is_symlink() or not lease_path.is_file():
                return False
            current_lease = load_json(lease_path, None)
            if (not isinstance(current_lease, dict)
                    or str(current_lease.get("jobId") or "") != str(job_id)
                    or str(current_lease.get("runId") or "") != str(run_id or "")
                    or type(current_lease.get("expiresAtMs")) is not int
                    or current_lease["expiresAtMs"] > now_ms()):
                return False
            digest = hashlib.sha256(json.dumps(
                current_lease, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode()).hexdigest()
            return digest == expected_lease_digest
        except Exception:
            return False

    try:
        if not job_id or not lease_path.exists():
            return {**result, "result": "skipped"}
        if not expected_lease_is_current():
            return {**result, "result": "blocked", "failedStage": "lease-generation-check",
                    "errorClass": "LeaseGenerationChanged", "partialWrites": partial}
        live_lease = load_json(lease_path, None)
        if not isinstance(live_lease, dict) or live_lease.get("dispatchState") not in {"not-started", "not-dispatched"}:
            return {**result, "result": "uncertain", "failedStage": "dispatch-outcome-unknown",
                    "errorClass": "GatewayDispatchOutcomeUnknown", "partialWrites": partial}
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        backup_dir = CRON_DIR / "snapshots" / "lease-reap"
        backup_dir.mkdir(parents=True, exist_ok=True)
        stage = "lease-backup"
        lease_backup = backup_dir / f"{lease_path.name}.before-reap-{stamp}.bak"
        shutil.copy2(lease_path, lease_backup)
        result["leaseBackupPath"] = str(lease_backup)
        run_path = RUNS_BY_RUN_DIR / f"{run_id}.json" if run_id else None
        if run_path and run_path.exists():
            stage = "run-read"
            with run_path.open(encoding="utf-8") as handle:
                run_record = json.load(handle)
            if not isinstance(run_record, dict):
                raise ValueError("run document must be an object")
            partial["runStateBefore"] = run_record.get("status")
            if run_record.get("status") == "running":
                if run_record.get("dispatchState") not in {"not-started", "not-dispatched"}:
                    return {**result, "result": "uncertain", "failedStage": "dispatch-outcome-unknown",
                            "errorClass": "GatewayDispatchOutcomeUnknown", "partialWrites": partial}
                if not expected_lease_is_current():
                    return {**result, "result": "blocked", "failedStage": "pre-run-write-lease-check",
                            "errorClass": "LeaseGenerationChanged", "partialWrites": partial}
                stage = "run-backup"
                run_backup = backup_dir / f"{run_path.name}.before-reap-{stamp}.bak"
                shutil.copy2(run_path, run_backup)
                result["runBackupPath"] = str(run_backup)
                finished = now_ms()
                started = int(run_record.get("startedAtMs", finished) or finished)
                run_record.update({
                    "status": "orphaned", "finishedAtMs": finished,
                    "durationMs": max(0, finished - started),
                    "failure": {"class": "lease_expired", "message": "Lease expired without completion update."},
                    "result": None,
                })
                stage = "run-write"
                if not expected_lease_is_current():
                    return {**result, "result": "blocked", "failedStage": "immediate-pre-run-write-lease-check",
                            "errorClass": "LeaseGenerationChanged", "partialWrites": partial}
                partial["runStateWriteAttempted"] = True
                write_json_atomic(run_path, run_record)
                partial["runStateUpdated"] = True
            if run_record.get("status") == "orphaned" and (run_record.get("failure") or {}).get("class") == "lease_expired":
                stage = "run-audit-append"
                result["runAuditEventId"] = ensure_lease_reap_audit(str(job_id), str(run_id), run_record)
                partial["runAuditAppended"] = True
        stage = "lease-delete"
        if not expected_lease_is_current():
            return {**result, "result": "blocked", "failedStage": "pre-lease-delete-generation-check",
                    "errorClass": "LeaseGenerationChanged", "partialWrites": partial}
        partial["leaseDeleteAttempted"] = True
        lease_path.unlink(missing_ok=True)
        if lease_path.exists():
            raise OSError("lease path remains after unlink")
        partial["leaseRemoved"] = True
        stage = "repair-enqueue"
        partial["repairRequestAttempted"] = True
        repair = enqueue_repair_request(str(job_id), "lease_expired", "cat-agents-stabilityd", run_id=str(run_id) if run_id else None, gate=gate)
        partial["repairRequestQueued"] = True
        return {**result, "result": "ok", "repairRequestPath": repair, "partialWrites": partial}
    except Exception as exc:
        disappearance_unknown = False
        if partial["leaseDeleteAttempted"] and not partial["leaseRemoved"]:
            try:
                partial["leaseRemoved"] = not lease_path.exists()
            except OSError:
                partial["leaseRemoved"] = None
                disappearance_unknown = True
        uncertain = bool(
            partial["runStateWriteAttempted"] or partial["leaseRemoved"]
            or partial["repairRequestAttempted"] or disappearance_unknown
            or partial["runStateBefore"] == "orphaned" and stage == "run-audit-append"
        )
        return {**result, "result": "uncertain" if uncertain else "failed", "failedStage": stage,
                "errorClass": type(exc).__name__, "partialWrites": partial}


@contextlib.contextmanager
def lease_mutation_lock():
    """Shared with the cron runner so renewal and stale-lease reap serialize."""
    if LEASE_DIR.is_symlink() or not LEASE_DIR.is_dir():
        raise OSError("lease root unavailable")
    lock_path = LEASE_DIR / ".stabilityd-lease-mutation.lock"
    with lock_path.open("a+b") as lock_fh:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def governed_reap_expired_lease(
    item: Dict[str, Any], gate: Dict[str, Any], policy: Dict[str, Any], snapshot_generation: str,
) -> Dict[str, Any]:
    job_id, run_id = item.get("jobId"), item.get("runId")
    job_text = str(job_id or "")
    run_text = str(run_id or "")
    job_digest = hashlib.sha256(job_text.encode()).hexdigest()
    run_digest = hashlib.sha256(run_text.encode()).hexdigest()
    target_ref = f"job:{job_digest[:12]}/run:{run_digest[:12]}"
    generation = str(current_host_generation() or "")
    if (not snapshot_generation or not generation or gate.get("status") != "ready"
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", job_text)
            or run_text and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", run_text)):
        return {"targetRef": target_ref, "result": "blocked", "blockedReason": "invalid-target-gate-or-generation"}
    lease_path = Path(str(item.get("path") or ""))
    try:
        if (lease_path.is_symlink() or lease_path.resolve().parent != LEASE_DIR.resolve()
                or lease_path.suffix != ".json" or not lease_path.is_file()):
            return {"targetRef": target_ref, "result": "blocked", "blockedReason": "lease-path-out-of-scope"}
    except OSError:
        return {"targetRef": target_ref, "result": "blocked", "blockedReason": "lease-path-unavailable"}

    def current_lease() -> Tuple[Optional[Dict[str, Any]], str]:
        try:
            if lease_path.is_symlink() or lease_path.resolve().parent != LEASE_DIR.resolve() or not lease_path.is_file():
                return None, "lease-path-changed"
            data = load_json(lease_path, None)
            if (not isinstance(data, dict) or str(data.get("jobId") or "") != job_text
                    or str(data.get("runId") or "") != run_text
                    or type(data.get("expiresAtMs")) is not int
                    or data["expiresAtMs"] > now_ms()):
                return None, "lease-not-expired-or-owner-changed"
            canonical = json.dumps(data, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":"), allow_nan=False)
            digest = hashlib.sha256(canonical.encode()).hexdigest()
            owner = data.get("leaseOwner")
            if not isinstance(owner, str) or not owner.strip():
                return None, "lease-owner-unverifiable"
            workload_state = data.get("workloadState")
            workload_owner = data.get("workloadOwner")
            dispatch_state = data.get("dispatchState")
            if dispatch_state not in {"not-started", "not-dispatched", "attempted"}:
                return None, "lease-dispatch-state-unverifiable"
            if workload_state == "not-started":
                if workload_owner is not None:
                    return None, "lease-workload-state-invalid"
            elif workload_state == "running":
                if (not isinstance(workload_owner, dict)
                        or workload_owner.get("host") != socket.gethostname()
                        or type(workload_owner.get("pid")) is not int
                        or workload_owner["pid"] <= 1):
                    return None, "lease-workload-owner-unverifiable"
            else:
                return None, "lease-workload-state-unverifiable"
            return {"digest": digest, "expiresAtMs": data["expiresAtMs"], "leaseOwner": owner,
                    "workloadState": workload_state, "workloadOwner": workload_owner,
                    "dispatchState": dispatch_state}, "ok"
        except Exception:
            return None, "lease-state-unavailable"

    def lease_owner_is_gone(owner: str) -> bool:
        try:
            owner_host, raw_pid = owner.rsplit(":", 1)
            pid = int(raw_pid)
            if owner_host != socket.gethostname() or pid <= 1:
                return False
            os.kill(pid, 0)
            return False
        except ProcessLookupError:
            return True
        except (OSError, ValueError, AttributeError):
            return False

    def all_lease_processes_are_gone(lease: Dict[str, Any]) -> bool:
        if not lease_owner_is_gone(str(lease.get("leaseOwner") or "")):
            return False
        if lease.get("workloadState") == "not-started":
            return True
        workload_owner = lease.get("workloadOwner")
        if not isinstance(workload_owner, dict):
            return False
        try:
            os.kill(workload_owner["pid"], 0)
            return False
        except ProcessLookupError:
            return True
        except (OSError, TypeError, ValueError):
            return False

    lease_state, lease_status = current_lease()
    if lease_status != "ok" or lease_state is None:
        return {"targetRef": target_ref, "result": "blocked", "blockedReason": lease_status}
    if not all_lease_processes_are_gone(lease_state):
        return {"targetRef": target_ref, "result": "blocked",
                "blockedReason": "lease-owner-or-workload-live-or-unverifiable"}
    lease_digest = lease_state["digest"]
    path_digest = hashlib.sha256(str(lease_path.resolve()).encode()).hexdigest()
    policy_digest, policy_ref = policy_reference(policy)
    rule = STANDING_RULES["cron.expired_lease.repair"]
    scope_payload = {"jobDigest": job_digest, "runDigest": run_digest,
                     "leaseDigest": lease_digest, "pathDigest": path_digest,
                     "generation": generation}
    scope_ref = "evidence://cron-lease-scope/sha256/" + hashlib.sha256(
        json.dumps(scope_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    spec = ActionSpec(
        idempotency_key=f"cron.expired_lease.repair:{job_digest}:{run_digest}:{lease_digest}:{generation}",
        action_type="cron.expired_lease.repair", target=f"cron-lease:{job_digest}:{run_digest}",
        generation=generation, source="stabilityd-daemon",
        input_data={"jobIdDigest": job_digest, "runIdDigest": run_digest,
                    "leaseDigest": lease_digest, "pathDigest": path_digest,
                    "expiresAtMs": lease_state["expiresAtMs"]},
        authorization_ref=rule.authority_ref, policy_ref=policy_ref,
        evidence_refs=(f"evidence://snapshot/{snapshot_generation}", scope_ref,
                       policy_ref, f"policy-digest:sha256:{policy_digest}"),
        metadata={"actor": "cat-agents-stabilityd", "request_source": "stabilityd-daemon"},
    )

    def boundary() -> Tuple[bool, str]:
        if current_host_generation() != generation:
            return False, "host-generation-changed"
        latest, status = current_lease()
        if status != "ok" or latest is None or latest.get("digest") != lease_digest:
            return False, status if status != "ok" else "lease-content-changed"
        if not all_lease_processes_are_gone(latest):
            return False, "lease-owner-or-workload-live-or-unverifiable"
        return True, scope_ref

    def eligibility(_spec: ActionSpec, loaded: Dict[str, Any], _now_ms: int) -> tuple[str, ...]:
        if loaded.get("canReapExpiredLeases") is not True or gate.get("status") != "ready":
            return ()
        allowed, ref = boundary()
        return (f"evidence://snapshot/{snapshot_generation}", ref) if allowed else ()

    def precheck(_spec: ActionSpec, _record: Any) -> BoundaryCheck:
        allowed, ref = boundary()
        if not allowed:
            return BoundaryCheck("rejected", "evidence://cron-lease-scope/changed")
        return BoundaryCheck("approved", ref)

    outcome: Dict[str, Any] = {}
    def operation(_spec: ActionSpec, _record: Any) -> OperationResult:
        try:
            with lease_mutation_lock():
                allowed, _ref = boundary()
                if not allowed:
                    result = {"result": "blocked", "failedStage": "locked-lease-fence",
                              "partialWrites": {}}
                else:
                    result = reap_expired_lease_candidate(
                        {**item, "path": str(lease_path)}, gate, expected_lease_digest=lease_digest,
                    )
        except Exception as exc:
            result = {"result": "failed", "failedStage": "lease-mutation-lock",
                      "errorClass": type(exc).__name__, "partialWrites": {}}
        outcome.update(result=result.get("result"), failedStage=result.get("failedStage"),
                       errorClass=result.get("errorClass"), partialWrites=result.get("partialWrites"))
        if isinstance(result.get("runAuditEventId"), str):
            outcome["runAuditEventId"] = result["runAuditEventId"]
        outcome_digest = hashlib.sha256(json.dumps(
            {key: outcome.get(key) for key in ("result", "failedStage", "errorClass", "partialWrites")},
            sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode()).hexdigest()
        partial = result.get("partialWrites") if isinstance(result.get("partialWrites"), dict) else {}
        side_effect_started = any(partial.get(key) is True for key in (
            "runStateUpdated", "runAuditAppended", "leaseRemoved", "repairRequestQueued",
        ))
        status = "unknown" if result.get("result") == "uncertain" or (
            side_effect_started and result.get("result") != "ok"
        ) else "complete"
        return OperationResult(status, f"outcome://cron-lease-reap/sha256/{outcome_digest}")

    def postcheck(_spec: ActionSpec, _record: Any, _operation_result: OperationResult) -> PostcheckResult:
        try:
            if lease_path.exists():
                return PostcheckResult("failed", "evidence://cron-lease-postcheck/lease-remains")
            repair_path = REPAIR_PENDING_DIR / f"{job_text}__lease_expired.json"
            repair, error, _schema = load_valid_repair_request(repair_path)
            if error or repair is None or str(repair.get("jobId")) != job_text or str(repair.get("runId") or "") != run_text:
                return PostcheckResult("unknown", "evidence://cron-lease-postcheck/repair-receipt-unavailable")
            run_path = RUNS_BY_RUN_DIR / f"{run_text}.json" if run_text else None
            if run_path and run_path.exists():
                run_record = load_json(run_path, {})
                if not isinstance(run_record, dict):
                    return PostcheckResult("unknown", "evidence://cron-lease-postcheck/run-state-invalid")
                if run_record.get("status") == "running":
                    return PostcheckResult("failed", "evidence://cron-lease-postcheck/run-still-running")
                if (run_record.get("status") == "orphaned"
                        and (run_record.get("failure") or {}).get("class") == "lease_expired"):
                    event_id = "lease-reap-" + hashlib.sha256(json.dumps(
                        [job_text, run_text, run_record.get("startedAtMs"), run_record.get("finishedAtMs")],
                        separators=(",", ":"),
                    ).encode()).hexdigest()
                    audit_found = False
                    for line in tail_text(RUNS_BY_JOB_DIR / f"{job_text}.jsonl", 1_000_000).splitlines():
                        try:
                            event = json.loads(line)
                        except (ValueError, TypeError):
                            continue
                        if isinstance(event, dict) and event.get("eventId") == event_id:
                            audit_found = True
                            break
                    if not audit_found:
                        return PostcheckResult("unknown", "evidence://cron-lease-postcheck/audit-missing")
            digest = hashlib.sha256(json.dumps(
                {"jobDigest": job_digest, "runDigest": run_digest, "leaseRemoved": True,
                 "repairReceipt": True}, sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()
            return PostcheckResult("verified", f"evidence://cron-lease-postcheck/sha256/{digest}")
        except Exception:
            return PostcheckResult("unknown", "evidence://cron-lease-postcheck/unknown")

    try:
        execution = execute_governed_effect(spec, policy, eligibility_evidence=eligibility,
                                            precheck=precheck, operation=operation, postcheck=postcheck)
    except Exception as exc:
        return {"targetRef": target_ref, "result": "uncertain", "errorClass": type(exc).__name__}
    states = {"succeeded": "ok", "failed": "failed", "blocked": "blocked", "uncertain": "uncertain"}
    return {"targetRef": target_ref, "result": states.get(execution.record.state, "existing"),
            "ledgerState": execution.record.state, "ledgerDisposition": execution.disposition,
            "leaseDigest": lease_digest,
            "failedStage": outcome.get("failedStage"), "errorClass": outcome.get("errorClass"),
            "partialWrites": outcome.get("partialWrites"),
            "runAuditEventId": outcome.get("runAuditEventId")}


def reset_session(
    session_key: str, reason: str, conn: sqlite3.Connection, *,
    expected_session_id: Optional[str] = None, expected_store_path: Optional[Path] = None,
) -> Dict[str, Any]:
    session_key_digest = hashlib.sha256(str(session_key).encode("utf-8")).hexdigest()
    last_key = f"session_reset:sha256:{session_key_digest}"
    last_reset = int(db_get(conn, last_key, 0) or 0)
    if last_reset and epoch() - last_reset < SESSION_RESET_COOLDOWN_SECONDS:
        return {"result": "cooldown_skip"}
    agent_id = session_key_agent_id(session_key)
    if not agent_id or not expected_session_id:
        return {"result": "target-generation-required"}
    current, status = openclaw_gateway_call(
        "sessions.reset", {"key": session_key, "agentId": agent_id,
                          "expectedSessionId": expected_session_id},
    )
    if status != "ok" or not isinstance(current, dict):
        return {"result": "gateway-reset-failed", "errorClass": status}
    db_set(conn, last_key, epoch())
    return {"result": "reset", "sessionId": current.get("sessionId")}


def openclaw_gateway_call(method: str, params: Dict[str, Any], timeout_seconds: int = 20) -> Tuple[Optional[Dict[str, Any]], str]:
    """Call a Gateway RPC through the installed CLI without persisting response text."""
    if method not in {"sessions.describe", "sessions.reset"}:
        return None, "unsupported-gateway-rpc"
    try:
        proc = run_cmd([
            "openclaw", "gateway", "call", method,
            "--params", json.dumps(params, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            "--json",
        ], timeout=timeout_seconds)
    except Exception as exc:
        return None, type(exc).__name__
    if proc.returncode != 0:
        return None, "gateway-rpc-nonzero-exit"
    payload, _diagnostics, parse_error = extract_json_payload(proc.stdout or "")
    if parse_error or not isinstance(payload, dict):
        return None, "gateway-rpc-invalid-response"
    if payload.get("ok") is False or payload.get("error"):
        return None, "gateway-rpc-rejected"
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    if isinstance(result.get("session"), dict):
        result = result["session"]
    return result, "ok"


def current_session_context(session_key: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], str]:
    agent_id = session_key_agent_id(session_key)
    if not agent_id:
        return None, {}, "session-agent-scope-unparseable"
    if is_protected_identity({agent_id}):
        return None, {}, "protected-session"
    registry = workflow_runtime_registry_records()
    if registry.get("source") != "db" or registry.get("writeEligible") is not True:
        return None, {}, "authoritative-runtime-registry-unavailable"
    active_agents = active_openclaw_agent_ids_from_registry(registry)
    if agent_id not in active_agents:
        return None, {}, "session-agent-not-active-openclaw-member"
    row, rpc_status = openclaw_gateway_call("sessions.describe", {"key": session_key, "agentId": agent_id})
    if rpc_status != "ok" or not isinstance(row, dict):
        return None, {}, "gateway-session-read-unavailable"
    if str(row.get("key") or row.get("sessionKey") or session_key) != session_key:
        return None, {}, "gateway-session-key-mismatch"
    session_id = row.get("sessionId")
    if not isinstance(session_id, str) or not session_id.strip():
        return None, {}, "gateway-session-id-unavailable"
    if type(row.get("hasActiveRun")) is not bool:
        return None, {}, "gateway-active-run-state-unavailable"
    activity = analyze_session_activity(row)
    if row.get("hasActiveRun") or activity.get("heavy") or activity.get("active"):
        return {"agentId": agent_id, "sessionId": session_id, "hasActiveRun": row["hasActiveRun"]}, activity, "session-active-or-heavy"
    safe_info = {"agentId": agent_id, "sessionId": session_id, "hasActiveRun": False}
    return safe_info, activity, "session-reset-eligible"


def governed_reset_session(
    conn: sqlite3.Connection, session_key: str, reason: str, policy: Dict[str, Any], snapshot_generation: str,
    expected_session_id: Optional[str] = None,
) -> Dict[str, Any]:
    session_key_digest = hashlib.sha256(session_key.encode("utf-8")).hexdigest()
    session_ref = f"sha256:{session_key_digest[:16]}"
    action_id = f"session-reset-{session_key_digest[:16]}-{int(time.time())}"
    generation = str(current_host_generation() or "")
    if not generation or not snapshot_generation:
        return {"sessionRef": session_ref, "result": "blocked", "blockedReason": "generation-unavailable"}
    if not isinstance(expected_session_id, str) or not expected_session_id:
        return {"sessionRef": session_ref, "result": "blocked", "blockedReason": "candidate-session-id-unavailable"}
    session_info, activity, target_status = current_session_context(session_key)
    if (target_status != "session-reset-eligible" or session_info is None
            or session_info.get("sessionId") != expected_session_id):
        blocked_reason = target_status if target_status != "session-reset-eligible" else "candidate-session-id-changed"
        return {"sessionRef": session_ref, "result": "blocked", "blockedReason": blocked_reason}
    session_id = expected_session_id
    session_id_digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    scope_payload = {"sessionKeyDigest": session_key_digest, "sessionIdDigest": session_id_digest,
                     "agentId": session_info.get("agentId"), "generation": generation}
    scope_ref = "evidence://openclaw-session-scope/sha256/" + hashlib.sha256(
        json.dumps(scope_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    reason_code = "context_overflow" if reason == "context_overflow" else "repeated_failures"
    policy_digest, policy_ref = policy_reference(policy)
    rule = STANDING_RULES["openclaw.session.reset"]
    last_key = f"session_reset:sha256:{session_key_digest}"
    spec = ActionSpec(
        idempotency_key=(f"openclaw.session.reset:{session_key_digest}:{session_id_digest}:{generation}:"
                         f"{int(epoch() // max(1, SESSION_RESET_COOLDOWN_SECONDS))}"),
        action_type="openclaw.session.reset", target=f"openclaw-session:sha256:{session_key_digest}",
        generation=generation, source="stabilityd-daemon",
        input_data={"sessionKeyDigest": session_key_digest, "sessionIdDigest": session_id_digest,
                    "agentId": session_info.get("agentId"), "reasonCode": reason_code},
        authorization_ref=rule.authority_ref, policy_ref=policy_ref,
        evidence_refs=(f"evidence://snapshot/{snapshot_generation}", scope_ref,
                       policy_ref, f"policy-digest:sha256:{policy_digest}"),
        metadata={"actor": "cat-agents-stabilityd", "request_source": "stabilityd-daemon"},
    )

    def live_boundary() -> Tuple[bool, str]:
        if current_host_generation() != generation:
            return False, "host-generation-changed"
        current_info, current_activity, status = current_session_context(session_key)
        if (status != "session-reset-eligible" or current_info is None
                or current_info.get("sessionId") != session_id
                or current_info.get("agentId") != session_info.get("agentId")):
            return False, status if status != "session-reset-eligible" else "session-target-changed"
        return True, scope_ref

    def eligibility(_spec: ActionSpec, loaded: Dict[str, Any], _now_ms: int) -> tuple[str, ...]:
        if loaded.get("canResetSession") is not True:
            return ()
        eligible, ref = live_boundary()
        return (f"evidence://snapshot/{snapshot_generation}", ref) if eligible else ()

    def precheck(_spec: ActionSpec, _record: Any) -> BoundaryCheck:
        eligible, ref = live_boundary()
        if not eligible:
            return BoundaryCheck("rejected", "evidence://openclaw-session-scope/changed")
        last = int(db_get(conn, last_key, 0) or 0)
        if last and epoch() - last < SESSION_RESET_COOLDOWN_SECONDS:
            return BoundaryCheck("rejected", "evidence://openclaw-session-scope/cooldown")
        return BoundaryCheck("approved", ref)

    operation_meta: Dict[str, Any] = {}
    def operation(_spec: ActionSpec, _record: Any) -> OperationResult:
        result = reset_session(session_key, reason_code, conn, expected_session_id=session_id)
        operation_meta.update(result=result.get("result"), resetSessionId=result.get("sessionId"))
        outcome_digest = hashlib.sha256(json.dumps(
            {"result": operation_meta["result"],
             "resetSessionIdDigest": hashlib.sha256(str(operation_meta["resetSessionId"] or "").encode()).hexdigest()},
            sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        status = "complete" if result.get("result") == "reset" else "partial"
        return OperationResult(status, f"outcome://openclaw-session-reset/sha256/{outcome_digest}")

    def postcheck(_spec: ActionSpec, _record: Any, _operation_result: OperationResult) -> PostcheckResult:
        try:
            current, _activity, status_code = current_session_context(session_key)
            if current is None:
                return PostcheckResult("unknown", "evidence://openclaw-session-postcheck/session-unavailable")
            # OpenClaw allows sessions.reset in place; compare the Gateway
            # receipt with the current target rather than requiring ID rotation.
            returned_session_id = operation_meta.get("resetSessionId")
            if not isinstance(returned_session_id, str) or not returned_session_id:
                return PostcheckResult("unknown", "evidence://openclaw-session-postcheck/reset-receipt-unavailable")
            receipt_matches = current.get("sessionId") == returned_session_id
            evidence = {"sessionKeyDigest": session_key_digest,
                        "resetReceiptMatchesCurrentSession": receipt_matches,
                        "gatewayStatus": status_code}
            digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            status = "verified" if receipt_matches else "unknown"
            return PostcheckResult(status, f"evidence://openclaw-session-postcheck/sha256/{digest}")
        except Exception:
            return PostcheckResult("unknown", "evidence://openclaw-session-postcheck/unknown")

    try:
        execution = execute_governed_effect(spec, policy, eligibility_evidence=eligibility,
                                            precheck=precheck, operation=operation, postcheck=postcheck)
    except Exception as exc:
        return {"actionId": action_id, "sessionRef": session_ref, "result": "uncertain",
                "error": type(exc).__name__}
    state_map = {"succeeded": "ok", "failed": "failed", "blocked": "blocked", "uncertain": "uncertain"}
    return {"actionId": execution.record.action_id, "sessionRef": session_ref,
            "result": state_map.get(execution.record.state, "existing"),
            "ledgerState": execution.record.state, "ledgerDisposition": execution.disposition,
            "sessionIdDigest": session_id_digest, "reason": reason_code,
            "resetSessionIdDigest": hashlib.sha256(str(operation_meta.get("resetSessionId") or "").encode()).hexdigest()}


def session_actuate(
    conn: sqlite3.Connection, snapshot: Dict[str, Any], policy: Dict[str, Any], *, snapshot_generation: str = "",
) -> List[Dict[str, Any]]:
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
        reason = "context_overflow" if int(item.get("overflowCount") or 0) >= SESSION_OVERFLOW_THRESHOLD else "repeated_failures"
        results.append(governed_reset_session(
            conn, session_key, reason, policy,
            str(snapshot_generation or snapshot.get("generationId") or ""),
            expected_session_id=str(item.get("sessionId") or ""),
        ))
    if results:
        action_result = "uncertain" if any(item.get("result") == "uncertain" for item in results) else \
            "failed" if any(item.get("result") == "failed" for item in results) else \
            "blocked" if all(item.get("result") == "blocked" for item in results) else "ok"
        actions.append({"action": "reset_unhealthy_sessions", "result": action_result, "results": results})
    return actions


def execute_governed_effect(
    spec: ActionSpec,
    policy: Dict[str, Any],
    *,
    eligibility_evidence: Any,
    precheck: Any,
    operation: Any,
    postcheck: Any,
) -> Any:
    """Bridge one existing effect leaf through durable intent and live fences."""
    digest, policy_ref = policy_reference(policy)
    rule = STANDING_RULES.get(spec.action_type)
    if rule is None:
        raise ValueError("unsupported governed action type")
    base_refs = tuple(spec.evidence_refs)
    if (
        spec.policy_ref != policy_ref
        or spec.authorization_ref != rule.authority_ref
        or len(base_refs) < 3
        or base_refs[-2:] != (policy_ref, f"policy-digest:sha256:{digest}")
    ):
        raise ValueError("action references do not bind the loaded policy")

    def evaluate(spec_: ActionSpec, policy_: Dict[str, Any], policy_digest: str, now_ms: int) -> EligibilityProof:
        refs = eligibility_evidence(spec_, policy_, now_ms)
        evidence_refs = tuple(refs) if isinstance(refs, (tuple, list)) else ()
        return EligibilityProof(
            action_type=spec_.action_type,
            target=spec_.target,
            generation=spec_.generation,
            input_digest=hashlib.sha256(
                json.dumps(spec_.input_data, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
            ).hexdigest(),
            policy_digest=policy_digest,
            evidence_refs=evidence_refs,
            checked_at_ms=now_ms,
            expires_at_ms=now_ms + 30_000,
            eligible=bool(evidence_refs),
        )

    authorizer = TrustedPolicyAuthorizer(
        policy_reader=lambda: dict(policy), eligibility_evaluator=evaluate,
        source=spec.source, clock_ms=lambda: epoch() * 1000,
    )
    with ActionLedger(STATE_DB) as ledger:
        executor = ActionExecutor(
            ledger, authorizer=authorizer, precheck=precheck, operation=operation,
            postcheck=postcheck, clock_ms=lambda: epoch() * 1000,
        )
        return executor.execute(spec)


def gateway_restart(
    conn: sqlite3.Connection,
    reason: str,
    protection_decision: Any = None,
    *,
    policy: Optional[Dict[str, Any]] = None,
    snapshot_generation: str = "",
    allow_protected_impact: bool = False,
) -> Dict[str, Any]:
    reason_code = re.sub(r"[^A-Za-z0-9_-]+", "-", str(reason))[:80] or "policy"
    decision_status = str(getattr(protection_decision, "status", "unknown"))
    decision_generation = getattr(protection_decision, "target_generation", None)
    protection = {
        "status": decision_status,
        "reason": getattr(protection_decision, "reason", "protection-scope-unavailable"),
        "affectedAgents": list(getattr(protection_decision, "affected_agents", ()) or ()),
        "protectedSubjects": list(getattr(protection_decision, "protected_subjects", ()) or ()),
        "targetGeneration": decision_generation,
    }
    if (
        decision_status not in {"clear", "protected"} or not decision_generation
        or not isinstance(policy, dict) or not snapshot_generation
    ):
        return {
            "ts": ts(), "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd", "component": "gateway", "action": "restart_gateway",
            "result": "blocked", "reason": reason_code,
            "blockedReason": "protection-scope-or-generation-unavailable",
            "protectionScope": protection,
        }
    if decision_status == "protected" and allow_protected_impact is not True:
        return {
            "ts": ts(), "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd", "component": "gateway", "action": "restart_gateway",
            "result": "blocked", "reason": reason_code, "blockedReason": "protected-impact-not-authorized",
            "protectionScope": protection,
        }

    def resolve_current_scope() -> Any:
        registry = workflow_runtime_registry_records()
        return resolve_protection_scope(
            registry.get("records") if isinstance(registry.get("records"), list) else [],
            registry_source=str(registry.get("source") or "unknown"),
            registry_write_eligible=registry.get("writeEligible") is True,
            scope_complete=registry.get("writeEligible") is True and registry.get("source") == "db",
            target_kind="shared-gateway", target_id="dev-server", runtime="openclaw",
            target_generation=current_host_generation() or "",
        )

    def scope_reference(scope: Any) -> str:
        safe = {
            "status": getattr(scope, "status", "unknown"),
            "reason": getattr(scope, "reason", "unknown"),
            "affectedAgents": sorted(getattr(scope, "affected_agents", ()) or ()),
            "protectedSubjects": sorted(getattr(scope, "protected_subjects", ()) or ()),
            "targetGeneration": getattr(scope, "target_generation", None),
        }
        encoded = json.dumps(safe, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return "evidence://gateway-impact/sha256/" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    try:
        current_scope = resolve_current_scope()
    except Exception:
        current_scope = None
    if (
        current_scope is None
        or current_scope.status not in {"clear", "protected"}
        or current_scope.target_generation != decision_generation
        or current_scope.status == "protected" and allow_protected_impact is not True
    ):
        return {
            "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd",
            "component": "gateway", "action": "restart_gateway", "result": "blocked",
            "reason": reason_code, "blockedReason": "protection-scope-changed-before-intent",
            "protectionScope": protection,
        }
    policy_digest, policy_ref = policy_reference(policy)
    base_ref = f"evidence://snapshot/{snapshot_generation}"
    scope_ref = scope_reference(current_scope)
    rule = STANDING_RULES["openclaw.gateway.restart"]
    spec = ActionSpec(
        idempotency_key=(
            f"openclaw.gateway.restart:{decision_generation}:{reason_code}:"
            f"{int(epoch() // max(1, RESTART_COOLDOWN_SECONDS))}"
        ),
        action_type="openclaw.gateway.restart", target="openclaw-gateway:dev-server",
        generation=str(decision_generation), source="stabilityd-daemon",
        input_data={"reasonCode": reason_code, "allowProtectedImpact": allow_protected_impact},
        authorization_ref=rule.authority_ref, policy_ref=policy_ref,
        evidence_refs=(base_ref, scope_ref, policy_ref, f"policy-digest:sha256:{policy_digest}"),
        metadata={"actor": "cat-agents-stabilityd", "request_source": "stabilityd-daemon"},
    )
    latest_scope = {"value": current_scope}

    def evidence(spec_: ActionSpec, loaded_policy: Dict[str, Any], now_ms: int) -> tuple[str, ...]:
        if (
            loaded_policy.get("canRestartGateway") is not True
            or loaded_policy.get("restartCandidate") is not True
            or str(loaded_policy.get("restartReason") or "policy") != str(reason)
        ):
            return ()
        try:
            scope = resolve_current_scope()
        except Exception:
            return ()
        latest_scope["value"] = scope
        if (
            scope.status not in {"clear", "protected"}
            or scope.target_generation != spec_.generation
            or scope.status == "protected" and allow_protected_impact is not True
        ):
            return ()
        return base_ref, scope_reference(scope)

    def precheck(_spec: ActionSpec, _record: Any) -> BoundaryCheck:
        try:
            scope = resolve_current_scope()
        except Exception:
            scope = None
        latest_scope["value"] = scope
        if (
            scope is None or scope.status not in {"clear", "protected"}
            or scope.target_generation != decision_generation
            or scope.status == "protected" and allow_protected_impact is not True
        ):
            return BoundaryCheck("rejected", "evidence://gateway-impact/unknown")
        return BoundaryCheck("approved", scope_reference(scope))

    operation_meta: dict[str, Any] = {}

    def operation(_spec: ActionSpec, record: Any) -> OperationResult:
        started = time.monotonic()
        proc = run_cmd(["sudo", "-n", "systemctl", "restart", "openclaw-gateway.service"], timeout=60)
        operation_meta.update(exitCode=proc.returncode, durationMs=int((time.monotonic() - started) * 1000),
                              stderrByteCount=len(proc.stderr or ""))
        if proc.returncode != 0:
            return OperationResult("partial", f"outcome://gateway-restart/exit-{proc.returncode}")
        # Record cooldown before declaring operation complete; a write failure
        # makes the ledger uncertain and prevents an automatic restart replay.
        record_restart_time(conn)
        return OperationResult("complete", f"outcome://gateway-restart/{record.action_id}")

    def postcheck(_spec: ActionSpec, _record: Any, _result: OperationResult) -> PostcheckResult:
        try:
            service = systemctl_show_gateway()
            port_ok = tcp_ok(PORT)
            health = gateway_http_health(PORT, timeout=8) if port_ok else {"ok": False}
        except Exception:
            return PostcheckResult("unknown", "evidence://gateway-postcheck/unknown")
        active = service.get("ActiveState") == "active" and service.get("SubState") == "running"
        if active and port_ok and health.get("ok") is True:
            status = "verified"
        elif service.get("ActiveState") == "inactive" or not port_ok:
            status = "failed"
        else:
            status = "unknown"
        digest = hashlib.sha256(json.dumps(
            {"active": active, "portOk": port_ok, "healthOk": health.get("ok") is True},
            sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        return PostcheckResult(status, f"evidence://gateway-postcheck/sha256/{digest}")

    try:
        execution = execute_governed_effect(
            spec, policy, eligibility_evidence=evidence, precheck=precheck,
            operation=operation, postcheck=postcheck,
        )
    except Exception as exc:
        return {
            "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd",
            "component": "gateway", "action": "restart_gateway", "result": "uncertain",
            "reason": reason_code, "errorClass": type(exc).__name__,
            "protectionScope": protection,
        }
    state_to_result = {"succeeded": "ok", "failed": "failed", "blocked": "blocked", "uncertain": "uncertain"}
    state = execution.record.state
    scope = latest_scope.get("value") or current_scope
    return {
        "actionId": execution.record.action_id,
        "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd",
        "component": "gateway", "action": "restart_gateway",
        "result": state_to_result.get(state, "existing" if execution.disposition == "existing" else "blocked"),
        "reason": reason_code, "ledgerState": state, "ledgerDisposition": execution.disposition,
        "exitCode": operation_meta.get("exitCode"), "durationMs": operation_meta.get("durationMs"),
        "stderrOmitted": True, "stderrByteCount": operation_meta.get("stderrByteCount", 0),
        "blockedReason": "durable-authority-or-precheck-denied" if state == "blocked" else None,
        "protectionScope": {
            "status": getattr(scope, "status", "unknown"),
            "reason": getattr(scope, "reason", "unknown"),
            "affectedAgents": list(getattr(scope, "affected_agents", ()) or ()),
            "protectedSubjects": list(getattr(scope, "protected_subjects", ()) or ()),
            "targetGeneration": getattr(scope, "target_generation", None),
        },
    }


def hermers_gateway_restart(
    conn: sqlite3.Connection, profile: str, unit: str, reason: str, *,
    policy: Optional[Dict[str, Any]] = None, snapshot_generation: str = "",
) -> Dict[str, Any]:
    action_id = f"hermers-gateway-restart-{hashlib.sha256(profile.encode()).hexdigest()[:12]}-{int(time.time())}"
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
    if not isinstance(policy, dict) or not snapshot_generation:
        return {"actionId": action_id, "ts": ts(), "tsEpoch": epoch(),
                "source": "cat-agents-stabilityd", "component": "hermers",
                "action": "restart_hermers_gateway", "result": "blocked",
                "profile": profile, "unit": unit, "blockedReason": "policy-or-snapshot-generation-unavailable"}
    def resolve_profile_scope() -> Any:
        registry = workflow_runtime_registry_records()
        return resolve_protection_scope(
            registry.get("records") if isinstance(registry.get("records"), list) else [],
            registry_source=str(registry.get("source") or "unknown"),
            registry_write_eligible=registry.get("writeEligible") is True,
            scope_complete=registry.get("writeEligible") is True and registry.get("source") == "db",
            target_kind="profile", target_id=profile, runtime="hermes",
            target_generation=current_host_generation() or "",
            additive_protected=HERMERS_PROFILE_PROTECTED_IDS,
        )

    try:
        scope = resolve_profile_scope()
    except Exception:
        scope = None
    if scope is None or scope.status != "clear" or not scope.target_generation:
        return {"actionId": action_id, "ts": ts(), "tsEpoch": epoch(),
                "source": "cat-agents-stabilityd", "component": "hermers",
                "action": "restart_hermers_gateway", "result": "blocked",
                "profile": profile, "unit": unit,
                "blockedReason": "protected-or-unknown-profile-scope",
                "protectionScopeStatus": getattr(scope, "status", "unknown")}
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
    policy_digest, policy_ref = policy_reference(policy)
    reason_code = re.sub(r"[^A-Za-z0-9_-]+", "-", str(reason))[:80] or "policy"
    scope_ref = "evidence://hermes-profile-scope/sha256/" + hashlib.sha256(
        json.dumps({"profile": profile, "generation": scope.target_generation,
                    "affected": sorted(scope.affected_agents), "status": scope.status},
                   sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    rule = STANDING_RULES["hermes.gateway.restart"]
    def unit_is_explicitly_down() -> bool:
        try:
            state = systemctl_user_show(unit).get("ActiveState")
            return state in {"inactive", "failed"}
        except Exception:
            return False

    spec = ActionSpec(
        idempotency_key=(f"hermes.gateway.restart:{profile}:{scope.target_generation}:{reason_code}:"
                         f"{int(epoch() // max(1, RESTART_COOLDOWN_SECONDS))}"),
        action_type="hermes.gateway.restart", target=f"hermes-gateway:{profile}",
        generation=str(scope.target_generation), source="stabilityd-daemon",
        input_data={"profile": profile, "unit": unit, "reasonCode": reason_code},
        authorization_ref=rule.authority_ref, policy_ref=policy_ref,
        evidence_refs=(f"evidence://snapshot/{snapshot_generation}", scope_ref,
                       policy_ref, f"policy-digest:sha256:{policy_digest}"),
        metadata={"actor": "cat-agents-stabilityd", "request_source": "stabilityd-daemon"},
    )
    def eligibility(spec_: ActionSpec, loaded: Dict[str, Any], now_ms: int) -> tuple[str, ...]:
        planned = loaded.get("hermersGatewayRestartProfiles")
        if (loaded.get("canRestartHermersGateway") is not True
                or str(loaded.get("hermersGatewayRestartReason") or "") != str(reason)
                or not isinstance(planned, list)):
            return ()
        matched = any(isinstance(item, dict) and str(item.get("profile") or "") == profile
                      and str(item.get("unit") or "") == unit for item in planned)
        try:
            latest = resolve_profile_scope()
        except Exception:
            return ()
        if (not matched or latest.status != "clear" or latest.target_generation != spec_.generation
                or tuple(sorted(latest.affected_agents)) != tuple(sorted(scope.affected_agents))
                or not unit_is_explicitly_down()):
            return ()
        return (f"evidence://snapshot/{snapshot_generation}", scope_ref)

    def precheck(_spec: ActionSpec, _record: Any) -> BoundaryCheck:
        try:
            latest = resolve_profile_scope()
        except Exception:
            latest = None
        if (latest is None or latest.status != "clear" or latest.target_generation != scope.target_generation
                or tuple(sorted(latest.affected_agents)) != tuple(sorted(scope.affected_agents))
                or not unit_is_explicitly_down()):
            return BoundaryCheck("rejected", "evidence://hermes-profile-scope/unknown")
        if len(recent_hermers_gateway_restart_history(conn)) >= MAX_RESTARTS_PER_WINDOW:
            return BoundaryCheck("rejected", "evidence://hermes-gateway/restart-storm")
        last = int(db_get(conn, last_key, 0) or 0)
        if last and epoch() - last < RESTART_COOLDOWN_SECONDS:
            return BoundaryCheck("rejected", "evidence://hermes-gateway/cooldown")
        return BoundaryCheck("approved", scope_ref)

    operation_meta: Dict[str, Any] = {}
    def operation(_spec: ActionSpec, record: Any) -> OperationResult:
        started = time.monotonic()
        proc = run_hermes_profile_gateway_cmd(profile, "restart", timeout=60)
        operation_meta.update(exitCode=proc.returncode, durationMs=int((time.monotonic() - started) * 1000),
                              stderrByteCount=len(proc.stderr or ""))
        if proc.returncode != 0:
            return OperationResult("partial", f"outcome://hermes-gateway-restart/exit-{proc.returncode}")
        db_set(conn, last_key, epoch())
        record_hermers_gateway_restart_time(conn, profile)
        return OperationResult("complete", f"outcome://hermes-gateway-restart/{record.action_id}")

    def postcheck(_spec: ActionSpec, _record: Any, _result: OperationResult) -> PostcheckResult:
        try:
            proc = run_hermes_profile_gateway_cmd(profile, "status", timeout=20)
            status_text = (proc.stdout or "").lower()
            explicit_failure = re.search(
                r"\b(not\s+(?:active|running|ready)|inactive|stopped|failed|down|unhealthy)\b",
                status_text,
            )
            explicit_ready = re.search(r"\b(active|running|ready)\b", status_text)
            if proc.returncode != 0 or explicit_failure:
                state = "failed"
            elif proc.returncode == 0 and explicit_ready:
                state = "verified"
            else:
                state = "unknown"
            digest = hashlib.sha256(f"{proc.returncode}:{state}".encode()).hexdigest()
            return PostcheckResult(state, f"evidence://hermes-gateway-postcheck/sha256/{digest}")
        except Exception:
            return PostcheckResult("unknown", "evidence://hermes-gateway-postcheck/unknown")

    try:
        execution = execute_governed_effect(
            spec, policy, eligibility_evidence=eligibility, precheck=precheck,
            operation=operation, postcheck=postcheck,
        )
    except Exception as exc:
        return {"actionId": action_id, "ts": ts(), "tsEpoch": epoch(),
                "source": "cat-agents-stabilityd", "component": "hermers",
                "action": "restart_hermers_gateway", "result": "uncertain",
                "profile": profile, "unit": unit, "error": type(exc).__name__}
    state_map = {"succeeded": "ok", "failed": "failed", "blocked": "blocked", "uncertain": "uncertain"}
    return {"actionId": execution.record.action_id, "ts": ts(), "tsEpoch": epoch(),
            "source": "cat-agents-stabilityd", "component": "hermers",
            "action": "restart_hermers_gateway",
            "result": state_map.get(execution.record.state, "existing" if execution.disposition == "existing" else "blocked"),
            "ledgerState": execution.record.state, "ledgerDisposition": execution.disposition,
            "profile": profile, "unit": unit, "reason": reason,
            "exitCode": operation_meta.get("exitCode"), "durationMs": operation_meta.get("durationMs"),
            "stderrOmitted": True, "stderrByteCount": operation_meta.get("stderrByteCount", 0)}


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
        "topMem": command_probe(["ps", "-eo", "pid,ppid,stat,etime,rss,comm", "--sort=-%mem"], timeout=5, max_chars=12_000),
        "topCpu": command_probe(["ps", "-eo", "pid,ppid,stat,etime,%cpu,comm", "--sort=-%cpu"], timeout=5, max_chars=12_000),
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


def execute_hermers_profile_lifecycle(
    conn: sqlite3.Connection, profile: str, item: Dict[str, Any], target_mode: str,
    policy: Dict[str, Any], snapshot_generation: str,
) -> Dict[str, Any]:
    unit = str(item.get("unit") or f"hermes-gateway-{profile}.service")
    action_id = f"hermes-profile-mode-{hashlib.sha256(profile.encode()).hexdigest()[:12]}-{target_mode}-{int(time.time())}"
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", profile) or unit != f"hermes-gateway-{profile}.service":
        return {"actionId": action_id, "action": "set_hermers_profile_mode", "result": "blocked",
                "profile": profile, "unit": unit, "targetMode": target_mode,
                "blockedReason": "invalid-profile-or-unit"}
    if (target_mode not in {"hot", "hibernate"} or profile not in HERMERS_PROFILE_LIFECYCLE_ALLOWLIST
            or item.get("managed") is not True or item.get("activeWork") is not False):
        return {"actionId": action_id, "action": "set_hermers_profile_mode", "result": "blocked",
                "profile": profile, "unit": unit, "targetMode": target_mode,
                "blockedReason": "lifecycle-candidate-not-eligible"}
    if target_mode == "hibernate" and (item.get("active") is not True or item.get("safeToHibernate") is not True):
        return {"actionId": action_id, "action": "set_hermers_profile_mode", "result": "blocked",
                "profile": profile, "unit": unit, "targetMode": target_mode,
                "blockedReason": str(item.get("safeToHibernateReason") or "runtime-safe-to-hibernate-missing")}
    if target_mode == "hot" and (item.get("active") is not False or HERMERS_PROFILE_MODE_START_ENABLED is not True):
        return {"actionId": action_id, "action": "set_hermers_profile_mode", "result": "blocked",
                "profile": profile, "unit": unit, "targetMode": target_mode,
                "blockedReason": "profile-start-not-eligible"}
    generation = str(current_host_generation() or "")
    if not generation or not snapshot_generation:
        return {"actionId": action_id, "action": "set_hermers_profile_mode", "result": "blocked",
                "profile": profile, "unit": unit, "targetMode": target_mode,
                "blockedReason": "generation-unavailable"}
    owner_ok, owner_reason, scope_ref = hermers_profile_live_owner(
        profile, list(item.get("agentIds") or []), generation,
    )
    if not owner_ok:
        return {"actionId": action_id, "action": "set_hermers_profile_mode", "result": "blocked",
                "profile": profile, "unit": unit, "targetMode": target_mode,
                "blockedReason": owner_reason}
    now_s = epoch()
    action_key = f"hermers_profile_mode:{profile}:{target_mode}"
    last_action = int(db_get(conn, action_key, 0) or 0)
    if last_action and now_s - last_action < HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS:
        return {"actionId": action_id, "action": "set_hermers_profile_mode", "result": "cooldown_skip",
                "profile": profile, "unit": unit, "targetMode": target_mode,
                "cooldownUntilEpoch": last_action + HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS}
    policy_digest, policy_ref = policy_reference(policy)
    rule = STANDING_RULES["hermes.profile.lifecycle"]
    action = "stop" if target_mode == "hibernate" else "start"
    reason_code = re.sub(r"[^A-Za-z0-9_-]+", "-", str(item.get("reason") or "policy"))[:80] or "policy"
    spec = ActionSpec(
        idempotency_key=(f"hermes.profile.lifecycle:{profile}:{target_mode}:{generation}:"
                         f"{int(now_s // max(1, HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS))}"),
        action_type="hermes.profile.lifecycle", target=f"hermes-profile:{profile}",
        generation=generation, source="stabilityd-daemon",
        input_data={"profile": profile, "unit": unit, "targetMode": target_mode,
                    "operation": action, "reasonCode": reason_code},
        authorization_ref=rule.authority_ref, policy_ref=policy_ref,
        evidence_refs=(f"evidence://snapshot/{snapshot_generation}", scope_ref,
                       policy_ref, f"policy-digest:sha256:{policy_digest}"),
        metadata={"actor": "cat-agents-stabilityd", "request_source": "stabilityd-daemon"},
    )

    def current_boundary() -> Tuple[bool, str, str]:
        valid, why, ref = hermers_profile_live_owner(profile, list(item.get("agentIds") or []), generation)
        if not valid:
            return False, why, ""
        try:
            registry = workflow_runtime_registry_records()
            profiles, meta = hermers_profiles_from_runtime_registry([], registry)
            activity = hermers_profile_workflow_activity(profiles).get(profile) or {}
            if (meta.get("scopeComplete") is not True or activity.get("probeOk") is not True
                    or int(activity.get("activeRuntimeCount") or 0) > 0
                    or int(activity.get("activeDispatchCount") or 0) > 0):
                return False, "active-or-unknown-workflow-activity", ""
            service = systemctl_user_show(unit)
            active = service.get("ActiveState") == "active" and service.get("SubState") == "running"
            if target_mode == "hibernate":
                if not active:
                    return False, "profile-no-longer-active", ""
                if item.get("safeToHibernate") is not True:
                    return False, "safe-to-hibernate-evidence-unavailable", ""
            elif active:
                return False, "profile-already-active", ""
            return True, "profile-lifecycle-boundary-verified", ref
        except Exception:
            return False, "profile-lifecycle-boundary-unknown", ""

    def eligibility(_spec: ActionSpec, loaded: Dict[str, Any], _now_ms: int) -> tuple[str, ...]:
        if loaded.get("hermersProfileModeActuateEnabled") is not True:
            return ()
        if target_mode == "hot" and loaded.get("hermersProfileModeStartEnabled") is not True:
            return ()
        eligible, _, ref = current_boundary()
        return (f"evidence://snapshot/{snapshot_generation}", ref) if eligible else ()

    def precheck(_spec: ActionSpec, _record: Any) -> BoundaryCheck:
        eligible, _, ref = current_boundary()
        if not eligible:
            return BoundaryCheck("rejected", "evidence://hermes-profile-lifecycle/boundary-changed")
        last = int(db_get(conn, action_key, 0) or 0)
        if last and epoch() - last < HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS:
            return BoundaryCheck("rejected", "evidence://hermes-profile-lifecycle/cooldown")
        return BoundaryCheck("approved", ref)

    operation_meta: Dict[str, Any] = {}
    def operation(_spec: ActionSpec, record: Any) -> OperationResult:
        started = time.monotonic()
        proc = run_hermes_profile_gateway_cmd(profile, action, timeout=30)
        operation_meta.update(exitCode=proc.returncode, durationMs=int((time.monotonic() - started) * 1000),
                              stderrByteCount=len(proc.stderr or ""))
        if proc.returncode != 0:
            return OperationResult("partial", f"outcome://hermes-profile-{action}/exit-{proc.returncode}")
        db_set(conn, action_key, epoch())
        if target_mode == "hibernate":
            db_set(conn, f"hermers_profile_mode:planned:{profile}",
                   {"profile": profile, "targetMode": target_mode, "unit": unit,
                    "reason": reason_code, "setAt": ts(),
                    "setAtEpoch": epoch(), "source": "cat-agents-stabilityd"})
        return OperationResult("complete", f"outcome://hermes-profile-{action}/{record.action_id}")

    def postcheck(_spec: ActionSpec, _record: Any, _result: OperationResult) -> PostcheckResult:
        try:
            service = systemctl_user_show(unit)
            active = service.get("ActiveState") == "active" and service.get("SubState") == "running"
            active_state = service.get("ActiveState")
            if not isinstance(active_state, str) or not active_state:
                state = "unknown"
            elif target_mode == "hot" and active:
                state = "verified"
            elif target_mode == "hibernate" and not active and active_state == "inactive":
                state = "verified"
            elif active_state == "unknown":
                state = "unknown"
            else:
                state = "failed"
            ref = "evidence://hermes-profile-postcheck/sha256/" + hashlib.sha256(
                json.dumps({"active": active, "activeState": service.get("ActiveState"),
                            "subState": service.get("SubState")}, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            return PostcheckResult(state, ref)
        except Exception:
            return PostcheckResult("unknown", "evidence://hermes-profile-postcheck/unknown")

    try:
        execution = execute_governed_effect(spec, policy, eligibility_evidence=eligibility,
                                            precheck=precheck, operation=operation, postcheck=postcheck)
    except Exception as exc:
        return {"actionId": action_id, "action": "set_hermers_profile_mode", "result": "uncertain",
                "profile": profile, "unit": unit, "targetMode": target_mode, "error": type(exc).__name__}
    state_map = {"succeeded": "ok", "failed": "failed", "blocked": "blocked", "uncertain": "uncertain"}
    return {"actionId": execution.record.action_id, "action": "set_hermers_profile_mode",
            "result": state_map.get(execution.record.state, "existing"),
            "ledgerState": execution.record.state, "ledgerDisposition": execution.disposition,
            "profile": profile, "unit": unit, "targetMode": target_mode,
            "operation": f"hermes-gateway-{action}", "adapter": "hermes-cli",
            "exitCode": operation_meta.get("exitCode"), "durationMs": operation_meta.get("durationMs"),
            "stderrOmitted": True, "stderrByteCount": operation_meta.get("stderrByteCount", 0)}


def hermers_profile_mode_actuate(
    conn: sqlite3.Connection, snapshot: Dict[str, Any], policy: Optional[Dict[str, Any]] = None,
    *, snapshot_generation: str = "",
) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    if not HERMERS_PROFILE_MODE_ENABLED or not HERMERS_PROFILE_MODE_ACTUATE_ENABLED or not isinstance(policy, dict):
        return actions
    hermers = snapshot.get("hermers") if isinstance(snapshot.get("hermers"), dict) else {}
    modes = hermers.get("profileModes") if isinstance(hermers.get("profileModes"), dict) else {}
    profiles = modes.get("profiles") if isinstance(modes.get("profiles"), dict) else {}
    now_s = epoch()
    for profile, item in profiles.items():
        if not isinstance(item, dict):
            continue
        target_mode = str(item.get("targetMode") or item.get("observedMode") or "warm")
        active = bool(item.get("active"))
        unit = str(item.get("unit") or f"hermes-gateway-{profile}.service")
        if (target_mode == "hibernate" and active) or (target_mode == "hot" and not active):
            actions.append(execute_hermers_profile_lifecycle(
                conn, str(profile), item, target_mode, policy,
                str(snapshot_generation or snapshot.get("generationId") or ""),
            ))
        elif item.get("managed") is not True and target_mode in {"hot", "hibernate"}:
            actions.append({"action": "set_hermers_profile_mode", "result": "blocked",
                            "profile": profile, "unit": unit, "targetMode": target_mode,
                            "blockedReason": "profile-not-in-lifecycle-allowlist"})
        elif item.get("activeWork"):
            actions.append({"action": "set_hermers_profile_mode", "result": "blocked",
                            "profile": profile, "unit": unit, "targetMode": target_mode,
                            "blockedReason": "active-work"})
    return actions


def _hermers_signal_profile_protected(profile: str, item: Optional[Dict[str, Any]] = None) -> bool:
    registry_ids = {str(value) for value in ((item or {}).get("agentIds") or []) if str(value)}
    # Config/environment can add protection, never remove canonical protected members.
    return is_protected_identity({profile, *registry_ids}, HERMERS_PROFILE_PROTECTED_IDS)


def _hermers_signal_profile_scope(profile: str, item: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    if _hermers_signal_profile_protected(profile, item):
        return False, "protected-profile"
    if not isinstance(item, dict) or item.get("registryScopeComplete") is not True:
        return False, "registry-scope-unavailable"
    if item.get("registryProfileMatched") is not True or str(item.get("registryProfile") or "") != profile:
        return False, "registry-profile-owner-unavailable"
    if not isinstance(item.get("agentIds"), list) or not item["agentIds"]:
        return False, "registry-agent-owner-unavailable"
    return True, "registry-profile-owner-verified"


def _verify_captured_process_identity(pid: int, item: Dict[str, Any]) -> Tuple[bool, str]:
    expected = item.get("processIdentity") if isinstance(item.get("processIdentity"), dict) else {}
    matched, reason = identities_match(expected, read_process_identity(pid))
    return (True, "identity-match") if matched else (False, reason)


def hermers_profile_live_owner(profile: str, expected_agents: List[str], expected_generation: str) -> Tuple[bool, str, str]:
    """Rebind a Hermes process effect to the current authoritative profile owner."""
    if is_protected_identity({profile, *expected_agents}, HERMERS_PROFILE_PROTECTED_IDS):
        return False, "protected-profile", ""
    try:
        registry = workflow_runtime_registry_records()
        profiles, meta = hermers_profiles_from_runtime_registry([], registry)
        item = profiles.get(profile) or {}
        if (registry.get("source") != "db" or registry.get("writeEligible") is not True
                or meta.get("scopeComplete") is not True or not item.get("registryRecords")
                or current_host_generation() != expected_generation):
            return False, "registry-or-generation-unavailable", ""
        current_agents = sorted(set(item.get("agentIds") or []))
        if not current_agents or current_agents != sorted(set(expected_agents)):
            return False, "profile-owner-changed", ""
        if is_protected_identity({profile, *current_agents}, HERMERS_PROFILE_PROTECTED_IDS):
            return False, "protected-profile", ""
        ref_data = {"profile": profile, "agents": current_agents, "generation": expected_generation}
        ref = "evidence://hermes-process-scope/sha256/" + hashlib.sha256(
            json.dumps(ref_data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return True, "profile-owner-verified", ref
    except Exception:
        return False, "registry-or-generation-unavailable", ""


def execute_hermers_process_signal(
    item: Dict[str, Any], action_type: str, policy_flag: str, verifier: Any,
    rows_provider: Any,
    policy: Dict[str, Any], snapshot_generation: str,
) -> Dict[str, Any]:
    profile = str(item.get("profile") or "")
    identity = item.get("processIdentity") if isinstance(item.get("processIdentity"), dict) else {}
    try:
        pid = int(identity.get("pid") or item.get("pid") or 0)
    except (TypeError, ValueError):
        pid = 0
    generation = str(current_host_generation() or "")
    identity_digest = hashlib.sha256(json.dumps(
        {key: identity.get(key) for key in ("pid", "starttime", "uid", "euid", "bootId", "cmdlineDigest", "cgroupDigest")},
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    base_result = {"pid": pid, "profile": profile}
    if pid <= 1 or not generation or not snapshot_generation or identity.get("status") != "known":
        return {**base_result, "result": "blocked", "reason": "identity-or-generation-unavailable"}
    owner_ok, owner_reason, scope_ref = hermers_profile_live_owner(
        profile, list(item.get("agentIds") or []), generation,
    )
    if not owner_ok:
        return {**base_result, "result": "blocked", "reason": owner_reason}
    policy_digest, policy_ref = policy_reference(policy)
    rule = STANDING_RULES[action_type]
    idempotency_key = f"{action_type}:{profile}:{pid}:{identity.get('bootId')}:{identity.get('starttime')}"
    spec = ActionSpec(
        idempotency_key=idempotency_key, action_type=action_type,
        target=f"hermes-process:{profile}:{pid}", generation=generation,
        source="stabilityd-daemon",
        input_data={"profile": profile, "pid": pid, "processIdentityDigest": identity_digest},
        authorization_ref=rule.authority_ref, policy_ref=policy_ref,
        evidence_refs=(f"evidence://snapshot/{snapshot_generation}", scope_ref,
                       f"evidence://process-identity/sha256/{identity_digest}",
                       policy_ref, f"policy-digest:sha256:{policy_digest}"),
        metadata={"actor": "cat-agents-stabilityd", "request_source": "stabilityd-daemon"},
    )
    latest = {"item": item, "scopeRef": scope_ref}

    def eligibility(spec_: ActionSpec, loaded: Dict[str, Any], _now_ms: int) -> tuple[str, ...]:
        if loaded.get(policy_flag) is not True:
            return ()
        valid, _, ref = hermers_profile_live_owner(profile, list(item.get("agentIds") or []), generation)
        if not valid:
            return ()
        try:
            rows = rows_provider()
            verified, _ = verifier(pid, profile, rows, item) if action_type.endswith("orphan_reap") else verifier(pid, profile, item, rows)
        except Exception:
            return ()
        if not verified:
            return ()
        latest.update(item=item, scopeRef=ref)
        return f"evidence://snapshot/{snapshot_generation}", ref, f"evidence://process-identity/sha256/{identity_digest}"

    def precheck(_spec: ActionSpec, _record: Any) -> BoundaryCheck:
        valid, _, ref = hermers_profile_live_owner(profile, list(item.get("agentIds") or []), generation)
        if not valid:
            return BoundaryCheck("rejected", "evidence://hermes-process-scope/unknown")
        try:
            rows = rows_provider()
            verified, _ = verifier(pid, profile, rows, item) if action_type.endswith("orphan_reap") else verifier(pid, profile, item, rows)
        except Exception:
            verified = False
        if not verified:
            return BoundaryCheck("rejected", "evidence://hermes-process-identity/changed")
        latest["scopeRef"] = ref
        return BoundaryCheck("approved", ref)

    result_box: Dict[str, Any] = {}
    def operation(_spec: ActionSpec, _record: Any) -> OperationResult:
        outcome = terminate_process_instance(identity)
        result_box.update(outcome)
        outcome_digest = hashlib.sha256(json.dumps(
            {"result": outcome.get("result"), "reason": outcome.get("reason"), "signal": outcome.get("signal")},
            sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        state = outcome.get("result")
        operation_status = "complete" if state == "succeeded" else "unknown" if state == "uncertain" else "partial"
        return OperationResult(operation_status, f"outcome://hermes-process-signal/sha256/{outcome_digest}")

    def postcheck(_spec: ActionSpec, _record: Any, operation_result: OperationResult) -> PostcheckResult:
        if result_box.get("result") == "uncertain":
            return PostcheckResult("unknown", "evidence://hermes-process-postcheck/uncertain")
        if result_box.get("result") != "succeeded":
            return PostcheckResult("failed", "evidence://hermes-process-postcheck/not-signaled")
        current = read_process_identity(pid)
        if current.get("status") != "known":
            if not Path("/proc").joinpath(str(pid)).exists():
                return PostcheckResult("verified", "evidence://hermes-process-postcheck/exited")
            return PostcheckResult("unknown", "evidence://hermes-process-postcheck/identity-unknown")
        matches, _ = identities_match(identity, current)
        if matches:
            return PostcheckResult("failed", "evidence://hermes-process-postcheck/same-instance")
        if any(current.get(key) != identity.get(key) for key in ("bootId", "pid", "starttime")):
            return PostcheckResult("verified", "evidence://hermes-process-postcheck/instance-gone")
        return PostcheckResult("unknown", "evidence://hermes-process-postcheck/identity-drift")

    try:
        execution = execute_governed_effect(spec, policy, eligibility_evidence=eligibility,
                                            precheck=precheck, operation=operation, postcheck=postcheck)
    except Exception as exc:
        return {**base_result, "result": "uncertain", "error": type(exc).__name__}
    state_map = {"succeeded": "ok", "failed": "failed", "blocked": "blocked", "uncertain": "uncertain"}
    return {**base_result, "result": state_map.get(execution.record.state, "existing"),
            "ledgerState": execution.record.state, "ledgerDisposition": execution.disposition,
            "reason": result_box.get("reason") if execution.disposition == "executed" else None}


def verify_hermers_orphan_worker(
    pid: int, profile: str, rows: List[Dict[str, str]], item: Optional[Dict[str, Any]] = None
) -> Tuple[bool, str]:
    registry_scope_ok, registry_scope_reason = _hermers_signal_profile_scope(profile, item)
    if not registry_scope_ok:
        return False, registry_scope_reason
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
    identity_ok, identity_reason = _verify_captured_process_identity(pid, item or {})
    if not identity_ok:
        return False, identity_reason
    return True, "verified-orphan"


def verify_hermers_idle_lsp(pid: int, profile: str, item: Dict[str, Any], rows: List[Dict[str, str]]) -> Tuple[bool, str]:
    registry_scope_ok, registry_scope_reason = _hermers_signal_profile_scope(profile, item)
    if not registry_scope_ok:
        return False, registry_scope_reason
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
    identity_ok, identity_reason = _verify_captured_process_identity(pid, item)
    if not identity_ok:
        return False, identity_reason
    return True, "verified-idle-lsp"


def _signal_batch_result(items: List[Dict[str, Any]]) -> str:
    results = {str(item.get("result") or "uncertain") for item in items}
    if "uncertain" in results:
        return "uncertain"
    if "failed" in results:
        return "failed"
    if "blocked" in results:
        return "blocked"
    return "ok"


def hermers_actuate(
    conn: sqlite3.Connection, snapshot: Dict[str, Any], policy: Dict[str, Any], *, snapshot_generation: str = "",
) -> List[Dict[str, Any]]:
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
            verified, verify_reason = verify_hermers_orphan_worker(pid, profile, current_rows, item)
            if not verified:
                killed.append({"pid": pid, "profile": profile, "result": "blocked", "reason": verify_reason})
                continue
            outcome = execute_hermers_process_signal(
                item, "hermes.process.orphan_reap", "canReapHermersOrphanWorkers",
                verify_hermers_orphan_worker, ps_rows, policy, snapshot_generation,
            )
            killed.append({"pid": pid, "profile": profile, "ageSeconds": item.get("ageSeconds"),
                           "verified": verify_reason, **outcome})
        if killed:
            actions.append({"action": "reap_hermers_acp_orphan_workers", "result": _signal_batch_result(killed), "workers": killed})
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
            outcome = execute_hermers_process_signal(
                item, "hermes.process.idle_lsp_reap", "canReapHermersIdleLsp",
                verify_hermers_idle_lsp, ps_rows, policy, snapshot_generation,
            )
            reaped.append(
                {
                    "pid": pid,
                    "profile": profile,
                    "processType": item.get("processType") or "pyright-langserver",
                    "ageSeconds": item.get("ageSeconds"),
                    "idleObservedSeconds": item.get("idleObservedSeconds"),
                    "rssBytes": item.get("rssBytes"),
                    "verified": verify_reason,
                    **outcome,
                }
            )
        if reaped:
            actions.append({"action": "reap_hermers_idle_lsp_processes", "result": _signal_batch_result(reaped), "processes": reaped})
    elif idle_lsps:
        actions.append(
            {
                "action": "observe_hermers_idle_lsp_processes",
                "result": "reap_blocked_by_policy",
                "processes": idle_lsps[:20],
            }
        )
    actions.extend(hermers_profile_mode_actuate(
        conn, snapshot, policy, snapshot_generation=snapshot_generation,
    ))
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
                    policy=policy, snapshot_generation=snapshot_generation,
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
    for action in cron_actuate(
        snapshot, policy, snapshot_generation=str(snapshot.get("generationId") or ""),
    ):
        action.update({"actionId": f"{action['action']}-{int(time.time() * 1000)}", "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd", "component": "cron"})
        actions.append(action)
    for action in session_actuate(
        conn, snapshot, policy, snapshot_generation=str(snapshot.get("generationId") or ""),
    ):
        action.update({"actionId": f"{action['action']}-{int(time.time() * 1000)}", "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd", "component": "session"})
        actions.append(action)
    for action in hermers_actuate(
        conn, snapshot, policy, snapshot_generation=str(snapshot.get("generationId") or ""),
    ):
        action.update({"actionId": f"{action['action']}-{int(time.time() * 1000)}", "ts": ts(), "tsEpoch": epoch(), "source": "cat-agents-stabilityd", "component": "hermers"})
        actions.append(action)
    if policy.get("canRestartGateway"):
        registry = workflow_runtime_registry_records()
        gateway = snapshot.get("gateway") if isinstance(snapshot.get("gateway"), dict) else {}
        protection_decision = resolve_protection_scope(
            registry.get("records") if isinstance(registry.get("records"), list) else [],
            registry_source=str(registry.get("source") or "unknown"),
            registry_write_eligible=registry.get("writeEligible") is True,
            scope_complete=registry.get("writeEligible") is True and registry.get("source") == "db",
            target_kind="shared-gateway",
            target_id="dev-server",
            runtime="openclaw",
            target_generation=str(gateway.get("nodeGeneration") or ""),
        )
        actions.append(
            gateway_restart(
                conn,
                str(policy.get("restartReason") or "policy"),
                protection_decision,
                policy=policy,
                snapshot_generation=str(snapshot.get("generationId") or ""),
                allow_protected_impact=bool(policy.get("canRestartGateway") and policy.get("restartCandidate")),
            )
        )
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


def write_legacy_watchdog_health(snapshot: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    gateway = snapshot.get("gateway") or {}
    control_plane = snapshot.get("controlPlane") or {}
    payload = {
        "generationId": snapshot.get("generationId"),
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
    return write_json_atomic(LEGACY_WATCHDOG_HEALTH, payload)


_COMPONENT_PROBE_NAMES = frozenset({
    "gateway", "cron", "session", "channel", "hermers", "auth", "resource", "config", "desired_state",
})
_COMPONENT_PROBE_DB_NAMES = frozenset({"hermers", "auth"})
_COMPONENT_PROBE_STATE_DB_ENV = "CAT_AGENTS_STABILITY_COMPONENT_STATE_DB"
_COMPONENT_PROBE_PARENT_PID_ENV = "CAT_AGENTS_STABILITY_COMPONENT_PARENT_PID"


class CollectorProcessCleanupFailure(RuntimeError):
    """A component process group could not be proven stopped; abort this writer generation."""


def install_component_probe_parent_death_guard(expected_parent_pid: int) -> bool:
    """Bind an internal worker group to its parent; false means parent already exited."""
    def kill_worker_group(_signum: int = 0, _frame: Any = None) -> None:
        with contextlib.suppress(OSError):
            os.killpg(os.getpgrp(), signal.SIGKILL)

    if type(expected_parent_pid) is not int or expected_parent_pid <= 1:
        return False
    if sys.platform.startswith("linux"):
        signal.signal(signal.SIGTERM, kill_worker_group)
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            return False
        if os.getppid() != expected_parent_pid:
            kill_worker_group()
            return False
        return True
    # macOS has no PR_SET_PDEATHSIG; this monitor is best-effort and the
    # production Linux worker uses the kernel parent-death signal above.
    parent_gone = threading.Event()

    def watch_parent() -> None:
        while not parent_gone.wait(0.1):
            if os.getppid() != expected_parent_pid:
                kill_worker_group()
                return

    if os.getppid() != expected_parent_pid:
        kill_worker_group()
        return False
    threading.Thread(target=watch_parent, name="stabilityd-probe-parent-watch", daemon=True).start()
    return True


def collector_worker_environment() -> Dict[str, str]:
    """Build a minimal, explicit worker environment without credential variables."""
    worker_env = {
        key: value for key, value in os.environ.items()
        if key in COLLECTOR_ENV_ALLOWLIST and isinstance(value, str) and "\0" not in value and len(value) <= 8192
    }
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        value = os.environ.get(key)
        if not isinstance(value, str) or not value or "\0" in value or len(value) > 8192:
            continue
        try:
            parsed = urllib.parse.urlsplit(value if "://" in value else "http://" + value)
            if (parsed.scheme in {"http", "https", "socks5", "socks5h"} and parsed.hostname
                    and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment):
                worker_env[key] = value
        except Exception:
            continue
    for key in ("NO_PROXY", "no_proxy"):
        value = os.environ.get(key)
        if isinstance(value, str) and "\0" not in value and len(value) <= 4096:
            worker_env[key] = value
    # urllib's explicit Telegram probe proxy may be configured separately. Pass
    # it only when it is a credential-free URL; otherwise use the loopback default.
    proxy = worker_env.get("OPENCLAW_STABILITY_HEALTH_PROXY")
    if proxy:
        try:
            parsed = urllib.parse.urlsplit(proxy)
            if (parsed.scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname
                    or parsed.username or parsed.password or parsed.query or parsed.fragment):
                worker_env.pop("OPENCLAW_STABILITY_HEALTH_PROXY", None)
        except Exception:
            worker_env.pop("OPENCLAW_STABILITY_HEALTH_PROXY", None)
    try:
        worker_env[_COMPONENT_PROBE_STATE_DB_ENV] = str(STATE_DB.resolve(strict=True))
    except OSError:
        worker_env.pop(_COMPONENT_PROBE_STATE_DB_ENV, None)
    return worker_env


def persist_component_cache_updates(conn: sqlite3.Connection, updates: Mapping[str, Any]) -> None:
    """Commit only the two existing collector cache domains, atomically in the parent."""
    if not isinstance(updates, Mapping) or len(updates) > 513 or conn.in_transaction:
        raise ValueError("invalid cache proposals or parent transaction state")
    encoded_updates = []
    total_bytes = 0
    for key, value in updates.items():
        if not isinstance(key, str) or not (
            key == "hermers_lsp_idle_state"
            or re.fullmatch(r"auth:openclaw:[A-Za-z0-9_-]{1,64}", key)
        ):
            raise ValueError("cache proposal key is outside the collector allowlist")
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        total_bytes += len(encoded.encode("utf-8"))
        if total_bytes > COLLECTOR_OUTPUT_MAX_BYTES:
            raise ValueError("cache proposals exceed size limit")
        encoded_updates.append((key, encoded, epoch()))
    if not encoded_updates:
        return
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.executemany(
            "INSERT INTO kv(key, value, updated_at) VALUES(?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            encoded_updates,
        )
        conn.commit()
    except Exception:
        with contextlib.suppress(Exception):
            conn.rollback()
        raise


def _run_component_collector(
    name: str, conn: Optional[sqlite3.Connection], findings: List[Dict[str, Any]],
    hermers_profiles: Optional[Iterable[str]] = None, cache_updates: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if name == "gateway":
        return gateway_collect(findings)
    if name == "cron":
        return cron_collect(findings)
    if name == "session":
        return session_collect(findings)
    if name == "channel":
        return channel_collect(findings)
    if name == "hermers":
        if conn is None:
            raise RuntimeError("component database unavailable")
        return hermers_collect(conn, findings, persist_cache=cache_updates is None, cache_updates=cache_updates)
    if name == "auth":
        if conn is None:
            raise RuntimeError("component database unavailable")
        return auth_collect(conn, findings, hermers_profiles,
                            persist_probe_cache=cache_updates is None, cache_updates=cache_updates)
    if name == "resource":
        return resource_collect(findings)
    if name == "config":
        return config_collect(findings)
    if name == "desired_state":
        return desired_state_drift()
    raise ValueError("unknown component")


def _open_component_probe_db() -> sqlite3.Connection:
    raw_db = os.environ.get(_COMPONENT_PROBE_STATE_DB_ENV, "")
    db_path = Path(raw_db)
    if not db_path.is_absolute() or not db_path.is_file() or db_path.is_symlink():
        raise ValueError("component state database unavailable")
    expected_db = STATE_DB.resolve(strict=True)
    if db_path.resolve(strict=True) != expected_db:
        raise ValueError("component state database path mismatch")
    uri = "file:" + urllib.parse.quote(str(db_path), safe="/") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=min(5.0, COLLECTOR_BUDGET_MS / 1000))
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA query_only=ON")
    return conn


def _encode_component_probe_result(
    data: Dict[str, Any], findings: List[Dict[str, Any]], cache_updates: Optional[Dict[str, Any]] = None,
) -> Optional[bytes]:
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    encoded = bytearray()
    for part in encoder.iterencode({"data": data, "findings": findings, "cacheUpdates": cache_updates or {}}):
        # A single giant string must not be copied into another giant encoded
        # buffer before the protocol bound is enforced.
        if len(part) > COLLECTOR_OUTPUT_MAX_BYTES:
            return None
        chunk = part.encode("utf-8")
        if len(encoded) + len(chunk) > COLLECTOR_OUTPUT_MAX_BYTES:
            return None
        encoded.extend(chunk)
    return bytes(encoded)


def _component_probe_worker(argv: List[str]) -> int:
    """Fresh-interpreter entry point. Only fixed read-only collectors are selectable."""
    global _inspection_cache_enabled
    if len(argv) != 2 or argv[0] not in _COMPONENT_PROBE_NAMES:
        return 2
    name, raw_profiles = argv
    try:
        try:
            expected_parent_pid = int(os.environ.get(_COMPONENT_PROBE_PARENT_PID_ENV) or "0")
        except ValueError:
            return 2
        if not install_component_probe_parent_death_guard(expected_parent_pid):
            return 2
        raw_inspection = os.environ.get(_INSPECTION_WORKER_ENV)
        if raw_inspection is not None:
            if name not in {"gateway", "cron"} or len(raw_inspection.encode("utf-8")) > _INSPECTION_STATE_MAX_BYTES:
                return 2
            inspection = json.loads(raw_inspection)
            accept_inspection_worker_state(inspection, "input")
            _inspection_cache_enabled = inspection["enabled"]
        hermers_profiles = json.loads(raw_profiles)
        if (not isinstance(hermers_profiles, list) or len(hermers_profiles) > 512
                or any(not isinstance(item, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item) is None
                       for item in hermers_profiles)):
            return 2
        findings: List[Dict[str, Any]] = []
        conn = None
        if name in _COMPONENT_PROBE_DB_NAMES:
            conn = _open_component_probe_db()
        cache_updates: Dict[str, Any] = {}
        try:
            with open(os.devnull, "w", encoding="utf-8") as sink, contextlib.redirect_stdout(sink):
                data = _run_component_collector(name, conn, findings, hermers_profiles, cache_updates)
            if raw_inspection is not None and isinstance(data, dict):
                data[_INSPECTION_WORKER_FIELD] = inspection_worker_state()
            if not isinstance(data, dict) or any(
                not isinstance(item, dict)
                or any(not isinstance(item.get(field), str) for field in ("key", "severity", "component", "message"))
                for item in findings
            ):
                return 2
            payload = _encode_component_probe_result(data, findings, cache_updates)
            if payload is None:
                return 3
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
            return 0
        finally:
            if conn is not None:
                conn.close()
    except Exception:
        # Do not emit exception text, configuration values, or tracebacks.
        return 1


def collect_snapshot(
    conn: sqlite3.Connection, *, component_probe_runner: Any = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    snapshot: Dict[str, Any] = {
        "schemaVersion": 1,
        "checkedAt": ts(),
        "checkedAtEpoch": epoch(),
    }
    self_progress = stabilityd_progress_evidence(snapshot["checkedAtEpoch"])
    snapshot["selfProgress"] = self_progress
    if self_progress.get("state") == "stale_previous_generation":
        add_finding(
            findings, "stabilityd_progress_stale", "warning", "stabilityd",
            "previous stabilityd generation exceeded the loop progress threshold",
            previousGenerationId=self_progress.get("previousGenerationId"),
            previousAgeSeconds=self_progress.get("previousAgeSeconds"),
            thresholdSeconds=self_progress.get("thresholdSeconds"),
            supervision="existing-daemon-loop",
        )
    probes: Dict[str, Any] = {}
    pending_cache_updates: Dict[str, Any] = {}
    collector_failed = False

    runner = component_probe_runner or run_component_probe_hard
    worker_env = collector_worker_environment() if component_probe_runner is None else {}

    def collect_component(name: str, fallback: Dict[str, Any], hermers_profiles: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        global _inspection_gateway_context, _cron_rpc_retry_after
        nonlocal collector_failed
        if snapshot.get("collectorFatal"):
            collector_failed = True
            probes[name] = {
                "component": name, "status": "error", "source": "cat-agents-stabilityd",
                "coverage": False, "durationMs": 0, "budgetMs": COLLECTOR_BUDGET_MS,
                "maxOutputBytes": COLLECTOR_OUTPUT_MAX_BYTES, "errorClass": "PriorWorkerCleanupUnverified",
                "fatal": True, "noLiveGroupMemberObserved": False,
            }
            return dict(fallback)
        requested_profiles = sorted({
            item for item in hermers_profiles or []
            if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item)
        })[:512]
        command = [
            sys.executable, str(Path(__file__).resolve()), "__component_probe_v1", name,
            json.dumps(requested_profiles, ensure_ascii=False, separators=(",", ":")),
        ]
        child_env = dict(worker_env)
        if _inspection_cache_enabled and name in {"gateway", "cron"}:
            child_env[_INSPECTION_WORKER_ENV] = json.dumps(
                inspection_worker_state(), allow_nan=False, separators=(",", ":"))
        if component_probe_runner is None:
            child_env[_COMPONENT_PROBE_PARENT_PID_ENV] = str(os.getpid())
        result = runner(
            name, command, fallback, source="cat-agents-stabilityd",
            max_output_bytes=COLLECTOR_OUTPUT_MAX_BYTES, budget_ms=COLLECTOR_BUDGET_MS,
            env=child_env,
        )
        probes[name] = result["probe"]
        if _inspection_cache_enabled and name in {"gateway", "cron"}:
            returned_state = result.get("data", {}).pop(_INSPECTION_WORKER_FIELD, None)
            try:
                if result["probe"]["status"] != "ok":
                    raise ValueError("inspection worker failed")
                accept_inspection_worker_state(returned_state, name)
            except (ValueError, TypeError):
                # No previous healthy context survives an incomplete gateway cycle.
                if name == "gateway":
                    _inspection_cache.clear()
                    _inspection_gateway_context = (0, False)
                else:
                    _cron_rpc_retry_after = time.monotonic() + 300
                if result["probe"]["status"] == "ok":
                    result["probe"].update({"status": "error", "coverage": False,
                                           "errorClass": "InvalidInspectionWorkerState"})
                    result["data"] = dict(fallback)
        if (result["probe"].get("fatal") is True
                or result["probe"].get("noLiveGroupMemberObserved") is False):
            snapshot["collectorFatal"] = True
            raise CollectorProcessCleanupFailure("collector process cleanup was not verified")
        if result["probe"]["status"] == "ok":
            component_findings = result.get("findings") or []
            cache_updates = result.get("cacheUpdates") or {}
            if not isinstance(component_findings, list) or any(
                not isinstance(item, dict)
                or any(not isinstance(item.get(field), str) for field in ("key", "severity", "component", "message"))
                for item in component_findings
            ):
                result["probe"].update({"status": "error", "coverage": False, "errorClass": "InvalidWorkerFindings"})
                result["data"] = dict(fallback)
                component_findings = []
            if result["probe"]["status"] == "ok" and not isinstance(cache_updates, Mapping):
                result["probe"].update({"status": "error", "coverage": False, "errorClass": "InvalidWorkerCacheUpdates"})
                result["data"] = dict(fallback)
            if result["probe"]["status"] == "ok":
                if cache_updates:
                    for key, value in cache_updates.items():
                        if key in pending_cache_updates:
                            result["probe"].update({"status": "error", "coverage": False, "errorClass": "DuplicateWorkerCacheUpdate"})
                            result["data"] = dict(fallback)
                            pending_cache_updates.clear()
                            break
                        pending_cache_updates[key] = value
                findings.extend(component_findings if result["probe"]["status"] == "ok" else [])
            if result["probe"]["status"] != "ok":
                collector_failed = True
        else:
            collector_failed = True
        if result["probe"]["status"] != "ok":
            if _inspection_cache_enabled and name == "gateway":
                _inspection_cache.clear()
                _inspection_gateway_context = (0, False)
            elif _inspection_cache_enabled and name == "cron":
                _cron_rpc_retry_after = time.monotonic() + 300
            add_finding(
                findings,
                f"stability_collector_{name}_probe_failed",
                "warning",
                name,
                f"stabilityd {name} collector returned incomplete evidence",
                errorClass=result["probe"].get("errorClass"),
                durationMs=result["probe"].get("durationMs"),
                budgetMs=result["probe"].get("budgetMs"),
                coverage=False,
            )
        return result["data"]

    snapshot["gateway"] = collect_component(
        "gateway",
        {"active": None, "pid": 0, "portOk": None, "healthOk": None, "status": "unknown"},
    )
    snapshot["cron"] = collect_component(
        "cron",
        {"staleRunning": [], "expiredLeases": [], "storageStatus": {"storage": "unknown"}},
    )
    snapshot["session"] = collect_component("session", {"resetCandidates": []})
    snapshot["channel"] = collect_component("channel", {"channels": []})
    snapshot["hermers"] = collect_component(
        "hermers",
        {"profiles": {}, "orphanAcpWorkers": [], "idleLspProcesses": [], "profileModes": {"profiles": {}},
         "profileRegistry": {"available": False, "scopeComplete": False, "source": "unknown"}},
    )
    hermers_profiles = (snapshot.get("hermers") or {}).get("profiles") if isinstance(snapshot.get("hermers"), dict) else {}
    snapshot["auth"] = collect_component(
        "auth",
        {"hermers": {"scopeComplete": False, "profiles": {}}, "openclaw": {"scopeComplete": False, "agents": {}}},
        (hermers_profiles or {}).keys() if isinstance(hermers_profiles, dict) else None,
    )
    snapshot["resource"] = collect_component("resource", {"status": "unknown"})
    snapshot["config"] = collect_component("config", {"status": "unknown"})
    snapshot["desiredState"] = collect_component(
        "desired_state",
        {"ok": False, "drifts": [], "observations": [], "status": "unknown"}
    )
    snapshot["collectorProbes"] = probes
    if pending_cache_updates and not collector_failed:
        try:
            persist_component_cache_updates(conn, pending_cache_updates)
        except Exception as exc:
            snapshot["collectorFatal"] = True
            add_finding(
                findings, "stability_collector_cache_commit_failed", "critical", "stabilityd",
                "stabilityd collector cache proposals could not be committed atomically",
                errorClass=type(exc).__name__, coverage=False,
            )
    elif collector_failed:
        # Cache proposals from otherwise successful children are never persisted
        # when any component output in this generation is incomplete.
        pending_cache_updates.clear()
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
    snapshot["authMaintenance"] = build_auth_maintenance_plan(snapshot.get("auth") if isinstance(snapshot.get("auth"), dict) else {}, findings)
    return snapshot, findings, policy


def stabilityd_progress_evidence(now_epoch: Optional[int] = None) -> Dict[str, Any]:
    """Observe prior committed-loop freshness without adding a supervisor/timer."""
    now_value = int(now_epoch if now_epoch is not None else epoch())
    latest = load_json(LATEST_PATH, {}) or {}
    completed = latest.get("completedAtEpoch") if isinstance(latest, dict) else None
    if not isinstance(completed, (int, float)) or isinstance(completed, bool) or not math.isfinite(completed):
        state, age = "first_observation", None
    elif completed > now_value + 5:
        state, age = "clock_skew", None
    else:
        age = max(0, now_value - int(completed))
        state = "stale_previous_generation" if age > STABILITYD_PROGRESS_STALE_SECONDS else "recent_previous_generation"
    return {
        "state": state,
        "previousGenerationId": latest.get("generationId") if isinstance(latest, dict) else None,
        "previousAgeSeconds": age,
        "thresholdSeconds": STABILITYD_PROGRESS_STALE_SECONDS,
        "supervision": "existing-daemon-loop",
    }


def run_once(conn: sqlite3.Connection, no_action: bool = False) -> Dict[str, Any]:
    # no_action disables actuators, but this entrypoint still publishes evidence/KV.
    # Both writer modes share this lock; pure status readers never acquire it.
    ensure_dirs()
    with contextlib.ExitStack() as stack:
        try:
            stack.enter_context(ActuationLock(ACTUATION_LOCK_PATH))
        except ActuationBusy:
            return {
                "schemaVersion": 1, "status": "busy", "checkedAt": ts(),
                "reason": "actuation-writer-active", "statePublished": False,
                "actions": [{"action": "none", "result": "busy", "reason": "actuation-writer-active"}],
            }
        return _run_once_body(conn, no_action=no_action)


def _run_once_body(conn: sqlite3.Connection, no_action: bool = False) -> Dict[str, Any]:
    ensure_dirs()
    snapshot, findings, policy = collect_snapshot(conn)
    generation_id = uuid.uuid4().hex
    snapshot["generationId"] = generation_id
    policy["generationId"] = generation_id
    snapshot["controlPlane"] = control_plane_backpressure(snapshot, policy)
    actions = actuate_collected_snapshot(conn, snapshot, policy, no_action=no_action)
    snapshot["actions"] = actions
    snapshot["completedAt"] = ts()
    snapshot["completedAtEpoch"] = epoch()
    snapshot["workflowEvidence"] = write_workflow_stability_evidence(snapshot)
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
    # Publish compatibility artifacts first. latest.json is the final pointer for
    # this generation and must never describe a generation whose sidecars failed.
    lanes_payload = dict(policy.get("lanes") or {})
    lanes_payload["generationId"] = generation_id
    modes_payload = dict((snapshot.get("hermers") or {}).get("profileModes") or {})
    modes_payload["generationId"] = generation_id
    auth_plan = dict(snapshot.get("authMaintenance") or {})
    auth_plan["generationId"] = generation_id
    backpressure = dict(snapshot["controlPlane"])
    backpressure["generationId"] = generation_id
    artifacts = [
        (POLICY_PATH, policy),
        (LANE_POLICY_PATH, lanes_payload),
        (HERMERS_PROFILE_MODES_PATH, modes_payload),
        (AUTH_MAINTENANCE_PLAN_PATH, auth_plan),
        (CONTROL_PLANE_BACKPRESSURE_PATH, backpressure),
    ]
    legacy_meta = write_legacy_watchdog_health(snapshot, policy)
    # Fixed-path readers must compare generationId; only latest.json is the
    # atomic commit pointer across the set of compatibility aliases.
    artifacts_meta_extra = [legacy_meta]
    if snapshot["workflowEvidence"].get("written") is True:
        artifacts_meta_extra.extend([
            artifact_metadata(Path(snapshot["workflowEvidence"]["jsonPath"])),
            artifact_metadata(Path(snapshot["workflowEvidence"]["markdownPath"])),
        ])
    return publish_generation(snapshot, artifacts, LATEST_PATH, artifacts_meta_extra)


def actuate_collected_snapshot(
    conn: sqlite3.Connection, snapshot: Dict[str, Any], policy: Dict[str, Any], *, no_action: bool = False,
) -> List[Dict[str, Any]]:
    if snapshot.get("collectorFatal") is True:
        return [{"action": "none", "result": "blocked", "reason": "collector-cache-commit-failed"}]
    return actuate(conn, snapshot, policy, no_action=no_action)


class StopSignal(Exception):
    pass


class DaemonLoopEvidenceWriteFailure(RuntimeError):
    """The loop cannot persist failure evidence and must stop safely."""


def daemon_loop(no_action: bool = False) -> int:
    global _inspection_cache_enabled
    ensure_dirs()
    lock_fh = LOCK_PATH.open("a+", encoding="utf-8")
    try:
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
        _inspection_cache_enabled = True
        log_line(f"daemon started interval={INTERVAL_SECONDS}s no_action={no_action}")
        while not stopping["value"]:
            started = time.time()
            try:
                run_once(conn, no_action=no_action)
            except CollectorProcessCleanupFailure:
                log_line("loop_aborted reason=collector-process-cleanup-unverified")
                raise
            except Exception as exc:
                err = daemon_loop_error_event(exc)
                evidence_write_failed = False
                try:
                    db_record_event(conn, err)
                except Exception:
                    # Do not let a storage exception (which may contain SQL,
                    # paths, or provider data) escape into the service journal.
                    evidence_write_failed = True
                if evidence_write_failed:
                    raise DaemonLoopEvidenceWriteFailure(
                        "daemon loop error evidence persistence failed"
                    ) from None
                log_line(f"loop_error stage=daemon-loop errorClass={type(exc).__name__}")
            elapsed = time.time() - started
            sleep_for = max(1, INTERVAL_SECONDS - elapsed)
            end = time.time() + sleep_for
            while time.time() < end and not stopping["value"]:
                time.sleep(min(1, end - time.time()))
        log_line("daemon stopped")
        return 0
    finally:
        lock_fh.close()


def daemon_loop_error_event(exc: BaseException) -> Dict[str, Any]:
    """Build persistable loop-failure evidence without exception or traceback text."""
    return {
        "ts": ts(),
        "tsEpoch": epoch(),
        "source": "cat-agents-stabilityd",
        "component": "daemon",
        "severity": "critical",
        "key": "stabilityd_loop_error",
        "message": "stabilityd run loop failed; diagnostic text omitted",
        "evidence": {"errorClass": type(exc).__name__, "stage": "daemon-loop"},
    }


def read_json_or_empty(path: Path) -> Any:
    return load_json(path, {})


def print_json(payload: Any) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def with_auth_freshness(payload: Dict[str, Any], timestamp_key: str, source: str) -> Dict[str, Any]:
    result = dict(payload)
    timestamp_epoch = parse_iso_epoch(result.get(timestamp_key))
    age_seconds = max(0, epoch() - int(timestamp_epoch)) if timestamp_epoch is not None else None
    result["source"] = source
    result["ageSeconds"] = age_seconds
    result["freshEnough"] = bool(age_seconds is not None and age_seconds <= AUTH_EVIDENCE_FRESH_SECONDS)
    result["freshSeconds"] = AUTH_EVIDENCE_FRESH_SECONDS
    return result


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
    policy = generation_compatible_payload(POLICY_PATH, latest, latest.get("policy"))
    lanes = generation_compatible_payload(LANE_POLICY_PATH, latest, policy.get("lanes"))
    findings = latest.get("findings") or []
    commands = [
        "systemctl status cat-agents-stabilityd.service --no-pager",
        "systemctl status openclaw-gateway.service --no-pager",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability status",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability lanes",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability auth-readiness",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability auth-maintenance",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability findings",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability preflight",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability recovery --limit 20",
        "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability action-classes",
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
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["__component_probe_v1"]:
        return _component_probe_worker(argv[1:])
    parser = argparse.ArgumentParser(description="Cat agents stability control plane")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("daemon")
    once_p = sub.add_parser("once")
    once_p.add_argument("--no-action", action="store_true")
    sub.add_parser("status")
    sub.add_parser("snapshot")
    sub.add_parser("policy")
    sub.add_parser("lanes")
    sub.add_parser("nodes")
    sub.add_parser("surfaces")
    sub.add_parser("preflight")
    recovery_p = sub.add_parser("recovery")
    recovery_p.add_argument("--limit", type=int, default=100)
    sub.add_parser("action-classes")
    auth_p = sub.add_parser("auth-readiness")
    auth_p.add_argument("--fresh", action="store_true", help="collect a fresh auth-readiness snapshot instead of returning latest daemon evidence")
    auth_maint_p = sub.add_parser("auth-maintenance")
    auth_maint_p.add_argument("--fresh", action="store_true", help="build the maintenance plan from a fresh auth-readiness sample")
    auth_maint_p.add_argument("--force-openclaw-probe", action="store_true", help="bypass the OpenClaw auth probe cache for post-mirror verification")
    auth_maint_p.add_argument("--execute", action="store_true", help="execute explicit auth-maintenance actions; mirror execution still requires --allow-mirror")
    auth_maint_p.add_argument("--dry-run", action="store_true", help="show auth-maintenance execution decisions without recording actions")
    auth_maint_p.add_argument("--allow-mirror", action="store_true", help="allow running the mac-codex OAuth mirror script for mirrorable actions")
    auth_maint_p.add_argument("--action-id", default="", help="execute or dry-run one maintenance action id")
    auth_mirror_p = sub.add_parser("auth-mirror")
    auth_mirror_p.add_argument("--apply", action="store_true", help="apply the mac-codex OAuth mirror; default runs the mirror script in its dry-run mode")
    auth_mirror_p.add_argument("--action-ids", default="", help="stabilityd maintenance action ids included in remote evidence")
    auth_mirror_p.add_argument("--codex-auth", default="", help="canonical mac-codex auth.json path")
    auth_mirror_p.add_argument("--mirror-operation-id", default="", help="stable retry id for reusing this attempt's rollback backups")
    auth_mirror_p.add_argument("--protect-operation-ids", default="", help="unresolved mirror artifacts to retain")
    auth_mirror_p.add_argument("--no-codex-cli", dest="codex_cli", action="store_false")
    auth_mirror_p.add_argument("--no-hermers", dest="hermers", action="store_false")
    auth_mirror_p.add_argument("--no-openclaw", dest="openclaw", action="store_false")
    auth_mirror_p.add_argument("--hermers-profiles", default="")
    auth_mirror_p.add_argument("--openclaw-agents", default="")
    auth_mirror_p.add_argument("--openclaw-profile-kinds", default="")
    auth_mirror_p.add_argument("--openclaw-targets", default="")
    auth_mirror_p.set_defaults(codex_cli=True, hermers=True, openclaw=True)
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
        try:
            return daemon_loop(no_action=False)
        except DaemonLoopEvidenceWriteFailure:
            print("cat-agents-stabilityd: loop_error_evidence_write_failed", file=sys.stderr)
            return 2
    if cmd == "once":
        conn = init_db()
        try:
            return print_json(run_once(conn, no_action=args.no_action))
        except CollectorProcessCleanupFailure:
            print_json({"status": "blocked", "reason": "collector-process-cleanup-unverified"})
            return 2
    if cmd == "status":
        latest = load_json(LATEST_PATH, {}) or {}
        policy = generation_compatible_payload(POLICY_PATH, latest, latest.get("policy"))
        updated_at_epoch = policy.get("updatedAtEpoch")
        if isinstance(updated_at_epoch, (int, float)) and not isinstance(updated_at_epoch, bool) and math.isfinite(updated_at_epoch):
            policy_age = max(0, epoch() - int(updated_at_epoch))
        else:
            snapshot_epoch = parse_iso_epoch(latest.get("completedAt") or latest.get("checkedAt"))
            policy_age = max(0, epoch() - int(snapshot_epoch)) if snapshot_epoch is not None else None
        return print_json(
            {
                "checkedAt": latest.get("checkedAt"),
                "completedAt": latest.get("completedAt"),
                "severity": latest.get("severity"),
                "mode": policy.get("mode"),
                "policyAgeSeconds": policy_age,
                "findingCount": len(latest.get("findings") or []),
                "lastActions": latest.get("actions"),
            }
        )
    if cmd == "snapshot":
        return print_json(read_json_or_empty(LATEST_PATH))
    if cmd == "policy":
        latest = load_json(LATEST_PATH, {}) or {}
        return print_json(generation_compatible_payload(POLICY_PATH, latest, latest.get("policy")))
    if cmd == "lanes":
        latest = load_json(LATEST_PATH, {}) or {}
        policy = generation_compatible_payload(POLICY_PATH, latest, latest.get("policy"))
        lanes = generation_compatible_payload(LANE_POLICY_PATH, latest, policy.get("lanes"))
        return print_json(lanes)
    if cmd == "nodes":
        latest = load_json(LATEST_PATH, {}) or {}
        latest = latest if isinstance(latest, dict) else {}
        observations = latest.get("nodeObservations") if isinstance(latest.get("nodeObservations"), list) else []
        return print_json(evaluate_inventory(observations, now_epoch=epoch()))
    if cmd == "surfaces":
        latest = load_json(LATEST_PATH, {}) or {}
        latest = latest if isinstance(latest, dict) else {}
        observations = latest.get("surfaceObservations") if isinstance(latest.get("surfaceObservations"), list) else []
        return print_json(evaluate_surface_observations(observations, now_epoch=epoch()))
    if cmd == "preflight":
        latest = load_json(LATEST_PATH, {}) or {}
        latest = latest if isinstance(latest, dict) else {}
        policy = generation_compatible_payload(POLICY_PATH, latest, latest.get("policy"))
        node_observations = latest.get("nodeObservations") if isinstance(latest.get("nodeObservations"), list) else []
        surface_observations = latest.get("surfaceObservations") if isinstance(latest.get("surfaceObservations"), list) else []
        nodes = evaluate_inventory(node_observations, now_epoch=epoch())
        surfaces = evaluate_surface_observations(surface_observations, now_epoch=epoch())
        return print_json(build_preflight_summary(
            latest, policy, nodes, surfaces, now_epoch=epoch(),
        ))
    if cmd == "recovery":
        ledger = load_action_ledger_readonly(STATE_DB, limit=args.limit)
        return print_json(build_recovery_summary(
            ledger.get("records") or [], ledger_status=str(ledger.get("status") or "unavailable"),
            limit=args.limit, ledger_counts=ledger.get("counts"),
            total_candidate_count=ledger.get("candidateCount"),
        ))
    if cmd == "action-classes":
        return print_json({"schemaVersion": 1,
                           "commands": classify_commands(),
                           "actuators": classify_action_types()})
    if cmd == "auth-readiness":
        latest = load_json(LATEST_PATH, {}) or {}
        latest_auth = latest.get("auth") if isinstance(latest.get("auth"), dict) else {}
        if latest_auth and not args.fresh:
            return print_json(with_auth_freshness(latest_auth, "checkedAt", "latest"))
        conn = init_memory_kv_db()
        findings: List[Dict[str, Any]] = []
        auth = auth_collect(conn, findings, force_openclaw_probe=args.fresh)
        auth["findings"] = findings
        return print_json(with_auth_freshness(auth, "checkedAt", "fresh"))
    if cmd == "auth-maintenance":
        latest = load_json(LATEST_PATH, {}) or {}
        if (args.execute or args.force_openclaw_probe) and not args.fresh:
            args.fresh = True
        if not args.fresh:
            latest_plan = generation_compatible_payload(AUTH_MAINTENANCE_PLAN_PATH, latest, latest.get("authMaintenance"))
            if latest_plan and not args.execute and not args.dry_run:
                return print_json(with_auth_freshness(latest_plan, "generatedAt", "latest"))
            if latest_plan:
                plan = latest_plan
            else:
                conn = init_memory_kv_db()
                findings: List[Dict[str, Any]] = []
                auth = auth_collect(conn, findings)
                plan = build_auth_maintenance_plan(auth, findings)
        else:
            conn = init_memory_kv_db()
            findings = []
            auth = auth_collect(conn, findings, force_openclaw_probe=args.force_openclaw_probe)
            plan = build_auth_maintenance_plan(auth, findings)
        if args.execute or args.dry_run:
            conn = init_db()
            return print_json(
                execute_auth_maintenance_plan(
                    conn,
                    plan,
                    action_id=args.action_id,
                    dry_run=args.dry_run,
                    allow_mirror=args.allow_mirror,
                )
            )
        return print_json(with_auth_freshness(plan, "generatedAt", "fresh" if args.fresh else "latest"))
    if cmd == "auth-mirror":
        scoped = bool(
            not args.codex_cli
            or not args.hermers
            or not args.openclaw
            or args.hermers_profiles
            or args.openclaw_agents
            or args.openclaw_profile_kinds
            or args.openclaw_targets
        )
        scope = None
        if scoped:
            scope = {
                "codexCli": args.codex_cli,
                "hermersProfiles": args.hermers_profiles.split(",") if args.hermers_profiles else [],
                "openclawTargets": [
                    {"agentId": target.split(":", 1)[0], "profileKind": target.split(":", 1)[1]}
                    for target in args.openclaw_targets.split(",")
                    if ":" in target
                ],
                "openclawAgents": args.openclaw_agents.split(",") if args.openclaw_agents else [],
                "openclawProfileKinds": args.openclaw_profile_kinds.split(",") if args.openclaw_profile_kinds else [],
            }
        return print_json(
            run_mac_codex_oauth_mirror(
                apply=args.apply,
                action_ids=args.action_ids,
                target_scope=scope,
                codex_auth=args.codex_auth,
                mirror_operation_id=args.mirror_operation_id,
                protect_operation_ids=args.protect_operation_ids,
            )
        )
    if cmd == "profile-modes":
        latest = load_json(LATEST_PATH, {}) or {}
        hermers = latest.get("hermers") if isinstance(latest.get("hermers"), dict) else {}
        return print_json(generation_compatible_payload(HERMERS_PROFILE_MODES_PATH, latest, hermers.get("profileModes")))
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
        try:
            snap = run_once(conn, no_action=args.no_action)
        except CollectorProcessCleanupFailure:
            print_json({"status": "blocked", "reason": "collector-process-cleanup-unverified"})
            return 2
        return print_json({"severity": snap.get("severity"), "policy": snap.get("policy"), "findings": snap.get("findings"), "actions": snap.get("actions")})
    if cmd == "repair":
        conn = init_db()
        try:
            snap = run_once(conn, no_action=args.dry_run)
        except CollectorProcessCleanupFailure:
            print_json({"status": "blocked", "reason": "collector-process-cleanup-unverified"})
            return 2
        return print_json({"dryRun": args.dry_run, "actions": snap.get("actions"), "policy": snap.get("policy")})
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
