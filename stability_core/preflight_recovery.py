"""Read-only readiness summaries and bounded action-ledger recovery views."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping

from .action_ledger import LEDGER_SCHEMA_VERSION
from .action_classes import ACTUATOR_CLASSES


_PUBLIC_REF_PREFIXES = (
    "evidence://", "stabilityd-policy://", "policy-digest:sha256:", "governance://",
    "outcome://", "runbook://",
)
_POLICY_MODES = {
    "healthy", "degraded", "gateway-unreachable", "channel-stalled", "delivery-failing",
    "cron-state-corrupt", "cron-congested", "session-stuck", "hermers-unavailable",
    "hermers-degraded", "auth-degraded", "resource-pressure", "restart-storm", "cooldown",
    "observe", "unknown",
}
_SEVERITIES = {"ok", "info", "warning", "high", "critical", "unknown"}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _timestamp_epoch(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.timestamp() if parsed.tzinfo is not None else None
    except ValueError:
        return None


def build_preflight_summary(
    latest: Mapping[str, Any], policy: Mapping[str, Any], nodes: Mapping[str, Any],
    surfaces: Mapping[str, Any], *, now_epoch: float, max_age_seconds: int = 300,
) -> dict[str, Any]:
    if isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float)) or not math.isfinite(now_epoch):
        raise ValueError("now_epoch must be finite")
    if type(max_age_seconds) is not int or max_age_seconds < 0:
        raise ValueError("max_age_seconds must be a non-negative integer")
    latest = latest if isinstance(latest, Mapping) else {}
    policy = policy if isinstance(policy, Mapping) else {}
    nodes = nodes if isinstance(nodes, Mapping) else {}
    surfaces = surfaces if isinstance(surfaces, Mapping) else {}
    latest_generation = latest.get("generationId") if isinstance(latest, Mapping) else None
    policy_generation = policy.get("generationId") if isinstance(policy, Mapping) else None
    if not policy_generation and isinstance(latest.get("policy"), Mapping):
        policy_generation = latest["policy"].get("generationId")
    completed = latest.get("completedAt") or latest.get("checkedAt")
    completed_epoch = _timestamp_epoch(completed)
    age = int(now_epoch - completed_epoch) if completed_epoch is not None else None
    generation_state = (
        "missing" if not isinstance(latest_generation, str) or not latest_generation.strip()
        else "mismatch" if policy_generation and policy_generation != latest_generation
        else "matched" if policy_generation == latest_generation
        else "unverified"
    )
    freshness = "unknown" if age is None else "future" if age < 0 else "fresh" if age <= max_age_seconds else "stale"
    blockers = []
    if generation_state in {"missing", "mismatch", "unverified"}:
        blockers.append(f"generation-{generation_state}")
    if freshness != "fresh":
        blockers.append(f"evidence-{freshness}")
    if not policy:
        blockers.append("policy-missing")
    raw_severity = latest.get("severity")
    severity = raw_severity if isinstance(raw_severity, str) and raw_severity in _SEVERITIES else "unknown"
    raw_mode = policy.get("mode")
    mode = raw_mode if isinstance(raw_mode, str) and raw_mode in _POLICY_MODES else "unknown"
    if severity in {"critical", "high"}:
        blockers.append(f"severity-{severity}")
    elif severity == "unknown":
        blockers.append("severity-unknown")
    if policy and mode == "unknown":
        blockers.append("policy-mode-unknown")
    return {
        "schemaVersion": 1,
        "preflightState": "blocked" if blockers else "reviewable",
        "generation": {"state": generation_state,
                       "generationRef": _digest(latest_generation) if isinstance(latest_generation, str) else None},
        "evidence": {"freshness": freshness, "ageSeconds": age, "maxAgeSeconds": max_age_seconds,
                     "completedAt": completed if isinstance(completed, str) and completed_epoch is not None else None},
        "policy": {"mode": mode, "severity": severity,
                   "authorizationEvaluated": False},
        "coverage": {
            "nodes": nodes.get("coverage") if isinstance(nodes.get("coverage"), Mapping) else {},
            "surfaces": surfaces.get("coverage") if isinstance(surfaces.get("coverage"), Mapping) else {},
        },
        "blockers": blockers,
        "dryRun": {"available": True, "executed": False,
                   "meaning": "observation-only; no action authorization or actuator call"},
        "liveMutation": "not-requested-and-not-performed",
    }


def _safe_ref(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if (value.startswith(_PUBLIC_REF_PREFIXES) and "\n" not in value and "\r" not in value
            and re.fullmatch(r"[A-Za-z0-9:/._#-]{1,240}", value)):
        return value[:240]
    return "opaque://sha256/" + _digest(value)


def _record_value(record: Any, name: str, default: Any = None) -> Any:
    if isinstance(record, Mapping):
        return record.get(name, default)
    return getattr(record, name, default)


def build_recovery_summary(
    records: list[Any], *, ledger_status: str, limit: int = 100,
    ledger_counts: Mapping[str, int] | None = None, total_candidate_count: int | None = None,
) -> dict[str, Any]:
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer from 1 to 1000")
    if ledger_status not in {"available", "missing", "not-initialized", "invalid", "unavailable"}:
        ledger_status = "unavailable"
    states = {"planned": 0, "executing": 0, "uncertain": 0, "succeeded": 0, "failed": 0, "blocked": 0}
    candidates = []
    for record in records if isinstance(records, list) else []:
        state = _record_value(record, "state")
        if state not in states:
            continue
        states[state] += 1
        if state not in {"planned", "executing", "uncertain"}:
            continue
        evidence_refs = _record_value(record, "evidence_refs", ())
        raw_action_id = _record_value(record, "action_id")
        action_id = (raw_action_id if isinstance(raw_action_id, str)
                     and re.fullmatch(r"act_[0-9a-f]{32}", raw_action_id)
                     else "action://sha256/" + _digest(str(raw_action_id)))
        raw_action_type = _record_value(record, "action_type")
        action_type = raw_action_type if isinstance(raw_action_type, str) and raw_action_type in ACTUATOR_CLASSES else "unknown/prohibited"
        raw_input_digest = _record_value(record, "input_digest")
        input_digest = raw_input_digest if isinstance(raw_input_digest, str) and re.fullmatch(r"[0-9a-f]{64}", raw_input_digest) else None
        candidates.append({
            "actionId": action_id,
            "actionType": action_type,
            "actionTypeDigest": None if action_type != "unknown/prohibited" else _digest(str(raw_action_type)),
            "state": state,
            "targetDigest": _digest(str(_record_value(record, "target", ""))),
            "generationDigest": _digest(str(_record_value(record, "generation", ""))),
            "inputDigest": input_digest,
            "authorizationRef": _safe_ref(_record_value(record, "authorization_ref")),
            "policyRef": _safe_ref(_record_value(record, "policy_ref")),
            "evidenceRefs": [ref for ref in (_safe_ref(item) for item in evidence_refs) if ref],
            "outcomeRef": _safe_ref(_record_value(record, "outcome_ref")),
            "postcheckRef": _safe_ref(_record_value(record, "postcheck_ref")),
            "precheckRef": _safe_ref(_record_value(record, "precheck_ref")),
            "createdAtMs": _record_value(record, "created_at_ms"),
            "updatedAtMs": _record_value(record, "updated_at_ms"),
            "nextStep": {
                "planned": "inspect-bound-authorization-and-evidence; this view does not execute",
                "executing": "inspect-startup-and-effect-state; do-not-replay",
                "uncertain": "manual-evidence-reconciliation-required; do-not-replay-or-clear-ledger",
            }[state],
        })
    candidates.sort(key=lambda row: (row["createdAtMs"] or 0, row["actionId"] or ""))
    if isinstance(ledger_counts, Mapping):
        for key in states:
            value = ledger_counts.get(key)
            if type(value) is int and value >= 0:
                states[key] = value
    total = total_candidate_count if type(total_candidate_count) is int and total_candidate_count >= 0 else len(candidates)
    return {
        "schemaVersion": 1,
        "ledgerStatus": ledger_status,
        "recoveryState": "unknown" if ledger_status != "available" else
            "manual-reconciliation-required" if states["uncertain"] else
            "startup-inspection-required" if states["executing"] or states["planned"] else "clear",
        "counts": states,
        "candidateCount": total,
        "candidates": candidates[:limit],
        "truncated": total > len(candidates),
        "automaticReplay": False,
        "ledgerMutation": False,
    }


def load_action_ledger_readonly(path: Path, *, limit: int = 100) -> dict[str, Any]:
    """Read only a versioned action ledger; never creates/migrates a missing DB."""
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer from 1 to 1000")
    if path.is_symlink():
        return {"status": "invalid", "records": []}
    if not path.exists():
        return {"status": "missing", "records": []}
    if not path.is_file():
        return {"status": "invalid", "records": []}
    conn = None
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=1.0)
        conn.execute("PRAGMA query_only=ON")
        return load_action_ledger_connection_readonly(conn, limit=limit, budget_ms=250)
    except (sqlite3.Error, ValueError, TypeError, OSError):
        return {"status": "unavailable", "records": []}
    finally:
        if conn is not None:
            conn.close()


def _read_action_ledger_state(conn: sqlite3.Connection, *, limit: int) -> dict[str, Any]:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"action_ledger", "stability_schema_versions"}.intersection(tables):
        return {"status": "not-initialized", "records": []}
    if not {"action_ledger", "stability_schema_versions"}.issubset(tables):
        return {"status": "invalid", "records": []}
    version = conn.execute(
        "SELECT version FROM stability_schema_versions WHERE component='action_ledger'"
    ).fetchone()
    if not version or version[0] != LEDGER_SCHEMA_VERSION:
        return {"status": "invalid", "records": []}
    names = [item[1] for item in conn.execute("PRAGMA table_info(action_ledger)")]
    expected = {"action_id", "action_type", "target", "generation", "state", "input_digest",
                "authorization_ref", "policy_ref", "evidence_refs_json", "created_at_ms", "updated_at_ms",
                "outcome_ref", "postcheck_ref", "precheck_ref", "idempotency_key", "metadata_json", "version"}
    if set(names) != expected:
        return {"status": "invalid", "records": []}
    counts = {row[0]: row[1] for row in conn.execute(
        "SELECT state,COUNT(*) FROM action_ledger GROUP BY state"
    )}
    candidates_count = sum(counts.get(state, 0) for state in ("planned", "executing", "uncertain"))
    rows = conn.execute(
        """SELECT action_id,action_type,target,generation,state,input_digest,authorization_ref,
                  policy_ref,evidence_refs_json,created_at_ms,updated_at_ms,outcome_ref,postcheck_ref,precheck_ref
           FROM action_ledger WHERE state IN ('planned','executing','uncertain')
           ORDER BY created_at_ms,action_id LIMIT ?""", (limit,)
    ).fetchall()
    records = []
    for row in rows:
        if (not all(isinstance(row[index], str) for index in (0, 1, 2, 3, 4, 5, 8))
                or any(row[index] is not None and not isinstance(row[index], str) for index in (6, 7))):
            return {"status": "invalid", "records": []}
        if (not re.fullmatch(r"[0-9a-f]{64}", row[5]) or len(row[8]) > 64_000
                or row[4] not in {"planned", "executing", "uncertain"}):
            return {"status": "invalid", "records": []}
        refs = json.loads(row[8])
        if (not isinstance(refs, list) or len(refs) > 64
                or any(not isinstance(ref, str) or len(ref) > 1000 for ref in refs)):
            return {"status": "invalid", "records": []}
        if (type(row[9]) is not int or type(row[10]) is not int
                or any(value is not None and not isinstance(value, str) for value in row[11:14])):
            return {"status": "invalid", "records": []}
        records.append({
            "action_id": row[0], "action_type": row[1], "target": row[2], "generation": row[3],
            "state": row[4], "input_digest": row[5], "authorization_ref": row[6], "policy_ref": row[7],
            "evidence_refs": refs, "created_at_ms": row[9], "updated_at_ms": row[10],
            "outcome_ref": row[11], "postcheck_ref": row[12], "precheck_ref": row[13],
        })
    return {"status": "available", "records": records, "counts": counts,
            "candidateCount": candidates_count}


def load_action_ledger_connection_readonly(conn: sqlite3.Connection, *, limit: int = 100,
                                          budget_ms: int | None = None) -> dict[str, Any]:
    """Read the actual borrowed connection in an owned read transaction.

    Existing caller transactions are rejected, never committed or rolled back.
    The reader cannot silently switch to another inode at the same filename.
    A requested budget reserves the connection's progress handler for this read;
    callers using their own handler should omit it. The budget bounds SQLite VM
    work, not an operating-system filesystem stall.
    """
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("limit must be an integer from 1 to 1000")
    if budget_ms is not None and (type(budget_ms) is not int or not 1 <= budget_ms <= 1000):
        raise ValueError("invalid read budget")
    begun = False
    handler_installed = False
    result = {"status": "unavailable", "records": []}
    try:
        if conn.in_transaction:
            return result
        conn.execute("BEGIN")
        begun = True
        if budget_ms is not None:
            deadline = time.monotonic() + budget_ms / 1000
            conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            handler_installed = True
        result = _read_action_ledger_state(conn, limit=limit)
    except (sqlite3.Error, ValueError, TypeError, OSError):
        result = {"status": "unavailable", "records": []}
    finally:
        if handler_installed:
            try:
                conn.set_progress_handler(None, 0)
            except sqlite3.Error:
                result = {"status": "unavailable", "records": []}
        if begun:
            try:
                conn.rollback()
            except sqlite3.Error:
                result = {"status": "unavailable", "records": []}
    return result
