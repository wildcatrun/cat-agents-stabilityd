#!/usr/bin/env python3
"""Shared lightweight heartbeat probe for cat agents.

This command is intentionally deterministic: it observes runtime state and
writes a small event, but it does not call an LLM. Cron jobs can run it first
and escalate to a model only when the probe returns HEARTBEAT_WARN.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


HOME = Path(os.environ.get("CAT_HEARTBEAT_HOME", str(Path.home())))
OPENCLAW = HOME / ".openclaw"
HERMES_HOME = HOME / ".hermes" / "profiles"
DEFAULT_STATE_DIR = OPENCLAW / "stability" / "heartbeat-probe"


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError as exc:
        return 127, "", f"COMMAND_NOT_FOUND: {exc.filename}"
    except PermissionError as exc:
        return 126, "", f"COMMAND_PERMISSION_DENIED: {exc.filename}"
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return 124, stdout, stderr + "\nTIMEOUT"


def parse_cli_json(text: str) -> Any:
    """Parse JSON even if a CLI printed a migration/log preamble first."""
    stripped = (text or "").strip()
    if not stripped:
        raise ValueError("empty JSON output")
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    decoder = json.JSONDecoder()
    for idx, char in enumerate(stripped):
        if char not in "{[":
            continue
        try:
            parsed, _end = decoder.raw_decode(stripped[idx:])
            return parsed
        except json.JSONDecodeError:
            continue
    raise ValueError("no JSON object or array found in CLI output")


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def load_state(state_dir: Path, agent: str) -> dict[str, Any]:
    return read_json(state_dir / f"{agent}.json", {})


def save_state(state_dir: Path, agent: str, state: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / f"{agent}.json").write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def append_event(state_dir: Path, event: dict[str, Any]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    with (state_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def summarize_openclaw(args: argparse.Namespace) -> dict[str, Any]:
    rc, out, err = run(["openclaw", "cron", "list", "--json"], timeout=args.timeout)
    result: dict[str, Any] = {
        "runtime": "openclaw",
        "agent": args.agent,
        "job_id": args.job_id,
        "ok": False,
        "errors": [],
        "warnings": [],
        "observations": {},
    }
    if rc != 0:
        result["errors"].append({"kind": "cron_list_failed", "rc": rc, "stderr_tail": err[-500:]})
        return result
    try:
        data = parse_cli_json(out)
    except Exception as exc:
        result["errors"].append({"kind": "cron_list_parse_failed", "error": repr(exc)})
        return result
    jobs = data.get("jobs", data if isinstance(data, list) else [])
    candidates = [
        job
        for job in jobs
        if job.get("agentId") == args.agent
        and ("heartbeat" in str(job.get("name", "")).lower() or "HEARTBEAT_" in str((job.get("payload") or {}).get("message", "")))
    ]
    job = None
    if args.job_id:
        job = next((item for item in jobs if item.get("id") == args.job_id), None)
        if job is None:
            result["warnings"].append({"kind": "job_id_missing", "job_id": args.job_id})
    if job is None and candidates:
        job = candidates[0]
    if job is None:
        result["errors"].append({"kind": "heartbeat_job_not_found", "candidate_count": len(candidates)})
        result["observations"]["candidate_count"] = len(candidates)
        return result

    state = job.get("state") or {}
    schedule = job.get("schedule") or {}
    payload = job.get("payload") or {}
    result["job"] = {
        "id": job.get("id"),
        "name": job.get("name"),
        "enabled": job.get("enabled"),
        "schedule": schedule.get("expr"),
        "timezone": schedule.get("tz"),
        "payload_kind": payload.get("kind"),
        "model": payload.get("model"),
        "last_status": state.get("lastRunStatus") or state.get("lastStatus"),
        "consecutive_errors": state.get("consecutiveErrors"),
        "next_run_at_ms": state.get("nextRunAtMs"),
        "last_error": state.get("lastError") or state.get("lastDiagnosticSummary"),
    }
    if not job.get("enabled", False):
        result["errors"].append({"kind": "job_disabled"})
    if result["job"]["last_status"] not in (None, "ok"):
        result["warnings"].append({"kind": "last_status_not_ok", "last_status": result["job"]["last_status"]})
    if int(state.get("consecutiveErrors") or 0) > args.max_consecutive_errors:
        result["warnings"].append({"kind": "consecutive_errors", "count": state.get("consecutiveErrors")})
    result["observations"]["heartbeat_candidates"] = len(candidates)
    result["ok"] = not result["errors"]
    return result


def summarize_hermers(args: argparse.Namespace) -> dict[str, Any]:
    profile = args.profile or args.agent
    result: dict[str, Any] = {
        "runtime": "hermers",
        "agent": args.agent,
        "profile": profile,
        "ok": False,
        "errors": [],
        "warnings": [],
        "observations": {},
    }
    rc, out, err = run(["systemctl", "--user", "is-active", f"hermes-gateway-{profile}.service"], timeout=args.timeout)
    active = out.strip()
    result["service"] = {"unit": f"hermes-gateway-{profile}.service", "active": active, "rc": rc}
    if active != "active":
        result["errors"].append({"kind": "gateway_inactive", "active": active, "stderr_tail": err[-500:]})

    jobs_path = HERMES_HOME / profile / "cron" / "jobs.json"
    data = read_json(jobs_path, None)
    if data is None:
        result["errors"].append({"kind": "cron_jobs_missing", "path": str(jobs_path)})
        jobs: list[dict[str, Any]] = []
    else:
        jobs = data.get("jobs", data if isinstance(data, list) else [])
    heartbeat_jobs = [job for job in jobs if "heartbeat" in str(job.get("name", "")).lower()]
    result["observations"]["cron_jobs"] = len(jobs)
    result["observations"]["heartbeat_jobs"] = len(heartbeat_jobs)
    enabled_heartbeat = [job for job in heartbeat_jobs if job.get("enabled", True)]
    result["heartbeat_jobs"] = [
        {
            "id": job.get("id"),
            "name": job.get("name"),
            "enabled": job.get("enabled", True),
            "schedule": job.get("schedule") or job.get("repeat"),
            "model": (job.get("payload") or {}).get("model") or job.get("model"),
        }
        for job in enabled_heartbeat[:10]
    ]
    if not enabled_heartbeat:
        result["errors"].append({"kind": "required_heartbeat_missing"})
    result["ok"] = not result["errors"]
    return result


def build_summary(args: argparse.Namespace) -> dict[str, Any]:
    runtime = args.runtime
    if runtime == "auto":
        runtime = "hermers" if args.profile else "openclaw"
    if runtime == "openclaw":
        return summarize_openclaw(args)
    if runtime == "hermers":
        return summarize_hermers(args)
    raise ValueError(f"unsupported runtime: {runtime}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Shared deterministic heartbeat probe for cat agents")
    parser.add_argument("--agent", required=True)
    parser.add_argument("--runtime", choices=["auto", "openclaw", "hermers"], default="auto")
    parser.add_argument("--profile")
    parser.add_argument("--job-id")
    parser.add_argument("--mode", choices=["basic", "secretary", "governance"], default="basic")
    parser.add_argument("--window-minutes", type=int, default=240)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    parser.add_argument("--max-consecutive-errors", type=int, default=0)
    parser.add_argument("--required", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print full JSON event instead of HEARTBEAT_* text")
    args = parser.parse_args()

    state_dir = Path(args.state_dir)
    observed = build_summary(args)
    hash_input = {
        "runtime": observed.get("runtime"),
        "agent": args.agent,
        "mode": args.mode,
        "job": observed.get("job"),
        "service": observed.get("service"),
        "heartbeat_jobs": observed.get("heartbeat_jobs"),
        "errors": observed.get("errors"),
        "warnings": observed.get("warnings"),
    }
    digest = stable_hash(hash_input)
    previous = load_state(state_dir, args.agent)
    changed = previous.get("last_hash") != digest
    status = "HEARTBEAT_OK" if observed.get("ok") else "HEARTBEAT_WARN"
    event = {
        "time": iso_now(),
        "agent": args.agent,
        "runtime": observed.get("runtime"),
        "profile": observed.get("profile"),
        "mode": args.mode,
        "window_minutes": args.window_minutes,
        "status": status,
        "changed": changed,
        "hash": digest,
        "observed": observed,
    }
    try:
        append_event(state_dir, event)
        save_state(state_dir, args.agent, {"updated_at": event["time"], "last_hash": digest, "last_status": status})
    except OSError as exc:
        observed.setdefault("errors", []).append({"kind": "state_write_failed", "error": repr(exc), "state_dir": str(state_dir)})
        observed["ok"] = False
        status = "HEARTBEAT_WARN"
        event["status"] = status
        event["observed"] = observed
    if args.json:
        print(json.dumps(event, ensure_ascii=False, indent=2))
    else:
        suffix = "changed" if changed else "unchanged"
        warnings = len(observed.get("warnings") or [])
        errors = len(observed.get("errors") or [])
        print(f"{status} {args.agent} runtime={observed.get('runtime')} {suffix} warnings={warnings} errors={errors}")
    return 0 if observed.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
