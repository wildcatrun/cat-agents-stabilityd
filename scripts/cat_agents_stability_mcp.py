#!/usr/bin/env python3
"""Minimal stdio MCP server for local Codex cat-agents-stability control-plane reads."""

from __future__ import annotations

import datetime as dt
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any


SERVER_NAME = "cat-agents-stability"
SERVER_VERSION = "0.1.0"

DEFAULT_LOCAL_REPO = str(Path(__file__).resolve().parents[1])
DEFAULT_REMOTE_PATH = "/home/flashcat/cat-agents-stabilityd"
DEFAULT_REMOTE_HOST = "106.54.53.146"
DEFAULT_REMOTE_USER = "flashcat"
DEFAULT_REMOTE_KEY = "/Users/Flashcat/.ssh/openclaw_server"
DEFAULT_AUDIT_LOG = "/Users/Flashcat/.cat-agents-stability-mcp/audit.jsonl"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def audit(event: dict[str, Any]) -> None:
    try:
        path = Path(os.environ.get("CAT_AGENTS_STABILITY_MCP_AUDIT_LOG", DEFAULT_AUDIT_LOG)).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        event.setdefault("ts", now_iso())
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    except OSError:
        return


def local_repo() -> Path:
    return Path(os.environ.get("CAT_AGENTS_STABILITY_LOCAL_REPO", DEFAULT_LOCAL_REPO)).expanduser()


def remote_path() -> str:
    return os.environ.get("CAT_AGENTS_STABILITY_REMOTE_PATH", DEFAULT_REMOTE_PATH)


def local_bin() -> Path:
    return local_repo() / "bin" / "cat-agents-stability"


def run(cmd: list[str], cwd: Path | None = None, timeout: int = 30) -> dict[str, Any]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "").strip(),
        "stderr": (proc.stderr or "").strip(),
    }


def run_remote(script: str, timeout: int = 30) -> dict[str, Any]:
    host = os.environ.get("CAT_AGENTS_STABILITY_REMOTE_HOST", DEFAULT_REMOTE_HOST)
    user = os.environ.get("CAT_AGENTS_STABILITY_REMOTE_USER", DEFAULT_REMOTE_USER)
    key = os.environ.get("CAT_AGENTS_STABILITY_REMOTE_KEY", DEFAULT_REMOTE_KEY)
    cmd = [
        "ssh",
        "-tt",
        "-i",
        key,
        "-o",
        "BatchMode=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        f"{user}@{host}",
        script,
    ]
    return run(cmd, timeout=max(timeout, 30))


def parse_json_output(result: dict[str, Any], fallback: Any) -> Any:
    if not result.get("ok"):
        return fallback
    try:
        return json.loads(result.get("stdout") or "")
    except json.JSONDecodeError:
        return fallback


def stability_cli_args(action: str, args: dict[str, Any]) -> list[str]:
    allowed = {"status", "snapshot", "policy", "lanes", "desired-state", "drift", "findings", "actions", "events", "runbook", "doctor", "repair", "once"}
    if action not in allowed:
        raise ValueError(f"unsupported stability action: {action}")
    cmd = [action]
    if action == "actions" and args.get("limit") is not None:
        cmd.extend(["--limit", str(args.get("limit"))])
    if action in {"doctor", "once"}:
        if bool(args.get("no_action", args.get("noAction", True))):
            cmd.append("--no-action")
    if action == "repair":
        if bool(args.get("dry_run", args.get("dryRun", True))):
            cmd.append("--dry-run")
    return cmd


def stability_call(args: dict[str, Any]) -> dict[str, Any]:
    source = str(args.get("source") or "remote").strip()
    action = str(args.get("action") or "status").strip()
    timeout = max(5, min(int(args.get("timeout") or 30), 240))
    cli_args = stability_cli_args(action, args)
    if source == "local":
        cmd = [str(local_bin()), *cli_args]
        result = run(cmd, cwd=local_repo(), timeout=timeout)
    elif source == "remote":
        script = " ".join([shlex.quote(f"{remote_path().rstrip('/')}/bin/cat-agents-stability"), *[shlex.quote(part) for part in cli_args]])
        result = run_remote(script, timeout=timeout)
    else:
        raise ValueError("source must be local or remote")
    payload = {
        "source": source,
        "action": action,
        "result": result,
        "json": parse_json_output(result, None),
    }
    audit({"event": "stability_call", "source": source, "action": action, "ok": result.get("ok")})
    return payload


def status(args: dict[str, Any]) -> dict[str, Any]:
    return stability_call({**args, "action": "status"})


def findings(args: dict[str, Any]) -> dict[str, Any]:
    return stability_call({**args, "action": "findings"})


def lanes(args: dict[str, Any]) -> dict[str, Any]:
    return stability_call({**args, "action": "lanes"})


def actions(args: dict[str, Any]) -> dict[str, Any]:
    return stability_call({**args, "action": "actions"})


def runbook(args: dict[str, Any]) -> dict[str, Any]:
    return stability_call({**args, "action": "runbook"})


def desired_state(args: dict[str, Any]) -> dict[str, Any]:
    return stability_call({**args, "action": "desired-state"})


def drift_check(args: dict[str, Any]) -> dict[str, Any]:
    return stability_call({**args, "action": "drift"})


def doctor(args: dict[str, Any]) -> dict[str, Any]:
    return stability_call({**args, "action": "doctor", "no_action": True})


def server_snapshot(args: dict[str, Any]) -> dict[str, Any]:
    max_files = max(1, min(int(args.get("max_files") or 120), 500))
    path = remote_path()
    script = (
        "set -e; "
        f"cd {shlex.quote(path)}; "
        "printf 'PWD=%s\\n' \"$PWD\"; "
        "printf 'SIZE='; du -sh . | awk '{print $1}'; "
        f"find . -maxdepth 4 -type f -not -path './.git/*' | sort | head -{max_files}"
    )
    result = run_remote(script, timeout=30)
    payload = {"remote_path": path, "max_files": max_files, "remote": result}
    audit({"event": "server_snapshot", "ok": result.get("ok"), "remote_path": path})
    return payload


def package_status(args: dict[str, Any]) -> dict[str, Any]:
    repo = local_repo()
    files = sorted(str(path.relative_to(repo)) for path in repo.rglob("*") if path.is_file() and ".git" not in path.parts)
    git = run(["git", "status", "--short", "--branch"], cwd=repo) if (repo / ".git").exists() else {"ok": False, "stdout": "", "stderr": "not a git repository"}
    payload = {
        "local_repo": str(repo),
        "exists": repo.exists(),
        "git": git,
        "file_count": len(files),
        "sample_files": files[: int(args.get("limit") or 80)],
    }
    audit({"event": "package_status", "file_count": len(files)})
    return payload


TOOLS: dict[str, dict[str, Any]] = {
    "stability_status": {
        "description": "Return cat-agents-stability status from local or remote stabilityd.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["local", "remote"]}}, "additionalProperties": False},
    },
    "stability_findings": {
        "description": "Return current cat-agents-stability findings.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["local", "remote"]}}, "additionalProperties": False},
    },
    "stability_lanes": {
        "description": "Return current cat-agents-stability lane policy.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["local", "remote"]}}, "additionalProperties": False},
    },
    "stability_actions": {
        "description": "Return recent cat-agents-stability actions.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["local", "remote"]}, "limit": {"type": "number"}}, "additionalProperties": False},
    },
    "stability_runbook": {
        "description": "Return generated cat-agents-stability runbook guidance.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["local", "remote"]}}, "additionalProperties": False},
    },
    "stability_desired_state": {
        "description": "Return the current cat-agents-stability desired-state registry.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["local", "remote"]}}, "additionalProperties": False},
    },
    "stability_drift_check": {
        "description": "Run a read-only drift check against the cat-agents-stability desired-state registry.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["local", "remote"]}}, "additionalProperties": False},
    },
    "stability_doctor_dry_run": {
        "description": "Run cat-agents-stability doctor in no-action mode.",
        "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["local", "remote"]}, "timeout": {"type": "number"}}, "additionalProperties": False},
    },
    "stability_server_snapshot": {
        "description": "Read-only snapshot of the development-server cat-agents-stability package directory.",
        "inputSchema": {"type": "object", "properties": {"max_files": {"type": "number"}}, "additionalProperties": False},
    },
    "stability_package_status": {
        "description": "Return local cat-agents-stability package file and Git status.",
        "inputSchema": {"type": "object", "properties": {"limit": {"type": "number"}}, "additionalProperties": False},
    },
}


def tool_result(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
        "structuredContent": payload,
    }


def error_response(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_request(req: dict[str, Any]) -> dict[str, Any] | None:
    req_id = req.get("id")
    method = req.get("method")
    params = req.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": params.get("protocolVersion") or "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": [{"name": n, **s} for n, s in TOOLS.items()]}}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        try:
            if name == "stability_status":
                payload = status(arguments)
            elif name == "stability_findings":
                payload = findings(arguments)
            elif name == "stability_lanes":
                payload = lanes(arguments)
            elif name == "stability_actions":
                payload = actions(arguments)
            elif name == "stability_runbook":
                payload = runbook(arguments)
            elif name == "stability_desired_state":
                payload = desired_state(arguments)
            elif name == "stability_drift_check":
                payload = drift_check(arguments)
            elif name == "stability_doctor_dry_run":
                payload = doctor(arguments)
            elif name == "stability_server_snapshot":
                payload = server_snapshot(arguments)
            elif name == "stability_package_status":
                payload = package_status(arguments)
            else:
                raise ValueError(f"unknown tool: {name}")
            return {"jsonrpc": "2.0", "id": req_id, "result": tool_result(payload)}
        except Exception as exc:
            audit({"event": "tool_error", "tool": name, "error": str(exc)})
            return error_response(req_id, -32000, str(exc))
    if method and method.startswith("notifications/"):
        return None
    return error_response(req_id, -32601, f"method not found: {method}")


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            response = handle_request(json.loads(line))
        except Exception as exc:
            response = error_response(None, -32700, str(exc))
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
