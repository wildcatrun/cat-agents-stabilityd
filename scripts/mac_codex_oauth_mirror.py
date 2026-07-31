#!/usr/bin/env python3
"""Mirror mac-codex OAuth access tokens to governed runtime stores.

The Mac Codex auth file remains the only refresh-token owner. Remote runtime
stores receive the current access token, the current id token when present, and
a non-secret dummy refresh marker so they can use valid access tokens but cannot
rotate refresh tokens.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import pathlib
import shlex
import socket
import subprocess
import sys
import time
from typing import Any


DUMMY_REFRESH = "MAC_CODEX_BROKER_REFRESH_DISABLED"
DEFAULT_SERVER = "flashcat@106.54.53.146"
DEFAULT_SSH_KEY = "/Users/Flashcat/.ssh/openclaw_server"
DEFAULT_HERMERS_PROFILES = "catbody,catears,cateyes,catheart,catnose,catpenclaw"
DEFAULT_OPENCLAW_AGENTS = "main"
DEFAULT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
DEFAULT_ARTIFACT_ROOT = "/home/flashcat/multi-agent-hedge-fund-framework/ops-artifacts/codex-working"


REMOTE_RECEIVER = r"""
import base64
import datetime as dt
import json
import os
import pathlib
import shutil
import sqlite3
import stat
import sys
import tempfile
import time

DUMMY_REFRESH = "MAC_CODEX_BROKER_REFRESH_DISABLED"
DEFAULT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"

def utc_now():
    return dt.datetime.now(dt.timezone.utc)

def iso_now():
    return utc_now().isoformat().replace("+00:00", "Z")

def exp_iso(exp):
    if not exp:
        return None
    return dt.datetime.fromtimestamp(int(exp), dt.timezone.utc).isoformat().replace("+00:00", "Z")

def ensure_dir(path):
    pathlib.Path(path).mkdir(parents=True, exist_ok=True)

def read_json(path, default):
    p = pathlib.Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except Exception:
        return default

def write_json_atomic(path, payload, mode=0o600):
    p = pathlib.Path(path)
    ensure_dir(p.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, p)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass

def backup_file(path, backup_dir, label):
    p = pathlib.Path(path)
    if not p.exists():
        return None
    ensure_dir(backup_dir)
    dest = pathlib.Path(backup_dir) / label
    shutil.copy2(p, dest)
    try:
        os.chmod(dest, stat.S_IMODE(p.stat().st_mode) or 0o600)
    except Exception:
        os.chmod(dest, 0o600)
    return str(dest)

def backup_sqlite(path, backup_dir, label):
    backups = []
    for suffix in ("", "-wal", "-shm"):
        src = pathlib.Path(path + suffix)
        if src.exists():
            dest_name = label + suffix.replace("-", ".")
            backups.append(backup_file(src, backup_dir, dest_name))
    return [item for item in backups if item]

def mirror_tokens(payload):
    tokens = payload["tokens"]
    return {
        "access_token": tokens["access_token"],
        "id_token": tokens.get("id_token") or "",
        "refresh_token": DUMMY_REFRESH,
    }

def apply_codex_cli(payload, artifact, dry_run):
    path = pathlib.Path(payload.get("remoteCodexAuthPath") or "/home/flashcat/.codex/auth.json")
    backup = None if dry_run else backup_file(path, artifact / "backups", "codex-cli.auth.json")
    existing = read_json(path, {})
    mirrored = {
        "auth_mode": "chatgpt",
        "last_refresh": payload["lastRefresh"],
        "tokens": mirror_tokens(payload),
        "mac_codex_mirror": {
            "source": payload["source"],
            "generatedAt": payload["generatedAt"],
            "refreshOwner": "mac-codex",
            "refreshTokenStored": False,
        },
    }
    if "OPENAI_API_KEY" in existing:
        mirrored["OPENAI_API_KEY"] = existing.get("OPENAI_API_KEY")
    if not dry_run:
        write_json_atomic(path, mirrored, 0o600)
    return {
        "target": "codex-cli",
        "path": str(path),
        "backup": backup,
        "wouldWrite": bool(dry_run),
        "written": not dry_run,
        "expiresAt": payload["accessExpiresAt"],
        "dummyRefresh": True,
    }

def hermers_entry(payload):
    return {
        "provider": "openai-codex",
        "id": "mac-codex-mirror",
        "label": "mac-codex-mirror",
        "auth_type": "oauth",
        "priority": 0,
        "source": "device_code",
        "access_token": payload["tokens"]["access_token"],
        "refresh_token": DUMMY_REFRESH,
        "expires_at": payload["accessExpiresAt"],
        "expires_at_ms": payload["accessExpiresMs"],
        "last_refresh": payload["lastRefresh"],
        "base_url": DEFAULT_CODEX_BASE_URL,
        "last_status": None,
        "last_status_at": None,
        "last_error_code": None,
        "last_error_reason": None,
        "last_error_message": None,
        "last_error_reset_at": None,
    }

def apply_hermers(payload, artifact, dry_run):
    results = []
    for profile in payload.get("hermersProfiles", []):
        path = pathlib.Path(f"/home/flashcat/.hermes/profiles/{profile}/auth.json")
        backup = None if dry_run else backup_file(path, artifact / "backups", f"hermers-{profile}.auth.json")
        auth = read_json(path, {"version": 1})
        if not isinstance(auth, dict):
            auth = {"version": 1}
        auth.setdefault("version", 1)
        auth["active_provider"] = "openai-codex"
        auth["updated_at"] = payload["generatedAt"]
        providers = auth.setdefault("providers", {})
        if not isinstance(providers, dict):
            providers = {}
            auth["providers"] = providers
        state = providers.get("openai-codex")
        if not isinstance(state, dict):
            state = {}
        state["tokens"] = mirror_tokens(payload)
        state["last_refresh"] = payload["lastRefresh"]
        state["auth_mode"] = "chatgpt"
        state["base_url"] = DEFAULT_CODEX_BASE_URL
        state["mac_codex_mirror"] = {
            "source": payload["source"],
            "generatedAt": payload["generatedAt"],
            "refreshOwner": "mac-codex",
            "refreshTokenStored": False,
        }
        providers["openai-codex"] = state
        pool = auth.setdefault("credential_pool", {})
        if not isinstance(pool, dict):
            pool = {}
            auth["credential_pool"] = pool
        pool["openai-codex"] = [hermers_entry(payload)]
        if not dry_run:
            write_json_atomic(path, auth, 0o600)
        results.append({
            "target": f"hermers:{profile}",
            "path": str(path),
            "backup": backup,
            "wouldWrite": bool(dry_run),
            "written": not dry_run,
            "expiresAt": payload["accessExpiresAt"],
            "dummyRefresh": True,
            "poolEntries": 1,
        })
    return results

def apply_openclaw(payload, artifact, dry_run):
    results = []
    profile_kinds = payload.get("openclawProfileKinds") or ["openai", "openai-codex"]
    for agent_id in payload.get("openclawAgents", []):
        db_path = f"/home/flashcat/.openclaw/agents/{agent_id}/agent/openclaw-agent.sqlite"
        if not pathlib.Path(db_path).exists():
            results.append({"target": f"openclaw:{agent_id}", "missing": True, "path": db_path})
            continue
        backups = [] if dry_run else backup_sqlite(db_path, artifact / "backups", f"openclaw-{agent_id}.sqlite")
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(
                "select store_json from auth_profile_store where store_key='primary'"
            ).fetchone()
            state_row = conn.execute(
                "select state_json from auth_profile_state where state_key='primary'"
            ).fetchone()
            store = json.loads(row[0]) if row else {"version": 1, "profiles": {}}
            state = json.loads(state_row[0]) if state_row else {"version": 1}
            profiles = store.setdefault("profiles", {})
            order = state.setdefault("order", {})
            last_good = state.setdefault("lastGood", {})
            usage = state.setdefault("usageStats", {})
            updated_keys = []
            for kind in profile_kinds:
                existing_key = None
                for key, value in profiles.items():
                    if isinstance(value, dict) and value.get("provider") == kind:
                        existing_key = key
                        break
                key = existing_key or f"{kind}:mac-codex"
                profile = profiles.get(key) if isinstance(profiles.get(key), dict) else {}
                profile["type"] = "oauth"
                profile["provider"] = kind
                profile["access"] = payload["tokens"]["access_token"]
                profile["refresh"] = DUMMY_REFRESH
                profile["expires"] = payload["accessExpiresMs"]
                profile.setdefault("email", "mac-codex")
                profile.setdefault("accountId", "mac-codex")
                profile.setdefault("chatgptPlanType", "pro")
                profile["macCodexMirror"] = {
                    "source": payload["source"],
                    "generatedAt": payload["generatedAt"],
                    "refreshOwner": "mac-codex",
                    "refreshTokenStored": False,
                }
                profiles[key] = profile
                order[kind] = [key]
                last_good[kind] = key
                stats = usage.get(key) if isinstance(usage.get(key), dict) else {}
                for stale_key in ("cooldownUntil", "cooldownReason", "cooldownModel", "lastFailureAt", "failureCounts"):
                    stats.pop(stale_key, None)
                stats["errorCount"] = 0
                usage[key] = stats
                updated_keys.append(key)
            now_ms = int(time.time() * 1000)
            if not dry_run:
                conn.execute(
                    "insert into auth_profile_store(store_key, store_json, updated_at) values('primary', ?, ?) "
                    "on conflict(store_key) do update set store_json=excluded.store_json, updated_at=excluded.updated_at",
                    (json.dumps(store, ensure_ascii=False), now_ms),
                )
                conn.execute(
                    "insert into auth_profile_state(state_key, state_json, updated_at) values('primary', ?, ?) "
                    "on conflict(state_key) do update set state_json=excluded.state_json, updated_at=excluded.updated_at",
                    (json.dumps(state, ensure_ascii=False), now_ms),
                )
                conn.commit()
            results.append({
                "target": f"openclaw:{agent_id}",
                "path": db_path,
                "backups": backups,
                "updatedProfiles": updated_keys,
                "wouldWrite": bool(dry_run),
                "written": not dry_run,
                "expiresAt": payload["accessExpiresAt"],
                "dummyRefresh": True,
            })
        finally:
            conn.close()
    return results

def main():
    payload = json.load(sys.stdin)
    dry_run = bool(payload.get("dryRun", True))
    artifact_root = pathlib.Path(payload.get("artifactRoot") or "/home/flashcat/multi-agent-hedge-fund-framework/ops-artifacts/codex-working")
    stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S%z") or str(int(time.time()))
    artifact = artifact_root / f"{stamp}-mac-codex-oauth-mirror"
    ensure_dir(artifact / "logs")
    ensure_dir(artifact / "backups")
    results = []
    targets = set(payload.get("targets") or [])
    if "codex-cli" in targets:
        results.append(apply_codex_cli(payload, artifact, dry_run))
    if "hermers" in targets:
        results.extend(apply_hermers(payload, artifact, dry_run))
    if "openclaw" in targets:
        results.extend(apply_openclaw(payload, artifact, dry_run))
    summary = {
        "schemaVersion": 1,
        "status": "dry-run" if dry_run else "applied",
        "artifact": str(artifact),
        "generatedAt": iso_now(),
        "source": payload.get("source"),
        "targets": sorted(targets),
        "tokenValuesRedacted": True,
        "refreshOwner": "mac-codex",
        "remoteRefreshTokenStored": False,
        "accessExpiresAt": payload["accessExpiresAt"],
        "results": results,
    }
    (artifact / "index.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
"""


def decode_jwt(token: str, label: str = "JWT") -> dict[str, Any]:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception as exc:
        raise SystemExit(f"failed to decode {label}: {type(exc).__name__}") from exc


def iso_from_epoch(epoch: int | float | None) -> str | None:
    if not epoch:
        return None
    return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).isoformat().replace("+00:00", "Z")


def require_fresh_jwt(token: str, label: str, min_ttl_seconds: int) -> tuple[int, int]:
    claims = decode_jwt(token, label)
    exp = int(claims.get("exp") or 0)
    remaining = exp - int(time.time())
    if remaining < min_ttl_seconds:
        raise SystemExit(
            f"Codex {label} has only {remaining}s remaining; refresh mac-codex login before mirroring"
        )
    return exp, remaining


def inspect_jwt_expiry(token: str, label: str) -> tuple[int, int]:
    claims = decode_jwt(token, label)
    exp = int(claims.get("exp") or 0)
    return exp, exp - int(time.time())


def load_codex_auth(path: pathlib.Path, min_ttl_seconds: int) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"Codex auth file not found: {path}")
    data = json.loads(path.read_text())
    tokens = data.get("tokens")
    if not isinstance(tokens, dict):
        raise SystemExit("Codex auth file is missing tokens object")
    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")
    refresh_token = tokens.get("refresh_token")
    if not isinstance(access_token, str) or not access_token.strip():
        raise SystemExit("Codex auth file is missing access_token")
    if not isinstance(id_token, str) or not id_token.strip():
        raise SystemExit("Codex auth file is missing id_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise SystemExit("Codex auth file is missing local refresh_token; mac-codex cannot be source")
    if refresh_token == DUMMY_REFRESH:
        raise SystemExit("Codex auth file contains the mirror refresh placeholder; this host is not the mac-codex refresh owner")
    access_exp, access_remaining = require_fresh_jwt(access_token, "access_token", min_ttl_seconds)
    id_exp, id_remaining = inspect_jwt_expiry(id_token, "id_token")
    return {
        "auth": data,
        "tokens": {
            "access_token": access_token,
            "id_token": id_token,
        },
        "accessExpiresEpoch": access_exp,
        "accessExpiresAt": iso_from_epoch(access_exp),
        "accessExpiresMs": access_exp * 1000,
        "accessSecondsRemaining": access_remaining,
        "idExpiresEpoch": id_exp,
        "idExpiresAt": iso_from_epoch(id_exp),
        "idSecondsRemaining": id_remaining,
        "idTokenFresh": id_remaining >= min_ttl_seconds,
        "lastRefresh": data.get("last_refresh") or dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    auth_path = pathlib.Path(args.codex_auth).expanduser()
    source = load_codex_auth(auth_path, args.min_ttl_seconds)
    targets = []
    if args.codex_cli:
        targets.append("codex-cli")
    if args.hermers:
        targets.append("hermers")
    if args.openclaw:
        targets.append("openclaw")
    return {
        "schemaVersion": 1,
        "source": {
            "host": socket.gethostname(),
            "authPath": str(auth_path),
            "role": "mac-codex",
        },
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "dryRun": not args.apply,
        "targets": targets,
        "tokens": source["tokens"],
        "lastRefresh": source["lastRefresh"],
        "accessExpiresAt": source["accessExpiresAt"],
        "accessExpiresMs": source["accessExpiresMs"],
        "accessSecondsRemaining": source["accessSecondsRemaining"],
        "idExpiresAt": source["idExpiresAt"],
        "idSecondsRemaining": source["idSecondsRemaining"],
        "idTokenFresh": source["idTokenFresh"],
        "hermersProfiles": split_csv(args.hermers_profiles),
        "openclawAgents": split_csv(args.openclaw_agents),
        "openclawProfileKinds": split_csv(args.openclaw_profile_kinds),
        "artifactRoot": args.artifact_root,
        "remoteCodexAuthPath": args.remote_codex_auth,
    }


def run_remote(args: argparse.Namespace, payload: dict[str, Any]) -> int:
    command = ["python3", "-c", REMOTE_RECEIVER]
    ssh_cmd = ["ssh"]
    if args.ssh_key:
        ssh_cmd.extend(["-i", args.ssh_key])
    ssh_cmd.extend(["-o", "BatchMode=yes", args.server, shlex.join(command)])
    proc = subprocess.run(
        ssh_cmd,
        input=json.dumps(payload),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=args.timeout,
    )
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    return proc.returncode


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mirror mac-codex OAuth access/id tokens to dev-server runtime stores without copying refresh tokens."
    )
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--ssh-key", default=DEFAULT_SSH_KEY)
    parser.add_argument("--codex-auth", default=os.path.expanduser("~/.codex/auth.json"))
    parser.add_argument("--artifact-root", default=DEFAULT_ARTIFACT_ROOT)
    parser.add_argument("--remote-codex-auth", default="/home/flashcat/.codex/auth.json")
    parser.add_argument("--hermers-profiles", default=DEFAULT_HERMERS_PROFILES)
    parser.add_argument("--openclaw-agents", default=DEFAULT_OPENCLAW_AGENTS)
    parser.add_argument("--openclaw-profile-kinds", default="openai,openai-codex")
    parser.add_argument("--min-ttl-seconds", type=int, default=3600)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--apply", action="store_true", help="write remote stores; default validates local mac-codex auth without connecting to the development server")
    parser.add_argument("--remote-dry-run", action="store_true", help="connect to the development server and run the remote receiver in dry-run mode")
    parser.add_argument("--local-preflight", action="store_true", help="validate local mac-codex auth and print a redacted summary without connecting to the development server")
    parser.add_argument("--json-only", action="store_true", help="print only the final JSON payload")
    parser.add_argument("--no-codex-cli", dest="codex_cli", action="store_false")
    parser.add_argument("--no-hermers", dest="hermers", action="store_false")
    parser.add_argument("--no-openclaw", dest="openclaw", action="store_false")
    parser.set_defaults(codex_cli=True, hermers=True, openclaw=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    payload = build_payload(args)
    local_preflight = bool(args.local_preflight or (not args.apply and not args.remote_dry_run))
    local_summary = {
        "schemaVersion": 1,
        "mode": "apply" if args.apply else "dry-run",
        "status": "preflight-ok" if local_preflight else "ready",
        "server": args.server,
        "targets": payload["targets"],
        "accessExpiresAt": payload["accessExpiresAt"],
        "accessSecondsRemaining": payload["accessSecondsRemaining"],
        "idExpiresAt": payload["idExpiresAt"],
        "idSecondsRemaining": payload["idSecondsRemaining"],
        "idTokenFresh": payload["idTokenFresh"],
        "refreshOwner": "mac-codex",
        "remoteRefreshTokenStored": False,
        "tokenValuesRedacted": True,
    }
    if local_preflight:
        print(json.dumps(local_summary, ensure_ascii=False, indent=2))
        return 0
    return run_remote(args, payload)


if __name__ == "__main__":
    raise SystemExit(main())
