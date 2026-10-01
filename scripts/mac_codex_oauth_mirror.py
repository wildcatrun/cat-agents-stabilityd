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
import platform
import re
import shlex
import socket
import subprocess
import sys
import time
from typing import Any


DUMMY_REFRESH = "MAC_CODEX_BROKER_REFRESH_DISABLED"
SAFE_RUNTIME_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DEFAULT_SERVER = "flashcat@106.54.53.146"
DEFAULT_FALLBACK_SERVER = "flashcat@dev-server.tail8e094d.ts.net"
DEFAULT_SSH_KEY = "/Users/Flashcat/.ssh/openclaw_server"
DEFAULT_HERMERS_PROFILES = "catbody,catears,cateyes,catheart,catnose,catpenclaw"
DEFAULT_OPENCLAW_AGENTS = "main"
DEFAULT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
DEFAULT_ARTIFACT_ROOT = "/home/flashcat/multi-agent-hedge-fund-framework/ops-artifacts/codex-working"
DEFAULT_REMOTE_CODEX_AUTH = "/home/flashcat/.codex/auth.json"
CANONICAL_LOCAL_CODEX_AUTH = pathlib.Path("/Users/Flashcat/.codex/auth.json")


REMOTE_RECEIVER = r"""
import base64
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import sqlite3
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
    target = pathlib.Path(path)
    if target.is_symlink():
        raise ValueError("symlink-directory-target")
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.is_symlink():
        raise ValueError("symlink-directory-target")
    os.chmod(target, 0o700)

def safe_target_path(root, target, label):
    root_path = pathlib.Path(root)
    target_path = pathlib.Path(target)
    if root_path.is_symlink() or root_path.resolve() != root_path.absolute():
        raise ValueError("symlink-" + label + "-root")
    root_real = root_path.resolve()
    try:
        relative = target_path.relative_to(root_path)
    except ValueError as exc:
        raise ValueError("outside-" + label + "-root") from exc
    cursor = root_path
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("symlink-" + label + "-target")
    resolved = target_path.resolve()
    try:
        resolved.relative_to(root_real)
    except ValueError as exc:
        raise ValueError("outside-" + label + "-root") from exc
    return target_path

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
    if dest.exists() or dest.is_symlink():
        raise ValueError("backup-destination-already-exists")
    shutil.copyfile(p, dest)
    os.chmod(dest, 0o600)
    return str(dest)

def backup_sqlite(path, backup_dir, label):
    source_path = pathlib.Path(path)
    if not source_path.exists():
        return []
    ensure_dir(backup_dir)
    dest = pathlib.Path(backup_dir) / label
    if dest.exists() or dest.is_symlink():
        raise ValueError("backup-destination-already-exists")
    source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True, timeout=30)
    target = sqlite3.connect(str(dest), timeout=30)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(dest, 0o600)
    return [str(dest)]

def safe_runtime_id(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value) is not None

def mirror_tokens(payload):
    tokens = payload["tokens"]
    return {
        "access_token": tokens["access_token"],
        "id_token": tokens.get("id_token") or "",
        "refresh_token": DUMMY_REFRESH,
    }

def apply_codex_cli(payload, artifact, dry_run):
    root = pathlib.Path("/home/flashcat/.codex")
    path = pathlib.Path(payload.get("remoteCodexAuthPath") or "/home/flashcat/.codex/auth.json")
    if path != root / "auth.json":
        raise ValueError("invalid-remote-codex-auth-path")
    path = safe_target_path(root, path, "codex-auth")
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
    profiles_root = pathlib.Path("/home/flashcat/.hermes/profiles")
    if profiles_root.is_symlink():
        raise ValueError("symlink-hermes-profiles-root")
    for profile in payload.get("hermersProfiles", []):
        if not safe_runtime_id(profile):
            raise ValueError("unsafe-hermers-profile-id")
        profile_dir = profiles_root / profile
        path = safe_target_path(profiles_root, profile_dir / "auth.json", "hermes-profile")
        if not profile_dir.is_dir() or not path.is_file():
            raise ValueError("missing-hermes-profile-auth")
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
    agents_root = pathlib.Path("/home/flashcat/.openclaw/agents")
    if agents_root.is_symlink():
        raise ValueError("symlink-openclaw-agents-root")
    target_pairs = payload.get("openclawTargets")
    if not target_pairs:
        profile_kinds = payload.get("openclawProfileKinds") or ["openai", "openai-codex"]
        target_pairs = [
            {"agentId": agent_id, "profileKind": profile_kind}
            for agent_id in payload.get("openclawAgents", [])
            for profile_kind in profile_kinds
        ]
    targets_by_agent = {}
    for item in target_pairs:
        if not isinstance(item, dict):
            raise ValueError("invalid-openclaw-target")
        agent_id = item.get("agentId")
        profile_kind = item.get("profileKind")
        if not safe_runtime_id(agent_id) or profile_kind not in {"openai", "openai-codex"}:
            raise ValueError("unsafe-openclaw-target")
        targets_by_agent.setdefault(agent_id, set()).add(profile_kind)
    for agent_id, profile_kinds_set in sorted(targets_by_agent.items()):
        profile_kinds = sorted(profile_kinds_set)
        agent_dir = agents_root / agent_id
        agent_state_dir = agent_dir / "agent"
        db_path = agent_state_dir / "openclaw-agent.sqlite"
        db_path = safe_target_path(agents_root, db_path, "openclaw-agent")
        if agent_dir.is_symlink() or agent_state_dir.is_symlink() or db_path.is_symlink():
            raise ValueError("symlink-openclaw-agent-target")
        if not db_path.exists():
            results.append({"target": f"openclaw:{agent_id}", "missing": True, "path": str(db_path)})
            continue
        backups = [] if dry_run else backup_sqlite(str(db_path), artifact / "backups", f"openclaw-{agent_id}.sqlite")
        conn = sqlite3.connect(str(db_path), timeout=30)
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
                "target": f"openclaw:{agent_id}:{','.join(profile_kinds)}",
                "path": str(db_path),
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
    incomplete = [
        item for item in results
        if item.get("missing") is True or (not dry_run and item.get("written") is not True)
    ]
    status = "dry-run" if dry_run else "partial-failure" if incomplete else "applied"
    summary = {
        "schemaVersion": 1,
        "status": status,
        "artifact": str(artifact),
        "generatedAt": iso_now(),
        "source": payload.get("source"),
        "targets": sorted(targets),
        "tokenValuesRedacted": True,
        "refreshOwner": "mac-codex",
        "remoteRefreshTokenStored": False,
        "stabilityActionIds": [
            str(item) for item in (payload.get("stabilityActionIds") or []) if str(item)
        ],
        "accessExpiresAt": payload["accessExpiresAt"],
        "results": results,
    }
    (artifact / "index.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 1 if incomplete and not dry_run else 0

if __name__ == "__main__":
    sys.exit(main())
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


def inspect_codex_auth(path: pathlib.Path) -> dict[str, Any]:
    """Return local mac-codex token timing without exposing token values."""
    if not path.exists():
        return {"status": "missing-auth-file", "path": str(path), "tokenValuesRedacted": True}
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        return {
            "status": "invalid-auth-file",
            "path": str(path),
            "errorType": type(exc).__name__,
            "tokenValuesRedacted": True,
        }
    tokens = data.get("tokens") if isinstance(data, dict) else None
    if not isinstance(tokens, dict):
        return {"status": "missing-tokens", "path": str(path), "tokenValuesRedacted": True}
    access_token = tokens.get("access_token")
    id_token = tokens.get("id_token")
    refresh_token = tokens.get("refresh_token")
    if not isinstance(access_token, str) or not access_token.strip():
        return {"status": "missing-access-token", "path": str(path), "tokenValuesRedacted": True}
    try:
        access_exp, access_remaining = inspect_jwt_expiry(access_token, "access_token")
    except Exception as exc:
        return {
            "status": "invalid-access-token",
            "path": str(path),
            "errorType": type(exc).__name__,
            "tokenValuesRedacted": True,
        }
    id_exp = 0
    id_remaining = None
    if isinstance(id_token, str) and id_token.strip():
        try:
            id_exp, id_remaining = inspect_jwt_expiry(id_token, "id_token")
        except Exception:
            id_exp, id_remaining = 0, None
    refresh_present = (
        isinstance(refresh_token, str)
        and bool(refresh_token.strip())
        and refresh_token != DUMMY_REFRESH
    )
    try:
        auth_mtime_epoch = int(path.stat().st_mtime)
    except OSError:
        auth_mtime_epoch = None
    return {
        "schemaVersion": 1,
        "status": "ok",
        "path": str(path),
        "mode": oct(path.stat().st_mode & 0o777),
        "authMode": data.get("auth_mode"),
        "lastRefresh": data.get("last_refresh"),
        "authMtimeEpoch": auth_mtime_epoch,
        "accessExpiresAt": iso_from_epoch(access_exp),
        "accessSecondsRemaining": access_remaining,
        "idExpiresAt": iso_from_epoch(id_exp),
        "idSecondsRemaining": id_remaining,
        "idTokenFresh": id_remaining is not None and id_remaining > 0,
        "refreshTokenPresent": refresh_present,
        "refreshOwner": "mac-codex" if refresh_present else None,
        "remoteRefreshTokenStored": False,
        "tokenValuesRedacted": True,
    }


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


def parse_openclaw_targets(value: str) -> list[dict[str, str]]:
    targets = []
    for item in split_csv(value):
        parts = item.split(":")
        if (
            len(parts) != 2
            or not SAFE_RUNTIME_ID.fullmatch(parts[0])
            or parts[1] not in {"openai", "openai-codex"}
        ):
            raise SystemExit("invalid or unsafe OpenClaw mirror target")
        targets.append({"agentId": parts[0], "profileKind": parts[1]})
    return targets


def validate_runtime_ids(values: list[str], label: str) -> list[str]:
    if any(not SAFE_RUNTIME_ID.fullmatch(item) for item in values):
        raise SystemExit(f"invalid or unsafe {label} id")
    return values


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
    hermers_profiles = validate_runtime_ids(split_csv(args.hermers_profiles), "Hermes profile")
    openclaw_agents = validate_runtime_ids(split_csv(args.openclaw_agents), "OpenClaw agent")
    openclaw_profile_kinds = split_csv(args.openclaw_profile_kinds)
    if any(item not in {"openai", "openai-codex"} for item in openclaw_profile_kinds):
        raise SystemExit("unsupported OpenClaw OAuth provider kind")
    openclaw_targets = parse_openclaw_targets(args.openclaw_targets)
    if args.openclaw and not openclaw_targets:
        openclaw_targets = [
            {"agentId": agent_id, "profileKind": profile_kind}
            for agent_id in openclaw_agents
            for profile_kind in openclaw_profile_kinds
        ]
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
        "hermersProfiles": hermers_profiles,
        "openclawAgents": openclaw_agents,
        "openclawProfileKinds": openclaw_profile_kinds,
        "openclawTargets": openclaw_targets,
        "stabilityActionIds": split_csv(args.stability_action_ids),
        "artifactRoot": args.artifact_root,
        "remoteCodexAuthPath": args.remote_codex_auth,
    }


def run_remote(args: argparse.Namespace, payload: dict[str, Any]) -> int:
    command = ["python3", "-c", REMOTE_RECEIVER]
    servers = [args.server]
    if args.fallback_server and args.fallback_server not in servers:
        servers.append(args.fallback_server)
    for index, server in enumerate(servers):
        ssh_cmd = ["ssh"]
        if args.ssh_key:
            ssh_cmd.extend(["-i", args.ssh_key])
        ssh_cmd.extend(
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ConnectTimeout=8",
                "-o",
                "ServerAliveInterval=5",
                "-o",
                "ServerAliveCountMax=2",
                server,
                shlex.join(command),
            ]
        )
        try:
            proc = subprocess.run(
                ssh_cmd,
                input=json.dumps(payload),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
            )
        except subprocess.TimeoutExpired:
            print(
                json.dumps(
                    {
                        "status": "remote-timeout",
                        "server": server,
                        "fallbackAttempted": False,
                        "fallbackAvailable": index + 1 < len(servers),
                        "tokenValuesRedacted": True,
                    }
                ),
                file=sys.stderr,
            )
            return 124
        if proc.returncode == 0:
            if proc.stdout:
                print(proc.stdout, end="")
            if proc.stderr:
                print(proc.stderr, end="", file=sys.stderr)
            return 0
        transport_errors = (
            "network is unreachable",
            "no route to host",
            "connect timed out",
            "connection timed out",
            "connection refused",
            "could not resolve hostname",
        )
        is_transport_failure = any(
            marker in proc.stderr.lower() for marker in transport_errors
        )
        if is_transport_failure and index + 1 < len(servers):
            print(
                json.dumps(
                    {
                        "status": "transport-fallback",
                        "failedServer": server,
                        "nextServer": servers[index + 1],
                        "tokenValuesRedacted": True,
                    }
                ),
                file=sys.stderr,
            )
            continue
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
        return proc.returncode
    return 255


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mirror mac-codex OAuth access/id tokens to dev-server runtime stores without copying refresh tokens."
    )
    parser.add_argument("--server", default=DEFAULT_SERVER)
    parser.add_argument("--fallback-server", default=DEFAULT_FALLBACK_SERVER)
    parser.add_argument("--ssh-key", default=DEFAULT_SSH_KEY)
    parser.add_argument("--codex-auth", default=os.path.expanduser("~/.codex/auth.json"))
    parser.add_argument("--artifact-root", default=DEFAULT_ARTIFACT_ROOT)
    parser.add_argument("--remote-codex-auth", default=DEFAULT_REMOTE_CODEX_AUTH)
    parser.add_argument("--hermers-profiles", default=DEFAULT_HERMERS_PROFILES)
    parser.add_argument("--openclaw-agents", default=DEFAULT_OPENCLAW_AGENTS)
    parser.add_argument("--openclaw-profile-kinds", default="openai,openai-codex")
    parser.add_argument("--openclaw-targets", default="", help="precise agent/provider pairs as agent:provider,agent:provider")
    parser.add_argument("--action-ids", dest="stability_action_ids", default="", help="stabilityd auth-maintenance action ids included in the mirror evidence")
    parser.add_argument("--min-ttl-seconds", type=int, default=300)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--apply", action="store_true", help="write remote stores; default validates local mac-codex auth without connecting to the development server")
    parser.add_argument("--remote-dry-run", action="store_true", help="connect to the development server and run the remote receiver in dry-run mode")
    parser.add_argument("--local-preflight", action="store_true", help="validate local mac-codex auth and print a redacted summary without connecting to the development server")
    parser.add_argument("--json-only", action="store_true", help="print only the final JSON payload")
    parser.add_argument("--inspect-auth", action="store_true", help="print redacted mac-codex token expiry metadata without connecting or requiring unexpired tokens")
    parser.add_argument("--no-codex-cli", dest="codex_cli", action="store_false")
    parser.add_argument("--no-hermers", dest="hermers", action="store_false")
    parser.add_argument("--no-openclaw", dest="openclaw", action="store_false")
    parser.set_defaults(codex_cli=True, hermers=True, openclaw=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.inspect_auth:
        print(json.dumps(inspect_codex_auth(pathlib.Path(args.codex_auth).expanduser()), ensure_ascii=False, indent=2))
        return 0
    if args.apply and platform.system() != "Darwin":
        raise SystemExit("OAuth mirror apply is restricted to the mac-codex refresh-owner host")
    if args.apply and pathlib.Path(args.codex_auth).expanduser().resolve() != CANONICAL_LOCAL_CODEX_AUTH:
        raise SystemExit("OAuth mirror apply is restricted to /Users/Flashcat/.codex/auth.json")
    if args.remote_codex_auth != DEFAULT_REMOTE_CODEX_AUTH:
        raise SystemExit("remote Codex mirror destination is fixed by stabilityd policy")
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
