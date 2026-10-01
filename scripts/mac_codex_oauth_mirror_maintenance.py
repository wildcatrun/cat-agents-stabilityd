#!/usr/bin/env python3
"""Keep dev-server Codex/Hermes/OpenClaw auth mirrors aligned with mac-codex.

The Mac Codex CLI remains the only refresh-token owner. Near access-token
expiry, this job makes one ephemeral read-only Codex CLI request so the CLI's
own auth manager can refresh its local credentials. It then mirrors only the
resulting access/id tokens to the development server.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


ROOT = pathlib.Path("/Users/Flashcat/cat-agents-stabilityd")
CLI = ROOT / "bin" / "cat-agents-stability"
MIRROR = ROOT / "scripts" / "mac_codex_oauth_mirror.py"
AUTH_PATH = pathlib.Path("/Users/Flashcat/.codex/auth.json")
CODEX_HOME = AUTH_PATH.parent
CODEX = pathlib.Path(os.environ.get("CAT_AGENTS_STABILITY_CODEX_BIN", "/usr/local/bin/codex"))
SSH = pathlib.Path("/usr/bin/ssh")
PYTHON = pathlib.Path("/usr/bin/python3")
SERVER = "flashcat@106.54.53.146"
FALLBACK_SERVER = "flashcat@dev-server.tail8e094d.ts.net"
SSH_KEY = pathlib.Path("/Users/Flashcat/.ssh/openclaw_server")
REMOTE_CLI = "/home/flashcat/cat-agents-stabilityd/bin/cat-agents-stability"
LOG_DIR = ROOT / "reports" / "auth-mirror"
LOCK_DIR = LOG_DIR / ".lock"
LATEST_FILE = LOG_DIR / "latest.json"
REMOTE_PLAN_FILE = LOG_DIR / "remote-plan-latest.json"
MODEL = "gpt-6-luna"
REFRESH_WINDOW_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_REFRESH_WINDOW_SECONDS", str(5 * 60)))
REFRESH_RETRY_BASE_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_REFRESH_RETRY_BASE_SECONDS", "60"))
REFRESH_RETRY_MAX_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_REFRESH_RETRY_MAX_SECONDS", str(15 * 60)))
CONCURRENT_REFRESH_SETTLE_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_CONCURRENT_REFRESH_SETTLE_SECONDS", "15"))
REMOTE_PLAN_POLL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_REMOTE_PLAN_POLL_SECONDS", "15"))
REMOTE_PLAN_FRESH_POLL_SECONDS = int(os.environ.get("CAT_AGENTS_STABILITY_AUTH_REMOTE_PLAN_FRESH_POLL_SECONDS", str(15 * 60)))
MIRROR_MIN_TTL_SECONDS = 5 * 60
CODEX_TIMEOUT_SECONDS = 180
SSH_TIMEOUT_SECONDS = 90
MIRROR_TARGETS = ("codex-cli", "hermers:", "openclaw:")
SAFE_RUNTIME_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def timestamp_epoch(value: Any) -> Optional[int]:
    try:
        text = str(value or "")
        if not text:
            return None
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return int(parsed.timestamp())
    except (TypeError, ValueError, OverflowError):
        return None


def plan_generation_epoch_ns(plan: Optional[Dict[str, Any]], success: Optional[Dict[str, Any]] = None) -> Optional[int]:
    try:
        value = int(plan.get("generatedAtEpochNs")) if isinstance(plan, dict) else 0
        if value > 0:
            return value
    except (TypeError, ValueError):
        pass
    try:
        value = int(success.get("remotePlanGeneratedAtEpochNs")) if isinstance(success, dict) else 0
        if value > 0:
            return value
    except (TypeError, ValueError):
        pass
    generated_at = plan.get("generatedAt") if isinstance(plan, dict) else None
    if generated_at:
        epoch_seconds = timestamp_epoch(generated_at)
        return epoch_seconds * 1_000_000_000 if epoch_seconds is not None else None
    epoch_seconds = timestamp_epoch(success.get("remotePlanGeneratedAt")) if isinstance(success, dict) else None
    return epoch_seconds * 1_000_000_000 if epoch_seconds is not None else None


def load_json(path: pathlib.Path) -> Optional[Dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def write_json_atomic(path: pathlib.Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp_name, str(path))
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def acquire_lock() -> bool:
    try:
        LOCK_DIR.mkdir(mode=0o700)
    except FileExistsError:
        pid_file = LOCK_DIR / "pid"
        try:
            pid = int(pid_file.read_text(encoding="ascii").strip())
            os.kill(pid, 0)
            return False
        except (OSError, ValueError):
            try:
                age = time.time() - LOCK_DIR.stat().st_mtime
                if age < 1800:
                    return False
                pid_file.unlink(missing_ok=True)
                LOCK_DIR.rmdir()
            except OSError:
                return False
            try:
                LOCK_DIR.mkdir(mode=0o700)
            except FileExistsError:
                return False
    (LOCK_DIR / "pid").write_text(str(os.getpid()), encoding="ascii")
    return True


def release_lock() -> None:
    try:
        (LOCK_DIR / "pid").unlink(missing_ok=True)
        LOCK_DIR.rmdir()
    except OSError:
        pass


def inspect_source() -> Dict[str, Any]:
    proc = subprocess.run(
        [str(PYTHON), str(MIRROR), "--codex-auth", str(AUTH_PATH), "--inspect-auth", "--json-only"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError("local-codex-auth-inspection-failed")
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("local-codex-auth-inspection-invalid-json") from exc
    if not isinstance(value, dict) or value.get("status") != "ok":
        raise RuntimeError("local-codex-auth-unavailable")
    return value


def eligible_mirror_actions(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    executor = plan.get("macCodexExecutor")
    if (
        plan.get("schemaVersion") != 1
        or not isinstance(executor, dict)
        or executor.get("supported") is not True
        or executor.get("refreshOwner") != "mac-codex"
        or executor.get("refreshBrokerEnabled") is not False
    ):
        return []
    actions = plan.get("actions")
    if not isinstance(actions, list):
        return []
    selected = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        policy = action.get("localAutomation")
        if not isinstance(policy, dict):
            continue
        if (
            policy.get("eligible") is not True
            or policy.get("owner") != "mac-codex"
            or policy.get("mode") != "access-id-token-mirror"
            or action.get("humanGateRequired") is not False
        ):
            continue
        target = str(action.get("target") or "")
        if target == MIRROR_TARGETS[0] or any(target.startswith(prefix) and len(target) > len(prefix) for prefix in MIRROR_TARGETS[1:]):
            selected.append(action)
    return selected


def plan_has_human_gate(plan: Dict[str, Any]) -> bool:
    if plan.get("schemaVersion") != 1:
        return True
    executor = plan.get("macCodexExecutor")
    if (
        not isinstance(executor, dict)
        or executor.get("supported") is not True
        or executor.get("refreshOwner") != "mac-codex"
        or executor.get("refreshBrokerEnabled") is not False
    ):
        return True
    actions = plan.get("actions")
    if not isinstance(actions, list):
        return True
    for action in actions:
        if not isinstance(action, dict) or type(action.get("humanGateRequired")) is not bool:
            return True
        if action["humanGateRequired"]:
            return True
    return False


def mirror_scope_for_actions(actions: List[Dict[str, Any]]) -> Dict[str, Any]:
    scope: Dict[str, Any] = {
        "codexCli": False,
        "hermersProfiles": set(),
        "openclawTargets": set(),
    }
    for action in actions:
        target = str(action.get("target") or "")
        if target == "codex-cli":
            scope["codexCli"] = True
        elif target.startswith("hermers:") and len(target.split(":")) == 2:
            profile = target.split(":", 1)[1]
            if not SAFE_RUNTIME_ID.fullmatch(profile):
                raise ValueError("unsafe-hermers-profile-target")
            scope["hermersProfiles"].add(profile)
        elif target.startswith("openclaw:"):
            parts = target.split(":")
            if (
                len(parts) != 3
                or not SAFE_RUNTIME_ID.fullmatch(parts[1])
                or parts[2] not in {"openai", "openai-codex"}
            ):
                raise ValueError("unsupported-openclaw-mirror-target")
            scope["openclawTargets"].add((parts[1], parts[2]))
        else:
            raise ValueError("unsupported-mirror-target")
    scope["hermersProfiles"] = sorted(scope["hermersProfiles"])
    scope["openclawTargets"] = [
        {"agentId": agent_id, "profileKind": profile_kind}
        for agent_id, profile_kind in sorted(scope["openclawTargets"])
    ]
    return scope


def normalize_mirror_scope(scope: Any, *, require_target: bool = False) -> Dict[str, Any]:
    if not isinstance(scope, dict) or type(scope.get("codexCli")) is not bool:
        raise ValueError("invalid-mirror-target-scope")
    hermers = scope.get("hermersProfiles")
    openclaw = scope.get("openclawTargets")
    if not isinstance(hermers, list) or not isinstance(openclaw, list):
        raise ValueError("invalid-mirror-target-scope")
    if any(not isinstance(item, str) or not SAFE_RUNTIME_ID.fullmatch(item) for item in hermers):
        raise ValueError("unsafe-hermers-profile-target")
    openclaw_pairs = set()
    for item in openclaw:
        if not isinstance(item, dict):
            raise ValueError("invalid-openclaw-target-scope")
        agent_id = item.get("agentId")
        profile_kind = item.get("profileKind")
        if not isinstance(agent_id, str) or not SAFE_RUNTIME_ID.fullmatch(agent_id):
            raise ValueError("unsafe-openclaw-agent-target")
        if profile_kind not in {"openai", "openai-codex"}:
            raise ValueError("unsupported-openclaw-mirror-target")
        openclaw_pairs.add((agent_id, profile_kind))
    result = {
        "codexCli": scope["codexCli"],
        "hermersProfiles": sorted(set(hermers)),
        "openclawTargets": [
            {"agentId": agent_id, "profileKind": provider}
            for agent_id, provider in sorted(openclaw_pairs)
        ],
    }
    if require_target and not (
        result["codexCli"] or result["hermersProfiles"] or result["openclawTargets"]
    ):
        raise ValueError("empty-mirror-target-scope")
    return result


def mirror_scope_for_plan_targets(plan: Dict[str, Any]) -> Dict[str, Any]:
    executor = plan.get("macCodexExecutor")
    if not isinstance(executor, dict):
        raise ValueError("missing-mac-codex-executor")
    return normalize_mirror_scope(executor.get("targets"), require_target=True)


def mirror_scope_contains(scope: Dict[str, Any], action: Dict[str, Any]) -> bool:
    try:
        needed = mirror_scope_for_actions([action])
        allowed = normalize_mirror_scope(scope)
    except ValueError:
        return False
    if needed["codexCli"] and not allowed["codexCli"]:
        return False
    if not set(needed["hermersProfiles"]).issubset(allowed["hermersProfiles"]):
        return False
    allowed_pairs = {
        (item["agentId"], item["profileKind"]) for item in allowed["openclawTargets"]
    }
    needed_pairs = {
        (item["agentId"], item["profileKind"]) for item in needed["openclawTargets"]
    }
    return needed_pairs.issubset(allowed_pairs)


def unresolved_mirror_action_ids(
    plan: Dict[str, Any], actions: List[Dict[str, Any]], *, source_wide: bool,
    scope: Optional[Dict[str, Any]] = None,
) -> List[str]:
    executor = plan.get("macCodexExecutor")
    planned_actions = plan.get("actions")
    if (
        plan.get("schemaVersion") != 1
        or not isinstance(executor, dict)
        or executor.get("supported") is not True
        or executor.get("refreshOwner") != "mac-codex"
        or executor.get("refreshBrokerEnabled") is not False
        or not isinstance(planned_actions, list)
    ):
        return ["invalid-plan"]
    if any(not isinstance(item, dict) or type(item.get("humanGateRequired")) is not bool for item in planned_actions):
        return ["invalid-plan-action"]
    if any(not isinstance(item.get("actionId"), str) or not item.get("actionId") for item in planned_actions):
        return ["invalid-plan-action-id"]
    attempted = {str(item.get("actionId") or "") for item in actions if str(item.get("actionId") or "")}
    if source_wide and any(item.get("humanGateRequired") is True for item in planned_actions):
        return ["human-gate-required"]
    if source_wide:
        try:
            scope = normalize_mirror_scope(scope, require_target=True)
        except ValueError:
            return ["invalid-mirror-target-scope"]
    unresolved: List[str] = []
    for item in planned_actions:
        action_id = str(item.get("actionId") or "")
        if not action_id:
            continue
        if source_wide:
            local_policy = item.get("localAutomation")
            mirror_pending = isinstance(local_policy, dict) and local_policy.get("eligible") is True
            cleanup_pending = item.get("kind") == "deduplicate-token-copies"
            if (mirror_pending and not mirror_scope_contains(scope, item)) or (
                cleanup_pending and not scope.get("hermersProfiles")
            ):
                unresolved.append(action_id)
            elif mirror_pending or cleanup_pending:
                unresolved.append(action_id)
        elif action_id in attempted:
            if item.get("humanGateRequired") is True:
                return ["human-gate-required"]
            unresolved.append(action_id)
    return sorted(set(unresolved))


def unresolved_saved_mirror_action_ids(
    plan: Dict[str, Any], success: Dict[str, Any]
) -> List[str]:
    source_wide = success.get("sourceWide") is True
    if source_wide:
        return unresolved_mirror_action_ids(
            plan,
            [],
            source_wide=True,
            scope=success.get("mirrorScope"),
        )
    action_ids = {
        str(item)
        for item in (success.get("mirrorActionIds") or [])
        if isinstance(item, str) and item
    }
    previous_attempt_ids = success.get("actionIds")
    if not action_ids and isinstance(previous_attempt_ids, list):
        action_ids = {str(item) for item in previous_attempt_ids if str(item)}
    if not action_ids:
        return ["missing-saved-mirror-action-ids"]
    plan_actions = plan.get("actions")
    if not isinstance(plan_actions, list):
        return ["invalid-plan"]
    attempted_actions = [
        item for item in plan_actions
        if isinstance(item, dict) and str(item.get("actionId") or "") in action_ids
    ]
    return unresolved_mirror_action_ids(plan, attempted_actions, source_wide=False)


def mirror_postcheck_block_reason(unresolved_ids: List[str]) -> Optional[str]:
    if "human-gate-required" in unresolved_ids:
        return "human-gate-required"
    blocker = next(
        (item for item in unresolved_ids if item.startswith("invalid-") or item == "missing-saved-mirror-action-ids"),
        None,
    )
    return blocker


def last_success(previous: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not previous:
        return None
    value = previous.get("lastSuccessfulMirror")
    if isinstance(value, dict):
        return value
    if previous.get("status") == "applied":
        summary = previous.get("mirrorSummary")
        summary = summary if isinstance(summary, dict) else {}
        return {
            "checkedAt": previous.get("checkedAt"),
            "sourceAccessExpiresAt": summary.get("accessExpiresAt"),
            "sourceLastRefresh": previous.get("sourceLastRefresh"),
            "sourceAuthMtimeEpoch": previous.get("sourceAuthMtimeEpoch"),
            "mirrorSummary": summary,
            "postcheckOk": True,
        }
    return None


def source_changed(source: Dict[str, Any], success: Optional[Dict[str, Any]]) -> bool:
    if not success:
        return True
    expiry = source.get("accessExpiresAt")
    last_refresh = source.get("lastRefresh")
    mtime = source.get("authMtimeEpoch")
    compared = False
    if expiry and success.get("sourceAccessExpiresAt"):
        compared = True
        if expiry != success.get("sourceAccessExpiresAt"):
            return True
    if last_refresh and success.get("sourceLastRefresh"):
        compared = True
        if last_refresh != success.get("sourceLastRefresh"):
            return True
    id_expiry = source.get("idExpiresAt")
    if id_expiry and success.get("sourceIdTokenExpiresAt"):
        compared = True
        if id_expiry != success.get("sourceIdTokenExpiresAt"):
            return True
    if compared:
        return False
    try:
        return bool(mtime and success.get("sourceAuthMtimeEpoch") and int(mtime) > int(success["sourceAuthMtimeEpoch"]))
    except (TypeError, ValueError):
        return False


def filter_postchecked_mirror_actions(
    actions: List[Dict[str, Any]],
    plan: Dict[str, Any],
    success: Optional[Dict[str, Any]],
    *,
    now_epoch: Optional[int] = None,
) -> List[Dict[str, Any]]:
    if not isinstance(success, dict) or success.get("postcheckOk") is not True:
        return actions
    now_epoch = int(now_epoch or time.time())
    try:
        last_mirror_epoch = int(success.get("mirrorCompletedAtEpoch") or 0)
    except (TypeError, ValueError):
        last_mirror_epoch = 0
    if not last_mirror_epoch or now_epoch - last_mirror_epoch >= 6 * 60 * 60:
        return actions
    plan_epoch = plan_generation_epoch_ns(plan)
    verified_epoch = plan_generation_epoch_ns(None, success)
    same_or_older_snapshot = (
        plan_epoch is not None
        and verified_epoch is not None
        and plan_epoch <= verified_epoch
    )
    legacy_snapshot = plan_epoch is None or verified_epoch is None
    if not same_or_older_snapshot and not legacy_snapshot:
        return actions
    if success.get("sourceWide") is True:
        scope = success.get("mirrorScope") if isinstance(success.get("mirrorScope"), dict) else {}
        return [item for item in actions if not mirror_scope_contains(scope, item)]
    action_ids = {str(item) for item in success.get("mirrorActionIds") or [] if str(item)}
    return [item for item in actions if str(item.get("actionId") or "") not in action_ids]


def refresh_condition_key(source: Dict[str, Any]) -> str:
    return "|".join(
        [
            str(source.get("accessExpiresAt") or ""),
            str(source.get("lastRefresh") or ""),
            str(source.get("idExpiresAt") or ""),
        ]
    )


def observe_concurrent_local_refresh(source: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    if CONCURRENT_REFRESH_SETTLE_SECONDS > 0:
        time.sleep(CONCURRENT_REFRESH_SETTLE_SECONDS)
    latest = inspect_source()
    if refresh_condition_key(latest) == refresh_condition_key(source):
        return None, latest
    return {
        "attemptedAt": iso_now(),
        "attemptedAtEpoch": int(time.time()),
        "refreshConditionKey": refresh_condition_key(source),
        "result": "token-advanced-by-concurrent-local-refresh",
        "method": "observed-shared-codex-auth-after-settle",
        "newAccessExpiresAt": latest.get("accessExpiresAt"),
        "tokenValuesRedacted": True,
    }, latest


def codex_refresh_due(source: Dict[str, Any], now_epoch: Optional[int] = None) -> bool:
    try:
        remaining = int(source.get("accessSecondsRemaining"))
    except (TypeError, ValueError):
        return False
    return remaining <= REFRESH_WINDOW_SECONDS


def should_nudge_refresh(
    source: Dict[str, Any], previous: Optional[Dict[str, Any]], now_epoch: Optional[int] = None
) -> bool:
    if not codex_refresh_due(source, now_epoch) or not source.get("refreshTokenPresent"):
        return False
    if not CODEX.is_file():
        return False
    attempt = previous.get("sourceRefreshAttempt") if isinstance(previous, dict) else None
    if not isinstance(attempt, dict):
        return True
    if attempt.get("refreshConditionKey") != refresh_condition_key(source):
        return True
    if attempt.get("manualRecoveryRequired") is True:
        return False
    try:
        attempted_at = int(attempt.get("attemptedAtEpoch"))
    except (TypeError, ValueError):
        return True
    now_epoch = now_epoch or int(time.time())
    try:
        retry_after = max(1, int(attempt.get("retryAfterSeconds") or REFRESH_RETRY_BASE_SECONDS))
    except (TypeError, ValueError):
        retry_after = REFRESH_RETRY_BASE_SECONDS
    return now_epoch - attempted_at >= retry_after


def next_retry_seconds(previous: Optional[Dict[str, Any]], condition_key: str) -> Tuple[int, int]:
    prior = previous.get("sourceRefreshAttempt") if isinstance(previous, dict) else None
    if not isinstance(prior, dict) or prior.get("refreshConditionKey") != condition_key:
        return 1, min(REFRESH_RETRY_BASE_SECONDS, REFRESH_RETRY_MAX_SECONDS)
    try:
        count = max(0, int(prior.get("attemptNumber") or 0)) + 1
    except (TypeError, ValueError):
        count = 1
    delay = min(REFRESH_RETRY_MAX_SECONDS, REFRESH_RETRY_BASE_SECONDS * (2 ** min(count - 1, 20)))
    return count, delay


def next_mirror_retry_seconds(previous: Optional[Dict[str, Any]], condition_key: str) -> Tuple[int, int]:
    prior = previous.get("lastMirrorAttempt") if isinstance(previous, dict) else None
    if (
        not isinstance(prior, dict)
        or prior.get("result") != "failed"
        or prior.get("refreshConditionKey") != condition_key
    ):
        return 1, min(REFRESH_RETRY_BASE_SECONDS, REFRESH_RETRY_MAX_SECONDS)
    try:
        count = max(0, int(prior.get("attemptNumber") or 0)) + 1
    except (TypeError, ValueError):
        count = 1
    delay = min(REFRESH_RETRY_MAX_SECONDS, REFRESH_RETRY_BASE_SECONDS * (2 ** min(count - 1, 20)))
    return count, delay


def mirror_retry_deferred(
    previous: Optional[Dict[str, Any]],
    source: Dict[str, Any],
    action_ids: Optional[List[str]] = None,
    now_epoch: Optional[int] = None,
) -> bool:
    prior = previous.get("lastMirrorAttempt") if isinstance(previous, dict) else None
    if not isinstance(prior, dict) or prior.get("result") != "failed":
        return False
    if prior.get("refreshConditionKey") != refresh_condition_key(source):
        return False
    if action_ids is not None:
        prior_ids = {str(item) for item in prior.get("actionIds") or [] if str(item)}
        if not prior_ids.intersection(str(item) for item in action_ids):
            return False
    try:
        attempted_at = int(prior.get("attemptedAtEpoch"))
        retry_after = max(1, int(prior.get("retryAfterSeconds") or REFRESH_RETRY_BASE_SECONDS))
    except (TypeError, ValueError):
        return False
    now_epoch = now_epoch or int(time.time())
    return now_epoch - attempted_at < retry_after


def mirror_operation_id_for_attempt(
    previous: Optional[Dict[str, Any]],
    source: Dict[str, Any],
    action_ids: List[str],
    scope: Optional[Dict[str, Any]],
    source_wide: bool,
) -> str:
    prior = previous.get("lastMirrorAttempt") if isinstance(previous, dict) else None
    if (
        isinstance(prior, dict)
        and prior.get("result") in {"failed", "postcheck-pending"}
        and prior.get("refreshConditionKey") == refresh_condition_key(source)
        and prior.get("sourceWide") is source_wide
        and prior.get("mirrorScope") == scope
    ):
        prior_ids = sorted({str(item) for item in prior.get("actionIds") or [] if str(item)})
        current_ids = sorted({str(item) for item in action_ids if str(item)})
        if source_wide or prior_ids == current_ids:
            prior_id = str(prior.get("operationId") or "")
            if SAFE_RUNTIME_ID.fullmatch(prior_id):
                return prior_id
    return uuid.uuid4().hex


def protected_mirror_operation_ids(previous: Optional[Dict[str, Any]]) -> List[str]:
    stored_ids = previous.get("pendingMirrorOperationIds") if isinstance(previous, dict) else []
    protected = {
        str(item)
        for item in (stored_ids or [])
        if str(item)
    }
    attempt = previous.get("lastMirrorAttempt") if isinstance(previous, dict) else None
    if isinstance(attempt, dict) and attempt.get("result") in {"failed", "postcheck-pending", "blocked"}:
        operation_id = str(attempt.get("operationId") or "")
        if SAFE_RUNTIME_ID.fullmatch(operation_id):
            protected.add(operation_id)
    return sorted(item for item in protected if SAFE_RUNTIME_ID.fullmatch(item))


def mark_last_mirror_postcheck_resolved(previous: Dict[str, Any]) -> None:
    attempt = previous.get("lastMirrorAttempt") if isinstance(previous, dict) else None
    if not isinstance(attempt, dict) or attempt.get("applyResult") != "applied":
        return
    if not SAFE_RUNTIME_ID.fullmatch(str(attempt.get("operationId") or "")):
        return
    previous["lastMirrorAttempt"] = {
        **attempt,
        "result": "applied",
        "postcheckStatus": "ok",
    }


def mirror_actions_already_postchecked(
    plan: Optional[Dict[str, Any]], success: Optional[Dict[str, Any]]
) -> bool:
    if not isinstance(plan, dict) or not isinstance(success, dict) or success.get("postcheckOk") is not True:
        return False
    current_epoch = plan_generation_epoch_ns(plan)
    verified_epoch = plan_generation_epoch_ns(None, success)
    return current_epoch is not None and verified_epoch is not None and current_epoch <= verified_epoch


def remote_plan_fetch_policy(
    previous: Optional[Dict[str, Any]],
    plan: Optional[Dict[str, Any]],
    source: Dict[str, Any],
    *,
    now_epoch: Optional[int] = None,
) -> Tuple[bool, bool]:
    now_epoch = int(now_epoch or time.time())
    try:
        last_plan_epoch = int(previous.get("remotePlanFetchedAtEpoch") or 0) if isinstance(previous, dict) else 0
    except (TypeError, ValueError):
        last_plan_epoch = 0
    try:
        last_fresh_epoch = int(previous.get("remoteFreshPlanFetchedAtEpoch") or 0) if isinstance(previous, dict) else 0
    except (TypeError, ValueError):
        last_fresh_epoch = 0
    poll_due = plan is None or not last_plan_epoch or now_epoch - last_plan_epoch >= REMOTE_PLAN_POLL_SECONDS
    fresh_due = plan is None or not last_fresh_epoch or now_epoch - last_fresh_epoch >= REMOTE_PLAN_FRESH_POLL_SECONDS
    success = last_success(previous)
    stale_duplicate = mirror_actions_already_postchecked(plan, success)
    urgent_actions = [item for item in eligible_mirror_actions(plan or {}) if not stale_duplicate]
    urgent_ids = [str(item.get("actionId") or "") for item in urgent_actions if str(item.get("actionId") or "")]
    plan_is_fresh = bool(plan and (plan.get("source") == "fresh" or plan.get("freshEnough") is True))
    urgent_due = (
        bool(urgent_ids)
        and not plan_is_fresh
        and not mirror_retry_deferred(previous, source, urgent_ids, now_epoch)
    )
    force_fresh = fresh_due or urgent_due
    return poll_due or force_fresh, force_fresh


def latest_plan_has_unvalidated_mac_request(
    plan: Optional[Dict[str, Any]],
    success: Optional[Dict[str, Any]],
    previous: Optional[Dict[str, Any]] = None,
    source: Optional[Dict[str, Any]] = None,
    now_epoch: Optional[int] = None,
) -> bool:
    if not isinstance(plan, dict) or plan.get("source") == "fresh":
        return False
    if mirror_actions_already_postchecked(plan, success):
        return False
    action_ids = [
        str(item.get("actionId") or "")
        for item in eligible_mirror_actions(plan)
        if str(item.get("actionId") or "")
    ]
    if not action_ids:
        return False
    if source is None:
        return True
    now_epoch = int(now_epoch or time.time())
    return any(
        not mirror_retry_deferred(previous, source, [action_id], now_epoch)
        for action_id in action_ids
    )


def classify_codex_failure(stderr: str) -> Tuple[str, bool]:
    value = str(stderr or "").lower()
    permanent_markers = (
        "refresh token has expired",
        "refresh token was already used",
        "refresh token was revoked",
        "refresh token was invalidated",
        "log out and sign in again",
        "please sign in again",
        "interactive login required",
    )
    if any(marker in value for marker in permanent_markers):
        return "interactive-reauth-required", True
    if "unsupported_country_region_territory" in value:
        return "proxy-or-region-blocked", False
    return "codex-cli-request-failed", False


def nudge_codex_refresh(
    source: Dict[str, Any], previous: Optional[Dict[str, Any]] = None
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    attempted_at = int(time.time())
    condition_key = refresh_condition_key(source)
    attempt_number, retry_after = next_retry_seconds(previous, condition_key)
    attempt = {
        "attemptedAt": iso_now(),
        "attemptedAtEpoch": attempted_at,
        "attemptNumber": attempt_number,
        "retryAfterSeconds": retry_after,
        "refreshConditionKey": condition_key,
        "forAccessExpiresAt": source.get("accessExpiresAt"),
        "method": "codex-cli-ephemeral-read-only-turn",
        "tokenValuesRedacted": True,
    }
    codex_env = os.environ.copy()
    for name, value in {
        "HTTP_PROXY": "http://127.0.0.1:7890",
        "HTTPS_PROXY": "http://127.0.0.1:7890",
        "ALL_PROXY": "socks5://127.0.0.1:7890",
        "http_proxy": "http://127.0.0.1:7890",
        "https_proxy": "http://127.0.0.1:7890",
        "all_proxy": "socks5://127.0.0.1:7890",
        "NO_PROXY": "127.0.0.1,localhost,::1",
        "no_proxy": "127.0.0.1,localhost,::1",
    }.items():
        codex_env[name] = value
    codex_env["CODEX_HOME"] = str(CODEX_HOME)
    try:
        proc = subprocess.run(
            [
                str(CODEX),
                "exec",
                "--model",
                MODEL,
                "--ignore-user-config",
                "--ignore-rules",
                "--disable",
                "shell_tool",
                "--disable",
                "unified_exec",
                "--disable",
                "unified_exec_tty",
                "--disable",
                "view_image",
                "--disable",
                "sleep_tool",
                "--disable",
                "apps",
                "--disable",
                "browser_use",
                "--disable",
                "browser_use_external",
                "--disable",
                "browser_use_full_cdp_access",
                "--disable",
                "computer_use",
                "--disable",
                "code_mode_host",
                "--disable",
                "image_generation",
                "--disable",
                "in_app_browser",
                "--disable",
                "in_app_local_automation",
                "--disable",
                "in_app_chat",
                "--disable",
                "plugins",
                "--disable",
                "plugin_sharing",
                "--disable",
                "remote_plugin",
                "--disable",
                "multi_agent",
                "--disable",
                "skill_search",
                "--disable",
                "skill_mcp_dependency_install",
                "--disable",
                "workspace_dependencies",
                "--disable",
                "auth_elicitation",
                "--disable",
                "tool_call_mcp_elicitation",
                "--sandbox",
                "read-only",
                "--ephemeral",
                "--skip-git-repo-check",
                "--cd",
                "/private/tmp",
                "Reply with exactly AUTH-MAINTENANCE-OK. Do not use tools, inspect files, or modify files.",
            ],
            env=codex_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=CODEX_TIMEOUT_SECONDS,
            check=False,
        )
        attempt["exitCode"] = int(proc.returncode)
    except subprocess.TimeoutExpired:
        attempt["exitCode"] = 124
        attempt["result"] = "timeout"
        return attempt, source
    except OSError as exc:
        attempt["exitCode"] = 127
        attempt["result"] = "codex-cli-unavailable"
        attempt["errorType"] = type(exc).__name__
        return attempt, source
    if attempt.get("exitCode") != 0:
        try:
            updated = inspect_source()
        except Exception:
            updated = source
        if refresh_condition_key(updated) != condition_key:
            attempt["result"] = "token-advanced-by-concurrent-local-refresh"
            attempt["manualRecoveryRequired"] = False
            attempt["newAccessExpiresAt"] = updated.get("accessExpiresAt")
            return attempt, updated
        attempt["result"], attempt["manualRecoveryRequired"] = classify_codex_failure(proc.stderr)
        return attempt, source
    try:
        updated = inspect_source()
    except Exception:
        attempt["result"] = "post-nudge-auth-inspection-failed"
        return attempt, source
    old_expiry = str(source.get("accessExpiresAt") or "")
    new_expiry = str(updated.get("accessExpiresAt") or "")
    last_refresh_advanced = bool(
        updated.get("lastRefresh")
        and str(updated.get("lastRefresh")) != str(source.get("lastRefresh"))
    )
    attempt["result"] = (
        "token-advanced"
        if (new_expiry and new_expiry != old_expiry) or last_refresh_advanced
        else "request-succeeded-token-unchanged"
    )
    attempt["newAccessExpiresAt"] = updated.get("accessExpiresAt")
    return attempt, updated


def transport_failure(stderr: str) -> bool:
    value = stderr.lower()
    return any(
        marker in value
        for marker in (
            "network is unreachable",
            "no route to host",
            "connect timed out",
            "connection timed out",
            "operation timed out",
            "connection refused",
            "connection reset",
            "broken pipe",
            "could not resolve hostname",
        )
    )


def fetch_remote_plan(
    *, force_openclaw_probe: bool = False
) -> Tuple[Dict[str, Any], str, List[Dict[str, Any]], pathlib.Path]:
    plan_file = REMOTE_PLAN_FILE
    errors: List[Dict[str, Any]] = []
    for index, server in enumerate((SERVER, FALLBACK_SERVER)):
        tmp_file = plan_file.with_suffix(plan_file.suffix + ".tmp")
        cmd = [
            str(SSH),
            "-i",
            str(SSH_KEY),
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
            REMOTE_CLI
            + " auth-maintenance --fresh --force-openclaw-probe"
            if force_openclaw_probe
            else REMOTE_CLI + " auth-maintenance",
        ]
        try:
            with tmp_file.open("w", encoding="utf-8") as out:
                proc = subprocess.run(
                    cmd,
                    stdout=out,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=SSH_TIMEOUT_SECONDS,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            tmp_file.unlink(missing_ok=True)
            errors.append({"server": server, "result": "timeout"})
            if index + 1 < 2:
                continue
            break
        if proc.returncode == 0:
            try:
                plan = load_json(tmp_file)
                if not plan:
                    raise ValueError("empty-plan")
            except Exception:
                tmp_file.unlink(missing_ok=True)
                errors.append({"server": server, "result": "invalid-plan-json"})
                break
            os.replace(tmp_file, plan_file)
            return plan, server, errors, plan_file
        tmp_file.unlink(missing_ok=True)
        transport = transport_failure(proc.stderr)
        errors.append({
            "server": server,
            "result": "ssh-transport-failed" if transport else "remote-command-failed",
            "exitCode": int(proc.returncode),
        })
        if not transport or index + 1 >= 2:
            break
    raise RuntimeError(json.dumps(errors, ensure_ascii=False))


def run_mirror(
    action_ids: List[str],
    scope: Optional[Dict[str, Any]] = None,
    operation_id: Optional[str] = None,
    protected_operation_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    command = [
        str(CLI), "auth-mirror", "--apply", "--codex-auth", str(AUTH_PATH),
        "--action-ids", ",".join(action_ids),
    ]
    if scope is not None:
        if not scope.get("codexCli"):
            command.append("--no-codex-cli")
        if scope.get("hermersProfiles"):
            command.extend(["--hermers-profiles", ",".join(scope["hermersProfiles"])])
        else:
            command.append("--no-hermers")
        if scope.get("openclawTargets"):
            encoded_targets = ",".join(
                f"{target['agentId']}:{target['profileKind']}"
                for target in scope["openclawTargets"]
            )
            command.extend(["--openclaw-targets", encoded_targets])
        else:
            command.append("--no-openclaw")
    if operation_id:
        command.extend(["--mirror-operation-id", operation_id])
    if protected_operation_ids:
        command.extend(["--protect-operation-ids", ",".join(protected_operation_ids)])
    proc = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=240,
        check=False,
    )
    try:
        value = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("mirror-command-returned-invalid-json") from exc
    if proc.returncode != 0 or value.get("result") != "applied":
        raise RuntimeError("mirror-apply-failed")
    return value


def write_attempt(
    previous: Optional[Dict[str, Any]],
    *,
    status: str,
    source: Optional[Dict[str, Any]] = None,
    plan: Optional[Dict[str, Any]] = None,
    server: Optional[str] = None,
    mirror_actions: Optional[List[Dict[str, Any]]] = None,
    mirror: Optional[Dict[str, Any]] = None,
    source_refresh_attempt: Optional[Dict[str, Any]] = None,
    remote_plan_fetched_at_epoch: Optional[int] = None,
    error: Optional[str] = None,
    transport_errors: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    success = last_success(previous)
    pending_operation_ids = set(protected_mirror_operation_ids(previous))
    last_mirror_attempt = None
    if isinstance(previous, dict) and isinstance(previous.get("lastMirrorAttempt"), dict):
        last_mirror_attempt = previous.get("lastMirrorAttempt")
        prior_operation_id = str(last_mirror_attempt.get("operationId") or "")
        if (
            last_mirror_attempt.get("result") == "applied"
            and last_mirror_attempt.get("postcheckStatus") == "ok"
            and SAFE_RUNTIME_ID.fullmatch(prior_operation_id)
        ):
            pending_operation_ids.discard(prior_operation_id)
    if source_refresh_attempt is None and isinstance(previous, dict):
        prior_attempt = previous.get("sourceRefreshAttempt")
        if isinstance(prior_attempt, dict):
            source_refresh_attempt = prior_attempt
    if remote_plan_fetched_at_epoch is None and isinstance(previous, dict):
        try:
            remote_plan_fetched_at_epoch = int(previous.get("remotePlanFetchedAtEpoch"))
        except (TypeError, ValueError):
            remote_plan_fetched_at_epoch = None
    remote_fresh_plan_fetched_at_epoch = None
    if isinstance(previous, dict):
        try:
            remote_fresh_plan_fetched_at_epoch = int(previous.get("remoteFreshPlanFetchedAtEpoch"))
        except (TypeError, ValueError):
            remote_fresh_plan_fetched_at_epoch = None
    if plan and plan.get("source") == "fresh":
        remote_fresh_plan_fetched_at_epoch = remote_plan_fetched_at_epoch or int(time.time())
    now = iso_now()
    summary: Dict[str, Any] = {
        "checkedAt": now,
        "status": status,
        "remoteServer": server,
        "remotePlanFetchedAtEpoch": remote_plan_fetched_at_epoch,
        "remoteFreshPlanFetchedAtEpoch": remote_fresh_plan_fetched_at_epoch,
        "remoteStatus": plan.get("status") if plan else None,
        "remoteSeverity": plan.get("severity") if plan else None,
        "remoteActionCount": plan.get("actionCount") if plan else None,
        "mirrorActionCount": len(mirror_actions or []),
        "mirrorActionIds": [str(x.get("actionId") or "") for x in (mirror_actions or [])],
        "sourceAccessExpiresAt": source.get("accessExpiresAt") if source else None,
        "sourceIdTokenExpiresAt": source.get("idExpiresAt") if source else None,
        "sourceAccessSecondsRemaining": source.get("accessSecondsRemaining") if source else None,
        "sourceIdTokenFresh": source.get("idTokenFresh") if source else None,
        "sourceLastRefresh": source.get("lastRefresh") if source else None,
        "sourceAuthMtimeEpoch": source.get("authMtimeEpoch") if source else None,
        "sourceRefreshAttempt": source_refresh_attempt,
        "mirrorSummary": mirror.get("summary") if mirror else None,
        "mirrorPostcheck": mirror.get("postcheck") if mirror else None,
        "lastMirrorAttempt": last_mirror_attempt,
        "error": error,
        "transportErrors": transport_errors or [],
        "tokenValuesRedacted": True,
    }
    attempted_action_ids = [str(x.get("actionId") or "") for x in (mirror_actions or []) if str(x.get("actionId") or "")]
    if mirror and mirror.get("sourceWide") is True and plan:
        attempted_action_ids = [
            str(item.get("actionId") or "")
            for item in (plan.get("actions") or [])
            if isinstance(item, dict)
            and str(item.get("actionId") or "")
            and (
                (isinstance(item.get("localAutomation"), dict) and item["localAutomation"].get("eligible") is True)
                or item.get("kind") == "deduplicate-token-copies"
            )
        ] or attempted_action_ids
    if attempted_action_ids:
        attempt_number, retry_after = next_mirror_retry_seconds(
            previous,
            refresh_condition_key(source or {}),
        )
        postcheck_status = (mirror.get("postcheck") or {}).get("status") if mirror else None
        apply_succeeded = bool(mirror and mirror.get("result") == "applied")
        attempt_result = (
            "applied" if apply_succeeded and postcheck_status == "ok"
            else "postcheck-pending" if apply_succeeded and postcheck_status == "unavailable"
            else "failed"
        )
        last_mirror_attempt = {
            "attemptedAt": now,
            "attemptedAtEpoch": int(time.time()),
            "attemptNumber": attempt_number,
            "retryAfterSeconds": retry_after,
            "refreshConditionKey": refresh_condition_key(source or {}),
            "actionIds": attempted_action_ids,
            "result": attempt_result,
            "applyResult": "applied" if apply_succeeded else "failed",
            "postcheckStatus": postcheck_status,
            "operationId": mirror.get("operationId") if mirror else None,
            "sourceWide": mirror.get("sourceWide") is True if mirror else False,
            "mirrorScope": mirror.get("mirrorScope") if mirror else None,
        }
        summary["lastMirrorAttempt"] = last_mirror_attempt
        operation_id = str(last_mirror_attempt.get("operationId") or "")
        if SAFE_RUNTIME_ID.fullmatch(operation_id):
            if attempt_result == "applied":
                pending_operation_ids.discard(operation_id)
                if last_mirror_attempt.get("sourceWide") is True:
                    pending_operation_ids.clear()
            else:
                pending_operation_ids.add(operation_id)
    summary["pendingMirrorOperationIds"] = sorted(
        item for item in pending_operation_ids if SAFE_RUNTIME_ID.fullmatch(item)
    )
    if mirror and mirror.get("result") == "applied":
        success = {
            "checkedAt": now,
            "sourceAccessExpiresAt": source.get("accessExpiresAt") if source else None,
            "sourceIdTokenExpiresAt": source.get("idExpiresAt") if source else None,
            "sourceLastRefresh": source.get("lastRefresh") if source else None,
            "sourceAuthMtimeEpoch": source.get("authMtimeEpoch") if source else None,
            "mirrorSummary": mirror.get("summary"),
            "mirrorActionIds": [str(x.get("actionId") or "") for x in (mirror_actions or [])],
            "mirrorCompletedAtEpoch": int(time.time()),
            "postcheckOk": (mirror.get("postcheck") or {}).get("status") == "ok",
            "postcheckStatus": (mirror.get("postcheck") or {}).get("status") or "not-run",
            "remotePlanGeneratedAt": plan.get("generatedAt") if plan else None,
            "remotePlanGeneratedAtEpochNs": plan.get("generatedAtEpochNs") if plan else None,
            "sourceWide": mirror.get("sourceWide") is True,
            "mirrorScope": mirror.get("mirrorScope"),
            "operationId": mirror.get("operationId"),
        }
    if success:
        summary["lastSuccessfulMirror"] = success
    write_json_atomic(LATEST_FILE, summary)
    return summary


def emit_summary(summary: Dict[str, Any], previous: Optional[Dict[str, Any]]) -> None:
    if not previous:
        print(json.dumps(summary, ensure_ascii=False))
        return
    previous_attempt = previous.get("sourceRefreshAttempt") if isinstance(previous, dict) else None
    current_attempt = summary.get("sourceRefreshAttempt")
    changed = (
        summary.get("status") != previous.get("status")
        or summary.get("mirrorActionIds") != previous.get("mirrorActionIds")
        or (current_attempt or {}).get("attemptedAt") != (previous_attempt or {}).get("attemptedAt")
        or summary.get("error") != previous.get("error")
    )
    if changed:
        print(json.dumps(summary, ensure_ascii=False))


def main() -> int:
    os.umask(0o077)
    LOG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not acquire_lock():
        return 0
    previous = load_json(LATEST_FILE)
    source_refresh_attempt: Optional[Dict[str, Any]] = None
    try:
        source = inspect_source()
        refresh_due = codex_refresh_due(source)
        if refresh_due and not source.get("refreshTokenPresent"):
            summary = write_attempt(previous, status="source-reauth-required", source=source, error="local-refresh-token-missing")
            emit_summary(summary, previous)
            return 1
        if refresh_due and not CODEX.is_file():
            summary = write_attempt(previous, status="codex-cli-unavailable", source=source, error="codex-cli-binary-missing")
            emit_summary(summary, previous)
            return 1
        if refresh_due and should_nudge_refresh(source, previous):
            source_refresh_attempt, source = observe_concurrent_local_refresh(source)
            if source_refresh_attempt is None:
                source_refresh_attempt, source = nudge_codex_refresh(source, previous)
        if codex_refresh_due(source):
            prior_refresh_attempt = source_refresh_attempt
            if prior_refresh_attempt is None and isinstance(previous, dict):
                value = previous.get("sourceRefreshAttempt")
                prior_refresh_attempt = value if isinstance(value, dict) else None
            if prior_refresh_attempt and prior_refresh_attempt.get("manualRecoveryRequired"):
                status = "source-reauth-required"
                error = "codex-cli-reported-interactive-reauth-required"
            elif source_refresh_attempt:
                status = "source-refresh-pending"
                error = "codex-cli-refresh-did-not-advance-source-token"
            else:
                status = "refresh-retry-deferred"
                error = None
            summary = write_attempt(
                previous,
                status=status,
                source=source,
                source_refresh_attempt=source_refresh_attempt,
                error=error,
            )
            emit_summary(summary, previous)
            return 1 if status in {"source-reauth-required", "source-refresh-pending"} else 0
        success = last_success(previous)
        changed = source_changed(source, success)
        now_epoch = int(time.time())
        plan = load_json(REMOTE_PLAN_FILE)
        server = str(previous.get("remoteServer") or "") if isinstance(previous, dict) else ""
        try:
            last_plan_epoch = int(previous.get("remotePlanFetchedAtEpoch") or 0) if isinstance(previous, dict) else 0
        except (TypeError, ValueError):
            last_plan_epoch = 0
        same_source_generation = bool(
            isinstance(previous, dict)
            and previous.get("sourceAccessExpiresAt") == source.get("accessExpiresAt")
            and previous.get("sourceLastRefresh") == source.get("lastRefresh")
        )
        pending_success = last_success(previous)
        pending_postcheck = bool(
            pending_success and pending_success.get("postcheckOk") is False
        )
        postcheck_query_retry = bool(
            pending_postcheck and pending_success.get("postcheckStatus") == "unavailable"
        )
        cached_gate_block = bool(
            changed
            and same_source_generation
            and isinstance(previous, dict)
            and previous.get("status") == "source-sync-blocked-by-plan-gate"
            and last_plan_epoch
            and now_epoch - last_plan_epoch < REMOTE_PLAN_POLL_SECONDS
        )
        source_sync_retry_deferred = changed and mirror_retry_deferred(previous, source, now_epoch=now_epoch)
        refresh_advanced = bool(source_refresh_attempt and source_refresh_attempt.get("result") == "token-advanced")
        fetch_plan, force_openclaw_probe = remote_plan_fetch_policy(
            previous,
            plan,
            source,
            now_epoch=now_epoch,
        )
        force_openclaw_probe = bool(
            force_openclaw_probe
            or (changed and not cached_gate_block and not source_sync_retry_deferred)
            or refresh_advanced
            or postcheck_query_retry
        )
        fetch_plan = bool(
            fetch_plan
            or force_openclaw_probe
            or (changed and not cached_gate_block and not source_sync_retry_deferred)
            or refresh_advanced
            or postcheck_query_retry
        )
        transport_errors: List[Dict[str, Any]] = []
        plan_fetched_at_epoch = last_plan_epoch or None
        if fetch_plan:
            try:
                plan, server, transport_errors, _plan_file = fetch_remote_plan(
                    force_openclaw_probe=force_openclaw_probe
                )
                plan_fetched_at_epoch = int(time.time())
            except Exception as exc:
                summary = write_attempt(
                    previous,
                    status="remote-unreachable",
                    source=source,
                    source_refresh_attempt=source_refresh_attempt,
                    error="remote-plan-unavailable",
                    transport_errors=json.loads(str(exc)) if str(exc).startswith("[") else [],
                )
                emit_summary(summary, previous)
                return 1
        if (
            fetch_plan
            and not force_openclaw_probe
            and latest_plan_has_unvalidated_mac_request(
                plan,
                pending_success,
                previous,
                source,
                now_epoch,
            )
        ):
            try:
                plan, server, request_errors, _plan_file = fetch_remote_plan(
                    force_openclaw_probe=True
                )
                transport_errors.extend(request_errors)
                plan_fetched_at_epoch = int(time.time())
            except Exception as exc:
                summary = write_attempt(
                    previous,
                    status="remote-unreachable",
                    source=source,
                    plan=plan,
                    server=server,
                    source_refresh_attempt=source_refresh_attempt,
                    remote_plan_fetched_at_epoch=plan_fetched_at_epoch,
                    error="fresh-auth-request-plan-unavailable",
                    transport_errors=transport_errors + (
                        json.loads(str(exc)) if str(exc).startswith("[") else []
                    ),
                )
                emit_summary(summary, previous)
                return 1
        if not isinstance(plan, dict):
            raise RuntimeError("remote-plan-cache-invalid")
        pending_sourcewide_retry_scope: Optional[Dict[str, Any]] = None
        pending_unresolved_ids: List[str] = []
        if pending_postcheck and pending_success:
            pending_sourcewide_retry_scope = pending_success.get("mirrorScope")
            pending_unresolved_ids = unresolved_saved_mirror_action_ids(plan, pending_success)
            previous = dict(previous or {})
            saved_success = dict(pending_success)
            postcheck_block = mirror_postcheck_block_reason(pending_unresolved_ids)
            if postcheck_block:
                saved_success["postcheckStatus"] = "blocked"
                previous["lastSuccessfulMirror"] = saved_success
                previous_attempt = previous.get("lastMirrorAttempt")
                if isinstance(previous_attempt, dict):
                    previous["lastMirrorAttempt"] = {
                        **previous_attempt,
                        "result": "blocked",
                        "actionIds": pending_unresolved_ids,
                        "postcheckStatus": "blocked",
                        "applyResult": "applied",
                    }
                summary = write_attempt(
                    previous,
                    status="postcheck-blocked",
                    source=source,
                    plan=plan,
                    server=server,
                    source_refresh_attempt=source_refresh_attempt,
                    remote_plan_fetched_at_epoch=plan_fetched_at_epoch,
                    error="postcheck-requires-human-gate-or-invalid-plan",
                    transport_errors=transport_errors,
                )
                emit_summary(summary, previous)
                return 1
            if not pending_unresolved_ids:
                saved_success["postcheckOk"] = True
                saved_success["postcheckStatus"] = "ok"
                previous["lastSuccessfulMirror"] = saved_success
                mark_last_mirror_postcheck_resolved(previous)
                summary = write_attempt(
                    previous,
                    status="postcheck-recovered",
                    source=source,
                    plan=plan,
                    server=server,
                    source_refresh_attempt=source_refresh_attempt,
                    remote_plan_fetched_at_epoch=plan_fetched_at_epoch,
                    transport_errors=transport_errors,
                )
                emit_summary(summary, previous)
                return 0
            saved_success["postcheckStatus"] = "unresolved-actions"
            previous["lastSuccessfulMirror"] = saved_success
            previous_attempt = previous.get("lastMirrorAttempt")
            if isinstance(previous_attempt, dict) and previous_attempt.get("result") == "postcheck-pending":
                previous["lastMirrorAttempt"] = {
                    **previous_attempt,
                    "result": "failed",
                    "actionIds": pending_unresolved_ids,
                    "postcheckStatus": "unresolved-actions",
                    "applyResult": "applied",
                }
        source_sync_retry_deferred = changed and mirror_retry_deferred(previous, source, now_epoch=now_epoch)
        if source_sync_retry_deferred:
            summary = write_attempt(
                previous,
                status="source-sync-retry-deferred",
                source=source,
                plan=plan,
                server=server,
                source_refresh_attempt=source_refresh_attempt,
                remote_plan_fetched_at_epoch=plan_fetched_at_epoch,
            )
            emit_summary(summary, previous)
            return 0
        selected = eligible_mirror_actions(plan)
        plan_mirror_retry_deferred = False
        if changed:
            if plan_has_human_gate(plan):
                summary = write_attempt(
                    previous,
                    status="source-sync-blocked-by-plan-gate",
                    source=source,
                    plan=plan,
                    server=server,
                    source_refresh_attempt=source_refresh_attempt,
                    remote_plan_fetched_at_epoch=plan_fetched_at_epoch,
                    error="plan-contains-human-gate-or-is-invalid",
                    transport_errors=transport_errors,
                )
                emit_summary(summary, previous)
                return 1
            selected = [{
                "actionId": "mac_codex_source_generation_advanced",
                "kind": "mirror-from-mac-codex",
                "target": "all-configured-mirror-targets",
                "humanGateRequired": False,
                "localAutomation": {"eligible": True, "owner": "mac-codex", "mode": "access-id-token-mirror"},
                "localSourceChange": True,
            }]
            mirror_scope = mirror_scope_for_plan_targets(plan)
        else:
            success = last_success(previous)
            if success and success.get("postcheckOk") is True and source.get("accessExpiresAt") == success.get("sourceAccessExpiresAt") and source.get("lastRefresh") == success.get("sourceLastRefresh"):
                selected = filter_postchecked_mirror_actions(
                    selected,
                    plan,
                    success,
                    now_epoch=now_epoch,
                )
            if selected:
                selected_ids = [str(item.get("actionId") or "") for item in selected]
                if mirror_retry_deferred(previous, source, selected_ids, now_epoch):
                    prior_mirror = previous.get("lastMirrorAttempt") if isinstance(previous, dict) else {}
                    deferred_ids = {str(item) for item in (prior_mirror or {}).get("actionIds") or [] if str(item)}
                    filtered = [item for item in selected if str(item.get("actionId") or "") not in deferred_ids]
                    plan_mirror_retry_deferred = len(filtered) != len(selected)
                    selected = filtered
            if selected:
                mirror_scope = mirror_scope_for_actions(selected)
            else:
                mirror_scope = {}
            if (
                not selected
                and pending_sourcewide_retry_scope
                and any(item.endswith("token_copy_drift_cleanup") for item in pending_unresolved_ids)
                and not mirror_retry_deferred(previous, source, pending_unresolved_ids, now_epoch)
            ):
                selected = [{
                    "actionId": "mac_codex_source_generation_advanced",
                    "kind": "mirror-from-mac-codex",
                    "target": "all-configured-mirror-targets",
                    "humanGateRequired": False,
                    "localAutomation": {"eligible": True, "owner": "mac-codex", "mode": "access-id-token-mirror"},
                    "localSourceChange": True,
                }]
                mirror_scope = normalize_mirror_scope(pending_sourcewide_retry_scope, require_target=True)
        if not selected:
            prior_attempt = source_refresh_attempt
            if prior_attempt is None and isinstance(previous, dict):
                value = previous.get("sourceRefreshAttempt")
                prior_attempt = value if isinstance(value, dict) else None
            if codex_refresh_due(source):
                if not source.get("refreshTokenPresent") or (prior_attempt and prior_attempt.get("manualRecoveryRequired")):
                    status = "source-reauth-required"
                elif source_refresh_attempt and source_refresh_attempt.get("result") != "token-advanced":
                    status = "source-refresh-pending"
                else:
                    status = "refresh-retry-deferred"
            else:
                status = "mirror-retry-deferred" if plan_mirror_retry_deferred else "healthy"
            summary = write_attempt(
                previous,
                status=status,
                source=source,
                plan=plan,
                server=server,
                source_refresh_attempt=source_refresh_attempt,
                remote_plan_fetched_at_epoch=plan_fetched_at_epoch,
                transport_errors=transport_errors,
            )
            emit_summary(summary, previous)
            return 1 if status in {"source-reauth-required", "source-refresh-pending"} else 0
        action_ids = [str(x.get("actionId") or "") for x in selected if str(x.get("actionId") or "")]
        source_wide = any(bool(item.get("localSourceChange")) for item in selected)
        operation_id = mirror_operation_id_for_attempt(
            previous, source, action_ids, mirror_scope, source_wide
        )
        mirror_result: Optional[Dict[str, Any]] = {
            "operationId": operation_id,
            "sourceWide": source_wide,
            "mirrorScope": mirror_scope,
        }
        try:
            if int(source.get("accessSecondsRemaining") or 0) < MIRROR_MIN_TTL_SECONDS:
                raise RuntimeError("source-access-token-below-mirror-min-ttl")
            applied_result = run_mirror(
                action_ids,
                mirror_scope,
                operation_id,
                protected_mirror_operation_ids(previous),
            )
            applied_result.update(mirror_result)
            mirror_result = applied_result
            mirror_result["sourceWide"] = source_wide
            mirror_result["mirrorScope"] = mirror_scope
            try:
                post_plan, post_server, post_errors, _post_plan_file = fetch_remote_plan(
                    force_openclaw_probe=True
                )
            except Exception as exc:
                mirror_result["postcheck"] = {"status": "unavailable"}
                raise RuntimeError("mirror-postcheck-unavailable") from exc
            unresolved_ids = unresolved_mirror_action_ids(
                post_plan,
                selected,
                source_wide=source_wide,
                scope=mirror_scope if source_wide else None,
            )
            plan = post_plan
            server = post_server
            transport_errors.extend(post_errors)
            plan_fetched_at_epoch = int(time.time())
            mirror_result["postcheck"] = {
                "status": "ok" if not unresolved_ids else "unresolved-actions",
                "checkedAt": iso_now(),
                "remotePlanGeneratedAt": post_plan.get("generatedAt"),
                "unresolvedActionIds": unresolved_ids,
                "tokenValuesRedacted": True,
            }
            if unresolved_ids:
                raise RuntimeError("mirror-postcheck-unresolved-auth-actions")
        except Exception as exc:
            summary = write_attempt(
                previous,
                status="mirror-failed",
                source=source,
                plan=plan,
                server=server,
                mirror_actions=selected,
                mirror=mirror_result,
                source_refresh_attempt=source_refresh_attempt,
                remote_plan_fetched_at_epoch=plan_fetched_at_epoch,
                error=str(exc),
                transport_errors=transport_errors,
            )
            emit_summary(summary, previous)
            return 1
        summary = write_attempt(
            previous,
            status="applied",
            source=source,
            plan=plan,
            server=server,
            mirror_actions=selected,
            mirror=mirror_result,
            source_refresh_attempt=source_refresh_attempt,
            remote_plan_fetched_at_epoch=plan_fetched_at_epoch,
            transport_errors=transport_errors,
        )
        emit_summary(summary, previous)
        return 0
    except Exception as exc:
        summary = write_attempt(
            previous,
            status="local-auth-or-refresh-error",
            source_refresh_attempt=source_refresh_attempt,
            error=type(exc).__name__,
        )
        emit_summary(summary, previous)
        return 1
    finally:
        release_lock()


if __name__ == "__main__":
    raise SystemExit(main())
