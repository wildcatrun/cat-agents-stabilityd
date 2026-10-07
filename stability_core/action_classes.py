"""Explicit, read-only visualization of stabilityd command and actuator classes."""

from __future__ import annotations

from typing import Any, Iterable


ACTUATOR_CLASSES: dict[str, dict[str, Any]] = {
    "cron.expired_lease.repair": {
        "class": "mutate", "authorization": "existing-policy-and-live-owner-fences",
        "humanGate": "policy-defined", "dryRun": "observation-only-no-simulated-effect",
        "effectBoundary": "owned-cron-lease-run-audit-and-repair-queue",
    },
    "cron.stale_running_state.repair": {
        "class": "mutate", "authorization": "blocked-without-openclaw-native-writer-coordination",
        "humanGate": "recovery-escalation-required", "dryRun": "observation-only-no-simulated-effect",
        "effectBoundary": "legacy-openclaw-cron-job-state",
    },
    "openclaw.session.reset": {
        "class": "mutate", "authorization": "existing-policy-registry-and-session-fences",
        "humanGate": "policy-defined", "dryRun": "observation-only-no-simulated-effect",
        "effectBoundary": "openclaw-gateway-sessions-reset-rpc",
    },
    "hermes.process.orphan_reap": {
        "class": "mutate", "authorization": "existing-policy-owner-and-process-identity-fences",
        "humanGate": "policy-defined", "dryRun": "observation-only-no-simulated-effect",
        "effectBoundary": "registry-owned-hermes-acp-process-signal",
    },
    "hermes.process.idle_lsp_reap": {
        "class": "mutate", "authorization": "existing-policy-owner-and-process-identity-fences",
        "humanGate": "policy-defined", "dryRun": "observation-only-no-simulated-effect",
        "effectBoundary": "registry-owned-hermes-lsp-process-signal",
    },
    "hermes.profile.lifecycle": {
        "class": "mutate", "authorization": "existing-policy-registry-and-profile-fences",
        "humanGate": "policy-defined", "dryRun": "observation-only-no-simulated-effect",
        "effectBoundary": "hermes-profile-gateway-start-stop",
    },
    "hermes.gateway.restart": {
        "class": "mutate", "authorization": "existing-policy-and-protected-impact-fences",
        "humanGate": "policy-defined", "dryRun": "observation-only-no-simulated-effect",
        "effectBoundary": "hermes-gateway-restart",
    },
    "openclaw.gateway.restart": {
        "class": "mutate", "authorization": "existing-policy-and-protected-impact-fences",
        "humanGate": "policy-defined", "dryRun": "observation-only-no-simulated-effect",
        "effectBoundary": "openclaw-gateway-restart",
    },
}

COMMAND_CLASSES: dict[str, dict[str, Any]] = {
    "status": {"class": "read", "authorization": "none", "effectBoundary": "published-generation"},
    "snapshot": {"class": "read", "authorization": "none", "effectBoundary": "published-generation"},
    "policy": {"class": "read", "authorization": "none", "effectBoundary": "published-policy"},
    "lanes": {"class": "read", "authorization": "none", "effectBoundary": "published-lane-policy"},
    "nodes": {"class": "read", "authorization": "none", "effectBoundary": "offline-node-observations"},
    "surfaces": {"class": "read", "authorization": "none", "effectBoundary": "offline-surface-observations"},
    "findings": {"class": "read", "authorization": "none", "effectBoundary": "published-findings"},
    "profile-modes": {"class": "read", "authorization": "none", "effectBoundary": "published-hermes-profile-evidence"},
    "desired-state": {"class": "read", "authorization": "none", "effectBoundary": "desired-state-document"},
    "drift": {"class": "read", "authorization": "none", "effectBoundary": "read-only-drift-observations"},
    "auth-readiness": {"class": "read", "authorization": "none", "effectBoundary": "redacted-auth-readiness-metadata"},
    "actions": {"class": "read", "authorization": "none", "effectBoundary": "legacy-action-event-log"},
    "events": {"class": "read", "authorization": "none", "effectBoundary": "event-log"},
    "recovery": {"class": "read", "authorization": "none", "effectBoundary": "action-ledger-read-only"},
    "runbook": {"class": "read", "authorization": "none", "effectBoundary": "published-policy-and-runbook-guidance"},
    "preflight": {"class": "read", "authorization": "none", "effectBoundary": "published-evidence-only"},
    "action-classes": {"class": "read", "authorization": "none", "effectBoundary": "static-allowlist"},
    "workflow-evidence": {"class": "evidence", "authorization": "artifact-write-only", "effectBoundary": "governed-workflow-evidence-artifact"},
    "once": {"class": "mutate", "authorization": "runtime-policy-gated", "dryRunFlag": "--no-action", "effectBoundary": "existing-stabilityd-actuators"},
    "doctor": {"class": "mutate", "authorization": "runtime-policy-gated", "dryRunFlag": "--no-action", "effectBoundary": "existing-stabilityd-actuators"},
    "repair": {"class": "mutate", "authorization": "runtime-policy-gated", "dryRunFlag": "--dry-run", "effectBoundary": "existing-stabilityd-actuators"},
    "auth-maintenance": {"class": "mutate", "authorization": "explicit-execute-and-policy-gated", "dryRunFlag": "--dry-run", "effectBoundary": "redacted-auth-maintenance-actions"},
    "auth-mirror": {"class": "mutate", "authorization": "separate-human-gate-and-mac-owner", "dryRunFlag": "default", "effectBoundary": "mac-codex-token-mirror"},
    "daemon": {"class": "mutate", "authorization": "service-manager-and-local-policy", "effectBoundary": "long-running-stabilityd-loop"},
}


def _entry(name: str, mapping: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rule = mapping.get(name)
    if rule is None:
        return {"name": name, "class": "unknown/prohibited", "authorization": "denied", "effectBoundary": "unknown"}
    return {"name": name, **rule}


def classify_action_types(action_types: Iterable[str] | None = None) -> dict[str, Any]:
    names = sorted(set(ACTUATOR_CLASSES) if action_types is None else {
        str(item) for item in action_types if isinstance(item, str) and item.strip()
    })
    entries = [_entry(name, ACTUATOR_CLASSES) for name in names]
    return {"schemaVersion": 1, "actuators": entries,
            "unknownTypes": [item["name"] for item in entries if item["class"] == "unknown/prohibited"]}


def classify_commands(command_names: Iterable[str] | None = None) -> dict[str, Any]:
    names = sorted(COMMAND_CLASSES if command_names is None else {
        str(item) for item in command_names if isinstance(item, str) and item.strip()
    })
    entries = [_entry(name, COMMAND_CLASSES) for name in names]
    return {"schemaVersion": 1, "commands": entries,
            "unknownCommands": [item["name"] for item in entries if item["class"] == "unknown/prohibited"]}
