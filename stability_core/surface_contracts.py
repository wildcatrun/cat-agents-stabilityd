"""Offline metadata contracts for cross-runtime service surfaces.

The module accepts only small allowlisted readiness facts; it cannot read
credentials, issue model calls, inspect trading records, or mutate runtimes.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import math
from typing import Any, Mapping


SURFACE_CONTRACTS: dict[str, dict[str, Any]] = {
    "openclaw-runtime": {
        "owner": "openclaw-gateway",
        "accessClass": "development-readonly-metadata",
        "allowedFields": {"gatewayReady": "bool", "pluginRegistryReady": "bool"},
        "dependencies": ["dev-server", "system-clock", "tailscale"],
        "fixtureOnly": False,
    },
    "hermes-runtime": {
        "owner": "hermes-runtime-adapter",
        "accessClass": "development-readonly-metadata",
        "allowedFields": {"acpReady": "bool", "profileRegistryComplete": "bool"},
        "dependencies": ["dev-server", "runtime_agents", "system-clock"],
        "fixtureOnly": False,
    },
    "local-codex": {
        "owner": "mac-codex",
        "accessClass": "local-redacted-metadata",
        "allowedFields": {"codexAppRunning": "bool", "cliReady": "bool", "mirrorReady": "bool",
                           "refreshOwner": "owner", "tokenStatus": "token-status"},
        "dependencies": ["mac-codex", "sparkle-proxy", "tailscale"],
        "fixtureOnly": False,
    },
    "im-delivery": {
        "owner": "openclaw-gateway-message-flow",
        "accessClass": "governed-receipt-metadata-only",
        "allowedFields": {"gatewayConnected": "bool", "messageFlowReady": "bool", "receiptStatus": "receipt-status",
                           },
        "dependencies": ["openclaw-runtime", "trading-agents-workflow", "telegram-or-wecom"],
        "fixtureOnly": False,
    },
    "data-plane": {
        "owner": "suihuo-data-api",
        "accessClass": "health-and-freshness-metadata-only",
        "allowedFields": {"apiReady": "bool", "mcpReady": "bool", "datasetFresh": "bool",
                           "writerAvailable": "bool"},
        "dependencies": ["wsl-datalab", "postgresql", "windows-host-forwarding", "system-clock"],
        "fixtureOnly": False,
    },
    "trading-core": {
        "owner": "trading-core",
        "accessClass": "prohibited-in-g1-offline-contract-only",
        "allowedFields": {},
        "dependencies": [],
        "fixtureOnly": True,
    },
}

_BOOL = {"bool"}
_TOKEN_STATUS = {"healthy", "expiring", "expired", "missing", "unknown"}
_RECEIPT_STATUS = {"fresh", "stale", "missing", "unknown", "failed"}
_OWNER = {"mac-codex"}
_TIMEZONES = {"UTC", "Etc/UTC", "Asia/Shanghai", "America/Los_Angeles"}
_SOURCE_KINDS = {"synthetic-fixture"}


def _epoch(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.timestamp() if parsed.tzinfo is not None else None


def _valid_field(field_type: str, value: Any) -> bool:
    if field_type in _BOOL:
        return type(value) is bool
    if field_type == "token-status":
        return isinstance(value, str) and value in _TOKEN_STATUS
    if field_type == "receipt-status":
        return isinstance(value, str) and value in _RECEIPT_STATUS
    if field_type == "owner":
        return isinstance(value, str) and value in _OWNER
    if field_type == "digest":
        return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())
    return False


def evaluate_surface_observations(
    observations: list[Mapping[str, Any]], *, now_epoch: float, max_age_seconds: int = 300,
) -> dict[str, Any]:
    """Normalize allowlisted readiness metadata and omit every unknown field."""
    if isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float)) or not math.isfinite(now_epoch):
        raise ValueError("now_epoch must be a finite number")
    if type(max_age_seconds) is not int or max_age_seconds < 0:
        raise ValueError("max_age_seconds must be a non-negative integer")
    invalid_input_list = not isinstance(observations, list)
    if invalid_input_list:
        observations = []
    by_surface: dict[str, Mapping[str, Any]] = {}
    rejected: list[str] = ["observation-list-invalid"] if invalid_input_list else []
    duplicates: set[str] = set()
    for observation in observations:
        if not isinstance(observation, Mapping):
            rejected.append("observation-not-object")
            continue
        surface_id = observation.get("surfaceId")
        contract = SURFACE_CONTRACTS.get(surface_id) if isinstance(surface_id, str) else None
        if contract is None:
            rejected.append("unknown-surface-id")
            continue
        if contract["fixtureOnly"]:
            rejected.append("surface-out-of-g1-scope")
            continue
        if surface_id in by_surface:
            duplicates.add(surface_id)
            continue
        by_surface[surface_id] = observation

    results = []
    for surface_id, contract in SURFACE_CONTRACTS.items():
        result: dict[str, Any] = {
            "surfaceId": surface_id,
            "owner": contract["owner"],
            "accessClass": contract["accessClass"],
            "dependencies": list(contract["dependencies"]),
            "state": "unknown",
            "reason": "not-observed" if not contract["fixtureOnly"] else "production-trading-access-excluded",
            "fixtureOnly": contract["fixtureOnly"],
            "fields": {},
        }
        observation = by_surface.get(surface_id)
        if contract["fixtureOnly"]:
            result["state"] = "blocked"
        elif surface_id in duplicates:
            result["reason"] = "duplicate-observation"
        elif observation is not None:
            observed_at = _epoch(observation.get("observedAt"))
            received_at = _epoch(observation.get("receivedAt"))
            source_kind = observation.get("sourceKind")
            timezone = observation.get("timezone")
            generation = observation.get("generation")
            if (
                observed_at is None or received_at is None
                or not isinstance(source_kind, str) or source_kind not in _SOURCE_KINDS
                or not isinstance(timezone, str) or timezone not in _TIMEZONES
                or not isinstance(generation, str) or not generation.strip()
            ):
                result["reason"] = "malformed-or-unbound-observation"
            elif observed_at > now_epoch + 30 or received_at > now_epoch + 30:
                result["reason"] = "clock-skew-future"
            elif now_epoch - observed_at > max_age_seconds or now_epoch - received_at > max_age_seconds:
                result["state"], result["reason"] = "unknown", "stale-observation"
            else:
                raw_fields = observation.get("fields")
                raw_fields = raw_fields if isinstance(raw_fields, Mapping) else {}
                fields = {
                    field_name: value
                    for field_name, field_type in contract["allowedFields"].items()
                    if (value := raw_fields.get(field_name)) is not None and _valid_field(field_type, value)
                }
                required = set(contract["allowedFields"])
                complete = required.issubset(fields)
                result.update(
                    state="fixture" if complete else "degraded",
                    reason="synthetic-fixture" if complete else "partial-coverage",
                    fields=fields,
                    observedAt=observation.get("observedAt"),
                    receivedAt=observation.get("receivedAt"),
                    timezone=timezone,
                    sourceKind=source_kind,
                    generationDigest=hashlib.sha256(generation.encode("utf-8")).hexdigest(),
                    ageSeconds=max(0, int(now_epoch - observed_at)),
                )
        results.append(result)
    return {
        "schemaVersion": 1,
        "source": "stabilityd-surface-contracts",
        "capturedAtEpoch": int(now_epoch),
        "surfaces": results,
        "coverage": {
            "expected": sum(1 for contract in SURFACE_CONTRACTS.values() if not contract["fixtureOnly"]),
            "observed": sum(1 for result in results if result["state"] == "observed"),
            "degraded": sum(1 for result in results if result["state"] == "degraded"),
            "fixtures": sum(1 for result in results if result["state"] == "fixture"),
            "unknown": sum(1 for result in results if result["state"] == "unknown"),
            "prohibited": sum(1 for result in results if result["state"] == "blocked"),
            "rejectedObservationCount": len(rejected),
            "rejectionCodes": sorted(set(rejected)),
        },
    }
