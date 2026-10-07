"""Offline-first multi-node inventory and observation freshness contracts.

This module deliberately has no SSH, socket, subprocess, service-control, or
credential capability. Runtime-specific collectors may supply bounded,
read-only observations later; production/trading entries stay fixture-only.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import math
from typing import Any, Iterable, Mapping


@dataclasses.dataclass(frozen=True)
class NodeDescriptor:
    node_id: str
    platform: str
    environment: str
    role: str
    surface: str
    parent_node: str | None
    owner_ref: str
    access_class: str
    expected_services: tuple[str, ...]
    fixture_only: bool
    network_dependencies: tuple[str, ...]
    time_dependency: str


NODES = (
    NodeDescriptor("dev-server", "linux", "development", "openclaw-hermes-runtime", "tailnet", None,
                   "stabilityd-ops", "existing-governed-readonly", ("openclaw-gateway", "hermes", "codex-cli", "workflow-plugin"), False,
                   ("tailscale", "ssh"), "ntp/system-clock"),
    NodeDescriptor("mac-codex", "macos", "local", "codex-oauth-owner-control-plane", "tailnet", None,
                   "local-codex-owner", "local-readonly-metadata", ("codex-app", "codex-cli", "oauth-mirror-readiness"), False,
                   ("tailscale", "sparkle-proxy"), "macos-system-clock"),
    NodeDescriptor("local-workstation", "windows", "local", "windows-host-and-wsl-parent", "tailnet", None,
                   "windows-host-owner", "host-readonly-metadata", ("tailscale-host", "wsl-supervisor", "port-forwarding"), False,
                   ("tailscale-host-service", "lan"), "windows-system-clock"),
    NodeDescriptor("wsl-agents", "linux-wsl", "local", "agent-workspace", "host-managed", "local-workstation",
                   "windows-host-owner", "host-managed-readonly-metadata", ("wsl-agents-distro", "agent-workspace"), False,
                   ("windows-host", "wsl-supervisor"), "wsl-system-clock"),
    NodeDescriptor("wsl-models", "linux-wsl", "local", "model-workers", "host-managed", "local-workstation",
                   "windows-host-owner", "host-managed-readonly-metadata", ("wsl-models-distro", "model-worker"), False,
                   ("windows-host", "wsl-supervisor"), "wsl-system-clock"),
    NodeDescriptor("wsl-datalab", "linux-wsl", "local", "data-lab", "host-managed", "local-workstation",
                   "windows-host-owner", "host-managed-readonly-metadata", ("wsl-datalab-distro", "suihuo-data-api"), False,
                   ("windows-host", "wsl-supervisor", "host-port-forward"), "wsl-system-clock"),
    NodeDescriptor("prod-server", "linux", "production", "trading-sim-production", "tailnet", None,
                   "production-owner", "prohibited-in-g1", ("trading-sim",), True,
                   (), "ntp/system-clock"),
    NodeDescriptor("prod-site", "https", "production", "trading-sim-site", "external", "prod-server",
                   "production-owner", "prohibited-in-g1", ("www.tradingsim.net",), True, (), "https-date-header"),
)
_NODE_BY_ID = {node.node_id: node for node in NODES}
_STATES = frozenset({"ready", "degraded", "unreachable"})
_SOURCE_KINDS = frozenset({"synthetic-fixture"})
_TIMEZONES = frozenset({"UTC", "Etc/UTC", "Asia/Shanghai", "America/Los_Angeles"})
_REASON_CODES = frozenset({"observed", "network-unreachable", "dependency-missing", "partial-coverage"})


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
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def evaluate_inventory(
    observations: Iterable[Mapping[str, Any]], *, now_epoch: float,
    max_age_seconds: int = 300, max_future_skew_seconds: int = 30,
    max_clock_skew_seconds: int = 300,
) -> dict[str, Any]:
    """Join explicit observations to the fixed inventory; missing stays unknown."""
    seen: dict[str, Mapping[str, Any]] = {}
    duplicate_ids: set[str] = set()
    rejected: list[str] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            rejected.append("observation-not-object")
            continue
        node_id = observation.get("nodeId")
        descriptor = _NODE_BY_ID.get(node_id) if isinstance(node_id, str) else None
        if descriptor is None:
            rejected.append("unknown-node-id")
            continue
        if descriptor.fixture_only:
            rejected.append("production-observation-out-of-scope")
            continue
        if node_id in seen:
            duplicate_ids.add(node_id)
            continue
        seen[node_id] = observation

    results = []
    for descriptor in NODES:
        observation = seen.get(descriptor.node_id)
        result: dict[str, Any] = {
            "nodeId": descriptor.node_id,
            "platform": descriptor.platform,
            "environment": descriptor.environment,
            "role": descriptor.role,
            "surface": descriptor.surface,
            "parentNode": descriptor.parent_node,
            "ownerRef": descriptor.owner_ref,
            "accessClass": descriptor.access_class,
            "expectedServices": list(descriptor.expected_services),
            "services": [
                {"serviceId": service_id, "state": "unknown", "reason": "not-observed"}
                for service_id in descriptor.expected_services
            ],
            "networkDependencies": list(descriptor.network_dependencies),
            "timeDependency": descriptor.time_dependency,
            "state": "unknown",
            "reason": "not-observed",
            "coverageStatus": "missing",
        }
        if descriptor.fixture_only:
            result.update(
                state="unknown", reason="production-access-excluded", coverageStatus="prohibited",
                services=[{"serviceId": service_id, "state": "unknown", "reason": "prohibited-in-g1"}
                          for service_id in descriptor.expected_services],
            )
        elif descriptor.node_id in duplicate_ids:
            result.update(state="unknown", reason="duplicate-observation", coverageStatus="invalid")
        elif observation is not None:
            observed_at = _epoch(observation.get("observedAt"))
            received_at = _epoch(observation.get("receivedAt"))
            generation = observation.get("generation")
            state = observation.get("state")
            source_kind = observation.get("sourceKind")
            timezone = observation.get("timezone")
            raw_reason = observation.get("reasonCode")
            has_reason = "reasonCode" in observation
            if (
                observed_at is None or received_at is None
                or not isinstance(source_kind, str) or source_kind not in _SOURCE_KINDS
                or not isinstance(timezone, str) or timezone not in _TIMEZONES
                or not isinstance(generation, str) or not generation.strip()
                or has_reason and (
                    not isinstance(raw_reason, str) or raw_reason not in _REASON_CODES
                )
            ):
                result.update(reason="malformed-or-unbound-observation", coverageStatus="invalid")
            elif observed_at > now_epoch + max_future_skew_seconds or received_at > now_epoch + max_future_skew_seconds:
                result.update(reason="clock-skew-future", coverageStatus="invalid")
            elif now_epoch - observed_at > max_age_seconds or now_epoch - received_at > max_age_seconds:
                result.update(reason="stale-observation", coverageStatus="stale")
            elif abs(received_at - observed_at) > max_clock_skew_seconds:
                result.update(reason="clock-skew-mismatch", coverageStatus="invalid")
            elif not isinstance(state, str) or state not in _STATES:
                result.update(reason="unknown-observation-state", coverageStatus="invalid")
            else:
                reason_code = raw_reason if has_reason else "observed"
                raw_services = observation.get("services")
                raw_services = raw_services if isinstance(raw_services, Mapping) else {}
                service_results = []
                for service_id in descriptor.expected_services:
                    service_state = raw_services.get(service_id)
                    if state == "unreachable":
                        service_results.append({"serviceId": service_id, "state": "fixture", "reportedState": "unreachable", "reason": "synthetic-fixture"})
                    elif not isinstance(service_state, str) or service_state not in _STATES:
                        service_results.append({"serviceId": service_id, "state": "unknown", "reason": "not-observed"})
                    else:
                        service_results.append({"serviceId": service_id, "state": "fixture", "reportedState": service_state,
                                               "reason": "synthetic-fixture"})
                service_coverage_complete = all(
                    item.get("state") == "fixture" and item.get("reportedState") in _STATES
                    for item in service_results
                )
                service_ready = service_coverage_complete and all(
                    item.get("reportedState") == "ready" for item in service_results
                )
                effective_state = state
                effective_reason = reason_code
                if state == "ready" and not service_ready:
                    effective_reason = "partial-fixture-coverage"
                result.update(
                    state="fixture",
                    reportedState=effective_state,
                    reason="synthetic-fixture" if effective_reason == "observed" else effective_reason,
                    generationDigest=hashlib.sha256(generation.encode("utf-8")).hexdigest(),
                    observedAt=observation.get("observedAt"),
                    receivedAt=observation.get("receivedAt"),
                    timezone=timezone,
                    sourceKind=source_kind,
                    services=service_results,
                    serviceCoverageComplete=service_coverage_complete,
                    ageSeconds=max(0, int(now_epoch - observed_at)),
                    clockSkewSeconds=int(received_at - observed_at),
                    coverage=True,
                    coverageStatus="fixture",
                )
        results.append(result)
    return {
        "schemaVersion": 1,
        "source": "stabilityd-node-inventory",
        "capturedAtEpoch": int(now_epoch),
        "nodes": results,
        "coverage": {
            "expected": len(NODES),
            "observed": sum(1 for item in results if item.get("coverageStatus") == "observed"),
            "missing": sum(1 for item in results if item.get("coverageStatus") == "missing"),
            "stale": sum(1 for item in results if item.get("coverageStatus") == "stale"),
            "invalid": sum(1 for item in results if item.get("coverageStatus") == "invalid"),
            "fixtures": sum(1 for item in results if item.get("coverageStatus") == "fixture"),
            "prohibited": sum(1 for item in results if item.get("coverageStatus") == "prohibited"),
            "unknown": sum(1 for item in results if item.get("state") == "unknown" and item.get("coverageStatus") != "prohibited"),
            "expectedServices": sum(len(item.expected_services) for item in NODES if not item.fixture_only),
            "observedServices": sum(
                1 for item in results for service in item.get("services", [])
                if service.get("state") in _STATES and item.get("coverageStatus") != "prohibited"
            ),
            "prohibitedServices": sum(len(item.expected_services) for item in NODES if item.fixture_only),
            "rejectedObservationCount": len(rejected),
            "rejectionCodes": sorted(set(rejected)),
        },
    }
