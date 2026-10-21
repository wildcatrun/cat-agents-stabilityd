"""Pure evidence classification. This module never grants actuator authority."""
from __future__ import annotations
import math
from typing import Any, Mapping

CRON_PRESSURE_KEYS = frozenset({
    'cron_stale_running_state', 'cron_expired_leases', 'gateway_congestion_logs',
})
CAPACITY_ONLY_KEYS = frozenset({'system_commit_pressure', 'system_commit_saturation'})
COMMIT_RUNTIME_PRESSURE_KEY = 'system_commit_runtime_pressure'
PSI_SOME_AVG10_PERCENT = 1.0
PSI_FULL_AVG10_PERCENT = 0.1


def finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


def commit_pressure_corroboration(context: Mapping[str, Any], available_bytes: int,
                                  available_warn_bytes: int) -> dict[str, Any]:
    """Reservations alone and since-boot OOM/swap counters are not current pressure."""
    psi = context.get('psi')
    some = finite_number(((psi or {}).get('some') or {}).get('avg10')) if isinstance(psi, dict) else None
    full = finite_number(((psi or {}).get('full') or {}).get('avg10')) if isinstance(psi, dict) else None
    psi_high = ((some is not None and some >= PSI_SOME_AVG10_PERCENT)
                or (full is not None and full >= PSI_FULL_AVG10_PERCENT))
    low_available = 0 < available_bytes <= available_warn_bytes
    return {'corroborated': bool(psi_high and low_available),
            'scopeComplete': some is not None and full is not None and available_bytes > 0,
            'psiPressure': bool(psi_high), 'lowAvailableMemory': low_available,
            'someAvg10Percent': some, 'fullAvg10Percent': full,
            'cumulativeCountersAuthorizeAction': False}


def observation_contract(name: str, data: Mapping[str, Any], probe: Mapping[str, Any]) -> dict[str, Any]:
    transport = probe.get('status') == 'ok'
    complete = None
    if name == 'auth':
        section = data.get('openclaw') or {}
        complete = section.get('scopeComplete') is True
        hermers = data.get('hermers') or {}
        if isinstance(hermers, dict) and hermers.get('scopeComplete') is False:
            complete = False
    elif name == 'hermers':
        registry = data.get('profileRegistry') or {}
        complete = registry.get('scopeComplete')
        if complete not in (True, False):
            complete = None
    if not transport:
        complete = False
    return {'transportSuccess': transport, 'scopeComplete': complete,
            'coverageStatus': 'partial' if complete is False else 'complete' if complete is True else 'unspecified',
            'readiness': 'unknown' if not transport or complete is False else 'not-inferred-from-probe-success',
            'actionEligibility': 'requires-existing-policy-and-fresh-precheck'}


def finding_classification(finding: Mapping[str, Any]) -> dict[str, Any]:
    key = str(finding.get('key') or '')
    component = str(finding.get('component') or 'unknown')
    if key in CAPACITY_ONLY_KEYS:
        kind = 'capacity-risk'
    elif key == 'cron_heartbeat_unhealthy':
        kind = 'task-execution-failure'
    elif key in CRON_PRESSURE_KEYS:
        kind = 'runtime-pressure-or-state-fault'
    elif component == 'auth':
        kind = 'authorization-or-observation-failure'
    elif component == 'resource':
        kind = 'resource-pressure'
    else:
        kind = 'component-finding'
    return {'key': key, 'kind': kind, 'component': component,
            'scope': 'host' if component == 'resource' else 'runtime-component',
            'grantsAuthority': False}
