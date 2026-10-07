"""Canonical protected-member and shared-dependency impact resolution."""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Iterable, Mapping, Sequence


PROTECTED_CANONICAL = frozenset({"main", "cat_heart", "cat_claw"})
_HERMES_PROFILE_REF = re.compile(r"^hermes(?:rs)?-profile:([A-Za-z0-9_-]{1,64})$", re.IGNORECASE)
_OPENCLAW_AGENT_REF = re.compile(r"^openclaw-agent:([A-Za-z0-9_-]{1,64})$", re.IGNORECASE)


@dataclasses.dataclass(frozen=True)
class ProtectionDecision:
    status: str  # protected | clear | unknown
    reason: str
    affected_agents: tuple[str, ...] = ()
    protected_subjects: tuple[str, ...] = ()
    target_generation: str | None = None


def canonical_subject(value: Any) -> str | None:
    """Map only established identity aliases; retired `catclaw` stays unrelated."""
    if not isinstance(value, str):
        return None
    identity = value.strip().lower()
    if identity in {"main", "cat_claw"}:
        return identity
    if identity in {"cat_heart", "catheart"}:
        return "cat_heart"
    hermes = _HERMES_PROFILE_REF.fullmatch(identity)
    if hermes:
        return canonical_subject(hermes.group(1))
    openclaw = _OPENCLAW_AGENT_REF.fullmatch(identity)
    if openclaw:
        return canonical_subject(openclaw.group(1))
    return None


def is_protected_identity(values: Iterable[Any], additive_protected: Iterable[str] = ()) -> bool:
    configured = {str(value).strip().lower() for value in additive_protected if str(value).strip()}
    raw_candidates = {value.strip().lower() for value in values if isinstance(value, str) and value.strip()}
    canonical_candidates = {subject for value in raw_candidates if (subject := canonical_subject(value))}
    return bool(canonical_candidates & PROTECTED_CANONICAL or raw_candidates & configured)


def _record_ids(record: Mapping[str, Any]) -> set[str]:
    values = {
        str(record.get("agent_id") or ""),
        str(record.get("agent_key") or "").split(":", 1)[-1],
        str(record.get("endpoint_ref") or ""),
    }
    return {value.strip() for value in values if value.strip()}


def _runtime_matches(record: Mapping[str, Any], runtime: str) -> bool:
    values = {
        str(record.get("runtime") or "").strip().lower(),
        str(record.get("platform") or "").strip().lower(),
        str(record.get("execution_adapter") or "").strip().lower(),
    }
    if runtime == "openclaw":
        return "openclaw" in values
    if runtime in {"hermes", "hermers", "hermes_acp"}:
        return bool(values & {"hermes", "hermers", "hermes_acp", "hermes_acp_gateway"})
    return runtime in values


def resolve_protection_scope(
    records: Sequence[Mapping[str, Any]],
    *,
    registry_source: str,
    registry_write_eligible: bool,
    scope_complete: bool,
    target_kind: str,
    target_id: str,
    runtime: str,
    target_generation: str,
    additive_protected: Iterable[str] = (),
) -> ProtectionDecision:
    """Resolve exact or shared dependency impact; unknown scope never means clear."""
    if (
        registry_source != "db" or registry_write_eligible is not True or scope_complete is not True
        or not isinstance(target_generation, str) or not target_generation.strip()
    ):
        return ProtectionDecision("unknown", "authoritative-registry-or-generation-unavailable",
                                  target_generation=target_generation or None)
    if (
        not isinstance(records, Sequence) or isinstance(records, (str, bytes))
        or any(not isinstance(record, Mapping) for record in records)
    ):
        return ProtectionDecision("unknown", "registry-records-invalid", target_generation=target_generation)
    if not isinstance(target_id, str) or target_kind not in {"profile", "agent", "shared-gateway"} or not target_id.strip():
        return ProtectionDecision("unknown", "target-scope-unparseable", target_generation=target_generation)

    affected: list[Mapping[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping) or str(record.get("status") or "").lower() != "active":
            continue
        if not _runtime_matches(record, runtime):
            continue
        adapters = {
            str(record.get(key) or "").strip().lower()
            for key in ("runtime", "platform", "execution_adapter", "workflow_ingress_adapter")
        }
        if "openclaw_route_shell" in adapters:
            continue
        if target_kind == "shared-gateway":
            affected.append(record)
            continue
        if target_kind == "agent":
            if str(record.get("agent_id") or "").strip() == target_id:
                affected.append(record)
            continue
        endpoint = str(record.get("endpoint_ref") or "").strip()
        match = _HERMES_PROFILE_REF.fullmatch(endpoint)
        profile = match.group(1) if match else ""
        if profile.lower() == target_id.lower():
            affected.append(record)

    if not affected:
        return ProtectionDecision("unknown", "no-authoritative-target-owner", target_generation=target_generation)
    affected_ids = sorted({str(record.get("agent_id") or "").strip() for record in affected if record.get("agent_id")})
    protected = sorted({
        canonical
        for record in affected
        for value in _record_ids(record)
        if (canonical := canonical_subject(value))
    } & PROTECTED_CANONICAL)
    configured = {str(value).strip().lower() for value in additive_protected if str(value).strip()}
    protected.extend(sorted({value.lower() for record in affected for value in _record_ids(record)} & configured))
    protected = sorted(set(protected))
    return ProtectionDecision(
        "protected" if protected else "clear",
        "protected-member-in-impact-scope" if protected else "scope-complete-no-protected-member",
        tuple(affected_ids), tuple(protected), target_generation,
    )
