"""Trusted local policy grant issuance for stabilityd's existing actuator set.

The authorizer owns policy loading and action-specific eligibility evaluation;
neither a tool request nor ActionLedger data can supply an authorization grant.
It preserves existing stabilityd actions and denies workflow, membership,
configuration, OAuth, production, and trading writes.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import time
from typing import Any, Callable, Mapping, Sequence

from .action_executor import ActionSpec, AuthorizationGrant


@dataclasses.dataclass(frozen=True)
class StandingRule:
    policy_flag: str
    target_prefixes: tuple[str, ...]
    authority_ref: str
    max_grant_ttl_ms: int = 30_000


@dataclasses.dataclass(frozen=True)
class EligibilityProof:
    """Trusted action-specific evidence result produced inside stabilityd."""

    action_type: str
    target: str
    generation: str
    input_digest: str
    policy_digest: str
    evidence_refs: tuple[str, ...]
    checked_at_ms: int
    expires_at_ms: int
    eligible: bool


STANDING_RULES = {
    "cron.expired_lease.repair": StandingRule(
        "canReapExpiredLeases", ("cron-lease:",), "governance://AGENTS.md#stabilityd-controlled-repair"
    ),
    "cron.stale_running_state.repair": StandingRule(
        "canMutateCronState", ("cron-job:",), "governance://AGENTS.md#stabilityd-controlled-repair"
    ),
    "openclaw.session.reset": StandingRule(
        "canResetSession", ("openclaw-session:",), "governance://AGENTS.md#stabilityd-controlled-repair"
    ),
    "hermes.process.orphan_reap": StandingRule(
        "canReapHermersOrphanWorkers", ("hermes-process:",), "governance://AGENTS.md#stabilityd-controlled-repair"
    ),
    "hermes.process.idle_lsp_reap": StandingRule(
        "canReapHermersIdleLsp", ("hermes-process:",), "governance://AGENTS.md#stabilityd-controlled-repair"
    ),
    "hermes.profile.lifecycle": StandingRule(
        "hermersProfileModeActuateEnabled", ("hermes-profile:",), "governance://AGENTS.md#stabilityd-controlled-repair"
    ),
    "hermes.gateway.restart": StandingRule(
        "canRestartHermersGateway", ("hermes-gateway:",), "governance://AGENTS.md#stabilityd-controlled-repair"
    ),
    "openclaw.gateway.restart": StandingRule(
        "canRestartGateway", ("openclaw-gateway:dev-server",), "governance://AGENTS.md#stabilityd-controlled-repair"
    ),
}

_DENIED_TARGET_MARKERS = ("workflow", "message_flow", "outbox", "human-gate", "trade", "production", "oauth", "credential")
TRUSTED_SOURCES = frozenset({"stabilityd-daemon", "stabilityd-cli"})
MAX_POLICY_TTL_MS = 15 * 60 * 1000
MAX_PROOF_AGE_MS = 30_000


def _digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def policy_reference(policy: Mapping[str, Any]) -> tuple[str, str]:
    """Return the canonical digest and opaque reference for a loaded policy."""
    digest = _digest(dict(policy))
    return digest, f"stabilityd-policy://sha256/{digest}"


class TrustedPolicyAuthorizer:
    """Load current policy and obtain a bound proof from trusted in-process code."""

    def __init__(
        self,
        *,
        policy_reader: Callable[[], Mapping[str, Any]],
        eligibility_evaluator: Callable[[ActionSpec, Mapping[str, Any], str, int], EligibilityProof],
        source: str,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        if source not in TRUSTED_SOURCES:
            raise ValueError("untrusted stabilityd authorizer source")
        if not callable(policy_reader) or not callable(eligibility_evaluator):
            raise ValueError("trusted policy and eligibility providers are required")
        self._policy_reader = policy_reader
        self._eligibility_evaluator = eligibility_evaluator
        self._source = source
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def __call__(self, spec: ActionSpec, _record: Any) -> AuthorizationGrant:
        rule = STANDING_RULES.get(spec.action_type)
        if rule is None or spec.source != self._source:
            return self._denied(spec, rule)
        target_lower = spec.target.lower()
        if not any(spec.target.startswith(prefix) for prefix in rule.target_prefixes) or any(
            marker in target_lower for marker in _DENIED_TARGET_MARKERS
        ):
            return self._denied(spec, rule)
        try:
            policy = self._policy_reader()
            if not isinstance(policy, Mapping) or policy.get(rule.policy_flag) is not True:
                return self._denied(spec, rule)
            digest, policy_ref = policy_reference(policy)
            now_ms = self._clock_ms()
            valid_until = int(policy.get("validUntilEpoch") or 0) * 1000
            updated_at = int(policy.get("updatedAtEpoch") or 0) * 1000
            if (
                valid_until <= now_ms or updated_at <= 0 or updated_at > now_ms + 5_000
                or valid_until <= updated_at or valid_until - updated_at > MAX_POLICY_TTL_MS
                or spec.policy_ref != policy_ref
            ):
                return self._denied(spec, rule)
            proof = self._eligibility_evaluator(spec, policy, digest, now_ms)
        except Exception:
            return self._denied(spec, rule)
        expected_digest = _digest(spec.input_data)
        if (
            not isinstance(proof, EligibilityProof)
            or proof.eligible is not True
            or proof.action_type != spec.action_type
            or proof.target != spec.target
            or proof.generation != spec.generation
            or proof.input_digest != expected_digest
            or proof.policy_digest != digest
            or proof.checked_at_ms > now_ms + 5_000
            or now_ms - proof.checked_at_ms > MAX_PROOF_AGE_MS
            or proof.expires_at_ms <= now_ms
            or proof.expires_at_ms > now_ms + MAX_PROOF_AGE_MS
            or not proof.evidence_refs
            or any(not isinstance(ref, str) or not ref.strip() for ref in proof.evidence_refs)
            or len(set(proof.evidence_refs)) != len(proof.evidence_refs)
        ):
            return self._denied(spec, rule)
        digest_ref = f"policy-digest:sha256:{digest}"
        expected_refs = tuple(dict.fromkeys([*proof.evidence_refs, policy_ref, digest_ref]))
        if tuple(spec.evidence_refs) != expected_refs or spec.authorization_ref != rule.authority_ref:
            return self._denied(spec, rule)
        expires_at = min(valid_until, proof.expires_at_ms, now_ms + rule.max_grant_ttl_ms)
        if expires_at <= now_ms:
            return self._denied(spec, rule)
        return AuthorizationGrant(
            status="authorized", authorization_ref=rule.authority_ref, policy_ref=policy_ref,
            action_type=spec.action_type, target=spec.target, generation=spec.generation,
            source=self._source, input_digest=expected_digest, evidence_refs=expected_refs,
            expires_at_ms=expires_at,
        )

    @staticmethod
    def _denied(spec: ActionSpec, rule: StandingRule | None) -> AuthorizationGrant:
        return AuthorizationGrant(
            status="denied", authorization_ref=rule.authority_ref if rule else "",
            policy_ref=spec.policy_ref if isinstance(spec.policy_ref, str) else "",
            action_type=spec.action_type, target=spec.target, generation=spec.generation,
            source=spec.source, input_digest="", evidence_refs=(), expires_at_ms=0,
        )
