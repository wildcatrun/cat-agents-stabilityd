"""Fail-closed executor for durable, explicitly authorized side effects.

The ledger is an idempotency and persistence mechanism, never an authority
source.  This module therefore requires separate authorization, precheck and
postcheck boundaries and validates their structured results before invoking an
operation.
"""

from __future__ import annotations

import dataclasses
import json
import time
from typing import Any, Callable, Mapping, Optional, Sequence

from .action_ledger import ActionLedger, ActionRecord, InvalidTransition, _canonical_digest


@dataclasses.dataclass(frozen=True)
class ActionSpec:
    idempotency_key: str
    action_type: str
    target: str
    generation: str
    source: str
    input_data: Any
    authorization_ref: str
    policy_ref: str
    evidence_refs: Sequence[str]
    metadata: Optional[Mapping[str, Any]] = None


@dataclasses.dataclass(frozen=True)
class AuthorizationGrant:
    status: str  # authorized | denied | unknown
    authorization_ref: str
    policy_ref: str
    action_type: str
    target: str
    generation: str
    source: str
    input_digest: str
    evidence_refs: Sequence[str]
    expires_at_ms: int


@dataclasses.dataclass(frozen=True)
class BoundaryCheck:
    status: str  # approved | rejected | unknown
    reference: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class OperationResult:
    status: str  # complete | partial | unknown
    outcome_ref: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class PostcheckResult:
    status: str  # verified | failed | unknown
    reference: Optional[str] = None


@dataclasses.dataclass(frozen=True)
class ExecutionResult:
    record: ActionRecord
    disposition: str  # executed | existing | blocked | uncertain


Authorizer = Callable[[ActionSpec, ActionRecord], AuthorizationGrant]
Precheck = Callable[[ActionSpec, ActionRecord], BoundaryCheck]
Operation = Callable[[ActionSpec, ActionRecord], OperationResult]
Postcheck = Callable[[ActionSpec, ActionRecord, OperationResult], PostcheckResult]


def _valid_ref(value: Optional[str]) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _exception_ref(stage: str, exc: BaseException) -> str:
    # Persist only a coarse category.  Exception text may contain credentials,
    # payloads, paths, or provider output and must never enter the ledger.
    category = type(exc).__name__.lower()
    if not category.isidentifier():
        category = "exception"
    return f"outcome://{stage}-exception/{category}"


class _FrozenDict(dict):
    def _readonly(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("action input is immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _readonly


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return _FrozenDict({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _snapshot_spec(spec: ActionSpec) -> ActionSpec:
    # Detach nested containers from the caller and make callback inputs immutable.
    data = json.loads(json.dumps(spec.input_data, ensure_ascii=False, allow_nan=False))
    metadata = dict(spec.metadata or {})
    if "request_source" in metadata and metadata["request_source"] != spec.source:
        raise ValueError("metadata request_source does not match action source")
    metadata["request_source"] = spec.source
    return dataclasses.replace(
        spec, input_data=_freeze_json(data), evidence_refs=tuple(spec.evidence_refs),
        metadata=_freeze_json(json.loads(json.dumps(metadata, allow_nan=False))),
    )


class ActionExecutor:
    """Execute an action once behind independent, structured boundaries."""

    def __init__(
        self,
        ledger: ActionLedger,
        *,
        authorizer: Authorizer,
        precheck: Precheck,
        operation: Operation,
        postcheck: Postcheck,
        clock_ms: Optional[Callable[[], int]] = None,
        timing_check=None,
        effect_timing=None,
    ) -> None:
        callbacks = (authorizer, precheck, operation, postcheck)
        if any(callback is None or not callable(callback) for callback in callbacks):
            raise ValueError("authorizer, precheck, operation, and postcheck callbacks are required")
        if any(hook is not None and not callable(hook) for hook in (timing_check, effect_timing)):
            raise ValueError("timing hooks must be trusted callable constructors")
        self._timing_check = timing_check
        self._effect_timing = effect_timing
        self._ledger = ledger
        self._authorizer = authorizer
        self._precheck = precheck
        self._operation = operation
        self._postcheck = postcheck
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def execute(self, spec: ActionSpec) -> ExecutionResult:
        """Persist a plan, validate boundaries, claim it with CAS, and execute."""
        self._validate_spec(spec)
        spec = _snapshot_spec(spec)
        record = self._ledger.plan_action(
            idempotency_key=spec.idempotency_key,
            action_type=spec.action_type,
            target=spec.target,
            generation=spec.generation,
            input_data=spec.input_data,
            authorization_ref=spec.authorization_ref,
            policy_ref=spec.policy_ref,
            evidence_refs=tuple(spec.evidence_refs),
            metadata=spec.metadata,
        )
        if record.state != "planned":
            return ExecutionResult(record, "existing")

        try:
            grant = self._authorizer(spec, record)
        except Exception:
            return self._block(record, "outcome://authorization-exception")
        if not self._grant_matches(spec, record, grant):
            return self._block(record, "outcome://authorization-rejected")

        try:
            precheck = self._precheck(spec, record)
        except Exception:
            return self._block(record, "outcome://precheck-exception")
        if not isinstance(precheck, BoundaryCheck) or precheck.status != "approved" or not _valid_ref(precheck.reference):
            return self._block(record, "outcome://precheck-rejected", getattr(precheck, "reference", None))
        if not self._grant_matches(spec, record, grant) or _canonical_digest(spec.input_data) != record.input_digest:
            return self._block(record, "outcome://authorization-expired-or-input-changed")

        if not self._timing_approved(spec, record, "before-cas"):
            return self._block(record, "outcome://clock-before-cas-refused")

        # This CAS is the final side-effect fence.  Another contender may have
        # completed or claimed the action after our read; it must not operate.
        try:
            executing = self._ledger.begin_execution(
                record.action_id, expected_version=record.version, precheck_ref=precheck.reference,
            )
        except InvalidTransition:
            current = self._ledger.get(record.action_id)
            if current is None:
                raise
            return ExecutionResult(current, "existing")

        # Claiming can wait for SQLite contention. Re-resolve live policy/evidence
        # after the CAS so expiry, revocation, runtime generation, and adapter
        # artifact identity are checked again immediately before the effect.
        try:
            final_grant = self._authorizer(spec, executing)
        except Exception:
            return self._block_executing(executing, "outcome://authorization-recheck-exception")
        if (
            not self._grant_matches(spec, executing, grant)
            or not self._grant_matches(spec, executing, final_grant)
            or _canonical_digest(spec.input_data) != executing.input_digest
        ):
            return self._block_executing(executing, "outcome://authorization-expired-before-effect")
        # Protection, registry ownership and runtime generation can change while
        # the durable CAS waits on storage. Recheck the complete action boundary
        # after the claim and persist that exact evidence before the effect.
        try:
            final_precheck = self._precheck(spec, executing)
        except Exception:
            return self._block_executing(executing, "outcome://final-precheck-exception")
        if (
            not isinstance(final_precheck, BoundaryCheck)
            or final_precheck.status != "approved"
            or not _valid_ref(final_precheck.reference)
        ):
            return self._block_executing(
                executing, "outcome://final-precheck-rejected",
                final_precheck.reference if isinstance(final_precheck, BoundaryCheck) else None,
            )
        # A failed ledger write leaves the durable claim as executing. That is
        # intentionally non-replayable and the operation remains uncalled.
        executing = self._ledger.refresh_execution_precheck(
            executing.action_id, expected_version=executing.version,
            precheck_ref=final_precheck.reference,
        )
        if not self._timing_approved(spec, executing, "before-effect"):
            return self._block_executing(executing, "outcome://clock-before-effect-refused")
        operation_failed = False
        try:
            operation_result = self._operation(spec, executing)
            if not isinstance(operation_result, OperationResult):
                operation_result = OperationResult("unknown", "outcome://operation-invalid-result")
        except Exception as exc:
            operation_failed = True
            operation_result = OperationResult("unknown", _exception_ref("operation", exc))

        try:
            verification = self._postcheck(spec, executing, operation_result)
        except Exception as exc:
            verification = PostcheckResult("unknown", _exception_ref("postcheck", exc))

        outcome_ref = operation_result.outcome_ref if _valid_ref(operation_result.outcome_ref) else None
        postcheck_ref = verification.reference if isinstance(verification, PostcheckResult) and _valid_ref(verification.reference) else None
        uncertain = (
            operation_failed
            or outcome_ref is None
            or operation_result.status != "complete"
            or not isinstance(verification, PostcheckResult)
            or verification.status == "unknown"
            or verification.status not in {"verified", "failed"}
            or postcheck_ref is None
        )
        effect_hook = None
        if operation_result.status == "complete" and outcome_ref is not None and self._effect_timing is not None:
            effect_hook = lambda conn, terminal: self._effect_timing(conn, spec, terminal, operation_result)
        if uncertain:
            final = self._ledger.transition(
                executing.action_id, expected_state="executing", expected_version=executing.version,
                new_state="uncertain", outcome_ref=outcome_ref, postcheck_ref=postcheck_ref,
                **({"transaction_hook": effect_hook} if effect_hook is not None else {}),
            )
            return ExecutionResult(final, "uncertain")

        final_state = "succeeded" if verification.status == "verified" else "failed"

        final = self._ledger.transition(
            executing.action_id, expected_state="executing", expected_version=executing.version,
            new_state=final_state, outcome_ref=outcome_ref, postcheck_ref=postcheck_ref,
            **({"transaction_hook": effect_hook} if effect_hook is not None else {}),
        )
        return ExecutionResult(final, "executed")

    def _timing_approved(self, spec, record, phase):
        if self._timing_check is None:
            return True
        try:
            return self._ledger.run_timing_check(
                lambda conn: self._timing_check(conn, spec, record, phase)
            ) is True
        except Exception:
            # No exception text/payload is persisted. No effect has run here.
            return False

    @staticmethod
    def _validate_spec(spec: ActionSpec) -> None:
        if not isinstance(spec, ActionSpec):
            raise TypeError("spec must be an ActionSpec")
        required = (
            spec.idempotency_key, spec.action_type, spec.target, spec.generation,
            spec.source, spec.authorization_ref, spec.policy_ref,
        )
        if not all(isinstance(value, str) and value.strip() for value in required):
            raise ValueError("action identity, source, authorization and policy references are required")
        if isinstance(spec.evidence_refs, (str, bytes)) or not spec.evidence_refs:
            raise ValueError("at least one evidence reference is required")

    def _grant_matches(self, spec: ActionSpec, record: ActionRecord, grant: object) -> bool:
        if not isinstance(grant, AuthorizationGrant) or grant.status != "authorized":
            return False
        return (
            grant.authorization_ref == spec.authorization_ref == record.authorization_ref
            and grant.policy_ref == spec.policy_ref == record.policy_ref
            and grant.action_type == spec.action_type == record.action_type
            and grant.target == spec.target == record.target
            and grant.generation == spec.generation == record.generation
            and grant.source == spec.source
            and record.metadata.get("request_source") == spec.source
            and grant.input_digest == record.input_digest
            and tuple(grant.evidence_refs) == tuple(spec.evidence_refs) == record.evidence_refs
            and type(grant.expires_at_ms) is int
            and grant.expires_at_ms > self._clock_ms()
        )

    def _block(
        self, record: ActionRecord, outcome_ref: str, postcheck_ref: Optional[str] = None
    ) -> ExecutionResult:
        try:
            blocked = self._ledger.transition(
                record.action_id, expected_state="planned", expected_version=record.version,
                new_state="blocked", outcome_ref=outcome_ref,
                postcheck_ref=postcheck_ref if _valid_ref(postcheck_ref) else None,
            )
        except InvalidTransition:
            current = self._ledger.get(record.action_id)
            if current is None:
                raise
            return ExecutionResult(current, "existing")
        return ExecutionResult(blocked, "blocked")

    def _block_executing(
        self, record: ActionRecord, outcome_ref: str, precheck_ref: Optional[str] = None
    ) -> ExecutionResult:
        try:
            blocked = self._ledger.transition(
                record.action_id, expected_state="executing", expected_version=record.version,
                new_state="blocked", outcome_ref=outcome_ref, precheck_ref=precheck_ref,
            )
        except InvalidTransition:
            current = self._ledger.get(record.action_id)
            if current is None:
                raise
            return ExecutionResult(current, "existing")
        return ExecutionResult(blocked, "blocked")
