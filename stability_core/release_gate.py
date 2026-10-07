"""Read-only release qualification and shadow-result comparison primitives."""

from __future__ import annotations

import dataclasses
import math
import re
from typing import Any, Mapping, Sequence


COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


@dataclasses.dataclass(frozen=True)
class ReleaseEvidence:
    installed_version: str
    candidate_version: str
    installed_commit: str
    candidate_commit: str
    loaded_commit: str
    loaded_generation: str
    candidate_generation: str
    candidate_tree_clean: bool
    candidate_commit_pinned: bool
    artifact_sha256: str
    previous_artifact_sha256: str
    tests_passed: bool
    independent_review_passed: bool
    loaded_generation_verified: bool
    schema_backward_compatible: bool
    migration_reversible: bool
    action_ledger_recovery_verified: bool
    rollback_artifact_available: bool
    auto_update_change_requires_g2: bool


@dataclasses.dataclass(frozen=True)
class ReleaseDecision:
    status: str  # eligible_for_g2_review | blocked | unknown
    reasons: tuple[str, ...]
    candidate_commit: str | None = None
    artifact_sha256: str | None = None
    activation_authorized: bool = False


@dataclasses.dataclass(frozen=True)
class ShadowComparison:
    status: str  # comparable | degraded | blocked
    reasons: tuple[str, ...]
    introduced_critical: tuple[str, ...]
    removed_coverage: tuple[str, ...]
    newly_authorized_effects: tuple[str, ...]
    max_latency_ratio: float | None


def _semver(value: Any) -> tuple[int, int, int] | None:
    match = SEMVER_RE.fullmatch(value) if isinstance(value, str) and len(value) <= 96 else None
    return tuple(int(match.group(i)) for i in (1, 2, 3)) if match else None


def qualify_release(evidence: ReleaseEvidence) -> ReleaseDecision:
    """Never activates or publishes; it only says whether a separate G2 review may start."""
    if not isinstance(evidence, ReleaseEvidence):
        return ReleaseDecision("unknown", ("release-evidence-invalid",))
    reasons: list[str] = []
    installed = _semver(evidence.installed_version)
    candidate = _semver(evidence.candidate_version)
    if installed is None or candidate is None:
        reasons.append("version-unparseable")
    elif candidate <= installed:
        reasons.append("candidate-version-not-forward")
    if not isinstance(evidence.installed_commit, str) or not COMMIT_RE.fullmatch(evidence.installed_commit):
        reasons.append("installed-commit-unknown")
    if not isinstance(evidence.candidate_commit, str) or not COMMIT_RE.fullmatch(evidence.candidate_commit):
        reasons.append("candidate-commit-unpinned")
    if evidence.candidate_commit == evidence.installed_commit:
        reasons.append("candidate-commit-not-distinct")
    if evidence.loaded_commit != evidence.candidate_commit:
        reasons.append("loaded-commit-does-not-match-candidate")
    if (
        not isinstance(evidence.loaded_generation, str) or not evidence.loaded_generation.strip()
        or not isinstance(evidence.candidate_generation, str) or not evidence.candidate_generation.strip()
        or evidence.loaded_generation != evidence.candidate_generation
    ):
        reasons.append("loaded-generation-does-not-match-candidate")
    if evidence.candidate_tree_clean is not True:
        reasons.append("candidate-tree-dirty")
    if evidence.candidate_commit_pinned is not True:
        reasons.append("candidate-commit-not-pinned")
    if evidence.loaded_generation_verified is not True:
        reasons.append("loaded-generation-unverified")
    if not isinstance(evidence.artifact_sha256, str) or not SHA256_RE.fullmatch(evidence.artifact_sha256):
        reasons.append("candidate-artifact-digest-invalid")
    if not isinstance(evidence.previous_artifact_sha256, str) or not SHA256_RE.fullmatch(evidence.previous_artifact_sha256):
        reasons.append("rollback-artifact-digest-invalid")
    if evidence.artifact_sha256 and evidence.artifact_sha256 == evidence.previous_artifact_sha256:
        reasons.append("candidate-artifact-not-distinct")
    if evidence.tests_passed is not True:
        reasons.append("quality-checks-incomplete")
    if evidence.independent_review_passed is not True:
        reasons.append("independent-review-incomplete")
    if evidence.schema_backward_compatible is not True:
        reasons.append("schema-compatibility-unproven")
    if evidence.migration_reversible is not True:
        reasons.append("migration-rollback-unproven")
    if evidence.action_ledger_recovery_verified is not True:
        reasons.append("action-ledger-recovery-unverified")
    if evidence.rollback_artifact_available is not True:
        reasons.append("rollback-artifact-unavailable")
    if evidence.auto_update_change_requires_g2 is not True:
        reasons.append("automatic-updater-scope-not-separated")
    if reasons:
        return ReleaseDecision("blocked", tuple(sorted(set(reasons))))
    return ReleaseDecision(
        "eligible_for_g2_review", (), evidence.candidate_commit, evidence.artifact_sha256,
        activation_authorized=False,
    )


def compare_shadow_results(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    *,
    max_latency_ratio: float = 1.25,
) -> ShadowComparison:
    """Compare dry-run snapshots without treating existing critical findings as regressions."""
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
        return ShadowComparison("blocked", ("shadow-snapshot-invalid",), (), (), (), None)
    reasons: list[str] = []
    if type(max_latency_ratio) not in (int, float):
        return ShadowComparison("blocked", ("latency-threshold-invalid",), (), (), (), None)
    try:
        threshold_finite = math.isfinite(float(max_latency_ratio))
    except (OverflowError, TypeError, ValueError):
        threshold_finite = False
    if not threshold_finite or max_latency_ratio <= 0:
        return ShadowComparison("blocked", ("latency-threshold-invalid",), (), (), (), None)
    if baseline.get("executionMode") != "shadow" or candidate.get("executionMode") != "shadow":
        reasons.append("non-shadow-snapshot")
    if not _findings_valid(baseline.get("findings")) or not _findings_valid(candidate.get("findings")):
        reasons.append("findings-evidence-invalid")
    if _coverage_values(baseline.get("coverage")) is None or _coverage_values(candidate.get("coverage")) is None:
        reasons.append("coverage-evidence-invalid")
    if not _actions_valid(baseline.get("actions")) or not _actions_valid(candidate.get("actions")):
        reasons.append("action-evidence-invalid")
    before_findings = _finding_map(baseline)
    after_findings = _finding_map(candidate)
    introduced_critical = tuple(sorted(
        key for key, value in after_findings.items()
        if str(value.get("severity") or "").lower() == "critical"
        and (key not in before_findings or str(before_findings[key].get("severity") or "").lower() != "critical")
    ))
    if introduced_critical:
        reasons.append("new-critical-finding")
    before_coverage = _string_set(baseline.get("coverage"))
    after_coverage = _string_set(candidate.get("coverage"))
    removed_coverage = tuple(sorted(before_coverage - after_coverage))
    if removed_coverage:
        reasons.append("coverage-regressed")
    before_effects = _shadow_effects(baseline)
    after_effects = _shadow_effects(candidate)
    newly_authorized = tuple(sorted(after_effects - before_effects))
    if newly_authorized:
        reasons.append("shadow-added-actuator-effect")
    latency_ratio = _latency_ratio(baseline.get("durationMs"), candidate.get("durationMs"))
    if latency_ratio is None:
        reasons.append("latency-evidence-invalid")
    elif latency_ratio > max_latency_ratio:
        reasons.append("latency-regressed")
    blocked_reasons = {
        "new-critical-finding", "coverage-regressed", "shadow-added-actuator-effect",
        "non-shadow-snapshot", "findings-evidence-invalid", "coverage-evidence-invalid",
        "action-evidence-invalid", "latency-evidence-invalid", "latency-threshold-invalid",
    }
    status = "blocked" if blocked_reasons & set(reasons) else "degraded" if reasons else "comparable"
    return ShadowComparison(status, tuple(sorted(set(reasons))), introduced_critical,
                            removed_coverage, newly_authorized, latency_ratio)


def _finding_map(snapshot: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    values = snapshot.get("findings")
    if not isinstance(values, list):
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for item in values:
        if isinstance(item, Mapping) and isinstance(item.get("key"), str) and item["key"].strip():
            result[item["key"].strip().lower()] = item
    return result


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {item.strip() for item in value if isinstance(item, str) and item.strip()}


def _findings_valid(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    seen: set[str] = set()
    allowed_severities = {"ok", "info", "warning", "high", "critical"}
    for item in value:
        if not isinstance(item, Mapping):
            return False
        key, severity = item.get("key"), item.get("severity")
        if not isinstance(key, str) or not key.strip() or not isinstance(severity, str):
            return False
        normalized = key.strip().lower()
        if normalized in seen or severity.strip().lower() not in allowed_severities:
            return False
        seen.add(normalized)
    return True


def _coverage_values(value: Any) -> set[str] | None:
    if not isinstance(value, (list, tuple, set)) or not value:
        return None
    if any(not isinstance(item, str) or not item.strip() for item in value):
        return None
    result = {item.strip() for item in value}
    return result if len(result) == len(value) else None


def _actions_valid(value: Any) -> bool:
    if not isinstance(value, list):
        return False
    for item in value:
        if not isinstance(item, Mapping):
            return False
        action = item.get("action")
        if not isinstance(action, str) or not action.strip():
            return False
        if any(key in item and type(item.get(key)) is not bool for key in ("wouldAct", "actionAuthorized")):
            return False
        if item.get("wouldAct") is True or item.get("actionAuthorized") is True:
            target = item.get("target") or item.get("profile") or item.get("jobId")
            if not isinstance(target, str) or not target.strip():
                return False
    return True


def _shadow_effects(snapshot: Mapping[str, Any]) -> set[str]:
    effects: set[str] = set()
    actions = snapshot.get("actions")
    if not isinstance(actions, list):
        return effects
    for item in actions:
        if not isinstance(item, Mapping):
            continue
        if item.get("wouldAct") is True or item.get("actionAuthorized") is True:
            action = str(item.get("action") or "").strip()
            target = str(item.get("target") or item.get("profile") or item.get("jobId") or "").strip()
            effects.add(f"{action}:{target}")
    return effects


def _latency_ratio(before: Any, after: Any) -> float | None:
    if type(before) not in (int, float) or type(after) not in (int, float) or before <= 0 or after < 0:
        return None
    try:
        before_float, after_float = float(before), float(after)
        if not math.isfinite(before_float) or not math.isfinite(after_float):
            return None
        return after_float / before_float
    except (OverflowError, TypeError, ValueError):
        return None
