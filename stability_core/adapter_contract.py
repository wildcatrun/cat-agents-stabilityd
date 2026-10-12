"""Fail-closed runtime adapter capability and artifact identity negotiation."""

from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Mapping, Sequence


KNOWN_RUNTIMES = frozenset({"openclaw", "hermes", "hermes_acp", "codex"})
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$")


@dataclasses.dataclass(frozen=True)
class AdapterContract:
    adapter_id: str
    api_major: int
    api_minimum: str
    api_maximum: str
    minimum_version: str
    maximum_version: str
    allowed_runtimes: tuple[str, ...]
    supported_capabilities: tuple[str, ...]
    verified_capabilities: tuple[str, ...]
    allowed_artifacts: tuple[tuple[str, str], ...]  # (producer commit, binary SHA-256)
    # Independently qualified content identity, never a measured-hash approval.
    # Runtime-owned readers must derive this from actual producer code/manifest.
    allowed_content_artifacts: tuple[tuple[str, str], ...] = ()


@dataclasses.dataclass(frozen=True)
class AdapterDescriptor:
    runtime: str
    adapter_id: str
    adapter_version: str
    api_version: str
    commit: str
    node_id: str
    generation: str
    observed_at_ms: int
    advertised_capabilities: Sequence[str]
    binary_source: str
    resolved_binary_path: str
    active_binary_path: str
    resolved_binary_sha256: str
    active_binary_sha256: str
    status: str = "ready"
    artifact_kind: str = "git-commit"
    artifact_digest: str = ""


@dataclasses.dataclass(frozen=True)
class CapabilityDecision:
    status: str  # verified | observation_only | unsupported | unknown
    capability: str
    reason: str
    action_authorized: bool = False  # always False; action authorization belongs to ActionExecutor
    adapter_id: str | None = None
    runtime: str | None = None
    generation: str | None = None
    binary_sha256: str | None = None
    artifact_kind: str | None = None
    producer_identity: str | None = None

    def __post_init__(self) -> None:
        if self.action_authorized is not False:
            raise ValueError("adapter capability assessment cannot authorize an action")


def _version(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    if "-" in value or "+" in value:
        return None
    match = VERSION_RE.fullmatch(value)
    return tuple(int(match.group(index)) for index in (1, 2, 3)) if match else None


def sha256_file(path: str) -> str:
    """Hash a resolved, single-link regular file without following a final symlink."""
    target = Path(path)
    try:
        if os.name != "posix":
            raise ValueError("binary verification currently requires a POSIX runtime")
        if not target.is_absolute() or target.is_symlink():
            raise ValueError("binary path must be absolute and not a symlink")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(target), flags)
    except OSError as exc:
        raise ValueError("binary path cannot be opened safely") from exc
    digest = hashlib.sha256()
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("binary must be a single-link regular file")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        after = os.fstat(fd)
        final = target.lstat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
                                 item.st_ctime_ns, item.st_nlink)
        if (not stat.S_ISREG(final.st_mode) or final.st_nlink != 1
                or identity(info) != identity(after) or identity(after) != identity(final)):
            raise ValueError("binary identity changed during measurement")
    finally:
        os.close(fd)
    return digest.hexdigest()


def negotiate_capability(
    descriptor: AdapterDescriptor | Mapping[str, Any] | None,
    contract: AdapterContract,
    capability: str,
    *,
    expected_node_id: str,
    expected_generation: str,
    now_ms: int,
    max_age_ms: int = 60_000,
) -> CapabilityDecision:
    """Classify a fresh compatible adapter; a verified result is not action authorization.

    Consumers must re-run this check in the action precheck and still require the
    separate standing-authority, protection, ledger, and postcheck gates.
    Windows remains observation-only until a native no-follow binary inspector exists.
    """
    if os.name != "posix":
        return CapabilityDecision("observation_only", capability, "platform-inspector-not-supported")
    if not isinstance(descriptor, (AdapterDescriptor, Mapping)):
        return CapabilityDecision("unknown", capability, "descriptor-unavailable", False)
    raw = dataclasses.asdict(descriptor) if isinstance(descriptor, AdapterDescriptor) else descriptor
    required = (
        "runtime", "adapter_id", "adapter_version", "api_version", "commit", "node_id",
        "generation", "observed_at_ms", "advertised_capabilities",
        "binary_source", "resolved_binary_path", "active_binary_path",
        "resolved_binary_sha256", "active_binary_sha256", "status",
    )
    if any(key not in raw for key in required):
        return CapabilityDecision("unknown", capability, "descriptor-incomplete", False)
    runtime = str(raw.get("runtime") or "")
    if runtime not in KNOWN_RUNTIMES or runtime not in contract.allowed_runtimes:
        return CapabilityDecision("unknown", capability, "runtime-unknown-or-out-of-contract", False, runtime=runtime or None)
    if raw.get("status") != "ready":
        return CapabilityDecision("observation_only", capability, "adapter-not-ready", False, contract.adapter_id, runtime)
    observed = raw.get("observed_at_ms")
    if type(observed) is not int or observed > now_ms + 5_000 or now_ms - observed > max_age_ms:
        return CapabilityDecision("observation_only", capability, "handshake-stale-or-invalid-time", False, contract.adapter_id, runtime)
    if (
        not isinstance(expected_node_id, str) or not expected_node_id.strip()
        or not isinstance(expected_generation, str) or not expected_generation.strip()
        or not isinstance(raw.get("node_id"), str) or not raw["node_id"].strip()
        or not isinstance(raw.get("generation"), str) or not raw["generation"].strip()
        or raw.get("node_id") != expected_node_id or raw.get("generation") != expected_generation
    ):
        return CapabilityDecision("observation_only", capability, "node-or-generation-mismatch", False, contract.adapter_id, runtime)
    if raw.get("adapter_id") != contract.adapter_id:
        return CapabilityDecision("unsupported", capability, "adapter-id-mismatch", False, str(raw.get("adapter_id") or ""), runtime)
    version = _version(raw.get("adapter_version"))
    minimum = _version(contract.minimum_version)
    maximum = _version(contract.maximum_version)
    if version is None or minimum is None or maximum is None:
        return CapabilityDecision("unknown", capability, "adapter-version-unparseable", False, contract.adapter_id, runtime)
    api_version = _version(raw.get("api_version"))
    api_minimum = _version(contract.api_minimum)
    api_maximum = _version(contract.api_maximum)
    if api_version is None or api_minimum is None or api_maximum is None:
        return CapabilityDecision("unknown", capability, "adapter-api-version-unparseable", False, contract.adapter_id, runtime)
    if not minimum <= version <= maximum or not api_minimum <= api_version <= api_maximum or api_version[0] != contract.api_major:
        return CapabilityDecision("unsupported", capability, "adapter-or-api-version-unsupported", False, contract.adapter_id, runtime)
    commit = raw.get("commit")
    if not isinstance(commit, str):
        return CapabilityDecision("observation_only", capability, "artifact-identity-unverified", False, contract.adapter_id, runtime)
    artifact_kind = raw.get("artifact_kind", "git-commit")
    artifact_digest = raw.get("artifact_digest", "")
    if artifact_kind == "git-commit":
        if artifact_digest != "":
            return CapabilityDecision("observation_only", capability, "artifact-identity-conflicting", False, contract.adapter_id, runtime)
        if not COMMIT_RE.fullmatch(commit):
            return CapabilityDecision("observation_only", capability, "adapter-commit-unverified", False, contract.adapter_id, runtime)
    elif artifact_kind == "content-manifest":
        if commit or not isinstance(artifact_digest, str) or not SHA256_RE.fullmatch(artifact_digest):
            return CapabilityDecision("observation_only", capability, "content-artifact-identity-unverified", False, contract.adapter_id, runtime)
    else:
        return CapabilityDecision("observation_only", capability, "artifact-identity-kind-unknown", False, contract.adapter_id, runtime)
    if raw.get("binary_source") not in {"runtime-owned", "embedded", "global"}:
        return CapabilityDecision("observation_only", capability, "binary-source-unknown", False, contract.adapter_id, runtime)
    if (
        not isinstance(raw.get("resolved_binary_path"), str) or not Path(raw["resolved_binary_path"]).is_absolute()
        or not isinstance(raw.get("active_binary_path"), str) or not Path(raw["active_binary_path"]).is_absolute()
    ):
        return CapabilityDecision("observation_only", capability, "binary-path-unverified", False, contract.adapter_id, runtime)
    resolved_digest = str(raw.get("resolved_binary_sha256") or "")
    active_digest = str(raw.get("active_binary_sha256") or "")
    if not SHA256_RE.fullmatch(resolved_digest) or not SHA256_RE.fullmatch(active_digest):
        return CapabilityDecision("observation_only", capability, "binary-digest-unverified", False, contract.adapter_id, runtime)
    if resolved_digest != active_digest:
        return CapabilityDecision("observation_only", capability, "active-binary-does-not-match-resolved-binary", False, contract.adapter_id, runtime)
    try:
        measured_resolved = sha256_file(str(raw["resolved_binary_path"]))
        measured_active = sha256_file(str(raw["active_binary_path"]))
    except (OSError, ValueError):
        return CapabilityDecision("observation_only", capability, "binary-measurement-failed", False, contract.adapter_id, runtime)
    if measured_resolved != resolved_digest or measured_active != active_digest:
        return CapabilityDecision("observation_only", capability, "binary-digest-does-not-match-measurement", False, contract.adapter_id, runtime)
    if artifact_kind == "git-commit":
        if (commit, resolved_digest) not in contract.allowed_artifacts:
            return CapabilityDecision("observation_only", capability, "commit-binary-pair-not-allowlisted", False, contract.adapter_id, runtime)
    elif (artifact_digest, resolved_digest) not in contract.allowed_content_artifacts:
        return CapabilityDecision("observation_only", capability, "content-binary-pair-not-allowlisted", False, contract.adapter_id, runtime)
    advertised = raw.get("advertised_capabilities")
    if not isinstance(advertised, (list, tuple)):
        return CapabilityDecision("unknown", capability, "capability-list-invalid", False, contract.adapter_id, runtime)
    if any(not isinstance(value, str) or not value for value in advertised) or len(set(advertised)) != len(advertised):
        return CapabilityDecision("unknown", capability, "capability-list-invalid", False, contract.adapter_id, runtime)
    if capability not in contract.supported_capabilities or capability not in advertised:
        return CapabilityDecision("unsupported", capability, "capability-not-supported", False, contract.adapter_id, runtime)
    if capability not in contract.verified_capabilities:
        return CapabilityDecision("observation_only", capability, "capability-not-independently-verified", False, contract.adapter_id, runtime)
    return CapabilityDecision(
        "verified", capability, "verified", False, contract.adapter_id, runtime,
        str(raw["generation"]), active_digest,
        artifact_kind, commit if artifact_kind == "git-commit" else artifact_digest,
    )
