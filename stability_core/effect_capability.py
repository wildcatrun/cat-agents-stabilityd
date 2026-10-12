"""Read-only effect capability providers; never action authority or runtime control.

Provider construction/readers are trusted code boundaries, like the existing
policy authorizer. Tool payloads/spec.metadata must never construct a provider
or its binding readers. Receipts are instance-issued and cannot be input facts.
No default providers, artifact allowlists, or verified fallbacks are installed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Callable

from .adapter_contract import AdapterContract, AdapterDescriptor, negotiate_capability, sha256_file
from .process_identity import IDENTITY_FIELDS, read_process_identity


class EffectOperation(Enum):
    LEASE_FILES = 'lease-files'
    PIDFD_SIGNAL = 'pidfd-signal'
    SYSTEMD_UNIT = 'systemd-unit'
    OPENCLAW_RPC = 'openclaw-rpc'
    HERMES_CLI = 'hermes-cli'


@dataclass(frozen=True)
class EffectRequirement:
    action_type: str
    operation: EffectOperation
    kind: str
    capability: str
    runtime: str


_RULES = {
    ('cron.expired_lease.repair', EffectOperation.LEASE_FILES): ('local-mechanical', 'cron.lease-files.v1', 'openclaw'),
    ('openclaw.session.reset', EffectOperation.OPENCLAW_RPC): ('runtime-api', 'sessions.reset', 'openclaw'),
    ('openclaw.gateway.restart', EffectOperation.SYSTEMD_UNIT): ('local-mechanical', 'unit.restart', 'openclaw'),
    ('hermes.gateway.restart', EffectOperation.SYSTEMD_UNIT): ('local-mechanical', 'unit.restart', 'hermes'),
    ('hermes.gateway.restart', EffectOperation.HERMES_CLI): ('runtime-api', 'gateway.restart', 'hermes'),
    ('hermes.profile.lifecycle', EffectOperation.SYSTEMD_UNIT): ('local-mechanical', 'unit.lifecycle', 'hermes'),
    ('hermes.profile.lifecycle', EffectOperation.HERMES_CLI): ('runtime-api', 'profile.lifecycle', 'hermes'),
    ('hermes.process.orphan_reap', EffectOperation.PIDFD_SIGNAL): ('local-mechanical', 'process.pidfd-reap', 'hermes'),
    ('hermes.process.idle_lsp_reap', EffectOperation.PIDFD_SIGNAL): ('local-mechanical', 'process.pidfd-reap', 'hermes'),
}


def resolve_requirement(action_type: str, operation: EffectOperation) -> EffectRequirement | None:
    if type(action_type) is not str or type(operation) is not EffectOperation:
        return None
    rule = _RULES.get((action_type, operation))
    return EffectRequirement(action_type, operation, *rule) if rule else None


@dataclass(frozen=True)
class EffectRequest:
    action_type: str
    operation: EffectOperation
    target: str
    node_id: str
    generation: str


@dataclass(frozen=True)
class SchemaBinding:
    schema_id: str
    subject_id: str
    owner_ref: str


@dataclass(frozen=True)
class FileBinding:
    request: EffectRequest
    root: Path
    path: Path
    identity: tuple[int, int]
    sha256: str
    schema: SchemaBinding


@dataclass(frozen=True)
class UnitEffectiveConfiguration:
    fragment_path: Path
    dropin_paths: tuple[Path, ...]
    execstart_argv: tuple[str, ...]
    node_id: str
    generation: str
    observed_at_ms: int
    coverage: str  # Explicit complete property set from the trusted unit reader.


@dataclass(frozen=True)
class UnitBinding:
    request: EffectRequest
    unit: str
    fragment: FileBinding
    executable: Path
    executable_sha256: str
    runtime_owner_ref: str
    dropin_files: tuple[FileBinding, ...] = ()
    effective_config: UnitEffectiveConfiguration | None = None
    executable_entry: Path | None = None
    executable_route: tuple = ()
    owner_uid: int | None = None  # Trusted runtime-user scope, not action metadata.


@dataclass(frozen=True)
class ProcessBinding:
    request: EffectRequest
    instance: tuple  # Exact IDENTITY_FIELDS sequence, not pid alone.
    owner_ref: str


@dataclass(frozen=True)
class CapabilityReceipt:
    status: str
    reason: str
    requirement: EffectRequirement | None
    evidence_ref: str | None = None
    action_authorized: bool = False
    _issuer: object = field(default=None, repr=False)
    bound_request: EffectRequest | None = field(default=None, repr=False)
    issued_at_ms: int | None = None
    verified_boot_id: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if self.action_authorized is not False:
            raise ValueError('capability-is-not-action-authority')

    def evidence(self):
        # Use this projection for logs/receipts, never serialize issuer/bindings.
        requirement = self.requirement
        return {"status": self.status, "reason": self.reason,
                "actionAuthorized": False, "evidenceRef": self.evidence_ref,
                "kind": requirement.kind if requirement else None,
                "capability": requirement.capability if requirement else None,
                "actionType": requirement.action_type if requirement else None}


_HASH = re.compile(r'[0-9a-f]{64}')

_BOOT_ID = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')


def read_local_boot_id():
    """Kernel birth identity; never extract it from request generation/payload."""
    value = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    if not _BOOT_ID.fullmatch(value):
        raise ValueError('local-boot-id-invalid')
    return value


def _unit_execstart(contents):
    """Strict bounded systemd subset, not shell parsing or shell execution.

    Accept plain tokens and simple quoted tokens, full ExecStart resets, and
    Service sections. Expansion/specifiers, escapes, continuations, command
    prefixes, multiple commands and mixed-quote tokens remain unknown.
    """
    commands = []
    token = re.compile(r"\s*(?:\"([^\"\\]*)\"|'([^'\\]*)'|([^\s\"'\\]+))")
    for raw in contents:
        service = False
        for line in raw.decode('utf-8').splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(('#',';')):
                continue
            if stripped.startswith('['):
                if not re.fullmatch(r'\[[A-Za-z][A-Za-z0-9]*\]', stripped):
                    raise ValueError('unit-section-invalid')
                service = stripped == '[Service]'
                continue
            if not service:
                continue
            key, separator, value = stripped.partition('=')
            if key.strip() != 'ExecStart':
                continue
            if not separator or any(char in value for char in ('\\','$','%')):
                raise ValueError('unit-syntax-unsupported')
            value = value.strip()
            if not value:
                commands.clear()
                continue
            argv = []
            cursor = 0
            while cursor < len(value):
                match = token.match(value, cursor)
                if not match:
                    raise ValueError('unit-argument-unsupported')
                part = next(group for group in match.groups() if group is not None)
                argv.append(part)
                cursor = match.end()
                if cursor < len(value) and not value[cursor].isspace():
                    raise ValueError('unit-mixed-quotes-unsupported')
            if (not argv or not Path(argv[0]).is_absolute() or len(argv) > 128
                    or any(len(arg) > 4096 or any(ord(c) < 32 for c in arg) for arg in argv)):
                raise ValueError('unit-command-unsupported')
            commands.append(tuple(argv))
    if len(commands) != 1:
        raise ValueError('unit-command-count-unsupported')
    return commands[0]


def _identifier(value):
    return type(value) is str and 0 < len(value) <= 512 and not any(ord(c) < 32 for c in value)


def _read_bound_file(binding: FileBinding):
    if type(binding) is not FileBinding or type(binding.schema) is not SchemaBinding:
        raise ValueError('file-binding-required')
    root, path = Path(binding.root), Path(binding.path)
    if not root.is_absolute() or not path.is_absolute():
        raise ValueError('file-path-invalid')
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError('file-symlink')
    if root.resolve() not in path.resolve().parents:
        raise ValueError('file-out-of-owner-root')
    if (type(binding.identity) is not tuple or len(binding.identity) != 2
            or any(type(n) is not int or n < 0 for n in binding.identity)
            or type(binding.sha256) is not str or not _HASH.fullmatch(binding.sha256)):
        raise ValueError('file-identity-invalid')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_dev, before.st_ino) != binding.identity or before.st_size > 65536):
            raise ValueError('file-identity-drift')
        data = bytearray()
        while len(data) <= 65536:
            block = os.read(fd, min(8192, 65537 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        final = path.lstat()
        if (len(data) > 65536 or not stat.S_ISREG(final.st_mode) or final.st_nlink != 1
                or identity(before) != identity(after) or identity(after) != identity(final)):
            raise ValueError('file-read-drift')
        if hashlib.sha256(data).hexdigest() != binding.sha256:
            raise ValueError('file-digest-drift')
        return bytes(data)
    finally:
        os.close(fd)


class EffectCapabilityProvider:
    """Trusted readonly reader boundary, no payload-to-proof conversion.

    Local file schema validator is a trusted runtime-owned parser and must return
    a SchemaBinding from actual bytes. Unit reader resolves the actual owned
    service route; process owner reader resolves registry/runtime ownership.
    Reader exceptions become fixed unknown categories without raw content.
    """
    def __init__(self, *, clock_ms: Callable[[], int], node_reader: Callable[[], tuple[str, str]],
                 source_kind='runtime-owned', api_reader=None, api_contract=None,
                 file_reader=None, schema_validator=None, unit_reader=None,
                 process_reader=None, process_owner_reader=None,
                 process_identity_reader=read_process_identity, process_protocol_reader=None,
                 boot_id_reader=read_local_boot_id,
                 max_age_ms=60000):
        if (not callable(clock_ms) or not callable(node_reader)
                or type(max_age_ms) is not int or not 1 <= max_age_ms <= 60000):
            raise ValueError('provider-config-invalid')
        self.clock_ms=clock_ms;self.node_reader=node_reader;self.source_kind=source_kind
        self.api_reader=api_reader;self.api_contract=api_contract
        self.file_reader=file_reader;self.schema_validator=schema_validator;self.unit_reader=unit_reader
        self.process_reader=process_reader;self.process_owner_reader=process_owner_reader
        self.process_identity_reader=process_identity_reader
        if not callable(boot_id_reader):
            raise ValueError("boot-reader-required")
        self.boot_id_reader=boot_id_reader
        self.process_protocol_reader=process_protocol_reader or (
            lambda: hasattr(os,'pidfd_open') and hasattr(__import__('signal'),'pidfd_send_signal'))
        self.max_age_ms=max_age_ms;self._issuer=object()

    def accepts(self, receipt, request):
        try:
            requirement = resolve_requirement(request.action_type, request.operation) if type(request) is EffectRequest else None
            now = self.clock_ms()
            return (type(receipt) is CapabilityReceipt and receipt._issuer is self._issuer
                    and receipt.status == 'verified' and receipt.action_authorized is False
                    and receipt.requirement == requirement and requirement is not None
                    and receipt.bound_request == request and type(receipt.issued_at_ms) is int
                    and self.source_kind == "runtime-owned"
                    and self.node_reader() == (request.node_id, request.generation)
                    and type(now) is int and 0 <= now - receipt.issued_at_ms <= self.max_age_ms
                    and (request.operation is not EffectOperation.PIDFD_SIGNAL
                         or receipt.verified_boot_id == self.boot_id_reader()))
        except Exception:
            return False

    def _result(self,status,reason,requirement=None,ref=None,*,request=None,boot_id=None):
        issued = self.clock_ms() if status == "verified" else None
        if status == "verified" and (type(issued) is not int or issued < 0):
            status,reason,ref = "unknown","provider-clock-invalid",None
        return CapabilityReceipt(status,reason,requirement,ref,False,self._issuer,request,issued,boot_id)

    def assess(self, request: EffectRequest):
        if type(request) is not EffectRequest:
            return self._result('unknown','typed-effect-request-required')
        verified_boot = [None]
        issue = lambda *args: self._result(*args, request=request, boot_id=verified_boot[0])
        requirement = resolve_requirement(request.action_type, request.operation)
        if requirement is None:
            return issue('unsupported','effect-operation-unsupported')
        if self.source_kind != 'runtime-owned':
            return issue('unknown','untrusted-provider-source',requirement)
        try:
            now = self.clock_ms()
            if type(now) is not int or now < 0 or not all(_identifier(v) for v in (request.target,request.node_id,request.generation)):
                raise ValueError('context-invalid')
            if self.node_reader() != (request.node_id,request.generation):
                return issue('unknown','node-generation-drift',requirement)
            if requirement.kind == 'runtime-api':
                if not callable(self.api_reader) or type(self.api_contract) is not AdapterContract:
                    return issue('unknown','api-provider-unavailable',requirement)
                descriptor = self.api_reader(request)
                if type(descriptor) is not AdapterDescriptor or descriptor.runtime != requirement.runtime:
                    return issue('unknown','typed-api-descriptor-required',requirement)
                decision = negotiate_capability(descriptor,self.api_contract,requirement.capability,
                    expected_node_id=request.node_id,expected_generation=request.generation,
                    now_ms=now,max_age_ms=self.max_age_ms)
                if self.node_reader() != (request.node_id, request.generation):
                    return issue('unknown', 'node-generation-drift', requirement)
                completed = self.clock_ms()
                if type(completed) is not int or not now <= completed <= now + self.max_age_ms:
                    return issue('unknown', 'provider-clock-drift', requirement)
                return issue(decision.status,decision.reason,requirement,
                    'evidence://effect-capability/sha256/'+hashlib.sha256(repr(decision).encode()).hexdigest())
            if request.operation is EffectOperation.LEASE_FILES:
                if not callable(self.file_reader) or not callable(self.schema_validator):
                    return issue('unknown','file-provider-unavailable',requirement)
                binding = self.file_reader(request)
                if type(binding) is not FileBinding or binding.request != request:
                    raise ValueError('file-target-binding')
                raw = _read_bound_file(binding)
                parsed = self.schema_validator(raw)
                if (type(parsed) is not SchemaBinding or parsed != binding.schema
                        or parsed.schema_id != 'openclaw-lease-files-v1'
                        or not _identifier(parsed.owner_ref) or parsed.subject_id != request.target):
                    raise ValueError('file-schema-owner-binding')
                evidence = (binding.identity,binding.sha256,parsed)
            elif request.operation is EffectOperation.SYSTEMD_UNIT:
                if not callable(self.unit_reader):
                    return issue('unknown','unit-provider-unavailable',requirement)
                binding = self.unit_reader(request)
                if (type(binding) is not UnitBinding or binding.request != request
                        or type(binding.fragment) is not FileBinding or binding.fragment.request != request
                        or not _identifier(binding.runtime_owner_ref)
                        or not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service',binding.unit)
                        or binding.fragment.path.name != binding.unit):
                    raise ValueError('unit-target-owner-binding')
                if binding.owner_uid is not None and (type(binding.owner_uid) is not int or binding.owner_uid < 0):
                    raise ValueError('unit-owner-scope-invalid')
                config = binding.effective_config
                if (type(config) is not UnitEffectiveConfiguration or config.coverage != "complete"
                        or config.node_id != request.node_id or config.generation != request.generation
                        or type(config.observed_at_ms) is not int
                        or not now - self.max_age_ms <= config.observed_at_ms <= now + 5000
                        or type(config.dropin_paths) is not tuple or len(config.dropin_paths) > 16
                        or type(binding.dropin_files) is not tuple
                        or config.fragment_path != binding.fragment.path
                        or tuple(item.path for item in binding.dropin_files) != config.dropin_paths
                        or len(set(config.dropin_paths)) != len(config.dropin_paths)
                        or config.fragment_path in config.dropin_paths
                        or type(config.execstart_argv) is not tuple):
                    raise ValueError("unit-effective-coverage-unavailable")
                contents = []
                for file in (binding.fragment, *binding.dropin_files):
                    if (type(file) is not FileBinding or file.request != request
                            or file.schema != SchemaBinding("systemd-unit-v1", request.target, binding.runtime_owner_ref)):
                        raise ValueError("unit-schema-owner-binding")
                    contents.append(_read_bound_file(file))
                argv = _unit_execstart(contents)
                if argv != config.execstart_argv or argv[0] != str(binding.executable_entry or binding.executable):
                    raise ValueError("unit-effective-execstart-conflict")
                if binding.executable_entry is not None:
                    from .unit_capability import resolve_unit_executable
                    resolved, route = resolve_unit_executable(binding.executable_entry, owner_uid=binding.owner_uid)
                    if resolved != binding.executable or route != binding.executable_route:
                        raise ValueError('unit-executable-route-drift')
                if (type(binding.executable_sha256) is not str
                        or not _HASH.fullmatch(binding.executable_sha256)
                        or sha256_file(str(binding.executable)) != binding.executable_sha256):
                    raise ValueError('unit-executable-drift')
                if binding.executable_entry is not None:
                    if resolve_unit_executable(binding.executable_entry, owner_uid=binding.owner_uid) != (binding.executable, binding.executable_route):
                        raise ValueError('unit-executable-route-drift')
                evidence = (binding.unit,tuple(file.sha256 for file in (binding.fragment,*binding.dropin_files)),
                            argv,binding.executable_sha256,binding.runtime_owner_ref,
                            binding.executable_entry,binding.executable_route,binding.owner_uid)
            else:
                if not callable(self.process_reader) or not callable(self.process_owner_reader):
                    return issue('unknown','process-provider-unavailable',requirement)
                binding = self.process_reader(request)
                if (type(binding) is not ProcessBinding or binding.request != request
                        or type(binding.instance) is not tuple or len(binding.instance) != len(IDENTITY_FIELDS)):
                    raise ValueError('process-target-binding')
                pid,start,uid,euid,boot,cmd,cgroup=binding.instance
                actual_boot = self.boot_id_reader()
                if type(actual_boot) is not str or not _BOOT_ID.fullmatch(actual_boot):
                    raise ValueError("process-boot-reader-invalid")
                if (any(type(v) is not int for v in (pid,start,uid,euid)) or pid <= 1 or start <= 0
                        or min(uid,euid) < 0 or boot != actual_boot or not _identifier(binding.owner_ref)
                        or any(type(v) is not str or not _HASH.fullmatch(v) for v in (cmd,cgroup))):
                    raise ValueError('process-instance-invalid')
                current=self.process_identity_reader(pid)
                if (type(current) is not dict or current.get('status')!='known'
                        or tuple(current.get(k) for k in IDENTITY_FIELDS) != binding.instance
                        or self.process_owner_reader(pid) != binding.owner_ref
                        or self.process_protocol_reader() is not True):
                    raise ValueError('process-identity-owner-protocol-drift')
                if self.boot_id_reader() != actual_boot:
                    raise ValueError("process-boot-drift")
                verified_boot[0] = actual_boot
                evidence=(binding.instance,binding.owner_ref,actual_boot)
            if self.node_reader() != (request.node_id, request.generation):
                return issue('unknown', 'node-generation-drift', requirement)
            completed = self.clock_ms()
            if type(completed) is not int or not now <= completed <= now + self.max_age_ms:
                return issue('unknown', 'provider-clock-drift', requirement)
            # No runtime-ready flag participates in a native mechanical proof.
            ref='evidence://effect-capability/sha256/'+hashlib.sha256(repr((request,evidence,now)).encode()).hexdigest()
            return issue('verified','local-mechanism-bound',requirement,ref)
        except Exception:
            return issue('unknown','provider-evidence-unavailable',requirement)
