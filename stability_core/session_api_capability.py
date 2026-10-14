"""Runtime-owned session API observations; no default artifact approval.

Qualification is a trusted-code input, never action metadata. Installed sources
must be independently qualified before providing it. None means unknown and
blocks only session reset. Schema-only tests are not a qualification.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import re

from .adapter_contract import AdapterContract, AdapterDescriptor, sha256_file
from .content_artifact import ContentArtifactSpec, measure_content_artifact
from .effect_capability import EffectCapabilityProvider, EffectRequest, EffectOperation
from .process_identity import read_process_identity, identities_match, IDENTITY_FIELDS
from .unit_capability import read_unit_binding, binding_identity, resolve_unit_executable


@dataclass(frozen=True)
class SessionApiQualification:
    code: ContentArtifactSpec
    contract: AdapterContract
    cli_entry: Path
    gateway_entry_relative: str
    protocol_relative: str
    runtime_uid: int
    provenance_ref: str
    endpoint_port: int
    unit_roots: tuple | None = None
    proc_root: Path = Path('/proc')


@dataclass(frozen=True)
class SessionRpcLauncher:
    executable: Path
    cli_entry: Path
    executable_sha256: str
    executable_route: tuple
    cli_route: tuple
    endpoint_url: str

    def __post_init__(self):
        if (not isinstance(self.executable, Path) or not self.executable.is_absolute()
                or not isinstance(self.cli_entry, Path) or not self.cli_entry.is_absolute()
                or re.fullmatch(r'[0-9a-f]{64}', self.executable_sha256) is None
                or type(self.executable_route) is not tuple or not self.executable_route
                or type(self.cli_route) is not tuple or not self.cli_route
                or re.fullmatch(r'ws://127\.0\.0\.1:[0-9]{1,5}', self.endpoint_url) is None):
            raise ValueError('session RPC launcher scope refused')

    @property
    def argv(self):
        # Never execute the JS shebang: /usr/bin/env would consult PATH for node.
        return (str(self.executable), str(self.cli_entry))


# No installed artifact or wire protocol has completed the independent gate.
# This constant may only be replaced by a reviewed qualification, not an env
# variable, runtime measurement, payload, tool argument or policy metadata.
SESSION_API_QUALIFICATION = None

def _code_identity(spec):
    fields = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    return tuple((str(p), fields(p.lstat())) for p in (spec.root, *(spec.root / f for f in sorted(spec.files))))

def _endpoint_identity(proc_root, pid, port, uid):
    # Closed IPv4-loopback listener subset, tied to this PID's kernel sockets.
    # Never infer ownership from a successful TCP connect or a unit name.
    with (proc_root / 'net/tcp').open('rb') as handle:
        raw = handle.read(1048577)
    if len(raw) > 1048576: raise ValueError('session listener budget')
    matches = []
    for line in raw.decode('ascii').splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 10 and fields[1] == f'0100007F:{port:04X}' and fields[3] == '0A':
            if fields[7] != str(uid) or not fields[9].isdigit():
                raise ValueError('session listener owner unknown')
            matches.append(fields[9])
    if len(matches) != 1: raise ValueError('session listener scope unknown')
    names = os.listdir(proc_root / str(pid) / 'fd')
    if len(names) > 4096: raise ValueError('session socket descriptor budget')
    owned = [name for name in names if os.readlink(proc_root / str(pid) / 'fd' / name) == 'socket:[' + matches[0] + ']']
    if not owned: raise ValueError('session listener not owned by Gateway')
    return matches[0], tuple(sorted(owned))


def make_session_api_capability(request, *, qualification, clock_ms, node_reader,
                                unit_properties_reader, gateway_state_reader):
    if (type(request) is not EffectRequest or request.action_type != 'openclaw.session.reset'
            or request.operation is not EffectOperation.OPENCLAW_RPC):
        raise ValueError('session capability request refused')
    pinned = {'identity': None, 'launcher': None}
    contract = qualification.contract if type(qualification) is SessionApiQualification else None

    def reader(current):
        if current != request or type(qualification) is not SessionApiQualification:
            raise ValueError('session qualification unavailable')
        q = qualification
        if (type(q.code) is not ContentArtifactSpec or type(q.contract) is not AdapterContract
                or type(q.runtime_uid) is not int or q.runtime_uid < 0
                or type(q.provenance_ref) is not str
                or not q.provenance_ref.startswith('evidence://session-api-qualification/')
                or not isinstance(q.cli_entry, Path) or not isinstance(q.proc_root, Path)
                or not q.proc_root.is_absolute() or type(q.endpoint_port) is not int
                or not 1 <= q.endpoint_port <= 65535):
            raise ValueError('session qualification scope refused')
        if q.gateway_entry_relative not in q.code.files or q.protocol_relative not in q.code.files:
            raise ValueError('session qualification source closure incomplete')
        code_identity = _code_identity(q.code)
        measurement = measure_content_artifact(q.code)
        cli, route = resolve_unit_executable(q.cli_entry, owner_uid=q.runtime_uid)
        if cli != q.code.root / q.gateway_entry_relative:
            raise ValueError('session CLI producer route unknown')
        unit = read_unit_binding(current, unit='openclaw-gateway.service',
            read_properties=unit_properties_reader, clock_ms=clock_ms,
            unit_roots=q.unit_roots, owner_uid=q.runtime_uid)
        argv = unit.effective_config.execstart_argv
        if len(argv) < 3 or argv[1] != str(cli) or argv[2] != 'gateway':
            raise ValueError('session Gateway producer route unknown')
        if argv.count('--port') != 1 or argv[argv.index('--port') + 1] != str(q.endpoint_port):
            raise ValueError('session Gateway endpoint route unknown')
        service = gateway_state_reader()
        pid = service.get('MainPID')
        if (service.get('ActiveState') != 'active' or service.get('SubState') != 'running'
                or type(pid) is not int or pid <= 1):
            raise ValueError('session Gateway instance unavailable')
        process = read_process_identity(pid, q.proc_root)
        if (process.get('status') != 'known' or process.get('uid') != q.runtime_uid
                or process.get('euid') != q.runtime_uid
                or current.generation != current.node_id + ':' + str(process.get('bootId')).lower()):
            raise ValueError('session Gateway owner unknown')
        with (q.proc_root / str(pid) / 'cmdline').open('rb') as handle:
            command = handle.read(32769)
        if len(command) > 32768 or command != b'\x00'.join(a.encode() for a in argv) + b'\x00':
            raise ValueError('session Gateway launch identity unknown')
        if hashlib.sha256(command).hexdigest() != process.get('cmdlineDigest'):
            raise ValueError('session Gateway command drift')
        endpoint = _endpoint_identity(q.proc_root, pid, q.endpoint_port, q.runtime_uid)
        # Closed source declaration subset. This is an observed wire-protocol
        # integer, mapped into the adapter's semver convention, not guessed from
        # package version or session payload schema. Other source shapes refuse.
        protocol_path = q.code.root / q.protocol_relative
        fd = os.open(protocol_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            with os.fdopen(fd, 'rb', closefd=False) as handle:
                protocol_source = handle.read(65537)
            if (before != os.fstat(fd) or before != protocol_path.lstat()
                    or hashlib.sha256(protocol_source).hexdigest() !=
                       next(digest for relative, digest, _size in measurement.records if relative == q.protocol_relative)):
                raise ValueError('session protocol file drift')
        finally:
            os.close(fd)
        if len(protocol_source) > 65536:
            raise ValueError('session protocol source budget')
        protocol = re.fullmatch(rb'\s*export const PROTOCOL_VERSION = ([1-9][0-9]{0,3});\s*', protocol_source)
        if protocol is None:
            raise ValueError('session wire protocol unqualified')
        protocol_version = protocol[1].decode() + '.0.0'
        binary = sha256_file(str(cli))
        after = read_process_identity(pid, q.proc_root)
        if (not identities_match(process, after)[0]
                or gateway_state_reader() != service
                or measure_content_artifact(q.code) != measurement
                or _endpoint_identity(q.proc_root, pid, q.endpoint_port, q.runtime_uid) != endpoint
                or _code_identity(q.code) != code_identity
                or binding_identity(read_unit_binding(current, unit='openclaw-gateway.service',
                    read_properties=unit_properties_reader, clock_ms=clock_ms,
                    unit_roots=q.unit_roots, owner_uid=q.runtime_uid)) != binding_identity(unit)
                or resolve_unit_executable(q.cli_entry, owner_uid=q.runtime_uid) != (cli, route)):
            raise ValueError('session runtime observation drift')
        identity = (measurement, code_identity, route, binding_identity(unit), binary, endpoint,
                    tuple(after.get(field) for field in IDENTITY_FIELDS), q.provenance_ref, protocol_version)
        launcher = SessionRpcLauncher(unit.executable, cli, unit.executable_sha256,
            unit.executable_route, route, f'ws://127.0.0.1:{q.endpoint_port}')
        if pinned['identity'] is None:
            pinned.update(identity=identity, launcher=launcher)
        elif pinned['identity'] != identity:
            raise ValueError('session runtime binding drift')
        return AdapterDescriptor('openclaw', q.contract.adapter_id, q.code.package_version,
            protocol_version, '', current.node_id, current.generation, clock_ms(),
            q.contract.supported_capabilities, 'runtime-owned', str(cli), str(cli), binary, binary,
            artifact_kind='content-manifest', artifact_digest=measurement.digest)

    provider = EffectCapabilityProvider(clock_ms=clock_ms, node_reader=node_reader,
        api_reader=reader if contract is not None else None, api_contract=contract)

    def assess():
        receipt = provider.assess(request)
        accepted = provider.accepts(receipt, request)
        if accepted:
            receipt = replace(receipt, evidence_ref='evidence://effect-capability/sha256/' +
                hashlib.sha256(repr((receipt.evidence_ref, pinned['identity'])).encode()).hexdigest())
        return accepted, receipt, pinned['launcher'] if accepted else None
    return assess
