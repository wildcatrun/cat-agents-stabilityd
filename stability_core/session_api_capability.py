"""Runtime-owned session API observations; no default artifact approval.

Qualification is a trusted-code input, never action metadata. Installed sources
must be independently qualified before providing it. None means unknown and
blocks only session reset. Schema-only tests are not a qualification.
"""
from __future__ import annotations
from dataclasses import dataclass, replace
import hashlib
import json
import subprocess
import tempfile
import os
from pathlib import Path
import re
import stat

from .adapter_contract import AdapterContract, AdapterDescriptor, sha256_file
from .content_artifact import ContentArtifactSpec, measure_content_artifact
from .effect_capability import EffectCapabilityProvider, EffectRequest, EffectOperation
from .process_identity import read_process_identity, identities_match, IDENTITY_FIELDS
from .unit_capability import read_unit_binding, binding_identity


# Reviewed launch context contains routing/config paths and proxy settings only.
# Loader injection and credential values are never inherited from the daemon.
_RPC_ENV_KEYS = frozenset({
    'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'XDG_CONFIG_HOME',
    'OPENCLAW_HOME', 'OPENCLAW_CONFIG_PATH', 'OPENCLAW_STATE_DIR',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
})


def _rpc_environment(items):
    if (type(items) is not tuple or len(items) > 32
            or any(type(item) is not tuple or len(item) != 2 for item in items)):
        raise ValueError('session RPC environment scope refused')
    values = {}
    for key, value in items:
        if (type(key) is not str or key not in _RPC_ENV_KEYS or key in values
                or type(value) is not str or '\x00' in value or len(value) > 4096):
            raise ValueError('session RPC environment entry refused')
        values[key] = value
    home = Path(values.get('HOME', ''))
    if not home.is_absolute() or '..' in home.parts:
        raise ValueError('session RPC environment home unavailable')
    return values


@dataclass(frozen=True)
class SessionSdkQualification:
    entry_relative: str
    wrapper_entry: Path
    wrapper_sha256: str
    server_version: str
    server_build_id: str | None
    semantics: str = 'v1'


def _wrapper_identity(path, owner_uid, expected):
    if not isinstance(path, Path) or not path.is_absolute() or '..' in path.parts:
        raise ValueError('session SDK wrapper route refused')
    parents=[]
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0,owner_uid} or info.st_mode & 0o022:
            raise ValueError('session SDK wrapper parent refused')
        parents.append((parent,(info.st_dev,info.st_ino,info.st_uid,info.st_mode)))
    identity=lambda i:(i.st_dev,i.st_ino,i.st_uid,i.st_mode,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid not in {0,owner_uid} or before.st_nlink!=1 or before.st_mode & 0o022 or before.st_size>2097152:
            raise ValueError('session SDK wrapper ownership refused')
        raw=os.read(fd,2097153)
        if (hashlib.sha256(raw).hexdigest()!=expected or identity(os.fstat(fd))!=identity(before)
                or identity(path.lstat())!=identity(before)
                or any((p.lstat().st_dev,p.lstat().st_ino,p.lstat().st_uid,p.lstat().st_mode)!=i for p,i in parents)):
            raise ValueError('session SDK wrapper drift')
        return identity(before),tuple(parents)
    finally: os.close(fd)


def _script_source_route(entry, *, owner_uid):
    """Pin the declared JS entry route, including owned ancestor aliases.

    This is source routing, not executable approval; Node retains the existing
    executable reader. Source bytes are checked by the qualified code manifest.
    """
    if (not isinstance(entry, Path) or not entry.is_absolute() or '..' in entry.parts
            or type(owner_uid) is not int or owner_uid<0):
        raise ValueError('session script route refused')
    root=Path('/').lstat()
    if not stat.S_ISDIR(root.st_mode) or root.st_uid not in {0,owner_uid} or root.st_mode & 0o022:
        raise ValueError('session script root refused')
    pending=list(entry.parts[1:]); current=Path('/')
    route=[('/', 'directory', (root.st_dev,root.st_ino,root.st_uid,root.st_mode),None)]; links=0
    while pending:
        component=pending.pop(0)
        if component=='.':continue
        if component=='..':
            current=current.parent
            continue
        current=current/component
        info=current.lstat()
        if info.st_uid not in {0,owner_uid}:
            raise ValueError('session script route owner refused')
        full=(info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_nlink,
              info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        if stat.S_ISLNK(info.st_mode):
            links+=1
            if links>16: raise ValueError('session script link budget')
            target=os.readlink(current)
            after=current.lstat()
            if full!=(after.st_dev,after.st_ino,after.st_uid,after.st_mode,after.st_nlink,
                       after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                raise ValueError('session script link drift')
            route.append((str(current),'link',full,target))
            # Preserve traversal order: a nested symlink before '..' must be
            # resolved before walking its parent, exactly as the kernel does.
            target_path=Path(target)
            pending=list(target_path.parts[1:] if target_path.is_absolute() else target_path.parts)+pending
            current=Path('/') if target_path.is_absolute() else current.parent
        elif stat.S_ISDIR(info.st_mode):
            if info.st_mode & 0o022: raise ValueError('session script directory refused')
            route.append((str(current),'directory',full[:4],None))
            if not pending: raise ValueError('session script file required')
        else:
            if pending or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode & 0o022:
                raise ValueError('session script file refused')
            route.append((str(current),'file',full,None))
    return current,tuple(route)


def _valid_expected_build(value):
    # None is a trusted expectation of wire-field absence, never a wildcard.
    return value is None or (type(value) is str and 0<len(value)<=256
                             and re.search(r'[\x00-\x1f\x7f]',value) is None)


def validate_sdk_response(text, *, version, build_id, boot_id=None, probe=False):
    if type(text) is not str or len(text.encode())>65536:
        raise ValueError('session SDK output budget')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result: raise ValueError('session SDK duplicate response field')
            result[key]=value
        return result
    value=json.loads(text,object_pairs_hook=unique)
    if type(value) is not dict or set(value)!={'ok','hello','result'} or value['ok'] is not True:
        raise ValueError('session SDK response refused')
    hello=value['hello']
    if (type(hello) is not dict or set(hello)!={'protocol','version','buildId','bootId','methods'}
            or type(hello['protocol']) is not int or hello['protocol']!=4
            or hello['version']!=version or hello['buildId']!=build_id
            or type(hello['bootId']) is not str or not hello['bootId'] or len(hello['bootId'])>256
            or re.search(r'[\x00-\x1f\x7f]',hello['bootId']) is not None
            or (boot_id is not None and hello['bootId']!=boot_id)
            or type(hello['methods']) is not list or len(hello['methods'])>2
            or any(type(m) is not str or m not in {'sessions.describe','sessions.reset'} for m in hello['methods'])
            or len(set(hello['methods']))!=len(hello['methods'])
            or (value['result'] is not None if probe else type(value['result']) is not dict)):
        raise ValueError('session SDK hello binding refused')
    return hello,value['result']


def run_sdk_process(argv, *, environment, cwd, timeout):
    # Spool child output to private files: output cannot allocate unbounded RAM.
    # Decode only the fixed response budget, never include child diagnostics in
    # exceptions/evidence. Timeout also bounds a non-responsive SDK process.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        proc=subprocess.run(list(argv),env=environment,cwd=str(cwd),timeout=timeout,
                            stdout=output,stderr=errors)
        if proc.returncode!=0: raise ValueError('session SDK process unavailable')
        if os.fstat(output.fileno()).st_size>65536 or os.fstat(errors.fileno()).st_size>65536:
            raise ValueError('session SDK output budget')
        output.seek(0)
        return output.read(65537).decode('utf-8')


def _run_sdk_probe(argv, *, environment, cwd):
    # Sole external SDK probe boundary; file/unit/process windows surround it.
    return run_sdk_process(argv,environment=environment,cwd=cwd,timeout=10)


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
    rpc_environment: tuple = ()
    sdk: SessionSdkQualification | None = None


@dataclass(frozen=True)
class SessionRpcLauncher:
    executable: Path
    cli_entry: Path
    executable_sha256: str
    executable_route: tuple
    cli_route: tuple
    endpoint_url: str
    environment_items: tuple
    sdk_entry: Path | None = None
    sources: tuple = ()
    server_version: str = ''
    server_build_id: str | None = ''
    server_boot_id: str = ''
    cwd: Path | None = None

    def __post_init__(self):
        _rpc_environment(self.environment_items)
        if (not isinstance(self.executable, Path) or not self.executable.is_absolute()
                or not isinstance(self.cli_entry, Path) or not self.cli_entry.is_absolute()
                or re.fullmatch(r'[0-9a-f]{64}', self.executable_sha256) is None
                or type(self.executable_route) is not tuple or not self.executable_route
                or type(self.cli_route) is not tuple or not self.cli_route
                or re.fullmatch(r'ws://127\.0\.0\.1:[0-9]{1,5}', self.endpoint_url) is None):
            raise ValueError('session RPC launcher scope refused')
        if (not isinstance(self.sdk_entry, Path) or not self.sdk_entry.is_absolute()
                or len(str(self.sdk_entry))>512 or re.search(r'[\x00-\x1f\x7f]',str(self.sdk_entry)) is not None
                or not isinstance(self.cwd, Path) or not self.cwd.is_absolute()
                or type(self.sources) is not tuple or not 1<=len(self.sources)<=64
                or any(type(row) is not tuple or len(row)!=2 or type(row[0]) is not str
                       or not Path(row[0]).is_absolute() or '..' in Path(row[0]).parts or len(row[0])>512
                       or re.search(r'[\x00-\x1f\x7f]',row[0]) is not None
                       or type(row[1]) is not str or re.fullmatch(r'[0-9a-f]{64}',row[1]) is None for row in self.sources)
                or not all(type(v) is str and v and len(v)<=256 and re.search(r'[\x00-\x1f\x7f]',v) is None for v in (self.server_version,self.server_boot_id))
                or not _valid_expected_build(self.server_build_id)):
            raise ValueError('session SDK launcher binding unavailable')

    @property
    def environment(self):
        return _rpc_environment(self.environment_items)

    @property
    def argv(self):
        return (str(self.executable), str(self.cli_entry))

    def command(self, method, params):
        required={'sessions.describe':{'key','agentId'},'sessions.reset':{'key','agentId','expectedSessionId'}}
        if (method not in required or type(params) is not dict or set(params)!=required[method]
                or any(type(v) is not str or not v or len(v)>512 or re.search(r'[\x00-\x1f\x7f]',v) is not None for v in params.values())):
            raise ValueError('session SDK call scope refused')
        return (*self.argv,json.dumps(dict(schema=1,mode='call',sdkEntry=str(self.sdk_entry),
            sources=[dict(path=p,sha256=d) for p,d in self.sources],endpoint=self.endpoint_url,
            server=dict(version=self.server_version,buildId=self.server_build_id,bootId=self.server_boot_id),
            method=method,params=params),sort_keys=True,separators=(',',':')))


# No installed artifact or wire protocol has completed the independent gate.
# This constant may only be replaced by a reviewed qualification, not an env
# variable, runtime measurement, payload, tool argument or policy metadata.
SESSION_API_QUALIFICATION = None

def _code_identity(spec):
    fields = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    return tuple((str(p), fields(p.lstat())) for p in (spec.root, *(spec.root / f for f in sorted(spec.files))))

def _kernel_executable_identity(proc_root, pid, executable):
    """Follow only the trusted proc PID/exe image, compare its actual inode.

    The kernel image can outlive the pathname replaced during an upgrade.
    Matching argv, a current disk hash, or the text of readlink is insufficient.
    Never apply this symlink-following exception to a caller-supplied file path.
    """
    link = proc_root / str(pid) / 'exe'
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                          s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    before_link = link.lstat()
    target = os.readlink(link)
    if (not stat.S_ISLNK(before_link.st_mode) or target.endswith(' (deleted)')
            or target != str(executable)):
        raise ValueError('session running executable route unknown')
    # Intentionally follow this kernel-owned exe link to an image descriptor;
    # O_NOFOLLOW is still required on ordinary program/source paths elsewhere.
    fd = os.open(link, os.O_RDONLY | os.O_NONBLOCK)
    try:
        image = os.fstat(fd)
        disk = executable.lstat()
        if (not stat.S_ISREG(image.st_mode) or not stat.S_ISREG(disk.st_mode)
                or image.st_nlink != 1 or identity(image) != identity(disk)):
            raise ValueError('session running executable image mismatch')
        if (identity(os.fstat(fd)) != identity(image)
                or identity(executable.lstat()) != identity(disk)
                or identity(link.lstat()) != identity(before_link)
                or os.readlink(link) != target or identity(link.stat()) != identity(image)):
            raise ValueError('session running executable image drift')
        return target, identity(before_link), identity(image)
    finally:
        os.close(fd)

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
        if (type(q.sdk) is not SessionSdkQualification or q.sdk.semantics!='v1'
                or q.sdk.entry_relative not in q.code.files
                or not all(type(v) is str and 0<len(v)<=256 and re.search(r'[\x00-\x1f\x7f]',v) is None for v in (q.sdk.server_version,))
                or not _valid_expected_build(q.sdk.server_build_id)
                or len(q.code.files)>64
                or re.fullmatch(r'[0-9a-f]{64}',q.sdk.wrapper_sha256) is None):
            raise ValueError('session SDK source qualification unavailable')
        if q.gateway_entry_relative not in q.code.files:
            raise ValueError('session qualification source closure incomplete')
        _rpc_environment(q.rpc_environment)
        code_identity = _code_identity(q.code)
        measurement = measure_content_artifact(q.code)
        cli, route = _script_source_route(q.cli_entry, owner_uid=q.runtime_uid)
        if cli != q.code.root / q.gateway_entry_relative:
            raise ValueError('session CLI producer route unknown')
        unit = read_unit_binding(current, unit='openclaw-gateway.service',
            read_properties=unit_properties_reader, clock_ms=clock_ms,
            unit_roots=q.unit_roots, owner_uid=q.runtime_uid)
        argv = unit.effective_config.execstart_argv
        if len(argv) < 3 or argv[1] != str(q.cli_entry) or argv[2] != 'gateway':
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
        kernel_image = _kernel_executable_identity(q.proc_root, pid, unit.executable)
        with (q.proc_root / str(pid) / 'cmdline').open('rb') as handle:
            command = handle.read(32769)
        if len(command) > 32768 or command != b'\x00'.join(a.encode() for a in argv) + b'\x00':
            raise ValueError('session Gateway launch identity unknown')
        if hashlib.sha256(command).hexdigest() != process.get('cmdlineDigest'):
            raise ValueError('session Gateway command drift')
        endpoint = _endpoint_identity(q.proc_root, pid, q.endpoint_port, q.runtime_uid)
        wrapper_identity=_wrapper_identity(q.sdk.wrapper_entry,q.runtime_uid,q.sdk.wrapper_sha256)
        sources=tuple((str(q.code.root/relative),digest) for relative,digest,_size in measurement.records)
        probe_payload=dict(schema=1,mode='probe',sdkEntry=str(q.code.root/q.sdk.entry_relative),
            sources=[dict(path=p,sha256=d) for p,d in sources],endpoint=f'ws://127.0.0.1:{q.endpoint_port}',
            server=dict(version=q.sdk.server_version,buildId=q.sdk.server_build_id,bootId=None),method='health',params={})
        response=_run_sdk_probe((str(unit.executable),str(q.sdk.wrapper_entry),json.dumps(probe_payload,sort_keys=True,separators=(',',':'))),
            environment=_rpc_environment(q.rpc_environment),cwd=q.code.root)
        hello,_=validate_sdk_response(response,version=q.sdk.server_version,build_id=q.sdk.server_build_id,probe=True)
        protocol_version='4.0.0'
        capabilities=tuple(c for c in q.contract.supported_capabilities if c in hello['methods'])
        binary = sha256_file(str(cli))
        after = read_process_identity(pid, q.proc_root)
        if (not identities_match(process, after)[0]
                or gateway_state_reader() != service
                or _kernel_executable_identity(q.proc_root, pid, unit.executable) != kernel_image
                or measure_content_artifact(q.code) != measurement
                or _endpoint_identity(q.proc_root, pid, q.endpoint_port, q.runtime_uid) != endpoint
                or _wrapper_identity(q.sdk.wrapper_entry,q.runtime_uid,q.sdk.wrapper_sha256)!=wrapper_identity
                or _code_identity(q.code) != code_identity
                or binding_identity(read_unit_binding(current, unit='openclaw-gateway.service',
                    read_properties=unit_properties_reader, clock_ms=clock_ms,
                    unit_roots=q.unit_roots, owner_uid=q.runtime_uid)) != binding_identity(unit)
                or _script_source_route(q.cli_entry, owner_uid=q.runtime_uid) != (cli, route)):
            raise ValueError('session runtime observation drift')
        identity = (measurement, code_identity, route, binding_identity(unit), binary, endpoint, kernel_image,
                    tuple(after.get(field) for field in IDENTITY_FIELDS), q.provenance_ref, protocol_version, q.rpc_environment, wrapper_identity, hello['bootId'],tuple(sorted(hello['methods'])))
        launcher = SessionRpcLauncher(unit.executable, q.sdk.wrapper_entry, unit.executable_sha256,
            unit.executable_route, wrapper_identity, f'ws://127.0.0.1:{q.endpoint_port}', q.rpc_environment,
            q.code.root/q.sdk.entry_relative,sources,q.sdk.server_version,q.sdk.server_build_id,hello['bootId'],q.code.root)
        if pinned['identity'] is None:
            pinned.update(identity=identity, launcher=launcher)
        elif pinned['identity'] != identity:
            raise ValueError('session runtime binding drift')
        return AdapterDescriptor('openclaw', q.contract.adapter_id, q.code.package_version,
            protocol_version, '', current.node_id, current.generation, clock_ms(),
            capabilities, 'runtime-owned', str(cli), str(cli), binary, binary,
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
