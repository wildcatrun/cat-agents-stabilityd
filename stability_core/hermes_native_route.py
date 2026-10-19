"""Finite reviewed Hermes source-window and native standalone route.

Independent reviewed expected source identities bind the actual profile/home/
standalone implementation. This does not prove all Python dependencies or loaded
memory bytes. A native route cannot certify mux CLI/schema capabilities.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shlex

from .effect_capability import EffectRequest, EffectOperation
from .unit_capability import read_unit_binding, binding_identity
from .hermes_environment_source import read_environment_source
from .hermes_profile_config import read_profile_config
from .hermes_profile_live import observe_profile_live
from .hermes_unit_route import validate_profile_argv
from .hermes_environment_source import _read_environment_source_projection
from .hermes_unit_environment import resolve_environment_file_sources
from .hermes_dotenv_projection import CONTROL_KEYS, IMPORT_KEYS
import stat


def _read_program_source(path, *, owner_uid, include_bytes=False):
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('native source scope invalid')
    identity = lambda x: (x.st_dev, x.st_ino, x.st_uid, x.st_mode, x.st_nlink,
                           x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    parents = []
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner_uid} or info.st_mode & 0o022:
            raise ValueError('native source parent untrusted')
        parents.append((parent, (info.st_dev, info.st_ino, info.st_uid, info.st_mode)))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid not in {0, owner_uid}
                or before.st_mode & 0o022 or before.st_nlink != 1 or before.st_size > 2097152):
            raise ValueError('native source ownership or budget')
        raw = bytearray()
        while len(raw) <= 2097152:
            part = os.read(fd, min(65536, 2097153-len(raw)))
            if not part: break
            raw.extend(part)
        if (len(raw) > 2097152 or identity(before) != identity(os.fstat(fd))
                or identity(before) != identity(path.lstat())
                or any((p.lstat().st_dev, p.lstat().st_ino, p.lstat().st_uid, p.lstat().st_mode) != i
                       for p, i in parents)):
            raise ValueError('native source read drift')
        result = (str(path), hashlib.sha256(raw).hexdigest(), identity(before), tuple(parents))
        return (result, bytes(raw)) if include_bytes else result
    finally:
        os.close(fd)


@dataclass(frozen=True)
class NativeQualification:
    owner_uid: int
    runtime_root: Path
    unit_roots: tuple
    argv: tuple
    executable_sha256: str
    # Reviewed finite profile/standalone launch source window. This is not an
    # assertion about every Python/site dependency or already loaded bytes.
    sources: tuple  # (absolute Path, independently expected sha256)
    absent_sources: tuple
    manager_sha256: str
    environment_sha256: str
    provenance_ref: str
    target_profile: str = ''  # Qualification scope, not a member registry.
    semantics: str = 'reviewed-hermes-profile-standalone-source-window-v1'
    environment_sha256s: tuple = ()  # Immutable reviewed alternatives; never measured admission.


# Shared adapter installation context, deliberately no per-agent member list.
# A reviewed installation qualifier may supply this; payload/env cannot.
NATIVE_QUALIFICATION = None


def _digest(raw):
    if type(raw) is not str or len(raw.encode()) > 32768:
        raise ValueError('native environment observation budget')
    return hashlib.sha256(raw.encode()).hexdigest()


def _environment_digests(qualification):
    """One legacy digest or a finite reviewed set, never ambient approval."""
    single, alternatives = qualification.environment_sha256, qualification.environment_sha256s
    valid = lambda value: type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None
    if type(alternatives) is not tuple:
        raise ValueError('native environment digest set refused')
    if alternatives:
        if (single != '' or not 1 <= len(alternatives) <= 16
                or any(not valid(value) for value in alternatives)
                or len(set(alternatives)) != len(alternatives)):
            raise ValueError('native environment digest set refused')
        return alternatives
    if not valid(single):
        raise ValueError('native environment digest refused')
    return (single,)


def _source_scope(source):
    # Directory birth/owner/mode are routing identity. Directory timestamps and
    # link counts legitimately change when the gateway writes other files.
    return (source.path, source.present, source.sha256, source.identity,
            tuple((path, identity[:4]) for path, identity in source.ancestors),
            source.missing_ancestor)


def _live_scope(observation):
    if not observation.live:
        raise ValueError('native profile not live')
    records = dict(observation.metadata)
    home = records.get(str(observation.home))
    if home is None or not stat.S_ISDIR(home[3]):
        raise ValueError('native profile directory identity unavailable')
    # The live reader already validates owned nofollow directories/markers and
    # tombstone absence. Keep inode/owner/mode identity, excluding volatile
    # marker size/mtime/ctime and directory link count.
    return {path: identity[:4] if identity is not None else None
            for path, identity in records.items()}


def _same_live_scope(before, after):
    # Newly created safe markers are allowed; an existing marker/directory may
    # not disappear or be replaced. Unsafe files and tombstones fail upstream.
    return all(expected is None or after.get(path) == expected
               for path, expected in before.items())


class NativeRoute:
    """Captures the qualification once; observations always come from readers."""
    def __init__(self, qualification, request, profile, *, read_properties,
                 read_environment, read_manager, clock_ms):
        q = qualification
        if (type(q) is not NativeQualification or type(request) is not EffectRequest
                or request.operation is not EffectOperation.SYSTEMD_UNIT
                or type(q.owner_uid) is not int or q.owner_uid != os.geteuid()
                or q.target_profile != profile
                or q.semantics != 'reviewed-hermes-profile-standalone-source-window-v1'
                or not q.provenance_ref.startswith('evidence://')
                or request.action_type not in {'hermes.gateway.restart', 'hermes.profile.lifecycle'}
                or request.target != ('hermes-gateway:' if request.action_type == 'hermes.gateway.restart'
                                      else 'hermes-profile:') + profile
                or type(q.sources) is not tuple or not q.sources
                or type(q.absent_sources) is not tuple):
            raise ValueError('native qualification unavailable')
        self._approved_environment_digests = _environment_digests(q)
        validate_profile_argv(q.argv, profile)
        if not {'main.py', 'profiles.py', 'gateway_multiplex_mode.py'} <= {p.name for p, _ in q.sources}:
            raise ValueError('native profile and standalone source window missing')
        self.q, self.request, self.profile = q, request, profile
        self.unit = 'hermes-gateway-' + profile + '.service'
        self._properties, self._environment = read_properties, read_environment
        self._manager, self._clock, self._pin = read_manager, clock_ms, None
        self.verify()

    def _observe(self):
        q = self.q
        manager_before = self._manager()
        environment_before = self._environment(self.unit)
        if (_digest(manager_before) != q.manager_sha256
                or _digest(environment_before) not in self._approved_environment_digests):
            raise ValueError('native effective launch environment unqualified')
        properties = dict(line.split('=', 1) for line in environment_before.splitlines())
        home = q.runtime_root / 'profiles' / self.profile
        if properties.pop('WorkingDirectory', None) != str(home):
            raise ValueError('native profile cwd drift')
        if properties.get('PassEnvironment') or properties.get('UnsetEnvironment'):
            raise ValueError('native environment launch subset unsupported')
        values = dict(token.split('=', 1) for token in shlex.split(properties.get('Environment', '')))
        if values.get('HERMES_HOME') != str(home):
            raise ValueError('native profile home environment drift')
        environment_text = '\n'.join(k + '=' + v for k, v in properties.items()) + '\n'
        environment_files = []
        def no_control_override(raw):
            # systemd EnvironmentFile performs no variable expansion. This
            # closed subset accepts ordinary secret assignments while refusing
            # every routing/loader control assignment and continuations.
            text = raw.decode('utf-8')
            if '\\' in text or '\x00' in text:
                raise ValueError('native environment file syntax unsupported')
            for token in shlex.split(text, comments=True):
                key, separator, _value = token.partition('=')
                if not separator or key in CONTROL_KEYS | IMPORT_KEYS:
                    raise ValueError('native environment file routing control unsupported')
            return True
        for path, optional in resolve_environment_file_sources(environment_text):
            observed, _projection = _read_environment_source_projection(path,
                owner_uid=q.owner_uid, optional=optional, projector=no_control_override)
            environment_files.append(observed)
        binding = read_unit_binding(self.request, unit=self.unit,
            read_properties=self._properties, clock_ms=self._clock,
            unit_roots=q.unit_roots, owner_uid=q.owner_uid)
        if (binding.effective_config.execstart_argv != q.argv
                or binding.executable_sha256 != q.executable_sha256):
            raise ValueError('native launch route unqualified')
        sources, paths = [], set()
        for path, expected in q.sources:
            if (not isinstance(path, Path) or path in paths
                    or type(expected) is not str or not re.fullmatch('[0-9a-f]{64}', expected)):
                raise ValueError('native qualified source scope invalid')
            paths.add(path)
            observed = _read_program_source(path, owner_uid=q.owner_uid)
            if observed[1] != expected:
                raise ValueError('native qualified source changed')
            sources.append(observed)
        absent = []
        for path in q.absent_sources:
            if not isinstance(path, Path) or path in paths:
                raise ValueError('native absent source scope invalid')
            paths.add(path)
            observed = read_environment_source(path, owner_uid=q.owner_uid, optional=True)
            if observed.present:
                raise ValueError('native previously absent launch source appeared')
            absent.append(observed)
        config = read_profile_config(q.runtime_root / 'profiles' / self.profile,
            profile=self.profile, runtime_root=q.runtime_root, owner_uid=q.owner_uid)
        if not config.standalone:
            raise ValueError('native route is not standalone')
        live = observe_profile_live(q.runtime_root, profile=self.profile, owner_uid=q.owner_uid)
        if live.live is not True:
            raise ValueError('native profile not live')
        # Whole window recheck, not independent samples of changed source sets.
        if (self._manager() != manager_before or self._environment(self.unit) != environment_before
                or tuple(_read_program_source(p, owner_uid=q.owner_uid) for p, _ in q.sources) != tuple(sources)
                or tuple(read_environment_source(p, owner_uid=q.owner_uid, optional=True)
                         for p in q.absent_sources) != tuple(absent)):
            raise ValueError('native source window drift')
        if tuple(read_environment_source(s.path, owner_uid=q.owner_uid, optional=True)
                 for s in environment_files) != tuple(environment_files):
            raise ValueError('native environment file window drift')
        final_binding = read_unit_binding(self.request, unit=self.unit,
            read_properties=self._properties, clock_ms=self._clock,
            unit_roots=q.unit_roots, owner_uid=q.owner_uid)
        final_config = read_profile_config(home, profile=self.profile,
            runtime_root=q.runtime_root, owner_uid=q.owner_uid)
        final_live = observe_profile_live(q.runtime_root, profile=self.profile, owner_uid=q.owner_uid)
        if (binding_identity(binding) != binding_identity(final_binding) or config != final_config
                or not _same_live_scope(_live_scope(live), _live_scope(final_live))):
            raise ValueError('native closing unit or profile window drift')
        return (binding_identity(binding), tuple(sources), tuple(_source_scope(s) for s in absent),
                tuple(_source_scope(s) for s in environment_files), config,
                _digest(environment_before), _live_scope(final_live))

    def verify(self):
        observed = self._observe()
        if self._pin is None:
            self._pin = observed
        elif (observed[:-1] != self._pin[:-1]
              or not _same_live_scope(self._pin[-1], observed[-1])):
            raise ValueError('native route identity drift')
        else:
            # A safe marker created by the operation becomes an existing
            # identity for later observations; do not allow its replacement
            # forever merely because it was absent in the first observation.
            promoted = dict(observed[-1])
            promoted.update({path: identity for path, identity in self._pin[-1].items()
                             if identity is not None})
            self._pin = (*self._pin[:-1], promoted)
        return 'evidence://hermes-native-route/sha256/' + hashlib.sha256(repr(observed).encode()).hexdigest()

    def argv(self, verb):
        if verb not in {'restart', 'start', 'stop'}:
            raise ValueError('native operation refused')
        return ('/usr/bin/env', 'XDG_RUNTIME_DIR=/run/user/' + str(self.q.owner_uid),
                'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/' + str(self.q.owner_uid) + '/bus',
                '/usr/bin/systemctl', '--user', verb, self.unit)

    def state_argv(self):
        return (*self.argv('start')[:-2], 'show', self.unit,
                '--property=ActiveState,SubState')


@dataclass(frozen=True)
class MuxQualification:
    """Independently reviewed CLI/protocol source window, never an action grant."""
    owner_uid: int
    runtime_root: Path
    target_profile: str
    interpreter_entry: Path
    interpreter_sha256: str
    cli_entry: Path
    cli_sha256: str
    sources: tuple
    environment: tuple
    cwd: Path
    socket_path: Path
    host_home: Path
    peer_cmdline_digest: str
    peer_boot_id: str
    provenance_ref: str
    code_root: Path | None = None
    bridge_entry: Path | None = None
    bridge_sha256: str = ''
    protocol: int = 1
    semantics: str = 'reviewed-hermes-mux-cli-logical-membership-v1'
    pm_binding: tuple = ()


MUX_PM_BINDING_FIELDS = frozenset({
    'semantics', 'ownerHome', 'installState', 'selectedVenv', 'interpreter',
    'interpreterSha256', 'factsSha256', 'receiptPath', 'receiptSha256', 'dependencyStamp',
})


def freeze_mux_pm_binding(value):
    """Validate a reviewed declaration without manufacturing live approval."""
    if (type(value) is not dict or set(value) != MUX_PM_BINDING_FIELDS
            or any(type(v) is not str or not v or len(v) > 4096 or '\x00' in v for v in value.values())
            or value['semantics'] != 'reviewed-hermes-pm-bootstrap-v1'):
        raise ValueError('mux PM binding declaration refused')
    for key in ('interpreterSha256', 'factsSha256', 'receiptSha256'):
        if re.fullmatch(r'[0-9a-f]{64}', value[key]) is None:
            raise ValueError('mux PM binding digest refused')
    for key in ('ownerHome', 'installState', 'selectedVenv', 'interpreter', 'receiptPath'):
        if not Path(value[key]).is_absolute() or '..' in Path(value[key]).parts:
            raise ValueError('mux PM binding route refused')
    return tuple(sorted(value.items()))


MUX_QUALIFICATION = None

MUX_RUNTIME_MODULES = (
    'hermes_cli', 'hermes_cli.main', 'hermes_cli.gateway', 'hermes_cli.profiles',
    'hermes_cli.gateway_profile_lifecycle', 'hermes_constants',
    'gateway', 'gateway.control_socket',
)


def qualified_module_origins(code_root, sources, *, search_paths):
    """Inspect the finite contract's real import routes without executing init.

    A same-named, same-hash file elsewhere is insufficient: the actual loader
    must select the reviewed module/package path under the installation root.
    This deliberately makes no statement about every other Python dependency.
    """
    from importlib.machinery import PathFinder, SourceFileLoader
    if not isinstance(code_root, Path) or not code_root.is_absolute() or '..' in code_root.parts:
        raise ValueError('mux code root unavailable')
    approved = {Path(path) for path, _digest in sources}
    origins, locations = {}, {}
    for name in MUX_RUNTIME_MODULES:
        parent = name.rpartition('.')[0]
        paths = locations[parent] if parent else search_paths
        spec = PathFinder.find_spec(name, paths)
        package = name in {'hermes_cli', 'gateway'}
        relative = Path(*name.split('.'))
        expected = code_root / relative / '__init__.py' if package else code_root / relative.with_suffix('.py')
        if (spec is None or type(spec.loader) is not SourceFileLoader
                or spec.origin != str(expected) or expected not in approved
                or spec.loader.path != str(expected)):
            raise ValueError('mux actual module origin not qualified')
        if package:
            if tuple(spec.submodule_search_locations or ()) != (str(expected.parent),):
                raise ValueError('mux actual package route not qualified')
            locations[name] = (str(expected.parent),)
        origins[name] = str(expected)
    return origins


class MuxRoute:
    def __init__(self, qualification, request, profile):
        from .effect_capability import EffectOperation
        q = qualification
        if (type(q) is not MuxQualification or type(q.owner_uid) is not int or q.owner_uid != os.geteuid()
                or type(request) is not EffectRequest
                or q.target_profile != profile or q.protocol != 1 or type(q.protocol) is not int
                or q.semantics != 'reviewed-hermes-mux-cli-logical-membership-v1'
                or not q.provenance_ref.startswith('evidence://')
                or request.operation is not EffectOperation.HERMES_CLI
                or request.action_type not in {'hermes.gateway.restart', 'hermes.profile.lifecycle'}
                or request.target != ('hermes-gateway:' if request.action_type == 'hermes.gateway.restart'
                                      else 'hermes-profile:') + profile
                or type(q.sources) is not tuple or not q.sources
                or type(q.environment) is not tuple
                or not {'main.py', 'profiles.py', 'gateway.py', 'control_socket.py',
                        'gateway_profile_lifecycle.py'} <= {p.name for p, _ in q.sources}
                or not isinstance(q.bridge_entry, Path) or not isinstance(q.code_root, Path)):
            raise ValueError('mux source qualification unavailable')
        self.q, self.request, self.profile, self._pin = q, request, profile, None
        self.last_residency = 'unknown'
        self.verify()

    def _observe(self):
        from .adapter_contract import sha256_file
        from .unit_capability import resolve_unit_executable
        from .hermes_control import query_readonly, profile_residency
        from .session_api_capability import _kernel_executable_identity
        import time
        q = self.q
        home = q.runtime_root / 'profiles' / self.profile
        env = dict(q.environment)
        if (len(env) != len(q.environment) or env.get('HERMES_HOME') != str(home)
                or q.cwd != home or set(env) & IMPORT_KEYS
                or any(type(k) is not str or type(v) is not str or '\x00' in k + v
                       or len(k) > 128 or len(v) > 4096 for k, v in q.environment)):
            raise ValueError('mux fixed launch context refused')
        executable, interpreter_route = resolve_unit_executable(q.interpreter_entry, owner_uid=q.owner_uid)
        cli, cli_route = resolve_unit_executable(q.cli_entry, owner_uid=q.owner_uid)
        if sha256_file(str(executable)) != q.interpreter_sha256 or sha256_file(str(cli)) != q.cli_sha256:
            raise ValueError('mux fixed launcher changed')
        bridge = _read_program_source(q.bridge_entry, owner_uid=q.owner_uid)
        if bridge[1] != q.bridge_sha256:
            raise ValueError('mux governed bridge changed')
        pm_guard = self._pm_guard(required=False)
        pm_identity = pm_guard.initial if pm_guard is not None else None
        sources = []
        for path, expected in q.sources:
            measured = _read_program_source(path, owner_uid=q.owner_uid)
            if measured[1] != expected:
                raise ValueError('mux source window changed')
            sources.append(measured)
        origins = qualified_module_origins(q.code_root, q.sources, search_paths=(str(q.code_root),))
        config = read_profile_config(home, profile=self.profile, runtime_root=q.runtime_root, owner_uid=q.owner_uid)
        if config.standalone:
            raise ValueError('mux target is standalone')
        live = observe_profile_live(q.runtime_root, profile=self.profile, owner_uid=q.owner_uid)
        socket_identity = lambda: (lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_ctime_ns))(q.socket_path.lstat())
        socket_before = socket_identity()
        first = query_readonly(q.socket_path, 'identify', expected_uid=q.owner_uid)
        second = query_readonly(q.socket_path, 'status', expected_uid=q.owner_uid)
        membership = profile_residency(first, second, expected_home=q.host_home,
            profile=self.profile, now_monotonic=time.monotonic())
        if (membership['topology'] != 'multiplex-membership'
                or second.process_identity.get('cmdlineDigest') != q.peer_cmdline_digest
                or second.process_identity.get('bootId') != q.peer_boot_id):
            raise ValueError('mux runtime instance or schema unqualified')
        image = _kernel_executable_identity(Path('/proc'), second.peer_pid, executable)
        final_config = read_profile_config(home, profile=self.profile, runtime_root=q.runtime_root, owner_uid=q.owner_uid)
        final_live = observe_profile_live(q.runtime_root, profile=self.profile, owner_uid=q.owner_uid)
        if (socket_identity() != socket_before or config != final_config or not _same_live_scope(_live_scope(live), _live_scope(final_live))
                or tuple(_read_program_source(p, owner_uid=q.owner_uid) for p, _ in q.sources) != tuple(sources)
                or resolve_unit_executable(q.interpreter_entry, owner_uid=q.owner_uid) != (executable, interpreter_route)
                or resolve_unit_executable(q.cli_entry, owner_uid=q.owner_uid) != (cli, cli_route)
                or _read_program_source(q.bridge_entry, owner_uid=q.owner_uid) != bridge
                or qualified_module_origins(q.code_root, q.sources, search_paths=(str(q.code_root),)) != origins):
            raise ValueError('mux source or launcher window drift')
        # Process identity includes birth/starttime, boot, UID, cmdline and cgroup.
        stable = (str(executable), interpreter_route, str(cli), cli_route, tuple(sources),
                  config, second.process_identity, image, socket_before, bridge, origins, pm_identity, _live_scope(final_live))
        if pm_guard is not None:
            pm_guard.fence()
        self.peer_identity = dict(second.process_identity)
        return stable, membership['residency']

    def verify(self, expected=None):
        observed, residency = self._observe()
        if self._pin is None:
            self._pin = observed
        elif (observed[:-1] != self._pin[:-1] or not _same_live_scope(self._pin[-1], observed[-1])):
            raise ValueError('mux pinned runtime identity drift')
        else:
            promoted = dict(observed[-1])
            promoted.update({p: i for p, i in self._pin[-1].items() if i is not None})
            self._pin = (*self._pin[:-1], promoted)
        if expected is not None and residency != expected:
            raise ValueError('mux logical target residency changed')
        self.last_residency = residency
        return 'evidence://hermes-mux-route/sha256/' + hashlib.sha256(repr((observed, residency)).encode()).hexdigest()

    def _pm_guard(self, *, required):
        value = self.q.pm_binding
        if not value:
            if required:
                raise ValueError('mux PM execution binding unavailable')
            return None  # Old objects remain inspectable, never executable.
        if type(value) is not tuple or any(type(pair) is not tuple or len(pair) != 2 for pair in value):
            raise ValueError('mux PM immutable binding refused')
        declaration = dict(value)
        if freeze_mux_pm_binding(declaration) != value:
            raise ValueError('mux PM immutable binding refused')
        if (declaration['interpreter'] != str(self.q.interpreter_entry)
                or declaration['interpreterSha256'] != self.q.interpreter_sha256
                or declaration['ownerHome'] != str(self.q.runtime_root)):
            raise ValueError('mux PM declaration and launcher differ')
        from .hermes_mux_bridge import PmBootstrapGuard
        return PmBootstrapGuard(dict(codeRoot=str(self.q.code_root),
            home=str(self.q.runtime_root / 'profiles' / self.profile),
            sourcePins=[(str(path), digest) for path, digest in self.q.sources],
            pmBinding=declaration), running_interpreter=False)

    def command(self, verb):
        import json
        if verb not in {'start', 'stop', 'restart'}:
            raise ValueError('mux profile operation refused')
        pm_guard = self._pm_guard(required=True)
        payload = dict(profile=self.profile, verb=verb, pmBinding=dict(self.q.pm_binding),
            home=str(self.q.runtime_root / 'profiles' / self.profile),
            hostHome=str(self.q.host_home), socket=str(self.q.socket_path), peer=self.peer_identity,
            homeIdentity=self._pin[-1][str(self.q.runtime_root / 'profiles' / self.profile)],
            sourcePins=[(str(path), digest) for path, digest in self.q.sources], codeRoot=str(self.q.code_root),
            serveUnserved=verb in {'start', 'restart'} and self.last_residency == 'unserved')
        return ((str(self.q.interpreter_entry), str(self.q.bridge_entry),
                 json.dumps(payload, sort_keys=True, separators=(',', ':'))),
                dict(self.q.environment), self.q.cwd)
