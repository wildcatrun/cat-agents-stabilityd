"""One-shot governed Hermes SDK adapter; never dispatch a service fallback."""
import json
from importlib.util import spec_from_file_location
import os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace

# Fixed plugin code root, not a caller-provided search path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from stability_core.hermes_control import query_readonly, send_profile_effect, profile_residency
from stability_core.process_identity import identities_match
from stability_core.hermes_native_route import _read_program_source, qualified_module_origins, MUX_RUNTIME_MODULES



class FixedSourceLoader:
    """Compile the owned, SHA-checked bytes directly; never consume a pyc."""
    def __init__(self, path, expected, fence):
        self.path, self.expected, self.fence = path, expected, fence

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        record, raw = _read_program_source(Path(self.path), owner_uid=os.geteuid(), include_bytes=True)
        if record[1] != self.expected:
            raise ValueError('mux source loader bytes changed')
        self.fence()
        code = compile(raw, self.path, 'exec', dont_inherit=True)
        exec(code, module.__dict__)
        self.fence()


class FixedRuntimeFinder:
    def __init__(self, origins, expected, fence):
        self.origins, self.expected, self.fence = origins, expected, fence

    def find_spec(self, fullname, path=None, target=None):
        origin = self.origins.get(fullname)
        if origin is None:
            return None
        package = fullname in {'hermes_cli', 'gateway', 'pm'}
        return spec_from_file_location(fullname, origin,
            loader=FixedSourceLoader(origin, self.expected[origin], self.fence),
            submodule_search_locations=[str(Path(origin).parent)] if package else None)


def prepare_runtime_imports(code_root, pins, fence=None):
    from importlib.machinery import BuiltinImporter, FrozenImporter, PathFinder
    bootstrap_modules = ('hermes_bootstrap', 'hermes_cli._early_recovery',
                         'hermes_cli.venv_sync', 'hermes_cli.runtime_state', 'pm', 'pm.environments')
    if any(name in sys.modules for name in (*MUX_RUNTIME_MODULES, *bootstrap_modules)):
        raise ValueError('mux runtime module was already loaded before qualification')
    launch_paths = [str(code_root)] + [p for p in sys.path if p and p != str(code_root)]
    origins = qualified_module_origins(code_root, pins, search_paths=tuple(launch_paths))
    expected = {str(path): digest for path, digest in pins}
    # These bootstrap modules execute before the IPC SDK is guarded. Like the
    # existing finite CLI set, compile their pinned bytes, never ambient pyc.
    from importlib.machinery import PathFinder, SourceFileLoader
    for name in bootstrap_modules:
        parent = name.rpartition('.')[0]
        package = name == 'pm'
        relative = Path(*name.split('.'))
        path = code_root / relative / '__init__.py' if package else code_root / relative.with_suffix('.py')
        search = [str(code_root / Path(*parent.split('.')))] if parent else [str(code_root)]
        spec = PathFinder.find_spec(name, search)
        if (str(path) not in expected or spec is None or type(spec.loader) is not SourceFileLoader
                or spec.origin != str(path) or spec.loader.path != str(path)):
            raise ValueError('mux bootstrap module route unqualified')
        origins[name] = str(path)
    if fence is None:
        def fence():
            for path, digest in pins:
                if _read_program_source(Path(path), owner_uid=os.geteuid())[1] != digest:
                    raise ValueError('mux fixed loader source window changed')
    sys.path[:] = launch_paths
    # Only this finite module set uses the pinned-byte loader. Dependency
    # closure outside it is unchanged and is not claimed as proved here.
    sys.meta_path[:] = [FixedRuntimeFinder(origins, expected, fence), BuiltinImporter, FrozenImporter, PathFinder]
    return origins


def verify_effect_window(payload):
    home = Path(payload['home'])
    for parent in (home, *home.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
            raise ValueError('mux bridge home ownership drift')
    actual = home.lstat()
    if [actual.st_dev, actual.st_ino, actual.st_uid, actual.st_mode] != payload['homeIdentity']:
        raise ValueError('mux bridge profile directory replaced')
    pins = payload['sourcePins']
    if type(pins) is not list or not 1 <= len(pins) <= 128:
        raise ValueError('mux bridge source window budget')
    for path_text, expected_hash in pins:
        if _read_program_source(Path(path_text), owner_uid=os.geteuid())[1] != expected_hash:
            raise ValueError('mux bridge source window drift')


def apply_parked_marker(home, expected_identity, operation):
    """Finite profile marker operation: no followed links and no Path patch."""
    if operation not in {'park', 'unpark'}:
        raise ValueError('mux marker operation refused')
    fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if [info.st_dev, info.st_ino, info.st_uid, info.st_mode] != expected_identity:
            raise ValueError('mux marker profile directory changed')
        name = 'gateway.parked'
        try: current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError: current = None
        if current is not None and (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
                or current.st_uid != os.geteuid() or current.st_mode & 0o022):
            raise ValueError('mux marker unsafe')
        if operation == 'unpark':
            try: os.unlink(name, dir_fd=fd)
            except FileNotFoundError: pass
        else:
            marker_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                                0o600, dir_fd=fd)
            try:
                marker = os.fstat(marker_fd)
                live = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if (not stat.S_ISREG(marker.st_mode) or marker.st_nlink != 1
                        or marker.st_uid != os.geteuid() or marker.st_mode & 0o022
                        or (marker.st_dev, marker.st_ino) != (live.st_dev, live.st_ino)):
                    raise ValueError('mux marker identity drift')
                os.utime(marker_fd, None)
            finally:
                os.close(marker_fd)
    finally:
        os.close(fd)

# This is a finite source-launch contract, not a general PM readiness probe.
# The trusted installation publisher must bind the completed PM generation and
# exact success receipt. Neither a live observation nor this bridge issues pins.
PM_BOOTSTRAP_SEMANTICS = 'reviewed-hermes-pm-bootstrap-v1'
PM_BOOTSTRAP_SOURCES = (
    'hermes_bootstrap.py', 'hermes_cli/_early_recovery.py',
    'hermes_cli/venv_sync.py', 'hermes_cli/runtime_state.py',
    'pm/__init__.py', 'pm/environments.py', 'pyproject.toml', 'uv.lock', 'pm/lock.json', 'install-stamp.json',
)


def _canonical_path(value):
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError('mux PM path unavailable')
    path = Path(value)
    if not path.is_absolute() or '..' in path.parts or path.resolve() != path:
        raise ValueError('mux PM path unqualified')
    return path


class PmBootstrapGuard:
    """Fail closed before runtime imports and every guarded IPC.

    Import-time audit enforcement blocks recovery writes / process handoffs even
    if a marker appears after the first fence. Only PM's existing install lock,
    selected-generation leases and ordinary profile logs may be written while
    imports run. The sticky violation survives runtime exception handlers.
    """
    def __init__(self, payload, *, running_interpreter=True):
        import hashlib
        self.running_interpreter = running_interpreter
        self.root = _canonical_path(payload['codeRoot'])
        self.home = _canonical_path(payload['home'])
        binding = payload.get('pmBinding')
        fields = {'semantics', 'ownerHome', 'installState', 'selectedVenv',
                  'interpreter', 'interpreterSha256', 'factsSha256',
                  'receiptPath', 'receiptSha256', 'dependencyStamp'}
        if type(binding) is not dict or set(binding) != fields or binding['semantics'] != PM_BOOTSTRAP_SEMANTICS:
            raise ValueError('mux PM binding unavailable')
        self.binding = binding
        self.owner = _canonical_path(binding['ownerHome'])
        key = hashlib.sha256(str(self.root).encode()).hexdigest()[:16]
        self.state = _canonical_path(binding['installState'])
        self.venv = _canonical_path(binding['selectedVenv'])
        if (self.state != self.owner / 'installs' / key
                or self.venv.parent.parent != self.state / 'environments'
                or self.venv.name != 'venv'
                or self.home.parent != self.owner / 'profiles'):
            raise ValueError('mux PM generation route refused')
        self.interpreter = Path(binding['interpreter'])
        if (not self.interpreter.is_absolute() or '..' in self.interpreter.parts
                or self.interpreter.parent != self.venv / 'bin'):
            raise ValueError('mux PM interpreter route refused')
        self.receipt = _canonical_path(binding['receiptPath'])
        self.pins = dict(payload['sourcePins'])
        if any(str(self.root / relative) not in self.pins for relative in PM_BOOTSTRAP_SOURCES):
            raise ValueError('mux PM source closure unavailable')
        for field in ('interpreterSha256', 'factsSha256', 'receiptSha256'):
            if type(binding[field]) is not str or re.fullmatch(r'[0-9a-f]{64}', binding[field]) is None:
                raise ValueError('mux PM digest unavailable')
        if type(binding['dependencyStamp']) is not str or not binding['dependencyStamp']:
            raise ValueError('mux PM dependency stamp unavailable')
        self.active = False
        self.violation = False
        self.violation_event = None
        self.violation_frames = ()
        self.initial = None
        self.fence()

    def _read(self, path, digest=None):
        record, raw = _read_program_source(path, owner_uid=os.geteuid(), include_bytes=True)
        if digest is not None and record[1] != digest:
            raise ValueError('mux PM artifact drift')
        return record, raw

    def _markers(self):
        git = self.root / '.git'
        if git.is_file():
            _record, text = self._read(git)
            value = text.decode('utf-8').strip()
            if not value.startswith('gitdir:'):
                raise ValueError('mux PM git route refused')
            git = (self.root / value[7:].strip()).resolve()
        paths = [self.root / name for name in (
            '.hermes-update-zip-swap', 'hermes_cli.hermes-update-old',
            '.update-incomplete', '.lazy-refresh-incomplete')]
        paths += [git / 'hermes-update-pull', self.owner / '.hermes-update-in-progress']
        paths += [self.state / name for name in (
            'publication.json', '.repair-incomplete', 'source-completion-pending',
            'source-completion-attempts')]
        for path in paths:
            # lexists also rejects broken links and directory-shaped markers.
            if os.path.lexists(path):
                raise ValueError('mux PM update or recovery pending')

    def fence(self):
        if self.violation:
            raise ValueError('mux bootstrap attempted forbidden side effect')
        self._markers()
        records = [self._read(self.root / name, self.pins[str(self.root / name)])[0]
                   for name in PM_BOOTSTRAP_SOURCES]
        _stamp_record, raw = self._read(self.root / 'install-stamp.json', self.pins[str(self.root / 'install-stamp.json')])
        stamp = json.loads(raw)
        if (stamp.get('schemaVersion') != 2 or stamp.get('updateMechanism') != 'external'
                or stamp.get('source') != 'local' or type(stamp.get('dirty')) is not bool
                or type(stamp.get('commit')) is not str
                or re.fullmatch(r'[0-9a-f]{40}', stamp['commit']) is None
                or stamp['commit'] == '0' * 40 or 'runtimeDir' in stamp):
            raise ValueError('mux immutable source stamp refused')
        fact_record, raw = self._read(self.state / 'facts.json', self.binding['factsSha256'])
        fact = json.loads(raw).get('packages', {}).get('venv', {})
        if (fact.get('environment') != str(self.venv)
                or fact.get('stamp') != self.binding['dependencyStamp']
                or type(fact.get('extras')) is not list or 'all' not in fact['extras']):
            raise ValueError('mux PM selected state refused')
        receipt_record, raw = self._read(self.receipt, self.binding['receiptSha256'])
        receipt = json.loads(raw)
        if (receipt.get('schema') != 1 or receipt.get('kind') != 'sync'
                or receipt.get('outcome') != 'ok' or type(receipt.get('exit_code')) is not int
                or receipt['exit_code'] != 0 or not receipt.get('finished_at')):
            raise ValueError('mux PM success receipt refused')
        # Read the actual kernel interpreter through its canonical owned route;
        # venv/bin/python itself may be the official symlink to that interpreter.
        from stability_core.unit_capability import resolve_unit_executable
        from stability_core.adapter_contract import sha256_file
        executable, route = resolve_unit_executable(self.interpreter, owner_uid=os.geteuid())
        if executable.stat().st_size > 256 * 1024 * 1024:
            raise ValueError('mux PM interpreter binary budget')
        digest = sha256_file(str(executable))
        if (digest != self.binding['interpreterSha256']
                or resolve_unit_executable(self.interpreter, owner_uid=os.geteuid()) != (executable, route)):
            raise ValueError('mux PM interpreter binary drift')
        interpreter_record = (str(executable), digest, route)
        if self.running_interpreter and (Path(sys.executable).resolve() != self.interpreter.resolve()
                or Path(sys.prefix).resolve() != self.venv
                or sys.version_info[:2] != (3, 14)):
            raise ValueError('mux PM running interpreter refused')
        cfg, _ = self._read(self.venv / 'pyvenv.cfg')
        current = (tuple(records), fact_record, receipt_record, interpreter_record, cfg)
        if self.initial is not None and current != self.initial:
            raise ValueError('mux PM publication changed')
        self.initial = current

    def _allowed_write(self, value):
        if not isinstance(value, (str, bytes, os.PathLike)):
            return False
        path = Path(os.fsdecode(value)).absolute()
        if '..' in path.parts:
            return False
        # Canonical ancestors prevent a log / lease alias escaping its scope.
        if path.parent.resolve() != path.parent or path.is_symlink():
            return False
        if path == self.state / '.install.lock':
            info = path.lstat()
            return (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and not info.st_mode & 0o022)
        leases = self.venv.parent / '.leases'
        if path == leases:
            return True
        if path.parent == leases and re.fullmatch(r'[0-9a-f]{32}', path.name):
            return True
        return any(path.is_relative_to(home / 'logs') for home in (self.owner, self.home))

    def audit(self, event, args):
        if not self.active:
            return
        forbidden = event in {'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn',
                              'os.fork', 'os.forkpty', 'socket.connect', 'socket.bind',
                              'os.chown', 'os.link', 'os.symlink'}
        paths = ()
        if event == 'open':
            path, mode, flags = args
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                paths = (path,)
                if isinstance(path, (str, bytes)) and Path(os.fsdecode(path)) == self.state / '.install.lock' and flags & os.O_TRUNC:
                    forbidden = True
        elif event in {'os.remove', 'os.rmdir', 'os.mkdir', 'os.rename', 'os.link', 'os.symlink',
                       'os.chmod', 'os.chown', 'os.truncate', 'os.utime'}:
            paths = args[:2] if event in {'os.rename', 'os.link', 'os.symlink'} else args[:1]
            # mkdir(exist_ok=True) on an already owned directory has no effect.
            if event == 'os.mkdir' and isinstance(paths[0], (str, bytes)):
                candidate = Path(os.fsdecode(paths[0]))
                if candidate.is_dir() and not candidate.is_symlink():
                    paths = ()
            if event == 'os.chmod':
                forbidden = True
            if event == 'os.chmod' and isinstance(paths[0], (str, bytes)):
                candidate = Path(os.fsdecode(paths[0]))
                if (candidate.is_absolute() and '..' not in candidate.parts
                        and candidate.is_relative_to(self.home) and candidate.resolve() == candidate
                        and type(args[1]) is int and (len(args) < 3 or args[2] in (-1, None))):
                    info = candidate.lstat()
                    if (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                            and not info.st_mode & 0o022 and stat.S_IMODE(info.st_mode) == args[1]):
                        paths = ()  # Existing directory, exactly identical bits.
                        forbidden = False
        if forbidden or any(not self._allowed_write(path) for path in paths):
            self.violation = True
            self.violation_event = event
            frames = []
            frame = sys._getframe(1)
            for _ in range(8):
                if frame is None:
                    break
                frames.append((Path(frame.f_code.co_filename).name, frame.f_lineno, frame.f_code.co_name))
                frame = frame.f_back
            self.violation_frames = tuple(frames)
            raise PermissionError('mux bootstrap side effect refused')

    def begin_imports(self):
        self.fence()
        # Official bootstrap respects operator temp variables before it can
        # chmod/prune profile scratch. Use an existing owned log directory,
        # already allowed for ordinary import metadata, never a prune marker.
        temp = self.home / 'logs'
        for path in (temp, *temp.parents):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                    or info.st_mode & 0o022):
                raise ValueError('mux bootstrap log temp route refused')
        os.environ.pop('HERMES_SCRATCH_DIR', None)
        for key in ('TMPDIR', 'TMP', 'TEMP'):
            os.environ[key] = str(temp)
        os.environ['HERMES_DISABLE_LAZY_INSTALLS'] = '1'
        sys.dont_write_bytecode = True
        sys.addaudithook(self.audit)
        self.active = True

    def finish_imports(self):
        self.active = False
        self.fence()


def execute(payload):
    if (type(payload) is not dict or set(payload) != {'profile', 'verb', 'home', 'hostHome', 'socket', 'peer', 'homeIdentity', 'sourcePins', 'codeRoot', 'serveUnserved', 'pmBinding'}
            or payload['verb'] not in {'start', 'stop', 'restart'}
            or type(payload['serveUnserved']) is not bool
            or (payload['serveUnserved'] and payload['verb'] not in {'start', 'restart'})
            or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', payload['profile'])
            or payload['profile'] == 'default'):
        raise ValueError('mux bridge input scope refused')
    profile, verb = payload['profile'], payload['verb']
    home, host_home, path = (Path(payload[k]) for k in ('home', 'hostHome', 'socket'))
    if any(not p.is_absolute() or '..' in p.parts for p in (home, host_home, path)):
        raise ValueError('mux bridge route refused')
    if os.environ.get('HERMES_HOME') != str(home):
        raise ValueError('mux bridge environment drift')
    verify_effect_window(payload)
    bootstrap = PmBootstrapGuard(payload)
    pins = payload['sourcePins']
    origins = prepare_runtime_imports(Path(payload['codeRoot']), pins,
                                      fence=lambda: verify_effect_window(payload))
    bootstrap.begin_imports()
    sys.argv = ['hermes', '-p', profile, 'gateway', verb]
    import hermes_cli.main  # Reviewed actual CLI profile preparse, before gateway imports.
    from hermes_cli import gateway
    from hermes_cli.profiles import parked_marker_path, profile_is_standalone
    from hermes_constants import get_hermes_home
    from gateway import control_socket
    from hermes_cli.gateway_profile_lifecycle import profile_lifecycle
    bootstrap.finish_imports()
    for name, origin in origins.items():
        loaded = sys.modules.get(name)
        if loaded is not None and (getattr(loaded, '__file__', None) != origin
                or getattr(getattr(loaded, '__spec__', None), 'origin', None) != origin):
            raise ValueError('mux loaded runtime module origin drift')
    verify_effect_window(payload)
    if gateway._current_profile_name() != profile or Path(get_hermes_home()) != home:
        raise ValueError('mux bridge actual CLI target drift')
    # Official lifecycle owns its parked marker. Refuse unsafe existing targets
    # before calling its touch/unlink operations; never follow a foreign link.
    marker = parked_marker_path(home)
    if marker.parent != home:
        raise ValueError('mux bridge parked marker route drift')
    try: info = marker.lstat()
    except FileNotFoundError: pass
    else:
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise ValueError('mux bridge parked marker unsafe')
    peer = payload['peer']
    def controlled_query(requested_home, method, *, params=None, timeout=2):
        bootstrap.fence()
        if Path(requested_home) != host_home:
            return None
        if method in {'identify', 'status'}:
            observation = query_readonly(path, method, expected_uid=peer['uid'])
            if (not identities_match(peer, observation.process_identity)[0]
                    or observation.payload.get('hermes_home') != str(host_home)):
                raise ValueError('mux bridge discovery peer drift')
            return observation.payload
        if method not in {'serve-profile', 'unserve-profile'} or params != {'name': profile}:
            raise ValueError('mux bridge protocol effect refused')
        verify_effect_window(payload)
        if (gateway._current_profile_name() != profile or Path(get_hermes_home()) != home
                or profile_is_standalone(home)):
            raise ValueError('mux actual target changed before effect')
        return send_profile_effect(path, method, profile=profile, expected_identity=peer)
    control_socket.query_gateway_control = controlled_query
    # Bind the logical precondition freshly. SDK helpers get the explicit host
    # and every mutation uses the same-connection peer guard above; discovery
    # records and generic gateway service fallback are never involved.
    import time
    first = query_readonly(path, 'identify', expected_uid=peer['uid'])
    second = query_readonly(path, 'status', expected_uid=peer['uid'])
    if not identities_match(peer, second.process_identity)[0]:
        raise ValueError('mux actuator peer changed')
    membership = profile_residency(first, second, expected_home=host_home,
        profile=profile, now_monotonic=time.monotonic())
    expected = 'unserved' if payload['serveUnserved'] else 'served'
    if membership['topology'] != 'multiplex-membership' or membership['residency'] != expected:
        raise ValueError('mux target logical precondition changed')
    verify_effect_window(payload)
    bootstrap.fence()
    if profile_is_standalone(home):
        raise ValueError('mux target became standalone')
    def confirmed(answer, key):
        if not isinstance(answer, dict) or answer.get(key) != profile or answer.get('error'):
            raise ValueError('mux SDK operation was not confirmed')
    if verb == 'stop':
        apply_parked_marker(home, payload['homeIdentity'], 'park')
        confirmed(control_socket.request_unserve_profile(host_home, profile), 'unserved')
    elif payload['serveUnserved']:
        apply_parked_marker(home, payload['homeIdentity'], 'unpark')
        confirmed(control_socket.request_serve_profile_hot(host_home, profile), 'served')
    elif verb == 'restart':
        confirmed(control_socket.request_unserve_profile(host_home, profile), 'unserved')
        confirmed(control_socket.request_serve_profile_hot(host_home, profile), 'served')
    else:
        raise ValueError('mux start must bind an unserved target')
    print('Qualified host completed the target profile operation.')
    return 0



if __name__ == '__main__':
    try:
        if len(sys.argv) != 2 or len(sys.argv[1]) > 32768:
            raise ValueError('mux bridge input budget')
        exit_code = execute(json.loads(sys.argv[1]))
    except Exception:
        print('Governed profile operation was not confirmed.', file=sys.stderr)
        exit_code = 75
    sys.exit(exit_code)
