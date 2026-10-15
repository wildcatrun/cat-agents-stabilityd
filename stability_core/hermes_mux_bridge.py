"""One-shot governed Hermes SDK adapter; never dispatch a service fallback."""
import json
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
        from importlib.util import spec_from_file_location
        origin = self.origins.get(fullname)
        if origin is None:
            return None
        package = fullname in {'hermes_cli', 'gateway'}
        return spec_from_file_location(fullname, origin,
            loader=FixedSourceLoader(origin, self.expected[origin], self.fence),
            submodule_search_locations=[str(Path(origin).parent)] if package else None)


def prepare_runtime_imports(code_root, pins, fence=None):
    from importlib.machinery import BuiltinImporter, FrozenImporter, PathFinder
    if any(name in sys.modules for name in MUX_RUNTIME_MODULES):
        raise ValueError('mux runtime module was already loaded before qualification')
    origins = qualified_module_origins(code_root, pins, search_paths=tuple(sys.path))
    expected = {str(path): digest for path, digest in pins}
    if fence is None:
        def fence():
            for path, digest in pins:
                if _read_program_source(Path(path), owner_uid=os.geteuid())[1] != digest:
                    raise ValueError('mux fixed loader source window changed')
    sys.path[:] = [str(code_root)] + [p for p in sys.path if p and p != str(code_root)]
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

def execute(payload):
    if (type(payload) is not dict or set(payload) != {'profile', 'verb', 'home', 'hostHome', 'socket', 'peer', 'homeIdentity', 'sourcePins', 'codeRoot', 'serveUnserved'}
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
    pins = payload['sourcePins']
    origins = prepare_runtime_imports(Path(payload['codeRoot']), pins,
                                      fence=lambda: verify_effect_window(payload))
    sys.argv = ['hermes', '-p', profile, 'gateway', verb]
    import hermes_cli.main  # Reviewed actual CLI profile preparse, before gateway imports.
    from hermes_cli import gateway
    from hermes_cli.profiles import parked_marker_path, profile_is_standalone
    from hermes_constants import get_hermes_home
    from gateway import control_socket
    from hermes_cli.gateway_profile_lifecycle import profile_lifecycle
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
