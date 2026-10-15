"""Real owned files and Linux UDS/SO_PEERCRED; no synthetic observations."""
import contextlib
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import threading
import tempfile
import subprocess
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import test_hermes_native_route_integration as base
from stability_core import hermes_native_route as routes
from stability_core.process_identity import read_process_identity

BRIDGE_SHA256 = '154b649b19bb7ce30f843a56ea671b395ef60f56cee4b4658c1615cb95a70650'


OFFICIAL_LIFECYCLE = '"""Named-profile lifecycle inside the host gateway, never a service-manager action."""\nfrom __future__ import annotations\n\nfrom hermes_constants import get_hermes_home, get_default_hermes_root\nfrom hermes_cli.profiles import parked_marker_path, profile_is_parked, profile_is_standalone, profiles_to_serve\n\n\ndef _confirmed(answer, key, name):\n    return isinstance(answer, dict) and answer.get(key) == name and not answer.get("error")\n\n\ndef _failure(answer):\n    if isinstance(answer, dict):\n        return answer.get("error") or "host operation is still pending"\n    return "host control socket did not answer"\n\n\ndef profile_lifecycle(command: str, args) -> bool:\n    """True when a named-profile command was handled (including an unconfirmed request)."""\n    from hermes_cli import gateway as gw\n    from gateway.control_socket import request_unserve_profile, request_serve_profile_hot\n\n    name = gw._current_profile_name()\n    if not name or name == "default" or getattr(args, "all", False) or getattr(args, "force", False):\n        return False\n    home = get_hermes_home()\n    if profile_is_standalone(home):\n        # gateway.standalone wins: the host never serves (or parks) an opted-out profile, so its\n        # verbs keep addressing its own gateway process even while a stale host record lists it.\n        return False\n    marker = parked_marker_path(home)\n    if command == "start":\n        if not profile_is_parked(home):\n            return False\n        marker.unlink()\n        owner = gw._host_multiplexer_for_all_verb()\n        if owner is None:\n            from hermes_cli.gateway_multiplex_served import live_default_gateway_pid\n            if live_default_gateway_pid() is None:\n                return False  # Unpark even when today\'s normal start path must start the host first.\n        host_home = owner.home if owner is not None else get_default_hermes_root()\n        answer = request_serve_profile_hot(host_home, name)\n        if _confirmed(answer, "served", name):\n            print(f"Profile \'{name}\' served by the host gateway.")\n        else:\n            print(f"Profile \'{name}\' unparked, but serving was not confirmed: {_failure(answer)}.")\n            print("The host retries on its next rescan (within 30s). Check gateway status.")\n        return True\n\n    # A separate --force gateway still owns its normal process/service lifecycle.\n    if gw.find_gateway_pids():\n        return False\n    owner = gw._served_by_another_host_gateway()\n    if owner is None and not gw.named_profile_served_by_running_multiplexer():\n        return False\n    host_home = owner.home if owner is not None else get_default_hermes_root()\n    if command == "stop":\n        # Persist intent BEFORE teardown: the periodic rescan must not re-add this profile.\n        marker.touch()\n        answer = request_unserve_profile(host_home, name)\n        if _confirmed(answer, "unserved", name):\n            print(f"Profile \'{name}\' parked; its bots and cron are stopped. "\n                  f"Start again with: hermes -p {name} gateway start")\n        else:\n            print(f"Profile \'{name}\' parked, but immediate stop was not confirmed: {_failure(answer)}.")\n            print("The host drops it on its next rescan (within 30s).")\n        return True\n\n    answer = request_unserve_profile(host_home, name)\n    if not _confirmed(answer, "unserved", name):\n        print(f"Profile \'{name}\' restart was not confirmed: {_failure(answer)}.")\n        return True\n    answer = request_serve_profile_hot(host_home, name)\n    if _confirmed(answer, "served", name):\n        print(f"Profile \'{name}\' restarted by the host gateway.")\n    else:\n        print(f"Profile \'{name}\' stopped, but serving was not confirmed: {_failure(answer)}.")\n        print("The host retries on its next rescan (within 30s). Check gateway status.")\n    return True\n\n\ndef print_parked_status() -> bool:\n    """A parked satellite is still installed, but is not a running gateway."""\n    from hermes_cli import gateway as gw\n    name = gw._current_profile_name()\n    if name and name != "default" and profile_is_parked(get_hermes_home()):\n        print(f"Profile \'{name}\': parked (hermes -p {name} gateway start)")\n        return True\n    if not name or name == "default":\n        parked = [profile for profile, home in profiles_to_serve(True, include_parked=True)\n                  if profile != "default" and profile_is_parked(home)]\n        if parked:\n            owner = gw.host_multiplexer_serving()\n            if owner is not None:\n                print(f"Served profiles: {\', \'.join(owner.profiles)}")\n            for profile in parked:\n                print(f"Profile \'{profile}\': parked (hermes -p {profile} gateway start)")\n    return False\n'
OFFICIAL_SDK = 'def request_unserve_profile(home: Path, name: str) -> Optional[dict[str, Any]]:\n    return query_gateway_control(home, "unserve-profile", params={"name": name}, timeout=8.0)\n\ndef request_serve_profile_hot(home: Path, name: str) -> Optional[dict[str, Any]]:\n    return query_gateway_control(home, "serve-profile", params={"name": name}, timeout=8.0)'

ACTUAL_DISCOVERY = 'def _served_by_another_host_gateway(profile_name: str | None = None):\n    """The host gateway serving ``profile_name`` when it is NOT this home\'s own process.\n\n    The owner must never be guarded out of restarting itself: a refusal keyed on "something serves\n    you" would make `hermes gateway restart` impossible for the profile that launched the host\n    process. Guards want "ANOTHER process already serves you", which is this.\n    """\n    gateway = host_multiplexer_serving(profile_name)\n    if gateway is None:\n        return None\n    try:\n        from gateway.status import _get_process_hermes_home, _same_hermes_home\n        if _same_hermes_home(gateway.home, _get_process_hermes_home()):\n            return None\n    except Exception:\n        logger.debug("Host multiplexer home comparison failed", exc_info=True)\n    return gateway'


@contextlib.contextmanager
def mux_fixture(served=True, with_socket=True, discovery_absent=False):
    with base.fixture() as f:
        (f.home / 'config.yaml').write_text('gateway:\n  standalone: false\n')
        cli = f.root / 'main.py'; cli.chmod(0o700)
        socket_temp = tempfile.TemporaryDirectory(prefix='mx-', dir=os.environ.get('TEST_SOCKET_ROOT', str(Path.home())))
        path = Path(socket_temp.name) / 's'
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if with_socket:
            listener.bind(str(path)); path.chmod(0o600); listener.listen(16); listener.settimeout(.1)
        state = dict(served=served, malformed=False, pending=False, ignore_write=False, revoke_owner=False, swap_marker_on_child_read=False); writes = []
        stopped = threading.Event(); failures = []
        def serve():
            while not stopped.is_set():
                try: connection, _ = listener.accept()
                except socket.timeout: continue
                except OSError:
                    if not stopped.is_set(): failures.append('listener-error')
                    return
                with connection:
                    try:
                        raw = bytearray()
                        while b'\n' not in raw and len(raw) <= 4096:
                            part = connection.recv(4096)
                            if not part: break
                            raw.extend(part)
                        if not raw: continue
                        request = json.loads(raw)
                        if state['swap_marker_on_child_read'] and request['verb'] in {'identify','status'}:
                            client_pid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[0]
                            if client_pid != os.getpid():
                                marker=f.home/'gateway.parked'
                                if marker.exists(): marker.unlink()
                                marker.symlink_to(f.root/'foreign-marker-target')
                                state['swap_marker_on_child_read']=False
                        result = dict(protocol=1, kind='hermes-gateway', gateway_state='running',
                            hermes_home=str(f.q.runtime_root), profile='default',
                            served_profiles=['default', 'catbody'] if state['served'] else ['default'])
                        if request['verb'] in {'serve-profile', 'unserve-profile'}:
                            if request.get('params') != {'name': 'catbody'}: raise ValueError('wrong logical target')
                            writes.append(dict(request))
                            if state['revoke_owner']: f.registry['records'].clear()
                            if not state['ignore_write']: state['served'] = request['verb'] == 'serve-profile'
                            result = ({'error': 'host operation is still pending'} if state['pending'] else
                                      {'served' if request['verb'] == 'serve-profile' else 'unserved': 'catbody'})
                        elif request['verb'] == 'identify': result['pid'] = os.getpid()
                        else: result.update(answering_pid=os.getpid(), answered_at=time.time())
                        if state['malformed']: result['served_profiles'] = []
                        connection.sendall(json.dumps(dict(ok=True, protocol=1, id=request['id'], result=result)).encode()+b'\n')
                    except (BrokenPipeError, ConnectionResetError): pass
                    except Exception as exc: failures.append(type(exc).__name__)
        worker = threading.Thread(target=serve, daemon=True)
        if with_socket: worker.start()
        package = f.root / 'hermes_cli'; package.mkdir(); (package / '__init__.py').write_text('')
        gateway_package = f.root / 'gateway'; gateway_package.mkdir(); (gateway_package / '__init__.py').write_text('')
        (package / 'main.py').write_text('# Fixture CLI import; fixed HERMES_HOME supplied by reviewed context.\n')
        helper = 'from __future__ import annotations\nfrom pathlib import Path\nfrom types import SimpleNamespace\nimport os, logging\nlogger = logging.getLogger(__name__)\n'
        helper += '_current_profile_name = lambda: "catbody"\nfind_gateway_pids = lambda: []\n'
        helper += 'host_multiplexer_serving = lambda profile_name=None: None if os.environ.get("FIXTURE_DISCOVERY_ABSENT") == "1" else SimpleNamespace(home=Path(os.environ["FIXTURE_HOST_HOME"]))\n'
        helper += ACTUAL_DISCOVERY + '\n'
        helper += '_host_multiplexer_for_all_verb = _served_by_another_host_gateway\n'
        helper += 'named_profile_served_by_running_multiplexer = lambda: os.environ.get("FIXTURE_DISCOVERY_ABSENT") != "1"\n'
        helper += 'gateway_command = lambda *a: (_ for _ in ()).throw(AssertionError("host service fallback forbidden"))\n'
        (package / 'gateway.py').write_text(helper)
        (package / 'gateway_profile_lifecycle.py').write_text(OFFICIAL_LIFECYCLE)
        (package / 'profiles.py').write_text('from pathlib import Path\n'
            'parked_marker_path = lambda home: Path(home) / "gateway.parked"\n'
            'profile_is_parked = lambda home: parked_marker_path(home).exists()\n'
            'profile_is_standalone = lambda home: False\nprofiles_to_serve = lambda *a, **k: []\n')
        (f.root / 'hermes_constants.py').write_text('from pathlib import Path\nimport os\n'
            'get_hermes_home = lambda: Path(os.environ["HERMES_HOME"])\n'
            'get_default_hermes_root = lambda: Path(os.environ["FIXTURE_HOST_HOME"])\n')
        (gateway_package / 'control_socket.py').write_text('from pathlib import Path\nfrom typing import Optional, Any\n'
            'query_gateway_control = lambda *a, **k: (_ for _ in ()).throw(AssertionError("unbound transport forbidden"))\n' + OFFICIAL_SDK + '\n')
        if not served: (f.home / 'gateway.parked').touch()
        extra_sources = tuple((p, hashlib.sha256(p.read_bytes()).hexdigest()) for p in
            (package / '__init__.py', gateway_package / '__init__.py',
             package / 'main.py', package / 'profiles.py', package / 'gateway.py',
             package / 'gateway_profile_lifecycle.py', gateway_package / 'control_socket.py', f.root / 'hermes_constants.py'))
        # The isolated QA checkout is read-only and owned by its host UID, not
        # DynamicUser. Deploy the exact candidate helpers into this fixture's
        # private owned plugin root; retain production ownership checks.
        candidate_core = Path(routes.__file__).parent
        plugin_root = f.root / 'fixture-plugin'; plugin_root.mkdir(mode=0o700)
        private_core = plugin_root / 'stability_core'; private_core.mkdir(mode=0o700)
        for original in candidate_core.glob('*.py'):
            copied = private_core / original.name
            raw = original.read_bytes(); copied.write_bytes(raw); copied.chmod(0o600)
            if hashlib.sha256(copied.read_bytes()).digest() != hashlib.sha256(raw).digest():
                raise AssertionError('fixture candidate helper copy changed')
        bridge = private_core / 'hermes_mux_bridge.py'
        if hashlib.sha256(bridge.read_bytes()).hexdigest() != BRIDGE_SHA256:
            raise AssertionError('fixture bridge differs from reviewed candidate')
        identity = read_process_identity(os.getpid())
        q = routes.MuxQualification(os.getuid(), f.q.runtime_root, 'catbody', Path(f.q.argv[0]),
            f.q.executable_sha256, cli, hashlib.sha256(base.SOURCES['main.py'].encode()).hexdigest(), f.q.sources + extra_sources,
            (('HOME', str(Path.home())), ('HERMES_HOME', str(f.home)), ('PATH', '/usr/bin:/bin'), ('PYTHONPATH', str(f.root)), ('FIXTURE_HOST_HOME', str(f.q.runtime_root)), ('FIXTURE_DISCOVERY_ABSENT', '1' if discovery_absent else '0')),
            f.home, path, f.q.runtime_root, identity.get('cmdlineDigest',''), identity.get('bootId',''),
            'evidence://reviewed-installed-source-fixture/mux-protocol1', code_root=f.root, bridge_entry=bridge,
            bridge_sha256=BRIDGE_SHA256)
        real_access = os.access
        def fixture_access(path, mode, *args, **kwargs):
            if mode == os.X_OK and Path(path) == cli:
                info = cli.lstat(); noexec = getattr(os, 'ST_NOEXEC', 0)
                if (noexec and os.statvfs(cli).f_flag & noexec and stat.S_ISREG(info.st_mode)
                        and info.st_nlink == 1 and info.st_uid == os.getuid()
                        and info.st_mode & stat.S_IXUSR and not info.st_mode & 0o022):
                    return True
            return real_access(path, mode, *args, **kwargs)
        commands = []
        def effect(route, verb, timeout):
            argv, env, cwd = route.command(verb); commands.append((argv, env, cwd))
            return subprocess.run(list(argv), env=env, cwd=str(cwd), timeout=timeout, text=True, capture_output=True)
        try:
            with mock.patch('os.access', side_effect=fixture_access), \
                 mock.patch.object(routes, 'NATIVE_QUALIFICATION', None), \
                 mock.patch.object(routes, 'MUX_QUALIFICATION', q), \
                 mock.patch.object(base.daemon, 'run_hermes_mux_command', side_effect=effect), \
                 mock.patch.object(base.daemon, 'systemctl_user_show', side_effect=AssertionError('mux must not read profile unit')), \
                 mock.patch.object(base.daemon, 'run_hermes_profile_gateway_cmd', side_effect=AssertionError('qualified mux must not fallback')):
                yield SimpleNamespace(**dict(vars(f), qualification=q, state=state, commands=commands, writes=writes))
        finally:
            stopped.set(); listener.close()
            if with_socket: worker.join(3)
            socket_temp.cleanup()
            if worker.is_alive() or failures: raise AssertionError(('real UDS server failures', failures))


class MuxScopeTests(unittest.TestCase):
    def test_private_plugin_copy_preserves_candidate_bytes_and_owned_reader_boundary(self):
        with mux_fixture(with_socket=False) as f:
            bridge = f.qualification.bridge_entry
            candidate_core = Path(routes.__file__).parent
            self.assertEqual(routes._read_program_source(bridge, owner_uid=os.getuid())[1], BRIDGE_SHA256)
            for original in candidate_core.glob('*.py'):
                copied = bridge.parent / original.name
                self.assertEqual(copied.read_bytes(), original.read_bytes())
                self.assertEqual(copied.stat().st_uid, os.getuid())
            # Model the R36 foreign-owned checkout ancestor without chown or
            # privileges. A foreign UID must still fail before source reading.
            real_lstat = Path.lstat
            foreign_parent = bridge.parent.parent
            def foreign_owner(path, *args, **kwargs):
                info = real_lstat(path, *args, **kwargs)
                if path == foreign_parent:
                    fields = list(info); fields[4] = os.getuid() + 100001
                    return os.stat_result(fields)
                return info
            with mock.patch.object(Path, 'lstat', foreign_owner):
                with self.assertRaisesRegex(ValueError, 'native source parent untrusted'):
                    routes._read_program_source(bridge, owner_uid=os.getuid())

    def test_unknown_context_preserves_existing_path(self):
        with mock.patch.object(routes, 'MUX_QUALIFICATION', None):
            self.assertIsNone(base.daemon.resolve_hermes_mux_route('catbody', 'hermes.profile.lifecycle', 'boot'))

    def test_import_origins_bind_actual_package_and_module_paths_without_execution(self):
        with mux_fixture(with_socket=False) as f:
            origins = routes.qualified_module_origins(f.root, f.qualification.sources, search_paths=(str(f.root),))
            self.assertEqual(origins['hermes_cli.main'], str(f.root / 'hermes_cli/main.py'))
            self.assertEqual(origins['gateway.control_socket'], str(f.root / 'gateway/control_socket.py'))
            without_init = tuple((p, digest) for p, digest in f.qualification.sources if p.name != '__init__.py')
            with self.assertRaises(ValueError):
                routes.qualified_module_origins(f.root, without_init, search_paths=(str(f.root),))

    def test_earlier_sys_path_module_hijack_is_refused_before_init(self):
        with mux_fixture(with_socket=False) as f:
            foreign = f.root / 'foreign'; package = foreign / 'hermes_cli'; package.mkdir(parents=True)
            sentinel = foreign / 'executed'
            (package / '__init__.py').write_text('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').touch()\n')
            with self.assertRaises(ValueError):
                routes.qualified_module_origins(f.root, f.qualification.sources,
                    search_paths=(str(foreign), str(f.root)))
            self.assertFalse(sentinel.exists())

    def test_preloaded_sys_modules_even_with_expected_filename_is_refused(self):
        from stability_core.hermes_mux_bridge import prepare_runtime_imports
        from types import ModuleType
        with mux_fixture(with_socket=False) as f:
            injected = ModuleType('hermes_cli.main'); injected.__file__ = str(f.root / 'hermes_cli/main.py')
            with mock.patch.dict(sys.modules, {'hermes_cli.main': injected}), \
                 self.assertRaises(ValueError):
                prepare_runtime_imports(f.root, f.qualification.sources)

    def test_valid_finite_import_context_remains_fixed_to_reviewed_root(self):
        from stability_core.hermes_mux_bridge import prepare_runtime_imports
        with mux_fixture(with_socket=False) as f, mock.patch.object(sys, 'path', [str(f.root)] + list(sys.path)), \
             mock.patch.object(sys, 'meta_path', list(sys.meta_path)):
            origins = prepare_runtime_imports(f.root, f.qualification.sources)
            self.assertEqual(sys.path[0], str(f.root))
            self.assertEqual(len(origins), len(routes.MUX_RUNTIME_MODULES))

    def test_valid_malicious_pyc_never_executes_for_finite_modules(self):
        from stability_core.hermes_mux_bridge import prepare_runtime_imports, FixedSourceLoader
        from importlib import import_module
        from importlib.util import cache_from_source
        from importlib._bootstrap_external import _code_to_timestamp_pyc
        for module_name, relative in (('hermes_cli', 'hermes_cli/__init__.py'), ('hermes_cli.main', 'hermes_cli/main.py')):
            with self.subTest(module=module_name), mux_fixture(with_socket=False) as f, mock.patch.object(sys, 'pycache_prefix', None):
                source = f.root / relative; sentinel = f.root / 'malicious-cache-executed'
                info = source.stat(); cached = Path(cache_from_source(str(source))); cached.parent.mkdir(exist_ok=True)
                code = compile('from pathlib import Path\nPath(' + repr(str(sentinel)) + ').touch()\n', str(source), 'exec')
                cached.write_bytes(_code_to_timestamp_pyc(code, int(info.st_mtime), info.st_size))
                with mock.patch.dict(sys.modules), mock.patch.object(sys, 'path', [str(f.root)] + list(sys.path)), \
                     mock.patch.object(sys, 'meta_path', list(sys.meta_path)):
                    prepare_runtime_imports(f.root, f.qualification.sources)
                    loaded = import_module(module_name)
                    self.assertIsInstance(loaded.__loader__, FixedSourceLoader)
                    self.assertFalse(sentinel.exists())

    def test_import_time_source_replacement_is_refused_before_any_effect(self):
        from stability_core.hermes_mux_bridge import execute, FixedSourceLoader
        with mux_fixture(with_socket=False) as f:
            info = f.home.stat()
            payload = dict(profile='catbody', verb='stop', home=str(f.home), hostHome=str(f.q.runtime_root),
                socket=str(f.qualification.socket_path), peer={}, homeIdentity=[info.st_dev,info.st_ino,info.st_uid,info.st_mode],
                sourcePins=[(str(p),digest) for p,digest in f.qualification.sources], codeRoot=str(f.root), serveUnserved=False)
            original = FixedSourceLoader.exec_module
            def changed(loader, module):
                original(loader, module)
                if module.__name__ == 'hermes_cli.main':
                    (f.root / 'hermes_cli/profiles.py').write_text('# replaced during import\n')
            with mock.patch.dict(sys.modules), mock.patch.object(sys, 'path', [str(f.root)] + list(sys.path)), \
                 mock.patch.object(sys, 'meta_path', list(sys.meta_path)), mock.patch.object(sys, 'argv', list(sys.argv)), \
                 mock.patch.dict(os.environ, {'HERMES_HOME':str(f.home)}), \
                 mock.patch.object(FixedSourceLoader, 'exec_module', changed), \
                 mock.patch('stability_core.hermes_mux_bridge.send_profile_effect') as effect:
                with self.assertRaises(ValueError): execute(payload)
                effect.assert_not_called()
                self.assertFalse((f.home / 'gateway.parked').exists())

    def test_real_discovery_and_official_restart_decline_missing_record(self):
        from stability_core.hermes_mux_bridge import prepare_runtime_imports
        from importlib import import_module
        with mux_fixture(False, with_socket=False, discovery_absent=True) as f, \
             mock.patch.dict(sys.modules), mock.patch.dict(os.environ, dict(f.qualification.environment)), \
             mock.patch.object(sys, 'path', [str(f.root)] + list(sys.path)), \
             mock.patch.object(sys, 'meta_path', list(sys.meta_path)):
            prepare_runtime_imports(f.root, f.qualification.sources)
            gateway = import_module('hermes_cli.gateway')
            lifecycle = import_module('hermes_cli.gateway_profile_lifecycle')
            self.assertIsNone(gateway._served_by_another_host_gateway())
            self.assertEqual(gateway.find_gateway_pids(), [])
            self.assertFalse(gateway.named_profile_served_by_running_multiplexer())
            self.assertFalse(lifecycle.profile_lifecycle('restart', SimpleNamespace(all=False, force=False)))
            self.assertEqual(f.writes, [])

    def test_nofollow_marker_park_rejects_symlink_swap_after_stat(self):
        from stability_core.hermes_mux_bridge import apply_parked_marker
        with mux_fixture(with_socket=False) as f:
            foreign=f.root/'foreign-marker-target';foreign.write_bytes(b'unchanged')
            before=foreign.stat();home=f.home.stat();expected=[home.st_dev,home.st_ino,home.st_uid,home.st_mode]
            original=os.open;changed=False
            def opened(name,flags,*args,**kwargs):
                nonlocal changed
                if name=='gateway.parked' and 'dir_fd' in kwargs and not changed:
                    os.symlink(str(foreign),name,dir_fd=kwargs['dir_fd']);changed=True
                return original(name,flags,*args,**kwargs)
            with mock.patch('stability_core.hermes_mux_bridge.os.open',side_effect=opened):
                with self.assertRaises((ValueError,OSError)):apply_parked_marker(f.home,expected,'park')
            after=foreign.stat();self.assertTrue(changed)
            self.assertEqual((before.st_ino,before.st_mtime_ns,before.st_size),(after.st_ino,after.st_mtime_ns,after.st_size))
            self.assertEqual(foreign.read_bytes(),b'unchanged')

    def test_unpark_race_only_unlinks_profile_name_without_following_foreign(self):
        from stability_core.hermes_mux_bridge import apply_parked_marker
        with mux_fixture(with_socket=False) as f:
            foreign=f.root/'foreign-marker-target';foreign.write_bytes(b'unchanged');before=foreign.stat()
            marker=f.home/'gateway.parked';marker.touch();home=f.home.stat()
            original=os.unlink;changed=False
            def unlink(name,*args,**kwargs):
                nonlocal changed
                if name=='gateway.parked' and 'dir_fd' in kwargs and not changed:
                    original(name,dir_fd=kwargs['dir_fd']);os.symlink(str(foreign),name,dir_fd=kwargs['dir_fd']);changed=True
                return original(name,*args,**kwargs)
            with mock.patch('stability_core.hermes_mux_bridge.os.unlink',side_effect=unlink):
                apply_parked_marker(f.home,[home.st_dev,home.st_ino,home.st_uid,home.st_mode],'unpark')
            self.assertTrue(changed);self.assertFalse(marker.exists())
            self.assertEqual(foreign.read_bytes(),b'unchanged');self.assertEqual(foreign.stat().st_mtime_ns,before.st_mtime_ns)

    def test_safe_marker_operations_are_profile_scoped_and_idempotent(self):
        from stability_core.hermes_mux_bridge import apply_parked_marker
        with mux_fixture(with_socket=False) as f:
            home=f.home.stat();expected=[home.st_dev,home.st_ino,home.st_uid,home.st_mode]
            apply_parked_marker(f.home,expected,'park');self.assertTrue((f.home/'gateway.parked').is_file())
            apply_parked_marker(f.home,expected,'park')
            apply_parked_marker(f.home,expected,'unpark');apply_parked_marker(f.home,expected,'unpark')
            self.assertFalse((f.home/'gateway.parked').exists())


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(socket, 'SO_PEERCRED'),
                     'pending isolated Linux qualification: real SO_PEERCRED/process image required')
class MuxActualPeerTests(unittest.TestCase):
    def restart(self):
        return base.NativeIntegrationTests().restart()

    def lifecycle(self, active):
        return base.NativeIntegrationTests().lifecycle(active)

    def test_actual_peer_stop_start_and_logical_postcheck(self):
        for served in (False, True):
            with self.subTest(served=served), mux_fixture(served) as f:
                result = self.lifecycle(served)
                self.assertEqual(result.get('ledgerState'), 'succeeded', result)
                self.assertTrue(result['muxRouteUsed']); self.assertFalse(result['nativeRouteUsed'])
                self.assertEqual(len(f.commands), 1)
                argv, env, cwd = f.commands[0]
                self.assertEqual(json.loads(argv[-1])['verb'], 'stop' if served else 'start')
                self.assertNotIn('systemctl', ' '.join(argv)); self.assertEqual(cwd, f.home)
                self.assertEqual(env['HERMES_HOME'], str(f.home))

    def test_restart_uses_target_membership_not_old_unit(self):
        with mux_fixture(False, discovery_absent=True) as f:
            result = self.restart()
            self.assertEqual(result.get('ledgerState'), 'succeeded', result)
            self.assertEqual(len(f.commands), 1)
            self.assertEqual(json.loads(f.commands[0][0][-1])['verb'], 'restart')
            self.assertTrue(json.loads(f.commands[0][0][-1])['serveUnserved'])
            self.assertEqual([r['verb'] for r in f.writes], ['serve-profile'])
            self.assertFalse((f.home / 'gateway.parked').exists())

    def test_pending_receipt_remains_uncertain_without_planned_hibernate(self):
        with mux_fixture(True) as f, mock.patch.object(base.daemon, 'db_set') as write:
            f.state['pending'] = True
            result = self.lifecycle(True)
            self.assertEqual(result.get('ledgerState'), 'uncertain', result)
            self.assertFalse(any('planned' in str(call) for call in write.call_args_list))
            f.state['served'] = True
            self.lifecycle(True)
            self.assertEqual(len(f.commands), 1)

    def test_same_peer_but_wrong_membership_cannot_confirm_stop(self):
        with mux_fixture(True) as f:
            f.state['ignore_write'] = True
            result = self.lifecycle(True)
            self.assertEqual(result.get('ledgerState'), 'uncertain', result)
            self.assertEqual(len(f.commands), 1)

    def test_source_drift_and_schema_refusal_zero_effect(self):
        for kind in ('source', 'schema'):
            with self.subTest(kind=kind), mux_fixture(True) as f:
                if kind == 'source': f.code.write_text(base.SOURCES['main.py']+'# drift\n')
                else: f.state['malformed'] = True
                self.assertEqual(self.lifecycle(True)['result'], 'blocked')
                self.assertEqual(f.commands, [])

    def test_peer_boot_or_cmdline_not_independently_qualified_zero_effect(self):
        with mux_fixture(True) as f, mock.patch.object(routes, 'MUX_QUALIFICATION',
                replace(f.qualification, peer_cmdline_digest='0'*64)):
            self.assertEqual(self.lifecycle(True)['result'], 'blocked')
            self.assertEqual(f.commands, [])

    def test_missing_discovery_stop_uses_explicit_sdk_without_service_fallback(self):
        with mux_fixture(True, discovery_absent=True) as f:
            result = self.lifecycle(True)
            self.assertEqual(result.get('ledgerState'), 'succeeded', result)
            self.assertEqual(len(f.commands), 1)
            self.assertEqual([r['verb'] for r in f.writes], ['unserve-profile'])

    def test_write_connection_checks_expected_birth_before_send(self):
        from stability_core.hermes_control import send_profile_effect
        with mux_fixture(True) as f:
            peer = read_process_identity(os.getpid()); peer['starttime'] += 1
            with self.assertRaises(ValueError):
                send_profile_effect(f.qualification.socket_path, 'unserve-profile', profile='catbody', expected_identity=peer)
            self.assertEqual(f.writes, [])

    def test_posteffect_registry_revocation_keeps_outcome_uncertain(self):
        with mux_fixture(True) as f, mock.patch.object(base.daemon, 'db_set') as write:
            f.state['revoke_owner'] = True
            result = self.lifecycle(True)
            self.assertEqual(result.get('ledgerState'), 'uncertain', result)
            self.assertEqual(len(f.writes), 1)
            self.assertFalse(any('planned' in str(call) for call in write.call_args_list))

    def test_unsafe_parked_marker_never_sends_effect(self):
        with mux_fixture(True) as f:
            (f.home / 'gateway.parked').symlink_to(f.root / 'foreign')
            result = self.lifecycle(True)
            self.assertEqual(result.get('ledgerState'), 'uncertain', result)
            self.assertEqual(f.writes, [])

    def test_marker_swap_during_child_discovery_never_touches_foreign(self):
        with mux_fixture(True) as f:
            foreign=f.root/'foreign-marker-target';foreign.write_bytes(b'unchanged');before=foreign.stat()
            f.state['swap_marker_on_child_read']=True
            result=self.lifecycle(True)
            self.assertEqual(result.get('ledgerState'),'uncertain',result)
            self.assertEqual(f.writes,[])
            self.assertFalse(f.state['swap_marker_on_child_read'])
            self.assertEqual(foreign.read_bytes(),b'unchanged')
            self.assertEqual(foreign.stat().st_mtime_ns,before.st_mtime_ns)

    def test_socket_replacement_does_not_reuse_peer_capability(self):
        with mux_fixture(True) as f:
            route = base.daemon.resolve_hermes_mux_route('catbody', 'hermes.profile.lifecycle', 'boot:fixture')
            f.qualification.socket_path.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
                replacement.bind(str(f.qualification.socket_path)); f.qualification.socket_path.chmod(0o600)
                with self.assertRaises((ValueError, OSError)): route.verify()
            self.assertEqual(f.commands, [])

if __name__ == '__main__': unittest.main()
