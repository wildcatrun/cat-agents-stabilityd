"""Native-route actual files/readers and real daemon/ledger entry integration."""
import contextlib
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from stability_core import hermes_native_route as native
from stability_core import unit_capability

SPEC = importlib.util.spec_from_file_location('hermes_native_daemon_test', Path(__file__).resolve().parents[2] / 'bin/cat_agents_stabilityd.py')
daemon = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = daemon; SPEC.loader.exec_module(daemon)
HASH = lambda raw: hashlib.sha256(raw).hexdigest()
# Exact source excerpts from reviewed installed main/profile/standalone paths.
# These qualify the finite route semantics under test, not an installed runtime.
SOURCES = {'main.py': 'def _scan_profile_flag(argv: list) -> tuple:\n    """Find -p/--profile/--profile= in argv -> (name, tokens_consumed, index).\n\n    Historically the flag worked even after the subcommand (`hermes chat -p\n    coder`), so scan broadly; stop at ``--`` and at the `mcp add --args`\n    passthrough region. The value is normalised (strip + casefold, matching\n    ``profiles.normalize_profile_name``) before validation so ``-p Work`` selects\n    ``work``. A value that cannot be a profile name is rejected so\n    resolve_profile_env never sys.exits on it; the rejection is explained (exit 2)\n    only when the flag comes BEFORE the first subcommand token under a real\n    ``hermes`` run — after a subcommand, ``-p`` may belong to that subcommand or a\n    plugin (`hermes kanban ... -p 8080`), and option-looking values (``no:xdist``,\n    ``--flag``) are always a silent skip.\n    """\n    from hermes_cli._parser import top_level_value_flag_sets\n\n    value_flags, optional_value_flags = top_level_value_flag_sets()\n    i = 0\n    saw_subcommand = False\n    while i < len(argv):\n        arg = argv[i]\n        if arg == "--" or (arg == "--args" and _inside_mcp_add_args(argv, i)):\n            break\n        if arg in {"--profile", "-p"} and i + 1 < len(argv):\n            raw = argv[i + 1]\n            value = raw.strip().casefold()\n            if re.match(_PROFILE_NAME_RE, value):\n                return value, 2, i\n            if not saw_subcommand and not _looks_like_option_value(raw) and _looks_like_hermes_invocation():\n                _exit_invalid_profile_name(raw)\n            break\n        if arg.startswith("--profile="):\n            return arg.split("=", 1)[1].strip().casefold(), 1, i\n        takes_value = "=" not in arg and i + 1 < len(argv) and (\n            arg in value_flags\n            or (arg in optional_value_flags and not argv[i + 1].startswith("-"))\n        )\n        if not takes_value and not arg.startswith("-"):\n            saw_subcommand = True\n        i += 2 if takes_value else 1\n    return None, 0, None\n', 'profiles.py': 'def profile_is_standalone(home: Path) -> bool:\n    """Does ``home``\'s own config.yaml opt this profile out of the host multiplexer\n    (``gateway.standalone: true``)? Memoised by file signature. The DEFAULT profile is\n    never standalone — it IS the host — and warns once per process if the key is set there."""\n    global _STANDALONE_WARNED\n    from yaml import YAMLError\n    from utils import file_signature\n\n    home = Path(home)\n    cfg_path = home / "config.yaml"\n    key = str(home)\n    try:\n        signature = file_signature(cfg_path.stat())\n    except FileNotFoundError:\n        signature = None\n    except OSError as exc:\n        signature = ("stat-error", exc.errno)\n        if _STANDALONE_MEMO.get(key) != (signature, False):\n            logger.warning("Cannot read gateway.standalone from %s (%s); treating as not standalone",\n                           cfg_path, type(exc).__name__)\n        _STANDALONE_MEMO[key] = (signature, False)\n        return False\n    cached = _STANDALONE_MEMO.get(key)\n    if cached is not None and cached[0] == signature and cached[1] is not None:\n        return cached[1]\n    value = None\n    if signature is not None:\n        from hermes_cli.config import read_user_config_raw\n        try:\n            cfg = read_user_config_raw(cfg_path) or {}\n        except (YAMLError, OSError, UnicodeError) as exc:\n            if cached is None or cached[0] != signature:\n                logger.warning("Cannot read gateway.standalone from %s (%s); treating as not standalone",\n                               cfg_path, type(exc).__name__)\n            # Access can recover without changing the signature. None retains the\n            # warning receipt without caching a transient failure as config.\n            _STANDALONE_MEMO[key] = (signature, False if isinstance(exc, YAMLError) else None)\n            return False\n        if isinstance(cfg.get("gateway"), dict):\n            value = cfg["gateway"].get("standalone")\n    result = _standalone_truthy(value)\n    if home == _get_default_hermes_home():\n        if result and not _STANDALONE_WARNED:\n            logger.warning(_STANDALONE_DEFAULT_WARNING)\n            _STANDALONE_WARNED = True\n        result = False\n    _STANDALONE_MEMO[key] = (signature, result)\n    return result\n\ndef _standalone_truthy(value: object) -> bool:\n    """``gateway.standalone`` truthiness via the shared bool parser; only the\n    ``gateway:`` section\'s ``standalone`` key is read (no top-level alias)."""\n    from gateway.config import _bool_token\n    if isinstance(value, str):\n        return _bool_token(value) is True\n    return bool(value)\n\ndef profile_root_for_env_home(env_home: str, default_root: Path) -> Path:\n    """Hermes root named by an exported ``HERMES_HOME``: the grandparent of a profile-shaped value\n    (``<root>/profiles/<name>``, mirrors ``get_default_hermes_root()``), the value itself otherwise,\n    *default_root* when unset. Pure: callers pass any process\'s env, not only ``os.environ``."""\n    env_home = env_home.strip()\n    if not env_home:\n        return default_root\n    env_path = Path(env_home)\n    return env_path.parent.parent if env_path.parent.name == "profiles" else env_path\n\ndef resolve_profile_env(profile_name: str) -> str:\n    """Resolve a profile name to a HERMES_HOME path string. Called early in the CLI entry\n    point, before hermes modules are imported, to set HERMES_HOME.\n\n    When HERMES_HOME is already set, the configured spelling IS the launch root (it may be a\n    junction/symlink alias of the platform default). Keep that spelling so profile re-home does not destroy\n    the launcher\'s lexical provenance -- the subprocess sanitizer needs it to match Hermes-owned PYTHONPATH\n    entries written in the same spelling (#82581 junction follow-up). Physically the paths are identical\n    (junction-transparent); only the spelling is preserved.\n    """\n    canon = _canon_valid(profile_name)\n    root = profile_root_for_env_home(os.environ.get("HERMES_HOME", ""), _get_default_hermes_home())\n    if canon == "default":\n        return str(root)\n    profile_dir = root / "profiles" / canon\n    if not named_profile_is_live(profile_dir):\n        raise _missing_profile_error(canon)\n    return str(profile_dir)\n', 'gateway_multiplex_mode.py': 'def _standalone_launcher() -> bool:\n    from hermes_constants import get_hermes_home, profile_name_for_home\n    from hermes_cli.profiles import profile_is_standalone\n\n    home = get_hermes_home()\n    return profile_name_for_home(home) not in (None, "default") and profile_is_standalone(home)\n\ndef standalone_launcher_decision(config) -> Optional[MultiplexDecision]:\n    """The per-profile opt-out also binds callers supplying an explicit GatewayConfig."""\n    if not _standalone_launcher():\n        return None\n    config.multiplex_profiles = False\n    return MultiplexDecision(False, "guard", STANDALONE_PROFILE_REASON)\n'}
BINARY = Path(sys.executable).resolve().read_bytes()

@contextlib.contextmanager
def fixture():
    with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
        root = Path(temp); (root / 'state').mkdir(); units = root / 'units'; units.mkdir()
        runtime = root / 'runtime'; home = runtime / 'profiles/catbody'; home.mkdir(parents=True)
        (home / 'config.yaml').write_text('gateway:\n  standalone: true\n')
        code = root / 'main.py'
        for name, text in SOURCES.items(): (root / name).write_text(text)
        binary = root / 'python'; binary.symlink_to(Path(sys.executable).resolve())
        argv = (str(binary), '-m', 'hermes_cli.main', '--profile', 'catbody', 'gateway', 'run')
        unit = units / 'hermes-gateway-catbody.service'; unit.write_text('[Service]\nExecStart=' + ' '.join(argv) + '\n')
        props = ('Id=' + unit.name + '\nLoadState=loaded\nFragmentPath=' + str(unit)
                 + '\nDropInPaths=\nExecStart={ path=' + str(binary) + ' ; argv[]=' + ' '.join(argv) + ' ; }\n')
        env = 'Environment=HERMES_HOME=' + str(home) + '\nEnvironmentFiles=' + str(home / '.env') + ' (ignore_errors=yes)\nPassEnvironment=\nUnsetEnvironment=\nWorkingDirectory=' + str(home) + '\n'
        q = native.NativeQualification(os.getuid(), runtime, (units,), argv, HASH(BINARY),
            tuple((root / name, HASH(text.encode())) for name, text in SOURCES.items()), (root / '.op.env', root / 'project.env'), HASH(b''), HASH(env.encode()),
            'evidence://reviewed-installed-source-excerpts/profile-standalone-v1', target_profile='catbody')
        registry = dict(source='db', writeEligible=True, records=[dict(agent_id='cat_body', runtime='hermes_acp',
            platform='hermes', execution_adapter='hermes_acp', endpoint_ref='hermes-profile:catbody', status='active', can_receive_dispatch=1)])
        effects = []; state = dict(ActiveState='inactive', SubState='dead'); reply = dict(returncode=0, stdout='', stderr='')
        def properties(unit, names):
            return (props if 'ExecStart' in names else
                    '\n'.join(k+'='+v for k,v in state.items())+'\n' if 'ActiveState' in names else env)
        def run(cmd, timeout=10):
            if '--property=' in cmd[-1]:
                return SimpleNamespace(returncode=0, stdout=properties(cmd[-2], cmd[-1].split('=',1)[1].split(',')), stderr='')
            if cmd[-1] == 'show-environment': return SimpleNamespace(returncode=0, stdout='', stderr='')
            effects.append(tuple(cmd)); state.update(ActiveState='inactive' if cmd[-2] == 'stop' else 'active', SubState='dead' if cmd[-2] == 'stop' else 'running')
            return SimpleNamespace(**reply)
        from stability_core import installation_capability as installation
        from installation_fixture_support import native_artifact
        factory = native_artifact(q, root / 'qualified_installations_v1.json', node_id=daemon.platform.node(),
            environment_template=env.replace(str(home), '{home}'))
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(installation, 'load_packaged_installations', return_value=factory))
            for p in (mock.patch.object(daemon, 'workflow_runtime_registry_records', return_value=registry),
                      mock.patch.object(daemon, 'current_host_generation', return_value='boot:fixture'),
                                            mock.patch.object(daemon, 'run_user_cmd', side_effect=run),
                      mock.patch.object(daemon, 'STATE_DB', root / 'state/ledger.db'),
                      mock.patch.object(daemon, 'db_get', return_value=0),
                      mock.patch.object(daemon, 'db_set'),
                      mock.patch.object(daemon, 'recent_hermers_gateway_restart_history', return_value=[]),
                      mock.patch.object(daemon, 'record_hermers_gateway_restart_time')):
                stack.enter_context(p)
            yield SimpleNamespace(root=root, code=code, unit=unit, home=home, q=q, effects=effects, state=state, registry=registry, reply=reply)

class NativeIntegrationTests(unittest.TestCase):
    def lifecycle(self, active):
        item = dict(unit='hermes-gateway-catbody.service', managed=True, activeWork=False,
                    active=active, safeToHibernate=True, agentIds=['cat_body'])
        policy = dict(hermersProfileModeActuateEnabled=True, hermersProfileModeStartEnabled=True,
                      updatedAtEpoch=daemon.epoch()-1, validUntilEpoch=daemon.epoch()+60)
        with mock.patch.object(daemon, 'HERMERS_PROFILE_LIFECYCLE_ALLOWLIST', {'catbody'}), \
             mock.patch.object(daemon, 'HERMERS_PROFILE_MODE_START_ENABLED', True), \
             mock.patch.object(daemon, 'hermers_profile_workflow_activity', return_value={
                 'catbody': dict(probeOk=True, activeRuntimeCount=0, activeDispatchCount=0)}):
            return daemon.execute_hermers_profile_lifecycle(mock.Mock(), 'catbody', item,
                'hibernate' if active else 'hot', policy, 'snapshot')

    def test_lifecycle_native_start_and_stop(self):
        for active in (False, True):
            with self.subTest(active=active), fixture() as f:
                f.state.update(ActiveState='active' if active else 'inactive', SubState='running' if active else 'dead')
                result = self.lifecycle(active)
                self.assertEqual(result.get('ledgerState'), 'succeeded', result)
                self.assertEqual(len(f.effects), 1)
                self.assertEqual(f.effects[0][-2], 'stop' if active else 'start')

    def test_pending_stop_cannot_write_planned_hibernate_or_retry(self):
        with fixture() as f, mock.patch.object(daemon, 'db_set') as persist:
            f.state.update(ActiveState='active', SubState='running')
            f.reply['stdout'] = 'Profile stop was not confirmed: host operation is still pending'
            first = self.lifecycle(True)
            self.assertEqual(first.get('ledgerState'), 'uncertain', first)
            self.assertFalse(any('planned' in str(call) for call in persist.call_args_list))
            f.state.update(ActiveState='active', SubState='running')
            self.lifecycle(True)
            self.assertEqual(len(f.effects), 1)

    def test_first_observation_import_controls_are_rejected(self):
        from stability_core.hermes_dotenv_projection import IMPORT_KEYS
        for key in IMPORT_KEYS:
            with self.subTest(key=key), fixture() as f:
                (f.home / '.env').write_text(key + '=/untrusted\n')
                self.assertEqual(self.restart()['result'], 'blocked')
                self.assertEqual(f.effects, [])

    def test_closing_window_rereads_unit_and_config_before_effect(self):
        for what in ('unit', 'config'):
            with self.subTest(what=what), fixture() as f:
                verify_original = native.NativeRoute.verify
                source_original = native._read_program_source
                counts = dict(verify=0, source=0)
                def verify(route):
                    counts['verify'] += 1; counts['source'] = 0
                    return verify_original(route)
                def source(*args, **kwargs):
                    result = source_original(*args, **kwargs); counts['source'] += 1
                    if counts == dict(verify=5, source=4):
                        if what == 'unit': f.unit.write_text('[Service]\n# replaced mid-window\n')
                        else: (f.home / 'config.yaml').write_text('gateway:\n  standalone: false\n')
                    return result
                with mock.patch.object(native.NativeRoute, 'verify', verify), \
                     mock.patch.object(native, '_read_program_source', source):
                    result = self.restart()
                self.assertEqual(result['result'], 'blocked', result)
                self.assertEqual(f.effects, [])

    def test_safe_state_write_during_effect_preserves_route_but_replacement_does_not(self):
        for what in ('update', 'create', 'replace', 'remove'):
            with self.subTest(what=what), fixture() as f:
                state_file = f.home / 'state.db'
                if what != 'create': state_file.write_bytes(b'before')
                original = daemon.run_user_cmd.side_effect
                def run(cmd, timeout=10):
                    count = len(f.effects); result = original(cmd, timeout)
                    if len(f.effects) != count:
                        if what in ('replace', 'remove'): state_file.unlink()
                        if what != 'remove': state_file.write_bytes(b'after runtime write')
                    return result
                with mock.patch.object(daemon, 'run_user_cmd', side_effect=run): result = self.restart()
                self.assertEqual(result.get('ledgerState'), 'succeeded' if what in ('update','create') else 'uncertain', result)
                self.assertEqual(len(f.effects), 1)

    def test_new_safe_marker_is_pinned_after_first_observation(self):
        with fixture() as f:
            route = daemon.resolve_hermes_native_route('catbody', 'hermes.gateway.restart', 'boot:fixture')
            marker = f.home / 'state.db'; marker.write_bytes(b'created')
            route.verify()
            marker.unlink(); marker.write_bytes(b'replacement')
            with self.assertRaises(ValueError): route.verify()

    def test_other_profile_without_registry_owner_is_unqualified(self):
        with fixture():
            with self.assertRaisesRegex(ValueError,'hermes-installation-unqualified'):
                daemon.resolve_hermes_native_route('catnose', 'hermes.gateway.restart', 'boot:fixture')

    def test_posteffect_scope_revocation_ignores_deprecated_qualification_global(self):
        for use_native in (True, False):
            for revoke in ('owner', 'dispatch'):
                with self.subTest(native=use_native, revoke=revoke), fixture() as f, \
                     mock.patch.object(daemon, 'db_set') as persist:
                    f.state.update(ActiveState='active', SubState='running')
                    def revoked():
                        if revoke == 'owner': f.registry['records'].clear()
                        else: daemon.hermers_profile_workflow_activity.return_value['catbody']['activeDispatchCount'] = 1
                    original = daemon.run_user_cmd.side_effect
                    def run(cmd, timeout=10):
                        count = len(f.effects); result = original(cmd, timeout)
                        if len(f.effects) != count: revoked()
                        return result
                    def legacy(profile, verb, timeout=10):
                        f.effects.append(('legacy', verb)); f.state.update(ActiveState='inactive', SubState='dead'); revoked()
                        return SimpleNamespace(returncode=0, stdout='Stopped', stderr='')
                    with mock.patch.object(native, 'NATIVE_QUALIFICATION', f.q if use_native else None), \
                         mock.patch.object(daemon, 'run_user_cmd', side_effect=run), \
                         mock.patch.object(daemon, 'run_hermes_profile_gateway_cmd', side_effect=legacy):
                        result = self.lifecycle(True)
                    self.assertEqual(result.get('ledgerState'), 'uncertain', result)
                    self.assertTrue(result['nativeRouteUsed'])  # Factory, never legacy-global fallback.
                    self.assertFalse(any('planned' in str(call) for call in persist.call_args_list))
                    self.assertEqual(len(f.effects), 1)

    def test_posteffect_owner_revocation_ignores_deprecated_qualification_global(self):
        for use_native in (True, False):
            with self.subTest(native=use_native), fixture() as f:
                original = daemon.run_user_cmd.side_effect
                def run(cmd, timeout=10):
                    count = len(f.effects); result = original(cmd, timeout)
                    if len(f.effects) != count: f.registry['records'].clear()
                    return result
                def legacy(profile, verb, timeout=10):
                    f.effects.append(('legacy', verb)); f.registry['records'].clear()
                    return SimpleNamespace(returncode=0, stdout='Gateway active and running', stderr='')
                with mock.patch.object(native, 'NATIVE_QUALIFICATION', f.q if use_native else None), \
                     mock.patch.object(daemon, 'run_user_cmd', side_effect=run), \
                     mock.patch.object(daemon, 'run_hermes_profile_gateway_cmd', side_effect=legacy):
                    result = self.restart()
                self.assertEqual(result.get('ledgerState'), 'uncertain', result)
                self.assertTrue(result['nativeRouteUsed'])
                self.assertEqual(len(f.effects), 1)

    def restart(self):
        policy = dict(canRestartHermersGateway=True, hermersGatewayRestartReason='down',
            hermersGatewayRestartProfiles=[dict(profile='catbody', unit='hermes-gateway-catbody.service')],
            updatedAtEpoch=daemon.epoch()-1, validUntilEpoch=daemon.epoch()+60)
        return daemon.hermers_gateway_restart(mock.Mock(), 'catbody', 'hermes-gateway-catbody.service',
            'down', policy=policy, snapshot_generation='snapshot')

    def test_actual_files_native_restart_once_without_gateway_socket(self):
        with fixture() as f, mock.patch.object(daemon, 'run_hermes_profile_gateway_cmd') as cli:
            result = self.restart()
            self.assertEqual(result.get('ledgerState'), 'succeeded', result)
            self.assertEqual(len(f.effects), 1)
            self.assertEqual(f.effects[0][-3:], ('--user', 'restart', 'hermes-gateway-catbody.service'))
            cli.assert_not_called()

    def test_source_drift_at_each_existing_fence_zero_effect(self):
        for phase in (2, 3, 5):
            with self.subTest(phase=phase), fixture() as f:
                original = native.NativeRoute.verify; calls = []
                def verify(route):
                    calls.append(1)
                    if len(calls) == phase:
                        f.code.write_bytes(SOURCES['main.py'].encode() + b'# drift\n')
                    return original(route)
                with mock.patch.object(native.NativeRoute, 'verify', verify): result = self.restart()
                self.assertEqual(result['result'], 'blocked', result)
                self.assertEqual(f.effects, [])
                self.assertGreaterEqual(len(calls), phase)

    def test_unit_config_and_registry_drift_after_claim_zero_effect(self):
        for what in ('unit', 'config', 'registry'):
            with self.subTest(what=what), fixture() as f:
                original = native.NativeRoute.verify; calls = []
                def verify(route):
                    calls.append(1)
                    if len(calls) == 5:
                        if what == 'unit': f.unit.write_text('[Service]\n# replaced\n')
                        elif what == 'config': (f.home / 'config.yaml').write_text('gateway:\n  standalone: false\n')
                        else: f.registry['records'][0]['agent_id'] = 'cat_ears'
                    return original(route)
                with mock.patch.object(native.NativeRoute, 'verify', verify): result = self.restart()
                self.assertEqual(result['result'], 'blocked', result)
                self.assertEqual(f.effects, [])

    def test_populated_environment_file_is_owned_and_secret_redacted(self):
        with fixture() as f:
            (f.home / '.env').write_text('API_KEY=PRIVATE_FIXTURE_VALUE\n')
            result = self.restart()
            self.assertEqual(result.get('ledgerState'), 'succeeded', result)
            self.assertNotIn('PRIVATE_FIXTURE_VALUE', repr(result))
            self.assertEqual(len(f.effects), 1)

    def test_multiplex_cannot_use_native_effect(self):
        with fixture() as f:
            (f.home / 'config.yaml').write_text('gateway:\n  standalone: false\n')
            self.assertEqual(self.restart()['result'], 'blocked'); self.assertEqual(f.effects, [])

    def test_same_bytes_source_replacement_refused(self):
        with fixture() as f:
            route = daemon.resolve_hermes_native_route('catbody', 'hermes.gateway.restart', 'boot:fixture')
            f.code.unlink(); f.code.write_text(SOURCES['main.py'])
            with self.assertRaises(ValueError): route.verify()

    def test_absent_source_appearance_refused(self):
        with fixture() as f:
            route = daemon.resolve_hermes_native_route('catbody', 'hermes.gateway.restart', 'boot:fixture')
            (f.home / '.env').write_text('HERMES_HOME=/wrong\n')
            with self.assertRaises(ValueError): route.verify()

if __name__ == '__main__': unittest.main()
