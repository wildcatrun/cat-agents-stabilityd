"""Actual reader/daemon integration with independently declared fixture contract."""
import contextlib
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from stability_core import session_api_capability as api
from stability_core.adapter_contract import AdapterContract
from stability_core.content_artifact import ContentArtifactSpec

ENTRY = b'#!/usr/bin/env node\n// reviewed synthetic session API fixture\n'
PROTOCOL = b'export const PROTOCOL_VERSION = 1;\n'
PACKAGE = b'{"name":"fixture-openclaw","version":"1.2.3"}\n'


@contextlib.contextmanager
def qualified_session_fixture(stabilityd):
    """Trusted test configuration, not a production approval or mocked descriptor."""
    with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
        root = Path(temp)
        code = root / 'code'; code.mkdir()
        raw_files = {'package.json': PACKAGE, 'openclaw.mjs': ENTRY, 'protocol.mjs': PROTOCOL}
        for name, raw in raw_files.items():
            (code / name).write_bytes(raw); (code / name).chmod(0o700 if name == 'openclaw.mjs' else 0o600)
        # Expected artifact identity derives from the reviewed fixture bytes,
        # independently of the runtime-owned descriptor/measurement under test.
        records = [(name, hashlib.sha256(raw_files[name]).hexdigest(), len(raw_files[name])) for name in sorted(raw_files)]
        digest = hashlib.sha256(json.dumps(dict(schemaVersion=1, packageName='fixture-openclaw',
            packageVersion='1.2.3', files=records), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        binary = hashlib.sha256(ENTRY).hexdigest()
        contract = AdapterContract('fixture-session-api', 1, '1.0.0', '1.0.0', '1.2.3', '1.2.3',
            ('openclaw',), ('sessions.reset',), ('sessions.reset',), (), ((digest, binary),))
        units = root / 'units'; units.mkdir()
        node = root / 'node'; node.write_text('#!/bin/sh\nexit 0\n'); node.chmod(0o700)
        cli = code / 'openclaw.mjs'
        argv = (str(node), str(cli), 'gateway', '--port', '18789')
        unit = units / 'openclaw-gateway.service'
        unit.write_text('[Service]\nExecStart=' + ' '.join(argv) + '\n'); unit.chmod(0o600)
        props = ('Id=openclaw-gateway.service\nLoadState=loaded\nFragmentPath=' + str(unit)
                 + '\nDropInPaths=\nExecStart={ path=' + str(node) + ' ; argv[]=' + ' '.join(argv) + ' ; }\n')
        proc = root / 'proc'; process = proc / '42'; process.mkdir(parents=True)
        boot = proc / 'sys/kernel/random'; boot.mkdir(parents=True)
        (boot / 'boot_id').write_text('boot')
        (process / 'stat').write_text('42 (fixture) ' + ' '.join(['S'] + ['0'] * 18 + ['99']))
        (process / 'status').write_text('Uid:\t' + '\t'.join([str(os.getuid())] * 4) + '\n')
        (process / 'cmdline').write_bytes(b'\x00'.join(a.encode() for a in argv) + b'\x00')
        (process / 'cgroup').write_text('0::/system.slice/openclaw-gateway.service\n')
        (process / 'exe').symlink_to(node)
        (proc / 'net').mkdir()
        (proc / 'net/tcp').write_text('header\n0: 0100007F:4965 00000000:0000 0A 0:0 0:0 0 '
                                    + str(os.getuid()) + ' 0 12345\n')
        (process / 'fd').mkdir()
        (process / 'fd/7').symlink_to('socket:[12345]')
        qualification = api.SessionApiQualification(ContentArtifactSpec(code, 'fixture-openclaw', '1.2.3', tuple(raw_files)),
            contract, cli, 'openclaw.mjs', 'protocol.mjs', os.getuid(),
            'evidence://session-api-qualification/independent-fixture-v1', 18789, (units,), proc)
        original_access = os.access
        def fixture_access(path, mode, *args, **kwargs):
            # Transport is mocked; these exact synthetic program files are not
            # executed. QA HOME may be /run on a genuinely noexec mount. Model
            # executable access only after the real metadata guards pass.
            if mode == os.X_OK and Path(path) in {node, cli}:
                try:
                    info = Path(path).lstat()
                    noexec = getattr(os, 'ST_NOEXEC', 0)
                    if (noexec and os.statvfs(path).f_flag & noexec
                            and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                            and info.st_uid == os.getuid() and not info.st_mode & 0o022
                            and info.st_mode & stat.S_IXUSR):
                        return True
                except OSError:
                    pass
            return original_access(path, mode, *args, **kwargs)
        with mock.patch.object(api, 'SESSION_API_QUALIFICATION', qualification), \
             mock.patch('os.access', side_effect=fixture_access), \
             mock.patch.object(stabilityd.platform, 'node', return_value='fixture-node'), \
             mock.patch.object(stabilityd, 'read_gateway_unit_properties', return_value=props), \
             mock.patch.object(stabilityd, 'systemctl_show_gateway', return_value={
                 'ActiveState': 'active', 'SubState': 'running', 'MainPID': 42}):
            yield SimpleNamespace(qualification=qualification, code=code, process=process, cli=cli, unit=unit, node=node)


MODULE_PATH = Path(__file__).resolve().parents[2] / 'bin/cat_agents_stabilityd.py'
SPEC = importlib.util.spec_from_file_location('session_effect_integration_daemon', MODULE_PATH)
daemon = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = daemon; SPEC.loader.exec_module(daemon)


class SessionCapabilityIntegrationTests(unittest.TestCase):
    key, session = 'agent:cat_voice:fixture:PRIVATE_TARGET', 'PRIVATE_SESSION'

    def invoke(self, *, mutation=None, nonzero=False, qualification=True, final_mutation=None):
        effects, rpc = [], []
        row = dict(key=self.key, agentId='cat_voice', sessionId=self.session, hasActiveRun=False)
        registry = dict(source='db', writeEligible=True, records=[dict(agent_id='cat_voice', runtime='openclaw',
                       platform='openclaw', execution_adapter='openclaw', endpoint_ref='openclaw-agent:cat_voice',
                       status='active', can_receive_dispatch=1)])
        with qualified_session_fixture(daemon) as fixture, tempfile.TemporaryDirectory() as directory, \
             daemon.init_memory_kv_db() as conn:
            from stability_core.action_ledger import ActionLedger
            refresh = ActionLedger.refresh_execution_precheck
            def persisted(ledger, *args, **kw):
                result = refresh(ledger, *args, **kw)
                if final_mutation is not None: final_mutation(fixture)
                return result
            def command(argv, **kw):
                method_index = 3 if argv[0] == 'openclaw' else 4
                rpc.append(argv[method_index])
                if argv[method_index] == 'sessions.describe':
                    if method_index == 4:
                        self.assertEqual(argv[:2], [str(fixture.node), str(fixture.cli)])
                        self.assertEqual(argv[-2:], ['--expect-url', 'ws://127.0.0.1:18789'])
                    if mutation is not None: mutation(fixture, len(rpc))
                    return SimpleNamespace(returncode=0, stdout=json.dumps({'session': row}), stderr='')
                self.assertEqual(argv[:2], [str(fixture.node), str(fixture.cli)])
                self.assertEqual(argv[-2:], ['--expect-url', 'ws://127.0.0.1:18789'])
                effects.append(argv)
                return SimpleNamespace(returncode=1 if nonzero else 0,
                    stdout=json.dumps({'ok': True, 'key': self.key, 'entry': {'sessionId': self.session}}),
                    stderr='PRIVATE_SECRET')
            with mock.patch.object(daemon, 'STATE_DB', Path(directory) / 'ledger.db'), \
                 mock.patch.object(daemon, 'epoch', return_value=1000), \
                 mock.patch.object(daemon, 'now_ms', return_value=1000000), \
                 mock.patch.object(daemon, 'current_host_generation', return_value='fixture-node:boot'), \
                 mock.patch.object(daemon, 'workflow_runtime_registry_records', return_value=registry), \
                 mock.patch.object(daemon, 'analyze_session_activity', return_value={'active': False, 'heavy': False}), \
                 mock.patch.object(ActionLedger, 'refresh_execution_precheck', new=persisted), \
                 mock.patch.object(daemon, 'run_cmd', side_effect=command):
                if not qualification:
                    with mock.patch.object(api, 'SESSION_API_QUALIFICATION', None):
                        first = daemon.governed_reset_session(conn, self.key, 'repeated_failures',
                            dict(canResetSession=True, updatedAtEpoch=999, validUntilEpoch=1060), 'snapshot', self.session)
                else:
                    first = daemon.governed_reset_session(conn, self.key, 'repeated_failures',
                        dict(canResetSession=True, updatedAtEpoch=999, validUntilEpoch=1060), 'snapshot', self.session)
                second = daemon.governed_reset_session(conn, self.key, 'repeated_failures',
                    dict(canResetSession=True, updatedAtEpoch=999, validUntilEpoch=1060), 'snapshot', self.session)
            return first, second, effects

    def test_actual_qualified_fixture_resets_exactly_once_and_pins_cli(self):
        first, second, effects = self.invoke()
        self.assertEqual(first['ledgerState'], 'succeeded')
        self.assertEqual(second['ledgerDisposition'], 'existing')
        self.assertEqual(len(effects), 1)
        self.assertNotIn('PRIVATE_', str(first))

    def test_absent_independent_qualification_blocks_only_reset(self):
        first, _second, effects = self.invoke(qualification=False)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_actual_source_drift_after_eligibility_sends_no_reset(self):
        def mutate(fixture, calls):
            if calls == 3: (fixture.code / 'protocol.mjs').write_text('export const PROTOCOL_VERSION = 2;\n')
        first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_same_bytes_inode_replacement_is_refused(self):
        def mutate(fixture, calls):
            if calls == 3:
                file = fixture.code / 'protocol.mjs'
                replacement = fixture.code / 'replacement'; replacement.write_bytes(file.read_bytes())
                replacement.chmod(0o600); os.replace(replacement, file)
        first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_gateway_process_birth_drift_is_refused(self):
        def mutate(fixture, calls):
            if calls == 3:
                file = fixture.process / 'stat'; file.write_text(file.read_text().replace('99', '100'))
        first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_interpreter_bytes_drift_is_refused_before_reset(self):
        def mutate(fixture, calls):
            if calls == 3: fixture.node.write_text('#!/bin/sh\nexit 7\n')
        first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_kernel_executable_other_or_deleted_route_sends_no_reset(self):
        for deleted in (False, True):
            def mutate(fixture, calls):
                if calls == 1:
                    link = fixture.process / 'exe'
                    link.unlink()
                    if deleted:
                        link.symlink_to(str(fixture.node) + ' (deleted)')
                    else:
                        other = fixture.node.parent / 'old-node'
                        other.write_bytes(fixture.node.read_bytes()); other.chmod(0o700)
                        link.symlink_to(other)
            with self.subTest(deleted=deleted):
                first, _second, effects = self.invoke(mutation=mutate)
                self.assertEqual(first['ledgerState'], 'blocked')
                self.assertEqual(effects, [])

    def test_old_kernel_inode_cannot_be_replaced_by_same_bytes_current_disk(self):
        readlink = os.readlink
        kernel_link = [None]
        expected_spelling = [None]
        def mutate(fixture, calls):
            if calls == 1:
                old = fixture.node.parent / 'retained-kernel-image'
                fixture.node.rename(old)
                fixture.node.write_bytes(old.read_bytes()); fixture.node.chmod(0o700)
                link = fixture.process / 'exe'; link.unlink(); link.symlink_to(old)
                kernel_link[0], expected_spelling[0] = link, str(fixture.node)
        def kernel_readlink(path, *args, **kwargs):
            # A normal filesystem symlink follows a name, whereas /proc/exe
            # follows the kernel's retained file object. Model only its spelling
            # here; fstat/stat still observe the real old and new owned inodes.
            if kernel_link[0] is not None and Path(path) == kernel_link[0]:
                return expected_spelling[0]
            return readlink(path, *args, **kwargs)
        with mock.patch('os.readlink', side_effect=kernel_readlink):
            first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_kernel_image_identity_change_inside_observation_refused(self):
        original = api._kernel_executable_identity
        changed = [False]
        def observe(root, pid, executable):
            result = original(root, pid, executable)
            if not changed[0]:
                changed[0] = True
                link = root / str(pid) / 'exe'
                link.unlink(); link.symlink_to(executable)
            return result
        with mock.patch.object(api, '_kernel_executable_identity', side_effect=observe):
            first, _second, effects = self.invoke()
        self.assertTrue(changed[0])
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_noexec_fixture_emulation_does_not_override_denied_mode(self):
        def mutate(fixture, calls):
            if calls == 3: fixture.node.chmod(0o600)
        original = os.statvfs
        def noexec(path):
            info = original(path)
            return SimpleNamespace(f_flag=info.f_flag | getattr(os, 'ST_NOEXEC', 8))
        with mock.patch('os.statvfs', side_effect=noexec):
            first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_interpreter_symlink_replacement_is_not_followed_to_new_program(self):
        def mutate(fixture, calls):
            if calls == 3:
                other = fixture.node.parent / 'other-node'
                other.write_bytes(fixture.node.read_bytes()); other.chmod(0o700)
                fixture.node.unlink(); fixture.node.symlink_to(other)
        first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_path_cannot_supply_fallback_when_pinned_interpreter_disappears(self):
        with mock.patch.dict(os.environ, {'PATH': '/unqualified-PATH-node'}):
            def mutate(fixture, calls):
                if calls == 3: fixture.node.unlink()
            first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_hostile_path_alone_cannot_redirect_valid_absolute_launcher(self):
        with mock.patch.dict(os.environ, {'PATH': '/unqualified-PATH-node'}):
            first, second, effects = self.invoke()
        self.assertEqual(first['ledgerState'], 'succeeded')
        self.assertEqual(second['ledgerDisposition'], 'existing')
        self.assertEqual(len(effects), 1)

    def test_actual_unsupported_protocol_at_initial_boundary_sends_no_reset(self):
        def mutate(fixture, calls):
            if calls == 1: (fixture.code / 'protocol.mjs').write_text('export const PROTOCOL_VERSION = 2;\n')
        first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_listener_owned_by_other_instance_sends_no_reset(self):
        def mutate(fixture, calls):
            if calls == 1: (fixture.process / 'fd/7').unlink()
        first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_final_after_claim_drift_sends_no_reset_and_remains_uncertain(self):
        def mutate(fixture):
            path = fixture.process / 'stat'; path.write_text(path.read_text().replace('99', '100'))
        first, second, effects = self.invoke(final_mutation=mutate)
        self.assertEqual(first['ledgerState'], 'uncertain')
        # A new producer-instance proof cannot be substituted into the old
        # uncertain intent. The immutable ledger rejects the conflicting proof.
        self.assertEqual(second['result'], 'uncertain')
        self.assertEqual(second['error'], 'ActionConflict')
        self.assertEqual(effects, [])

    def test_nonzero_mutation_remains_uncertain_and_never_retries(self):
        first, second, effects = self.invoke(nonzero=True)
        self.assertEqual(first['ledgerState'], 'uncertain')
        self.assertEqual(second['ledgerDisposition'], 'existing')
        self.assertEqual(len(effects), 1)
        self.assertNotIn('PRIVATE_SECRET', str(first))


if __name__ == '__main__': unittest.main()
