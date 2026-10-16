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
from stability_core import installation_capability as installation
from stability_core.adapter_contract import AdapterContract
from stability_core.content_artifact import ContentArtifactSpec

ENTRY = b'#!/usr/bin/env node\n// reviewed synthetic session API fixture\n'
SDK = b'// independently bounded SDK entry fixture; execution mocked only at external SDK boundary\n'
PACKAGE = b'{"name":"fixture-openclaw","version":"1.2.3"}\n'


def sdk_reply(result, **hello_changes):
    hello=dict(protocol=4,version='fixture-v1',buildId='fixture-build',bootId='server-boot',methods=['sessions.describe','sessions.reset'])
    hello.update(hello_changes)
    return json.dumps(dict(ok=True,hello=hello,result=result))


def launcher_fixture(environment):
    return api.SessionRpcLauncher(Path('/node'),Path('/wrapper'), '0'*64,
        ('node-route',),('wrapper-route',),'ws://127.0.0.1:18789',environment,
        Path('/sdk.mjs'),(('/sdk.mjs','0'*64),),'fixture-v1','fixture-build','server-boot',Path('/fixture'))


@contextlib.contextmanager
def qualified_session_fixture(stabilityd):
    """Trusted test configuration, not a production approval or mocked descriptor."""
    with tempfile.TemporaryDirectory(dir=Path.home()) as temp:
        root = Path(temp)
        code = root / 'code'; code.mkdir()
        raw_files = {'package.json': PACKAGE, 'openclaw.mjs': ENTRY, 'sdk.mjs': SDK}
        for name, raw in raw_files.items():
            (code / name).write_bytes(raw); (code / name).chmod(0o700 if name == 'openclaw.mjs' else 0o600)
        # Expected artifact identity derives from the reviewed fixture bytes,
        # independently of the runtime-owned descriptor/measurement under test.
        records = [(name, hashlib.sha256(raw_files[name]).hexdigest(), len(raw_files[name])) for name in sorted(raw_files)]
        digest = hashlib.sha256(json.dumps(dict(schemaVersion=1, packageName='fixture-openclaw',
            packageVersion='1.2.3', files=records), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        binary = hashlib.sha256(ENTRY).hexdigest()
        contract = AdapterContract('fixture-session-api', 4, '4.0.0', '4.0.0', '1.2.3', '1.2.3',
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
        wrapper=root/'session_sdk_bridge.mjs';wrapper.write_bytes(b'// owned SDK bridge fixture; external invocation mocked\n')
        qualification = api.SessionApiQualification(ContentArtifactSpec(code, 'fixture-openclaw', '1.2.3', tuple(raw_files)),
            contract, cli, 'openclaw.mjs', 'sdk.mjs', os.getuid(),
            'evidence://session-api-qualification/independent-fixture-v1', 18789, (units,), proc,
            rpc_environment=(('HOME', str(root)),),
            sdk=api.SessionSdkQualification('sdk.mjs',wrapper,hashlib.sha256(wrapper.read_bytes()).hexdigest(),'fixture-v1','fixture-build'))
        from stability_core import installation_capability as installation
        from installation_fixture_support import session_artifact
        factory=session_artifact(qualification,root/'qualified_installations_v1.json',raw_files,node_id='fixture-node')
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
        with mock.patch.object(installation, 'load_packaged_installations', return_value=factory), \
             mock.patch.object(api, '_run_sdk_probe', return_value=sdk_reply(None)) as probe, \
             mock.patch('os.access', side_effect=fixture_access), \
             mock.patch.object(stabilityd.platform, 'node', return_value='fixture-node'), \
             mock.patch.object(stabilityd, 'read_gateway_unit_properties', return_value=props), \
             mock.patch.object(stabilityd, 'systemctl_show_gateway', return_value={
                 'ActiveState': 'active', 'SubState': 'running', 'MainPID': 42}):
            yield SimpleNamespace(qualification=qualification, code=code, process=process, cli=cli, unit=unit, node=node, wrapper=wrapper, probe=probe, installation_factory=factory)


MODULE_PATH = Path(__file__).resolve().parents[2] / 'bin/cat_agents_stabilityd.py'
SPEC = importlib.util.spec_from_file_location('session_effect_integration_daemon', MODULE_PATH)
daemon = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = daemon; SPEC.loader.exec_module(daemon)


class SessionCapabilityIntegrationTests(unittest.TestCase):
    def setUp(self):
        from clock_fixture_support import install_clock_fixture
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        install_clock_fixture(self,daemon,Path(tmp.name)/'actuation.lock')

    key, session = 'agent:cat_voice:fixture:PRIVATE_TARGET', 'PRIVATE_SESSION'

    def invoke(self, *, mutation=None, nonzero=False, qualification=True, final_mutation=None, sdk_mutation=None):
        effects, rpc = [], []
        row = dict(key=self.key, agentId='cat_voice', sessionId=self.session, hasActiveRun=False)
        registry = dict(source='db', writeEligible=True, records=[dict(agent_id='cat_voice', runtime='openclaw',
                       platform='openclaw', execution_adapter='openclaw', endpoint_ref='openclaw-agent:cat_voice',
                       status='active', can_receive_dispatch=1)])
        with qualified_session_fixture(daemon) as fixture, tempfile.TemporaryDirectory() as directory, \
             daemon.init_memory_kv_db() as conn:
            if sdk_mutation is not None: sdk_mutation(fixture)
            from stability_core.action_ledger import ActionLedger
            refresh = ActionLedger.refresh_execution_precheck
            def persisted(ledger, *args, **kw):
                result = refresh(ledger, *args, **kw)
                if final_mutation is not None: final_mutation(fixture)
                return result
            def command(argv, **kw):
                qualified = argv[0] != 'openclaw'
                if qualified:
                    payload=json.loads(argv[2]);method=payload['method']
                    self.assertEqual(argv[:2],[str(fixture.node),str(fixture.wrapper)])
                    self.assertEqual(kw.get('cwd'),str(fixture.code))
                    self.assertEqual(kw.get('env'),dict(fixture.qualification.rpc_environment))
                    self.assertEqual(payload['server']['bootId'],'server-boot')
                    self.assertEqual(payload['sdkEntry'],str(fixture.code/'sdk.mjs'))
                else:
                    method=argv[3]
                    self.assertNotIn('env',kw)
                rpc.append(method)
                if method=='sessions.describe':
                    if mutation is not None: mutation(fixture,len(rpc))
                    result={'session':row}
                else:
                    effects.append(argv)
                    result={'ok':True,'key':self.key,'entry':{'sessionId':self.session}}
                return SimpleNamespace(returncode=1 if nonzero and method=='sessions.reset' else 0,
                    stdout=sdk_reply(result) if qualified else json.dumps(result),stderr='PRIVATE_SECRET')
            def sdk_call(argv,environment,cwd,timeout):
                reply=command(list(argv),env=environment,cwd=str(cwd))
                if reply.returncode!=0: raise ValueError('session SDK process unavailable')
                return reply.stdout
            with mock.patch.object(daemon, 'STATE_DB', Path(directory) / 'ledger.db'), \
                 mock.patch.object(daemon, 'epoch', return_value=1000), \
                 mock.patch.object(daemon, 'now_ms', return_value=1000000), \
                 mock.patch.object(daemon, 'current_host_generation', return_value='fixture-node:boot'), \
                 mock.patch.object(daemon, 'workflow_runtime_registry_records', return_value=registry), \
                 mock.patch.object(daemon, 'analyze_session_activity', return_value={'active': False, 'heavy': False}), \
                 mock.patch.object(ActionLedger, 'refresh_execution_precheck', new=persisted), \
                 mock.patch.object(daemon, 'run_cmd', side_effect=command), \
                 mock.patch.object(api, 'run_sdk_process', side_effect=sdk_call):
                if not qualification:
                    with mock.patch.object(installation, 'load_packaged_installations', side_effect=ValueError('fixture artifact unavailable')):
                        first = daemon.governed_reset_session(conn, self.key, 'repeated_failures',
                            dict(canResetSession=True, updatedAtEpoch=999, validUntilEpoch=1060), 'snapshot', self.session)
                else:
                    first = daemon.governed_reset_session(conn, self.key, 'repeated_failures',
                        dict(canResetSession=True, updatedAtEpoch=999, validUntilEpoch=1060), 'snapshot', self.session)
                second = daemon.governed_reset_session(conn, self.key, 'repeated_failures',
                    dict(canResetSession=True, updatedAtEpoch=999, validUntilEpoch=1060), 'snapshot', self.session)
            return first, second, effects

    def test_rpc_environment_is_closed_and_not_ambient_or_mutable(self):
        approved = (('HOME', '/fixture/home'), ('HTTPS_PROXY', 'http://127.0.0.1:7890'))
        with mock.patch.dict(os.environ, {'NODE_OPTIONS': '--require=/unapproved/preload.js',
                                         'LD_PRELOAD': '/unapproved/preload.so'}):
            launcher = launcher_fixture(approved)
            self.assertEqual(launcher.environment, dict(approved))
            changed = launcher.environment
            changed['NODE_OPTIONS'] = '--require=/foreign'
            self.assertEqual(launcher.environment, dict(approved))
        for items in ((('HOME', '/fixture'), ('NODE_OPTIONS', '--require=/foreign')),
                      (('HOME', '/fixture'), ('LD_PRELOAD', '/foreign')),
                      (('HOME', '/fixture'), ('OPENCLAW_GATEWAY_TOKEN', 'synthetic')),
                      (('HOME', '/fixture'), ('HOME', '/other')), (),
                      (('HOME', 'relative'),), (('HOME', '/fixture'), ('NO_PROXY', 'x\x00y'))):
            with self.subTest(keys=[i[0] for i in items]), self.assertRaises(ValueError):
                launcher_fixture(items)

    def test_qualified_rpc_passes_only_fixed_environment_to_process(self):
        launcher=launcher_fixture((('HOME','/fixture/home'),))
        def child(argv,**kwargs):
            kwargs['stdout'].write(sdk_reply({'sessionId':'fixture'}).encode());kwargs['stdout'].flush()
            return SimpleNamespace(returncode=0)
        with mock.patch.dict(os.environ,{'NODE_OPTIONS':'--require=/foreign','LD_PRELOAD':'/foreign'}), \
             mock.patch.object(api.subprocess,'run',side_effect=child) as run:
            self.assertEqual(daemon.openclaw_gateway_call('sessions.describe',{'key':'agent:cat_voice:x','agentId':'cat_voice'},rpc_launcher=launcher)[1],'ok')
        self.assertEqual(run.call_args.kwargs['env'],{'HOME':'/fixture/home'})
        self.assertEqual(run.call_args.kwargs['cwd'],'/fixture')
        self.assertEqual(run.call_args.args[0][:2],['/node','/wrapper'])

    def test_sdk_response_and_call_schema_are_closed(self):
        launcher=launcher_fixture((('HOME','/fixture/home'),))
        for method,params in [('sessions.reset',{'key':'x','agentId':'cat_voice'}),
                              ('health',{}),('sessions.describe',{'key':'x','agentId':'cat_voice','token':'forged'}),
                              ('sessions.describe',{'key':'x'*513,'agentId':'cat_voice'}),
                              ('sessions.describe',{'key':'x\ny','agentId':'cat_voice'})]:
            with self.subTest(method=method,params=params),self.assertRaises(ValueError):launcher.command(method,params)
        for response in ('{}',sdk_reply(None),sdk_reply({})+' trailing',
                         sdk_reply({},bootId='wrong'),sdk_reply({},bootId='bad\nboot'),sdk_reply({},protocol=True),
                         sdk_reply({}).replace('"ok": true','"ok": true, "ok": true')):
            with self.subTest(response=response),self.assertRaises((ValueError,TypeError)):
                api.validate_sdk_response(response,version='fixture-v1',build_id='fixture-build',boot_id='server-boot')

    def test_factory_binds_literal_unit_script_alias_to_reviewed_source(self):
        def configure(fixture):
            alias=fixture.code.parent/'declared-package'
            alias.symlink_to(fixture.code,target_is_directory=True)
            entry=alias/fixture.cli.name
            fixture.installation_factory._manifest['installations'][0]['cliEntry']=str(entry)
            old=str(fixture.cli);new=str(entry)
            daemon.read_gateway_unit_properties.return_value=daemon.read_gateway_unit_properties.return_value.replace(old,new)
            fixture.unit.write_text(fixture.unit.read_text().replace(old,new))
            command=fixture.process/'cmdline'
            command.write_bytes(command.read_bytes().replace(old.encode(),new.encode()))
            fixture.cli.chmod(0o600)  # Node source is not itself an executable.
        first,_second,effects=self.invoke(sdk_mutation=configure)
        self.assertEqual(first['ledgerState'],'succeeded')
        self.assertEqual(len(effects),1)
        def replace_alias(fixture):
            alias=fixture.code.parent/'declared-package'
            other=fixture.code.parent/'replacement'
            if other.exists():return
            other.mkdir()
            (other/fixture.cli.name).write_bytes(ENTRY)
            alias.unlink();alias.symlink_to(other,target_is_directory=True)
        first,_second,effects=self.invoke(sdk_mutation=configure,final_mutation=replace_alias)
        # This hook runs after the durable effect claim. Drift prevents reset,
        # but the claimed intent must remain uncertain and cannot be retried.
        self.assertEqual(first['ledgerState'],'uncertain')
        self.assertEqual(_second['ledgerState'],'uncertain')
        self.assertEqual(_second['result'],'existing')
        self.assertEqual(effects,[])

    def test_script_route_owned_ancestor_alias_and_drift(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root=Path(directory); real=root/'real'; real.mkdir()
            script=real/'index.js'; script.write_text('// reviewed script\n');script.chmod(0o600)
            alias=root/'alias';alias.symlink_to(real,target_is_directory=True)
            declared=alias/'index.js'
            resolved,pinned=api._script_source_route(declared,owner_uid=os.getuid())
            self.assertEqual(resolved,script)
            (root/'sibling').mkdir()
            self.assertEqual(api._script_source_route(declared,owner_uid=os.getuid()),(resolved,pinned))
            other=root/'other';other.mkdir();(other/'index.js').write_text('// other')
            alias.unlink();alias.symlink_to(other,target_is_directory=True)
            self.assertNotEqual(api._script_source_route(declared,owner_uid=os.getuid()),(resolved,pinned))
            real.chmod(0o770)
            with self.assertRaises(ValueError):api._script_source_route(script,owner_uid=os.getuid())

    def test_script_route_parent_after_nested_alias_matches_kernel(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            root=Path(directory);safe=root/'safe';safe.mkdir()
            other=root/'other';other.mkdir();(other/'deep').mkdir()
            (safe/'payload.js').write_text('// lexical decoy')
            actual=other/'payload.js';actual.write_text('// kernel producer')
            (safe/'jump').symlink_to(other/'deep',target_is_directory=True)
            entry=root/'entry.js';entry.symlink_to('safe/jump/../payload.js')
            resolved,route=api._script_source_route(entry,owner_uid=os.getuid())
            self.assertEqual(resolved,actual)
            self.assertEqual(resolved.read_bytes(),entry.read_bytes())
            self.assertIn(str(safe/'jump'),[row[0] for row in route])
            # A qualification for the lexical decoy cannot match this route.
            self.assertNotEqual(resolved,safe/'payload.js')

    def test_expected_build_absence_is_pinned_not_wildcard(self):
        launcher=replace(launcher_fixture((('HOME','/fixture/home'),)),server_build_id=None)
        payload=json.loads(launcher.command('sessions.describe',dict(key='x',agentId='main'))[2])
        self.assertIsNone(payload['server']['buildId'])
        hello,_=api.validate_sdk_response(sdk_reply({},buildId=None),version='fixture-v1',build_id=None,boot_id='server-boot')
        self.assertIsNone(hello['buildId'])
        for value in ('fixture-build','',False):
            with self.subTest(value=value),self.assertRaises(ValueError):
                api.validate_sdk_response(sdk_reply({},buildId=value),version='fixture-v1',build_id=None,boot_id='server-boot')
        with self.assertRaises(ValueError):
            api.validate_sdk_response(sdk_reply({},buildId=None),version='fixture-v1',build_id='fixture-build',boot_id='server-boot')

    def test_sdk_process_output_budget_and_nonzero_are_sanitized(self):
        for kind in ('stdout','stderr','nonzero'):
            def child(argv,**kwargs):
                if kind!='nonzero':kwargs[kind].write(b'PRIVATE_SECRET'+b'x'*65536);kwargs[kind].flush()
                return SimpleNamespace(returncode=75 if kind=='nonzero' else 0)
            with self.subTest(kind=kind),mock.patch.object(api.subprocess,'run',side_effect=child):
                with self.assertRaises(ValueError) as error:
                    api.run_sdk_process(('/node','/wrapper','{}'),environment={'HOME':'/fixture'},cwd=Path('/fixture'),timeout=1)
                self.assertNotIn('PRIVATE_SECRET',str(error.exception))

    def test_sdk_is_required_and_old_protocol_text_cannot_qualify(self):
        def absent(fixture):
            fixture.installation_factory._manifest['sourceContracts'][0].pop('sdkEntry')
        first,_second,effects=self.invoke(sdk_mutation=absent)
        self.assertEqual(first['ledgerState'],'blocked');self.assertEqual(effects,[])

    def test_probe_actual_hello_version_build_protocol_and_methods_are_required(self):
        for changes in (dict(protocol=1),dict(protocol=True),dict(version='other'),dict(buildId='other'),
                        dict(bootId=''),dict(methods=['sessions.describe']),dict(methods=['sessions.reset','sessions.reset'])):
            with self.subTest(changes=changes):
                def changed(fixture):fixture.probe.return_value=sdk_reply(None,**changes)
                first,_second,effects=self.invoke(sdk_mutation=changed)
                self.assertEqual(first['ledgerState'],'blocked');self.assertEqual(effects,[])

    def test_probe_window_source_and_hello_boot_drift_are_refused(self):
        for kind in ('source','boot'):
            with self.subTest(kind=kind):
                def changed(fixture):
                    calls=[]
                    def probe(argv,**kwargs):
                        payload=json.loads(argv[2]);calls.append(payload)
                        self.assertEqual(payload['mode'],'probe');self.assertEqual(payload['method'],'health')
                        self.assertEqual(payload['server']['bootId'],None)
                        self.assertEqual(kwargs['cwd'],fixture.code)
                        self.assertEqual(kwargs['environment'],dict(fixture.qualification.rpc_environment))
                        self.assertNotIn('token',payload)
                        if kind=='source':(fixture.code/'sdk.mjs').write_text('// changed during hello\n')
                        return sdk_reply(None,bootId='new-boot' if kind=='boot' and len(calls)>1 else 'server-boot')
                    fixture.probe.side_effect=probe
                first,_second,effects=self.invoke(sdk_mutation=changed)
                self.assertEqual(first['ledgerState'],'blocked');self.assertEqual(effects,[])

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
            if calls == 3: (fixture.code / 'sdk.mjs').write_text('// SDK source changed\n')
        first, _second, effects = self.invoke(mutation=mutate)
        self.assertEqual(first['ledgerState'], 'blocked')
        self.assertEqual(effects, [])

    def test_same_bytes_inode_replacement_is_refused(self):
        def mutate(fixture, calls):
            if calls == 3:
                file = fixture.code / 'sdk.mjs'
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
            if calls == 1: (fixture.code / 'sdk.mjs').write_text('// SDK source changed\n')
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
        # Existing uncertain intent is a read-only historical receipt, never
        # a new authorization or retry after a changed producer observation.
        self.assertEqual(second['result'], 'existing')
        self.assertEqual(second['ledgerState'], 'uncertain')
        self.assertTrue(second['historicalExisting'])
        self.assertFalse(second['authorizationReused'])
        self.assertEqual(effects, [])

    def test_nonzero_mutation_remains_uncertain_and_never_retries(self):
        first, second, effects = self.invoke(nonzero=True)
        self.assertEqual(first['ledgerState'], 'uncertain')
        self.assertEqual(second['ledgerDisposition'], 'existing')
        self.assertEqual(len(effects), 1)
        self.assertNotIn('PRIVATE_SECRET', str(first))


if __name__ == '__main__': unittest.main()
