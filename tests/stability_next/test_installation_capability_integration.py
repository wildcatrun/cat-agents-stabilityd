"""Owned artifact -> actual factory -> existing reader/daemon/ledger entry.

Fixture source contract is independently fixed by the existing reviewed source
excerpts; production installed metadata is a separate qualification artifact.
"""
import contextlib
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import test_hermes_native_route_integration as base
from stability_core import installation_capability as installation
from stability_core import hermes_native_route as native
from stability_core.effect_capability import EffectRequest, EffectOperation


def fixture_manifest(f):
    environment=('Environment=HERMES_HOME={home}\nEnvironmentFiles={home}/.env (ignore_errors=yes)\n'
                 'PassEnvironment=\nUnsetEnvironment=\nWorkingDirectory={home}\n')
    return dict(schemaVersion=1,sourceContracts=[dict(id='fixture-native-source-v1',family='hermes',kind='native',
        semantics='reviewed-hermes-profile-standalone-source-window-v1',files=[dict(path=name,
        sha256=hashlib.sha256(text.encode()).hexdigest()) for name,text in base.SOURCES.items()])],
        installations=[dict(id='fixture-installation',nodeId='fixture-node',family='hermes',status='qualified',
        ownerUid=f.q.owner_uid,codeRoot=str(f.root),runtimeRoot=str(f.q.runtime_root),unitRoots=[str(f.root/'units')],
        contracts=dict(native='fixture-native-source-v1'),nativeArgv=[str(f.root/'python'),'-m','hermes_cli.main',
            '--profile','{profile}','gateway','run'],interpreterSha256=hashlib.sha256(base.BINARY).hexdigest(),
        absentSources=[str(f.root/'.op.env'),str(f.root/'project.env')],managerSha256=hashlib.sha256(b'').hexdigest(),
        unitEnvironmentTemplate=environment)])


@contextlib.contextmanager
def assembled_fixture(change=None):
    with base.fixture() as f:
        data=fixture_manifest(f)
        if change:change(data)
        raw=(json.dumps(data,sort_keys=True)+'\n').encode();path=f.root/'installations.json';path.write_bytes(raw);path.chmod(0o600)
        factory=installation.InstallationFactory.from_artifact(path,hashlib.sha256(raw).hexdigest())
        # Only external release artifact location is injected; qualification
        # objects are constructed by the real factory, not set in globals.
        with mock.patch.object(installation,'load_packaged_installations',return_value=factory), \
             mock.patch.object(base.daemon.platform,'node',return_value='fixture-node'), \
             mock.patch.object(base.daemon,'current_host_generation',return_value='fixture-node:boot'), \
             mock.patch.object(native,'NATIVE_QUALIFICATION',None), \
             mock.patch.object(native,'MUX_QUALIFICATION',None):
            yield f,factory,path


class InstallationCapabilityIntegrationTests(unittest.TestCase):
    def test_literal_argv_braces_are_not_routing_placeholders(self):
        values=dict(profile='fixture',home='/fixture/home',runtime_root='/fixture/runtime')
        literal="print({'ids': ids, 'count': len(ids), 'flags': {1, 2}})"
        self.assertEqual(installation._render_template(literal,values),literal)
        self.assertEqual(installation._render_template('{home}/{profile}:{runtime_root}',values),
                         '/fixture/home/fixture:/fixture/runtime')
        self.assertEqual(installation._render_template('{unknown}',values),'{unknown}')
        # Replacement paths containing braces are not expanded a second time.
        self.assertEqual(installation._render_template('{home}',dict(values,home='/fixture/{profile}')),
                         '/fixture/{profile}')
        from test_hermes_mux_route_integration import mux_fixture
        with mux_fixture(with_socket=False) as fixture:
            factory=fixture.installation_factory
            layout=factory._manifest['installations'][0]
            layout['muxPeerArgv']=['/fixture/python','-c',literal+"; print('{profile}')"]
            factory._boot_reader=lambda:'fixture-boot'
            request=EffectRequest('hermes.profile.lifecycle',EffectOperation.HERMES_CLI,
                'hermes-profile:catbody',layout['nodeId'],layout['nodeId']+':fixture-boot')
            decision=factory.hermes(request,fixture.registry,'catbody')
            self.assertEqual(decision.status,'supported-mux',decision)
            expected=hashlib.sha256(b'\0'.join(token.encode() for token in layout['muxPeerArgv'])+b'\0').hexdigest()
            self.assertEqual(decision.qualification.peer_cmdline_digest,expected)
            self.assertFalse(decision.action_authorized)

    def test_owned_contract_factory_connects_actual_native_restart_without_qualification_globals(self):
        with assembled_fixture() as (f,factory,path):
            result=base.NativeIntegrationTests().restart()
            self.assertEqual(result.get('ledgerState'),'succeeded',result)
            self.assertTrue(result['nativeRouteUsed']);self.assertEqual(len(f.effects),1)
            self.assertEqual(f.effects[0][-2],'restart')

    def test_one_installation_governs_two_registry_targets_without_profile_catalog(self):
        with assembled_fixture() as (f,factory,path):
            home=f.q.runtime_root/'profiles/catnose';home.mkdir()
            (home/'config.yaml').write_text('gateway:\n  standalone: true\n')
            other=f.root/'units/hermes-gateway-catnose.service'
            other.write_text(f.unit.read_text().replace('catbody','catnose'))
            f.registry['records'].append(dict(agent_id='cat_nose',runtime='hermers',platform='hermes',
                execution_adapter='hermes_acp',endpoint_ref='hermes-profile:catnose',status='active',can_receive_dispatch=1))
            original=base.daemon.run_user_cmd.side_effect
            def read_and_effect(argv,timeout=10):
                reply=original(argv,timeout)
                if '--property=' in argv[-1] and argv[-2]=='hermes-gateway-catnose.service':
                    reply.stdout=reply.stdout.replace('catbody','catnose')
                return reply
            with mock.patch.object(base.daemon,'run_user_cmd',side_effect=read_and_effect):
                for profile in ('catbody','catnose'):
                    f.state.update(ActiveState='inactive',SubState='dead')
                    unit='hermes-gateway-'+profile+'.service'
                    policy=dict(canRestartHermersGateway=True,hermersGatewayRestartReason='down',
                        hermersGatewayRestartProfiles=[dict(profile=profile,unit=unit)],
                        updatedAtEpoch=base.daemon.epoch()-1,validUntilEpoch=base.daemon.epoch()+60)
                    result=base.daemon.hermers_gateway_restart(mock.Mock(),profile,unit,'down',policy=policy,snapshot_generation='fixture')
                    self.assertEqual(result.get('ledgerState'),'succeeded',result)
            self.assertEqual(len(f.effects),2)
            self.assertNotIn('catbody',path.read_text());self.assertNotIn('catnose',path.read_text())

    def test_unqualified_source_or_layout_cannot_fallback_to_cli(self):
        for kind in ('layout','source','source-drift','mux-without-contract'):
            def change(data):
                if kind=='layout':data['installations'][0]['status']='pending'
                if kind=='source':data['sourceContracts'][0]['files'][0]['sha256']='0'*64
            with self.subTest(kind=kind),assembled_fixture(change) as (f,factory,path), \
                 mock.patch.object(base.daemon,'run_hermes_profile_gateway_cmd',side_effect=AssertionError('unqualified fallback')) as cli:
                if kind=='source-drift':f.code.write_text('# replaced\n')
                if kind=='mux-without-contract':(f.home/'config.yaml').write_text('gateway:\n  standalone: false\n')
                result=base.NativeIntegrationTests().restart()
                self.assertEqual(result['result'],'blocked',result)
                if kind=='layout':self.assertEqual(result['blockedReason'],'hermes-installation-unqualified')
                self.assertEqual(f.effects,[]);cli.assert_not_called()

    def test_registry_remains_target_authority_and_no_profile_roster_is_needed(self):
        with assembled_fixture() as (f,factory,path):
            request=EffectRequest('hermes.gateway.restart',EffectOperation.HERMES_CLI,
                'hermes-gateway:catbody','fixture-node','fixture-node:boot')
            decision=factory.hermes(request,f.registry,'catbody')
            self.assertEqual(decision.status,'supported-native')
            self.assertFalse(decision.action_authorized)
            for change in ('revoked','duplicate','snapshot','stale-adapter','missing-primary-runtime'):
                registry=json.loads(json.dumps(f.registry))
                if change=='revoked':registry['records'][0]['status']='dormant'
                elif change=='duplicate':registry['records'].append(dict(registry['records'][0]))
                elif change=='stale-adapter':registry['records'][0]['runtime']='openclaw'
                elif change=='missing-primary-runtime':registry['records'][0].pop('runtime')
                else:registry.update(source='snapshot',writeEligible=False)
                self.assertEqual(factory.hermes(request,registry,'catbody').status,'unknown')
            self.assertNotIn('catbody',path.read_text())

    def test_packaged_catalog_is_actual_source_material_without_invented_members_or_activation(self):
        # The isolated Linux runner has a different UID than the read-only
        # checkout owner. Exercise the production loader against an owned copy
        # of exactly the pinned release artifact, without weakening its guards.
        raw=installation.PACKAGED_MANIFEST.read_bytes()
        with tempfile.TemporaryDirectory(dir=Path.home()) as directory:
            path=Path(directory)/'qualified_installations_v1.json'
            path.write_bytes(raw);path.chmod(0o600)
            with mock.patch.object(installation,'PACKAGED_MANIFEST',path):
                factory=installation.load_packaged_installations()
        catalog=factory._manifest
        self.assertEqual({c['family'] for c in catalog['sourceContracts']},{'hermes','openclaw'})
        self.assertEqual({c['kind'] for c in catalog['sourceContracts']},{'native','mux','session'})
        self.assertTrue(all(c['files'] for c in catalog['sourceContracts']))
        self.assertTrue(all(i['missingQualificationInputs'] for i in catalog['installations']))
        self.assertTrue(all(i['observedAdmissionBlocks'] for i in catalog['installations']))
        text=installation.PACKAGED_MANIFEST.read_text()
        for member in ('catbody','catears','cateyes','catheart','catnose','catpenclaw'):
            self.assertNotIn(member,text)

    def test_manifest_pin_and_first_observation_unsafe_routes_are_refused(self):
        with assembled_fixture() as (f,factory,path):
            digest=hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):installation.InstallationFactory.from_artifact(path,'0'*64)
            path.chmod(0o666)
            with self.assertRaises(ValueError):installation.InstallationFactory.from_artifact(path,digest)
            path.chmod(0o600)
            link=f.root/'contract-link';link.symlink_to(path)
            with self.assertRaises((ValueError,OSError)):installation.InstallationFactory.from_artifact(link,digest)


if __name__=='__main__':unittest.main()
