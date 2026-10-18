"""Finite reviewed launch alternatives; real factory and native route readers."""
import dataclasses
import hashlib
import unittest
from unittest import mock
from stability_core import hermes_native_route as native
from stability_core.effect_capability import EffectRequest, EffectOperation
import test_installation_capability_integration as assembly
import test_hermes_native_route_integration as base

H=lambda text:hashlib.sha256(text.encode()).hexdigest()


def raw_environment(data,profile='catbody'):
    item=data['installations'][0]
    home=item['runtimeRoot']+'/profiles/'+profile
    return item['unitEnvironmentTemplate'].replace('{home}',home)


def reviewed_set(data):
    item=data['installations'][0]
    first=raw_environment(data)
    other=first.replace('Environment=','Environment=FIXTURE_BROWSER=1 ',1)
    item.pop('unitEnvironmentTemplate')
    item['unitEnvironmentSha256s']=[H(first),H(other)]


def environment_override(raw):
    original=base.daemon.run_user_cmd.side_effect
    def reader(argv,timeout=10):
        result=original(argv,timeout)
        if '--property=' in argv[-1] and 'EnvironmentFiles' in argv[-1]:
            result.stdout=raw() if callable(raw) else raw
        return result
    return mock.patch.object(base.daemon,'run_user_cmd',side_effect=reader)


class NativeEnvironmentDigestSetTests(unittest.TestCase):
    def test_factory_set_connects_actual_governed_restart(self):
        with assembly.assembled_fixture(reviewed_set) as (f,factory,path):
            result=base.NativeIntegrationTests().restart()
            self.assertEqual(result['ledgerState'],'succeeded',result)
            self.assertEqual(len(f.effects),1)
            route=base.daemon.resolve_hermes_native_route('catbody','hermes.gateway.restart','fixture-node:boot')
            self.assertEqual(route.q.environment_sha256,'')
            self.assertEqual(type(route.q.environment_sha256s),tuple)
            self.assertEqual(len(route.q.environment_sha256s),2)
            self.assertNotIn('catbody',path.read_text())

    def test_reviewed_set_supports_two_registry_targets_without_roster_mapping(self):
        def change(data):
            item=data['installations'][0]
            approved=[H(raw_environment(data,profile)) for profile in ('catbody','catnose')]
            item.pop('unitEnvironmentTemplate');item['unitEnvironmentSha256s']=approved
        with assembly.assembled_fixture(change) as (f,_,path):
            home=f.q.runtime_root/'profiles/catnose';home.mkdir()
            (home/'config.yaml').write_text('gateway:\n  standalone: true\n')
            (f.root/'units/hermes-gateway-catnose.service').write_text(f.unit.read_text().replace('catbody','catnose'))
            f.registry['records'].append(dict(agent_id='cat_nose',runtime='hermers',platform='hermes',
                execution_adapter='hermes_acp',endpoint_ref='hermes-profile:catnose',status='active',can_receive_dispatch=1))
            original=base.daemon.run_user_cmd.side_effect
            def reader(argv,timeout=10):
                result=original(argv,timeout)
                if '--property=' in argv[-1] and argv[-2]=='hermes-gateway-catnose.service':
                    result.stdout=result.stdout.replace('catbody','catnose')
                return result
            with mock.patch.object(base.daemon,'run_user_cmd',side_effect=reader):
                for profile in ('catbody','catnose'):
                    route=base.daemon.resolve_hermes_native_route(profile,'hermes.gateway.restart','fixture-node:boot')
                    route.verify()
                    self.assertEqual(route.profile,profile)
            self.assertEqual(f.effects,[])
            self.assertNotIn('catbody',path.read_text());self.assertNotIn('catnose',path.read_text())

    def test_second_reviewed_variant_is_supported_without_observed_approval(self):
        with assembly.assembled_fixture(reviewed_set) as (f,factory,path):
            expected=assembly.fixture_manifest(f)
            raw=raw_environment(expected).replace('Environment=','Environment=FIXTURE_BROWSER=1 ',1)
            with environment_override(raw):
                result=base.NativeIntegrationTests().restart()
            self.assertEqual(result['ledgerState'],'succeeded',result)
            self.assertEqual(len(f.effects),1)

    def test_invalid_or_ambiguous_manifest_sets_are_unknown(self):
        invalid=([],['0'*64]*2,['A'*64],['x'],[1],None,'0'*64,
                 [H(str(n)) for n in range(17)])
        for value in invalid:
            def change(data):
                reviewed_set(data);data['installations'][0]['unitEnvironmentSha256s']=value
            with self.subTest(value=value),assembly.assembled_fixture(change) as (f,factory,path):
                request=EffectRequest('hermes.gateway.restart',EffectOperation.HERMES_CLI,
                    'hermes-gateway:catbody','fixture-node','fixture-node:boot')
                decision=factory.hermes(request,f.registry,'catbody')
                self.assertEqual(decision.status,'unknown')
                self.assertFalse(decision.action_authorized)
                self.assertEqual(f.effects,[])
        for legacy in ('unitEnvironmentSha256','unitEnvironmentTemplate'):
            def change(data):
                reviewed_set(data);data['installations'][0][legacy]='0'*64
            with self.subTest(legacy=legacy),assembly.assembled_fixture(change) as (f,_,_):
                result=base.NativeIntegrationTests().restart()
                self.assertEqual(result['result'],'blocked')
                self.assertEqual(f.effects,[])

    def test_qualification_requires_immutable_bounded_strict_tuple_before_io(self):
        with base.fixture() as f:
            request=EffectRequest('hermes.gateway.restart',EffectOperation.SYSTEMD_UNIT,
                'hermes-gateway:catbody','fixture-node','fixture-node:boot')
            invalid=(['0'*64],('A'*64,),('0'*64,'0'*64),tuple(H(str(n)) for n in range(17)),(None,))
            for values in invalid:
                q=dataclasses.replace(f.q,environment_sha256='',environment_sha256s=values)
                read=mock.Mock(side_effect=AssertionError('must refuse before observation'))
                with self.subTest(values=values),self.assertRaises(ValueError):
                    native.NativeRoute(q,request,'catbody',read_properties=read,read_environment=read,read_manager=read,clock_ms=lambda:1000)
                read.assert_not_called()

    def test_unknown_measured_digest_never_expands_set(self):
        with assembly.assembled_fixture(reviewed_set) as (f,_,_):
            raw=raw_environment(assembly.fixture_manifest(f)).replace('Environment=','Environment=UNREVIEWED=1 ',1)
            with environment_override(raw):
                result=base.NativeIntegrationTests().restart()
            self.assertEqual(result['result'],'blocked')
            self.assertEqual(f.effects,[])

    def test_two_approved_variants_cannot_drift_within_observation_window(self):
        with assembly.assembled_fixture(reviewed_set) as (f,_,_):
            raw=raw_environment(assembly.fixture_manifest(f));calls=[]
            def changing():
                calls.append(1)
                return raw if len(calls)==1 else raw.replace('Environment=','Environment=FIXTURE_BROWSER=1 ',1)
            with environment_override(changing),self.assertRaisesRegex(ValueError,'window drift'):
                base.daemon.resolve_hermes_native_route('catbody','hermes.gateway.restart','fixture-node:boot')
            self.assertEqual(f.effects,[])

    def test_selected_approved_digest_is_pinned_across_verify_calls(self):
        with assembly.assembled_fixture(reviewed_set) as (f,_,_):
            raw=raw_environment(assembly.fixture_manifest(f));current=[raw]
            with environment_override(lambda:current[0]):
                route=base.daemon.resolve_hermes_native_route('catbody','hermes.gateway.restart','fixture-node:boot')
                route.verify()
                current[0]=raw.replace('Environment=','Environment=FIXTURE_BROWSER=1 ',1)
                with self.assertRaisesRegex(ValueError,'identity drift'):route.verify()
            self.assertEqual(f.effects,[])

    def test_reviewed_hash_does_not_override_profile_home_semantics(self):
        holder={}
        def change(data):
            raw=raw_environment(data).replace('Environment=HERMES_HOME=','Environment=HERMES_HOME=/wrong',1)
            holder['raw']=raw;item=data['installations'][0]
            item.pop('unitEnvironmentTemplate');item['unitEnvironmentSha256s']=[H(raw)]
        with assembly.assembled_fixture(change) as (f,_,_):
            with environment_override(holder['raw']):result=base.NativeIntegrationTests().restart()
            self.assertEqual(result['result'],'blocked')
            self.assertEqual(f.effects,[])

    def test_legacy_single_digest_and_template_keep_supported_route(self):
        for mode in ('single','template'):
            def change(data):
                if mode=='single':
                    item=data['installations'][0];raw=raw_environment(data)
                    item.pop('unitEnvironmentTemplate');item['unitEnvironmentSha256']=H(raw)
            with self.subTest(mode=mode),assembly.assembled_fixture(change) as (f,_,_):
                result=base.NativeIntegrationTests().restart()
                self.assertEqual(result['ledgerState'],'succeeded',result)
                self.assertEqual(len(f.effects),1)

if __name__=='__main__':unittest.main()
