"""Registry-derived collector topology, without any actuator or live process."""
import contextlib
from types import SimpleNamespace
import unittest
from unittest import mock
from test_registry_safety import stabilityd as d


class HermesCollectorTopologyTests(unittest.TestCase):
    def collect(self, status, residency='served', fail=False):
        route=SimpleNamespace(last_residency=residency,peer_identity={'pid':4242},
                              verify=mock.Mock(side_effect=ValueError('refused') if fail else None))
        profile='registry_worker';findings=[]
        registry={profile:{'agentIds':['worker'],'registryRecords':[{}]}}
        patches={
            'ps_rows':[], 'hermers_profiles_from_runtime_registry':(registry,{'source':'db','writeEligible':True}),
            'hermes_installation_decision':SimpleNamespace(status=status,qualification=object()),
            'current_host_generation':'node:boot','load_json':{'pid':999},
            'hermers_gateway_processes':[], 'hermers_acp_workers':[], 'hermers_lsp_processes':[],
            'update_hermers_lsp_idle_state':[], 'hermers_profile_workflow_activity':{},
            'hermers_workflow_summary':{},
            'build_hermers_profile_modes':{'profiles':{profile:{'expectedActive':True,'managed':True,'lifecycleActionAllowed':True}}},
        }
        with contextlib.ExitStack() as stack:
            for name,value in patches.items(): stack.enter_context(mock.patch.object(d,name,return_value=value))
            unit=stack.enter_context(mock.patch.object(d,'systemctl_user_show',return_value={'ActiveState':'active','SubState':'running','MainPID':123}))
            stack.enter_context(mock.patch('stability_core.hermes_native_route.MuxRoute',return_value=route))
            result=d.hermers_collect(None,findings,persist_cache=False)
        return result,findings,unit,route

    def test_served_mux_uses_actual_peer_and_never_old_unit(self):
        result,findings,unit,route=self.collect('supported-mux')
        row=result['profiles']['registry_worker']
        self.assertTrue(row['active']);self.assertEqual(row['pid'],4242)
        self.assertEqual(row['topology'],'mux');self.assertIsNone(row['unit'])
        unit.assert_not_called();route.verify.assert_called_once()
        self.assertFalse(any(f['key'] in {'hermers_gateway_service_down','hermers_gateway_state_pid_mismatch'} for f in findings))

    def test_verified_unserved_mux_is_not_promoted_to_active(self):
        result,findings,unit,_=self.collect('supported-mux','unserved')
        self.assertFalse(result['profiles']['registry_worker']['active']);unit.assert_not_called()
        self.assertTrue(any(f['key']=='hermers_gateway_service_down' for f in findings))

    def test_unknown_or_failed_mux_never_becomes_false_service_down_or_authority(self):
        for status,fail in [('unknown',False),('supported-mux',True)]:
            with self.subTest(status=status):
                result,findings,unit,_=self.collect(status,fail=fail)
                self.assertEqual(result['profiles']['registry_worker']['topology'],'unknown')
                self.assertFalse(result['profileModes']['profiles']['registry_worker']['lifecycleActionAllowed'])
                self.assertTrue(any(f['key']=='hermers_gateway_observation_unknown' for f in findings))
                self.assertFalse(any(f['key']=='hermers_gateway_service_down' for f in findings));unit.assert_not_called()

    def test_native_keeps_unit_and_state_pid_checks(self):
        result,findings,unit,_=self.collect('supported-native')
        self.assertEqual(result['profiles']['registry_worker']['pid'],123)
        unit.assert_called_once_with('hermes-gateway-registry_worker.service')
        self.assertTrue(any(f['key']=='hermers_gateway_state_pid_mismatch' for f in findings))
