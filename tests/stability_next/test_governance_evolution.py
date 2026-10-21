"""S1 regressions for registered scope, pressure evidence and local impact."""
from __future__ import annotations
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT=pathlib.Path(__file__).resolve().parents[2]
_tmp=tempfile.TemporaryDirectory(prefix='stability-evolution-tests-')
os.environ['OPENCLAW_HOME_DIR']=_tmp.name
os.environ['CAT_AGENTS_WORKFLOW_ROOT']=str(pathlib.Path(_tmp.name)/'workflow')
os.environ['CAT_AGENTS_WORKFLOW_DB']=str(pathlib.Path(_tmp.name)/'absent.db')
os.environ['CAT_AGENTS_STABILITY_CODEX_AUTH_PATH']=str(pathlib.Path(_tmp.name)/'absent-auth.json')
spec=importlib.util.spec_from_file_location('evolution_daemon', ROOT/'bin/cat_agents_stabilityd.py')
d=importlib.util.module_from_spec(spec);sys.modules[spec.name]=d;spec.loader.exec_module(d)
from stability_core.governance_decisions import commit_pressure_corroboration, observation_contract


def row(agent='main',adapter='native',**changes):
    return {'agent_id':agent,'runtime':'openclaw','platform':'openclaw','execution_adapter':adapter,
            'status':'active','can_receive_dispatch':1,'endpoint_ref':'openclaw-agent:'+agent,**changes}


def finding(key,component='cron',severity='high'):
    return {'key':key,'severity':severity,'component':component,'message':'fixture'}


class GovernanceEvolutionTests(unittest.TestCase):
    def policy(self, findings, snapshot=None):
        snapshot=snapshot or {'gateway':{'active':True,'portOk':True,'healthOk':True},'cron':{'storageStatus':{'storage':'sqlite'}}}
        streaks={f['key']:{'count':100,'firstSeen':d.epoch()-3600,'lastSeen':d.epoch()} for f in findings}
        with d.init_memory_kv_db() as conn, mock.patch.object(d,'mechanical_timing_projection',return_value=None):
            return d.policy_from_findings(conn,findings,snapshot,streaks)

    def test_native_registry_scope_and_legacy_adapter(self):
        ids=['main','cat_claw','cat_voice','cat_tail','cat_gunclaw','cat_swordclaw','cat_shieldclaw']
        result,rejected=d.openclaw_auth_scope_from_registry({'records':[row(a) for a in ids]})
        self.assertEqual(result,sorted(ids));self.assertEqual(rejected,[])
        self.assertEqual(d.openclaw_auth_scope_from_registry({'records':[row(adapter='openclaw') ]})[0],['main'])

    def test_invalid_legacy_shell_unknown_adapter_and_endpoint_remain_excluded(self):
        rows=[row(adapter='openclaw_route_shell'),row(adapter='unqualified'),
              row(endpoint_ref='openclaw-agent:other'),row(can_receive_dispatch=0),row(status='retired')]
        selected,rejected=d.openclaw_auth_scope_from_registry({'records':rows})
        self.assertEqual(selected,[]);self.assertEqual(len(rejected),1)

    def test_empty_registry_never_invents_targets(self):
        self.assertEqual(d.openclaw_auth_scope_from_registry({}),([],[]))

    def test_failed_heartbeat_is_visible_without_global_congestion(self):
        p=self.policy([finding('cron_heartbeat_unhealthy')])
        self.assertEqual(p['severity'],'high');self.assertEqual(p['mode'],'degraded')
        self.assertFalse(p['shouldPauseNonCriticalCron']);self.assertFalse(p['deferControlPlaneHeavyReports'])
        self.assertFalse(p['restartCandidate']);self.assertFalse(p['lanes']['cron']['pressure'])
        self.assertEqual(p['lanes']['cron']['maxConcurrency'],d.CRON_MAX_CONCURRENCY_NORMAL)

    def test_actual_congestion_still_constrains_cron(self):
        p=self.policy([finding('gateway_congestion_logs')])
        self.assertEqual(p['mode'],'cron-congested');self.assertTrue(p['shouldPauseNonCriticalCron'])
        self.assertTrue(p['lanes']['cron']['pressure'])

    def test_stale_lease_still_has_runtime_pressure(self):
        p=self.policy([finding('cron_expired_leases')])
        self.assertEqual(p['mode'],'cron-state-corrupt');self.assertTrue(p['lanes']['cron']['pressure'])

    def test_hermes_local_failure_does_not_pause_openclaw_cron(self):
        p=self.policy([finding('hermers_runtime_failure_burst','hermers')])
        self.assertEqual(p['mode'],'hermers-degraded');self.assertFalse(p['shouldPauseNonCriticalCron'])
        self.assertFalse(p['lanes']['cron']['pressure'])
        self.assertEqual(p['lanes']['cron']['maxConcurrency'],d.CRON_MAX_CONCURRENCY_NORMAL)

    def test_raw_commit_ratio_is_capacity_risk_and_does_not_gate_all_work(self):
        p=self.policy([finding('system_commit_pressure','resource','warning')])
        self.assertFalse(p['deferControlPlaneHeavyReports']);self.assertFalse(p['lanes']['secondaryPressureDomains']['resource'])
        self.assertEqual(p['decisionEvidence']['classifications'][0]['kind'],'capacity-risk')

    def test_commit_corroboration_requires_both_pressure_and_low_available(self):
        low={'psi':{'some':{'avg10':0.0},'full':{'avg10':0.0}},'vmstatCounters':{'oom_kill':999}}
        high={'psi':{'some':{'avg10':2.0},'full':{'avg10':0.2}}}
        self.assertFalse(commit_pressure_corroboration(low,2700,1000)['corroborated'])
        self.assertFalse(commit_pressure_corroboration(high,2700,1000)['corroborated'])
        self.assertTrue(commit_pressure_corroboration(high,500,1000)['corroborated'])
        self.assertFalse(commit_pressure_corroboration({},500,1000)['scopeComplete'])

    def test_corroborated_pressure_keeps_real_protection(self):
        p=self.policy([finding('system_commit_runtime_pressure','resource','critical')])
        self.assertEqual(p['mode'],'resource-pressure');self.assertTrue(p['deferControlPlaneHeavyReports'])
        self.assertTrue(p['lanes']['secondaryPressureDomains']['resource'])

    def test_successful_transport_with_empty_scope_is_not_complete(self):
        contract=observation_contract('auth',{'openclaw':{'scopeComplete':False}}, {'status':'ok'})
        self.assertTrue(contract['transportSuccess']);self.assertFalse(contract['scopeComplete'])
        self.assertEqual(contract['readiness'],'unknown')

    def test_probe_error_and_unknown_profile_do_not_infer_ready_or_idle(self):
        contract=observation_contract('hermers',{'profileRegistry':{}},{'status':'error'})
        self.assertFalse(contract['scopeComplete']);self.assertEqual(contract['readiness'],'unknown')
        contract=observation_contract('hermers',{'profileRegistry':{}},{'status':'ok'})
        self.assertIsNone(contract['scopeComplete']);self.assertNotEqual(contract['readiness'],'ready')

    def test_resource_collect_keeps_capacity_warning_without_incident(self):
        context={'psi':{'some':{'avg10':0.0},'full':{'avg10':0.0}},'overcommitMode':0,'commitInterpretation':'fixture'}
        mem={'MemTotal':8*1024**3,'MemAvailable':3*1024**3,'SwapTotal':8*1024**3,'SwapFree':8*1024**3,'CommitLimit':12*1024**3,'Committed_AS':int(11.9*1024**3)}
        with mock.patch.object(d,'backup_disk_summary',return_value={}),mock.patch.object(d,'meminfo_bytes',return_value=mem),mock.patch.object(d,'memory_pressure_context',return_value=context):
            findings=[];resource=d.resource_collect(findings)
        item=next(f for f in findings if f['key']=='system_commit_pressure')
        self.assertEqual(item['severity'],'warning');self.assertFalse(resource['memory']['commitCorroboration']['corroborated'])
        d.add_resource_governance_findings(findings,{'resource':resource},{'system_commit_pressure':{'count':100}})
        self.assertNotIn('gateway_resource_incident',[f['key'] for f in findings])

if __name__=='__main__':
    try:unittest.main()
    finally:_tmp.cleanup()
