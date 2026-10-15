"""Offline central runtime, real local registry reader and native entry fixtures.

No installed-runtime claim: systemd effects/properties and host boot identity use
existing native owned-file fixture boundaries. The SQLite reader is not mocked.
"""
import contextlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('offline_native_fixture', Path(__file__).with_name('test_hermes_native_route_integration.py'))
base = importlib.util.module_from_spec(SPEC); sys.modules[SPEC.name] = base; SPEC.loader.exec_module(base)
daemon = base.daemon
REAL_REGISTRY_READER = daemon.workflow_runtime_registry_records


@contextlib.contextmanager
def offline_fixture():
    with base.fixture() as f:
        database = f.root / 'workflow.db'
        with sqlite3.connect(database) as conn:
            conn.execute('CREATE TABLE runtime_agents(agent_id TEXT,runtime TEXT,status TEXT,platform TEXT,'
                         'execution_adapter TEXT,can_receive_dispatch INTEGER,can_start_workflow INTEGER,'
                         'gateway_proxy_allowed INTEGER,endpoint_ref TEXT)')
            conn.execute('INSERT INTO runtime_agents VALUES(?,?,?,?,?,?,?,?,?)',
                         ('cat_body','hermers','active','hermes','hermes_acp',1,1,0,'hermes-profile:catbody'))
        f.database = database
        f.policy = dict(canRestartHermersGateway=True, hermersGatewayRestartReason='down',
            hermersGatewayRestartProfiles=[dict(profile='catbody',unit='hermes-gateway-catbody.service')],
            updatedAtEpoch=daemon.epoch()-1, validUntilEpoch=daemon.epoch()+60)
        f.generation = ['boot:fixture']
        with mock.patch.object(daemon, 'WORKFLOW_DB', database), \
             mock.patch.object(daemon, 'WORKFLOW_RUNTIME_AGENTS_SNAPSHOT', f.root/'registry.snapshot.json'), \
             mock.patch.object(daemon, 'workflow_runtime_registry_records', REAL_REGISTRY_READER), \
             mock.patch.object(daemon, 'current_host_generation', side_effect=lambda:f.generation[0]), \
             mock.patch.object(daemon, 'openclaw_gateway_call', return_value=(None,'gateway-unavailable')) as gateway, \
             mock.patch.object(daemon, 'run_hermes_profile_gateway_cmd', side_effect=AssertionError('native route must not call CLI')):
            f.gateway = gateway
            yield f


def restart(f, policy=True):
    return daemon.hermers_gateway_restart(mock.Mock(), 'catbody', 'hermes-gateway-catbody.service',
        'down', policy=f.policy if policy else None, snapshot_generation='offline-snapshot')


class OfflineRegistryEntryTests(unittest.TestCase):
    def test_real_sqlite_owner_and_local_grant_allow_native_repair_with_gateway_unavailable(self):
        with offline_fixture() as f:
            self.assertEqual(daemon.openclaw_gateway_call('health',{}), (None,'gateway-unavailable'))
            registry = daemon.workflow_runtime_registry_records()
            self.assertEqual((registry['source'],registry['writeEligible']), ('db',True))
            self.assertEqual(registry['records'][0]['agent_id'],'cat_body')
            self.assertEqual(registry['records'][0]['runtime'],'hermers')
            result = restart(f)
            self.assertEqual(result.get('ledgerState'),'succeeded',result)
            self.assertEqual(len(f.effects),1)
            self.assertEqual(f.effects[0][-2],'restart')
            # Only the explicit unavailable probe above: native repair never
            # requests a Gateway session, runtime CLI or central authorization.
            self.assertEqual(f.gateway.call_count,1)

    def test_real_sqlite_invalid_empty_duplicate_and_missing_fields_cannot_authorize(self):
        for case in ('empty-id','duplicate-id','missing-field'):
            with self.subTest(case=case), offline_fixture() as f:
                with sqlite3.connect(f.database) as conn:
                    if case=='empty-id': conn.execute("UPDATE runtime_agents SET agent_id=' '")
                    elif case=='duplicate-id': conn.execute('INSERT INTO runtime_agents SELECT * FROM runtime_agents')
                    else: conn.execute("UPDATE runtime_agents SET endpoint_ref=NULL")
                registry=daemon.workflow_runtime_registry_records()
                self.assertEqual(registry['source'],'db',registry)
                self.assertFalse(registry['writeEligible'],registry)
                self.assertEqual(registry['health'],'incomplete')
                if case=='duplicate-id': self.assertEqual(registry['duplicateAgentIds'],['cat_body'])
                self.assertEqual(restart(f).get('result'),'blocked')
                self.assertEqual(f.effects,[])

    def test_missing_or_expired_local_grant_never_reaches_native_effect(self):
        for case in ('missing','expired'):
            with self.subTest(case=case), offline_fixture() as f:
                if case=='expired':
                    f.policy.update(updatedAtEpoch=daemon.epoch()-120,validUntilEpoch=daemon.epoch()-1)
                result=restart(f,policy=case!='missing')
                self.assertEqual(result.get('result'),'blocked',result)
                self.assertEqual(f.effects,[])
                f.gateway.assert_not_called()

    def test_postclaim_grant_revocation_owner_cancellation_and_generation_change_have_zero_effect(self):
        for case in ('grant-revoked','owner-cancelled','generation-changed'):
            with self.subTest(case=case), offline_fixture() as f:
                from stability_core.action_ledger import ActionLedger
                begin = ActionLedger.begin_execution
                claims=[]
                def change_after_claim(ledger,*args,**kwargs):
                    record=begin(ledger,*args,**kwargs);claims.append(record.state)
                    if case=='grant-revoked': f.policy['canRestartHermersGateway']=False
                    elif case=='owner-cancelled':
                        with sqlite3.connect(f.database) as conn:
                            conn.execute("UPDATE runtime_agents SET status='dormant' WHERE agent_id='cat_body'")
                    else: f.generation[0]='boot:changed'
                    return record
                with mock.patch.object(ActionLedger,'begin_execution',change_after_claim):
                    result=restart(f)
                self.assertEqual(claims,['executing'])
                self.assertEqual(result.get('result'),'blocked',result)
                self.assertEqual(f.effects,[])
                f.gateway.assert_not_called()

    def test_valid_json_snapshot_cannot_replace_missing_sqlite_authority(self):
        with offline_fixture() as f:
            rows=daemon.workflow_runtime_registry_records()['records']
            daemon.WORKFLOW_RUNTIME_AGENTS_SNAPSHOT.write_text(json.dumps(dict(
                schemaVersion=1,generatedAt=daemon.ts(),records=rows)))
            f.database.unlink()
            registry=daemon.workflow_runtime_registry_records()
            self.assertEqual(registry['source'],'snapshot')
            self.assertEqual(registry['snapshotHealth'],'fresh_valid_observation_only')
            self.assertFalse(registry['writeEligible'])
            result=restart(f)
            self.assertEqual(result.get('result'),'blocked',result)
            self.assertEqual(f.effects,[])
            f.gateway.assert_not_called()


if __name__=='__main__': unittest.main()
