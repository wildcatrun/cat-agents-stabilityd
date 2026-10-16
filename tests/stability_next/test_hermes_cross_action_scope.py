"""Cross-action exclusion uses the real SQLite transaction and daemon entries."""
import contextlib
import importlib.util
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from stability_core.action_ledger import ActionConflict, ActionLedger
from stability_core import hermes_native_route

SPEC=importlib.util.spec_from_file_location('hermes_cross_scope_daemon',Path(__file__).resolve().parents[2]/'bin/cat_agents_stabilityd.py')
m=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=m;SPEC.loader.exec_module(m)

def plan(ledger, target, key='prior', state='planned', generation='old-generation'):
    record=ledger.plan_action(idempotency_key=key,action_type='fixture-repair',target=target,
        generation=generation,input_data={'fixture':True},authorization_ref='auth://fixture',
        policy_ref='policy://fixture',evidence_refs=('evidence://fixture',))
    if state!='planned':
        record=ledger.begin_execution(record.action_id,expected_version=record.version,precheck_ref='check://fixture')
    if state in {'uncertain','succeeded','failed','blocked'}:
        record=ledger.transition(record.action_id,expected_state='executing',expected_version=record.version,
            new_state=state,outcome_ref='outcome://fixture',postcheck_ref='check://fixture')
    return record

@contextlib.contextmanager
def fixture(profile="catbody"):
    with tempfile.TemporaryDirectory() as temporary,contextlib.ExitStack() as stack:
        path=Path(temporary)/'state.db'
        registry=dict(source='db',writeEligible=True,records=[dict(agent_id='cat_body',runtime='hermes_acp',
            platform='hermes',execution_adapter='hermes_acp',endpoint_ref="hermes-profile:"+profile,status='active',can_receive_dispatch=1)])
        effects=[]
        def command(profile,verb,timeout=60):
            if verb!='status':effects.append((profile,verb))
            return SimpleNamespace(returncode=0,stdout='Gateway active and running',stderr='')
        # Deliberately isolate alias transaction guards from source capability:
        # this suite's fake CLI is not an installation-qualification positive.
        for patch in (mock.patch.object(m,'resolve_hermes_native_route',return_value=None),
                      mock.patch.object(m,'resolve_hermes_mux_route',return_value=None),
                      mock.patch.object(m,'STATE_DB',path),mock.patch.object(hermes_native_route,'NATIVE_QUALIFICATION',None),
                      mock.patch.object(m,'workflow_runtime_registry_records',return_value=registry),
                      mock.patch.object(m,'current_host_generation',return_value='new-generation'),
                      mock.patch.object(m,'db_get',return_value=0),mock.patch.object(m,'db_set'),
                      mock.patch.object(m,'record_hermers_gateway_restart_time'),
                      mock.patch.object(m,'recent_hermers_gateway_restart_history',return_value=[]),
                      mock.patch.object(m,'HERMERS_PROFILE_LIFECYCLE_ALLOWLIST',{profile}),
                      mock.patch.object(m,'HERMERS_PROFILE_MODE_START_ENABLED',True),
                      mock.patch.object(m,'hermers_profile_workflow_activity',return_value={profile:dict(probeOk=True,activeRuntimeCount=0,activeDispatchCount=0)}),
                      mock.patch.object(m,'systemctl_user_show',return_value={'ActiveState':'inactive','SubState':'dead'}),
                      mock.patch.object(m,'run_hermes_profile_gateway_cmd',side_effect=command)):
            stack.enter_context(patch)
        yield path,effects

def entry(kind, profile="catbody"):
    policy=dict(updatedAtEpoch=m.epoch()-1,validUntilEpoch=m.epoch()+60)
    if kind=='restart':
        policy.update(canRestartHermersGateway=True,hermersGatewayRestartReason='down',
                      hermersGatewayRestartProfiles=[dict(profile=profile,unit=f"hermes-gateway-{profile}.service")])
        return m.hermers_gateway_restart(mock.Mock(),profile,f"hermes-gateway-{profile}.service",'down',policy=policy,snapshot_generation='fixture')
    policy.update(hermersProfileModeActuateEnabled=True,hermersProfileModeStartEnabled=True)
    return m.execute_hermers_profile_lifecycle(mock.Mock(),profile,dict(unit=f"hermes-gateway-{profile}.service",
        managed=True,activeWork=False,active=False,safeToHibernate=True,agentIds=['cat_body']), 'hot',policy,'fixture')

class CrossActionTests(unittest.TestCase):
    def insert_legacy_alias(self, ledger, original, target, state):
        """Seed a valid old-writer reservation without the new alias guard."""
        row = dict(ledger._conn.execute('SELECT * FROM action_ledger WHERE action_id=?',
                                       (original.action_id,)).fetchone())
        row.update(action_id=ActionLedger.stable_action_id('legacy-other'),
                   idempotency_key='legacy-other', target=target, state=state,
                   version=2, outcome_ref='outcome://legacy', postcheck_ref='check://legacy')
        columns = tuple(row)
        ledger._conn.execute('INSERT INTO action_ledger (' + ','.join(columns) + ') VALUES ('
                             + ','.join('?' for _ in columns) + ')', tuple(row[k] for k in columns))

    def test_legacy_dual_active_aliases_cannot_claim_existing_plan(self):
        for first, other in [('hermes-gateway:catbody','hermes-profile:CatBody'),
                             ('hermes-profile:catbody','hermes-gateway:CatBody')]:
            for state in ('planned','executing','uncertain'):
                with self.subTest(first=first,state=state), tempfile.TemporaryDirectory() as temporary:
                    with ActionLedger(Path(temporary)/'ledger.db') as ledger:
                        original = plan(ledger, first)
                        self.insert_legacy_alias(ledger, original, other, state)
                        self.assertEqual(plan(ledger, first), original)
                        with self.assertRaises(ActionConflict):
                            ledger.begin_execution(original.action_id, expected_version=original.version,
                                                   precheck_ref='check://fixture')
                        self.assertEqual(ledger.get(original.action_id), original)

    def test_legacy_alias_added_after_claim_blocks_final_precheck_write(self):
        with tempfile.TemporaryDirectory() as temporary, ActionLedger(Path(temporary)/'ledger.db') as ledger:
            original = plan(ledger, 'hermes-gateway:catbody')
            claimed = ledger.begin_execution(original.action_id, expected_version=original.version,
                                             precheck_ref='check://fixture')
            self.insert_legacy_alias(ledger, claimed, 'hermes-profile:catbody', 'uncertain')
            with self.assertRaises(ActionConflict):
                ledger.refresh_execution_precheck(claimed.action_id, expected_version=claimed.version,
                                                   precheck_ref='check://final')
            self.assertEqual(ledger.get(claimed.action_id), claimed)

    def test_both_real_entries_refuse_other_alias_in_all_active_states_and_generations(self):
        for kind,alias in [('restart','hermes-profile:CatBody'),('start','hermes-gateway:CatBody')]:
            for state in ('planned','executing','uncertain'):
                with self.subTest(kind=kind,state=state),fixture() as (path,effects):
                    with ActionLedger(path) as ledger:prior=plan(ledger,alias,state=state)
                    result=entry(kind)
                    self.assertIn(result['result'],('uncertain','blocked'))
                    self.assertEqual(effects,[])
                    with ActionLedger(path) as ledger:
                        self.assertEqual(ledger.get(prior.action_id).state,state)
                        self.assertEqual(ledger._conn.execute('SELECT count(*) FROM action_ledger').fetchone()[0],1)

    def test_same_key_existing_and_terminal_release_keep_targets_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary,ActionLedger(Path(temporary)/'ledger.db') as ledger:
            first=plan(ledger,'hermes-gateway:CatBody')
            self.assertEqual(plan(ledger,'hermes-gateway:CatBody'),first)
            with self.assertRaises(ActionConflict):plan(ledger,'hermes-profile:catbody',key='other')
            executing=ledger.begin_execution(first.action_id,expected_version=first.version,precheck_ref='check://fixture')
            ledger.transition(executing.action_id,expected_state='executing',expected_version=executing.version,
                              new_state='succeeded',outcome_ref='outcome://fixture',postcheck_ref='check://fixture')
            next_record=plan(ledger,'hermes-profile:catbody',key='after')
            self.assertEqual(next_record.target,'hermes-profile:catbody')
            self.assertEqual(first.target,'hermes-gateway:CatBody')

    def test_two_real_entry_connections_race_without_double_effect(self):
        with fixture() as (path,effects):
            ActionLedger(path).close()
            barrier=threading.Barrier(2);original=ActionLedger.plan_action;results=[];errors=[];contender_refused=threading.Event()
            def synchronized(ledger,**kwargs):
                barrier.wait(timeout=10)
                try:return original(ledger,**kwargs)
                except ActionConflict:
                    contender_refused.set();raise
            original_command=m.run_hermes_profile_gateway_cmd.side_effect
            def held_command(profile,verb,timeout=60):
                if verb != "status" and not contender_refused.wait(timeout=10):
                    raise RuntimeError("other alias was not refused before first effect")
                return original_command(profile,verb,timeout)
            def invoke(kind):
                try:results.append(entry(kind))
                except BaseException as error:errors.append(error)
            with mock.patch.object(ActionLedger,'plan_action',synchronized), \
                 mock.patch.object(m,'run_hermes_profile_gateway_cmd',side_effect=held_command):
                threads=[threading.Thread(target=invoke,args=(kind,)) for kind in ('restart','start')]
                for thread in threads:thread.start()
                for thread in threads:thread.join(timeout=15)
                self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors,[])
            self.assertEqual(len(results),2)
            self.assertEqual(len(effects),1)
            with sqlite3.connect(path) as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM action_ledger").fetchone()[0],1)

    def test_all_daemon_accepted_ascii_profile_prefixes_share_reservation(self):
        for profile in ("1cat", "_cat", "-cat", "CatBody", "x" * 64):
            for first, second in (("gateway", "profile"), ("profile", "gateway")):
                with self.subTest(profile=profile, first=first), tempfile.TemporaryDirectory() as temporary:
                    with ActionLedger(Path(temporary)/"ledger.db") as ledger:
                        original = plan(ledger, "hermes-" + first + ":" + profile)
                        with self.assertRaises(ActionConflict):
                            plan(ledger, "hermes-" + second + ":" + profile.swapcase(), key="other")
                        self.assertEqual(ledger.get(original.action_id), original)
                        self.assertEqual(ledger._conn.execute("SELECT count(*) FROM action_ledger").fetchone()[0], 1)

    def test_numeric_profile_real_entries_refuse_opposite_alias(self):
        for kind, alias in (("restart", "profile"), ("start", "gateway")):
            with self.subTest(kind=kind), fixture("1cat") as (path, effects):
                with ActionLedger(path) as ledger:
                    plan(ledger, "hermes-" + alias + ":1cat")
                with mock.patch.object(m, "HERMERS_PROFILE_LIFECYCLE_ALLOWLIST", {"1cat"}):
                    result = entry(kind, "1cat")
                self.assertIn(result["result"], ("uncertain", "blocked"))
                self.assertEqual(result.get("error"), "ActionConflict")
                self.assertEqual(effects, [])
                with ActionLedger(path) as ledger:
                    self.assertEqual(ledger._conn.execute("SELECT count(*) FROM action_ledger").fetchone()[0], 1)

    def test_namespace_and_invalid_profile_are_not_broadened(self):
        with tempfile.TemporaryDirectory() as temporary,ActionLedger(Path(temporary)/'ledger.db') as ledger:
            plan(ledger,'other:catbody',key='other')
            plan(ledger,'hermes-gateway:bad.name',key='badgateway')
            plan(ledger,'hermes-profile:bad.name',key='badprofile')
            plan(ledger,'hermes-profile:catbody',key='real')
            self.assertEqual(ledger._conn.execute('SELECT count(*) FROM action_ledger').fetchone()[0],4)

if __name__=='__main__':unittest.main()
