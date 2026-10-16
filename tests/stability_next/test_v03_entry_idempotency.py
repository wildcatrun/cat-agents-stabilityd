"""Historical receipts preserve strict ledger writes and actual CLI round routing."""
import contextlib
import dataclasses
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from stability_core.action_ledger import ActionLedger, ActionConflict, IdempotencyConflict

S = importlib.util.spec_from_file_location('v03_daemon', Path(__file__).resolve().parents[2]/'bin/cat_agents_stabilityd.py')
m = importlib.util.module_from_spec(S); sys.modules[S.name] = m; S.loader.exec_module(m)

class EntryIdempotencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.path = self.root/'state.db'
        self.patch = mock.patch.object(m, 'STATE_DB', self.path); self.patch.start(); self.addCleanup(self.patch.stop)
        self.now = mock.patch.object(m, 'epoch', return_value=2000000000); self.now.start(); self.addCleanup(self.now.stop)
        self.calls = []
        from clock_fixture_support import install_clock_fixture
        install_clock_fixture(self,m,self.root/'actuation.lock')

    def spec(self, n=1):
        policy = dict(updatedAtEpoch=2000000000-n, validUntilEpoch=2000000060+n, canRestartGateway=True)
        digest, ref = m.policy_reference(policy)
        return m.ActionSpec('stable-intent', 'openclaw.gateway.restart', 'openclaw-gateway:dev-server',
            'runtime-birth', 'stabilityd-daemon', {'reason':'down'},
            m.STANDING_RULES['openclaw.gateway.restart'].authority_ref, ref,
            (f'evidence://snapshot/{n}', ref, f'policy-digest:sha256:{digest}'), {'actor':'cat-agents-stabilityd'}), policy

    def execute(self, spec, policy):
        def operation(*args):
            self.calls.append('effect'); return m.OperationResult('complete', 'outcome://done')
        return m.execute_governed_effect(spec, policy,
            eligibility_evidence=lambda s,p,t: (s.evidence_refs[0],),
            precheck=lambda *a: m.BoundaryCheck('approved', 'check://ok'), operation=operation,
            postcheck=lambda *a: m.PostcheckResult('verified', 'check://done'))

    def test_changed_snapshot_and_policy_return_historical_terminal_without_callbacks(self):
        first = self.execute(*self.spec())
        self.assertEqual(first.record.state, 'succeeded')
        with mock.patch.object(m.TrustedPolicyAuthorizer, '__call__', side_effect=AssertionError('new grant')):
            second = self.execute(*self.spec(2))
        self.assertEqual(second.disposition, 'existing'); self.assertEqual(second.record, first.record)
        self.assertEqual(self.calls, ['effect'])

    def test_all_states_are_lookup_only_and_never_resume(self):
        for state in ('planned','executing','uncertain','succeeded','failed','blocked'):
            with self.subTest(state=state):
                path=self.root/(state+'.db')
                with mock.patch.object(m,'STATE_DB',path):
                    spec, policy=self.spec()
                    with ActionLedger(path) as ledger:
                        record=ledger.plan_action(idempotency_key=spec.idempotency_key, action_type=spec.action_type,
                            target=spec.target, generation=spec.generation, input_data=spec.input_data,
                            authorization_ref=spec.authorization_ref, policy_ref=spec.policy_ref,
                            evidence_refs=spec.evidence_refs, metadata={'actor':'cat-agents-stabilityd','request_source':spec.source})
                        if state != 'planned':
                            if state=='blocked':
                                record=ledger.transition(record.action_id, expected_state='planned',expected_version=record.version,new_state='blocked',outcome_ref='outcome://blocked')
                            else:
                                record=ledger.begin_execution(record.action_id,expected_version=record.version,precheck_ref='check://ok')
                                if state!='executing':
                                    record=ledger.transition(record.action_id,expected_state='executing',expected_version=record.version,new_state=state,outcome_ref='outcome://old',postcheck_ref='check://old')
                    with mock.patch.object(m.TrustedPolicyAuthorizer,'__call__',side_effect=AssertionError('grant')):
                        result=self.execute(*self.spec(2))
                    self.assertEqual(result.record,record); self.assertEqual(result.disposition,'existing')
        self.assertEqual(self.calls,[])

    def test_changed_identity_or_authority_is_rejected(self):
        self.execute(*self.spec())
        fresh,policy=self.spec(2)
        changes=[{'input_data':{'reason':'different'}},{'target':'openclaw-gateway:other'},
                 {'generation':'other'},{'authorization_ref':'authority://other'},
                 {'source':'stabilityd-cli'}, {'metadata':{'actor':'other'}}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises((ActionConflict,ValueError)):
                self.execute(dataclasses.replace(fresh,**change),policy)
        self.assertEqual(self.calls,['effect'])

    def test_loaded_policy_binding_must_validate_before_history(self):
        self.execute(*self.spec()); fresh,policy=self.spec(2)
        with self.assertRaises(ValueError): self.execute(fresh,{**policy,'canRestartGateway':False})

    def test_current_policy_revocation_returns_only_historical_receipt(self):
        old=self.execute(*self.spec())
        spec,policy=self.spec(2);policy['canRestartGateway']=False
        digest,ref=m.policy_reference(policy)
        spec=dataclasses.replace(spec,policy_ref=ref,evidence_refs=('evidence://new',ref,f'policy-digest:sha256:{digest}'))
        with mock.patch.object(m.TrustedPolicyAuthorizer,'__call__',side_effect=AssertionError('new grant')):
            result=self.execute(spec,policy)
        self.assertEqual(result.record,old.record);self.assertEqual(result.disposition,'existing')
        self.assertEqual(self.calls,['effect'])
        denied=self.execute(dataclasses.replace(spec,idempotency_key='new-intent'),policy)
        self.assertEqual(denied.record.state,'blocked')
        self.assertEqual(self.calls,['effect'])

    def test_alias_reservation_is_not_caught_as_history(self):
        spec,policy=self.spec()
        with ActionLedger(self.path) as ledger:
            ledger.plan_action(idempotency_key='other',action_type=spec.action_type,target=spec.target,
                generation='other',input_data={},authorization_ref='authority://old',policy_ref='policy://old',evidence_refs=('evidence://old',))
        with self.assertRaises(ActionConflict) as caught: self.execute(spec,policy)
        self.assertNotIsInstance(caught.exception,IdempotencyConflict);self.assertEqual(self.calls,[])

    def test_actual_main_two_rounds_change_snapshot_and_policy(self):
        outputs=[]; generations=[]; policies=[]
        def collect(*args,**kwargs):
            _,policy=self.spec(len(policies)+1);policies.append(policy)
            return {'checkedAt':m.ts(),'checkedAtEpoch':m.epoch(),'severity':'low'},[],policy
        def actuator(conn,snapshot,policy,**kwargs):
            generations.append(snapshot['generationId'])
            spec,_=self.spec(len(generations))
            digest,ref=m.policy_reference(policy)
            spec=dataclasses.replace(spec,policy_ref=ref,evidence_refs=(f"evidence://snapshot/{snapshot['generationId']}",ref,f'policy-digest:sha256:{digest}'))
            result=self.execute(spec,policy)
            return [{'action':'fixture-effect','actionId':result.record.action_id,'ledgerDisposition':result.disposition,'ledgerState':result.record.state}]
        with contextlib.ExitStack() as stack:
            for name,value in [('ACTUATION_LOCK_PATH',self.root/'actuation.lock'),('EVENT_OUTBOX_V2_ENABLED',False)]:stack.enter_context(mock.patch.object(m,name,value))
            for name in ('ensure_dirs','drain_event_exports','db_record_action','log_line'):
                stack.enter_context(mock.patch.object(m,name))
            stack.enter_context(mock.patch.object(m,'init_db',return_value=mock.Mock()))
            stack.enter_context(mock.patch.object(m,'collect_snapshot',side_effect=collect))
            stack.enter_context(mock.patch.object(m,'actuate_collected_snapshot',side_effect=actuator))
            stack.enter_context(mock.patch.object(m,'control_plane_backpressure',return_value={}))
            stack.enter_context(mock.patch.object(m,'event_pipeline_evidence',return_value={}))
            stack.enter_context(mock.patch.object(m,'write_workflow_stability_evidence',return_value={'written':False}))
            stack.enter_context(mock.patch.object(m,'write_legacy_watchdog_health',return_value={}))
            stack.enter_context(mock.patch.object(m,'publish_generation',side_effect=lambda snapshot,*a,**k:dict(snapshot)))
            for command in ('once','repair'):
                out=io.StringIO()
                with contextlib.redirect_stdout(out):self.assertEqual(m.main([command]),0)
                outputs.append(json.loads(out.getvalue()))
        self.assertNotEqual(generations[0],generations[1]);self.assertNotEqual(policies[0],policies[1])
        self.assertEqual(self.calls,['effect'])
        self.assertEqual(outputs[0]['actions'][0]['actionId'],outputs[1]['actions'][0]['actionId'])
        self.assertEqual(outputs[1]['actions'][0]['ledgerDisposition'],'existing')

    def test_public_mcp_doctor_forces_no_action(self):
        spec=importlib.util.spec_from_file_location('v03_mcp',Path(__file__).resolve().parents[2]/'scripts/cat_agents_stability_mcp.py')
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        self.assertNotIn('stability_repair',module.TOOLS)
        self.assertNotIn('stability_once',module.TOOLS)
        with mock.patch.object(module,'stability_call',side_effect=lambda args:module.stability_cli_args(args['action'],args)):
            self.assertEqual(module.doctor({'no_action':False} ),['doctor','--no-action'])

    def test_actual_main_busy_does_not_enter_body(self):
        from stability_core.actuation_lock import ActuationLock
        with mock.patch.object(m,'ACTUATION_LOCK_PATH',self.root/'lock'),mock.patch.object(m,'init_db',return_value=None),mock.patch.object(m,'_run_once_body') as body,ActuationLock(self.root/'lock'):
            out=io.StringIO()
            with contextlib.redirect_stdout(out):self.assertEqual(m.main(['repair']),0)
            self.assertEqual(json.loads(out.getvalue())['actions'][0]['result'],'busy');body.assert_not_called()

if __name__=='__main__':unittest.main()
