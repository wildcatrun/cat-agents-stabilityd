import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests'))
from compat_verifiers import verify_clock_policy_v2 as v2
from compat_verifiers import verify_current_policy_shadow as v1


class ClockPolicyV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=json.loads(v2.FIXTURE.read_text())
        cls.source=(ROOT/'bin/cat_agents_stabilityd.py').read_text()
        cls.case=next(c for c in v1.scenarios(ROOT) if c['name']=='matrix/hard-fault/critical/hot')
        cls.report=v2.replay(ROOT)

    def test_current_explicit_v2_gate_and_full_matrix(self):
        self.assertEqual(self.report['status'],'compatible-in-declared-clock-scope',self.report['differences'])
        self.assertEqual(self.report['historicalScenarioCount'],203)
        self.assertEqual(self.report['matrixEvaluations'],406)
        self.assertEqual(self.report['totalEvaluations'],416)
        self.assertEqual(self.report['differences'],[])
        self.assertFalse(self.report['automaticActivation'])
        self.assertFalse(self.report['actuatorExecution'])
        self.assertFalse(self.report['collectorExecution'])
        gate=json.loads(v2.GATE.read_text())
        self.assertEqual(gate['schemaVersion'],2)
        self.assertEqual(gate['historicalGate'],'current-policy-shadow-v1')

    def test_forward_backward_and_recovery_require_actual_monotonic_evidence(self):
        rows={r['scenario']:r for r in self.report['explicitClockResults']}
        forward=rows['forward-wall-jump-mono-still-cooling']
        self.assertTrue(forward['legacyCandidateCanRestart']);self.assertFalse(forward['candidateCanRestart'])
        back=rows['backward-recovery-mono-expired-before-legacy-wall']
        self.assertFalse(back['legacyCandidateCanRestart']);self.assertTrue(back['candidateCanRestart'])
        self.assertFalse(rows['recovery-new-epoch-still-cooling']['candidateCanRestart'])
        self.assertTrue(rows['recovery-monotonic-expired']['candidateCanRestart'])
        self.assertFalse(rows['forward-wall-does-not-clear-monotonic-storm']['candidateCanRestart'])
        quarantine=rows['forward-quarantine-candidate-is-not-authority']
        self.assertTrue(quarantine['candidateCanRestart'])
        self.assertEqual(quarantine['clockState'],'unavailable-or-quarantined')
        self.assertIn('actual effects require fresh matching clock epoch',self.report['authority'])

    def test_registry_derived_per_profile_cooldown_keeps_global_storm_scope(self):
        rows=self.report['hermesProfileResults']
        self.assertEqual(len(rows),2)
        for row in rows:
            self.assertEqual(row['eligibleProfiles'],['fixture_two'])
            self.assertEqual(row['coolingProfile'],'fixture_one')
        self.assertEqual((rows[0]['globalHistoryCount'],rows[0]['remainingGlobalBudget'],rows[0]['candidateCanRestart']),(1,2,True))
        self.assertEqual((rows[1]['globalHistoryCount'],rows[1]['remainingGlobalBudget'],rows[1]['candidateCanRestart']),(3,0,False))

    def test_exact_comparator_rejects_non_time_authority_protection_lane_and_gate_drift(self):
        expected={'policy':{'canResetSession':False,'canReapExpiredLeases':False,
                  'session':{'protectedDirectSessionKeys':['protected']},
                  'domains':{'cron':{'state':'limited'}}},'repairGate':{'status':'blocked'}}
        projection={'windows':{},'history':{},'epoch':'fixed'}
        actual=copy.deepcopy(expected)
        actual['policy']['clockDiscipline']={'state':'available','epoch':'fixed',
            'executionFence':'required-for-time-dependent-effects'}
        self.assertEqual(v2.compare(expected,actual,projection),{})
        mutations=(lambda p:p['policy'].update(canResetSession=True),
            lambda p:p['policy'].update(canReapExpiredLeases=True),
            lambda p:p['policy']['session'].update(protectedDirectSessionKeys=[]),
            lambda p:p['policy']['domains']['cron'].update(state='open'),
            lambda p:p['repairGate'].update(status='ready'),
            lambda p:p['policy'].update(newGrant=True),
            lambda p:p['policy']['clockDiscipline'].update(epoch='forged'),
            lambda p:p['policy']['clockDiscipline'].update(state='available',actionAuthorized=True))
        for mutation in mutations:
            changed=copy.deepcopy(actual);mutation(changed)
            self.assertTrue(v2.compare(expected,changed,projection))

    def test_exact_source_function_and_global_dependency_fences(self):
        pin=self.fixture['candidate'];settings=v1.synthetic_settings()
        with self.assertRaisesRegex(ValueError,'pinned source'):
            v2.load_candidate(self.source+'\n# source drift\n',pin,settings,self.case,None)
        changed=self.source.replace('severity = max_severity(findings)','severity = "critical"',1)
        updated=copy.deepcopy(pin);updated['sourceSha256']=hashlib.sha256(changed.encode()).hexdigest()
        with self.assertRaisesRegex(ValueError,'pinned policy function'):
            v2.load_candidate(changed,updated,settings,self.case,None)
        changed=self.source.replace('timing = mechanical_timing_projection(conn)','timing = unapproved_runtime_global(conn)',1)
        updated=copy.deepcopy(pin);updated['sourceSha256']=hashlib.sha256(changed.encode()).hexdigest()
        updated['functions']={k:hashlib.sha256(v.encode()).hexdigest() for k,v in v1.source_segments(changed).items()}
        with self.assertRaisesRegex(ValueError,'unapproved policy dependency'):
            v2.load_candidate(changed,updated,settings,self.case,None)

    def test_module_body_and_runtime_calls_cannot_execute(self):
        source=self.source+'\nimport nonexistent_runtime\nraise RuntimeError("must not execute")\n'
        pin=copy.deepcopy(self.fixture['candidate']);pin['sourceSha256']=hashlib.sha256(source.encode()).hexdigest()
        namespace=v2.load_candidate(source,pin,v1.synthetic_settings(),self.case,None)
        result=v2.output(namespace,self.case)
        self.assertEqual(result['policy']['clockDiscipline']['state'],'unavailable-or-quarantined')
        for name in ('open','__import__','eval','exec'):self.assertNotIn(name,namespace['__builtins__'])
        self.assertNotIn('nonexistent_runtime',namespace)
        self.assertNotIn('daemon_clock',namespace)

if __name__=='__main__':unittest.main()
