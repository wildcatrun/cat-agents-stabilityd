import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from compat_verifiers import verify_current_policy_shadow as verifier


class CurrentPolicyShadowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(verifier.FIXTURE.read_text())
        cls.source = subprocess.check_output(['git', 'show', cls.fixture['baselineCommit'] +
                                            ':bin/cat_agents_stabilityd.py'], cwd=ROOT, text=True, timeout=10)
        candidate = subprocess.check_output(['git', 'show', cls.fixture['candidateCommit'] +
                                            ':bin/cat_agents_stabilityd.py'], cwd=ROOT, text=True, timeout=10)
        if hashlib.sha256(candidate.encode()).hexdigest() != cls.fixture['pins']['candidate']['sourceSha256']:
            raise ValueError('candidate commit/source provenance mismatch')

    def test_full_policy_replay_permits_only_previously_reviewed_visibility_fields(self):
        report = verifier.replay(ROOT)
        self.assertEqual(report['scenarioCount'], 203)
        self.assertFalse(report['automaticActivation'])
        self.assertFalse(report['collectorExecution'])
        self.assertFalse(report['actuatorExecution'])
        self.assertEqual(report['status'], 'compatible-in-declared-offline-scope')
        self.assertEqual(report['differences'], [])
        expected = {'canReapExpiredLeases', 'hermersProfileModeEnabled',
                    'hermersProfileModeActuateEnabled', 'hermersProfileModeStartEnabled'}
        for extension in report['declaredExtensions']:
            self.assertEqual(set(extension['fields']), expected)
        flags = {row['scenario']: row['values'] for row in report['declaredExtensions']}
        self.assertFalse(flags['flags/lease-off-json']['canReapExpiredLeases'])
        self.assertFalse(flags['flags/lease-off-sqlite']['canReapExpiredLeases'])
        self.assertTrue(flags['flags/lease-on-sqlite']['canReapExpiredLeases'])
        self.assertFalse(flags['flags/mode-off-actuate-on']['hermersProfileModeEnabled'])
        self.assertFalse(flags['flags/mode-off-actuate-on']['hermersProfileModeActuateEnabled'])
        self.assertTrue(flags['flags/mode-on-actuate-off']['hermersProfileModeEnabled'])
        self.assertFalse(flags['flags/mode-on-actuate-off']['hermersProfileModeActuateEnabled'])
        self.assertFalse(flags['flags/mode-on-actuate-off']['hermersProfileModeStartEnabled'])

    def test_source_and_selected_function_drift_rejected_before_execution(self):
        pin = self.fixture['pins']['baseline']
        case = verifier.scenarios(ROOT)[0]
        with self.assertRaisesRegex(ValueError, 'pinned source changed'):
            verifier.load_selected(self.source + '\nraise RuntimeError("never execute")', pin,
                                   verifier.synthetic_settings(), case)
        changed = self.source.replace('severity = max_severity(findings)', 'severity = "critical"', 1)
        updated = copy.deepcopy(pin)
        updated['sourceSha256'] = hashlib.sha256(changed.encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'pinned policy function changed'):
            verifier.load_selected(changed, updated, verifier.synthetic_settings(), case)

    def test_comparator_rejects_unreviewed_fields_changed_existing_flags_and_gate(self):
        before = {'policy': {'canRestartGateway': False, 'nested': {'canReset': False}},
                  'repairGate': {'status': 'blocked'}}
        after = {'policy': {'canRestartGateway': True, 'nested': {'canReset': True},
                            'newExecutionGrant': True, 'reviewedVisibility': False},
                 'repairGate': {'status': 'approved'}}
        diff = verifier.compare_policy_outputs(before, after, ['reviewedVisibility'])
        self.assertEqual(diff['added'], ['newExecutionGrant'])
        self.assertEqual(diff['changed'], ['canRestartGateway', 'nested'])
        self.assertTrue(diff['repairGateChanged'])

    def test_unselected_module_body_and_imports_do_not_execute(self):
        source = self.source + '\nimport nonexistent_runtime_module\nraise RuntimeError("never execute")\n'
        pin = copy.deepcopy(self.fixture['pins']['baseline'])
        pin['sourceSha256'] = hashlib.sha256(source.encode()).hexdigest()
        namespace = verifier.load_selected(source, pin, verifier.synthetic_settings(), verifier.scenarios(ROOT)[0])
        self.assertTrue(callable(namespace['policy_from_findings']))
        self.assertNotIn('nonexistent_runtime_module', namespace)
        self.assertNotIn('__import__', namespace['__builtins__'])
        self.assertNotIn('open', namespace['__builtins__'])

    def test_matrix_has_independent_inputs_and_bounded_failure_coverage(self):
        cases = verifier.scenarios(ROOT)
        self.assertEqual(len({c['name'] for c in cases}), 203)
        for phase in ('cold', 'hot', 'cooldown', 'storm', 'startup', 'disabled', 'sqlite'):
            self.assertEqual(sum(c['name'].endswith('/' + phase) for c in cases), 27)
        hard = next(c for c in cases if c['name'] == 'matrix/hard-fault/critical/hot')
        cron = next(c for c in cases if c['name'] == 'matrix/cron/critical/hot')
        self.assertFalse(hard['snapshot']['gateway']['active'])
        self.assertTrue(cron['snapshot']['gateway']['active'])


if __name__ == '__main__':
    unittest.main()
