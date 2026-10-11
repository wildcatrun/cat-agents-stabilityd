import contextlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from stability_core.collector_budget import RoundBudget, BudgetConfig, COMPONENTS

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('round_budget_integration', ROOT / 'bin/cat_agents_stabilityd.py')
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


class Clock:
    def __init__(self): self.value = 0.0
    def __call__(self): return self.value
    def advance(self, ms): self.value += ms / 1000


class CollectorBudgetIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.conn = m.init_memory_kv_db()
        self.stack = contextlib.ExitStack()
        self.clock = Clock()
        self.stack.enter_context(mock.patch.object(m.time, 'monotonic', self.clock))
        for name, value in {
            'action_recovery_evidence':{'counts':{}, 'ledgerStatus':'not-initialized'},
            'event_pipeline_evidence':{'mode':'legacy'}, 'stabilityd_progress_evidence':{},
            'collector_worker_environment':{}, 'update_runtime_trends':{}, 'update_streaks':{},
            'policy_from_findings':{'mode':'fixture','lanes':{}}, 'build_auth_maintenance_plan':{},
            'control_plane_backpressure':{}, 'write_workflow_stability_evidence':{'written':False},
            'write_legacy_watchdog_health':{},
        }.items():
            self.stack.enter_context(mock.patch.object(m, name, return_value=value))
        for name in ('add_resource_governance_findings', 'persist_component_cache_updates',
                     'ensure_dirs', 'drain_event_exports', 'db_record_event', 'db_record_action', 'log_line'):
            self.stack.enter_context(mock.patch.object(m, name))
        self.stack.enter_context(mock.patch.object(m, '_inspection_cache_enabled', False))
        self.stack.enter_context(mock.patch.object(m, 'EVENT_OUTBOX_ENABLED', False))
        self.stack.enter_context(mock.patch.object(m, 'EVENT_OUTBOX_V2_ENABLED', False))
        for name in ('POLICY_PATH','LANE_POLICY_PATH','HERMERS_PROFILE_MODES_PATH','AUTH_MAINTENANCE_PLAN_PATH',
                     'CONTROL_PLANE_BACKPRESSURE_PATH','LATEST_PATH'):
            self.stack.enter_context(mock.patch.object(m, name, self.root / (name + '.json')))
        self.calls = []

    def tearDown(self):
        self.stack.close(); self.conn.close(); self.temp.cleanup()

    def runner(self, name, command, fallback, **kw):
        self.calls.append((name, kw['budget_ms']))
        return {'probe':{'status':'ok','coverage':True,'durationMs':0,'budgetMs':kw['budget_ms'],
                         'noLiveGroupMemberObserved':True}, 'data':dict(fallback)}

    def test_default_hard_entry_and_injected_entry_preserve_full_caps(self):
        with mock.patch.object(m, 'run_component_probe_hard', side_effect=self.runner) as hard:
            snapshot, _, _ = m.collect_snapshot(self.conn)
        self.assertEqual(hard.call_count, 9)
        self.assertEqual(self.calls, [(name, 60000) for name in COMPONENTS])
        self.assertEqual(snapshot['collectorBudget']['completedComponents'], 9)
        self.calls.clear()
        m.collect_snapshot(self.conn, component_probe_runner=self.runner)
        self.assertEqual(self.calls, [(name, 60000) for name in COMPONENTS])

    def test_first_timeout_preserves_later_independent_cap_and_cleanup_fence(self):
        def timeout(name, command, fallback, **kw):
            result = self.runner(name, command, fallback, **kw)
            if name == 'gateway':
                self.clock.advance(62000)
                result['probe'].update(status='timeout', coverage=False)
            return result
        snapshot, _, _ = m.collect_snapshot(self.conn, component_probe_runner=timeout)
        self.assertEqual(self.calls[1:], [(name, 60000) for name in COMPONENTS[1:]])
        self.assertEqual(snapshot['collectorBudgetStatus'], 'partial')
        self.assertEqual(snapshot['collectorProbes']['gateway']['status'], 'timeout')

    def test_skip_does_not_spawn_and_clears_cache_with_unknown_fallback(self):
        budget = RoundBudget(clock=self.clock)
        self.clock.advance(80000)
        m._inspection_cache['synthetic-prior'] = {'healthy':True}
        with mock.patch.object(m, '_inspection_cache_enabled', True):
            snapshot, findings, _ = m.collect_snapshot(self.conn, component_probe_runner=self.runner, round_budget=budget)
        self.assertNotIn('gateway', [name for name, _ in self.calls])
        self.assertEqual(snapshot['collectorProbes']['gateway']['status'], 'unknown')
        self.assertFalse(snapshot['collectorProbes']['gateway']['workerSpawned'])
        self.assertIsNone(snapshot['gateway']['active'])
        self.assertNotIn('synthetic-prior', m._inspection_cache)
        self.assertTrue(any(x['key'].endswith('round_budget_skipped') for x in findings))
        self.assertEqual(snapshot['collectorBudget']['completedComponents'], 9)

    def test_cold_near_sixty_seconds_still_admits_rest(self):
        def cold(name, command, fallback, **kw):
            result = self.runner(name, command, fallback, **kw)
            if name == 'gateway': self.clock.advance(61990)
            return result
        m.collect_snapshot(self.conn, component_probe_runner=cold)
        self.assertEqual(self.calls, [(name, 60000) for name in COMPONENTS])

    def test_reduced_owned_allocation_is_actual_runner_timeout(self):
        budget = RoundBudget(clock=self.clock)
        self.clock.advance(30000)
        def consume(name, command, fallback, **kw):
            result = self.runner(name, command, fallback, **kw)
            if name == 'gateway': self.clock.advance(kw['budget_ms'] + 2000)
            return result
        m.collect_snapshot(self.conn, component_probe_runner=consume, round_budget=budget)
        self.assertEqual(self.calls[0], ('gateway', 42000))
        self.assertEqual(self.calls[1:], [(name, 60000) for name in COMPONENTS[1:]])

    def test_real_fatal_cleanup_raises_instead_of_budget_finish_clearing_it(self):
        budget = RoundBudget(clock=self.clock)
        def unsafe(name, command, fallback, **kw):
            result = self.runner(name, command, fallback, **kw)
            result['probe']['noLiveGroupMemberObserved'] = False
            return result
        with self.assertRaises(m.CollectorProcessCleanupFailure):
            m.collect_snapshot(self.conn, component_probe_runner=unsafe, round_budget=budget)
        self.assertEqual(budget.evidence()['completedComponents'], 1)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(budget.evidence()['allocations'][0]['cleanupQualification'], 'caller-owned-fatal-fence')

    def run_body(self, runner=None):
        with mock.patch.object(m, 'run_component_probe_hard', side_effect=runner or self.runner), \
             mock.patch.object(m, 'actuate_collected_snapshot', return_value=[]) as actuator:
            result = m._run_once_body(self.conn, no_action=False)
            return result, actuator

    def test_clock_invalid_skips_all_and_never_enters_actuator(self):
        self.clock.value = float('nan')
        result, actuator = self.run_body()
        actuator.assert_not_called()
        self.assertEqual(self.calls, [])
        self.assertEqual(result['actions'][0]['reason'], 'round-budget-unavailable')
        self.assertEqual(result['collectorBudgetStatus'], 'partial')
        self.assertEqual(json.loads(m.LATEST_PATH.read_text()), result)

    def test_round_exhausted_after_collect_never_enters_action_function(self):
        def policy(*args):
            self.clock.advance(600000)
            return {'mode':'fixture','lanes':{}}
        with mock.patch.object(m, 'policy_from_findings', side_effect=policy):
            result, actuator = self.run_body()
        actuator.assert_not_called()
        self.assertEqual(result['collectorBudgetChecks']['actuation']['status'], 'unknown')
        self.assertEqual(result['actions'][0]['result'], 'blocked')
        self.assertEqual(result['collectorBudgetStatus'], 'partial')
        self.assertEqual(json.loads(m.LATEST_PATH.read_text()), result)

    def test_same_round_starts_before_ensure_and_drain(self):
        def overhead(*args): self.clock.advance(40000)
        with mock.patch.object(m, 'ensure_dirs', side_effect=overhead), \
             mock.patch.object(m, 'drain_event_exports', side_effect=overhead):
            result, _ = self.run_body()
        self.assertEqual(result['collectorBudget']['allocations'][0]['elapsedMs'], 80000)
        self.assertEqual(result['collectorProbes']['gateway']['status'], 'unknown')
        self.assertNotIn('gateway', [name for name, _ in self.calls])

    def test_expired_publication_publishes_partial_without_return_mutation(self):
        original = m.publish_generation
        def publication(snapshot, artifacts, latest, extra):
            self.clock.advance(600000)
            return original(snapshot, artifacts, latest, extra)
        with mock.patch.object(m, 'publish_generation', side_effect=publication), \
             mock.patch.object(m, 'log_line') as logger:
            result, actuator = self.run_body()
        self.assertEqual(json.loads(m.LATEST_PATH.read_text()), result)
        completion = [call.args[0] for call in logger.call_args_list if call.args[0].startswith('collector_round_completion=')]
        self.assertEqual(len(completion), 1)
        receipt = json.loads(completion[0].split('=', 1)[1])
        self.assertEqual(receipt['generationId'], result['generationId'])
        self.assertEqual(receipt['check']['status'], 'unknown')
        self.assertNotIn('return', result['collectorBudgetChecks'])
        actuator.assert_called_once()

    def test_overdue_before_publication_latest_and_return_both_partial(self):
        def actuator(conn, snapshot, policy, **kw):
            self.clock.advance(600000)
            return []
        with mock.patch.object(m, 'run_component_probe_hard', side_effect=self.runner), \
             mock.patch.object(m, 'actuate_collected_snapshot', side_effect=actuator):
            result = m._run_once_body(self.conn)
        self.assertEqual(result['collectorBudgetStatus'], 'partial')
        self.assertEqual(result['collectorBudgetChecks']['publication']['status'], 'unknown')
        self.assertEqual(json.loads(m.LATEST_PATH.read_text()), result)

    def test_post_publication_receipt_log_failure_does_not_return_success(self):
        def logging(value):
            if value.startswith('collector_round_completion='):
                raise OSError('synthetic receipt failure')
        with mock.patch.object(m, 'log_line', side_effect=logging):
            with self.assertRaisesRegex(OSError, 'receipt failure'):
                self.run_body()
        self.assertTrue(m.LATEST_PATH.exists())


if __name__ == '__main__': unittest.main()
