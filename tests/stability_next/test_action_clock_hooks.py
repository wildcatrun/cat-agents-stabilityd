import sqlite3
import unittest
import test_action_executor as executor_fixtures
from stability_core.action_ledger import ActionLedger
from stability_core.clock_discipline import ClockDiscipline


class ActionClockHookTests(unittest.TestCase):
    def setUp(self):
        self.f = executor_fixtures.ActionExecutorTests()
        self.f.setUp()
        self.ledger = ActionLedger(self.f.path)
        self.c = ClockDiscipline(self.ledger._conn, tolerance_ms=10, recovery_stable_ms=50)
        def init(conn):
            self.c.install()
            p = self.c.sample(boot_id='boot', wall_ms=1000, mono_ms=100)
            self.c.complete_legacy_import(p)
        self.ledger.run_timing_check(init)

    def tearDown(self):
        self.ledger.close()
        self.f.tearDown()

    def check(self, conn, spec, record, phase):
        self.assertTrue(conn.in_transaction)
        p = self.c.sample(boot_id='boot', wall_ms=1000, mono_ms=100)
        return p.usable and self.c.remaining_ms(spec.target, p) == 0

    def terminal(self, conn, spec, record, operation):
        self.assertTrue(conn.in_transaction)
        self.assertIn(record.state, ('succeeded', 'failed', 'uncertain'))
        self.assertEqual(conn.execute('SELECT state FROM action_ledger WHERE action_id=?', (record.action_id,)).fetchone()[0], record.state)
        p = self.c.sample(boot_id='boot', wall_ms=1000, mono_ms=100)
        self.c.record_success(action_id=record.action_id, scope=spec.target, cooldown_ms=1800, history_ms=6000, proof=p)

    def test_success_atomic_and_historical_replay_no_callbacks(self):
        ex = self.f.callbacks(self.ledger)
        ex._timing_check, ex._effect_timing = self.check, self.terminal
        result = ex.execute(self.f.spec())
        self.assertEqual((result.record.state, self.f.calls), ('succeeded', 1))
        self.assertEqual(self.ledger._conn.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0], 1)
        def forbidden(*args): raise AssertionError('historical callback invoked')
        ex._timing_check = ex._effect_timing = ex._authorizer = forbidden
        self.assertEqual(ex.execute(self.f.spec()).disposition, 'existing')
        self.assertEqual(self.f.calls, 1)

    def test_before_effect_jump_blocks_without_uncertain_and_persists_quarantine(self):
        ex = self.f.callbacks(self.ledger)
        def check(conn, spec, record, phase):
            p = self.c.sample(boot_id='boot', wall_ms=10000 if phase=='before-effect' else 1000, mono_ms=100)
            return p.usable
        ex._timing_check = check
        result = ex.execute(self.f.spec())
        self.assertEqual((result.record.state, result.disposition, self.f.calls), ('blocked', 'blocked', 0))
        self.assertEqual(self.ledger._conn.execute('SELECT quarantine FROM stability_clock_anchor').fetchone()[0], 1)

    def test_before_cas_exception_or_unknown_never_effects(self):
        for n, callback in enumerate((lambda *a: None, lambda *a: (_ for _ in ()).throw(sqlite3.OperationalError('secret-value')))):
            ex = self.f.callbacks(self.ledger)
            ex._timing_check = callback
            result = ex.execute(self.f.spec(str(n)))
            self.assertEqual(result.record.state, 'blocked')
        self.assertEqual(self.f.calls, 0)
        self.assertNotIn('secret-value', str(self.ledger._conn.execute('SELECT * FROM action_ledger').fetchall()))

    def test_post_effect_timing_failure_rolls_back_terminal_and_timing(self):
        ex = self.f.callbacks(self.ledger)
        ex._timing_check = self.check
        def broken(conn, spec, record, operation):
            self.terminal(conn, spec, record, operation)
            raise sqlite3.OperationalError('disk-full-sensitive-detail')
        ex._effect_timing = broken
        with self.assertRaises(sqlite3.OperationalError): ex.execute(self.f.spec())
        current = self.ledger.startup_reconcile_candidates()
        self.assertEqual((len(current), current[0].state, self.f.calls), (1, 'executing', 1))
        self.assertEqual(self.ledger._conn.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0], 0)
        self.assertEqual(ex.execute(self.f.spec()).disposition, 'existing')
        self.assertEqual(self.f.calls, 1)

    def test_complete_effect_failed_postcheck_keeps_cooldown(self):
        from stability_core.action_executor import PostcheckResult
        ex = self.f.callbacks(self.ledger, postcheck=lambda *a: PostcheckResult('failed', 'check://failed'))
        ex._timing_check, ex._effect_timing = self.check, self.terminal
        self.assertEqual(ex.execute(self.f.spec()).record.state, 'failed')
        self.assertEqual(self.ledger._conn.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0], 1)
        self.assertEqual(ex.execute(self.f.spec('new-key')).record.state, 'blocked')
        self.assertEqual(self.f.calls, 1)

    def test_complete_effect_unknown_postcheck_counts_but_unknown_operation_does_not(self):
        from stability_core.action_executor import PostcheckResult, OperationResult
        ex = self.f.callbacks(self.ledger, postcheck=lambda *a: PostcheckResult('unknown', 'check://unknown'))
        ex._timing_check, ex._effect_timing = self.check, self.terminal
        self.assertEqual(ex.execute(self.f.spec()).record.state, 'uncertain')
        self.assertEqual(self.ledger._conn.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0], 1)
        other = self.f.spec('other-key')
        import dataclasses
        other = dataclasses.replace(other, target='node/b')
        ex._operation = lambda *a: OperationResult('unknown', 'outcome://unknown')
        ex._effect_timing = lambda *a: self.fail('unknown operation must not record success')
        self.assertEqual(ex.execute(other).record.state, 'uncertain')
        self.assertEqual(self.ledger._conn.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0], 1)

if __name__ == '__main__': unittest.main()
