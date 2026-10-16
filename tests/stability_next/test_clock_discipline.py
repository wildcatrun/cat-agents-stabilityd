import sqlite3
import unittest
from stability_core.clock_discipline import ClockDiscipline, ClockRefused


class ClockTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.execute('BEGIN IMMEDIATE')
        self.c = ClockDiscipline(self.db, tolerance_ms=10, recovery_stable_ms=50, max_history=4)
        self.c.install()
        self.p = self.sample(1000, 100)

    def tearDown(self):
        self.db.close()

    def sample(self, wall, mono, boot='boot-a'):
        return self.c.sample(boot_id=boot, wall_ms=wall, mono_ms=mono)

    def success(self):
        self.c.record_success(action_id='ledger-1', scope='gateway', cooldown_ms=180, history_ms=600, proof=self.p)

    def test_jump_quarantine_preserves_cooldown_and_recovers(self):
        self.success()
        q = self.sample(10000, 110)
        self.assertFalse(q.usable)
        with self.assertRaises(ClockRefused): self.c.remaining_ms('gateway', self.p)
        self.assertFalse(self.sample(10030, 140).usable)
        p = self.sample(10050, 160)
        self.assertTrue(p.usable)
        self.assertEqual(self.c.remaining_ms('gateway', p), 120)
        self.assertEqual(self.c.remaining_ms('gateway', self.sample(10170, 280)), 0)
        self.assertEqual(self.c.history_count('gateway', self.sample(10590, 700)), 0)

    def test_accumulated_small_steps_fixed_anchor(self):
        self.assertTrue(self.sample(1015, 110).usable)
        self.assertTrue(self.sample(1030, 120).usable)
        self.assertFalse(self.sample(1045, 130).usable)

    def test_quarantine_small_steps_do_not_fake_stability(self):
        self.assertFalse(self.sample(2000, 110).usable)
        for n in range(1, 12):
            self.assertFalse(self.sample(2000+n*15, 110+n*10).usable)

    def test_reopen_and_legacy_once(self):
        self.c.import_legacy_window('gateway', 180, self.p)
        self.db.commit()
        self.db.execute('BEGIN IMMEDIATE')
        self.c = ClockDiscipline(self.db, tolerance_ms=10, recovery_stable_ms=50, max_history=4)
        self.c.install()
        p = self.sample(1080, 180)
        self.c.import_legacy_window('gateway', 180, p)
        self.assertEqual(self.c.remaining_ms('gateway', p), 100)

    def test_cross_boot_full_finite_window_no_wall_credit(self):
        self.success()
        p = self.sample(99999999, 5, 'boot-b')
        self.assertEqual(self.c.remaining_ms('gateway', p), 180)
        self.assertEqual(self.c.history_count('gateway', p), 1)
        p = self.sample(100000179, 185, 'boot-b')
        self.assertEqual(self.c.remaining_ms('gateway', p), 0)
        self.assertEqual(self.c.history_count('gateway', p), 1)

    def test_backward_and_monotonic_regression(self):
        self.assertFalse(self.sample(500, 110).usable)
        with self.assertRaisesRegex(ClockRefused, 'regression'): self.sample(501, 109)

    def test_atomic_with_ledger_and_failure_rollback(self):
        self.db.execute('CREATE TABLE fixture_ledger(id TEXT,state TEXT)')
        self.db.commit()
        self.db.execute('BEGIN IMMEDIATE')
        self.db.execute("INSERT INTO fixture_ledger VALUES('ledger-1','succeeded')")
        self.success()
        self.db.rollback()
        self.db.execute('BEGIN IMMEDIATE')
        self.assertEqual(self.db.execute('SELECT count(*) FROM fixture_ledger').fetchone()[0], 0)
        self.assertEqual(self.c.history_count('gateway', self.p), 0)
        self.db.execute('CREATE TRIGGER deny_history BEFORE INSERT ON stability_clock_history BEGIN SELECT RAISE(ABORT,"fixture-disk-failure"); END')
        with self.assertRaises(sqlite3.Error): self.success()
        self.assertEqual(self.c.remaining_ms('gateway', self.p), 0)

    def test_legacy_history_once_and_budget(self):
        for n in range(4):
            self.c.import_legacy_history(action_id='old-'+str(n), scope='gateway', history_ms=600, proof=self.p)
        self.c.import_legacy_history(action_id='old-0', scope='gateway', history_ms=600, proof=self.sample(1010, 110))
        self.assertEqual(self.c.history_count('gateway', self.sample(1020, 120)), 4)
        with self.assertRaisesRegex(ClockRefused, 'budget'): self.c.preflight_capacity('gateway', self.sample(1030, 130))
        self.c.complete_legacy_import(self.sample(1040, 140))
        self.assertEqual(self.c.history_count('gateway', self.sample(1600, 700)), 0)
        self.c.preflight_capacity('gateway', self.sample(1601, 701))

    def test_dynamic_scopes_reclaimed_after_migration(self):
        self.c.complete_legacy_import(self.p)
        for n in range(20):
            p = self.sample(1000+n*1000, 100+n*1000)
            self.c.record_success(action_id=str(n), scope='session:'+str(n), cooldown_ms=20, history_ms=30, proof=p)
            self.assertLessEqual(self.db.execute('SELECT count(*) FROM stability_clock_windows').fetchone()[0], 1)
        with self.assertRaisesRegex(ClockRefused, 'import-closed'):
            self.c.import_legacy_window('session:0', 20, p)

    def test_corrupt_rows_preserved_and_refused_before_prune_or_boot(self):
        for column, value in [('duration', -1), ('duration', 'garbage'), ('deadline', -1), ('deadline', 2.5)]:
            with self.subTest(column=column, value=value):
                self.db.execute('SAVEPOINT corrupt')
                self.c.import_legacy_window('legacy', 20, self.p)
                self.c.complete_legacy_import(self.p)
                self.db.execute('UPDATE stability_clock_windows SET '+column+'=?', (value,))
                before = self.db.execute('SELECT * FROM stability_clock_windows').fetchall()
                with self.assertRaisesRegex(ClockRefused, 'corrupt'):
                    self.sample(100000, 100000, 'newboot')
                self.assertEqual(self.db.execute('SELECT * FROM stability_clock_windows').fetchall(), before)
                self.db.execute('ROLLBACK TO corrupt')
                self.db.execute('RELEASE corrupt')

    def test_profile_cooldown_and_global_storm_have_distinct_scopes(self):
        self.c.record_success(action_id='restart-1', scope='hermes-profile:one', history_scope='hermers-global', cooldown_ms=180, history_ms=600, proof=self.p)
        self.assertEqual(self.c.remaining_ms('hermes-profile:one', self.p), 180)
        self.assertEqual(self.c.remaining_ms('hermes-profile:two', self.p), 0)
        self.assertEqual(self.c.history_count('hermers-global', self.p), 1)
        self.assertEqual(self.c.history_count('hermes-profile:one', self.p), 0)

    def test_foreign_trigger_on_owned_table_refused(self):
        self.db.execute('CREATE TRIGGER unrelated_name AFTER INSERT ON stability_clock_windows BEGIN SELECT 1; END')
        with self.assertRaisesRegex(ClockRefused, 'schema'): self.c.install()

    def test_wrong_schema_same_names_refused(self):
        self.db.execute('ALTER TABLE stability_clock_windows ADD COLUMN bogus TEXT')
        with self.assertRaisesRegex(ClockRefused, 'schema'): self.c.install()

    def test_partial_schema_refused_without_adoption(self):
        other = sqlite3.connect(':memory:')
        try:
            other.execute('CREATE TABLE stability_clock_windows(scope TEXT)')
            other.execute('BEGIN')
            c = ClockDiscipline(other, tolerance_ms=10, recovery_stable_ms=50)
            with self.assertRaisesRegex(ClockRefused, 'schema'): c.install()
            self.assertEqual(other.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0], 1)
        finally: other.close()

    def test_transaction_policy_fence_and_idempotence(self):
        self.success()
        self.c.record_success(action_id='ledger-1', scope='gateway', cooldown_ms=180, history_ms=600, proof=self.sample(1020, 120))
        self.assertEqual(self.c.remaining_ms('gateway', self.sample(1030, 130)), 150)
        other = ClockDiscipline(self.db, tolerance_ms=11, recovery_stable_ms=50, max_history=4)
        with self.assertRaisesRegex(ClockRefused, 'policy-drift'): other.sample(boot_id='boot-a', wall_ms=1030, mono_ms=130)
        self.db.commit()
        with self.assertRaisesRegex(ClockRefused, 'transaction'): self.c.remaining_ms('gateway', self.p)


if __name__ == '__main__': unittest.main()
