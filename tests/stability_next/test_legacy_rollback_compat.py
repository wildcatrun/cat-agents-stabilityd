"""Pinned legacy SQLite readers; no live state or automatic rollback safety claim."""
import ast
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

from stability_core.action_ledger import ActionConflict, ActionLedger

FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures/compat/legacy_rollback_symbols_v1.json'
BASELINE = 'ece4157a38cc60dfbedc0268ca296f7775a956f0'
SYMBOLS_DIGEST = '167938d5d85acdc137f0cd9676c1b1377adde411226994563d0830d6f7e874c1'
NAMES = ('init_db', 'db_get', 'db_set', 'recent_restart_history', 'recent_hermers_gateway_restart_history')


def load_legacy(fixture, path, *, source=None):
    if fixture['baselineCommit'] != BASELINE or set(fixture['symbols']) != set(NAMES):
        raise ValueError('baseline identity mismatch')
    if hashlib.sha256(json.dumps(fixture['symbols'], sort_keys=True,
                               separators=(',', ':')).encode()).hexdigest() != SYMBOLS_DIGEST:
        raise ValueError('pinned symbols digest mismatch')
    selected = []
    trees = ast.parse(source if source is not None else '\n\n'.join(
        fixture['symbols'][name]['source'] for name in NAMES))
    for name in NAMES:
        nodes = [node for node in trees.body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(nodes) != 1:
            raise ValueError('selected symbol missing or duplicated')
        node = nodes[0]
        pinned = fixture['symbols'][name]
        if hashlib.sha256(pinned['source'].encode()).hexdigest() != pinned['sourceSha256']:
            raise ValueError('source identity mismatch')
        expected = hashlib.sha256(ast.dump(ast.parse(pinned['source']), include_attributes=False).encode()).hexdigest()
        actual = hashlib.sha256(ast.dump(ast.Module(body=[node], type_ignores=[]), include_attributes=False).encode()).hexdigest()
        if expected != pinned['astSha256'] or actual != expected:
            raise ValueError('selected symbol drift')
        selected.append(node)
    namespace = {'sqlite3': sqlite3, 'json': json, 'Any': Any, 'Dict': Dict, 'List': List,
                 'STATE_DB': path, 'ensure_dirs': lambda: None, 'epoch': lambda: 10000,
                 'RESTART_WINDOW_SECONDS': 3600}
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<pinned-legacy-symbols>', 'exec'), namespace)
    return namespace


class LegacyRollbackCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = json.loads(FIXTURE.read_text())

    def test_loader_rejects_selected_drift_and_ignores_unselected_code(self):
        source = '\n\n'.join(self.fixture['symbols'][name]['source'] for name in NAMES)
        with self.assertRaisesRegex(ValueError, 'selected symbol drift'):
            load_legacy(self.fixture, Path('unused'), source=source.replace('cutoff = epoch()', 'cutoff = 1 + epoch()', 1))
        namespace = load_legacy(self.fixture, Path('unused'), source=source + '\nraise RuntimeError("must never execute")\n')
        self.assertTrue(callable(namespace['db_get']))
        self.assertNotIn('ActionLedger', namespace)

    def test_legacy_new_schema_backup_restore_preserves_history_and_uncertainty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state.db'
            legacy = load_legacy(self.fixture, state)
            conn = legacy['init_db']()
            values = {'stabilityd_last_gateway_restart_at': 9900,
                      'stabilityd_gateway_restart_history': [5000, 7000, 9900],
                      'stabilityd_hermers_gateway_restart_history': [5000, {'tsEpoch': 9901, 'profile': 'fixture-profile'}],
                      'fixture_cooldown': {'until': 11000, 'attempt': 2}}
            for key, value in values.items():
                legacy['db_set'](conn, key, value)
            conn.execute('INSERT INTO actions(ts_epoch,action_id,action,result,payload) VALUES(?,?,?,?,?)',
                         (9900, 'fixture-action', 'restart_gateway', 'ok', '{"synthetic":true}'))
            conn.commit()
            expected = {table: conn.execute('SELECT * FROM ' + table + ' ORDER BY 1').fetchall()
                        for table in ('kv', 'actions', 'events')}
            before = root / 'before.db'
            with sqlite3.connect(before) as destination:
                conn.backup(destination)
            conn.close()
            with ActionLedger(state) as ledger:
                record = ledger.plan_action(idempotency_key='fixture-uncertain', action_type='fake-effect',
                    target='fixture-host/gateway', generation='fixture-generation', input_data={'synthetic': True},
                    authorization_ref='auth://fixture', policy_ref='policy://fixture', evidence_refs=('evidence://fixture',))
                record = ledger.begin_execution(record.action_id, expected_version=record.version, precheck_ref='check://fixture')
                ledger.transition(record.action_id, expected_state='executing', expected_version=record.version,
                                  new_state='uncertain', outcome_ref='outcome://fixture', postcheck_ref='check://unknown')
            after = root / 'after.db'
            with sqlite3.connect(state) as source, sqlite3.connect(after) as destination:
                source.backup(destination)
            for name, backup in (('old', before), ('new', after)):
                restored = root / (name + '-restored.db')
                with sqlite3.connect(backup) as source, sqlite3.connect(restored) as destination:
                    source.backup(destination)
                readers = load_legacy(self.fixture, restored)
                old_conn = readers['init_db']()
                try:
                    self.assertEqual(old_conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                    for table, rows in expected.items():
                        self.assertEqual(old_conn.execute('SELECT * FROM ' + table + ' ORDER BY 1').fetchall(), rows)
                    for key, value in values.items():
                        self.assertEqual(readers['db_get'](old_conn, key), value)
                    self.assertEqual(readers['recent_restart_history'](old_conn), [7000, 9900])
                    self.assertEqual(readers['recent_hermers_gateway_restart_history'](old_conn),
                                     [{'tsEpoch': 9901, 'profile': 'fixture-profile'}])
                    # Legacy readers have no awareness of the new reservation.
                    self.assertEqual(readers['db_get'](old_conn, 'action_ledger', 'not-known'), 'not-known')
                    if name == 'new':
                        self.assertEqual(old_conn.execute('SELECT state FROM action_ledger').fetchall(), [('uncertain',)])
                finally:
                    old_conn.close()
                if name == 'new':
                    with ActionLedger(restored) as ledger:
                        self.assertEqual(ledger.get(record.action_id).state, 'uncertain')
                        with self.assertRaises(ActionConflict):
                            ledger.plan_action(idempotency_key='fixture-retry', action_type='fake-effect',
                                target='fixture-host/gateway', generation='another-generation', input_data={})


if __name__ == '__main__':
    unittest.main()
