"""Actual daemon restart with synthetic collectors/effects, no runtime calls."""
import importlib.util
import json
import os
from pathlib import Path
import hashlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from stability_core.action_ledger import ActionLedger
import stability_core.preflight_recovery as recovery_module

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('startup_recovery_test', ROOT / 'bin/cat_agents_stabilityd.py')
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)

CHILD = r'''
import importlib.util,json,os,signal,sys
from pathlib import Path
root=Path(sys.argv[1]);home=Path(sys.argv[2]);mode=sys.argv[3]
sys.path.insert(0,str(root))
os.environ['OPENCLAW_HOME_DIR']=str(home)
os.environ['CAT_AGENTS_WORKFLOW_ROOT']=str(home/'workflow')
os.environ['CAT_AGENTS_WORKFLOW_DB']=str(home/'workflow'/'missing.db')
from stability_core.action_ledger import ActionLedger,ActionConflict
from stability_core.action_executor import ActionExecutor,ActionSpec,AuthorizationGrant,BoundaryCheck,OperationResult,PostcheckResult
spec=importlib.util.spec_from_file_location('synthetic_startup_daemon',root/'bin/cat_agents_stabilityd.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
if mode=='crash':
    with ActionLedger(m.STATE_DB) as ledger:
        record=ledger.plan_action(idempotency_key='old-intent',action_type='fixture',target='private-target-sentinel',
            generation='old-boot',input_data={'synthetic':True},authorization_ref='auth://fixture',
            policy_ref='policy://fixture',evidence_refs=('evidence://fixture',))
        ledger.begin_execution(record.action_id,expected_version=record.version,precheck_ref='check://fixture')
        with (home/'crash-effect').open('a') as f:
            f.write('one-effect\n');f.flush();os.fsync(f.fileno())
        os._exit(73)

def runner(name,command,fallback,**kwargs):
    return {'data':dict(fallback),'findings':[],'cacheUpdates':{},
            'probe':{'component':name,'status':'ok','coverage':True,'durationMs':1}}
m.update_runtime_trends=lambda *_:{}
m.update_streaks=lambda *_:{}
m.add_resource_governance_findings=lambda *_:None
m.policy_from_findings=lambda *_:{'mode':'fixture'}
m.build_auth_maintenance_plan=lambda *_:{}

def actuate(conn,snapshot,policy,*,no_action=False):
    actions=[]
    with ActionLedger(m.STATE_DB) as ledger:
        def authorize(s,r):
            return AuthorizationGrant(status='authorized',authorization_ref=s.authorization_ref,policy_ref=s.policy_ref,
                action_type=s.action_type,target=s.target,generation=s.generation,source=s.source,
                input_digest=r.input_digest,evidence_refs=s.evidence_refs,expires_at_ms=2000)
        def operation(s,r):
            with (home/'allowed-effects').open('a') as f:f.write('one-allowed-effect\n')
            return OperationResult('complete','outcome://fixture')
        executor=ActionExecutor(ledger,authorizer=authorize,precheck=lambda *_:BoundaryCheck('approved','check://fixture'),
            operation=operation,postcheck=lambda *_:PostcheckResult('verified','check://fixture'),clock_ms=lambda:1000)
        for target in ('private-target-sentinel','independent-target'):
            s=ActionSpec(idempotency_key='new-'+target,action_type='fixture',target=target,generation='new-boot',
                source='fixture',input_data={'synthetic':True},authorization_ref='auth://fixture',policy_ref='policy://fixture',
                evidence_refs=('evidence://fixture',))
            try:
                result=executor.execute(s)
                actions.append(result.record.state)
            except ActionConflict:
                actions.append('blocked')
    return actions
m.actuate=actuate

def cycle(conn,*,no_action=False):
    # Collectors are synthetic. The actual daemon loop and committed SQLite
    # recovery read are exercised in this new process.
    m._inspection_cache_enabled=False
    snapshot,findings,policy=m.collect_snapshot(conn,component_probe_runner=runner)
    actions=m.actuate_collected_snapshot(conn,snapshot,policy,no_action=no_action)
    (home/'restart-report.json').write_text(json.dumps({'recovery':snapshot['actionRecovery'],
        'findingKeys':[f['key'] for f in findings],'actions':actions}))
    os.kill(os.getpid(),signal.SIGTERM)
m.run_once=cycle
raise SystemExit(m.daemon_loop())
'''


class StartupRecoveryTests(unittest.TestCase):
    def test_physical_store_corruption_blocks_daemon_before_collection_or_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / 'state.db'
            damaged = b'CORRUPT_PRIVATE_STATE_SENTINEL\x00not-sqlite'
            database.write_bytes(damaged)
            logs = []
            with mock.patch.object(m, 'STATE_DB', database), \
                 mock.patch.object(m, 'LOCK_PATH', root / 'daemon.lock'), \
                 mock.patch.object(m, 'ensure_dirs'), \
                 mock.patch.object(m.signal, 'signal'), \
                 mock.patch.object(m, 'log_line', side_effect=logs.append), \
                 mock.patch.object(m, 'run_once') as cycle:
                self.assertEqual(m.daemon_loop(), 1)
                cycle.assert_not_called()
            self.assertEqual(database.read_bytes(), damaged)
            self.assertEqual(len(logs), 1)
            self.assertIn('startup_blocked stage=state-store errorClass=DatabaseError', logs[0])
            self.assertIn('actionReadiness=unknown automaticRecovery=false', logs[0])
            self.assertNotIn('CORRUPT_PRIVATE_STATE_SENTINEL', str(logs))
            self.assertEqual({p.name for p in root.iterdir()}, {'state.db', 'daemon.lock'})
            with (root / 'daemon.lock').open('a+') as handle:
                m.fcntl.flock(handle.fileno(), m.fcntl.LOCK_EX | m.fcntl.LOCK_NB)

    def test_large_recovery_query_budget_returns_unknown_and_releases_read_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.db'
            with ActionLedger(path) as ledger:
                ledger.plan_action(idempotency_key='seed', action_type='fixture', target='seed',
                                   generation='fixture', input_data={})
            with sqlite3.connect(path) as conn:
                cursor = conn.execute('SELECT * FROM action_ledger')
                names = [column[0] for column in cursor.description]
                seed = dict(zip(names, cursor.fetchone()))
                rows = []
                for number in range(1, 1001):
                    row = {**seed, 'action_id': 'act_' + format(number, '032x'),
                           'idempotency_key': 'key-' + str(number), 'target': 'target-' + str(number)}
                    rows.append(tuple(row[name] for name in names))
                conn.executemany('INSERT INTO action_ledger(' + ','.join(names) + ') VALUES(' +
                                 ','.join('?' for _ in names) + ')', rows)
                conn.commit()
                with mock.patch.object(recovery_module.time, 'monotonic', side_effect=[0.0, 1.0]):
                    summary = m.action_recovery_evidence(conn, checked_at='fixture-time', checked_at_epoch=100)
                self.assertEqual(summary['ledgerStatus'], 'unavailable')
                self.assertEqual(summary['recoveryState'], 'unknown')
                self.assertFalse(conn.in_transaction)
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM action_ledger').fetchone()[0], 1001)

    def test_recovery_keeps_open_connection_scope_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.db'
            replacement = Path(directory) / 'replacement.db'
            with ActionLedger(path) as ledger:
                record = ledger.plan_action(idempotency_key='replacement-fixture', action_type='fixture',
                                           target='private-target', generation='fixture', input_data={},
                                           authorization_ref='auth://fixture', policy_ref='policy://fixture',
                                           evidence_refs=('evidence://fixture',))
                ledger.begin_execution(record.action_id, expected_version=record.version)
            with sqlite3.connect(path) as conn:
                # DELETE journal makes the inode replacement fixture deterministic
                # and avoids old WAL sidecars influencing the new file.
                conn.execute('PRAGMA journal_mode=DELETE')
                with sqlite3.connect(replacement) as other:
                    other.execute('CREATE TABLE kv(key TEXT PRIMARY KEY,value TEXT)')
                    other.commit()
                os.replace(replacement, path)
                before = hashlib.sha256(path.read_bytes()).hexdigest()
                recovery = m.action_recovery_evidence(conn, checked_at='fixture-time', checked_at_epoch=100)
                self.assertEqual(recovery['counts']['executing'], 1)
                self.assertEqual(recovery['ledgerStatus'], 'available')
                self.assertEqual(before, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_caller_transaction_is_not_committed_rolled_back_or_inspected(self):
        with sqlite3.connect(':memory:') as conn:
            conn.execute('CREATE TABLE fixture(value TEXT)')
            conn.execute("INSERT INTO fixture VALUES('uncommitted')")
            summary = m.action_recovery_evidence(conn, checked_at='fixture-time', checked_at_epoch=100)
            self.assertEqual(summary['ledgerStatus'], 'unavailable')
            self.assertTrue(conn.in_transaction)
            self.assertEqual(conn.execute('SELECT value FROM fixture').fetchone()[0], 'uncommitted')
            conn.rollback()
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM fixture').fetchone()[0], 0)

    def test_crash_restart_reports_reserved_target_and_allows_independent_target(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            for mode, expected in (('crash', 73), ('restart', 0)):
                result = subprocess.run([sys.executable, '-c', CHILD, str(ROOT), str(home), mode],
                                        cwd=ROOT, capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, expected, result.stderr)
            report = json.loads((home / 'restart-report.json').read_text())
            recovery = report['recovery']
            self.assertEqual(recovery['ledgerStatus'], 'available')
            self.assertEqual(recovery['counts']['executing'], 1)
            self.assertFalse(recovery['automaticReplay'])
            self.assertFalse(recovery['ledgerMutation'])
            self.assertIn('stabilityd_action_recovery_required', report['findingKeys'])
            self.assertEqual(report['actions'], ['blocked', 'succeeded'])
            self.assertEqual((home / 'crash-effect').read_text(), 'one-effect\n')
            self.assertEqual((home / 'allowed-effects').read_text(), 'one-allowed-effect\n')
            self.assertNotIn('private-target-sentinel', json.dumps(report))

    def test_recovery_uses_current_connection_and_never_opens_global_default(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'legacy.db'
            with sqlite3.connect(path) as conn:
                conn.execute('CREATE TABLE kv(key TEXT PRIMARY KEY,value TEXT)')
                conn.commit()
                summary = m.action_recovery_evidence(conn, checked_at='fixture-time', checked_at_epoch=100)
            self.assertEqual(summary['ledgerStatus'], 'not-initialized')
            self.assertEqual(summary['recoveryState'], 'unknown')
            with sqlite3.connect(path) as check:
                names = [row[0] for row in check.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                self.assertEqual(names, ['kv'])
            with sqlite3.connect(':memory:') as conn:
                self.assertEqual(m.action_recovery_evidence(conn, checked_at='fixture-time',
                    checked_at_epoch=100)['ledgerStatus'], 'not-initialized')
