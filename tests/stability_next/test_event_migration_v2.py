import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import shutil
import unittest
from unittest import mock
from typing import Any, Dict

# Exact two-function source excerpt from immutable historical commit 3f742b490fc4fa67d15727668d5c720b6034631d.
OLD_WRITER_SOURCE = 'def init_db() -> sqlite3.Connection:\n    ensure_dirs()\n    conn = sqlite3.connect(str(STATE_DB))\n    conn.execute("PRAGMA journal_mode=WAL")\n    conn.execute("PRAGMA synchronous=NORMAL")\n    conn.execute(\n        "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)"\n    )\n    conn.execute(\n        "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, source TEXT, component TEXT, severity TEXT, key TEXT, payload TEXT NOT NULL)"\n    )\n    conn.execute(\n        "CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, action_id TEXT, action TEXT, result TEXT, payload TEXT NOT NULL)"\n    )\n    conn.commit()\n    return conn\n\ndef db_record_event(conn: sqlite3.Connection, event: Dict[str, Any]) -> None:\n    conn.execute(\n        "INSERT INTO events(ts_epoch, source, component, severity, key, payload) VALUES(?, ?, ?, ?, ?, ?)",\n        (\n            int(event.get("tsEpoch") or epoch()),\n            event.get("source"),\n            event.get("component"),\n            event.get("severity"),\n            event.get("key"),\n            json.dumps(event, ensure_ascii=False),\n        ),\n    )\n    conn.commit()\n    append_jsonl(EVENTS_JSONL, event)'

from stability_core import event_migration_v2 as migration
from stability_core.event_migration_v2 import build_offline_package, preserve_rollback, MigrationError
from stability_core.action_ledger import ActionLedger
from stability_core.event_outbox import EventOutbox
from stability_core.event_pipeline_v2 import EventPipelineV2


class OfflineMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.db = self.root / 'source.db'
        self.stream = self.root / 'source.jsonl'
        self.conn = sqlite3.connect(self.db)
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, source TEXT, component TEXT, severity TEXT, key TEXT, payload TEXT NOT NULL)')
        self.conn.execute('CREATE TABLE kv(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL)')
        self.conn.execute('CREATE TABLE actions(id INTEGER PRIMARY KEY AUTOINCREMENT,ts_epoch INTEGER NOT NULL,action_id TEXT,action TEXT,result TEXT,payload TEXT NOT NULL)')
        self.conn.executemany('INSERT INTO events(id,ts_epoch,payload) VALUES(?,0,?)', [(n, json.dumps({'n': n})) for n in range(70)])
        self.conn.execute("INSERT INTO kv VALUES('cooldown','1234',1234)")
        self.conn.execute("INSERT INTO actions(ts_epoch,payload) VALUES(0,'uncertain')")
        self.conn.commit()
        self.stream.write_bytes(b''.join(json.dumps({'n': n}).encode() + b'\n' for n in range(70)))
        self.package = self.root / 'package'

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def build(self, **kwargs):
        return build_offline_package(self.db, self.stream, self.package, **kwargs)

    def test_wal_legacy_history_control_state_latest50_preserved(self):
        # WAL remains open: backup API must include committed WAL contents.
        self.conn.execute("INSERT INTO kv VALUES('wal-only','present',222)")
        self.conn.commit()
        result = self.build()
        self.assertEqual(result['status'], 'offline-qualified')
        self.assertFalse(result['activationAllowed'])
        self.assertFalse(result['writerFreezeEstablished'])
        history = sqlite3.connect(self.package / 'history.sqlite')
        candidate = sqlite3.connect(self.package / 'candidate.sqlite')
        try:
            self.assertEqual(history.execute('SELECT * FROM events').fetchall(), self.conn.execute('SELECT * FROM events').fetchall())
            for table in ('kv', 'actions'):
                self.assertEqual(history.execute('SELECT * FROM ' + table).fetchall(), candidate.execute('SELECT * FROM ' + table).fetchall())
            self.assertEqual(candidate.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0], 0)
            self.assertEqual(candidate.execute('SELECT COUNT(*) FROM event_v2_generations').fetchone()[0], 0)
            self.assertEqual(candidate.execute('SELECT witness_path FROM event_v2_meta').fetchone()[0], str(self.package / 'archive' / 'witness.json'))
            self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0], 70)
        finally:
            history.close(); candidate.close()
        self.assertEqual((self.package / 'history.jsonl').read_bytes(), self.stream.read_bytes())
        self.assertEqual([json.loads(x)['n'] for x in (self.package / 'events.jsonl').read_text().splitlines()], list(range(20, 70)))

    def v1(self, state):
        outbox = EventOutbox(self.db)
        outbox.close()
        line = self.stream.read_bytes().splitlines(keepends=True)[0]
        info = os.stat(self.stream)
        self.conn.execute("""INSERT INTO stability_event_outbox
            (event_id,producer,generation,attempt,producer_seq,payload_digest,line,state,legacy_id,target,dev,inode,offset,line_digest)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ('id','fixture','g',1,0,hashlib.sha256(line).hexdigest(),line,state,0,str(self.stream),info.st_dev,info.st_ino,0,hashlib.sha256(line).hexdigest()))
        self.conn.commit()

    def test_real_action_ledger_every_column_and_index_preserved(self):
        ledger = ActionLedger(self.db)
        try:
            for n, state in enumerate(('planned', 'executing', 'uncertain')):
                record = ledger.plan_action(idempotency_key='key'+str(n), action_type='synthetic',
                                           target='target'+str(n), generation='g', input_data={'n': n})
                self.conn.execute('UPDATE action_ledger SET state=? WHERE action_id=?', (state, record.action_id))
                self.conn.commit()
        finally:
            ledger.close()
        before = self.conn.execute('SELECT * FROM action_ledger ORDER BY action_id').fetchall()
        self.build()
        candidate = sqlite3.connect(self.package / 'candidate.sqlite')
        try:
            self.assertEqual(candidate.execute('SELECT * FROM action_ledger ORDER BY action_id').fetchall(), before)
            self.assertEqual(candidate.execute('SELECT * FROM stability_schema_versions').fetchall(),
                             self.conn.execute('SELECT * FROM stability_schema_versions').fetchall())
            self.assertEqual(candidate.execute("SELECT sql FROM sqlite_master WHERE name='action_ledger_one_active_scope'").fetchone(),
                             self.conn.execute("SELECT sql FROM sqlite_master WHERE name='action_ledger_one_active_scope'").fetchone())
        finally:
            candidate.close()

    def test_v1_exported_exact_bytes_no_replay(self):
        self.v1('exported')
        self.assertEqual(self.build()['sourceMode'], 'v1-exported-reconciled')

    def test_pending_exporting_unknown_refuse_and_preserve_partial(self):
        for state in ('pending', 'exporting', 'unknown'):
            with self.subTest(state=state):
                self.v1(state)
                self.package = self.root / state
                with self.assertRaisesRegex(MigrationError, 'unreconciled'):
                    self.build()
                self.assertEqual(json.loads((self.package / 'manifest.json').read_text())['status'], 'partial')
                self.assertTrue((self.package / 'history.sqlite').exists())
                self.conn.execute('DROP TABLE stability_event_outbox')
                self.conn.execute('DROP TABLE stability_event_outbox_version')
                self.conn.execute('DROP TABLE stability_event_outbox_target')
                self.conn.commit()

    def test_v1_wrong_offset_or_target_refuses_qualification(self):
        self.v1('exported')
        self.conn.execute('UPDATE stability_event_outbox SET offset=1')
        self.conn.commit()
        with self.assertRaisesRegex(MigrationError, 'export-proof'):
            self.build()
        self.package = self.root / 'wrong-target'
        self.conn.execute("UPDATE stability_event_outbox SET offset=0,target='other'")
        self.conn.commit()
        with self.assertRaisesRegex(MigrationError, 'target-proof'):
            self.build()

    def test_real_wal_commit_after_snapshot_refuses_qualification(self):
        def mutate(stage):
            if stage == 'immutable-history-snapshot':
                self.conn.execute("UPDATE kv SET value='after' WHERE key='cooldown'")
                self.conn.commit()
        with self.assertRaisesRegex(MigrationError, 'source-changing'):
            self.build(stage_hook=mutate)
        self.assertEqual(json.loads((self.package / 'manifest.json').read_text())['status'], 'partial')
        self.assertEqual(self.conn.execute("SELECT value FROM kv WHERE key='cooldown'").fetchone()[0], 'after')
        old = sqlite3.connect(self.package / 'history.sqlite')
        try:
            self.assertEqual(old.execute("SELECT value FROM kv WHERE key='cooldown'").fetchone()[0], '1234')
        finally:
            old.close()

    def test_actual_old_writer_ignores_v2_marker_in_tmp_store(self):
        self.build()
        path = self.package / 'candidate.sqlite'
        stream = self.root / 'historical-writer.jsonl'
        def append_jsonl(target, event):
            with target.open('a') as output:
                output.write(json.dumps(event) + '\n')
        namespace = dict(sqlite3=sqlite3, json=json, STATE_DB=path, EVENTS_JSONL=stream,
                         ensure_dirs=lambda: None, epoch=lambda: 1, append_jsonl=append_jsonl,
                         Any=Any, Dict=Dict)
        exec(OLD_WRITER_SOURCE, namespace)
        old = namespace['init_db']()
        try:
            namespace['db_record_event'](old, {'tsEpoch': 1, 'key': 'old-writer-counterexample'})
            self.assertEqual(old.execute('SELECT version FROM stability_event_outbox_version').fetchone()[0], 2)
            self.assertEqual(old.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)
            self.assertTrue(stream.exists())
        finally:
            old.close()

    def test_each_stage_interruption_remains_partial(self):
        for stage_name in ('immutable-history-snapshot', 'historical-delivery-reconciled',
                           'control-state-continuity', 'new-store-witness-bound', 'package-complete'):
            self.package = self.root / stage_name
            def interrupt(stage):
                if stage == stage_name:
                    raise RuntimeError('synthetic')
            with self.assertRaises(RuntimeError):
                self.build(stage_hook=interrupt)
            self.assertEqual(json.loads((self.package / 'manifest.json').read_text())['status'], 'partial')

    def test_stage_interrupt_never_qualified(self):
        def interrupt(stage):
            if stage == 'new-store-witness-bound':
                raise RuntimeError('synthetic')
        with self.assertRaises(RuntimeError):
            self.build(stage_hook=interrupt)
        value = json.loads((self.package / 'manifest.json').read_text())
        self.assertEqual(value['status'], 'partial')
        self.assertFalse(value['activationAllowed'])

    def test_rollback_keeps_increment_ledger_separate(self):
        self.build()
        self.conn.execute("INSERT INTO actions(ts_epoch,payload) VALUES(0,'after-backup')")
        self.conn.commit()
        outcome = preserve_rollback(self.package, self.db, self.stream, self.root / 'rollback')
        self.assertTrue(outcome['requiresActionReconciliation'])
        self.assertEqual((self.root / 'rollback' / 'old-observation.jsonl').read_bytes(), self.stream.read_bytes())
        old = sqlite3.connect(self.root / 'rollback' / 'old-observation.sqlite')
        new = sqlite3.connect(self.root / 'rollback' / 'increments.sqlite')
        try:
            self.assertEqual(old.execute('SELECT COUNT(*) FROM actions').fetchone()[0], 1)
            self.assertEqual(new.execute('SELECT COUNT(*) FROM actions').fetchone()[0], 2)
        finally:
            old.close(); new.close()
        moved = self.root / 'independent-restoration'
        shutil.move(str(self.root / 'rollback'), moved)
        standalone = json.loads((moved / 'rollback.json').read_text())
        self.assertEqual(hashlib.sha256((moved / 'old-observation.jsonl').read_bytes()).hexdigest(),
                         standalone['oldHistoryJsonlSha256'])
        self.assertEqual([json.loads(line)['n'] for line in (moved / 'old-observation.jsonl').read_text().splitlines()][-50:],
                         list(range(20, 70)))
        self.assertEqual(hashlib.sha256((moved / 'migration-source-manifest.json').read_bytes()).hexdigest(),
                         standalone['sourceManifestSha256'])

    def test_v2_rollback_retains_retired_archive_and_bound_witness(self):
        self.build()
        path = self.package / 'candidate.sqlite'
        candidate = sqlite3.connect(path)
        candidate.execute('PRAGMA journal_mode=WAL')
        candidate.execute('PRAGMA synchronous=FULL')
        info = os.stat(path)
        pipeline = EventPipelineV2(candidate, path, (info.st_dev, info.st_ino),
                                   self.package / 'events.jsonl', self.package / 'archive',
                                   keep_generations=2, keep_archives=2)
        try:
            for n in range(6):
                pipeline.record([{'tsEpoch': n + 100, 'message': 'increment'}])
            self.assertGreater(pipeline.core.retention_state()['retirementSeq'], 0)
        finally:
            pipeline.close()
        try:
            result = preserve_rollback(self.package, path, self.package / 'events.jsonl', self.root / 'v2-rollback')
            self.assertIn('witness.json', result['archiveFileSha256'])
            for name, expected in result['archiveFileSha256'].items():
                self.assertEqual(hashlib.sha256((self.root / 'v2-rollback' / 'increment-archive' / name).read_bytes()).hexdigest(), expected)
            self.assertEqual(result['incrementStoreId'], json.loads((self.package / 'manifest.json').read_text())['eventStore']['storeId'])
            segment = next((self.package / 'archive').glob('segment-*.json'))
            original = segment.read_bytes()
            segment.write_bytes(original + b' ')
            with self.assertRaisesRegex(MigrationError, 'archive-conflict'):
                preserve_rollback(self.package, path, self.package / 'events.jsonl', self.root / 'corrupt-segment')
            segment.write_bytes(original)
            manifest_path = Path(str(segment) + '.manifest')
            original_manifest = manifest_path.read_bytes()
            manifest_path.unlink()
            with self.assertRaises(FileNotFoundError):
                preserve_rollback(self.package, path, self.package / 'events.jsonl', self.root / 'missing-segment-manifest')
            manifest_path.write_bytes(original_manifest)
            for folder in ('corrupt-segment', 'missing-segment-manifest'):
                self.assertEqual(json.loads((self.root / folder / 'rollback.json').read_text())['status'], 'partial')
        finally:
            candidate.close()

    def test_same_named_wrong_schema_refuses_before_candidate(self):
        self.conn.execute('DROP TABLE kv')
        self.conn.execute('CREATE TABLE kv(key TEXT PRIMARY KEY,value TEXT,updated_at INTEGER,unexpected TEXT)')
        self.conn.commit()
        with self.assertRaisesRegex(MigrationError, 'unsupported-schema'):
            self.build()
        self.assertFalse((self.package / 'candidate.sqlite').exists())
        self.assertEqual(json.loads((self.package / 'manifest.json').read_text())['status'], 'partial')

    def test_actual_ledger_uppercase_literal_schema_refused(self):
        ledger = ActionLedger(self.db)
        ledger.close()
        ddl = self.conn.execute("SELECT sql FROM sqlite_master WHERE name='action_ledger'").fetchone()[0]
        self.conn.execute('DROP TABLE action_ledger')
        self.conn.execute(ddl.replace("'planned'", "'PLANNED'"))
        self.conn.execute("CREATE UNIQUE INDEX action_ledger_one_active_scope ON action_ledger(target) WHERE state IN ('planned','executing','uncertain')")
        self.conn.commit()
        with self.assertRaisesRegex(MigrationError, 'unsupported-schema'):
            self.build()
        self.assertFalse((self.package / 'candidate.sqlite').exists())
        self.assertEqual(json.loads((self.package / 'manifest.json').read_text())['status'], 'partial')

    def test_sql_normalization_preserves_quoted_literals_and_escapes(self):
        normalize = migration._normalized_sql
        self.assertNotEqual(normalize("CHECK(state IN ('planned'))"), normalize("CHECK(state IN ('PLANNED'))"))
        self.assertNotEqual(normalize("CHECK(state IN ('planned'))"), normalize("CHECK(state IN (' planned'))"))
        self.assertNotEqual(normalize("CHECK(x='it''s A')"), normalize("CHECK(x='it''s a')"))
        self.assertNotEqual(normalize('CHECK(x="literal A")'), normalize('CHECK(x="literal a")'))
        self.assertEqual(normalize("CREATE TABLE x(a TEXT CHECK(a='if not exists'))"),
                         normalize("create table x ( a text CHECK (a = 'if not exists') )"))

    def test_valid_copied_ledger_accepts_new_plan_without_losing_old(self):
        ledger = ActionLedger(self.db)
        try:
            old = ledger.plan_action(idempotency_key='before', action_type='synthetic', target='old', generation='g', input_data={})
        finally:
            ledger.close()
        self.build()
        copied = ActionLedger(self.package / 'candidate.sqlite')
        try:
            new = copied.plan_action(idempotency_key='after', action_type='synthetic', target='new', generation='g', input_data={})
            self.assertEqual(new.state, 'planned')
            self.assertNotEqual(old.action_id, new.action_id)
            self.assertEqual(copied._conn.execute('SELECT COUNT(*) FROM action_ledger').fetchone()[0], 2)
        finally:
            copied.close()

    def test_legacy_incompatible_tail_not_silently_truncated(self):
        for n, raw in enumerate((b'[]\n', b'123\n', b'{"message":"' + b'x' * 65536 + b'"}\n', b'{"n":1}')):
            self.package = self.root / ('tail' + str(n))
            self.stream.write_bytes(raw)
            with self.assertRaises(MigrationError):
                self.build()
            self.assertEqual((self.package / 'history.jsonl').read_bytes(), raw)
            self.assertEqual(json.loads((self.package / 'manifest.json').read_text())['status'], 'partial')

    def test_v2_rollback_missing_or_wrong_witness_refuses(self):
        self.build()
        witness = self.package / 'archive' / 'witness.json'
        original = witness.read_bytes()
        witness.unlink()
        with self.assertRaises(FileNotFoundError):
            preserve_rollback(self.package, self.package / 'candidate.sqlite', self.package / 'events.jsonl', self.root / 'missing-witness')
        witness.write_text(json.dumps({'version':2, 'storeId':'wrong', 'retirementSeq':9000, 'frontiers':{}, 'chain':'0'*64}))
        with self.assertRaisesRegex(MigrationError, 'witness-conflict'):
            preserve_rollback(self.package, self.package / 'candidate.sqlite', self.package / 'events.jsonl', self.root / 'wrong-witness')
        witness.write_bytes(original)
        for name in ('missing-witness', 'wrong-witness'):
            self.assertEqual(json.loads((self.root / name / 'rollback.json').read_text())['status'], 'partial')

    def test_copy_then_in_place_archive_rewrite_refused(self):
        self.build()
        witness = self.package / 'archive' / 'witness.json'
        original_write = migration._write
        def mutate(path, content):
            original_write(path, content)
            if Path(path).name == 'witness.json' and Path(path).parent.name == 'increment-archive':
                witness.write_bytes(content + b' ')
        with mock.patch.object(migration, '_write', side_effect=mutate):
            with self.assertRaisesRegex(MigrationError, 'source-changing'):
                preserve_rollback(self.package, self.package / 'candidate.sqlite', self.package / 'events.jsonl', self.root / 'rewrite')
        self.assertEqual(json.loads((self.root / 'rewrite' / 'rollback.json').read_text())['status'], 'partial')

    def test_unknown_schema_symlink_hardlink_rejected(self):
        self.conn.execute('CREATE TABLE unknown_state(value TEXT)')
        self.conn.commit()
        with self.assertRaisesRegex(MigrationError, 'unknown-schema'):
            self.build()
        self.package = self.root / 'second'
        link = self.root / 'hardlink'
        os.link(self.db, link)
        with self.assertRaisesRegex(MigrationError, 'file-identity'):
            self.build()
        os.unlink(link)
        sym = self.root / 'symlink'
        sym.symlink_to(self.stream)
        with self.assertRaisesRegex(MigrationError, 'symlink'):
            build_offline_package(self.db, sym, self.root / 'third')


if __name__ == '__main__':
    unittest.main()
