import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from stability_core.event_outbox import EventOutbox, EventOutboxError

ROOT = Path(__file__).resolve().parents[2]


def event(n=1):
    return {'ts':'2026-10-08T00:00:00Z','tsEpoch':1791417600,'source':'fixture',
            'component':'fixture','severity':'high','key':str(n),'message':'synthetic'}


def record(box,n=1,payload=None):
    return box.record(payload or event(n),producer='fixture/node',generation='fixture-generation',attempt=1,seq=n)


class EventOutboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.db=self.root/'events.db';self.log=self.root/'events.jsonl'

    def tearDown(self):self.tmp.cleanup()

    def test_identity_retry_conflict_and_identical_independent_event(self):
        with EventOutbox(self.db) as box:
            first=record(box,1,event())
            self.assertTrue(record(box,1,event())['duplicate'])
            second=record(box,2,event())
            self.assertNotEqual(first['eventId'],second['eventId'])
            with self.assertRaisesRegex(EventOutboxError,'event-identity-conflict'):
                record(box,1,event(99))
            self.assertEqual(box.drain(self.log)['exported'],2)
            self.assertEqual(len(self.log.read_text().splitlines()),2)
            self.assertEqual(box.connection.execute('SELECT COUNT(*) FROM events').fetchone()[0],2)
            self.assertEqual(box.connection.execute('PRAGMA synchronous').fetchone()[0],2)

    def test_legacy_history_and_latest50_order(self):
        self.log.write_text(json.dumps(event(0))+'\n')
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, source TEXT, component TEXT, severity TEXT, key TEXT, payload TEXT NOT NULL)')
            db.execute('INSERT INTO events(ts_epoch,payload) VALUES(?,?)',(1,'{"legacy":true}'))
        with EventOutbox(self.db) as box:
            for n in range(1,54):record(box,n)
            self.assertEqual(box.drain(self.log,max_batch=100)['exported'],53)
            payloads=[json.loads(line) for line in self.log.read_text().splitlines()]
            self.assertEqual([p['key'] for p in payloads[-50:]],[str(n) for n in range(4,54)])
            self.assertEqual(payloads[0],event(0))

    def test_record_transaction_failure_and_caller_transaction_not_committed(self):
        with EventOutbox(self.db) as box:
            box.connection.execute("CREATE TRIGGER fixture_fail BEFORE INSERT ON stability_event_outbox BEGIN SELECT RAISE(ABORT,'SYNTHETIC_SECRET'); END")
            with self.assertRaisesRegex(EventOutboxError,'^event-record-failed$'):
                record(box)
            self.assertEqual(box.connection.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)
            box.connection.execute('DROP TRIGGER fixture_fail')
            box.connection.execute('BEGIN')
            with self.assertRaisesRegex(EventOutboxError,'caller-transaction-active'):record(box)
            with self.assertRaisesRegex(EventOutboxError,'caller-transaction-active'):box.drain(self.log)
            self.assertTrue(box.connection.in_transaction)
            box.connection.rollback()

    def test_pending_retention_and_batch_budgets(self):
        with EventOutbox(self.db,max_records=2) as box:
            record(box,1);record(box,2)
            with self.assertRaisesRegex(EventOutboxError,'outbox-budget-exceeded'):record(box,3)

            self.assertEqual(box.status()['states'],{'pending':2})
            self.assertEqual(box.drain(self.log,max_batch_bytes=1)['exported'],0)
            self.assertEqual(box.drain(self.log,max_batch=1)['exported'],1)
            self.assertEqual(box.status()['states'],{'exported':1,'pending':1})
            with self.assertRaisesRegex(EventOutboxError,'outbox-budget-exceeded'):record(box,3)

    def test_payload_total_budget_and_same_column_schema_drift(self):
        with EventOutbox(self.db,max_payload_bytes=256,max_total_bytes=256) as box:
            with self.assertRaises(EventOutboxError):
                record(box,payload={**event(),'message':'x'*300})
            self.assertEqual(box.connection.execute('SELECT COUNT(*) FROM events').fetchone()[0],0)
            record(box)
            with self.assertRaisesRegex(EventOutboxError,'outbox-budget-exceeded'):record(box,2)
        with sqlite3.connect(self.db) as db:
            sql=db.execute("SELECT sql FROM sqlite_master WHERE name='stability_event_outbox'").fetchone()[0]
            db.execute('ALTER TABLE stability_event_outbox RENAME TO fixture_old')
            db.execute(sql.replace('event_id TEXT NOT NULL UNIQUE','event_id TEXT NOT NULL'))
            db.execute('DROP TABLE fixture_old')
        with self.assertRaisesRegex(EventOutboxError,'outbox-schema-invalid'):EventOutbox(self.db)

    def crash_at(self,stage):
        with EventOutbox(self.db) as box:record(box)
        code='''import os,sys\nfrom stability_core.event_outbox import EventOutbox\nwith EventOutbox(sys.argv[1]) as box:\n def crash(stage):\n  if stage==sys.argv[3]:os._exit(73)\n box.drain(sys.argv[2],hook=crash)\n'''
        proc=subprocess.run([sys.executable,'-c',code,str(self.db),str(self.log),stage],cwd=ROOT,capture_output=True,text=True,timeout=10)
        self.assertEqual(proc.returncode,73,proc.stderr)

    def test_real_process_crash_intent_append_fsync_and_receipt_recovery(self):
        for stage in ('intent','append','fsync','before-receipt','receipt'):
            with self.subTest(stage=stage):
                self.db=self.root/(stage+'.db');self.log=self.root/(stage+'.jsonl')
                self.crash_at(stage)
                with EventOutbox(self.db) as box:
                    box.drain(self.log)
                    self.assertTrue(box.status()['complete'])
                self.assertEqual([json.loads(line) for line in self.log.read_text().splitlines()],[event()])

    def test_rotation_partial_and_offset_conflict_are_unknown(self):
        for kind in ('rotation','partial','offset','content'):
            with self.subTest(kind=kind):
                self.db=self.root/(kind+'.db');self.log=self.root/(kind+'.jsonl')
                self.crash_at('intent')
                if kind=='rotation':
                    self.log.rename(self.root/(kind+'.old'));self.log.write_text('')
                elif kind=='partial':self.log.write_text('{')
                elif kind=='offset':self.log.write_text(json.dumps(event())+'\nextra\n')
                else:
                    with EventOutbox(self.db) as box:
                        line=box.connection.execute('SELECT line FROM stability_event_outbox').fetchone()[0]
                    self.log.write_bytes(b'x'*(len(line)-1)+b'\n')
                before=self.log.read_bytes()
                with EventOutbox(self.db) as box:
                    result=box.drain(self.log)
                    self.assertEqual(result['coverage'],'unknown')
                    self.assertEqual(result['exported'],0)
                self.assertEqual(self.log.read_bytes(),before)

    def test_fsync_and_receipt_failures_do_not_leak_sensitive_errors(self):
        with EventOutbox(self.db) as box:
            record(box)
            with mock.patch('stability_core.event_outbox.os.fsync',side_effect=OSError('SYNTHETIC_SECRET')):
                with self.assertRaisesRegex(EventOutboxError,'^event-export-failed$'):box.drain(self.log)
            self.assertEqual(box.status()['coverage'],'unknown')
        db=self.root/'receipt.db';log=self.root/'receipt.jsonl'
        with EventOutbox(db) as box:
            record(box)
            box.connection.execute("CREATE TRIGGER fixture_receipt_fail BEFORE UPDATE OF state ON stability_event_outbox WHEN NEW.state='exported' BEGIN SELECT RAISE(ABORT,'SYNTHETIC_SECRET'); END")
            with self.assertRaisesRegex(EventOutboxError,'^event-export-failed$'):box.drain(log)
            self.assertEqual(box.status()['coverage'],'unknown')

    def test_concurrent_drains_and_target_binding(self):
        with EventOutbox(self.db) as box:
            for n in range(1,11):record(box,n)
        barrier=threading.Barrier(2);errors=[]
        def drain():
            try:
                with EventOutbox(self.db) as box:
                    barrier.wait(timeout=10);box.drain(self.log)
            except Exception as exc:errors.append(type(exc).__name__)
        threads=[threading.Thread(target=drain) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join(timeout=15)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(errors,[])
        self.assertEqual([json.loads(line)['key'] for line in self.log.read_text().splitlines()],[str(n) for n in range(1,11)])
        with EventOutbox(self.db) as box:
            with self.assertRaisesRegex(EventOutboxError,'export-target-conflict'):box.drain(self.root/'other.jsonl')

    def test_corrupt_stored_payload_is_not_appended(self):
        with EventOutbox(self.db) as box:
            record(box)
            box.connection.execute("UPDATE stability_event_outbox SET line=?",(b'bad\n',))
            self.assertEqual(box.drain(self.log)['coverage'],'unknown')
            self.assertEqual(self.log.read_bytes(),b'')

    def test_rotation_during_append_fsync_and_receipt_never_reports_complete(self):
        for stage in ('before-append','fsync','before-receipt'):
            with self.subTest(stage=stage):
                db=self.root/(stage+'-rotation.db');log=self.root/(stage+'-rotation.jsonl')
                old=self.root/(stage+'-retired.jsonl')
                def rotate(at):
                    if at==stage:
                        log.rename(old);log.write_bytes(b'')
                with EventOutbox(db) as box:
                    record(box)
                    result=box.drain(log,hook=rotate)
                    self.assertEqual(result['coverage'],'unknown')
                    self.assertEqual(result['exported'],0)
                    self.assertFalse(result['complete'])
                    self.assertEqual(log.read_bytes(),b'')
                    self.assertEqual(box.drain(log)['exported'],0)
                    self.assertEqual(log.read_bytes(),b'')
                self.assertEqual(old.read_bytes(),b'' if stage=='before-append' else
                                 (json.dumps(event(),ensure_ascii=False)+'\n').encode())

    def test_different_databases_share_export_file_lock(self):
        databases=[self.root/'node-a.db',self.root/'node-b.db']
        for i,db in enumerate(databases):
            with EventOutbox(db) as box:
                for n in range(5):
                    box.record(event(i*5+n),producer='fixture/node-'+str(i),
                               generation='fixture-generation',attempt=1,seq=n)
        barrier=threading.Barrier(2);errors=[]
        def drain(db):
            try:
                with EventOutbox(db) as box:
                    barrier.wait(timeout=10);box.drain(self.log)
            except Exception as exc:errors.append(type(exc).__name__)
        threads=[threading.Thread(target=drain,args=(db,)) for db in databases]
        for thread in threads:thread.start()
        for thread in threads:thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors,[])
        # A bounded busy return is drained by the caller's next existing cycle.
        for db in databases:
            with EventOutbox(db) as box:
                box.drain(self.log)
                self.assertTrue(box.status()['complete'])
        keys=[json.loads(line)['key'] for line in self.log.read_text().splitlines()]
        self.assertEqual(len(keys),10)
        self.assertEqual(set(keys),{str(n) for n in range(10)})

    def test_partial_unversioned_or_unsupported_owned_store_is_not_adopted(self):
        for mutation in ('drop-version','drop-outbox','drop-target','empty-version','future-version'):
            with self.subTest(mutation=mutation):
                db=self.root/(mutation+'.db')
                with EventOutbox(db) as box:record(box)
                with sqlite3.connect(db) as conn:
                    if mutation.startswith('drop-'):
                        suffix={'drop-version':'version','drop-outbox':None,'drop-target':'target'}[mutation]
                        table='stability_event_outbox'+('_'+suffix if suffix else '')
                        conn.execute('DROP TABLE '+table)
                    elif mutation=='empty-version':
                        conn.execute('DELETE FROM stability_event_outbox_version')
                    else:conn.execute('UPDATE stability_event_outbox_version SET version=99')
                    before=conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
                with self.assertRaises(EventOutboxError):EventOutbox(db)
                with sqlite3.connect(db) as conn:
                    self.assertEqual(conn.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall(),before)
                    self.assertEqual(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)

    def test_legacy_same_columns_wrong_types_or_constraints_are_rejected(self):
        for mutation in ('id-text','time-text','payload-nullable'):
            with self.subTest(mutation=mutation):
                db=self.root/(mutation+'.db')
                sql='CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, source TEXT, component TEXT, severity TEXT, key TEXT, payload TEXT NOT NULL)'
                if mutation=='id-text':sql=sql.replace('id INTEGER PRIMARY KEY AUTOINCREMENT','id TEXT')
                elif mutation=='time-text':sql=sql.replace('ts_epoch INTEGER','ts_epoch TEXT')
                else:sql=sql.replace('payload TEXT NOT NULL','payload TEXT')
                with sqlite3.connect(db) as conn:conn.execute(sql)
                with self.assertRaisesRegex(EventOutboxError,'legacy-schema-invalid'):EventOutbox(db)
                with sqlite3.connect(db) as conn:
                    self.assertEqual(conn.execute("SELECT name FROM sqlite_master WHERE name LIKE 'stability_event_outbox%'").fetchall(),[])

    def test_borrowed_connection_lifecycle_and_settings_are_preserved(self):
        conn=sqlite3.connect(self.db)
        try:
            conn.execute('PRAGMA journal_mode=WAL');conn.execute('PRAGMA synchronous=FULL')
            st=os.lstat(self.db);identity=(st.st_dev,st.st_ino)
            with EventOutbox(self.db,connection=conn,connection_identity=identity) as box:
                self.assertIs(box.connection,conn)
                record(box)
                self.assertEqual(box.drain(self.log)['exported'],1)
            self.assertEqual(conn.execute('PRAGMA journal_mode').fetchone()[0],'wal')
            self.assertEqual(conn.execute('PRAGMA synchronous').fetchone()[0],2)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
            conn.execute('BEGIN')
            conn.execute('INSERT INTO events(ts_epoch,payload) VALUES(1,?)',('fixture',))
            with self.assertRaisesRegex(EventOutboxError,'caller-transaction-active'):
                EventOutbox(self.db,connection=conn,connection_identity=identity)
            self.assertTrue(conn.in_transaction)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],2)
            conn.rollback()
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
            with EventOutbox(self.db,connection=conn,connection_identity=identity):
                conn.execute('BEGIN')
                conn.execute('INSERT INTO events(ts_epoch,payload) VALUES(1,?)',('caller-owned',))
            self.assertTrue(conn.in_transaction)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],2)
            conn.rollback()
        finally:conn.close()

    def test_borrowed_unsafe_settings_memory_or_wrong_path_are_not_changed(self):
        for mode in ('delete','normal','memory','path'):
            with self.subTest(mode=mode):
                db=self.root/(mode+'.db')
                conn=sqlite3.connect(':memory:' if mode=='memory' else db)
                try:
                    if mode in ('normal','path'):
                        conn.execute('PRAGMA journal_mode=WAL')
                        conn.execute('PRAGMA synchronous='+('NORMAL' if mode=='normal' else 'FULL'))
                    identity=(os.lstat(db).st_dev,os.lstat(db).st_ino) if mode!='memory' else (0,0)
                    settings=(conn.execute('PRAGMA journal_mode').fetchone()[0],conn.execute('PRAGMA synchronous').fetchone()[0])
                    with self.assertRaises(EventOutboxError):
                        EventOutbox(self.root/'wrong.db' if mode=='path' else db,connection=conn,connection_identity=identity)
                    self.assertEqual((conn.execute('PRAGMA journal_mode').fetchone()[0],conn.execute('PRAGMA synchronous').fetchone()[0]),settings)
                    self.assertEqual(conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(),[])
                    self.assertFalse(conn.in_transaction)
                finally:conn.close()

    def test_borrowed_delete_swap_never_opens_or_changes_replacement(self):
        conn=sqlite3.connect(self.db)
        try:
            conn.execute('PRAGMA journal_mode=WAL');conn.execute('PRAGMA synchronous=FULL')
            conn.execute('CREATE TABLE original (value TEXT)');conn.commit()
            conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            st=os.lstat(self.db);identity=(st.st_dev,st.st_ino)
            replacement=self.root/'replacement.db'
            with sqlite3.connect(replacement) as other:
                other.execute('CREATE TABLE replacement_only (value TEXT)')
                other.execute('INSERT INTO replacement_only VALUES(?)',('untouched',))
            self.db.unlink();replacement.rename(self.db)
            before=self.db.read_bytes()
            sidecars={suffix:Path(str(self.db)+suffix).read_bytes() if Path(str(self.db)+suffix).exists() else None
                      for suffix in ('-wal','-shm')}
            with self.assertRaises(EventOutboxError):EventOutbox(self.db,connection=conn,connection_identity=identity)
            self.assertEqual(self.db.read_bytes(),before)
            for suffix,content in sidecars.items():
                path=Path(str(self.db)+suffix)
                self.assertEqual(path.read_bytes() if path.exists() else None,content)
            with sqlite3.connect(self.db) as other:
                self.assertEqual(other.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(),[('replacement_only',)])
                self.assertEqual(other.execute('SELECT value FROM replacement_only').fetchall(),[('untouched',)])
        finally:conn.close()

    def test_borrowed_identity_provenance_is_required(self):
        conn=sqlite3.connect(self.db)
        try:
            conn.execute('PRAGMA journal_mode=WAL');conn.execute('PRAGMA synchronous=FULL')
            with self.assertRaisesRegex(EventOutboxError,'borrowed-identity-required'):
                EventOutbox(self.db,connection=conn)
            self.assertEqual(conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(),[])
        finally:conn.close()


if __name__=='__main__':unittest.main()
