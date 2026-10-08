import json
import hashlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from stability_core.event_outbox import EventOutbox, EventOutboxError
from stability_core.event_retention import EventRetention


class EventRetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.box=EventOutbox(self.root/'events.db')
    def tearDown(self):
        self.box.close(); self.tmp.cleanup()
    def retention(self, **kwargs):
        return EventRetention(self.box,self.root/'archive',install=True,**kwargs)
    def recorded(self,retention):
        ordinal=retention.register_generation('p','g')
        retention.require_generation('p','g',ordinal,new_record=True)
        self.box.record({'tsEpoch':1,'message':'synthetic'},producer='p',generation='g',attempt=0,seq=1)
        return ordinal
    def test_explicit_install_and_generation_gate(self):
        with self.assertRaisesRegex(EventOutboxError,'retention-install-required'):
            EventRetention(self.box,self.root/'archive')
        r=self.retention(); n=self.recorded(r)
        self.assertEqual(n,1)
        r.seal_generation('p','g',n)
        with self.assertRaisesRegex(EventOutboxError,'event-generation-sealed'):
            r.require_generation('p','g',n,new_record=True)
        self.assertTrue(r.require_generation('p','g',n)['sealed'])
        with self.assertRaisesRegex(EventOutboxError,'event-generation-unregistered'):
            r.require_generation('p','different',n)
    def test_archive_receipt_preserves_v1_rows_and_retirement_refuses(self):
        r=self.retention();n=self.recorded(r)
        self.box.drain(self.root/'events.jsonl');r.seal_generation('p','g',n)
        result=r.prepare_archive('p',n)
        segment=self.root/'archive'/result['archive']
        self.assertEqual(json.loads(segment.read_text())['events'][0]['line'],'{"tsEpoch": 1, "message": "synthetic"}\n')
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_event_outbox').fetchone()[0],1)
        self.assertTrue(self.box.record({'tsEpoch':1,'message':'synthetic'},producer='p',generation='g',attempt=0,seq=1)['duplicate'])
        with self.assertRaisesRegex(EventOutboxError,'retention-integration-required'):
            r.archive_and_retire('p',n)
    def test_archive_file_budget_reserves_both_new_files_before_publication(self):
        r=self.retention(max_archive_files=1);n=self.recorded(r)
        self.box.drain(self.root/'events.jsonl');r.seal_generation('p','g',n)
        with self.assertRaisesRegex(EventOutboxError,'retention-archive-budget'):
            r.prepare_archive('p',n)
        self.assertEqual(list((self.root/'archive').iterdir()), [])
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_retention_archives').fetchone()[0],0)
    def test_pending_unknown_unsealed_and_budget_cannot_archive(self):
        r=self.retention(max_archive_bytes=1);n=self.recorded(r)
        with self.assertRaisesRegex(EventOutboxError,'retention-generation-not-sealed'):r.prepare_archive('p',n)
        r.seal_generation('p','g',n)
        with self.assertRaisesRegex(EventOutboxError,'retention-unfinished-events'):r.prepare_archive('p',n)
        self.box.drain(self.root/'events.jsonl')
        with self.assertRaisesRegex(EventOutboxError,'retention-archive-budget'):r.prepare_archive('p',n)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_retention_archives').fetchone()[0],0)
    def test_publication_failure_does_not_retire_or_delete(self):
        r=self.retention();n=self.recorded(r);self.box.drain(self.root/'events.jsonl');r.seal_generation('p','g',n)
        def crash(stage):
            if stage=='manifest':raise RuntimeError('synthetic')
        with self.assertRaisesRegex(EventOutboxError,'^retention-archive-failed$'):r.prepare_archive('p',n,hook=crash)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_retention_archives').fetchone()[0],0)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_event_outbox').fetchone()[0],1)
        self.assertEqual(self.box.connection.execute('SELECT retired FROM stability_retention_producers').fetchone()[0],0)
    def test_real_process_crash_manifest_retains_exported_rows(self):
        r=self.retention();n=self.recorded(r)
        self.box.drain(self.root/'events.jsonl');r.seal_generation('p','g',n)
        code="""import os,sys
from stability_core.event_outbox import EventOutbox
from stability_core.event_retention import EventRetention
with EventOutbox(sys.argv[1]) as box:
 r=EventRetention(box,sys.argv[2])
 def crash(stage):
  if stage=='manifest':os._exit(73)
 r.prepare_archive('p',1,hook=crash)
"""
        proc=subprocess.run([sys.executable,'-c',code,str(self.root/'events.db'),str(self.root/'archive')],cwd=Path(__file__).resolve().parents[2],capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,73)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_retention_archives').fetchone()[0],0)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_event_outbox').fetchone()[0],1)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
        self.assertEqual(len(list((self.root/'archive').iterdir())),2)

    def test_active_caller_transaction_and_version_refuse(self):
        self.box.connection.execute('BEGIN')
        with self.assertRaisesRegex(EventOutboxError,'caller-transaction-active'):self.retention()
        self.assertTrue(self.box.connection.in_transaction);self.box.connection.rollback()
        r=self.retention()
        self.box.connection.execute('UPDATE stability_retention_version SET version=99')
        with self.assertRaisesRegex(EventOutboxError,'retention-schema-invalid'):self.retention()

    def test_generation_total_budget_does_not_mutate_existing_frontier(self):
        retention = self.retention(max_generations=1)
        self.assertEqual(retention.register_generation('p','first'), 1)
        before = self.box.connection.execute('SELECT * FROM stability_retention_producers').fetchall()
        with self.assertRaisesRegex(EventOutboxError, 'retention-generation-budget'):
            retention.register_generation('another-producer','second')
        self.assertEqual(before, self.box.connection.execute('SELECT * FROM stability_retention_producers').fetchall())
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_retention_generations').fetchone()[0], 1)

    def test_large_frontier_rejected_before_generation_query(self):
        retention = self.retention(max_batch_records=1)
        for index in range(3):
            ordinal = retention.register_generation('p','g'+str(index))
            retention.seal_generation('p','g'+str(index),ordinal)
        statements = []
        self.box.connection.set_trace_callback(statements.append)
        try:
            with self.assertRaisesRegex(EventOutboxError, 'retention-batch-budget'):
                retention.prepare_archive('p',3)
        finally:
            self.box.connection.set_trace_callback(None)
        self.assertFalse(any('SELECT ordinal,' in query for query in statements))
        self.assertFalse((self.root/'archive').exists())
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_retention_archives').fetchone()[0], 0)

    def test_malformed_version_one_schema_rejected_without_modification(self):
        for mutation in ('missing-columns','missing-unique','missing-sealed-check'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                with EventOutbox(Path(directory)/'state.db') as box:
                    EventRetention(box,Path(directory)/'archive',install=True)
                    box.connection.execute('DROP TABLE stability_retention_generations')
                    statement = 'CREATE TABLE stability_retention_generations(producer TEXT NOT NULL, ordinal INTEGER NOT NULL, generation TEXT NOT NULL, sealed INTEGER NOT NULL CHECK(sealed IN (0,1)), PRIMARY KEY(producer,ordinal), UNIQUE(producer,generation))'
                    if mutation == 'missing-columns': statement = 'CREATE TABLE stability_retention_generations(unexpected TEXT)'
                    elif mutation == 'missing-unique': statement = statement.replace(', UNIQUE(producer,generation)', '')
                    else: statement = statement.replace(' CHECK(sealed IN (0,1))', '')
                    box.connection.execute(statement)
                    before = list(box.connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name"))
                    with self.assertRaisesRegex(EventOutboxError,'retention-schema-invalid'):
                        EventRetention(box,Path(directory)/'archive',install=True)
                    self.assertEqual(before, list(box.connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name")))
                    self.assertFalse(box.connection.in_transaction)
                    self.assertFalse((Path(directory)/'archive').exists())

    def test_reused_object_rejects_changed_schema_version_and_masks_sql_errors(self):
        retention = self.retention()
        ordinal = retention.register_generation('p','g')
        self.box.connection.execute('UPDATE stability_retention_version SET version=99')
        with self.assertRaisesRegex(EventOutboxError,'retention-schema-invalid'):
            retention.require_generation('p','g',ordinal)
        self.box.connection.execute('UPDATE stability_retention_version SET version=1')
        self.box.connection.execute("CREATE TRIGGER private_schema_trigger BEFORE INSERT ON stability_retention_generations BEGIN SELECT RAISE(ABORT,'PRIVATE_SQL_ERROR'); END")
        before = self.box.connection.execute('SELECT * FROM stability_retention_producers').fetchall()
        with self.assertRaisesRegex(EventOutboxError,'^retention-generation-failed$') as error:
            retention.register_generation('p','second')
        self.assertNotIn('PRIVATE_SQL_ERROR', str(error.exception))
        self.assertEqual(before,self.box.connection.execute('SELECT * FROM stability_retention_producers').fetchall())

    def test_oversized_corrupt_blob_is_only_read_as_bounded_prefix(self):
        retention = self.retention(max_batch_bytes=64)
        ordinal = self.recorded(retention)
        self.box.drain(self.root/'events.jsonl')
        retention.seal_generation('p','g',ordinal)
        self.box.connection.execute('UPDATE stability_event_outbox SET line=?', (b'x' * 100000,))
        prefix_sizes=[]
        def row_factory(_cursor,row):
            if len(row)==10 and isinstance(row[3],bytes): prefix_sizes.append(len(row[3]))
            return row
        self.box.connection.row_factory=row_factory
        try:
            with self.assertRaisesRegex(EventOutboxError,'retention-batch-budget'):
                retention.prepare_archive('p',ordinal)
        finally:
            self.box.connection.row_factory=None
        self.assertEqual(prefix_sizes,[65])
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_retention_archives').fetchone()[0],0)
        self.assertFalse((self.root/'archive').exists())

    def test_corrupt_line_and_canonical_payload_digests_do_not_create_receipts(self):
        for mode in ('line-digest','payload-digest','event-identity'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                with EventOutbox(Path(directory)/'events.db') as box:
                    retention=EventRetention(box,Path(directory)/'archive',install=True)
                    ordinal=retention.register_generation('p','g')
                    box.record({'tsEpoch':1,'message':'original'},producer='p',generation='g',attempt=0,seq=1)
                    box.drain(Path(directory)/'events.jsonl')
                    retention.seal_generation('p','g',ordinal)
                    changed=b'{"tsEpoch": 1, "message": "tampered"}\n'
                    if mode=='line-digest':box.connection.execute('UPDATE stability_event_outbox SET line=?',(changed,))
                    elif mode=='payload-digest':box.connection.execute('UPDATE stability_event_outbox SET line=?,line_digest=?',(changed,hashlib.sha256(changed).hexdigest()))
                    else:box.connection.execute('UPDATE stability_event_outbox SET event_id=?',('0'*64,))
                    with self.assertRaisesRegex(EventOutboxError,'retention-event-invalid'):
                        retention.prepare_archive('p',ordinal)
                    self.assertEqual(box.connection.execute('SELECT COUNT(*) FROM stability_retention_archives').fetchone()[0],0)
                    self.assertEqual(box.connection.execute('SELECT state FROM stability_event_outbox').fetchone()[0],'exported')
                    self.assertFalse((Path(directory)/'archive').exists())

    def test_empty_archive_files_are_bounded_separately_from_byte_quota(self):
        retention=self.retention(max_archive_files=2)
        ordinal=self.recorded(retention)
        self.box.drain(self.root/'events.jsonl')
        retention.seal_generation('p','g',ordinal)
        archive=self.root/'archive';archive.mkdir()
        for index in range(3):(archive/('empty'+str(index))).write_bytes(b'')
        with self.assertRaisesRegex(EventOutboxError,'retention-archive-budget'):
            retention.prepare_archive('p',ordinal)
        self.assertEqual(len(list(archive.iterdir())),3)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM stability_retention_archives').fetchone()[0],0)

if __name__=='__main__':unittest.main()
