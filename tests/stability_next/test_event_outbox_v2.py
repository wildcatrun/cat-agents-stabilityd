"""Fresh offline SQLite/file fixtures; never runtime actions or live migration."""
import dataclasses
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from stability_core.action_ledger import ActionLedger
from stability_core.event_outbox import EventOutbox, EventOutboxError
from stability_core.event_outbox_v2 import EventOutboxV2
from stability_core.event_v2_contract import (ExportReceipt, ArchiveReceipt, OwnerEndedProof,
    _issue_verified_export_receipt, _issue_verified_receipt, archive_manifest,
    canonical, witness_value)

ROOT=Path(__file__).resolve().parents[2]

class EventOutboxV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.path=self.root/'state.db';self.witness=self.root/'witness.json'
        self.box=EventOutboxV2(self.path,initialize=True,owner_epoch='boot',witness_path=self.witness)
        self.witness.write_bytes(canonical(self.box.retention_state()))
        self.events=[{'tsEpoch':1,'message':'synthetic-observation'}]
    def tearDown(self):
        self.box.close();self.tmp.cleanup()
    def recorded(self,**kwargs):
        handle=self.box.begin_generation(kwargs.get('producer','p'),self.box.owner_epoch)
        self.box.record_batch(handle,self.events,expected_count=1,batch_digest=self.box.batch_digest(self.events))
        return handle
    def export(self):
        target=self.root/'events.jsonl'
        if not target.exists():target.write_bytes(b'')
        batch=self.box.prepare_export_batch();info=target.stat()
        intent=self.box.bind_export(batch,'stream',target,info.st_dev,info.st_ino,info.st_size)
        with target.open('ab') as out:out.write(intent.content);out.flush();os.fsync(out.fileno())
        receipt=_issue_verified_export_receipt(intent)
        self.box.confirm_export(receipt)
        return intent,receipt
    def archive(self,handle):
        self.box.seal_generation(handle);self.export()
        request=self.box.prepare_archive(handle.producer,handle.ordinal,witness_path=self.witness)
        segment=self.root/(request.request_digest+'.segment');manifest=self.root/(request.request_digest+'.manifest')
        segment.write_bytes(request.content);manifest.write_bytes(archive_manifest(request,segment))
        receipt=_issue_verified_receipt(request,segment,manifest)
        self.witness.write_bytes(canonical(witness_value(request)))
        self.box.retire(receipt,witness_path=self.witness)
        return request,receipt

    def test_owned_batch_encodes_once_and_keeps_exact_evidence(self):
        events = [{'tsEpoch': 1, 'message': '猫\nquoted " text', 'nested': [1, None]}]
        expected = self.box._encode_events(events)
        handle = self.box.begin_generation('p', 'boot')
        with mock.patch.object(self.box, '_encode_events', wraps=self.box._encode_events) as encode:
            receipt = self.box._record_owned_batch(handle, events)
            self.assertEqual(encode.call_count, 1)
        self.assertEqual(receipt, {'duplicate': False, 'count': 1, 'ordinal': handle.ordinal})
        row = self.box.connection.execute('SELECT payload_digest,line,line_digest FROM event_v2_rows').fetchone()
        self.assertEqual(tuple(row), expected[0])
        stored = self.box.connection.execute('SELECT batch_digest FROM event_v2_generations').fetchone()[0]
        self.assertEqual(stored, self.box.batch_digest(events))
        self.box.seal_generation(handle)
        self.assertTrue(self.box._record_owned_batch(handle, events)['duplicate'])
        events[0]['message'] = 'changed'
        with self.assertRaisesRegex(EventOutboxError, 'v2-generation-batch-conflict'):
            self.box._record_owned_batch(handle, events)
        self.assertEqual(tuple(self.box.connection.execute('SELECT payload_digest,line,line_digest FROM event_v2_rows').fetchone()), expected[0])

    def test_owned_batch_rejects_invalid_events_without_recording(self):
        handle = self.box.begin_generation('p', 'boot')
        for events in ([{'tsEpoch': True}], [{'tsEpoch': 1, 'value': float('nan')}],
                       [{'tsEpoch': 1, 'message': 'x' * (self.box.max_payload_bytes + 1)}]):
            with self.assertRaises(EventOutboxError):
                self.box._record_owned_batch(handle, events)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0], 0)
        self.assertIsNone(self.box.connection.execute('SELECT expected_count FROM event_v2_generations').fetchone()[0])
        for bad_digest in (None, '', '0' * 64, ()):
            with self.assertRaisesRegex(EventOutboxError, 'v2-batch-digest-conflict'):
                self.box.record_batch(handle, self.events, expected_count=1, batch_digest=bad_digest)

    def test_mandatory_handle_and_atomic_batch_digest(self):
        handle=self.box.begin_generation('p','boot')
        with self.assertRaisesRegex(EventOutboxError,'v2-generation-handle-invalid'):
            self.box.record_batch(dataclasses.asdict(handle),self.events,expected_count=1,
                                  batch_digest=self.box.batch_digest(self.events))
        with self.assertRaisesRegex(EventOutboxError,'v2-batch-digest-conflict'):
            self.box.record_batch(handle,self.events,expected_count=1,batch_digest='0'*64)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],0)
        self.assertIsNone(self.box.connection.execute('SELECT expected_count FROM event_v2_generations').fetchone()[0])

    def test_sealed_retry_is_same_identity_existing_only(self):
        handle=self.recorded();self.box.seal_generation(handle)
        self.assertTrue(self.box.record_batch(handle,self.events,expected_count=1,
                           batch_digest=self.box.batch_digest(self.events))['duplicate'])
        changed=[{'tsEpoch':1,'message':'different'}]
        with self.assertRaisesRegex(EventOutboxError,'v2-generation-batch-conflict'):
            self.box.record_batch(handle,changed,expected_count=1,batch_digest=self.box.batch_digest(changed))
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],1)

    def test_hot_budget_failure_preserves_generation_and_existing_rows(self):
        self.recorded();self.box.max_hot_records=1
        other=self.box.begin_generation('p','boot')
        with self.assertRaisesRegex(EventOutboxError,'v2-hot-budget'):
            self.box.record_batch(other,self.events,expected_count=1,batch_digest=self.box.batch_digest(self.events))
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],1)
        self.assertIsNone(self.box.connection.execute('SELECT expected_count FROM event_v2_generations WHERE ordinal=2').fetchone()[0])

    def test_file_export_proof_cannot_clear_unknown(self):
        self.recorded();target=self.root/'events.jsonl';target.write_bytes(b'')
        batch=self.box.prepare_export_batch();info=target.stat()
        intent=self.box.bind_export(batch,'stream',target,info.st_dev,info.st_ino,0)
        target.write_bytes(intent.content[:2])
        with self.assertRaises(EventOutboxError):_issue_verified_export_receipt(intent)
        self.box.mark_export_unknown(intent,'stream-export-failed')
        target.write_bytes(intent.content)
        receipt=_issue_verified_export_receipt(intent)
        with self.assertRaisesRegex(EventOutboxError,'v2-export-unknown-reconciliation-required'):
            self.box.confirm_export(receipt)
        self.assertEqual(self.box.pending_export_intents()[0].state,'unknown')
        self.assertFalse(self.box.stream_rotation_allowed('stream'))

    def test_untrusted_receipt_and_late_error_do_not_downgrade_committed_export(self):
        self.recorded();intent,receipt=self.export()
        with self.assertRaisesRegex(EventOutboxError,'export-receipt-required'):
            self.box.confirm_export({'success':True})
        self.box.mark_export_unknown(intent,'stream-export-failed')
        self.assertEqual(self.box.pending_export_intents(),[])
        self.assertEqual(self.box.connection.execute('SELECT state FROM event_v2_rows').fetchone()[0],'exported')

    def test_archive_requires_closed_generation_and_durable_export(self):
        handle=self.recorded()
        with self.assertRaisesRegex(EventOutboxError,'v2-generation-not-closed'):
            self.box.prepare_archive('p',handle.ordinal)
        self.box.seal_generation(handle)
        with self.assertRaisesRegex(EventOutboxError,'v2-events-not-exported'):
            self.box.prepare_archive('p',handle.ordinal)
        with self.assertRaisesRegex(EventOutboxError,'archive-receipt-required'):
            self.box.retire({'durable':True},witness_path=self.witness)
        self.assertEqual(self.box.connection.execute('SELECT retired FROM event_v2_producers').fetchone()[0],0)

    def test_retired_handle_rejects_forever_and_new_observation_mints_new_uuid(self):
        handle=self.recorded();request,_=self.archive(handle)
        self.assertEqual(self.box.connection.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],0)
        with self.assertRaisesRegex(EventOutboxError,'v2-generation-retired'):
            self.box.record_batch(handle,self.events,expected_count=1,batch_digest=self.box.batch_digest(self.events))
        another=self.recorded()
        self.assertEqual(another.ordinal,2);self.assertNotEqual(handle.generation_uuid,another.generation_uuid)
        forged=dataclasses.replace(handle,ordinal=another.ordinal)
        with self.assertRaisesRegex(EventOutboxError,'v2-generation-unregistered'):
            self.box.record_batch(forged,self.events,expected_count=1,batch_digest=self.box.batch_digest(self.events))
        with self.assertRaisesRegex(EventOutboxError,'v2-prune-latest-prohibited'):
            self.box.ack_pruned([request.request_digest])

    def test_catalog_compaction_waits_for_deleted_files_and_preserves_watermark(self):
        first=self.recorded();request,receipt=self.archive(first)
        second=self.recorded();self.archive(second)
        with self.assertRaisesRegex(EventOutboxError,'v2-prune-files-not-removed'):
            self.box.ack_pruned([request.request_digest])
        Path(receipt.segment_path).unlink();Path(receipt.manifest_path).unlink()
        self.box.ack_pruned([request.request_digest]);self.box.ack_pruned([request.request_digest])
        self.assertEqual(len(self.box.prunable_archive_requests()),1)
        self.assertEqual(self.box.retention_state()['frontiers'],{'p':2})
        with self.assertRaisesRegex(EventOutboxError,'v2-generation-retired'):
            self.box.record_batch(first,self.events,expected_count=1,batch_digest=self.box.batch_digest(self.events))

    def test_older_db_and_newer_witness_block_writer_before_new_records(self):
        backup=self.root/'before.db'
        with sqlite3.connect(backup) as destination:self.box.connection.backup(destination)
        handle=self.recorded();self.archive(handle);self.box.close()
        with self.assertRaisesRegex(EventOutboxError,'v2-restore-frontier-drift'):
            EventOutboxV2(backup,witness_path=self.witness)
        with sqlite3.connect(backup) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],0)
            self.assertEqual(conn.execute('SELECT retirement_seq FROM event_v2_meta').fetchone()[0],0)

    def test_borrowed_transaction_and_replaced_path_never_mutate_wrong_database(self):
        self.box.close()
        conn=sqlite3.connect(self.path)
        conn.execute('PRAGMA synchronous=FULL');identity=(self.path.stat().st_dev,self.path.stat().st_ino)
        conn.execute('BEGIN')
        with self.assertRaisesRegex(EventOutboxError,'v2-caller-transaction-active'):
            EventOutboxV2(self.path,connection=conn,connection_identity=identity)
        self.assertTrue(conn.in_transaction);conn.rollback()
        conn.execute('PRAGMA journal_mode=DELETE')
        other=self.root/'replacement.db'
        with sqlite3.connect(other) as replacement:replacement.execute('CREATE TABLE sentinel(v TEXT)')
        os.replace(other,self.path);before=self.path.read_bytes()
        with self.assertRaisesRegex(EventOutboxError,'v2-store-identity-changed'):
            EventOutboxV2(self.path,connection=conn,connection_identity=identity)
        self.assertEqual(before,self.path.read_bytes());conn.close()

    def test_current_v1_rejects_v2_marker_and_legacy_history_requires_migration(self):
        self.box.close()
        with self.assertRaises(EventOutboxError):EventOutbox(self.path)
        legacy=self.root/'legacy.db'
        with EventOutbox(legacy) as old:
            old.record({'tsEpoch':1},producer='old',generation='old',attempt=0,seq=0)
        with self.assertRaises(EventOutboxError):EventOutboxV2(legacy,initialize=True)
        with sqlite3.connect(legacy) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM events').fetchone()[0],1)
            self.assertEqual(conn.execute('SELECT version FROM stability_event_outbox_version').fetchone()[0],1)

    def test_core_writer_lock_cannot_be_replaced_by_unrelated_proof_or_other_writer(self):
        handle=self.recorded()
        with self.assertRaises(EventOutboxError):EventOutboxV2(self.path,owner_epoch='other')
        alternate=self.root/'unrelated-lock'
        with self.assertRaisesRegex(EventOutboxError,'v2-writer-lock-path-invalid'):
            EventOutboxV2(self.path,owner_epoch='other',writer_lock_path=alternate)
        self.assertFalse(alternate.exists())
        with self.assertRaisesRegex(EventOutboxError,'v2-prior-owner-still-current'):
            self.box.owner_ended_proof(handle)
        forged=OwnerEndedProof(self.box.store_id,'boot','other',(1,1),object())
        with self.assertRaisesRegex(EventOutboxError,'v2-writer-proof-required'):
            self.box.close_interrupted_generation(handle,forged)
        self.assertEqual(self.box.connection.execute('SELECT state FROM event_v2_generations').fetchone()[0],'open')

    def test_real_crash_restores_committed_batch_and_marks_only_observation_interrupted(self):
        self.box.close()
        code="""import os,sys
from stability_core.event_outbox_v2 import EventOutboxV2
with EventOutboxV2(sys.argv[1],owner_epoch='old') as box:
 h=box.begin_generation('p','old');events=[{'tsEpoch':1,'message':'crash'}]
 box.record_batch(h,events,expected_count=1,batch_digest=box.batch_digest(events))
 os._exit(73)
"""
        child=subprocess.run([sys.executable,'-c',code,str(self.path)],cwd=ROOT,capture_output=True,timeout=10)
        self.assertEqual(child.returncode,73,child.stderr)
        self.box=EventOutboxV2(self.path,owner_epoch='new')
        handle=self.box.load_generation('p',1,'old')
        result=self.box.close_interrupted_generation(handle,self.box.owner_ended_proof(handle))
        self.assertFalse(result['observationsComplete']);self.assertEqual(result['committedCount'],1)
        self.assertEqual(self.box.connection.execute('SELECT state FROM event_v2_rows').fetchone()[0],'pending')
        self.export()
        request=self.box.prepare_archive('p',1)
        self.assertFalse(json.loads(request.content)['generations'][0]['observationsComplete'])

    def test_retirement_does_not_clear_action_ledger_executing_or_uncertain(self):
        self.box.close()
        with ActionLedger(self.path) as ledger:
            record=ledger.plan_action(idempotency_key='intent',action_type='fixture',target='fixture',generation='boot',
                input_data={},authorization_ref='auth://fixture',policy_ref='policy://fixture',evidence_refs=('evidence://fixture',))
            ledger.begin_execution(record.action_id,expected_version=record.version)
        self.box=EventOutboxV2(self.path,owner_epoch='boot',witness_path=self.witness)
        before=self.box.connection.execute('SELECT * FROM action_ledger').fetchall()
        self.archive(self.recorded())
        self.assertEqual(before,self.box.connection.execute('SELECT * FROM action_ledger').fetchall())

    def test_witness_omission_uses_persisted_path_and_cannot_remint_after_restore(self):
        backup=self.root/'zero-before.db'
        with sqlite3.connect(backup) as destination:self.box.connection.backup(destination)
        handle=self.recorded();self.archive(handle);self.box.close()
        with self.assertRaisesRegex(EventOutboxError,'v2-restore-frontier-drift'):
            EventOutboxV2(backup,witness_path=None)
        with self.assertRaisesRegex(EventOutboxError,'v2-witness-path-conflict'):
            EventOutboxV2(backup,witness_path=self.root/'fake-witness.json')
        with sqlite3.connect(backup) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM event_v2_producers').fetchone()[0],0)

    def test_bootstrap_is_only_new_schema_context_and_never_a_writer_grant(self):
        virgin=self.root/'virgin.db'
        with EventOutboxV2(virgin,initialize=True,owner_epoch='virgin') as fresh:
            state=fresh.retention_state()
            self.assertEqual(state['retirementSeq'],0)
            with self.assertRaisesRegex(EventOutboxError,'v2-witness-required'):
                fresh.begin_generation('p','virgin')
        # Reopening an existing zero-state DB cannot reset/bootstrap a missing witness.
        with self.assertRaisesRegex(EventOutboxError,'v2-witness-required'):
            EventOutboxV2(virgin,initialize=True)
        fresh_witness=self.witness
        self.box.close();fresh_witness.unlink()
        with self.assertRaisesRegex(EventOutboxError,'v2-witness-required'):
            EventOutboxV2(self.path)

    def test_hardlink_alias_cannot_create_second_owner_or_mutate_first(self):
        handle=self.recorded()
        alias=self.root/'alias.db';os.link(self.path,alias)
        with self.assertRaisesRegex(EventOutboxError,'v2-store-identity-changed'):
            EventOutboxV2(alias,owner_epoch='second')
        with self.assertRaisesRegex(EventOutboxError,'v2-store-identity-changed'):
            self.box.begin_generation('p','boot')
        with self.assertRaisesRegex(EventOutboxError,'v2-store-identity-changed'):
            self.box.owner_ended_proof(handle)
        self.assertEqual(self.box.connection.execute('SELECT state FROM event_v2_generations').fetchone()[0],'open')
        alias.unlink()
        self.assertEqual(self.box.begin_generation('p','boot').ordinal,2)

    def test_stream_target_pin_survives_hot_retirement_and_cli_history_cannot_split(self):
        handle=self.recorded();request,_=self.archive(handle)
        event=json.loads(request.content)['events'][0]
        self.assertEqual(Path(event['target']), (self.root/'events.jsonl').resolve())
        with self.assertRaisesRegex(EventOutboxError,'v2-stream-target-conflict'):
            self.box.validate_stream_binding('stream',self.root/'different.jsonl')
        with self.assertRaisesRegex(EventOutboxError,'v2-stream-target-conflict'):
            self.box.validate_stream_binding('different-stream',self.root/'events.jsonl')
        self.assertTrue(self.box.validate_stream_binding('stream',self.root/'events.jsonl')['bound'])

    def test_real_witness_ahead_crash_has_only_event_reconciliation_capability(self):
        # Fresh observation schema shares an actual durable uncertain action
        # sentinel, but neither initialization nor event repair qualifies it.
        self.box.close()
        crash_state=self.root/'crash-state.db'
        with ActionLedger(crash_state) as ledger:
            action=ledger.plan_action(idempotency_key='uncertain-sentinel',action_type='fixture',target='fixture',
                generation='old',input_data={},authorization_ref='auth://fixture',policy_ref='policy://fixture',
                evidence_refs=('evidence://fixture',))
            action=ledger.begin_execution(action.action_id,expected_version=action.version)
            ledger.transition(action.action_id,expected_state='executing',expected_version=action.version,
                              new_state='uncertain')
        from stability_core.event_stream_v2 import ArchivePublisher
        publisher=ArchivePublisher(self.root/'durable-archive')
        with EventOutboxV2(crash_state,initialize=True,witness_path=publisher.witness_path) as initial:
            publisher.initialize_witness(initial.retention_state())
        code="""import os,sys
from pathlib import Path
from stability_core.event_outbox_v2 import EventOutboxV2
from stability_core.event_stream_v2 import ArchivePublisher,EventStream
+p=ArchivePublisher(Path(sys.argv[1]).parent/'durable-archive')
+with EventOutboxV2(sys.argv[1],owner_epoch='child') as c:
+ h=c.begin_generation('p','child');events=[{'tsEpoch':1,'message':'after-witness-crash'}]
+ c.record_batch(h,events,expected_count=1,batch_digest=c.batch_digest(events));c.seal_generation(h)
+ EventStream(Path(sys.argv[1]).parent/'events.jsonl',stream_id='stream').drain(c)
+ r=c.prepare_archive('p',1);p.publish(r);p.advance_witness(r)
+ os._exit(73)
+""".replace('\n+','\n')
        child=subprocess.run([sys.executable,'-c',code,str(crash_state)],cwd=ROOT,
                             capture_output=True,timeout=20)
        self.assertEqual(child.returncode,73,child.stderr)
        with self.assertRaisesRegex(EventOutboxError,'v2-restore-frontier-drift'):
            EventOutboxV2(crash_state)
        exported_before=(self.root/'events.jsonl').read_bytes()
        self.box=EventOutboxV2(crash_state,owner_epoch='recover',recovery_open=True)
        sentinel=self.box.connection.execute('SELECT * FROM action_ledger').fetchall()
        for operation in (lambda:self.box.begin_generation('p','recover'),
                          lambda:self.box.prepare_export_batch(),
                          lambda:self.box.prunable_archive_requests(),
                          lambda:self.box.ack_pruned([])):
            with self.assertRaisesRegex(EventOutboxError,'v2-recovery-only'):operation()
        request=self.box.recovery_archive_request()
        with self.assertRaisesRegex(EventOutboxError,'archive-receipt-required'):
            self.box.retire(dataclasses.asdict(request))
        receipt=publisher.load_receipt(request)
        result=self.box.retire(receipt)
        self.assertEqual(result['scope'],'local-event-retention')
        self.assertEqual(result['actionRecoveryQualification'],'separate-required')
        self.assertFalse(result['actionStateChanged'])
        self.assertEqual(sentinel,self.box.connection.execute('SELECT * FROM action_ledger').fetchall())
        self.assertEqual(exported_before,(self.root/'events.jsonl').read_bytes())
        self.assertEqual(self.box.begin_generation('p','recover').ordinal,2)

    def test_recovery_does_not_open_for_ahead_more_than_one_or_corrupt_chain(self):
        handle=self.recorded();self.box.seal_generation(handle);self.export()
        request=self.box.prepare_archive('p',1)
        value=witness_value(request);value['retirementSeq']=2
        self.witness.write_bytes(canonical(value));self.box.close()
        with self.assertRaisesRegex(EventOutboxError,'v2-recovery-witness-invalid'):
            EventOutboxV2(self.path,recovery_open=True)
        value['retirementSeq']=1;value['chain']='0'*64
        self.witness.write_bytes(canonical(value))
        with self.assertRaisesRegex(EventOutboxError,'v2-recovery-request-conflict'):
            EventOutboxV2(self.path,recovery_open=True)

    def test_borrowed_row_factory_preserved_through_sealed_retry_export_archive_and_catalog(self):
        from stability_core.event_stream_v2 import ArchivePublisher,EventStream
        path=self.root/'row-store.db'
        publisher=ArchivePublisher(self.root/'row-archive')
        conn=sqlite3.connect(path)
        try:
            conn.execute('PRAGMA journal_mode=WAL');conn.execute('PRAGMA synchronous=FULL')
            conn.row_factory=sqlite3.Row
            identity=(path.stat().st_dev,path.stat().st_ino)
            with EventOutboxV2(path,initialize=True,connection=conn,connection_identity=identity,
                    witness_path=publisher.witness_path,owner_epoch='row-owner') as core:
                publisher.initialize_witness(core.retention_state())
                handle=core.begin_generation('p','row-owner')
                payload_digest=core.batch_digest(self.events)
                self.assertFalse(core.record_batch(handle,self.events,expected_count=1,
                                                  batch_digest=payload_digest)['duplicate'])
                core.seal_generation(handle)
                self.assertTrue(core.record_batch(handle,self.events,expected_count=1,
                                                 batch_digest=payload_digest)['duplicate'])
                stream=EventStream(self.root/'row-events.jsonl')
                stream.drain(core)
                request=core.prepare_archive('p',1,witness_path=publisher.witness_path)
                self.assertIs(type(json.loads(request.content)['events'][0]),dict)
                receipt=publisher.publish(request);publisher.advance_witness(request)
                result=core.retire(receipt)
                self.assertIs(type(result),dict)
                state=core.retention_state();catalog=core.prunable_archive_requests()
                self.assertIs(type(state),dict);self.assertIs(type(state['frontiers']),dict)
                self.assertEqual(state['frontiers'],{'p':1})
                self.assertIs(type(catalog[request.request_digest]),dict)
                self.assertIs(type(catalog[request.request_digest]['retirement_seq']),int)
                json.dumps({'state':state,'catalog':catalog,'result':result})
                # Latest receipt is pinned irrespective of caller row factory.
                with self.assertRaisesRegex(EventOutboxError,'v2-prune-latest-prohibited'):
                    core.ack_pruned([request.request_digest])
                self.assertIs(conn.row_factory,sqlite3.Row)
                self.assertEqual(conn.execute('PRAGMA journal_mode').fetchone()[0],'wal')
                self.assertEqual(conn.execute('PRAGMA synchronous').fetchone()[0],2)
            # Borrowed close must leave caller handle and its factory alive.
            self.assertIs(conn.row_factory,sqlite3.Row)
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],0)
        finally:conn.close()

    def test_borrowed_row_factory_recovery_only_rebuilds_actual_plain_frames(self):
        from stability_core.event_stream_v2 import ArchivePublisher,EventStream
        path=self.root/'row-recovery.db';publisher=ArchivePublisher(self.root/'row-recovery-archive')
        conn=sqlite3.connect(path)
        try:
            conn.execute('PRAGMA journal_mode=WAL');conn.execute('PRAGMA synchronous=FULL')
            conn.row_factory=sqlite3.Row;identity=(path.stat().st_dev,path.stat().st_ino)
            with EventOutboxV2(path,initialize=True,connection=conn,connection_identity=identity,
                    witness_path=publisher.witness_path,owner_epoch='old-row') as core:
                publisher.initialize_witness(core.retention_state())
                handle=core.begin_generation('p','old-row')
                core.record_batch(handle,self.events,expected_count=1,batch_digest=core.batch_digest(self.events))
                core.seal_generation(handle);EventStream(self.root/'row-recovery-events.jsonl').drain(core)
                request=core.prepare_archive('p',1)
                publisher.publish(request);publisher.advance_witness(request)
            with EventOutboxV2(path,connection=conn,connection_identity=identity,recovery_open=True,
                    owner_epoch='new-row') as recovery:
                restored=recovery.recovery_archive_request()
                self.assertEqual(restored,request)
                result=recovery.retire(publisher.load_receipt(restored))
                self.assertEqual(result['actionRecoveryQualification'],'separate-required')
                self.assertIs(type(result),dict);json.dumps(result)
                self.assertIs(conn.row_factory,sqlite3.Row)
                self.assertEqual(recovery.begin_generation('p','new-row').ordinal,2)
            self.assertFalse(conn.in_transaction)
            self.assertIs(conn.row_factory,sqlite3.Row)
        finally:conn.close()

if __name__=='__main__':unittest.main()
