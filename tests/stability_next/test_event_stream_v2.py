import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from stability_core.event_stream_v2 import EventStream, EventStreamError


def line(n):return json.dumps({'tsEpoch':n,'message':'synthetic','seq':n}).encode()+b'\n'


class EventStreamFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.target=self.root/'events.jsonl'
    def tearDown(self):self.tmp.cleanup()
    def test_rotation_preserves_exact_latest50_continuously(self):
        stream=EventStream(self.target,max_active_bytes=6000)
        rotations=0
        for n in range(4200):
            def hook(stage):
                nonlocal rotations
                if stage=='rotation-receipt':rotations+=1
            with stream.locked():
                stream._make_room(line(n),hook=hook)
                with self.target.open('ab') as out:out.write(line(n));out.flush();os.fsync(out.fileno())
        self.assertGreater(rotations,0)
        self.assertEqual([row['seq'] for row in stream.latest()],list(range(4150,4200)))
        self.assertLessEqual(self.target.stat().st_size,6000)
        self.assertFalse(stream.marker.exists())
        self.assertEqual(len(list(self.root.glob('.stability-v2-rotation-*'))),0)
    def test_real_crash_rotation_intent_recovers_without_losing_latest(self):
        self.target.write_bytes(b''.join(line(n) for n in range(100)))
        code="""import os,sys
from stability_core.event_stream_v2 import EventStream
s=EventStream(sys.argv[1],max_active_bytes=6000)
def crash(stage):
 if stage=='rotation-intent':os._exit(73)
with s.locked():s._make_room(b'{"tsEpoch":101,"message":"'+b'x'*2000+b'"}\\n',hook=crash)
"""
        proc=subprocess.run([sys.executable,'-c',code,str(self.target)],cwd=Path(__file__).resolve().parents[2],capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,73,proc.stderr)
        stream=EventStream(self.target,max_active_bytes=6000)
        self.assertTrue(stream.marker.exists())
        with stream.locked():stream._recover_rotation()
        self.assertEqual([r['seq'] for r in stream.latest()],list(range(50,100)))
        self.assertFalse(stream.marker.exists())
    def test_partial_target_and_too_large_tail_fail_closed(self):
        stream=EventStream(self.target,max_active_bytes=200)
        self.target.write_bytes(b'{')
        with self.assertRaisesRegex(EventStreamError,'stream-partial-tail'):
            with stream.locked():stream._make_room(line(1))
        self.target.write_bytes(line(1)*3)
        with self.assertRaisesRegex(EventStreamError,'stream-active-budget'):
            with stream.locked():stream._make_room(line(2)*2)
        self.assertEqual(self.target.read_bytes(),line(1)*3)
    def test_symlink_lock_target_and_rotation_conflict_are_not_followed(self):
        other=self.root/'other';other.write_bytes(b'synthetic')
        self.target.symlink_to(other)
        with self.assertRaisesRegex(EventStreamError,'stream-target-invalid'):
            EventStream(self.target)
        self.assertEqual(other.read_bytes(),b'synthetic')
    def test_current_file_latest_is_chronological_and_bounded(self):
        self.target.write_bytes(b''.join(line(n) for n in range(70)))
        stream=EventStream(self.target)
        self.assertEqual([r['seq'] for r in stream.latest()],list(range(20,70)))
        with self.assertRaisesRegex(EventStreamError,'invalid-latest-limit'):stream.latest(51)



class ArchivePublisherFilesystemTests(unittest.TestCase):
    def setUp(self):
        from stability_core.event_stream_v2 import ArchivePublisher
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)/'archives'
        self.publisher=ArchivePublisher(self.root,max_files=12,max_bytes=1048576)
        self.state={'version':2,'storeId':'store-fixture','retirementSeq':0,'chain':'0'*64,'frontiers':{}}
        self.publisher.initialize_witness(self.state)
    def tearDown(self):self.tmp.cleanup()
    def request(self,n):
        import hashlib
        from stability_core.event_v2_contract import ArchiveRequest
        content=json.dumps({'synthetic':n}).encode()
        return ArchiveRequest('store-fixture','p',n-1,n,self.state['chain'],n-1,(('p',n),),content,
            hashlib.sha256(content).hexdigest(),hashlib.sha256(('request-'+str(n)).encode()).hexdigest(),1)
    def test_durable_publish_and_monotonic_witness(self):
        from stability_core.event_v2_contract import _verify_archive_receipt,witness_value
        req=self.request(1);receipt=self.publisher.publish(req)
        self.assertEqual(_verify_archive_receipt(receipt).request,req)
        self.publisher.advance_witness(req)
        self.assertEqual(self.publisher.read_witness(),witness_value(req))
        self.assertEqual(self.publisher.load_receipt(req).request,req)
        self.assertEqual(self.publisher.advance_witness(req),self.publisher.witness_path)
        self.state=witness_value(req)
        req2=self.request(2);self.publisher.publish(req2);self.publisher.advance_witness(req2)
        with self.assertRaisesRegex(EventStreamError,'witness-request-conflict'):
            self.publisher.advance_witness(req)
        with self.assertRaisesRegex(EventStreamError,'witness-recovery-request-conflict'):
            self.publisher.load_receipt(req)
    def test_archive_quota_and_corruption_never_issue_receipt(self):
        from stability_core.event_stream_v2 import ArchivePublisher
        small=ArchivePublisher(self.root,max_files=3,max_bytes=1048576)
        with self.assertRaisesRegex(EventStreamError,'archive-capacity-exhausted'):small.publish(self.request(1))
        req=self.request(1);receipt=self.publisher.publish(req)
        Path(receipt.segment_path).write_bytes(b'corrupt')
        with self.assertRaisesRegex(EventStreamError,'archive-immutable-conflict'):self.publisher.publish(req)
    def test_mismatched_database_and_pins_block_pruning(self):
        class Core:
            def retention_state(inner):return self.state
        req=self.request(1);self.publisher.publish(req);self.publisher.advance_witness(req)
        with self.assertRaisesRegex(EventStreamError,'witness-database-conflict'):
            self.publisher.prune_committed(Core())
        self.assertEqual(len(list(self.root.glob('segment-*.json'))),1)
    def test_pins_unregistered_archives_and_bounded_catalog_pruning(self):
        from stability_core.event_v2_contract import witness_value
        catalog={};state=self.state
        class Core:
            def retention_state(inner):return state
            def prunable_archive_requests(inner):return dict(catalog)
            def ack_pruned(inner,digests):
                for digest in digests:
                    entry=catalog.get(digest)
                    if entry:
                        self.assertFalse(Path(entry['segment']).exists())
                        self.assertFalse(Path(entry['manifest']).exists())
                        del catalog[digest]
        core=Core();first=None
        for n in range(1,100):
            self.state=state
            req=self.request(n);receipt=self.publisher.publish(req)
            self.publisher.advance_witness(req);state=witness_value(req)
            catalog[req.request_digest]={'chain':req.chain,'retirement_seq':n,
                'segment':receipt.segment_path,'manifest':receipt.manifest_path,
                'content_digest':req.content_digest,'producer':'p','through_ordinal':n}
            if n==1:first=req.request_digest
            self.publisher.prune_committed(core,pinned_request_digests=(first,))
            self.assertLessEqual(len(catalog),2)
            self.assertLessEqual(len(list(self.root.iterdir())),6)
        self.assertIn(first,catalog)
        self.publisher.prune_committed(core)
        self.assertEqual(len(catalog),1)

    def test_prune_crash_after_files_before_ack_recovers_exactly(self):
        from stability_core.event_v2_contract import witness_value
        catalog={};state=self.state
        class Core:
            def retention_state(inner):return state
            def prunable_archive_requests(inner):return dict(catalog)
            def ack_pruned(inner,digests):
                for digest in digests:catalog.pop(digest,None)
        for n in (1,2):
            self.state=state;req=self.request(n);receipt=self.publisher.publish(req)
            self.publisher.advance_witness(req);state=witness_value(req)
            catalog[req.request_digest]={'chain':req.chain,'retirement_seq':n,
                'segment':receipt.segment_path,'manifest':receipt.manifest_path,
                'content_digest':req.content_digest,'producer':'p','through_ordinal':n}
        def crash(stage):
            if stage=='prune-files':raise RuntimeError('synthetic')
        with self.assertRaisesRegex(EventStreamError,'archive-prune-failed'):
            self.publisher.prune_committed(Core(),hook=crash)
        self.assertTrue(self.publisher.prune_marker.exists())
        self.assertEqual(len(catalog),2)
        self.publisher.prune_committed(Core())
        self.assertFalse(self.publisher.prune_marker.exists())
        self.assertEqual(len(catalog),1)

    def test_real_crash_witness_temp_old_witness_remains_recoverable(self):
        req=self.request(1);self.publisher.publish(req)
        import dataclasses
        code="""import json,os,sys
from stability_core.event_stream_v2 import ArchivePublisher
from stability_core.event_v2_contract import ArchiveRequest
p=ArchivePublisher(sys.argv[1],max_files=12,max_bytes=1048576)
d=json.loads(sys.argv[2]);d['content']=d['content'].encode();d['frontiers']=tuple(tuple(x) for x in d['frontiers'])
r=ArchiveRequest(**d)
def crash(stage):
 if stage=='witness-temp':os._exit(73)
p.advance_witness(r,hook=crash)
"""
        data=dataclasses.asdict(req);data['content']=req.content.decode()
        result=subprocess.run([sys.executable,'-c',code,str(self.root),json.dumps(data)],cwd=Path(__file__).resolve().parents[2],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,73,result.stderr)
        self.assertEqual(self.publisher.read_witness(),self.state)
        self.publisher.advance_witness(req)
        self.assertEqual(self.publisher.read_witness()['retirementSeq'],1)



class EventStreamCoreIntegrationTests(unittest.TestCase):
    def test_more_than4096_events_export_retire_and_prune_with_bounded_state(self):
        from stability_core.event_outbox_v2 import EventOutboxV2
        from stability_core.event_stream_v2 import ArchivePublisher
        from stability_core.event_outbox import EventOutboxError
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);publisher=ArchivePublisher(root/'archive',max_files=12,max_bytes=1048576)
            stream=EventStream(root/'events.jsonl',max_active_bytes=12000)
            with EventOutboxV2(root/'events.db',initialize=True,witness_path=publisher.witness_path,
                               max_hot_records=100,max_generations=4,max_receipts=4) as core:
                publisher.initialize_witness(core.retention_state())
                core.connection.execute('CREATE TABLE action_ledger (fixture TEXT)')
                core.connection.execute("INSERT INTO action_ledger VALUES('untouched')")
                first=None
                for start in range(0,4200,50):
                    events=[{'tsEpoch':n,'message':'synthetic','seq':n} for n in range(start,start+50)]
                    handle=core.begin_generation('p',core.owner_epoch)
                    if first is None:first=handle
                    core.record_batch(handle,events,expected_count=50,batch_digest=core.batch_digest(events))
                    core.seal_generation(handle)
                    self.assertEqual(stream.drain(core)['exportedBatches'],1)
                    request=core.prepare_archive('p',handle.ordinal,max_records=50,max_bytes=65536,witness_path=publisher.witness_path)
                    receipt=publisher.publish(request)
                    publisher.advance_witness(request)
                    core.retire(receipt,witness_path=publisher.witness_path)
                    publisher.prune_committed(core)
                    self.assertEqual(core.connection.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],0)
                    self.assertEqual(core.connection.execute('SELECT COUNT(*) FROM event_v2_generations').fetchone()[0],0)
                    self.assertEqual(core.connection.execute('SELECT COUNT(*) FROM event_v2_receipts').fetchone()[0],1)
                    self.assertLessEqual(stream.target.stat().st_size,12000)
                    self.assertLessEqual(len(list(publisher.root.iterdir())),4)
                self.assertEqual([r['seq'] for r in stream.latest()],list(range(4150,4200)))
                self.assertEqual(core.connection.execute('SELECT fixture FROM action_ledger').fetchall(),[('untouched',)])
                with self.assertRaisesRegex(EventOutboxError,'v2-generation-retired'):
                    core.load_generation('p',first.ordinal,first.owner_epoch)
                self.assertEqual(core.retention_state(),publisher.read_witness())

    def test_full_file_unknown_is_not_automatically_healed_or_reappended(self):
        from stability_core.event_outbox_v2 import EventOutboxV2
        from stability_core.event_outbox import EventOutboxError
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);stream=EventStream(root/'events.jsonl')
            from stability_core.event_stream_v2 import ArchivePublisher
            publisher=ArchivePublisher(root/'archive')
            with EventOutboxV2(root/'events.db',initialize=True,witness_path=publisher.witness_path) as core:
                publisher.initialize_witness(core.retention_state())
                events=[{'tsEpoch':1,'message':'synthetic'}]
                handle=core.begin_generation('p',core.owner_epoch)
                core.record_batch(handle,events,expected_count=1,batch_digest=core.batch_digest(events))
                core.seal_generation(handle)
                def fail(stage):
                    if stage=='before-export-receipt':raise RuntimeError('synthetic')
                with self.assertRaisesRegex(EventStreamError,'stream-export-failed'):stream.drain(core,hook=fail)
                before=stream.target.read_bytes()
                self.assertEqual(core.pending_export_intents()[0].state,'unknown')
                with self.assertRaisesRegex(EventStreamError,'export-unknown-blocked'):stream.drain(core)
                self.assertEqual(stream.target.read_bytes(),before)
                with self.assertRaises(EventOutboxError):core.confirm_export(True)
                with self.assertRaisesRegex(EventOutboxError,'v2-events-not-exported'):
                    core.prepare_archive('p',handle.ordinal)

    def test_wrong_stream_does_not_poison_other_valid_export_intent(self):
        from stability_core.event_outbox_v2 import EventOutboxV2
        from stability_core.event_stream_v2 import ArchivePublisher
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);publisher=ArchivePublisher(root/'archive')
            stream=EventStream(root/'events.jsonl')
            with EventOutboxV2(root/'events.db',initialize=True,witness_path=publisher.witness_path) as core:
                publisher.initialize_witness(core.retention_state())
                events=[{'tsEpoch':1}];handle=core.begin_generation('p',core.owner_epoch)
                core.record_batch(handle,events,expected_count=1,batch_digest=core.batch_digest(events));core.seal_generation(handle)
                batch=core.prepare_export_batch()
                with stream.locked():
                    stream._make_room(batch.content)
                    info=stream.target.stat()
                    core.bind_export(batch,stream.stream_id,str(stream.target),info.st_dev,info.st_ino,info.st_size)
                with self.assertRaises(EventStreamError):
                    EventStream(root/'other.jsonl',stream_id='other').drain(core)
                self.assertEqual(core.pending_export_intents()[0].state,'exporting')
                self.assertFalse((root/'other.jsonl').exists())
                self.assertFalse((root/'other.jsonl.v2.lock').exists())
                stream.drain(core)
                self.assertEqual(stream.latest(),events)

    def test_real_process_export_crash_exactly_once_recovery(self):
        from stability_core.event_outbox_v2 import EventOutboxV2
        stages=('export-intent','append','fsync','before-export-receipt','export-receipt')
        for stage in stages:
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                from stability_core.event_stream_v2 import ArchivePublisher
                publisher=ArchivePublisher(root/'archive')
                with EventOutboxV2(root/'events.db',initialize=True,witness_path=publisher.witness_path) as core:
                    publisher.initialize_witness(core.retention_state())
                    events=[{'tsEpoch':1,'message':'synthetic'}]
                    handle=core.begin_generation('p',core.owner_epoch)
                    core.record_batch(handle,events,expected_count=1,batch_digest=core.batch_digest(events))
                    core.seal_generation(handle)
                code="""import os,sys
from stability_core.event_outbox_v2 import EventOutboxV2
from stability_core.event_stream_v2 import EventStream
from pathlib import Path
with EventOutboxV2(sys.argv[1],witness_path=Path(sys.argv[1]).parent/'archive'/'witness.json') as c:
 def crash(stage):
  if stage==sys.argv[3]:os._exit(73)
 EventStream(sys.argv[2]).drain(c,hook=crash)
"""
                proc=subprocess.run([sys.executable,'-c',code,str(root/'events.db'),str(root/'events.jsonl'),stage],cwd=Path(__file__).resolve().parents[2],capture_output=True,timeout=10)
                self.assertEqual(proc.returncode,73,proc.stderr)
                with EventOutboxV2(root/'events.db',witness_path=publisher.witness_path) as core:
                    stream=EventStream(root/'events.jsonl');stream.drain(core)
                    self.assertEqual(stream.latest(),events)
                    self.assertEqual(core.pending_export_intents(),[])
                    self.assertEqual(core.connection.execute("SELECT state FROM event_v2_rows").fetchall(),[('exported',)])


    def test_real_process_prune_files_before_sql_ack_recovers(self):
        from stability_core.event_outbox_v2 import EventOutboxV2
        from stability_core.event_stream_v2 import ArchivePublisher
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);publisher=ArchivePublisher(root/'archive');stream=EventStream(root/'events.jsonl')
            with EventOutboxV2(root/'events.db',initialize=True,witness_path=publisher.witness_path) as core:
                publisher.initialize_witness(core.retention_state())
                for n in (1,2):
                    events=[{'tsEpoch':n,'seq':n}];handle=core.begin_generation('p',core.owner_epoch)
                    core.record_batch(handle,events,expected_count=1,batch_digest=core.batch_digest(events));core.seal_generation(handle)
                    stream.drain(core)
                    request=core.prepare_archive('p',handle.ordinal,witness_path=publisher.witness_path)
                    receipt=publisher.publish(request);publisher.advance_witness(request);core.retire(receipt)
            code="""import os,sys
from stability_core.event_outbox_v2 import EventOutboxV2
from stability_core.event_stream_v2 import ArchivePublisher
p=ArchivePublisher(sys.argv[2])
with EventOutboxV2(sys.argv[1],witness_path=p.witness_path) as c:
 def crash(stage):
  if stage=='prune-files':os._exit(73)
 p.prune_committed(c,hook=crash)
"""
            result=subprocess.run([sys.executable,'-c',code,str(root/'events.db'),str(root/'archive')],cwd=Path(__file__).resolve().parents[2],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,73,result.stderr)
            self.assertTrue(publisher.prune_marker.exists())
            with EventOutboxV2(root/'events.db',witness_path=publisher.witness_path) as core:
                self.assertEqual(len(core.prunable_archive_requests()),2)
                publisher.prune_committed(core)
                self.assertEqual(len(core.prunable_archive_requests()),1)
                self.assertFalse(publisher.prune_marker.exists())
                self.assertEqual(core.retention_state(),publisher.read_witness())

    def test_restored_old_db_new_witness_never_replays_retired_observations(self):
        import sqlite3
        from stability_core.event_outbox_v2 import EventOutboxV2
        from stability_core.event_stream_v2 import ArchivePublisher
        from stability_core.event_outbox import EventOutboxError
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);publisher=ArchivePublisher(root/'archive');stream=EventStream(root/'events.jsonl')
            with EventOutboxV2(root/'events.db',initialize=True,witness_path=publisher.witness_path) as core:
                publisher.initialize_witness(core.retention_state())
                events=[{'tsEpoch':1,'seq':1}];handle=core.begin_generation('p',core.owner_epoch)
                core.record_batch(handle,events,expected_count=1,batch_digest=core.batch_digest(events));core.seal_generation(handle)
                stream.drain(core)
                with sqlite3.connect(root/'old.db') as backup:core.connection.backup(backup)
                request=core.prepare_archive('p',handle.ordinal,witness_path=publisher.witness_path)
                receipt=publisher.publish(request);publisher.advance_witness(request);core.retire(receipt)
            before=stream.target.read_bytes()
            with self.assertRaisesRegex(EventOutboxError,'v2-restore-frontier-drift'):
                EventOutboxV2(root/'old.db',witness_path=publisher.witness_path)
            self.assertEqual(stream.target.read_bytes(),before)
            with sqlite3.connect(root/'old.db') as old:
                self.assertEqual(old.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],1)


    def test_real_witness_ahead_crash_restricted_recovery_then_normal_writer(self):
        from stability_core.event_outbox_v2 import EventOutboxV2
        from stability_core.event_stream_v2 import ArchivePublisher
        from stability_core.event_outbox import EventOutboxError
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);publisher=ArchivePublisher(root/'archive');stream=EventStream(root/'events.jsonl')
            with EventOutboxV2(root/'events.db',initialize=True,witness_path=publisher.witness_path) as core:
                publisher.initialize_witness(core.retention_state())
                events=[{'tsEpoch':1,'seq':1}];handle=core.begin_generation('p',core.owner_epoch)
                core.record_batch(handle,events,expected_count=1,batch_digest=core.batch_digest(events));core.seal_generation(handle)
                stream.drain(core)
            code="""import os,sys
from stability_core.event_outbox_v2 import EventOutboxV2
from stability_core.event_stream_v2 import ArchivePublisher
p=ArchivePublisher(sys.argv[2])
with EventOutboxV2(sys.argv[1],witness_path=p.witness_path) as c:
 r=c.prepare_archive('p',1,witness_path=p.witness_path)
 p.publish(r)
 def crash(stage):
  if stage=='witness-receipt':os._exit(73)
 p.advance_witness(r,hook=crash)
"""
            result=subprocess.run([sys.executable,'-c',code,str(root/'events.db'),str(root/'archive')],cwd=Path(__file__).resolve().parents[2],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,73,result.stderr)
            with self.assertRaises(EventOutboxError):
                EventOutboxV2(root/'events.db',witness_path=publisher.witness_path)
            before=stream.target.read_bytes()
            with EventOutboxV2(root/'events.db',witness_path=publisher.witness_path,recovery_open=True) as core:
                with self.assertRaises(EventOutboxError):core.begin_generation('p',core.owner_epoch)
                request=core.recovery_archive_request()
                receipt=publisher.load_receipt(request)
                self.assertEqual(core.retire(receipt)['retired'],True)
                self.assertEqual(core.retention_state(),publisher.read_witness())
                new=core.begin_generation('p',core.owner_epoch)
                self.assertEqual(new.ordinal,2)
                self.assertEqual(stream.target.read_bytes(),before)
                self.assertEqual(core.connection.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],0)


if __name__=='__main__':unittest.main()
