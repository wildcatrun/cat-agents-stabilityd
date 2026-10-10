"""Slow durable qualification: healthy cycles, not merely event throughput.

Explicit finite retry horizon of eight sealed generations. Runs all real local
SQLite/filesystem operations; no subprocess/network/runtime service execution.
"""
import json
import tempfile
import time
import unittest
from collections import deque
from pathlib import Path

from stability_core.event_outbox import EventOutboxError
from stability_core.event_outbox_v2 import EventOutboxV2
from stability_core.event_stream_v2 import ArchivePublisher, EventStream


class EventStreamContinuousQualificationTests(unittest.TestCase):
    def test_4208_healthy_generations_finite_retry_horizon_and_storage_plateau(self):
        cycles=4208;retry_window=8
        started=time.monotonic();samples=[]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            publisher=ArchivePublisher(root/'archive',max_files=12,max_bytes=1048576)
            stream=EventStream(root/'events.jsonl',max_active_bytes=8192)
            queue=deque();first=None
            with EventOutboxV2(root/'events.db',initialize=True,witness_path=publisher.witness_path,
                               max_hot_records=32,max_generations=16,max_receipts=4) as core:
                publisher.initialize_witness(core.retention_state())
                core.connection.execute('CREATE TABLE action_ledger (fixture TEXT)')
                core.connection.execute("INSERT INTO action_ledger VALUES('untouched')")
                for n in range(cycles):
                    events=[{'tsEpoch':n,'message':'synthetic','cycle':n}]
                    handle=core.begin_generation('p',core.owner_epoch)
                    if first is None:first=handle
                    checksum=core.batch_digest(events)
                    core.record_batch(handle,events,expected_count=1,batch_digest=checksum)
                    core.seal_generation(handle)
                    stream.drain(core)
                    queue.append((handle,events,checksum))
                    # Every current identity remains retryable while its explicit
                    # durable generation has not crossed the retirement frontier.
                    duplicate=core.record_batch(handle,events,expected_count=1,batch_digest=checksum)
                    self.assertTrue(duplicate['duplicate'])
                    if len(queue)>retry_window:
                        old,old_events,old_digest=queue.popleft()
                        request=core.prepare_archive('p',old.ordinal,max_records=1,max_bytes=65536,witness_path=publisher.witness_path)
                        receipt=publisher.publish(request)
                        publisher.advance_witness(request)
                        core.retire(receipt,witness_path=publisher.witness_path)
                        publisher.prune_committed(core)
                        with self.assertRaisesRegex(EventOutboxError,'v2-generation-retired'):
                            core.record_batch(old,old_events,expected_count=1,batch_digest=old_digest)
                    if n>=retry_window:
                        oldest,oldest_events,oldest_digest=queue[0]
                        self.assertTrue(core.record_batch(oldest,oldest_events,expected_count=1,batch_digest=oldest_digest)['duplicate'])
                    self.assertEqual(core.connection.execute('SELECT COUNT(*) FROM event_v2_rows').fetchone()[0],min(n+1,retry_window))
                    self.assertEqual(core.connection.execute('SELECT COUNT(*) FROM event_v2_generations').fetchone()[0],min(n+1,retry_window))
                    self.assertLessEqual(core.connection.execute('SELECT COUNT(*) FROM event_v2_receipts').fetchone()[0],1)
                    self.assertLessEqual(stream.target.stat().st_size,8192)
                    self.assertLessEqual(len(list(publisher.root.iterdir())),4)
                    if (n+1)%512==0 or n+1==cycles:
                        db_bytes=sum(path.stat().st_size for path in root.glob('events.db*') if path.is_file())
                        archive_bytes=sum(path.stat().st_size for path in publisher.root.iterdir())
                        sample={'cycles':n+1,'retirements':core.retention_state()['retirementSeq'],
                                'hotRecords':len(queue),'catalog':len(core.prunable_archive_requests()),
                                'archiveFiles':len(list(publisher.root.iterdir())),
                                'dbAndSidecarsBytes':db_bytes,'dbMainBytes':(root/'events.db').stat().st_size,
                                'dbAllocatedPages':core.connection.execute('PRAGMA page_count').fetchone()[0],
                                'archiveBytes':archive_bytes,
                                'activeBytes':stream.target.stat().st_size}
                        samples.append(sample)
                        self.assertLess(db_bytes+archive_bytes+sample['activeBytes'],10485760)
                        print(json.dumps({'qualification':'stream-v2-continuous','elapsedSeconds':round(time.monotonic()-started,2),**sample}),flush=True)
                self.assertEqual(core.retention_state()['retirementSeq'],cycles-retry_window)
                self.assertGreater(core.retention_state()['retirementSeq'],4096)
                self.assertEqual(core.retention_state(),publisher.read_witness())
                self.assertEqual([item['cycle'] for item in stream.latest()],list(range(cycles-50,cycles)))
                self.assertEqual(core.connection.execute('SELECT fixture FROM action_ledger').fetchall(),[('untouched',)])
                self.assertEqual(core.connection.execute('SELECT COUNT(*) FROM event_v2_intents').fetchone()[0],0)
                with self.assertRaisesRegex(EventOutboxError,'v2-generation-retired'):
                    core.load_generation('p',first.ordinal,first.owner_epoch)
                # Main-store allocation and logical cardinality must plateau.
                # WAL bytes legitimately cycle across automatic checkpoints;
                # retain those raw samples and enforce the total hard ceiling,
                # rather than misclassifying their sawtooth as linear growth.
                late=samples[-4:]
                self.assertLessEqual(max(s['dbMainBytes'] for s in late)-min(s['dbMainBytes'] for s in late),65536)
                self.assertLessEqual(max(s['dbAllocatedPages'] for s in late)-min(s['dbAllocatedPages'] for s in late),16)
                self.assertLessEqual(max(s['archiveBytes'] for s in late)-min(s['archiveBytes'] for s in late),4096)
                self.assertTrue(all(s['hotRecords']==retry_window and s['catalog']==1 and s['archiveFiles']==4 for s in late))


if __name__=='__main__':unittest.main()
