import json
import random
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from stability_core.event_store import _bounded_json_size, ingest_event, read_events

class EventTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:'); self.addCleanup(self.db.close)
    def put(self, identity='a',ts=100,now=100,**kw):
        ttl_seconds = kw.get('ttl_seconds', 86400)
        max_forward_skew_seconds = kw.pop('max_forward_skew_seconds', min(5, ttl_seconds - 1))
        return ingest_event(
            self.db, {'tsEpoch':ts,'key':'finding'}, event_id=identity, now_epoch=now,
            max_forward_skew_seconds=max_forward_skew_seconds, **kw,
        )
    def test_retries_conflicts_and_distinct_times(self):
        self.put(); self.assertEqual(self.put(now=101)['state'],'duplicate')
        self.assertEqual(self.db.execute('SELECT received_at FROM stability_event_candidate').fetchone()[0],100)
        with self.assertRaisesRegex(ValueError,'conflict'):self.put(ts=101)
        self.put('b',ts=101,now=101); self.assertEqual(len(read_events(self.db)),2)
    def test_ttl_count_and_identity_horizon(self):
        self.put(ttl_seconds=10)
        self.put('b',now=105,ttl_seconds=10)
        self.put('c',now=110,ttl_seconds=10)
        self.assertEqual(self.db.execute('SELECT count(*) FROM stability_event_candidate').fetchone()[0],3)
        self.put('d',now=111,ttl_seconds=10)
        self.assertIsNone(self.db.execute("SELECT event_id FROM stability_event_candidate WHERE event_id='a'").fetchone())
        self.put('e',now=112,max_records=1)
        self.assertEqual(len(read_events(self.db)),1)
        self.assertEqual(self.put('a',now=113,max_records=1)['state'],'stored')
    def test_payload_rejected_without_schema_or_secret_write(self):
        with self.assertRaisesRegex(ValueError,'budget'):self.put(max_payload_bytes=1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0],0)
    def test_oversized_payload_is_rejected_before_full_json_encoding(self):
        events=({'tsEpoch':100,'blob':'x'*10000},{'tsEpoch':100,'count':10**100000})
        with patch('stability_core.event_store.json.dumps', side_effect=AssertionError('full encoder called')):
            for event in events:
                with self.assertRaisesRegex(ValueError,'payload-budget'):
                    ingest_event(self.db,event,event_id='large',now_epoch=100,max_forward_skew_seconds=5,max_payload_bytes=128)
        self.assertEqual(self.db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0],0)
    def test_preflight_size_matches_canonical_utf8_encoding(self):
        event={'tsEpoch':100,'unicode':'猫😀','escaped':'"\\/\b\f\n\r\t\x00','nested':[True,None,-123.5]}
        encoded=json.dumps(event,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
        self.assertEqual(_bounded_json_size(event,65536),len(encoded))
    def test_preflight_matches_deterministic_nested_values(self):
        rng=random.Random(7)
        alphabet=['a','猫','😀','"','\\','\n','\x00']
        def value(depth=0):
            if depth >= 3:
                return rng.choice([None,True,False,rng.randint(-100000,100000),rng.random(),''.join(rng.choices(alphabet,k=rng.randint(0,12)))])
            kind=rng.randrange(3)
            if kind == 0:
                return [value(depth+1) for _ in range(rng.randrange(5))]
            if kind == 1:
                return {'k'+str(i):value(depth+1) for i in range(rng.randrange(5))}
            return value(3)
        for _ in range(100):
            event={'tsEpoch':100,'value':value()}
            encoded=json.dumps(event,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
            self.assertEqual(_bounded_json_size(event,65536),len(encoded))
    def test_payload_exact_limit_accepts_and_limit_minus_one_rejects(self):
        event={'tsEpoch':100,'value':'猫\n'}
        encoded=json.dumps(event,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
        ingest_event(self.db,event,event_id='edge',now_epoch=100,max_forward_skew_seconds=5,max_payload_bytes=len(encoded))
        with self.assertRaisesRegex(ValueError,'payload-budget'):
            ingest_event(self.db,event,event_id='edge-rejected',now_epoch=100,max_forward_skew_seconds=5,max_payload_bytes=len(encoded)-1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM stability_event_candidate').fetchone()[0],1)
    def test_long_common_prefix_keys_are_budgeted_before_json_encoding(self):
        prefix='a'*1000
        event={'tsEpoch':100,prefix+'1':1,prefix+'2':2}
        with patch('stability_core.event_store.json.dumps', side_effect=AssertionError('full encoder called')):
            with self.assertRaisesRegex(ValueError,'payload-budget'):
                ingest_event(self.db,event,event_id='long-keys',now_epoch=100,max_forward_skew_seconds=5,max_payload_bytes=128)
        self.assertEqual(self.db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0],0)
    def test_deep_or_wide_payload_is_bounded_before_schema_write(self):
        deep={'tsEpoch':100}; cursor=deep
        for _ in range(70):
            child={}; cursor['nested']=child; cursor=child
        with self.assertRaisesRegex(ValueError,'depth'):
            ingest_event(self.db,deep,event_id='deep',now_epoch=100,max_forward_skew_seconds=5)
        with self.assertRaisesRegex(ValueError,'budget'):
            ingest_event(self.db,{'tsEpoch':100,'items':[0]*4000},event_id='wide',now_epoch=100,max_forward_skew_seconds=5,max_payload_bytes=128)
        self.assertEqual(self.db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0],0)
    def test_ingest_clock_regression_does_not_extend_identity(self):
        self.put()
        self.assertTrue(self.put(now=90)['clockRegressed'])
        with self.assertRaisesRegex(ValueError,'regressed'):self.put('b',now=90)
        self.assertEqual(len(read_events(self.db)),1)
    def test_forward_clock_jump_is_bounded_before_eviction_and_high_water_update(self):
        self.put(ttl_seconds=10, max_forward_skew_seconds=5)
        self.put('b',now=105,ttl_seconds=10,max_forward_skew_seconds=5)
        before_rows = self.db.execute(
            'SELECT event_id,digest,received_at,payload FROM stability_event_candidate ORDER BY event_id'
        ).fetchall()
        before_clock = self.db.execute(
            'SELECT high_water FROM stability_event_candidate_clock WHERE id=1'
        ).fetchone()[0]
        self.assertEqual(before_clock,105)
        with self.assertRaisesRegex(ValueError,'forward-jump'):
            self.put('c',now=111,ttl_seconds=10,max_forward_skew_seconds=5)
        with self.assertRaisesRegex(ValueError,'forward-jump'):
            self.put('a',now=111,ttl_seconds=10,max_forward_skew_seconds=5)
        self.assertEqual(
            self.db.execute('SELECT event_id,digest,received_at,payload FROM stability_event_candidate ORDER BY event_id').fetchall(),
            before_rows,
        )
        self.assertEqual(
            self.db.execute('SELECT high_water FROM stability_event_candidate_clock WHERE id=1').fetchone()[0],
            before_clock,
        )
    def test_forward_clock_cap_is_required_and_strictly_below_ttl(self):
        event={'tsEpoch':100,'key':'finding'}
        with self.assertRaises(TypeError):
            ingest_event(self.db,event,event_id='missing-cap',now_epoch=100)
        for value in (0, True, 1.5, 10):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError,'retention-budget'):
                ingest_event(self.db,event,event_id='bad-cap',now_epoch=100,
                             max_forward_skew_seconds=value,ttl_seconds=10)
        self.assertEqual(self.db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0],0)
    def test_invalid_stored_high_water_fails_closed_without_event_changes(self):
        self.put()
        self.db.commit()
        before_rows = self.db.execute(
            'SELECT event_id,digest,received_at,payload FROM stability_event_candidate'
        ).fetchall()
        for damaged in ('damaged', float('inf'), -1):
            with self.subTest(damaged=damaged):
                self.db.execute(
                    'UPDATE stability_event_candidate_clock SET high_water=? WHERE id=1', (damaged,)
                )
                self.db.commit()
                stored_value = self.db.execute(
                    'SELECT high_water FROM stability_event_candidate_clock WHERE id=1'
                ).fetchone()[0]
                with self.assertRaisesRegex(ValueError,'stored-high-water'):
                    self.put('new',now=101)
                self.assertEqual(
                    self.db.execute('SELECT event_id,digest,received_at,payload FROM stability_event_candidate').fetchall(),
                    before_rows,
                )
                self.assertEqual(
                    self.db.execute('SELECT high_water FROM stability_event_candidate_clock WHERE id=1').fetchone()[0],
                    stored_value,
                )
    def test_observed_clock_invalid(self):
        for value in (float('nan'),float('inf'),-1,True):
            with self.assertRaises(ValueError): self.put(ts=value)
    def test_backup_restore_preserves_identity_and_clock(self):
        self.put(); self.db.commit(); copy=sqlite3.connect(':memory:'); self.addCleanup(copy.close)
        self.db.backup(copy)
        result=ingest_event(copy,{'tsEpoch':100,'key':'finding'},event_id='a',now_epoch=101,max_forward_skew_seconds=5)
        self.assertEqual(result['state'],'duplicate')
        with self.assertRaisesRegex(ValueError,'regressed'):ingest_event(copy,{'tsEpoch':90},event_id='b',now_epoch=90,max_forward_skew_seconds=5)
    def test_file_backed_wal_backup_and_reopen_preserve_identity_and_clock(self):
        event = {'tsEpoch': 100, 'key': 'finding'}
        with tempfile.TemporaryDirectory() as tmp:
            source_path = Path(tmp) / 'events.db'
            backup_path = Path(tmp) / 'events-backup.db'
            restored_path = Path(tmp) / 'events-restored.db'
            source = sqlite3.connect(source_path)
            try:
                self.assertEqual(source.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower(), 'wal')
                source.execute('PRAGMA synchronous=NORMAL')
                source.execute('PRAGMA wal_autocheckpoint=0')
                source.execute('BEGIN IMMEDIATE')
                self.assertEqual(
                    ingest_event(source, event, event_id='wal-event', now_epoch=100,max_forward_skew_seconds=5)['state'], 'stored'
                )
                self.assertTrue(source.in_transaction, 'caller transaction must remain caller-owned')
                source.commit()
                self.assertFalse(source.in_transaction)
                wal_path = Path(str(source_path) + '-wal')
                page_size = source.execute('PRAGMA page_size').fetchone()[0]
                self.assertTrue(wal_path.exists())
                self.assertGreaterEqual(
                    wal_path.stat().st_size, 32 + 24 + page_size,
                    'fixture must contain a committed WAL frame before backup',
                )
                reader = sqlite3.connect(source_path)
                try:
                    self.assertEqual(read_events(reader), [event])
                finally:
                    reader.close()
                backup = sqlite3.connect(backup_path)
                try:
                    source.backup(backup)
                    self.assertEqual(backup.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                    self.assertEqual(read_events(backup), [event])
                    restored = sqlite3.connect(restored_path)
                    try:
                        backup.backup(restored)
                        self.assertEqual(restored.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                    finally:
                        restored.close()
                finally:
                    backup.close()
            finally:
                source.close()
            for path in (source_path, restored_path):
                reopened = sqlite3.connect(path)
                try:
                    retry=ingest_event(reopened,event,event_id='wal-event',now_epoch=101,max_forward_skew_seconds=5)
                    self.assertEqual(retry['state'], 'duplicate')
                    with self.assertRaisesRegex(ValueError,'regressed'):
                        ingest_event(reopened, {'tsEpoch': 90}, event_id='older-clock-event', now_epoch=90,max_forward_skew_seconds=5)
                finally:
                    reopened.close()
    def test_transaction_failure_preserves_prior_events(self):
        self.put(ts=98,now=100);self.db.commit()
        self.db.execute("CREATE TRIGGER reject_new BEFORE INSERT ON stability_event_candidate BEGIN SELECT RAISE(ABORT,'failed'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.put('b',ts=100,now=101,ttl_seconds=2,max_forward_skew_seconds=1)
        self.assertEqual(len(read_events(self.db)),1)
    def test_failed_count_prune_rolls_back_ttl_eviction_insert_and_high_water(self):
        self.put('a',now=100,ttl_seconds=10,max_forward_skew_seconds=5)
        self.put('b',now=105,ttl_seconds=10,max_forward_skew_seconds=5)
        self.put('c',now=110,ttl_seconds=10,max_forward_skew_seconds=5)
        before_rows = self.db.execute(
            'SELECT event_id,digest,received_at,payload FROM stability_event_candidate ORDER BY event_id'
        ).fetchall()
        before_clock = self.db.execute(
            'SELECT high_water FROM stability_event_candidate_clock WHERE id=1'
        ).fetchone()[0]
        self.db.execute(
            "CREATE TRIGGER reject_count_prune BEFORE DELETE ON stability_event_candidate "
            "WHEN OLD.event_id='b' BEGIN SELECT RAISE(ABORT,'failed'); END"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.put('d',now=115,ttl_seconds=10,max_forward_skew_seconds=5,max_records=2)
        self.assertEqual(
            self.db.execute('SELECT event_id,digest,received_at,payload FROM stability_event_candidate ORDER BY event_id').fetchall(),
            before_rows,
        )
        self.assertEqual(
            self.db.execute('SELECT high_water FROM stability_event_candidate_clock WHERE id=1').fetchone()[0],
            before_clock,
        )
    def test_readonly_empty_and_no_default_integration(self):
        self.assertEqual(read_events(self.db),[])
        self.assertEqual(self.db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0],0)
        from pathlib import Path
        self.assertNotIn('from stability_core.event_store',(Path(__file__).resolve().parents[2]/'bin/cat_agents_stabilityd.py').read_text())

if __name__=='__main__':unittest.main()
