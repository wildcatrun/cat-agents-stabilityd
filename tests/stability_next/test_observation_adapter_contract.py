import copy
import sqlite3
import unittest
from unittest import mock
from stability_core import observation_adapter_contract as c
from stability_core.observation_store import load_observation_records

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(':memory:')
        self.addCleanup(self.conn.close)
        self.grants = {'p': c.ProducerGrant('v1', frozenset({'fixture-a', 'fixture-b'}))}
        self.generations = {'fixture-a': 'a'*64, 'fixture-b': 'a'*64}
        self.record = dict(producerId='p', adapterVersion='v1', nodeId='fixture-a', sourceKind='synthetic-fixture',
                           eventId='b'*64, generationDigest='a'*64, evidenceDigest=c.evidence_digest({'coverage':True,'sampleCount':1}),
                           observedAtEpoch=100, evidence={'coverage':True,'sampleCount':1})
    def ingest(self, record=None, **kw):
        args=dict(trusted_producer_id='p', grants=self.grants, current_generations=self.generations, now_epoch=100)
        args.update(kw)
        return c.ingest_synthetic_observation(self.conn, self.record if record is None else record, **args)
    def test_fresh_is_not_readiness_or_action_authority(self):
        result=self.ingest()
        self.assertEqual(result['observationFreshness'],'fresh')
        self.assertFalse(result['readinessEvaluated'])
        self.assertFalse(result['actionReplay'])
        self.assertNotIn('ready',result)
        self.assertNotIn('authorized',result)
    def test_identity_scope_source_version_generation_digest_coverage(self):
        for key,value,reason in [('producerId','fake','producer-mismatch'),('nodeId','fixture-evil','node-scope-denied'),
                ('nodeId','prod-server','node-scope-denied'),('sourceKind','read-only-probe','source-kind-denied'),
                ('adapterVersion','v2','adapter-version-mismatch'),('generationDigest','c'*64,'generation-mismatch'),
                ('evidenceDigest','c'*64,'evidence-digest-mismatch'),('eventId','invalid','invalid-digest'),
                ('evidence',{'coverage':False,'sampleCount':1},'invalid-coverage-evidence')]:
            with self.subTest(key=key,value=value):
                record=copy.deepcopy(self.record); record[key]=value
                self.assertEqual(self.ingest(record)['rejected'],[reason])
        self.assertEqual(self.ingest(trusted_producer_id='unknown')['rejected'],['unknown-producer'])
        self.assertEqual(self.conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0],0)
    def test_input_cannot_supply_receipt_or_grant(self):
        for key in ('receivedAtEpoch','authorized_source_kinds','node_scope'):
            record=dict(self.record); record[key]=1
            self.assertEqual(self.ingest(record)['rejected'],['invalid-envelope-fields'])
        self.ingest(now_epoch=101)
        self.assertEqual(load_observation_records(self.conn)[0]['receivedAtEpoch'],101)
    def test_retry_and_conflict(self):
        self.ingest()
        result=self.ingest(now_epoch=101)
        self.assertEqual(result['summary']['duplicatesSuppressed'],1)
        self.assertEqual(load_observation_records(self.conn)[0]['receivedAtEpoch'],100)
        record=copy.deepcopy(self.record); record['evidence']['sampleCount']=2
        record['evidenceDigest']=c.evidence_digest(record['evidence'])
        self.assertIn('event-id-conflict',self.ingest(record)['rejected'])
        self.assertEqual(load_observation_records(self.conn),[])
    def test_clock_and_stale(self):
        for observed,now,state in [(200,100,'clock-invalid'),(100,131,'clock-skew'),(100,700000,'clock-skew')]:
            record=dict(self.record); record['observedAtEpoch']=observed
            # independent events prevent conflicts
            record['eventId']=format(now,'064x')
            self.assertEqual(self.ingest(record,now_epoch=now)['observationFreshness'],state)
    def test_transaction_failure_rolls_back(self):
        self.ingest(); self.conn.commit()
        self.conn.execute("CREATE TRIGGER fail_observation_insert BEFORE INSERT ON stability_observation_events BEGIN SELECT RAISE(ABORT,'fixture-failure'); END")
        record=dict(self.record); record['eventId']='c'*64
        with self.assertRaises(sqlite3.IntegrityError): self.ingest(record)
        self.assertEqual(len(load_observation_records(self.conn)),1)
    def test_other_node_records_preserved(self):
        self.ingest()
        record=dict(self.record,nodeId='fixture-b',eventId='c'*64)
        self.ingest(record)
        self.assertEqual(len(load_observation_records(self.conn)),2)
    def test_existing_default_has_no_contract_hook(self):
        from pathlib import Path
        root=Path(__file__).resolve().parents[2]
        daemon=(root/'bin/cat_agents_stabilityd.py').read_text()
        self.assertNotIn('observation_adapter_contract',daemon)
        self.assertNotIn('ingest_synthetic_observation',daemon)
    def test_canonical_and_closed_evidence(self):
        self.assertEqual(c.evidence_digest({'sampleCount':1,'coverage':True}),self.record['evidenceDigest'])
        with self.assertRaises(ValueError): c.evidence_digest({'coverage':True,'sampleCount':1,'token':'secret'})

if __name__=='__main__': unittest.main()
