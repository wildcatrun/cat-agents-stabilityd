"""Actual lease prechecks/ledger/file repair, synthetic absent-owner observations only."""
import importlib.util
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('lease_capability_integration',ROOT/'bin/cat_agents_stabilityd.py')
m=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=m;SPEC.loader.exec_module(m)


class LeaseCapabilityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.lease_root=self.root/'leases';self.runs=self.root/'runs';self.repairs=self.root/'pending'
        self.byjob=self.root/'by-job';self.cron=self.root/'cron'
        for root in (self.lease_root,self.runs,self.repairs,self.byjob,self.cron):root.mkdir()
        self.path=self.lease_root/'lease.json';self.run=self.runs/'run.json';self.repair=self.repairs/'job__lease_expired.json'
        self.lease={'jobId':'job','runId':'run','leaseOwner':socket.gethostname()+':987654321',
                    'expiresAtMs':999000,'workloadState':'not-started','workloadOwner':None,'dispatchState':'not-dispatched'}
        self.run_data={'jobId':'job','runId':'run','status':'running','dispatchState':'not-dispatched','startedAtMs':990000}
        self.path.write_text(json.dumps(self.lease,indent=2));self.run.write_text(json.dumps(self.run_data,indent=2))
        self.item={'jobId':'job','runId':'run','path':str(self.path)}
        self.policy={'canReapExpiredLeases':True,'updatedAtEpoch':999,'validUntilEpoch':1060}
        self.gate={'status':'ready'}
        patches=[mock.patch.object(m,'STATE_DB',self.root/'state.db'),mock.patch.object(m,'LEASE_DIR',self.lease_root),
                 mock.patch.object(m,'RUNS_BY_RUN_DIR',self.runs),mock.patch.object(m,'RUNS_BY_JOB_DIR',self.byjob),
                 mock.patch.object(m,'REPAIR_PENDING_DIR',self.repairs),mock.patch.object(m,'CRON_DIR',self.cron),
                 mock.patch.object(m,'current_host_generation',return_value='fixture-node:12345678-1234-1234-1234-123456789abc'),
                 mock.patch.object(m.platform,'node',return_value='fixture-node'),mock.patch.object(m,'epoch',return_value=1000),
                 mock.patch.object(m,'now_ms',return_value=1000000),mock.patch.object(m.os,'kill',side_effect=ProcessLookupError)]
        for patch in patches:patch.start();self.addCleanup(patch.stop)

    def call(self):
        return m.governed_reap_expired_lease(self.item,self.gate,self.policy,'fixture-generation')

    def test_real_file_repair_and_ledger_survive_gateway_unavailable(self):
        actual=m.reap_expired_lease_candidate
        with mock.patch.object(m,'gateway_collect',side_effect=AssertionError('Gateway forbidden')), \
             mock.patch.object(m,'run_cmd',side_effect=AssertionError('runtime command forbidden')), \
             mock.patch.object(m,'reap_expired_lease_candidate',wraps=actual) as operation:
            result=self.call()
        self.assertEqual(result['ledgerState'],'succeeded');operation.assert_called_once()
        self.assertFalse(self.path.exists());self.assertEqual(json.loads(self.run.read_text())['status'],'orphaned')
        repair,error,_=m.load_valid_repair_request(self.repair)
        self.assertIsNone(error);self.assertEqual(repair['schemaVersion'],1)
        self.assertEqual(self.call()['result'],'blocked')

    def test_unknown_lease_schema_type_and_owner_do_not_enter_operation(self):
        for document in ({**self.lease,'schemaVersion':2},{**self.lease,'expiresAtMs':True},
                         {**self.lease,'leaseOwner':''},[],{**self.lease,'workloadState':'unknown'}):
            with self.subTest(document=document),mock.patch.object(m,'reap_expired_lease_candidate') as operation:
                self.path.write_text(json.dumps(document));result=self.call()
                self.assertEqual(result['result'],'blocked');operation.assert_not_called()

    def test_unknown_run_and_repair_protocols_refuse_before_effect(self):
        documents=[('run',[]),('run',{**self.run_data,'schemaVersion':99}),('run',{**self.run_data,'startedAtMs':True}),
                   ('run',{**self.run_data,'jobId':'different'}),('repair',[]),
                   ('repair',{'schemaVersion':99,'jobId':'job','reason':'lease_expired','source':'fixture','status':'pending'})]
        for kind,document in documents:
            with self.subTest(kind=kind,document=document),mock.patch.object(m,'reap_expired_lease_candidate') as operation:
                self.run.write_text(json.dumps(self.run_data));self.repair.unlink(missing_ok=True)
                (self.run if kind=='run' else self.repair).write_text(json.dumps(document))
                self.assertEqual(self.call()['result'],'blocked');operation.assert_not_called()

    def test_missing_run_is_explicitly_skipped_and_missing_repair_created(self):
        self.run.unlink()
        result=self.call()
        self.assertEqual(result['ledgerState'],'succeeded');self.assertFalse(self.run.exists())
        self.assertTrue(self.repair.exists())

    def test_byte_drift_after_claim_cannot_hide_behind_same_canonical_digest(self):
        actual=m.ActionLedger.begin_execution
        def change(ledger,*args,**kwargs):
            result=actual(ledger,*args,**kwargs)
            self.path.write_text(json.dumps(self.lease,separators=(',',':')))
            return result
        with mock.patch.object(m.ActionLedger,'begin_execution',change), \
             mock.patch.object(m,'reap_expired_lease_candidate') as operation:
            result=self.call()
        self.assertEqual(result['ledgerState'],'blocked');operation.assert_not_called();self.assertTrue(self.path.exists())

    def test_companion_directory_replacement_after_claim_blocks_effect(self):
        actual=m.ActionLedger.begin_execution
        def change(ledger,*args,**kwargs):
            result=actual(ledger,*args,**kwargs)
            self.repairs.rename(self.root/'old-pending');self.repairs.mkdir()
            return result
        with mock.patch.object(m.ActionLedger,'begin_execution',change), \
             mock.patch.object(m,'reap_expired_lease_candidate') as operation:
            result=self.call()
        self.assertEqual(result['ledgerState'],'blocked');operation.assert_not_called()

    def test_symlink_companion_and_lease_do_not_enter_operation(self):
        self.run.rename(self.root/'actual-run');self.run.symlink_to(self.root/'actual-run')
        with mock.patch.object(m,'reap_expired_lease_candidate') as operation:
            self.assertEqual(self.call()['result'],'blocked');operation.assert_not_called()
        self.run.unlink();self.run.write_text(json.dumps(self.run_data));self.path.rename(self.root/'actual-lease')
        self.path.symlink_to(self.root/'actual-lease')
        with mock.patch.object(m,'reap_expired_lease_candidate') as operation:
            self.assertEqual(self.call()['result'],'blocked');operation.assert_not_called()


if __name__=='__main__':unittest.main()
