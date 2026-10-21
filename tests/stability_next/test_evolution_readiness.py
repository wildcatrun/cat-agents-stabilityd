from __future__ import annotations
import contextlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from stability_core.evolution_readiness import environment_report,delivery_metadata,compare_reports


class EvolutionReadinessTests(unittest.TestCase):
    def report(self,**changes):
        snapshot={'checkedAtEpoch':time.time(),'gateway':{'healthOk':True,'openclawVersion':{'version':'2026.9.7','secret':'MUST_NOT_EXPORT'}},'hermers':{'profiles':{}}}
        snapshot.update(changes)
        return environment_report(snapshot,{'source':'db','writeEligible':True,'records':[{'agent_id':'main','runtime':'openclaw','platform':'openclaw','execution_adapter':'native','endpoint_ref':'openclaw-agent:main','status':'active'}]},now=time.time(),node_id='dev-server',python_version='3.14.7')

    def test_current_contract_and_fixed_node_inventory_never_grant_authority(self):
        r=self.report();self.assertEqual(r['targetCapabilities'][0]['status'],'supported')
        self.assertFalse(r['authorityGranted']);self.assertNotIn('MUST_NOT_EXPORT',json.dumps(r))
        self.assertTrue(all(x['status']=='unobserved' for x in r['physicalNodes'] if x['nodeId']!='dev-server'))

    def test_old_or_unknown_schema_cannot_be_promoted_to_current_health(self):
        r=self.report(checkedAtEpoch=1,gateway='new-schema')
        self.assertFalse(r['sourceFresh']);self.assertIsNone(r['platforms']['openclaw']['observedVersion'])
        self.assertEqual(r['dependencies'][0]['status'],'unknown')

    def test_before_after_comparison_does_not_auto_upgrade_or_authorize(self):
        r=self.report();c=compare_reports(r,r);self.assertEqual(c['status'],'supported');self.assertFalse(c['platformUpgradeAuthorized'])
        self.assertEqual(compare_reports(r,{**r,'schemaFingerprint':'new'})['status'],'observe_only')
        self.assertEqual(compare_reports(r,{**r,'sourceNode':'other'})['status'],'blocked')
        self.assertEqual(compare_reports(r,{**r,'schemaVersion':999})['status'],'unknown')

    def test_ack_is_not_execution_or_user_delivery(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=Path(tmp)/'workflow.db'
            with contextlib.closing(sqlite3.connect(db)) as c:
                c.execute('CREATE TABLE runtime_runs(status TEXT, started_at TEXT, completed_at TEXT, latency_ms INTEGER)')
                c.execute("INSERT INTO runtime_runs VALUES('acked','2026-10-22T00:00:00Z','2026-10-22T00:00:01Z',1000)");c.commit()
            before=db.read_bytes();now=__import__('datetime').datetime.fromisoformat('2026-10-22T00:01:00+00:00').timestamp()
            r=delivery_metadata(db,now=now)
            self.assertEqual(r['tables']['runtime_runs']['sampleStatusCounts'],{'acked':1})
            self.assertIsNone(r['tables']['runtime_runs']['semanticExecutionSuccessRate'])
            self.assertFalse(r['inboxIsHumanConfirmation']);self.assertEqual(db.read_bytes(),before)

    def test_empty_database_and_row_budget_leave_unknown_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=delivery_metadata(Path(tmp)/'absent.db',now=time.time())
            self.assertEqual(r['coverage'],'unknown');self.assertFalse((Path(tmp)/'absent.db').exists())
            with self.assertRaises(ValueError):delivery_metadata(Path(tmp)/'absent.db',now=time.time(),max_rows=100000)

if __name__=='__main__':unittest.main()
