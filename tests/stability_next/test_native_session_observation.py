import contextlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock
from test_registry_safety import stabilityd as d
ROOT=Path(__file__).resolve().parents[2]

class NativeSessionObservationTests(unittest.TestCase):
    def project(self,value,ids):
        source='import {projectSessionInventory as project} from '+json.dumps((ROOT/'scripts/gateway_sessions_readonly.mjs').as_uri())+'; console.log(JSON.stringify(project('+json.dumps(value)+','+json.dumps(ids)+')));'
        return subprocess.run(['node','--input-type=module','-e',source],capture_output=True,text=True,timeout=5)

    def test_full_metadata_scope_is_not_activity_or_reset_authority(self):
        value={'sessions':[{'agentId':'main','key':'agent:main:main','hasActiveRun':True,'updatedAt':1000,'privateTranscript':'MUST_NOT_EXPORT'}],
               'totalCount':1,'hasMore':False,'nextOffset':None}
        result=self.project(value,['main']);self.assertEqual(result.returncode,0,result.stderr)
        r=json.loads(result.stdout);self.assertTrue(r['scopeComplete']);self.assertFalse(r['authorityGranted'])
        self.assertNotIn('MUST_NOT_EXPORT',result.stdout);self.assertIn('no transcript',r['activityCoverage'])
        self.assertTrue(r['sessions'][0]['hasActiveRun'])

    def test_missing_member_truncation_and_unknown_schema_remain_incomplete(self):
        value={'sessions':[],'totalCount':0,'hasMore':False,'nextOffset':None}
        self.assertFalse(json.loads(self.project(value,['main']).stdout)['scopeComplete'])
        value.update(totalCount=100,hasMore=True,nextOffset=1)
        self.assertFalse(json.loads(self.project(value,['main']).stdout)['inventoryComplete'])
        self.assertNotEqual(self.project({'sessions':[]},['main']).returncode,0)

    def test_illegal_endpoint_does_not_alias_member_and_legacy_failure_never_authorizes_reset(self):
        value={'sessions':[{'agentId':'main','key':'agent:other:main'}],'totalCount':1,'hasMore':False,'nextOffset':None}
        self.assertNotEqual(self.project(value,['main']).returncode,0)
        registry={'source':'db','writeEligible':True,'records':[{'agent_id':'main','runtime':'openclaw','platform':'openclaw','status':'active','execution_adapter':'native','can_receive_dispatch':1,'endpoint_ref':'openclaw-agent:main'}]}
        with mock.patch.object(d,'workflow_runtime_registry_records',return_value=registry), mock.patch.object(d,'iter_session_store_paths',return_value=[]), mock.patch.object(d,'native_session_inventory',return_value={'available':False,'scopeComplete':False}), mock.patch.object(d,'parse_session_problems_from_logs',return_value={}):
            findings=[];result=d.session_collect(findings)
        self.assertFalse(result['scope']['scopeComplete']);self.assertEqual(result['resetCandidates'],[])
        self.assertIn('session_inventory_scope_incomplete',[f['key'] for f in findings])

if __name__=='__main__':unittest.main()
