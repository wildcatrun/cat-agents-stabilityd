from pathlib import Path
import sys
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from stability_core.condition_evidence import condition_fingerprint,resource_condition_fingerprint
from stability_core import dependency_health as h

class ConditionsTests(unittest.TestCase):
    def test_volatile_metrics_do_not_create_new_incident_identity(self):
        finding={'key':'pressure','severity':'high','component':'resource','memoryBytes':100}
        self.assertEqual(condition_fingerprint(finding),condition_fingerprint({**finding,'memoryBytes':200}))
        self.assertNotEqual(condition_fingerprint(finding),condition_fingerprint({**finding,'severity':'critical'}))
        self.assertNotEqual(resource_condition_fingerprint(['pressure'],1),resource_condition_fingerprint(['pressure'],2))

    def test_dependency_failure_expires_success_and_never_reads_credentials(self):
        before=(h._cache,h._sampled_monotonic)
        try:
            clock=[100.0];response=mock.MagicMock();response.__enter__.return_value.status=200
            opener=mock.Mock();opener.open.return_value=response
            with mock.patch.object(h.socket,'create_connection',return_value=mock.MagicMock()) as connect, mock.patch.object(h.urllib.request,'build_opener',return_value=opener):
                first=h.collect_dependency_health(clock=lambda:clock[0],force=True)
                self.assertEqual(first['facts'][1]['readiness'],'http-health-only')
                self.assertFalse(first['credentialsRead']);self.assertEqual(first['facts'][0]['readiness'],'unknown')
                clock[0]+=20;self.assertTrue(h.collect_dependency_health(clock=lambda:clock[0])['cached'])
                self.assertEqual(connect.call_count,1)
                clock[0]+=301;opener.open.side_effect=TimeoutError('sensitive-error')
                failed=h.collect_dependency_health(clock=lambda:clock[0]);self.assertEqual(failed['facts'][1]['readiness'],'unknown')
                self.assertNotIn('sensitive-error',str(failed));self.assertEqual(failed['ttlSeconds'],60)
        finally:h._cache,h._sampled_monotonic=before

if __name__=='__main__':unittest.main()
