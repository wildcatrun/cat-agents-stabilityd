import datetime as dt
import json
import gzip
import os
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from stability_core.ordinary_telemetry import maintain,ROLE

class OrdinaryTelemetryTests(unittest.TestCase):
    def test_only_closed_ordinary_counters_are_compressed_and_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);folder=root/'ordinary-telemetry';folder.mkdir(mode=0o700)
            now=dt.datetime(2026,10,22,tzinfo=dt.timezone.utc).timestamp()
            for day in ('2026-10-10','2026-09-01'):
                p=folder/('ordinary-'+day+'.json');p.write_text(json.dumps({'kind':ROLE,'day':day,'noActionCount':10,'authorityGranted':False}));p.chmod(0o600)
            incident=folder/'ordinary-2026-09-02.json';incident.write_text(json.dumps({'kind':'incident','protected':True}));incident.chmod(0o600)
            ledger=root/'state.db';ledger.write_bytes(b'ledger-must-stay')
            r=maintain(root,now=now,no_action_count=20)
            self.assertEqual(r['compressed'],1);self.assertEqual(r['removedExpired'],1)
            self.assertTrue((folder/'ordinary-2026-10-10.json.gz').exists());self.assertTrue(incident.exists())
            self.assertEqual(ledger.read_bytes(),b'ledger-must-stay');self.assertFalse(r['protectedHistoryTouched'])
            again=maintain(root,now=now,no_action_count=21);self.assertEqual(again['compressed'],0);self.assertEqual(again['removedExpired'],0)

    def test_symlink_cannot_redirect_retention(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root';root.mkdir(mode=0o700);outside=Path(tmp)/'outside';outside.mkdir()
            (root/'ordinary-telemetry').symlink_to(outside,target_is_directory=True)
            with self.assertRaises(ValueError):maintain(root,now=1000000,no_action_count=1)

    def test_compressed_input_has_a_bounded_expansion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);folder=root/'ordinary-telemetry';folder.mkdir(mode=0o700)
            p=folder/'ordinary-2026-09-01.json.gz'
            p.write_bytes(gzip.compress(b'x'*1000000));p.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'decompression-budget'):
                maintain(root,now=dt.datetime(2026,10,22,tzinfo=dt.timezone.utc).timestamp(),no_action_count=1)
            self.assertTrue(p.exists())

if __name__=='__main__':unittest.main()
