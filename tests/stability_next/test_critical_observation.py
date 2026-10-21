"""T15: observation remains available while a heavy collector is waiting."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from stability_core.critical_observation import CriticalObservation
from stability_core.probe_runner import run_component_probe_hard


class CriticalObservationTests(unittest.TestCase):
    def test_one_parent_owned_callback_without_scheduler_or_authority(self):
        clock=[100.0];calls=[]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'critical.json'
            observer=CriticalObservation(path,1234,probe=lambda port:(calls.append(port) or {'status':'live'}),clock=lambda:clock[0])
            observer.tick();observer.tick();self.assertEqual(calls,[1234])
            clock[0]+=20;observer.tick();self.assertEqual(len(calls),2)
            result=json.loads(path.read_text());self.assertFalse(result['authorityGranted'])
            self.assertIn('not task',result['scope'])
            observer.owner=-1
            with self.assertRaises(ValueError):observer.tick(force=True)

    def test_heavy_worker_deadline_still_ticks_and_cleanup_is_retained(self):
        ticks=[]
        result=run_component_probe_hard('fixture',[sys.executable,'-I','-c','import time; time.sleep(2)'],{},source='fixture',budget_ms=150,terminate_grace_ms=0,observer_tick=lambda:ticks.append(1))
        self.assertGreater(len(ticks),0)
        self.assertEqual(result['probe']['errorClass'],'ProbeTimeout')
        self.assertTrue(result['probe']['leaderReaped'])
        self.assertTrue(result['probe']['noLiveGroupMemberObserved'])

    def test_callback_error_is_classified_and_does_not_bypass_cleanup(self):
        def bad():raise RuntimeError('secret must never be emitted')
        result=run_component_probe_hard('fixture',[sys.executable,'-I','-c','import time; time.sleep(2)'],{},source='fixture',budget_ms=150,terminate_grace_ms=0,observer_tick=bad)
        self.assertEqual(result['probe']['observerErrorClass'],'RuntimeError')
        self.assertNotIn('secret',json.dumps(result));self.assertTrue(result['probe']['leaderReaped'])

if __name__=='__main__':unittest.main()
