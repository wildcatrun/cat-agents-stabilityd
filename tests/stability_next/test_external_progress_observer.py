"""A live synthetic worker cannot make stale committed progress look fresh.

The observer uses actual read-only daemon functions and status entry, never a
worker callback. This proves detection, not automatic service recovery.
"""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_self_progress import stabilityd


class ExternalProgressObserverTests(unittest.TestCase):
    def test_live_stalled_worker_is_observed_without_waiting_for_its_next_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            latest = root / 'latest.json'
            old = int(time.time()) - stabilityd.STABILITYD_PROGRESS_STALE_SECONDS - 30
            latest.write_text(json.dumps({
                'generationId': 'fixture-stalled', 'completedAtEpoch': old,
                'policy': {'updatedAtEpoch': old, 'mode': 'observe'},
                'findings': [], 'actions': [],
            }))
            before = latest.read_bytes()
            worker = subprocess.Popen(
                [sys.executable, '-c', 'import time; time.sleep(60)'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                self.assertIsNone(worker.poll())
                with mock.patch.object(stabilityd, 'LATEST_PATH', latest), \
                     mock.patch.object(stabilityd, 'POLICY_PATH', root / 'policy.json'), \
                     mock.patch.object(stabilityd, 'init_db', side_effect=AssertionError('observer must not write DB')), \
                     mock.patch.object(stabilityd, 'run_once', side_effect=AssertionError('observer must not advance worker')), \
                     mock.patch.object(stabilityd, 'gateway_collect', side_effect=AssertionError('observer must not probe runtime')):
                    evidence = stabilityd.stabilityd_progress_evidence()
                    self.assertEqual(evidence['state'], 'stale_previous_generation')
                    self.assertEqual(evidence['previousGenerationId'], 'fixture-stalled')
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(stabilityd.main(['status']), 0)
                    summary = json.loads(output.getvalue())
                    self.assertGreater(summary['policyAgeSeconds'], stabilityd.STABILITYD_PROGRESS_STALE_SECONDS)
                self.assertIsNone(worker.poll())
                self.assertEqual(latest.read_bytes(), before)
                self.assertEqual(sorted(path.name for path in root.iterdir()), ['latest.json'])
            finally:
                worker.terminate()
                try:
                    worker.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.wait(timeout=2)
            self.assertIsNotNone(worker.returncode)


if __name__ == '__main__':
    unittest.main()
