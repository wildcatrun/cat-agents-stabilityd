"""Crash the real executor between an external effect and its result commit."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from stability_core.action_executor import ActionExecutor, ActionSpec
from stability_core.action_ledger import ActionLedger


CHILD = r'''
import os, sys
from pathlib import Path
from stability_core.action_executor import ActionExecutor, ActionSpec, AuthorizationGrant, BoundaryCheck
from stability_core.action_ledger import ActionLedger
db, effect = map(Path, sys.argv[1:])
spec = ActionSpec('crash-effect', 'fixture-repair', 'fixture/node', 'g1', 'stabilityd',
                  {'fixture': True}, 'auth://fixture', 'policy://fixture', ('evidence://fixture',))
def authorize(spec, record):
    return AuthorizationGrant('authorized', spec.authorization_ref, spec.policy_ref,
        spec.action_type, spec.target, spec.generation, spec.source, record.input_digest,
        spec.evidence_refs, 2000)
def operation(spec, record):
    # Exclusive durable file creation models a non-repeatable external effect.
    with effect.open('x') as handle:
        handle.write(record.action_id + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(effect.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
    # No executor exception handler, result/postcheck, or ledger close runs.
    os._exit(73)
with ActionLedger(db) as ledger:
    executor = ActionExecutor(ledger, authorizer=authorize,
        precheck=lambda *_: BoundaryCheck('approved', 'check://fixture'),
        operation=operation,
        postcheck=lambda *_: (_ for _ in ()).throw(RuntimeError('must not reach postcheck')),
        clock_ms=lambda: 1000)
    executor.execute(spec)
'''


class ProcessCrashTests(unittest.TestCase):
    def test_effect_then_abrupt_exit_keeps_claim_and_never_replays(self):
        repo = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            db, effect = Path(directory) / 'state.db', Path(directory) / 'effect.txt'
            env = dict(os.environ, PYTHONPATH=str(repo), PYTHONDONTWRITEBYTECODE='1')
            completed = subprocess.run([sys.executable, '-c', CHILD, str(db), str(effect)],
                                       cwd=repo, env=env, capture_output=True, timeout=15)
            self.assertEqual(completed.returncode, 73, completed.stderr.decode())
            action_id = effect.read_text().strip()
            original_bytes = effect.read_bytes()
            spec = ActionSpec('crash-effect', 'fixture-repair', 'fixture/node', 'g1', 'stabilityd',
                              {'fixture': True}, 'auth://fixture', 'policy://fixture', ('evidence://fixture',))
            callback_hits = []
            def forbidden(*_):
                callback_hits.append(True)
                self.fail('unreconciled executing action must not invoke callbacks')
            # Two distinct process-independent reopenings exercise recovery and
            # repeated recovery without authorizing a second effect.
            versions = []
            for _ in range(2):
                with ActionLedger(db) as ledger:
                    executor = ActionExecutor(ledger, authorizer=forbidden, precheck=forbidden,
                                              operation=forbidden, postcheck=forbidden,
                                              clock_ms=lambda: 1000)
                    result = executor.execute(spec)
                    self.assertEqual(result.disposition, 'existing')
                    self.assertEqual(result.record.state, 'executing')
                    self.assertEqual(result.record.action_id, action_id)
                    versions.append(result.record.version)
                    self.assertEqual(effect.read_bytes(), original_bytes)
            self.assertEqual(versions[0], versions[1])
            self.assertEqual(callback_hits, [])


if __name__ == '__main__':
    unittest.main()
