"""Finite synthetic two-node recovery composition, without a transport runtime.

The local list represents disconnected delivery, not a new retry mechanism.
Observation envelopes never authorize actions. Existing executor intent identity
and actual restart policy are checked alongside ingestion at each replay stage.
Large forward wall-clock leaps beyond the cooldown deadline are NOT qualified by
this test: policy has no independent wall/monotonic comparison (separate finding).
"""
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from stability_core.observation_adapter_contract import (
    ProducerGrant, evidence_digest, ingest_synthetic_observation,
)
from stability_core.observation_store import load_observation_records
from stability_core.action_ledger import ActionLedger
from stability_core.action_executor import (
    ActionExecutor, ActionSpec, AuthorizationGrant, BoundaryCheck, OperationResult, PostcheckResult,
)
import test_policy_cli_golden as policy_golden


class MultiNodeRecoveryClockTests(unittest.TestCase):
    def test_disconnected_batch_duplicate_reordered_recovery_preserves_receipts_actions_and_cooldown(self):
        nodes = ('fixture-dev', 'fixture-wsl')
        generations = {node: hashlib.sha256(node.encode()).hexdigest() for node in nodes}
        grants = {'fixture-producer':ProducerGrant('v1', frozenset(nodes))}
        evidence = {'coverage':True, 'sampleCount':1}
        def envelope(node, seq, observed):
            return {'producerId':'fixture-producer','adapterVersion':'v1','nodeId':node,
                    'sourceKind':'synthetic-fixture','eventId':hashlib.sha256((node+seq).encode()).hexdigest(),
                    'generationDigest':generations[node], 'evidenceDigest':evidence_digest(evidence),
                    'observedAtEpoch':observed,'evidence':dict(evidence)}
        effects, authorization_calls = [], []
        def authorize(s, r):
            authorization_calls.append(s.target)
            return AuthorizationGrant('authorized',s.authorization_ref,s.policy_ref,s.action_type,
                s.target,s.generation,s.source,r.input_digest,s.evidence_refs,99999999)
        def operation(s, _):
            effects.append(s.target)
            return OperationResult('complete','outcome://fixture-complete')
        specs = [ActionSpec('fixture-repair-'+node,'fixture-repair',node,generations[node],
                 'fixture',{'synthetic':True},'auth://fixture','policy://fixture',('evidence://fixture',))
                 for node in nodes]
        policy_fixture = policy_golden.PolicyCliGoldenTests()
        with tempfile.TemporaryDirectory() as tmp, \
             sqlite3.connect(str(Path(tmp)/'observations.db')) as conn, \
             ActionLedger(Path(tmp)/'actions.db') as ledger:
            executor = ActionExecutor(ledger, authorizer=authorize,
                precheck=lambda *_:BoundaryCheck('approved','check://fixture'), operation=operation,
                postcheck=lambda *_:PostcheckResult('verified','check://fixture-ready'),clock_ms=lambda:1000)
            initial_ids = []
            for spec in specs:
                first = executor.execute(spec)
                self.assertEqual(first.disposition,'executed')
                initial_ids.append(first.record.action_id)
            def ingest(record, now):
                result = ingest_synthetic_observation(conn,record,trusted_producer_id='fixture-producer',
                    grants=grants,current_generations=generations,now_epoch=now)
                self.assertFalse(result['actionReplay'])
                self.assertFalse(result['readinessEvaluated'])
                return result
            for node in nodes:
                ingest(envelope(node,'initial',10000),10000)
            # Offline: nothing is ingested; two per-node source observations queue locally.
            pending = [(envelope(node,'newer',10060), envelope(node,'older',9990)) for node in nodes]
            self.assertEqual(len(load_observation_records(conn)),2)
            for newer, older in pending:
                ingest(newer,10080)
                late = ingest(older,10080)
                self.assertNotEqual(late['observationFreshness'],'fresh')
            rows = load_observation_records(conn)
            self.assertEqual(len(rows),6)
            first_receipts = {r['eventId']:r['receivedAtEpoch'] for r in rows}
            for now in (10081,9950,11799):
                # Replay in reverse node/order; receipts remain the first receiver time.
                for newer, older in reversed(pending):
                    old_retry = ingest(older,now)
                    self.assertNotEqual(old_retry['observationFreshness'],'fresh')
                    ingest(newer,now)
                current = load_observation_records(conn)
                self.assertEqual(len(current),6)
                self.assertEqual({r['eventId']:r['receivedAtEpoch'] for r in current},first_receipts)
                if now == 9950:
                    self.assertTrue(all(r['status']=='clock-invalid' for r in current))
                for spec, action_id in zip(specs,initial_ids):
                    retry = executor.execute(spec)
                    self.assertEqual((retry.disposition,retry.record.state,retry.record.action_id),
                                     ('existing','succeeded',action_id))
                policy = policy_fixture._restart_policy(now=now,last_restart=10000)
                self.assertFalse(policy['canRestartGateway'])
                self.assertEqual(policy['cooldownUntilEpoch'],11800)
                self.assertIn('cooldown',policy['restartBlockedReasons'])
            self.assertEqual(effects,list(nodes))
            # Replays must not even re-enter authorization, let alone the operation.
            self.assertEqual(authorization_calls,[node for node in nodes for _ in range(2)])
            self.assertEqual(ledger._conn.execute('SELECT count(*) FROM action_ledger').fetchone()[0],2)


if __name__ == '__main__':
    unittest.main()
