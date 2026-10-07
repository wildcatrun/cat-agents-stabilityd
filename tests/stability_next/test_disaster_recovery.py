"""Fake host/runtime recovery rehearsals; never contacts live services."""

import os
import subprocess
import sys
import tempfile
import sqlite3
import unittest
from pathlib import Path
import textwrap

from stability_core.action_executor import (
    ActionExecutor, ActionSpec, AuthorizationGrant, BoundaryCheck, OperationResult, PostcheckResult,
)
from stability_core.action_ledger import ActionConflict, ActionLedger
from stability_core.authorization import EligibilityProof, STANDING_RULES, TrustedPolicyAuthorizer, _digest
from stability_core.protected_scope import resolve_protection_scope


class DisasterRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "recovery.db"
        self.effects = []

    def tearDown(self):
        self.tmp.cleanup()

    def spec(self, key="restart-1", generation="boot-1"):
        return ActionSpec(
            idempotency_key=key, action_type="fake-runtime-repair", target="fake-host/gateway",
            generation=generation, source="fixture", input_data={"kind": "restart"},
            authorization_ref="auth://fixture", policy_ref="policy://fixture",
            evidence_refs=("evidence://fixture",), metadata={"request_source": "fixture"},
        )

    def executor(self, ledger, *, authorize=None, operation=None):
        def grant(spec, record):
            return AuthorizationGrant(
                status="authorized", authorization_ref=spec.authorization_ref,
                policy_ref=spec.policy_ref, action_type=spec.action_type, target=spec.target,
                generation=spec.generation, source=spec.source, input_digest=record.input_digest,
                evidence_refs=spec.evidence_refs, expires_at_ms=999999,
            )
        return ActionExecutor(
            ledger, authorizer=authorize or grant,
            precheck=lambda *_: BoundaryCheck("approved", "check://fake-host-protection"),
            operation=operation or self._effect,
            postcheck=lambda *_: PostcheckResult("verified", "check://fake-host-ready"),
            clock_ms=lambda: 1000,
        )

    def _effect(self, *_):
        self.effects.append("invoked")
        return OperationResult("complete", "outcome://fake/complete")

    def test_daemon_crash_and_host_offline_never_replay_durable_executing_action(self):
        spec = self.spec()
        with ActionLedger(self.path) as ledger:
            record = ledger.plan_action(
                idempotency_key=spec.idempotency_key, action_type=spec.action_type,
                target=spec.target, generation=spec.generation, input_data=spec.input_data,
                authorization_ref=spec.authorization_ref, policy_ref=spec.policy_ref,
                evidence_refs=spec.evidence_refs, metadata=spec.metadata,
            )
            ledger.begin_execution(record.action_id, expected_version=record.version,
                                   precheck_ref="check://before-crash")
        # Reopen simulates daemon recovery after host/network loss.
        with ActionLedger(self.path) as reopened:
            result = self.executor(reopened).execute(spec)
            self.assertEqual((result.disposition, result.record.state), ("existing", "executing"))
        self.assertEqual(self.effects, [])

    def test_wal_backup_api_preserves_durable_executing_intent_on_restore(self):
        spec = self.spec(key="wal-restore-fixture", generation="fake-host-generation")
        backup_path = Path(self.tmp.name) / "recovery-backup.db"
        restored_path = Path(self.tmp.name) / "recovery-restored.db"
        with ActionLedger(self.path) as ledger:
            record = ledger.plan_action(
                idempotency_key=spec.idempotency_key, action_type=spec.action_type,
                target=spec.target, generation=spec.generation, input_data=spec.input_data,
                authorization_ref=spec.authorization_ref, policy_ref=spec.policy_ref,
                evidence_refs=spec.evidence_refs, metadata=spec.metadata,
            )
            ledger.begin_execution(record.action_id, expected_version=record.version,
                                   precheck_ref="check://wal-fixture")
            source = sqlite3.connect(self.path)
            backup = sqlite3.connect(backup_path)
            try:
                self.assertEqual(source.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
                source.execute("PRAGMA wal_autocheckpoint=0")
                wal_path = Path(str(self.path) + "-wal")
                self.assertTrue(wal_path.exists())
                self.assertGreater(wal_path.stat().st_size, 32, "fixture must contain committed WAL frames")
                source.backup(backup)
                self.assertEqual(backup.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            finally:
                source.close()
                backup.close()
        with sqlite3.connect(backup_path) as backup, sqlite3.connect(restored_path) as restored:
            backup.backup(restored)
            self.assertEqual(restored.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        with ActionLedger(restored_path) as recovered:
            restored_record = recovered.get(record.action_id)
            self.assertIsNotNone(restored_record)
            self.assertEqual(restored_record.state, "executing")
            self.assertEqual(restored_record.precheck_ref, "check://wal-fixture")
            retry = self.executor(recovered).execute(spec)
            self.assertEqual((retry.record.state, retry.disposition), ("executing", "existing"))
        self.assertEqual(self.effects, [])

    def test_process_crash_after_durable_synthetic_effect_does_not_replay(self):
        idempotency_key = "crash-after-synthetic-effect"
        marker_path = Path(self.tmp.name) / "effect-marker.txt"
        child = textwrap.dedent("""
            import os
            import sys
            from stability_core.action_executor import ActionExecutor, ActionSpec, AuthorizationGrant, BoundaryCheck
            from stability_core.action_ledger import ActionLedger

            database_path, marker_path = sys.argv[1], sys.argv[2]
            spec = ActionSpec(
                idempotency_key="crash-after-synthetic-effect",
                action_type="fake-runtime-repair",
                target="fake-host/gateway",
                generation="boot-1",
                source="fixture",
                input_data={"kind": "restart"},
                authorization_ref="auth://fixture",
                policy_ref="policy://fixture",
                evidence_refs=("evidence://fixture",),
                metadata={"request_source": "fixture"},
            )

            def authorize(action, record):
                return AuthorizationGrant(
                    "authorized", action.authorization_ref, action.policy_ref,
                    action.action_type, action.target, action.generation,
                    action.source, record.input_digest, action.evidence_refs, 2_000_000,
                )

            def fake_effect(_action, _record):
                with open(marker_path, "a", encoding="utf-8") as marker:
                    marker.write("effect\\n")
                    marker.flush()
                    os.fsync(marker.fileno())
                os._exit(73)

            with ActionLedger(database_path) as ledger:
                executor = ActionExecutor(
                    ledger,
                    authorizer=authorize,
                    precheck=lambda *_: BoundaryCheck("approved", "check://synthetic-before-effect"),
                    operation=fake_effect,
                    postcheck=lambda *_: None,
                    clock_ms=lambda: 1_000_000,
                )
                executor.execute(spec)
            raise SystemExit(74)
        """)
        environment = {
            "PATH": os.defpath,
            "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        result = subprocess.run(
            [sys.executable, "-c", child, str(self.path), str(marker_path)],
            cwd=str(Path(__file__).resolve().parents[2]),
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertEqual(marker_path.read_text(encoding="utf-8"), "effect\n")

        spec = self.spec(key=idempotency_key)
        action_id = ActionLedger.stable_action_id(idempotency_key)
        with ActionLedger(self.path) as recovered:
            record = recovered.get(action_id)
            self.assertIsNotNone(record)
            self.assertEqual(record.state, "executing")
            retry = self.executor(recovered).execute(spec)
            self.assertEqual((retry.disposition, retry.record.state), ("existing", "executing"))

        self.assertEqual(marker_path.read_text(encoding="utf-8"), "effect\n")
        self.assertEqual(self.effects, [])

    def test_uncertain_prior_generation_holds_target_after_restart(self):
        with ActionLedger(self.path) as ledger:
            old = self.spec("old-action", "boot-1")
            record = ledger.plan_action(
                idempotency_key=old.idempotency_key, action_type=old.action_type,
                target=old.target, generation=old.generation, input_data=old.input_data,
                authorization_ref=old.authorization_ref, policy_ref=old.policy_ref,
                evidence_refs=old.evidence_refs, metadata=old.metadata,
            )
            executing = ledger.begin_execution(record.action_id, expected_version=record.version,
                                               precheck_ref="check://pre")
            ledger.transition(executing.action_id, expected_state="executing",
                              expected_version=executing.version, new_state="uncertain",
                              outcome_ref="outcome://unknown", postcheck_ref="check://unknown")
            new = self.spec("new-action", "boot-2")
            with self.assertRaises(ActionConflict):
                ledger.plan_action(
                    idempotency_key=new.idempotency_key, action_type=new.action_type,
                    target=new.target, generation=new.generation, input_data=new.input_data,
                    authorization_ref=new.authorization_ref, policy_ref=new.policy_ref,
                    evidence_refs=new.evidence_refs, metadata=new.metadata,
                )
        self.assertEqual(self.effects, [])

    def test_runtime_generation_change_at_final_fence_blocks_fake_restart(self):
        with ActionLedger(self.path) as ledger:
            host_generation = ["boot-1"]
            authorizer_calls = [0]

            def live_authorizer(spec, record):
                authorizer_calls[0] += 1
                if host_generation[0] != spec.generation:
                    return AuthorizationGrant(
                        status="denied", authorization_ref=spec.authorization_ref,
                        policy_ref=spec.policy_ref, action_type=spec.action_type, target=spec.target,
                        generation=spec.generation, source=spec.source, input_digest=record.input_digest,
                        evidence_refs=spec.evidence_refs, expires_at_ms=999999,
                    )
                return self.executor(ledger)._authorizer(spec, record)

            executor = self.executor(ledger, authorize=live_authorizer)
            # Fake reboot occurs after initial checks but before the final fence.
            def rebooting_precheck(*_):
                host_generation[0] = "boot-2"
                return BoundaryCheck("approved", "check://old-boot")
            executor._precheck = rebooting_precheck
            result = executor.execute(self.spec(generation="boot-1"))
            self.assertEqual((result.record.state, result.disposition), ("blocked", "blocked"))
            self.assertGreaterEqual(authorizer_calls[0], 2)
        self.assertEqual(self.effects, [])

    def test_trusted_policy_and_registry_protection_block_protected_gateway_fixture(self):
        now_ms = 1_050_000
        policy = {"canRestartGateway": True, "updatedAtEpoch": 1000, "validUntilEpoch": 1100}
        digest = _digest(policy)
        policy_ref = f"stabilityd-policy://sha256/{digest}"
        target = "openclaw-gateway:dev-server"
        action_type = "openclaw.gateway.restart"
        evidence = ("evidence://registry-snapshot", policy_ref, f"policy-digest:sha256:{digest}")
        rule = STANDING_RULES[action_type]

        def evaluate(spec, _policy, policy_digest, checked_at):
            return EligibilityProof(
                action_type=spec.action_type, target=spec.target, generation=spec.generation,
                input_digest=_digest(spec.input_data), policy_digest=policy_digest,
                evidence_refs=("evidence://registry-snapshot",), checked_at_ms=checked_at,
                expires_at_ms=checked_at + 20_000, eligible=True,
            )

        authorizer = TrustedPolicyAuthorizer(
            policy_reader=lambda: policy, eligibility_evaluator=evaluate,
            source="stabilityd-daemon", clock_ms=lambda: now_ms,
        )
        spec = ActionSpec(
            idempotency_key="protected-gateway-fixture", action_type=action_type, target=target,
            generation="fake-boot-1", source="stabilityd-daemon", input_data={"reason": "fixture"},
            authorization_ref=rule.authority_ref, policy_ref=policy_ref, evidence_refs=evidence,
            metadata={"request_source": "stabilityd-daemon"},
        )
        registry_records = [{
            "agent_id": "cat_voice", "runtime": "openclaw", "platform": "openclaw",
            "execution_adapter": "openclaw", "endpoint_ref": "openclaw-agent:cat_voice", "status": "active",
        }]
        protection_checks = [0]

        def protection_precheck(*_):
            protection_checks[0] += 1
            current_records = registry_records if protection_checks[0] == 1 else [{
                "agent_id": "main", "runtime": "openclaw", "platform": "openclaw",
                "execution_adapter": "openclaw", "endpoint_ref": "openclaw-agent:main", "status": "active",
            }]
            decision = resolve_protection_scope(
                current_records, registry_source="db", registry_write_eligible=True,
                scope_complete=True, target_kind="shared-gateway", target_id="dev-server",
                runtime="openclaw", target_generation="fake-boot-1",
            )
            if decision.status != "clear":
                return BoundaryCheck("rejected", f"check://protection/{decision.status}")
            return BoundaryCheck("approved", "check://protection/clear")

        with ActionLedger(self.path) as ledger:
            executor = ActionExecutor(
                ledger, authorizer=authorizer, precheck=protection_precheck,
                operation=self._effect,
                postcheck=lambda *_: PostcheckResult("verified", "check://fake-ready"),
                clock_ms=lambda: now_ms,
            )
            result = executor.execute(spec)
            self.assertEqual((result.record.state, result.disposition), ("blocked", "blocked"))
            self.assertEqual(result.record.precheck_ref, "check://protection/protected")
            self.assertEqual(protection_checks[0], 2)
        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main()
