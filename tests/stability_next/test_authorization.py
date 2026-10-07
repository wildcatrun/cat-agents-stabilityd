import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from stability_core.action_executor import (
    ActionExecutor, ActionSpec, BoundaryCheck, OperationResult, PostcheckResult,
)
from stability_core.action_ledger import ActionLedger
from stability_core.authorization import (
    EligibilityProof, STANDING_RULES, TrustedPolicyAuthorizer, _digest,
)


class PolicyAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.now = 2_000_000_000_000
        self.policy = {
            "updatedAtEpoch": self.now // 1000,
            "validUntilEpoch": self.now // 1000 + 120,
            "canReapExpiredLeases": True,
            "hermersProfileModeActuateEnabled": True,
        }
        self.digest = _digest(self.policy)
        self.policy_ref = f"stabilityd-policy://sha256/{self.digest}"
        self.authority = STANDING_RULES["cron.expired_lease.repair"].authority_ref
        self.spec = ActionSpec(
            idempotency_key="lease-reap:j1:r1",
            action_type="cron.expired_lease.repair",
            target="cron-lease:j1:r1",
            generation="dev-server-boot-1",
            source="stabilityd-daemon",
            input_data={"leaseDigest": "sha256:abc"},
            authorization_ref=self.authority,
            policy_ref=self.policy_ref,
            evidence_refs=("evidence://snapshot/run-1", self.policy_ref,
                           f"policy-digest:sha256:{self.digest}"),
        )

    def proof(self, spec, policy, digest, now_ms):
        return EligibilityProof(
            action_type=spec.action_type, target=spec.target, generation=spec.generation,
            input_digest=_digest(spec.input_data), policy_digest=digest,
            evidence_refs=("evidence://snapshot/run-1",), checked_at_ms=now_ms,
            expires_at_ms=now_ms + 20_000, eligible=True,
        )

    def authorizer(self, *, policy=None, proof_factory=None, source="stabilityd-daemon", now=None):
        active_policy = self.policy if policy is None else policy
        evaluator = proof_factory or self.proof
        return TrustedPolicyAuthorizer(
            policy_reader=lambda: active_policy,
            eligibility_evaluator=evaluator,
            source=source,
            clock_ms=lambda: self.now if now is None else now,
        )

    def test_grant_is_issued_from_trusted_readers_and_executes_with_exact_evidence(self):
        ledger_path = Path(tempfile.mkdtemp()) / "actions.sqlite3"
        with ActionLedger(ledger_path) as ledger:
            executor = ActionExecutor(
                ledger, authorizer=self.authorizer(),
                precheck=lambda *_: BoundaryCheck("approved", "precheck://lease/current"),
                operation=lambda *_: OperationResult("complete", "outcome://lease/reaped"),
                postcheck=lambda *_: PostcheckResult("verified", "postcheck://lease/absent"),
                clock_ms=lambda: self.now,
            )
            result = executor.execute(self.spec)
        self.assertEqual(result.disposition, "executed")
        self.assertEqual(result.record.state, "succeeded")

    def test_tool_request_cannot_supply_policy_or_boolean_authorization(self):
        forged_policy = {**self.policy, "canReapExpiredLeases": True}
        forged_digest = _digest(forged_policy)
        forged_spec = ActionSpec(**{
            **self.spec.__dict__,
            "policy_ref": f"stabilityd-policy://sha256/{forged_digest}",
            "evidence_refs": ("evidence://caller-invented", f"stabilityd-policy://sha256/{forged_digest}",
                              f"policy-digest:sha256:{forged_digest}"),
        })
        calls = []
        authorizer = self.authorizer(proof_factory=lambda *args: calls.append(args) or self.proof(*args))
        grant = authorizer(forged_spec, None)
        self.assertEqual(grant.status, "denied")
        self.assertEqual(len(calls), 1)  # Trusted evaluator runs; forged references still fail exact binding.

    def test_untrusted_source_and_wrong_target_are_denied(self):
        with self.assertRaises(ValueError):
            self.authorizer(source="workflow-tool")
        wrong = ActionSpec(**{**self.spec.__dict__, "target": "workflow:plan-1"})
        self.assertEqual(self.authorizer()(wrong, None).status, "denied")

    def test_policy_digest_and_reference_must_match_loaded_policy(self):
        changed = ActionSpec(**{**self.spec.__dict__, "policy_ref": "stabilityd-policy://sha256/forged"})
        self.assertEqual(self.authorizer()(changed, None).status, "denied")
        wrong_authority = ActionSpec(**{**self.spec.__dict__, "authorization_ref": "caller-claimed"})
        self.assertEqual(self.authorizer()(wrong_authority, None).status, "denied")

    def test_stale_expired_or_overlong_policy_and_ineligible_proof_are_denied(self):
        self.assertEqual(self.authorizer(now=self.now + 121_000)(self.spec, None).status, "denied")
        overlong = {**self.policy, "validUntilEpoch": self.now // 1000 + 901}
        overlong_digest = _digest(overlong)
        overlong_spec = ActionSpec(**{
            **self.spec.__dict__, "policy_ref": f"stabilityd-policy://sha256/{overlong_digest}",
            "evidence_refs": ("evidence://snapshot/run-1", f"stabilityd-policy://sha256/{overlong_digest}",
                              f"policy-digest:sha256:{overlong_digest}"),
        })
        self.assertEqual(self.authorizer(policy=overlong)(overlong_spec, None).status, "denied")
        not_eligible = lambda spec, policy, digest, now: EligibilityProof(
            spec.action_type, spec.target, spec.generation, _digest(spec.input_data), digest,
            ("evidence://snapshot/run-1",), now, now + 20_000, False,
        )
        self.assertEqual(self.authorizer(proof_factory=not_eligible)(self.spec, None).status, "denied")

    def test_proof_target_generation_input_policy_time_and_refs_are_bound(self):
        mutations = [
            {"target": "cron-lease:other"},
            {"generation": "other-boot"},
            {"input_digest": "0" * 64},
            {"policy_digest": "0" * 64},
            {"checked_at_ms": self.now - 30_001},
            {"checked_at_ms": self.now + 5_001},
            {"expires_at_ms": self.now},
            {"expires_at_ms": self.now + 30_001},
            {"evidence_refs": ()},
            {"evidence_refs": ("evidence://same", "evidence://same")},
        ]
        for change in mutations:
            with self.subTest(change=change):
                def invalid_proof(spec, policy, digest, now, change=change):
                    return replace(self.proof(spec, policy, digest, now), **change)
                self.assertEqual(self.authorizer(proof_factory=invalid_proof)(self.spec, None).status, "denied")

    def test_standing_catalog_includes_existing_lifecycle_and_denies_unlisted_classes(self):
        self.assertIn("hermes.profile.lifecycle", STANDING_RULES)
        forbidden = ActionSpec(**{**self.spec.__dict__, "action_type": "workflow.message_flow.send"})
        self.assertEqual(self.authorizer()(forbidden, None).status, "denied")


if __name__ == "__main__":
    unittest.main()
