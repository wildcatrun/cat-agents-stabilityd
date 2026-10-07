import tempfile
import unittest
from pathlib import Path
from stability_core.action_executor import (
    ActionExecutor, ActionSpec, BoundaryCheck, OperationResult, PostcheckResult,
)
from stability_core.action_ledger import ActionLedger
from stability_core.authorization import (
    EligibilityProof, STANDING_RULES, TrustedPolicyAuthorizer, _digest,
)
from stability_core.protected_scope import resolve_protection_scope


class OfflineDualGateTests(unittest.TestCase):
    def setUp(self):
        self.now_ms = 2_000_000_000_000
        self.policy = {
            "updatedAtEpoch": self.now_ms // 1000 - 1,
            "validUntilEpoch": self.now_ms // 1000 + 60,
            "hermersProfileModeActuateEnabled": True,
        }
        self.registry = {
            "source": "db",
            "writeEligible": True,
            "scopeComplete": True,
            "generation": "profile-generation-1",
            "records": [{
                "agent_id": "cat_nose",
                "runtime": "hermes_acp",
                "platform": "hermes",
                "execution_adapter": "hermes_acp",
                "endpoint_ref": "hermes-profile:catnose",
                "status": "active",
            }],
        }

    def run_synthetic_action(self, *, policy_available=True, registry=None):
        policy = dict(self.policy)
        policy_digest = _digest(policy)
        policy_ref = f"stabilityd-policy://sha256/{policy_digest}"
        evidence_ref = f"evidence://registry/snapshot/{self.registry['generation']}"
        rule = STANDING_RULES["hermes.profile.lifecycle"]
        spec = ActionSpec(
            idempotency_key=f"offline-dual-gate:{policy_available}:{registry is not None}",
            action_type="hermes.profile.lifecycle",
            target="hermes-profile:catnose",
            generation=self.registry["generation"],
            source="stabilityd-daemon",
            input_data={"requestedMode": "warm", "reason": "synthetic-necessary-governance"},
            authorization_ref=rule.authority_ref,
            policy_ref=policy_ref,
            evidence_refs=(evidence_ref, policy_ref, f"policy-digest:sha256:{policy_digest}"),
        )

        def policy_reader():
            if not policy_available:
                raise OSError("local cached authorization is unavailable")
            local_policy_reads.append("local-policy")
            return policy

        def eligibility(spec_arg, _policy, digest, checked_at):
            return EligibilityProof(
                action_type=spec_arg.action_type,
                target=spec_arg.target,
                generation=spec_arg.generation,
                input_digest=_digest(spec_arg.input_data),
                policy_digest=digest,
                evidence_refs=(evidence_ref,),
                checked_at_ms=checked_at,
                expires_at_ms=checked_at + 20_000,
                eligible=True,
            )

        authorizer = TrustedPolicyAuthorizer(
            policy_reader=policy_reader,
            eligibility_evaluator=eligibility,
            source="stabilityd-daemon",
            clock_ms=lambda: self.now_ms,
        )
        local_policy_reads = []
        executed = []

        def precheck(action, _record):
            if registry is None or registry.get("generation") != action.generation:
                return BoundaryCheck("unknown", "protection://owner-snapshot-generation-mismatch")
            source = "snapshot" if registry is None else registry["source"]
            rows = [] if registry is None else registry["records"]
            decision = resolve_protection_scope(
                rows,
                registry_source=source,
                registry_write_eligible=registry is not None and registry["writeEligible"],
                scope_complete=registry is not None and registry["scopeComplete"],
                target_kind="profile",
                target_id="catnose",
                runtime="hermes_acp",
                target_generation=action.generation,
            )
            if decision.status != "clear" or decision.target_generation != action.generation:
                return BoundaryCheck("unknown", "protection://owner-scope-unavailable")
            return BoundaryCheck(
                "approved", f"protection://owner-scope/clear/{registry['generation']}"
            )

        with tempfile.TemporaryDirectory() as tmpdir, ActionLedger(Path(tmpdir) / "actions.sqlite3") as ledger:
            executor = ActionExecutor(
                ledger,
                authorizer=authorizer,
                precheck=precheck,
                operation=lambda *_: (executed.append("local-fixture-operation")
                                      or OperationResult("complete", "outcome://fixture/warmed")),
                postcheck=lambda *_: PostcheckResult("verified", "postcheck://fixture/ready"),
                clock_ms=lambda: self.now_ms,
            )
            result = executor.execute(spec)

        return result, executed, local_policy_reads

    def test_local_authority_and_complete_owner_snapshot_allow_without_remote_dependency(self):
        result, executed, local_policy_reads = self.run_synthetic_action(registry=self.registry)
        self.assertEqual(result.disposition, "executed")
        self.assertEqual(result.record.state, "succeeded")
        self.assertEqual(executed, ["local-fixture-operation"])
        self.assertEqual(local_policy_reads, ["local-policy", "local-policy"])

    def test_missing_either_local_gate_blocks_without_operation(self):
        cases = (
            ("local-authorization-unavailable", False, self.registry),
            ("protection-snapshot-unknown", True, None),
            ("protection-snapshot-generation-mismatch", True,
             {**self.registry, "generation": "previous-profile-generation"}),
        )
        for label, policy_available, registry in cases:
            with self.subTest(gate=label):
                result, executed, _local_policy_reads = self.run_synthetic_action(
                    policy_available=policy_available,
                    registry=registry,
                )
                self.assertEqual(result.disposition, "blocked")
                self.assertEqual(result.record.state, "blocked")
                self.assertEqual(executed, [])


if __name__ == "__main__":
    unittest.main()
