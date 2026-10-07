import dataclasses
import math
import unittest

from stability_core.release_gate import ReleaseEvidence, compare_shadow_results, qualify_release


class ReleaseGateTests(unittest.TestCase):
    def evidence(self):
        return ReleaseEvidence(
            installed_version="0.1.0", candidate_version="1.0.0",
            installed_commit="a" * 40, candidate_commit="b" * 40,
            loaded_commit="b" * 40, loaded_generation="g1", candidate_generation="g1",
            candidate_tree_clean=True, candidate_commit_pinned=True,
            artifact_sha256="c" * 64, previous_artifact_sha256="d" * 64,
            tests_passed=True, independent_review_passed=True,
            loaded_generation_verified=True, schema_backward_compatible=True,
            migration_reversible=True, action_ledger_recovery_verified=True,
            rollback_artifact_available=True, auto_update_change_requires_g2=True,
        )

    def shadow(self, **overrides):
        payload = {
            "executionMode": "shadow",
            "findings": [{"key": "existing-critical", "severity": "critical"}],
            "coverage": ["gateway", "registry", "hermes"],
            "durationMs": 1000,
            "actions": [{"action": "restart_gateway", "target": "dev-server", "wouldAct": False}],
        }
        payload.update(overrides)
        return payload

    def test_release_only_qualifies_for_separate_g2_review_and_never_activates(self):
        result = qualify_release(self.evidence())
        self.assertEqual(result.status, "eligible_for_g2_review")
        self.assertFalse(result.activation_authorized)
        self.assertEqual(result.candidate_commit, "b" * 40)

    def test_dirty_unpinned_unreviewed_or_unrecoverable_candidate_is_blocked(self):
        evidence = dataclasses.replace(
            self.evidence(), candidate_tree_clean=False, candidate_commit_pinned=False,
            independent_review_passed=False, migration_reversible=False,
            action_ledger_recovery_verified=False, auto_update_change_requires_g2=False,
        )
        decision = qualify_release(evidence)
        self.assertEqual(decision.status, "blocked")
        self.assertIn("candidate-tree-dirty", decision.reasons)
        self.assertIn("candidate-commit-not-pinned", decision.reasons)
        self.assertIn("independent-review-incomplete", decision.reasons)
        self.assertIn("migration-rollback-unproven", decision.reasons)
        self.assertIn("automatic-updater-scope-not-separated", decision.reasons)
        self.assertFalse(decision.activation_authorized)

    def test_version_digest_and_boolean_fields_are_strict(self):
        invalid = dataclasses.replace(self.evidence(), candidate_version="0.1.0",
                                      artifact_sha256="bad", tests_passed=1)
        decision = qualify_release(invalid)
        self.assertEqual(decision.status, "blocked")
        self.assertIn("candidate-version-not-forward", decision.reasons)
        self.assertIn("candidate-artifact-digest-invalid", decision.reasons)
        self.assertIn("quality-checks-incomplete", decision.reasons)

    def test_candidate_commit_and_loaded_generation_must_match(self):
        invalid = dataclasses.replace(self.evidence(), loaded_commit="a" * 40,
                                      loaded_generation="old", candidate_generation="new")
        decision = qualify_release(invalid)
        self.assertIn("loaded-commit-does-not-match-candidate", decision.reasons)
        self.assertIn("loaded-generation-does-not-match-candidate", decision.reasons)

    def test_existing_critical_is_not_a_new_regression(self):
        result = compare_shadow_results(self.shadow(), self.shadow(durationMs=1100))
        self.assertEqual(result.status, "comparable")
        self.assertEqual(result.introduced_critical, ())

    def test_new_critical_coverage_loss_and_new_predicted_effect_block(self):
        baseline = self.shadow()
        new_critical = self.shadow(findings=[{"key": "new", "severity": "critical"}])
        self.assertIn("new-critical-finding", compare_shadow_results(baseline, new_critical).reasons)
        coverage_loss = self.shadow(coverage=["gateway"])
        self.assertIn("coverage-regressed", compare_shadow_results(baseline, coverage_loss).reasons)
        new_effect = self.shadow(actions=[{"action": "restart_gateway", "target": "dev-server", "wouldAct": True}])
        self.assertIn("shadow-added-actuator-effect", compare_shadow_results(baseline, new_effect).reasons)
        self.assertEqual(compare_shadow_results(baseline, new_effect).status, "blocked")

    def test_non_shadow_or_incomplete_evidence_is_blocked(self):
        non_shadow = compare_shadow_results(self.shadow(), self.shadow(executionMode="live"))
        self.assertEqual(non_shadow.status, "blocked")
        self.assertIn("non-shadow-snapshot", non_shadow.reasons)
        missing = compare_shadow_results({}, {})
        self.assertEqual(missing.status, "blocked")

    def test_latency_regression_is_degraded_without_rewriting_findings(self):
        result = compare_shadow_results(self.shadow(), self.shadow(durationMs=1400))
        self.assertEqual(result.status, "degraded")
        self.assertIn("latency-regressed", result.reasons)
        self.assertEqual(result.introduced_critical, ())

    def test_non_finite_latency_and_threshold_are_blocked(self):
        for value in (math.nan, math.inf, -math.inf, 10 ** 1000):
            with self.subTest(value=str(value)[:24]):
                result = compare_shadow_results(self.shadow(), self.shadow(durationMs=value))
                self.assertEqual(result.status, "blocked")
                self.assertIn("latency-evidence-invalid", result.reasons)
        self.assertEqual(compare_shadow_results(self.shadow(), self.shadow(), max_latency_ratio=math.nan).status,
                         "blocked")

    def test_malformed_duplicate_findings_coverage_and_actions_are_blocked(self):
        baseline = self.shadow()
        missing_key = self.shadow(findings=[{"severity": "critical"}])
        self.assertIn("findings-evidence-invalid", compare_shadow_results(baseline, missing_key).reasons)
        duplicate_keys = self.shadow(findings=[
            {"key": "duplicate", "severity": "critical"},
            {"key": "DUPLICATE", "severity": "warning"},
        ])
        self.assertEqual(compare_shadow_results(baseline, duplicate_keys).status, "blocked")
        malformed_coverage = self.shadow(coverage=["gateway", None])
        self.assertIn("coverage-evidence-invalid", compare_shadow_results(baseline, malformed_coverage).reasons)
        malformed_action = self.shadow(actions=[{"wouldAct": True, "action": "restart_gateway"}])
        self.assertIn("action-evidence-invalid", compare_shadow_results(baseline, malformed_action).reasons)
        string_flag = self.shadow(actions=[{"action": "restart_gateway", "target": "dev", "wouldAct": "true"}])
        result = compare_shadow_results(baseline, string_flag)
        self.assertEqual(result.status, "blocked")
        self.assertIn("action-evidence-invalid", result.reasons)


if __name__ == "__main__":
    unittest.main()
