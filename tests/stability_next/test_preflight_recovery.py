import hashlib
import tempfile
import unittest
from pathlib import Path

from stability_core.action_ledger import ActionLedger
from stability_core.preflight_recovery import (
    build_preflight_summary, build_recovery_summary, load_action_ledger_readonly,
)


class PreflightRecoveryTests(unittest.TestCase):
    def test_preflight_generation_mismatch_and_stale_evidence_block_review(self):
        result = build_preflight_summary(
            {"generationId": "g2", "completedAt": "2026-10-05T00:00:00Z", "severity": "low"},
            {"generationId": "g1", "mode": "observe"},
            {"coverage": {"observed": 0, "unknown": 2}},
            {"coverage": {"fixture": 1}},
            now_epoch=1_792_000_000, max_age_seconds=60,
        )
        self.assertEqual(result["preflightState"], "blocked")
        self.assertEqual(result["generation"]["state"], "mismatch")
        self.assertIn("generation-mismatch", result["blockers"])
        self.assertIn("evidence-stale", result["blockers"])
        self.assertFalse(result["policy"]["authorizationEvaluated"])
        self.assertFalse(result["dryRun"]["executed"])
        self.assertEqual(result["liveMutation"], "not-requested-and-not-performed")

    def test_preflight_missing_inputs_are_unknown_not_ready(self):
        result = build_preflight_summary({}, {}, {}, {}, now_epoch=100)
        self.assertEqual(result["preflightState"], "blocked")
        self.assertIn("generation-missing", result["blockers"])
        self.assertIn("evidence-unknown", result["blockers"])
        self.assertEqual(result["policy"]["authorizationEvaluated"], False)

    def test_future_generation_timestamp_is_not_fresh(self):
        result = build_preflight_summary(
            {"generationId": "g1", "completedAt": "2099-01-01T00:00:00Z", "severity": "ok"},
            {"generationId": "g1", "mode": "healthy"}, {}, {}, now_epoch=1_800_000_000,
        )
        self.assertEqual(result["evidence"]["freshness"], "future")
        self.assertLess(result["evidence"]["ageSeconds"], 0)
        self.assertEqual(result["preflightState"], "blocked")
        self.assertIn("evidence-future", result["blockers"])

    def test_readonly_ledger_view_redacts_target_and_metadata_and_preserves_uncertain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            with ActionLedger(path) as ledger:
                record = ledger.plan_action(
                    idempotency_key="fixture-idempotency", action_type="openclaw.session.reset",
                    target="session-key-private-sentinel", generation="host-boot-private-sentinel",
                    input_data={"sessionId": "session-private-sentinel"},
                    authorization_ref="governance://approved/session-reset",
                    policy_ref="stabilityd-policy://sha256/" + "a" * 64,
                    evidence_refs=("evidence://session/snapshot", "/private/raw/path-sentinel"),
                    metadata={"actor": "stabilityd-daemon"},
                )
                executing = ledger.begin_execution(record.action_id, expected_version=0)
                ledger.transition(executing.action_id, expected_state="executing", expected_version=1,
                                  new_state="uncertain")
            # SQLite may update transient WAL shared-memory lock marks while
            # opening a read-only reader; persistent DB/WAL content must stay stable.
            before = {item.name: item.read_bytes() for item in Path(directory).iterdir()
                      if item.is_file() and not item.name.endswith("-shm")}
            loaded = load_action_ledger_readonly(path, limit=10)
            after = {item.name: item.read_bytes() for item in Path(directory).iterdir()
                     if item.is_file() and not item.name.endswith("-shm")}
            summary = build_recovery_summary(
                loaded["records"], ledger_status=loaded["status"], limit=10,
                ledger_counts=loaded.get("counts"), total_candidate_count=loaded.get("candidateCount"),
            )
            self.assertEqual(loaded["status"], "available")
            self.assertEqual(before, after, "read-only ledger inspection changed database or sidecar bytes")
            self.assertEqual(summary["recoveryState"], "manual-reconciliation-required")
            self.assertEqual(summary["candidateCount"], 1)
            self.assertFalse(summary["automaticReplay"])
            rendered = str(summary)
            for secret in ("session-key-private-sentinel", "host-boot-private-sentinel",
                           "session-private-sentinel", "raw/path-sentinel", "sessionId", "actor"):
                self.assertNotIn(secret, rendered)
            candidate = summary["candidates"][0]
            self.assertEqual(candidate["state"], "uncertain")
            self.assertTrue(candidate["targetDigest"])
            self.assertTrue(candidate["inputDigest"])
            self.assertEqual(candidate["evidenceRefs"][1].split("/")[-1],
                             hashlib.sha256(b"/private/raw/path-sentinel").hexdigest())

    def test_missing_and_unversioned_ledgers_fail_closed_without_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.db"
            self.assertEqual(load_action_ledger_readonly(missing)["status"], "missing")
            self.assertFalse(missing.exists())
            unversioned = Path(directory) / "unversioned.db"
            import sqlite3
            with sqlite3.connect(unversioned) as conn:
                conn.execute("CREATE TABLE action_ledger (action_id TEXT)")
            before = unversioned.read_bytes()
            result = load_action_ledger_readonly(unversioned)
            self.assertEqual(result["status"], "invalid")
            self.assertEqual(unversioned.read_bytes(), before)

    def test_legal_planned_action_with_null_authorization_refs_remains_reconcilable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            with ActionLedger(path) as ledger:
                record = ledger.plan_action(
                    idempotency_key="unbound-plan", action_type="openclaw.gateway.restart",
                    target="gateway-target", generation="generation-1", input_data={"candidate": True},
                    evidence_refs=("evidence://snapshot/g1",),
                )
            loaded = load_action_ledger_readonly(path)
            summary = build_recovery_summary(loaded["records"], ledger_status=loaded["status"],
                                             ledger_counts=loaded.get("counts"),
                                             total_candidate_count=loaded.get("candidateCount"))
            self.assertEqual(loaded["status"], "available")
            self.assertEqual(summary["candidates"][0]["actionId"], record.action_id)
            self.assertTrue(record.action_id.startswith("act_"))
            self.assertIsNone(summary["candidates"][0]["authorizationRef"])
            self.assertIsNone(summary["candidates"][0]["policyRef"])

    def test_malformed_input_digest_is_rejected_without_echo(self):
        import sqlite3
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.db"
            with ActionLedger(path) as ledger:
                ledger.plan_action(
                    idempotency_key="digest-fixture", action_type="openclaw.gateway.restart",
                    target="gateway-target", generation="generation-1", input_data={"candidate": True},
                )
            secret = "PRIVATE-TOKEN-SENTINEL"
            with sqlite3.connect(path) as conn:
                conn.execute("UPDATE action_ledger SET input_digest=?", (secret,))
            loaded = load_action_ledger_readonly(path)
            self.assertEqual(loaded["status"], "invalid")
            self.assertNotIn(secret, str(loaded))

    def test_recovery_limit_counts_all_rows_and_never_replays(self):
        records = [
            {"action_id": f"a{i}", "action_type": "unknown.action", "target": f"target-{i}",
             "generation": "g1", "state": "uncertain", "input_digest": "d" * 64,
             "created_at_ms": i, "evidence_refs": []}
            for i in range(3)
        ]
        summary = build_recovery_summary(records[:2], ledger_status="available", limit=1,
                                         ledger_counts={"uncertain": 3}, total_candidate_count=3)
        self.assertEqual(summary["candidateCount"], 3)
        self.assertEqual(summary["counts"]["uncertain"], 3)
        self.assertTrue(summary["truncated"])
        self.assertFalse(summary["automaticReplay"])
        self.assertEqual(summary["candidates"][0]["nextStep"],
                         "manual-evidence-reconciliation-required; do-not-replay-or-clear-ledger")


if __name__ == "__main__":
    unittest.main()
