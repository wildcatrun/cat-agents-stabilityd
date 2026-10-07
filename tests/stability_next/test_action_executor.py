import sqlite3
import threading
import unittest
from unittest import mock

from stability_core.action_executor import (
    ActionExecutor, ActionSpec, AuthorizationGrant, BoundaryCheck, OperationResult, PostcheckResult,
)
from stability_core.action_ledger import ActionLedger, InvalidTransition


class ActionExecutorTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        self._temporary = tempfile.TemporaryDirectory()
        self.path = Path(self._temporary.name) / "state.db"
        self.calls = 0

    def tearDown(self):
        self._temporary.cleanup()

    def spec(self, key="k1"):
        return ActionSpec(
            idempotency_key=key, action_type="repair", target="node/a", generation="g1",
            source="stabilityd", input_data={"requested": True},
            authorization_ref="auth://1", policy_ref="policy://1", evidence_refs=("evidence://1",),
            metadata={"trace_id": "trace-1", "request_source": "stabilityd"},
        )

    def callbacks(self, ledger, *, grant_change=None, postcheck=None):
        def authorize(spec, record):
            values = dict(
                status="authorized", authorization_ref=spec.authorization_ref, policy_ref=spec.policy_ref,
                action_type=spec.action_type, target=spec.target, generation=spec.generation,
                source=spec.source, input_digest=record.input_digest,
                evidence_refs=spec.evidence_refs, expires_at_ms=2_000,
            )
            values.update(grant_change or {})
            return AuthorizationGrant(**values)

        def operation(spec, record):
            self.calls += 1
            return OperationResult("complete", "outcome://safe/1")

        return ActionExecutor(
            ledger, authorizer=authorize,
            precheck=lambda spec, record: BoundaryCheck("approved", "check://pre/1"),
            operation=operation,
            postcheck=postcheck or (lambda spec, record, result: PostcheckResult("verified", "check://post/1")),
            clock_ms=lambda: 1_000,
        )

    def test_gate_rejects_expired_wrong_target_and_plain_bool(self):
        changes = (
            {"expires_at_ms": 999}, {"target": "node/b"}, {"source": "other"},
            {"evidence_refs": ("evidence://other",)}, {"status": "denied"},
        )
        for index, change in enumerate(changes):
            with self.subTest(change=change), ActionLedger(self.path.with_name(f"state-{index}.db")) as ledger:
                result = self.callbacks(ledger, grant_change=change).execute(self.spec(f"k{index}"))
                self.assertEqual(result.record.state, "blocked")
        with ActionLedger(self.path.with_name("bool.db")) as ledger:
            executor = ActionExecutor(
                ledger, authorizer=lambda *_: True,
                precheck=lambda *_: BoundaryCheck("approved", "pre://1"),
                operation=lambda *_: (_ for _ in ()).throw(AssertionError("must not execute")),
                postcheck=lambda *_: PostcheckResult("verified", "post://1"),
            )
            self.assertEqual(executor.execute(self.spec("bool")).record.state, "blocked")
        self.assertEqual(self.calls, 0)

    def test_timeout_partial_and_missing_verification_reference_are_uncertain(self):
        variants = (OperationResult("partial", "outcome://partial/1"), TimeoutError("provider detail"))
        for index, variant in enumerate(variants):
            with self.subTest(variant=type(variant).__name__), ActionLedger(self.path.with_name(f"uncertain-{index}.db")) as ledger:
                executor = self.callbacks(ledger)
                if isinstance(variant, BaseException):
                    executor._operation = lambda *_args, error=variant: (_ for _ in ()).throw(error)
                else:
                    executor._operation = lambda *_args, value=variant: value
                self.assertEqual(executor.execute(self.spec(f"u{index}")).record.state, "uncertain")
        with ActionLedger(self.path.with_name("no-postcheck-ref.db")) as ledger:
            executor = self.callbacks(ledger, postcheck=lambda *_: PostcheckResult("verified"))
            self.assertEqual(executor.execute(self.spec("no-ref")).record.state, "uncertain")

    def test_durable_claim_failure_invokes_operation_zero_times(self):
        ledger = ActionLedger(self.path)
        executor = self.callbacks(ledger)
        original = ledger._conn.execute

        class BrokenConnection:
            def execute(self, sql, params=()):
                if sql.startswith("UPDATE action_ledger") and "executing" in params:
                    raise sqlite3.OperationalError("disk full")
                return original(sql, params)

        ledger._conn = BrokenConnection()
        with self.assertRaises(sqlite3.OperationalError):
            executor.execute(self.spec())
        self.assertEqual(self.calls, 0)

    def test_final_precheck_evidence_write_failure_never_invokes_or_replays_operation(self):
        with ActionLedger(self.path) as ledger:
            executor = self.callbacks(ledger)
            with mock.patch.object(ledger, "refresh_execution_precheck",
                                   side_effect=sqlite3.OperationalError("disk full")):
                with self.assertRaises(sqlite3.OperationalError):
                    executor.execute(self.spec())
            records = ledger.startup_reconcile_candidates()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].state, "executing")
            retry = executor.execute(self.spec())
            self.assertEqual((retry.disposition, retry.record.state), ("existing", "executing"))
        self.assertEqual(self.calls, 0)

    def test_postcheck_exception_is_uncertain_and_exception_text_is_not_stored(self):
        sensitive_value = "sensitive-provider-payload"
        with ActionLedger(self.path) as ledger:
            executor = self.callbacks(
                ledger, postcheck=lambda *_: (_ for _ in ()).throw(RuntimeError(sensitive_value))
            )
            result = executor.execute(self.spec())
            self.assertEqual((result.record.state, result.disposition), ("uncertain", "uncertain"))
        self.assertNotIn(sensitive_value.encode(), self.path.read_bytes())

    def test_duplicate_and_crash_reopen_do_not_repeat_operation(self):
        with ActionLedger(self.path) as ledger:
            executor = self.callbacks(ledger)
            first = executor.execute(self.spec())
            second = executor.execute(self.spec())
            self.assertEqual((first.record.state, second.disposition, self.calls), ("succeeded", "existing", 1))

        crash_path = self.path.with_name("crash.db")
        with ActionLedger(crash_path) as ledger:
            spec = self.spec("crash")
            record = ledger.plan_action(
                idempotency_key=spec.idempotency_key, action_type=spec.action_type, target=spec.target,
                generation=spec.generation, input_data=spec.input_data,
                authorization_ref=spec.authorization_ref, policy_ref=spec.policy_ref,
                evidence_refs=spec.evidence_refs, metadata=spec.metadata,
            )
            ledger.begin_execution(record.action_id, expected_version=record.version)
        with ActionLedger(crash_path) as reopened:
            result = self.callbacks(reopened).execute(spec)
            self.assertEqual((result.record.state, result.disposition), ("executing", "existing"))
            self.assertEqual(self.calls, 1)

    def test_cas_concurrency_allows_one_operation(self):
        ActionLedger(self.path).close()
        barrier = threading.Barrier(3)
        results = []

        def contender():
            with ActionLedger(self.path) as ledger:
                executor = self.callbacks(ledger)
                barrier.wait()
                results.append(executor.execute(self.spec()))

        threads = [threading.Thread(target=contender) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(self.calls, 1)
        self.assertEqual(sorted(result.disposition for result in results), ["executed", "existing"])

    def test_unstarted_abandonment_wins_claim_race_without_calling_operation(self):
        with ActionLedger(self.path):
            pass
        precheck_entered = threading.Event()
        release_precheck = threading.Event()
        results, errors = [], []
        def worker():
            try:
                with ActionLedger(self.path) as ledger:
                    executor = self.callbacks(ledger)
                    def slow_precheck(*_):
                        precheck_entered.set()
                        if not release_precheck.wait(3):
                            raise TimeoutError("test synchronization timed out")
                        return BoundaryCheck("approved", "check://pre/race")
                    executor._precheck = slow_precheck
                    results.append(executor.execute(self.spec("abandon-race")))
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(precheck_entered.wait(3))
        with ActionLedger(self.path) as resolver:
            planned = resolver.get(ActionLedger.stable_action_id("abandon-race"))
            self.assertEqual(planned.state, "planned")
            resolver.abandon_unstarted_plan(planned.action_id, expected_version=planned.version)
        release_precheck.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual((results[0].record.state, results[0].disposition), ("blocked", "existing"))
        self.assertEqual(self.calls, 0)

    def test_claim_wins_unstarted_abandonment_race(self):
        with ActionLedger(self.path):
            pass
        final_precheck_entered = threading.Event()
        release_final_precheck = threading.Event()
        results, errors = [], []
        def worker():
            try:
                with ActionLedger(self.path) as ledger:
                    executor = self.callbacks(ledger)
                    checks = [0]
                    def gated_precheck(*_):
                        checks[0] += 1
                        if checks[0] == 2:
                            final_precheck_entered.set()
                            if not release_final_precheck.wait(3):
                                raise TimeoutError("test synchronization timed out")
                        return BoundaryCheck("approved", "check://pre/claim-race")
                    executor._precheck = gated_precheck
                    results.append(executor.execute(self.spec("claim-race")))
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(final_precheck_entered.wait(3))
        with ActionLedger(self.path) as resolver:
            executing = resolver.get(ActionLedger.stable_action_id("claim-race"))
            self.assertEqual(executing.state, "executing")
            with self.assertRaises(InvalidTransition):
                resolver.abandon_unstarted_plan(executing.action_id, expected_version=executing.version)
            self.assertEqual(resolver.get(executing.action_id), executing)
        release_final_precheck.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual((results[0].record.state, results[0].disposition), ("succeeded", "executed"))
        self.assertEqual(self.calls, 1)

    def test_callbacks_cannot_mutate_authorized_input(self):
        for stage in ("authorizer", "precheck"):
            with self.subTest(stage=stage), ActionLedger(self.path.with_name(stage + ".db")) as ledger:
                executor = self.callbacks(ledger)
                def mutate(spec, record):
                    spec.input_data["requested"] = False
                if stage == "authorizer":
                    executor._authorizer = mutate
                else:
                    executor._precheck = mutate
                result = executor.execute(self.spec(stage))
                self.assertEqual(result.record.state, "blocked")
        self.assertEqual(self.calls, 0)

    def test_grant_expiring_during_precheck_cannot_execute(self):
        with ActionLedger(self.path) as ledger:
            executor = self.callbacks(ledger)
            clock = [1000]
            executor._clock_ms = lambda: clock[0]
            def slow_precheck(*args):
                clock[0] = 2500
                return BoundaryCheck("approved", "check://slow")
            executor._precheck = slow_precheck
            self.assertEqual(executor.execute(self.spec()).record.state, "blocked")
            self.assertEqual(self.calls, 0)

    def test_grant_expiring_during_claim_cannot_execute(self):
        with ActionLedger(self.path) as ledger:
            executor = self.callbacks(ledger)
            clock = [1000]
            executor._clock_ms = lambda: clock[0]
            claim = ledger.begin_execution
            def slow_claim(*args, **kwargs):
                result = claim(*args, **kwargs)
                clock[0] = 2500
                return result
            ledger.begin_execution = slow_claim
            self.assertEqual(executor.execute(self.spec()).record.state, "blocked")
            self.assertEqual(self.calls, 0)

    def test_live_authorization_revoked_after_claim_blocks_before_operation(self):
        with ActionLedger(self.path) as ledger:
            executor = self.callbacks(ledger)
            base = executor._authorizer
            count = [0]
            def revoke_after_claim(spec, record):
                count[0] += 1
                grant = base(spec, record)
                if count[0] > 1:
                    return AuthorizationGrant(**{**grant.__dict__, "status": "denied"})
                return grant
            executor._authorizer = revoke_after_claim
            result = executor.execute(self.spec())
            self.assertEqual(result.record.state, "blocked")
            self.assertEqual(result.record.precheck_ref, "check://pre/1")
            self.assertEqual(count[0], 2)
        self.assertEqual(self.calls, 0)

    def test_changed_request_source_cannot_rebind_same_key(self):
        import dataclasses
        from stability_core.action_ledger import ActionConflict
        with ActionLedger(self.path) as ledger:
            spec = self.spec()
            executor = self.callbacks(ledger)
            executor.execute(spec)
            changed = dataclasses.replace(spec, source="other", metadata={"request_source": "other"})
            with self.assertRaises(ActionConflict):
                executor.execute(changed)
        self.assertEqual(self.calls, 1)

    def test_complete_without_outcome_evidence_is_uncertain(self):
        for index, outcome in enumerate((None, " ")):
            with self.subTest(outcome=outcome), ActionLedger(self.path.with_name(f"no-outcome-{index}.db")) as ledger:
                executor = self.callbacks(ledger)
                executor._operation = lambda *_args: OperationResult("complete", outcome)
                self.assertEqual(executor.execute(self.spec(str(index))).record.state, "uncertain")


if __name__ == "__main__":
    unittest.main()
