import sqlite3
import threading
import unittest

from stability_core.action_ledger import ActionConflict, ActionLedger, InvalidTransition, LedgerDurabilityError


def plan(ledger, key="k1", target="node/a", generation="g1", input_data=None):
    return ledger.plan_action(
        idempotency_key=key, action_type="repair", target=target, generation=generation,
        input_data={"requested": True} if input_data is None else input_data,
        authorization_ref="auth://approved/1", policy_ref="policy://v1",
        evidence_refs=("evidence://before/1",), metadata={"trace_id": "t1"},
    )


class ActionLedgerTests(unittest.TestCase):
 def setUp(self):
    import tempfile
    self._temporary = tempfile.TemporaryDirectory()
    from pathlib import Path
    self.tmp_path = Path(self._temporary.name)

 def tearDown(self):
    self._temporary.cleanup()

 def test_crash_reopen_lists_executing_without_retry(self):
    tmp_path = self.tmp_path
    path = tmp_path / "state.db"
    ledger = ActionLedger(path)
    intended = plan(ledger)
    executing = ledger.begin_execution(intended.action_id, expected_version=0)
    ledger.close()  # simulate process loss after an external side effect

    reopened = ActionLedger(path)
    candidates = reopened.startup_reconcile_candidates()
    assert [(r.action_id, r.state, r.version) for r in candidates] == [(executing.action_id, "executing", 1)]
    assert reopened.get(executing.action_id).state == "executing"


 def test_duplicate_key_returns_same_record_but_changed_input_is_rejected(self):
    tmp_path = self.tmp_path
    with ActionLedger(tmp_path / "state.db") as ledger:
        original = plan(ledger)
        assert plan(ledger) == original
        with self.assertRaisesRegex(ActionConflict, "reused"):
            plan(ledger, input_data={"requested": False})


 def test_cas_and_active_target_generation_are_exclusive(self):
    tmp_path = self.tmp_path
    path = tmp_path / "state.db"
    first = ActionLedger(path)
    action = plan(first)
    barrier = threading.Barrier(3)
    results = []

    def race(kind):
        with ActionLedger(path) as contender:
            barrier.wait()
            try:
                value = (plan(contender, key="k2") if kind == "scope" else
                         contender.begin_execution(action.action_id, expected_version=0))
                results.append((kind, "ok", value.state))
            except (ActionConflict, InvalidTransition) as exc:
                results.append((kind, "rejected", type(exc).__name__))

    threads = [threading.Thread(target=race, args=(kind,)) for kind in ("cas-a", "cas-b")]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    self.assertEqual(sorted(status for _, status, _ in results), ["ok", "rejected"])
    with self.assertRaisesRegex(ActionConflict, "active"):
        plan(first, key="k2")
    first.close()

 def test_concurrent_plans_reserve_one_active_scope(self):
    path = self.tmp_path / "state.db"
    # Install schema before racing connections so this test isolates the scope reservation.
    ActionLedger(path).close()
    barrier = threading.Barrier(3)
    results = []

    def race(key):
        with ActionLedger(path) as contender:
            barrier.wait()
            try:
                results.append((key, "ok", plan(contender, key=key).action_id))
            except ActionConflict as exc:
                results.append((key, "rejected", type(exc).__name__))

    threads = [threading.Thread(target=race, args=(key,)) for key in ("scope-a", "scope-b")]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()
    self.assertEqual(sorted(status for _, status, _ in results), ["ok", "rejected"])


 def test_schema_is_additive_and_preserves_legacy_tables(self):
    tmp_path = self.tmp_path
    path = tmp_path / "state.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)")
    conn.execute("CREATE TABLE actions (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
    conn.execute("INSERT INTO kv VALUES ('old','value',1)")
    conn.commit()
    conn.close()
    with ActionLedger(path) as ledger:
        plan(ledger)
    conn = sqlite3.connect(path)
    assert conn.execute("SELECT value FROM kv WHERE key='old'").fetchone() == ("value",)
    assert conn.execute("SELECT COUNT(*) FROM action_ledger").fetchone() == (1,)


 def test_uncertain_holds_scope_and_generic_writer_cannot_resolve(self):
    tmp_path = self.tmp_path
    with ActionLedger(tmp_path / "state.db") as ledger:
        action = plan(ledger)
        action = ledger.begin_execution(action.action_id, expected_version=0)
        action = ledger.transition(action.action_id, expected_state="executing", expected_version=1, new_state="uncertain")
        with self.assertRaises(ActionConflict):
            plan(ledger, key="retry")
        with self.assertRaisesRegex(InvalidTransition, "not allowed"):
            ledger.transition(action.action_id, expected_state="uncertain", expected_version=2, new_state="failed")
        with self.assertRaisesRegex(InvalidTransition, "not allowed"):
            ledger.transition(
                action.action_id, expected_state="uncertain", expected_version=2, new_state="succeeded",
                postcheck_ref="evidence://self-asserted/1",
            )
        self.assertEqual(ledger.get(action.action_id).state, "uncertain")


 def test_failed_persistence_never_returns_execution_permission(self):
    tmp_path = self.tmp_path
    ledger = ActionLedger(tmp_path / "state.db")
    action = plan(ledger)
    original = ledger._conn.execute

    class BrokenConnection:
        def execute(self, sql, params=()):
            if sql.startswith("UPDATE action_ledger"):
                raise sqlite3.OperationalError("disk full")
            return original(sql, params)

    ledger._conn = BrokenConnection()
    with self.assertRaisesRegex(sqlite3.OperationalError, "disk full"):
        ledger.begin_execution(action.action_id, expected_version=0)


 def test_rejects_memory_and_raw_input_or_unknown_metadata_is_not_stored(self):
    tmp_path = self.tmp_path
    with self.assertRaises(LedgerDurabilityError):
        ActionLedger(":memory:")
    with self.assertRaises(LedgerDurabilityError):
        ActionLedger("")
    secret = "top-secret-value"
    with ActionLedger(tmp_path / "state.db") as ledger:
        plan(ledger, input_data={"token": secret})
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            ledger.plan_action(idempotency_key="x", action_type="a", target="t", generation="g", input_data={}, metadata={"secret": secret})
    assert secret.encode() not in (tmp_path / "state.db").read_bytes()

 def test_schema_mismatch_is_explicit_and_old_table_is_not_modified(self):
    path = self.tmp_path / "incompatible.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE action_ledger (action_id TEXT PRIMARY KEY)")
    with self.assertRaisesRegex(LedgerDurabilityError, "migration required"):
        ActionLedger(path)
    with sqlite3.connect(path) as conn:
        self.assertEqual(len(conn.execute("PRAGMA table_info(action_ledger)").fetchall()), 1)

 def test_intent_is_not_authorization_and_missing_refs_cannot_be_claimed(self):
    with ActionLedger(self.tmp_path / "state.db") as ledger:
        action = ledger.plan_action(
            idempotency_key="unauthorized", action_type="repair", target="node/a",
            generation="g1", input_data={},
        )
        with self.assertRaisesRegex(InvalidTransition, "references"):
            ledger.begin_execution(action.action_id, expected_version=0)
        self.assertEqual(ledger.get(action.action_id).state, "planned")

 def test_blank_or_non_string_references_and_identifiers_are_rejected(self):
    with ActionLedger(self.tmp_path / "state.db") as ledger:
        for value in (" ", 1, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ledger.plan_action(
                    idempotency_key="bad-ref", action_type="repair", target="t", generation="g",
                    input_data={}, authorization_ref=value, policy_ref="policy", evidence_refs=("e",),
                )
        with self.assertRaises(ValueError):
            ledger.plan_action(idempotency_key=" ", action_type="repair", target="t", generation="g", input_data={})
        with self.assertRaises(ValueError):
            ledger.plan_action(idempotency_key="bad", action_type="repair", target="t", generation="g", input_data={}, evidence_refs="not-a-sequence")
        with self.assertRaises(ValueError):
            ledger.plan_action(idempotency_key="nan", action_type="repair", target="t", generation="g", input_data={}, metadata={"actor": float("nan")})

 def test_same_columns_without_schema_version_are_not_adopted(self):
    path = self.tmp_path / "unversioned.db"
    with ActionLedger(path):
        pass
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM stability_schema_versions")
    with self.assertRaisesRegex(LedgerDurabilityError, "unversioned"):
        ActionLedger(path)
    with sqlite3.connect(path) as conn:
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM stability_schema_versions").fetchone()[0], 0)

 def test_terminal_result_requires_evidence_and_precheck_survives(self):
    with ActionLedger(self.tmp_path / "state.db") as ledger:
        action = plan(ledger)
        action = ledger.begin_execution(action.action_id, expected_version=0, precheck_ref="pre://1")
        with self.assertRaisesRegex(InvalidTransition, "references"):
            ledger.transition(action.action_id, expected_state="executing", expected_version=1, new_state="succeeded")
        final = ledger.transition(
            action.action_id, expected_state="executing", expected_version=1, new_state="succeeded",
            outcome_ref="outcome://1", postcheck_ref="post://1",
        )
        self.assertEqual(final.precheck_ref, "pre://1")

 def test_uncertain_old_generation_blocks_new_generation_same_target(self):
    with ActionLedger(self.tmp_path / "state.db") as ledger:
        action = plan(ledger)
        action = ledger.begin_execution(action.action_id, expected_version=0)
        ledger.transition(action.action_id, expected_state="executing", expected_version=1, new_state="uncertain")
        with self.assertRaises(ActionConflict):
            plan(ledger, key="new-generation", generation="g2")
        self.assertEqual(plan(ledger, key="other-target", target="node/b", generation="g2").state, "planned")

 def test_only_unclaimed_plan_can_be_explicitly_abandoned(self):
    with ActionLedger(self.tmp_path / "state.db") as ledger:
        action = plan(ledger)
        abandoned = ledger.abandon_unstarted_plan(action.action_id, expected_version=action.version)
        self.assertEqual((abandoned.state, abandoned.version), ("blocked", action.version + 1))
        self.assertEqual(
            abandoned.outcome_ref,
            "outcome://action-ledger/abandoned-before-claim/v0-to-v1",
        )
        with self.assertRaises(InvalidTransition):
            ledger.begin_execution(action.action_id, expected_version=action.version)
        self.assertEqual(ledger.get(action.action_id), abandoned)

 def test_unstarted_abandonment_rejects_stale_repeated_and_ambiguous_states(self):
    with ActionLedger(self.tmp_path / "state.db") as ledger:
        planned = plan(ledger)
        with self.assertRaises(InvalidTransition):
            ledger.abandon_unstarted_plan(planned.action_id, expected_version=planned.version + 1)
        self.assertEqual(ledger.get(planned.action_id), planned)

        executing = ledger.begin_execution(planned.action_id, expected_version=planned.version)
        with self.assertRaises(InvalidTransition):
            ledger.abandon_unstarted_plan(executing.action_id, expected_version=executing.version)
        uncertain = ledger.transition(
            executing.action_id, expected_state="executing", expected_version=executing.version,
            new_state="uncertain",
        )
        with self.assertRaises(InvalidTransition):
            ledger.abandon_unstarted_plan(uncertain.action_id, expected_version=uncertain.version)
        self.assertEqual(ledger.get(uncertain.action_id), uncertain)

 def test_unstarted_abandonment_rejects_non_integer_versions(self):
    with ActionLedger(self.tmp_path / "state.db") as ledger:
        action = plan(ledger)
        for version in (True, -1, 1.0, "0"):
            with self.subTest(version=version), self.assertRaises(InvalidTransition):
                ledger.abandon_unstarted_plan(action.action_id, expected_version=version)
        self.assertEqual(ledger.get(action.action_id), action)

 def test_existing_index_must_have_unique_and_exact_active_predicate(self):
    variants = (
        "CREATE INDEX action_ledger_one_active_scope ON action_ledger(target)",
        "CREATE UNIQUE INDEX action_ledger_one_active_scope ON action_ledger(target)",
        "CREATE UNIQUE INDEX action_ledger_one_active_scope ON action_ledger(target) WHERE state IN ('planned','executing')",
        "CREATE UNIQUE INDEX action_ledger_one_active_scope ON action_ledger(target) WHERE state IN ('PLANNED','EXECUTING','UNCERTAIN')",
        "CREATE UNIQUE INDEX action_ledger_one_active_scope ON action_ledger(target) WHERE state IN (' planned','executing','uncertain')",
        "CREATE UNIQUE INDEX action_ledger_one_active_scope ON action_ledger(target) WHERE state IN ('wrong') -- WHERE state IN ('planned','executing','uncertain')",
    )
    for index, sql in enumerate(variants):
        with self.subTest(sql=sql):
            path = self.tmp_path / f"index-{index}.db"
            with ActionLedger(path):
                pass
            with sqlite3.connect(path) as conn:
                conn.execute("DROP INDEX action_ledger_one_active_scope")
                conn.execute(sql)
            with self.assertRaisesRegex(LedgerDurabilityError, "index constraints"):
                ActionLedger(path)


if __name__ == "__main__":
    unittest.main()
