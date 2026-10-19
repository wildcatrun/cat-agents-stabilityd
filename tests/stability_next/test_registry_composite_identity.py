"""Official runtime-scoped identities do not relax registry evidence gates."""
import unittest

import test_registry_safety as base

REQUIRED_COLUMNS = base.REQUIRED_COLUMNS
stabilityd = base.stabilityd


class RegistryCompositeIdentityTests(unittest.TestCase):
    setUp = base.RegistrySafetyTests.setUp
    create_db = base.RegistrySafetyTests.create_db
    row = staticmethod(base.RegistrySafetyTests.row)

    def read_rows(self, rows, composite=True, columns=None):
        self.create_db(columns=columns or (("agent_key",) + REQUIRED_COLUMNS if composite else REQUIRED_COLUMNS), rows=rows)
        return stabilityd.workflow_runtime_registry_records()

    def test_complete_distinct_runtime_instances_preserve_rows_and_capabilities(self):
        rows = [self.row(), self.row(agent_key="openclaw_route_shell:catnose", runtime="openclaw_route_shell",
                                    status="dormant", platform="openclaw", execution_adapter="route_shell",
                                    endpoint_ref="openclaw-agent:catnose", can_receive_dispatch=0)]
        result = self.read_rows(rows)
        self.assertTrue(result["writeEligible"])
        self.assertEqual(result["source"], "db")
        self.assertEqual(result["identitySchema"], "runtime-composite")
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual([r["can_receive_dispatch"] for r in result["records"]], [1, 0])
        self.assertEqual(result["duplicateAgentIds"], [])
        self.assertEqual(stabilityd.active_openclaw_agent_ids_from_registry(result), [])

    def test_duplicate_key_rejected_and_all_rows_preserved(self):
        result = self.read_rows([self.row(), self.row()])
        self.assertFalse(result["writeEligible"])
        self.assertEqual(result["duplicateAgentKeys"], ["hermes_acp:catnose"])
        self.assertEqual(len(result["records"]), 2)

    def test_empty_null_and_inconsistent_key_rejected(self):
        for index, key in enumerate((None, "", " ", "hermers:catnose", "hermes_acp:someone_else")):
            with self.subTest(key=key):
                with unittest.mock.patch.object(self, "db", self.root / ("key-" + str(index) + ".db")):
                    with unittest.mock.patch.object(stabilityd, "WORKFLOW_DB", self.db):
                        result = self.read_rows([self.row(agent_key=key)])
                self.assertFalse(result["writeEligible"])
                self.assertEqual(len(result["records"]), 1)

    def test_legacy_flat_duplicate_agent_id_still_rejected(self):
        result = self.read_rows([self.row(), self.row(runtime="openclaw")], composite=False)
        self.assertFalse(result["writeEligible"])
        self.assertEqual(result["duplicateAgentIds"], ["catnose"])

    def test_composite_does_not_fill_missing_endpoint_even_for_dormant_row(self):
        result = self.read_rows([self.row(), self.row(agent_key="other:catnose", runtime="other",
                                                     status="dormant", endpoint_ref=None)])
        self.assertFalse(result["writeEligible"])
        self.assertEqual(len(result["records"]), 2)
        self.assertIsNone(next(r for r in result["records"] if r["runtime"] == "other")["endpoint_ref"])

    def test_closed_history_empty_endpoint_is_observation_only(self):
        rows = [self.row(agent_key="openclaw:archived_" + status, agent_id="archived_" + status, runtime="openclaw",
                         platform="openclaw", execution_adapter="openclaw_native", status=status,
                         endpoint_ref=None, can_receive_dispatch=0, can_start_workflow=0,
                         gateway_proxy_allowed=0) for status in ("retired", "inactive", "dormant")]
        result = self.read_rows(rows)
        self.assertTrue(result["writeEligible"])
        self.assertEqual(len(result["records"]), 3)
        self.assertEqual(len(result["observationOnlyHistoricalRows"]), 3)
        self.assertEqual(stabilityd.active_openclaw_agent_ids_from_registry(result), [])

    def test_unclosed_history_and_active_empty_endpoint_rejected(self):
        for index, overrides in enumerate((
            {"status": "active"}, {"status": "unknown"}, {"status": "dormant", "can_start_workflow": 1},
            {"status": "inactive", "gateway_proxy_allowed": None},
        )):
            with self.subTest(overrides=overrides):
                db = self.root / ("unclosed-" + str(index) + ".db")
                with unittest.mock.patch.object(self, "db", db), unittest.mock.patch.object(stabilityd, "WORKFLOW_DB", db):
                    row = self.row(endpoint_ref=None, can_receive_dispatch=0, can_start_workflow=0, gateway_proxy_allowed=0)
                    row.update(overrides)
                    result = self.read_rows([row])
                self.assertFalse(result["writeEligible"])
                self.assertEqual(result["observationOnlyHistoricalRows"], [])

    def test_unknown_columns_do_not_replace_required_evidence(self):
        columns = ("agent_key",) + tuple(c for c in REQUIRED_COLUMNS if c != "endpoint_ref") + ("endpoint_guess",)
        result = self.read_rows([dict(self.row(), endpoint_guess="hermes-profile:catnose")], columns=columns)
        self.assertFalse(result["writeEligible"])
        self.assertEqual(result["missingRequiredColumns"], ["endpoint_ref"])

    def test_null_capability_not_defaulted(self):
        result = self.read_rows([self.row(can_receive_dispatch=None)])
        self.assertFalse(result["writeEligible"])
        self.assertIsNone(result["records"][0]["can_receive_dispatch"])

    def test_official_builtin_inboxes_need_no_fabricated_endpoint(self):
        rows = [self.row(agent_key=runtime + ":inbox", agent_id="inbox", runtime=runtime,
                         platform=runtime, execution_adapter="adapter", workflow_ingress_adapter="adapter",
                         endpoint_ref="") for runtime in ("codex", "local_codex")]
        result = self.read_rows(rows, columns=("agent_key", "workflow_ingress_adapter") + REQUIRED_COLUMNS)
        self.assertTrue(result["writeEligible"])
        self.assertEqual(len(result["builtinInboxRows"]), 2)
        self.assertTrue(all(r["runtimeActuationEligible"] is False for r in result["builtinInboxRows"]))
        self.assertEqual(stabilityd.active_openclaw_agent_ids_from_registry(result), [])
        self.assertTrue(all(r["endpoint_ref"] == "" for r in result["records"]))

    def test_builtin_inbox_exception_does_not_admit_conflicting_or_unknown_routes(self):
        cases = ({"platform": "openclaw"}, {"execution_adapter": "native"},
                 {"workflow_ingress_adapter": None}, {"gateway_proxy_allowed": 1},
                 {"can_receive_dispatch": None}, {"runtime": "other", "agent_key": "other:inbox", "platform": "other"})
        for index, overrides in enumerate(cases):
            with self.subTest(overrides=overrides):
                db = self.root / ("inbox-" + str(index) + ".db")
                with unittest.mock.patch.object(self, "db", db), unittest.mock.patch.object(stabilityd, "WORKFLOW_DB", db):
                    row = self.row(agent_key="codex:inbox", agent_id="inbox", runtime="codex", platform="codex",
                                   execution_adapter="adapter", workflow_ingress_adapter="adapter", endpoint_ref="")
                    row.update(overrides)
                    result = self.read_rows([row], columns=("agent_key", "workflow_ingress_adapter") + REQUIRED_COLUMNS)
                self.assertFalse(result["writeEligible"])


if __name__ == "__main__":
    unittest.main()
