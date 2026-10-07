import unittest

from stability_core.node_inventory import NODES, evaluate_inventory


def ready_services(node_id):
    descriptor = next(node for node in NODES if node.node_id == node_id)
    return {service_id: "ready" for service_id in descriptor.expected_services}


class NodeInventoryTests(unittest.TestCase):
    def test_known_local_and_dev_nodes_are_freshness_bound_but_production_is_fixture_only(self):
        observations = [
            {"nodeId": "dev-server", "observedAt": 980, "receivedAt": 981, "timezone": "Asia/Shanghai",
             "sourceKind": "synthetic-fixture", "generation": "boot-dev-1", "state": "ready",
             "services": ready_services("dev-server")},
            {"nodeId": "mac-codex", "observedAt": 980, "receivedAt": 981, "timezone": "Asia/Shanghai",
             "sourceKind": "synthetic-fixture", "generation": "node-mac-1", "state": "degraded",
             "services": ready_services("mac-codex")},
            {"nodeId": "local-workstation", "observedAt": 980, "receivedAt": 981, "timezone": "Asia/Shanghai",
             "sourceKind": "synthetic-fixture", "generation": "host-win-1", "state": "unreachable",
             "services": ready_services("local-workstation")},
            {"nodeId": "wsl-datalab", "observedAt": 980, "receivedAt": 981, "timezone": "Asia/Shanghai",
             "sourceKind": "synthetic-fixture", "generation": "wsl-dl-1", "state": "ready",
             "services": ready_services("wsl-datalab")},
            # Even an explicitly supplied observation cannot probe production in this plan.
            {"nodeId": "prod-server", "observedAt": 999, "generation": "prod-1", "state": "ready"},
        ]
        report = evaluate_inventory(observations, now_epoch=1000)
        by_id = {item["nodeId"]: item for item in report["nodes"]}
        self.assertEqual(by_id["dev-server"]["state"], "fixture")
        self.assertEqual(by_id["dev-server"]["reportedState"], "ready")
        self.assertEqual(by_id["mac-codex"]["state"], "fixture")
        self.assertEqual(by_id["mac-codex"]["reportedState"], "degraded")
        self.assertEqual(by_id["local-workstation"]["state"], "fixture")
        self.assertEqual(by_id["local-workstation"]["reportedState"], "unreachable")
        self.assertEqual(by_id["wsl-datalab"]["parentNode"], "local-workstation")
        self.assertEqual(by_id["dev-server"]["ownerRef"], "stabilityd-ops")
        self.assertIn("openclaw-gateway", by_id["dev-server"]["expectedServices"])
        self.assertEqual(by_id["dev-server"]["serviceCoverageComplete"], True)
        self.assertEqual(report["coverage"]["observed"], 0)
        self.assertEqual(report["coverage"]["fixtures"], 4)
        self.assertEqual(report["coverage"]["prohibitedServices"], 2)
        self.assertEqual(by_id["prod-server"]["reason"], "production-access-excluded")
        self.assertEqual(by_id["prod-site"]["reason"], "production-access-excluded")
        self.assertIn("production-observation-out-of-scope", report["coverage"]["rejectionCodes"])

    def test_missing_stale_future_duplicate_and_unknown_observations_never_become_ready(self):
        report = evaluate_inventory([
            {"nodeId": "dev-server", "observedAt": 500, "receivedAt": 500, "timezone": "UTC",
             "sourceKind": "synthetic-fixture", "generation": "old", "state": "ready"},
            {"nodeId": "mac-codex", "observedAt": 2000, "receivedAt": 2000, "timezone": "UTC",
             "sourceKind": "synthetic-fixture", "generation": "future", "state": "ready"},
            {"nodeId": "local-workstation", "observedAt": 999, "receivedAt": 999, "timezone": "UTC",
             "sourceKind": "synthetic-fixture", "generation": "a", "state": "ready"},
            {"nodeId": "local-workstation", "observedAt": 999, "receivedAt": 999, "timezone": "UTC",
             "sourceKind": "synthetic-fixture", "generation": "b", "state": "ready"},
            {"nodeId": "unknown-host", "observedAt": 999, "generation": "x", "state": "ready"},
        ], now_epoch=1000)
        by_id = {item["nodeId"]: item for item in report["nodes"]}
        self.assertEqual(by_id["dev-server"]["reason"], "stale-observation")
        self.assertEqual(by_id["mac-codex"]["reason"], "clock-skew-future")
        self.assertEqual(by_id["local-workstation"]["reason"], "duplicate-observation")
        self.assertEqual(by_id["wsl-agents"]["state"], "unknown")
        self.assertEqual(report["coverage"]["prohibited"], 2)
        self.assertEqual(report["coverage"]["missing"], 3)
        self.assertIn("unknown-node-id", report["coverage"]["rejectionCodes"])

    def test_bad_observation_data_is_not_echoed_into_report(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        report = evaluate_inventory([{"nodeId": "dev-server", "observedAt": sentinel, "receivedAt": sentinel,
                                      "generation": sentinel, "state": sentinel,
                                      "timezone": sentinel, "sourceKind": sentinel,
                                      "reasonCode": sentinel}], now_epoch=1000)
        self.assertNotIn(sentinel, str(report))
        self.assertEqual(report["nodes"][0]["reason"], "malformed-or-unbound-observation")

    def test_stale_receipt_clock_skew_and_unhashable_enums_fail_closed_per_node(self):
        common = {"sourceKind": "synthetic-fixture", "timezone": "UTC", "state": "ready", "generation": "g1"}
        report = evaluate_inventory([
            {"nodeId": "dev-server", **common, "observedAt": 999, "receivedAt": -1},
            {"nodeId": "mac-codex", **common, "observedAt": 500, "receivedAt": 999},
            {"nodeId": "local-workstation", **common, "observedAt": 999, "receivedAt": 999,
             "sourceKind": ["unhashable"]},
            {"nodeId": "wsl-agents", **common, "observedAt": 999, "receivedAt": 999,
             "state": ["unhashable"]},
            {"nodeId": "wsl-models", **common, "observedAt": 999, "receivedAt": 999,
             "reasonCode": ["unhashable"], "services": ready_services("wsl-models")},
            {"nodeId": "wsl-datalab", **common, "observedAt": 999, "receivedAt": 999,
             "reasonCode": None, "services": ready_services("wsl-datalab")},
        ], now_epoch=1000, max_age_seconds=1000, max_clock_skew_seconds=300)
        by_id = {item["nodeId"]: item for item in report["nodes"]}
        self.assertEqual(by_id["dev-server"]["coverageStatus"], "stale")
        self.assertEqual(by_id["mac-codex"]["reason"], "clock-skew-mismatch")
        self.assertEqual(by_id["local-workstation"]["coverageStatus"], "invalid")
        self.assertEqual(by_id["wsl-agents"]["coverageStatus"], "invalid")
        self.assertEqual(by_id["wsl-models"]["coverageStatus"], "invalid")
        self.assertEqual(by_id["wsl-datalab"]["coverageStatus"], "invalid")

    def test_node_reachable_does_not_imply_services_ready_or_covered(self):
        report = evaluate_inventory([{
            "nodeId": "dev-server", "observedAt": 999, "receivedAt": 999, "timezone": "UTC",
            "sourceKind": "synthetic-fixture", "generation": "g1", "state": "ready",
            "services": {"openclaw-gateway": "ready", "secret-extra-service": "ready"},
        }], now_epoch=1000)
        node = report["nodes"][0]
        self.assertEqual(node["state"], "fixture")
        self.assertEqual(node["reason"], "partial-fixture-coverage")
        self.assertFalse(node["serviceCoverageComplete"])
        self.assertEqual([item["serviceId"] for item in node["services"]], node["expectedServices"])

    def test_self_asserted_real_probe_source_is_not_trusted_without_producer_binding(self):
        report = evaluate_inventory([{
            "nodeId": "dev-server", "observedAt": 999, "receivedAt": 999, "timezone": "UTC",
            "sourceKind": "read-only-probe", "generation": "g1", "state": "ready",
            "services": ready_services("dev-server"),
        }], now_epoch=1000)
        node = report["nodes"][0]
        self.assertEqual(node["state"], "unknown")
        self.assertEqual(node["coverageStatus"], "invalid")
        self.assertEqual(report["coverage"]["observed"], 0)


if __name__ == "__main__":
    unittest.main()
