import hashlib
import unittest

from stability_core.surface_contracts import SURFACE_CONTRACTS, evaluate_surface_observations


class SurfaceContractTests(unittest.TestCase):
    def fixture(self, surface, fields, **overrides):
        observation = dict(surfaceId=surface, observedAt=990, receivedAt=991,
                           timezone="UTC", sourceKind="synthetic-fixture", generation="fixture", fields=fields)
        observation.update(overrides)
        report = evaluate_surface_observations([observation], now_epoch=1000)
        return next(item for item in report["surfaces"] if item["surfaceId"] == surface)

    def test_receipts_do_not_prove_human_or_semantic_confirmation(self):
        for kind in ("local-inbox", "runtime-ack", "delivery"):
            with self.subTest(kind=kind):
                result = self.fixture("im-delivery", dict(gatewayConnected=True, messageFlowReady=True,
                    receiptStatus="fresh", receiptKind=kind, humanConfirmation=True, actionAuthorized=True))
                self.assertEqual(result["state"], "fixture")
                self.assertEqual(result["fields"]["receiptKind"], kind)
                self.assertEqual(result["humanConfirmation"], "unknown")
                self.assertEqual(result["semanticReadiness"], "unknown")
                self.assertFalse(result["actionAuthorized"])

    def test_data_thresholds_are_business_owned_metadata_without_policy_numbers(self):
        fields = dict(apiReady=True, mcpReady=True, datasetFresh=True, writerAvailable=True,
                      thresholdOwner="business-layer", thresholdDigest="a" * 64, maxAgeSeconds=1)
        result = self.fixture("data-plane", fields)
        self.assertEqual(result["thresholdBinding"], "fixture-business-owned")
        self.assertNotIn("maxAgeSeconds", result["fields"])
        fields["thresholdOwner"] = "stabilityd"
        result = self.fixture("data-plane", fields)
        self.assertEqual(result["thresholdBinding"], "unknown")
        self.assertNotIn("thresholdOwner", result["fields"])

    def test_paper_and_live_modes_are_synthetic_only_and_never_authorize_trades(self):
        for mode in ("paper", "live"):
            with self.subTest(mode=mode):
                result = self.fixture("trading-core", dict(executionMode=mode, adapterReady=True,
                    accountBalance="SECRET", credential="SECRET", actionAuthorized=True))
                self.assertEqual(result["state"], "fixture")
                self.assertTrue(result["fixtureOnly"])
                self.assertFalse(result["actionAuthorized"])
                self.assertNotIn("SECRET", str(result))
                self.assertEqual(self.fixture("trading-core", {}, sourceKind="offline-metadata")["state"], "blocked")

    def test_reversed_time_order_never_admits_readiness_fields(self):
        result = self.fixture("im-delivery", dict(gatewayConnected=True, messageFlowReady=True,
                              receiptStatus="fresh"), receivedAt=989)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "observation-time-order-invalid")
        self.assertEqual(result["fields"], {})

    def test_oauth_owner_and_no_raw_credentials_or_payloads(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        fields = {
            "codexAppRunning": True, "cliReady": True, "mirrorReady": True,
            "refreshOwner": "mac-codex", "tokenStatus": "healthy",
            "token": sentinel, "access_token": sentinel, "authJson": sentinel,
        }
        report = evaluate_surface_observations([{
            "surfaceId": "local-codex", "observedAt": 990, "receivedAt": 991,
            "timezone": "Asia/Shanghai", "sourceKind": "synthetic-fixture",
            "generation": sentinel, "fields": fields,
        }], now_epoch=1000)
        local = next(item for item in report["surfaces"] if item["surfaceId"] == "local-codex")
        self.assertEqual(local["state"], "fixture")
        self.assertEqual(local["fields"]["refreshOwner"], "mac-codex")
        self.assertNotIn(sentinel, str(report))
        self.assertNotIn("access_token", str(report))
        self.assertEqual(local["generationDigest"], hashlib.sha256(sentinel.encode()).hexdigest())

    def test_cross_platform_surfaces_are_allowlisted_and_trading_is_prohibited(self):
        self.assertEqual(SURFACE_CONTRACTS["trading-core"]["fixtureOnly"], True)
        obs = [{
            "surfaceId": "openclaw-runtime", "observedAt": 999, "receivedAt": 1000,
            "timezone": "UTC", "sourceKind": "synthetic-fixture", "generation": "g1",
            "fields": {"gatewayReady": True, "pluginRegistryReady": True, "arbitrary": "discard-me"},
        }, {
            "surfaceId": "trading-core", "observedAt": 999, "receivedAt": 1000,
            "timezone": "UTC", "sourceKind": "offline-metadata", "generation": "g2",
            "fields": {"accountBalance": 1000000},
        }]
        report = evaluate_surface_observations(obs, now_epoch=1000)
        surfaces = {item["surfaceId"]: item for item in report["surfaces"]}
        self.assertEqual(surfaces["openclaw-runtime"]["state"], "fixture")
        self.assertNotIn("arbitrary", surfaces["openclaw-runtime"]["fields"])
        self.assertEqual(surfaces["trading-core"]["state"], "blocked")
        self.assertNotIn("accountBalance", str(report))
        self.assertEqual(report["coverage"]["observed"], 0)
        self.assertEqual(report["coverage"]["fixtures"], 1)
        self.assertEqual(report["coverage"]["prohibited"], 1)

    def test_expired_and_invalid_metadata_is_unknown_or_degraded_without_echo(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        report = evaluate_surface_observations([{
            "surfaceId": "im-delivery", "observedAt": 10, "receivedAt": 11,
            "timezone": "UTC", "sourceKind": "synthetic-fixture", "generation": "g",
            "fields": {"gatewayConnected": True, "messageFlowReady": True,
                       "receiptStatus": sentinel, "messageBody": sentinel},
        }], now_epoch=1000, max_age_seconds=100)
        surface = next(item for item in report["surfaces"] if item["surfaceId"] == "im-delivery")
        self.assertEqual(surface["state"], "unknown")
        self.assertNotIn(sentinel, str(report))

    def test_self_asserted_non_fixture_source_never_becomes_observed(self):
        report = evaluate_surface_observations([{
            "surfaceId": "openclaw-runtime", "observedAt": 999, "receivedAt": 999,
            "timezone": "UTC", "sourceKind": "offline-metadata", "generation": "g1",
            "fields": {"gatewayReady": True, "pluginRegistryReady": True},
        }], now_epoch=1000)
        surface = next(item for item in report["surfaces"] if item["surfaceId"] == "openclaw-runtime")
        self.assertEqual(surface["state"], "unknown")
        self.assertEqual(surface["reason"], "malformed-or-unbound-observation")

    def test_bad_top_level_inputs_fail_without_partial_report(self):
        with self.assertRaises(ValueError):
            evaluate_surface_observations([], now_epoch=float("nan"))
        for invalid_ttl in (float("nan"), -1, True):
            with self.subTest(ttl=invalid_ttl), self.assertRaises(ValueError):
                evaluate_surface_observations([], now_epoch=1000, max_age_seconds=invalid_ttl)
        report = evaluate_surface_observations("not-an-observation-list", now_epoch=1000)
        self.assertIn("observation-list-invalid", report["coverage"]["rejectionCodes"])


if __name__ == "__main__":
    unittest.main()
