import hashlib
import unittest

from stability_core.observation_reconcile import reconcile_observation_batch


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def record(event, observed, received=None, *, node="dev-server", generation="g1", payload="evidence", source="synthetic-fixture"):
    return {
        "nodeId": node, "eventId": digest(event), "generationDigest": digest(generation),
        "evidenceDigest": digest(payload), "sourceKind": source,
        "observedAtEpoch": observed, "receivedAtEpoch": observed if received is None else received,
        "credential": "must-not-persist",
    }


class ObservationReconcileTests(unittest.TestCase):
    def test_retry_duplicate_is_suppressed_and_no_action_replay_surface_exists(self):
        event = record("event-1", 990)
        result = reconcile_observation_batch([event], [event], now_epoch=1000,
                                             current_generations={"dev-server": digest("g1")})
        self.assertEqual(result["summary"]["accepted"], 1)
        self.assertEqual(result["summary"]["duplicatesSuppressed"], 1)
        self.assertFalse(result["actionReplay"])
        self.assertNotIn("credential", result["records"][0])

    def test_equivalent_numeric_timestamp_encodings_deduplicate(self):
        first = record("event-numeric", 990, 990)
        second = record("event-numeric", 990.0, 990.0)
        result = reconcile_observation_batch([first], [second], now_epoch=1000,
                                             current_generations={"dev-server": digest("g1")})
        self.assertEqual(result["summary"]["duplicatesSuppressed"], 1)
        self.assertEqual(result["summary"]["eventConflictsRemoved"], 0)

    def test_event_id_conflicting_payload_removes_both_copies(self):
        first = record("event-1", 990, payload="digest-a")
        second = record("event-1", 991, payload="digest-b")
        result = reconcile_observation_batch([], [first, second], now_epoch=1000,
                                             current_generations={"dev-server": digest("g1")})
        self.assertEqual(result["records"], [])
        self.assertEqual(result["summary"]["eventConflictsRemoved"], 1)

    def test_event_identity_binds_node_generation_source_and_timestamps(self):
        first = record("shared-id", 990, payload="same-payload")
        changed_time = record("shared-id", 991, payload="same-payload")
        same_payload_other_node = record("shared-id", 990, node="mac-codex", payload="same-payload")
        generations = {"dev-server": digest("g1"), "mac-codex": digest("g1")}
        result = reconcile_observation_batch([], [first, changed_time], now_epoch=1000,
                                             current_generations=generations)
        self.assertEqual(result["records"], [])
        cross_node = reconcile_observation_batch([], [first, same_payload_other_node], now_epoch=1000,
                                                 current_generations=generations)
        self.assertEqual(cross_node["records"], [])
        self.assertEqual(cross_node["summary"]["eventConflictsRemoved"], 1)

    def test_unfenced_node_generation_is_rejected_by_default(self):
        unregistered = record("unknown-node", 990, node="unregistered-node")
        result = reconcile_observation_batch([], [unregistered], now_epoch=1000,
                                             current_generations={"dev-server": digest("g1")})
        self.assertEqual(result["records"], [])
        self.assertEqual(result["summary"]["rejected"]["generation-unfenced-node"], 1)

    def test_generation_stale_clock_and_out_of_order_evidence_are_not_fresh(self):
        result = reconcile_observation_batch([], [
            record("new", 995), record("old-time", 980),
            record("stale", 1, generation="g1"), record("old-generation", 996, generation="g0"),
            record("future", 2000),
        ], now_epoch=1000, current_generations={"dev-server": digest("g1")}, max_age_seconds=100)
        states = {item["eventId"]: item["status"] for item in result["records"]}
        self.assertEqual(states[digest("new")], "fresh")
        self.assertEqual(states[digest("old-time")], "out-of-order")
        self.assertEqual(states[digest("stale")], "stale")
        self.assertNotIn(digest("old-generation"), states)
        self.assertEqual(result["summary"]["rejected"]["generation-mismatch"], 1)
        self.assertEqual(states[digest("future")], "clock-invalid")

    def test_buffer_is_bounded_and_invalid_fields_are_not_echoed(self):
        sentinel = "FIXTURE_SECRET_DO_NOT_PERSIST"
        batch = [record(f"event-{idx}", 900 + idx, payload=sentinel + str(idx)) for idx in range(5)]
        batch.append({"nodeId": "dev-server", "sourceKind": [], "eventId": sentinel})
        result = reconcile_observation_batch([], batch, now_epoch=1000,
                                             current_generations={"dev-server": digest("g1")}, max_records=3)
        self.assertEqual(result["summary"]["accepted"], 3)
        self.assertEqual(result["summary"]["overflowDropped"], 2)
        self.assertNotIn(sentinel, str(result))

    def test_invalid_limits_and_generations_are_rejected(self):
        with self.assertRaises(ValueError):
            reconcile_observation_batch([], [], now_epoch=float("nan"), current_generations={})
        with self.assertRaises(ValueError):
            reconcile_observation_batch([], [], now_epoch=1, current_generations={"dev-server": "bad"})


if __name__ == "__main__":
    unittest.main()
