import importlib.util
import contextlib
import io
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest import mock

from stability_core import node_transport_contract as transport
from stability_core.node_inventory import evaluate_inventory


def receipt():
    raw = json.dumps({
        "schemaVersion": 1, "collectorVersion": "dev-host-metadata-v1",
        "observedAtEpoch": 1000, "bootId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "codeCommit": "a" * 40, "codeDirty": False,
        "publishedGeneration": "b" * 32, "publishedCompletedAtEpoch": 999,
    }).encode()
    with mock.patch.object(transport, "_pin_is_approved", return_value=True), \
         mock.patch.object(transport, "_bounded_ssh", return_value=transport._CommandResult(0, raw)), \
         mock.patch.object(transport.time, "time", return_value=1000):
        return transport.collect_dev_metadata()


class NodeTransportBridgeTests(unittest.TestCase):
    def test_exact_remote_script_executes_with_only_synthetic_files_and_git(self):
        calls = []
        def git(command, **kwargs):
            calls.append(command)
            self.assertEqual(command[0], "git")
            self.assertNotIn("HOME", kwargs["env"])
            return SimpleNamespace(returncode=0, stdout=("a" * 40).encode())
        def path(name):
            fake = mock.MagicMock()
            if name == "/proc/sys/kernel/random/boot_id":
                fake.read_text.return_value = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
            elif name == "/home/flashcat/.openclaw/stability/latest.json":
                raw = json.dumps({"generationId": "b" * 32, "completedAtEpoch": 999}).encode()
                fake.stat.return_value = SimpleNamespace(st_size=len(raw))
                fake.open.return_value.__enter__.side_effect = lambda: io.BytesIO(raw)
            else:
                self.fail("unexpected metadata read")
            return fake
        output = io.StringIO()
        with mock.patch("subprocess.run", side_effect=git), mock.patch("pathlib.Path", side_effect=path), \
             contextlib.redirect_stdout(output):
            exec(compile(transport.REMOTE_METADATA_SCRIPT, "fixed-remote-metadata", "exec"),
                 {"__name__": "__main__", "__package__": None})
        metadata = transport._parse_metadata(output.getvalue().encode())
        self.assertEqual(metadata.code_commit, "a" * 40)
        self.assertEqual(metadata.published_generation, "b" * 32)
        self.assertTrue(calls)

    def test_untrusted_oversized_numeric_timestamp_is_rejected_without_exception(self):
        node = evaluate_inventory([{
            "nodeId": "dev-server", "observedAt": 10 ** 1000,
            "receivedAt": 1000, "sourceKind": "synthetic-fixture",
            "timezone": "UTC", "generation": "g", "state": "ready",
        }], now_epoch=1000)["nodes"][0]
        self.assertEqual(node["coverageStatus"], "invalid")

    def test_authenticated_metadata_never_upgrades_runtime_readiness(self):
        report = evaluate_inventory([receipt()], now_epoch=1000)
        node = report["nodes"][0]
        self.assertEqual(node["state"], "unknown")
        self.assertEqual(node["coverageStatus"], "partial")
        self.assertEqual(node["transportEvidence"]["transportLiveness"], "reachable")
        self.assertFalse(node["serviceCoverageComplete"])
        self.assertEqual(report["coverage"]["observedServices"], 0)
        self.assertEqual(report["coverage"]["partial"], 1)
        self.assertTrue(all(s["state"] == "unknown" for s in node["services"]))

    def test_serialized_receipt_is_evidence_only_and_duplicates_are_rejected(self):
        observation = receipt()
        summary = transport.trusted_summary(observation, now_epoch=1000)
        forged = {**summary, "state": "ready", "observedAt": 1000,
                  "receivedAt": 1000, "generation": "self-reported"}
        self.assertEqual(evaluate_inventory([forged], now_epoch=1000)["nodes"][0]["coverageStatus"], "invalid")
        report = evaluate_inventory([observation, observation], now_epoch=1000)
        self.assertEqual(report["nodes"][0]["reason"], "duplicate-observation")

    def test_stale_authenticated_receipt_does_not_count_as_partial_coverage(self):
        node = evaluate_inventory([receipt()], now_epoch=2000)["nodes"][0]
        self.assertEqual(node["coverageStatus"], "stale")
        self.assertEqual(node["transportEvidence"]["transportLiveness"], "unknown")

    def test_mcp_remote_nodes_uses_fixed_transport_and_sanitizes_failure(self):
        path = Path(__file__).resolve().parents[2] / "scripts/cat_agents_stability_mcp.py"
        spec = importlib.util.spec_from_file_location("node_bridge_mcp", path)
        mcp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mcp)
        with mock.patch.object(transport, "collect_dev_metadata", return_value=transport.TransportFailure("transport-unavailable")), \
             mock.patch.object(mcp, "run_remote") as legacy, mock.patch.object(mcp, "audit"):
            result = mcp.nodes({"source": "remote", "host": "prod-server", "script": "unexpected"})
        legacy.assert_not_called()
        self.assertFalse(result["result"]["ok"])
        self.assertEqual(result["result"]["stderr"], "")
        self.assertEqual(result["json"]["transportFailure"]["nodeId"], "dev-server")
        self.assertEqual(json.loads(result["result"]["stdout"]), result["json"])

    def test_local_and_invalid_sources_never_enter_remote_transport(self):
        path = Path(__file__).resolve().parents[2] / "scripts/cat_agents_stability_mcp.py"
        spec = importlib.util.spec_from_file_location("node_bridge_mcp_local", path)
        mcp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mcp)
        with mock.patch.object(transport, "collect_dev_metadata") as remote, \
             mock.patch.object(mcp, "stability_call", return_value={"legacy": True}) as local:
            self.assertEqual(mcp.nodes({"source": "local"}), {"legacy": True})
            local.assert_called_once_with({"source": "local", "action": "nodes"})
            with self.assertRaises(ValueError):
                mcp.nodes({"source": "production"})
            remote.assert_not_called()


if __name__ == "__main__":
    unittest.main()
