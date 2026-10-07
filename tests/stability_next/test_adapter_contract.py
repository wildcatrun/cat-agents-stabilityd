import dataclasses
import hashlib
import tempfile
import unittest
from pathlib import Path

from stability_core.adapter_contract import (
    AdapterContract, AdapterDescriptor, CapabilityDecision, negotiate_capability, sha256_file,
)


class AdapterContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.binary_path = Path(self.temp.name) / "adapter"
        self.binary_path.write_bytes(b"verified-adapter-binary")
        self.binary_digest = hashlib.sha256(b"verified-adapter-binary").hexdigest()
        self.contract = AdapterContract(
            adapter_id="stabilityd.hermes-profile.v1", api_major=1,
            api_minimum="1.0.0", api_maximum="1.9.9",
            minimum_version="1.2.0", maximum_version="1.9.9",
            allowed_runtimes=("hermes_acp",), supported_capabilities=("profile.restart", "profile.inspect"),
            verified_capabilities=("profile.restart", "profile.inspect"),
            allowed_artifacts=(("a" * 40, self.binary_digest),),
        )
        self.descriptor = AdapterDescriptor(
            runtime="hermes_acp", adapter_id=self.contract.adapter_id,
            adapter_version="1.4.0", api_version="1.2.0", commit="a" * 40,
            node_id="dev-node", generation="boot-7", observed_at_ms=1_000_000,
            advertised_capabilities=("profile.inspect", "profile.restart"),
            binary_source="runtime-owned", resolved_binary_path=str(self.binary_path),
            active_binary_path=str(self.binary_path), resolved_binary_sha256=self.binary_digest,
            active_binary_sha256=self.binary_digest,
        )

    def negotiate(self, descriptor=None, capability="profile.restart"):
        return negotiate_capability(
            self.descriptor if descriptor is None else descriptor, self.contract, capability,
            expected_node_id="dev-node", expected_generation="boot-7", now_ms=1_010_000,
        )

    def test_supported_fresh_handshake_with_matching_binary_grants_only_named_capability(self):
        result = self.negotiate(capability="profile.restart")
        self.assertEqual(result.status, "verified")
        self.assertFalse(result.action_authorized)
        self.assertEqual(result.binary_sha256, self.binary_digest)
        self.assertEqual(self.negotiate(capability="unlisted.write").status, "unsupported")

    def test_compatible_but_unverified_or_unknown_runtime_remains_observation_only(self):
        unverified_contract = dataclasses.replace(self.contract, verified_capabilities=("profile.inspect",))
        result = negotiate_capability(self.descriptor, unverified_contract, "profile.restart",
                                      expected_node_id="dev-node", expected_generation="boot-7", now_ms=1_010_000)
        self.assertEqual(result.status, "observation_only")
        unknown_runtime = dataclasses.replace(self.descriptor, runtime="future_runtime")
        self.assertEqual(self.negotiate(unknown_runtime).status, "unknown")

    def test_stale_future_or_wrong_node_generation_cannot_grant_write(self):
        self.assertNotEqual(self.negotiate(dataclasses.replace(self.descriptor, observed_at_ms=1)).status, "verified")
        self.assertNotEqual(self.negotiate(dataclasses.replace(self.descriptor, observed_at_ms=1_020_000)).status, "verified")
        self.assertNotEqual(self.negotiate(dataclasses.replace(self.descriptor, node_id="other")).status, "verified")
        self.assertNotEqual(self.negotiate(dataclasses.replace(self.descriptor, generation="old-boot")).status, "verified")

    def test_embedded_global_binary_mismatch_fails_closed(self):
        embedded_vs_global = dataclasses.replace(
            self.descriptor, binary_source="global", resolved_binary_sha256="c" * 64,
            active_binary_sha256=self.binary_digest,
        )
        result = self.negotiate(embedded_vs_global)
        self.assertEqual(result.status, "observation_only")
        self.assertEqual(result.reason, "active-binary-does-not-match-resolved-binary")
        self.assertFalse(result.action_authorized)

    def test_descriptor_cannot_self_assert_binary_hash_or_commit_pair(self):
        forged_hash = dataclasses.replace(
            self.descriptor, resolved_binary_sha256="c" * 64, active_binary_sha256="c" * 64,
        )
        self.assertNotEqual(self.negotiate(forged_hash).status, "verified")
        wrong_pair = dataclasses.replace(self.contract, allowed_artifacts=(("d" * 40, self.binary_digest),))
        result = negotiate_capability(
            self.descriptor, wrong_pair, "profile.restart", expected_node_id="dev-node",
            expected_generation="boot-7", now_ms=1_010_000,
        )
        self.assertNotEqual(result.status, "verified")

    def test_unknown_or_unsupported_api_and_missing_descriptor_fail_closed(self):
        self.assertEqual(negotiate_capability(None, self.contract, "profile.restart",
                                              expected_node_id="dev-node", expected_generation="boot-7",
                                              now_ms=1_010_000).status, "unknown")
        self.assertEqual(self.negotiate({}).status, "unknown")
        unsupported = dataclasses.replace(self.descriptor, adapter_version="2.0.0")
        self.assertEqual(self.negotiate(unsupported).status, "unsupported")
        bad_api = dataclasses.replace(self.descriptor, api_version="1")
        self.assertEqual(self.negotiate(bad_api).status, "unknown")
        bad_path = dataclasses.replace(self.descriptor, active_binary_path="relative/binary")
        self.assertNotEqual(self.negotiate(bad_path).status, "verified")
        self.assertNotEqual(negotiate_capability(self.descriptor, self.contract, "profile.restart",
                                                 expected_node_id="", expected_generation="", now_ms=1_010_000).status,
                            "verified")

    def test_binary_hash_reader_requires_safe_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "adapter"
            binary.write_bytes(b"fixture-binary")
            self.assertEqual(sha256_file(str(binary)), hashlib.sha256(b"fixture-binary").hexdigest())
            link = Path(directory) / "adapter-link"
            link.symlink_to(binary)
            with self.assertRaises(ValueError):
                sha256_file(str(link))
            with self.assertRaises(ValueError):
                sha256_file(directory)

    def test_capability_assessment_type_cannot_be_promoted_to_action_authority(self):
        with self.assertRaises(ValueError):
            CapabilityDecision("verified", "profile.restart", "verified", action_authorized=True)


if __name__ == "__main__":
    unittest.main()
