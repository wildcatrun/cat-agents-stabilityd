import importlib.util
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stability_core import generation


MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "cat_agents_stabilityd.py"
SPEC = importlib.util.spec_from_file_location("stabilityd_generation_test", MODULE_PATH)
stabilityd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = stabilityd
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stabilityd)


class GenerationPublicationTests(unittest.TestCase):
    def test_latest_is_last_commit_pointer_and_manifest_matches_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            latest = root / "latest.json"
            policy = root / "policy.json"
            snapshot = {"generationId": "g-1", "completedAt": "2026-10-05T00:00:00Z"}
            stabilityd.publish_generation(snapshot, [(policy, {"generationId": "g-1", "mode": "safe"})], latest)
            published = json.loads(latest.read_text())
            artifact = published["generationManifest"]["artifacts"][0]
            self.assertEqual(published["generationManifest"]["status"], "committed")
            self.assertEqual(artifact["sha256"], hashlib.sha256(policy.read_bytes()).hexdigest())
            self.assertEqual(artifact["bytes"], policy.stat().st_size)
            self.assertEqual(json.loads(policy.read_text())["generationId"], published["generationId"])

    def test_sidecar_failure_preserves_previous_latest_pointer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            latest = root / "latest.json"
            first = root / "first.json"
            broken = root / "broken.json"
            latest.write_text('{"generationId":"old"}\n')
            original = generation.write_json_atomic

            def fail_second(path, payload):
                if path == broken:
                    raise OSError("fixture write failure")
                return original(path, payload)

            with mock.patch.object(generation, "write_json_atomic", side_effect=fail_second):
                with self.assertRaises(OSError):
                    stabilityd.publish_generation(
                        {"generationId": "new", "completedAt": "now"},
                        [(first, {"generationId": "new"}), (broken, {})], latest,
                    )
            self.assertEqual(json.loads(latest.read_text())["generationId"], "old")
            self.assertTrue(first.exists())

    def test_latest_manifest_failure_preserves_previous_pointer_and_never_returns_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            latest = root / "latest.json"
            sidecar = root / "policy.json"
            latest.write_text('{"generationId":"old","generationManifest":{"status":"committed"}}\n')
            old_latest = latest.read_bytes()
            original = generation.write_json_atomic

            def fail_latest(path, payload):
                if path == latest:
                    raise OSError("fixture latest pointer failure")
                return original(path, payload)

            with mock.patch.object(generation, "write_json_atomic", side_effect=fail_latest):
                with self.assertRaisesRegex(OSError, "latest pointer failure"):
                    stabilityd.publish_generation(
                        {"generationId": "new", "completedAt": "2026-10-05T00:00:00Z"},
                        [(sidecar, {"generationId": "new", "mode": "safe"})], latest,
                    )

            self.assertEqual(latest.read_bytes(), old_latest)
            self.assertEqual(json.loads(sidecar.read_text())["generationId"], "new")
            self.assertEqual(list(root.glob("latest.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
