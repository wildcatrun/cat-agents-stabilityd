import importlib.util
import hashlib
import json
import os
import stat
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
    def test_latest_commit_pointer_does_not_reread_unused_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            latest, sidecar = root / 'latest.json', root / 'policy.json'
            original = generation.artifact_metadata
            inspected = []
            def metadata(path):
                inspected.append(path)
                self.assertNotEqual(path, latest)
                return original(path)
            with mock.patch.object(generation, 'artifact_metadata', side_effect=metadata):
                result = generation.publish_generation({'generationId': 'new'}, [(sidecar, {'ready': True})], latest)
            self.assertEqual(inspected, [sidecar])
            self.assertEqual(json.loads(latest.read_text()), result)
            self.assertEqual(result['generationManifest']['artifacts'][0]['sha256'],
                             hashlib.sha256(sidecar.read_bytes()).hexdigest())
            # Existing public writers keep their metadata return contract.
            self.assertEqual(generation.write_json_atomic(root / 'standalone.json', {})['bytes'], 3)

    def test_wrong_borrowed_fence_cannot_create_destination_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "not-created"
            with generation._directory_fence(root) as fence:
                with self.assertRaisesRegex(OSError, "scope changed"):
                    generation.write_json_atomic(missing / "result.json", {}, _parent_fence=fence)
            self.assertFalse(missing.exists())

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

            def fail_second(path, payload, **kwargs):
                if path == broken:
                    raise OSError("fixture write failure")
                return original(path, payload, **kwargs)

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

            def fail_latest(path, payload, **kwargs):
                if path == latest:
                    raise OSError("fixture latest pointer failure")
                return original(path, payload, **kwargs)

            with mock.patch.object(generation, "write_json_atomic", side_effect=fail_latest):
                with self.assertRaisesRegex(OSError, "latest pointer failure"):
                    stabilityd.publish_generation(
                        {"generationId": "new", "completedAt": "2026-10-05T00:00:00Z"},
                        [(sidecar, {"generationId": "new", "mode": "safe"})], latest,
                    )

            self.assertEqual(latest.read_bytes(), old_latest)
            self.assertEqual(json.loads(sidecar.read_text())["generationId"], "new")
            self.assertEqual(list(root.glob("latest.json.*.tmp")), [])


    def test_sidecar_file_and_directory_fsync_failures_never_advance_latest(self):
        for failure in ('file', 'directory'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); latest = root / 'latest.json'; sidecar = root / 'policy.json'
                latest.write_text('{"generationId":"old"}\n'); old = latest.read_bytes()
                original = os.fsync
                seen = []
                def sync(fd):
                    kind = 'directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file'
                    seen.append(kind)
                    if kind == failure:
                        raise OSError('synthetic-' + failure + '-fsync-failure')
                    return original(fd)
                with mock.patch.object(generation.os, 'fsync', side_effect=sync):
                    with self.assertRaisesRegex(OSError, 'synthetic-.*-fsync-failure'):
                        generation.publish_generation({'generationId':'new'}, [(sidecar, {'generationId':'new'})], latest)
                self.assertIn(failure, seen)
                self.assertEqual(latest.read_bytes(), old)
                self.assertEqual(list(root.glob('*.tmp')), [])
                if failure == 'file':
                    self.assertFalse(sidecar.exists())
                else:
                    # Rename happened; durability failed. Never infer rollback.
                    self.assertEqual(json.loads(sidecar.read_text())['generationId'], 'new')

    def test_latest_file_fsync_failure_preserves_old_pointer_and_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); latest = root / 'latest.json'; sidecar = root / 'policy.json'
            latest.write_text('{"generationId":"old"}\n'); old = latest.read_bytes()
            original = os.fsync; count = 0
            def sync(fd):
                nonlocal count
                if stat.S_ISREG(os.fstat(fd).st_mode):
                    count += 1
                    if count == 2: raise OSError('synthetic-latest-file-fsync-failure')
                return original(fd)
            with mock.patch.object(generation.os, 'fsync', side_effect=sync):
                with self.assertRaisesRegex(OSError, 'latest-file-fsync-failure'):
                    generation.publish_generation({'generationId':'new'}, [(sidecar, {'generationId':'new'})], latest)
            self.assertEqual(count, 2)
            self.assertEqual(latest.read_bytes(), old)
            self.assertEqual(json.loads(sidecar.read_text())['generationId'], 'new')
            self.assertEqual(list(root.glob('*.tmp')), [])

    def test_latest_directory_fsync_failure_can_expose_complete_new_pointer_but_never_return_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); latest = root / 'latest.json'; sidecar = root / 'policy.json'
            latest.write_text('{"generationId":"old"}\n')
            original = generation._fsync_directory; count = 0
            def sync(path, **kwargs):
                nonlocal count
                count += 1
                if count == 2: raise OSError('synthetic-latest-directory-fsync-failure')
                return original(path, **kwargs)
            with mock.patch.object(generation, '_fsync_directory', side_effect=sync):
                with self.assertRaisesRegex(OSError, 'latest-directory-fsync-failure'):
                    generation.publish_generation({'generationId':'new'}, [(sidecar, {'generationId':'new'})], latest)
            self.assertEqual(count, 2)
            # The latest rename cannot be undone safely by claiming old latest.
            # Its visibility is not proof of crash durability or API success.
            published = json.loads(latest.read_text())
            self.assertEqual(published['generationId'], 'new')
            self.assertEqual(published['generationManifest']['artifacts'][0]['sha256'], hashlib.sha256(sidecar.read_bytes()).hexdigest())
            self.assertEqual(list(root.glob('*.tmp')), [])

    def test_parent_directory_replacement_before_latest_refuses_incomplete_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp); root = workspace / 'active'; root.mkdir()
            latest = root / 'latest.json'; sidecar = root / 'policy.json'
            latest.write_text('{"generationId":"old"}\n')
            original = generation.artifact_metadata; replaced = False
            def metadata(path):
                nonlocal replaced
                result = original(path)
                if path == sidecar and not replaced:
                    root.rename(workspace / 'retired')
                    root.mkdir()
                    replaced = True
                return result
            with mock.patch.object(generation, 'artifact_metadata', side_effect=metadata):
                with self.assertRaises(OSError, msg='publication must reject a changed parent identity'):
                    generation.publish_generation({'generationId':'new'}, [(sidecar, {'generationId':'new'})], latest)
            self.assertTrue(replaced)
            if latest.exists():
                published = json.loads(latest.read_text())
                self.assertNotEqual(published.get('generationId'), 'new', 'incomplete replacement directory became committed latest')
            self.assertEqual(json.loads((workspace/'retired'/'latest.json').read_text())['generationId'], 'old')


    def test_directory_swap_during_latest_encoding_never_writes_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp); root = workspace / 'active'; root.mkdir()
            latest = root / 'latest.json'; sidecar = root / 'policy.json'
            latest.write_text('{"generationId":"old"}\n')
            original = generation.json.dump
            def encode(payload, handle, **kwargs):
                if 'generationManifest' in payload:
                    root.rename(workspace / 'retired')
                    root.mkdir()
                return original(payload, handle, **kwargs)
            with mock.patch.object(generation.json, 'dump', side_effect=encode):
                with self.assertRaises(OSError):
                    generation.publish_generation({'generationId':'new'}, [(sidecar, {'generationId':'new'})], latest)
            self.assertFalse(latest.exists())
            self.assertEqual(json.loads((workspace/'retired'/'latest.json').read_text())['generationId'], 'old')
            self.assertEqual(list((workspace/'retired').glob('*.tmp')), [])


    def test_multiple_parent_directories_publish_complete_private_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); latest = root / 'latest' / 'latest.json'
            first = root / 'one' / 'first.json'; second = root / 'two' / 'second.json'
            generation.publish_generation({'generationId':'multi'}, [(first, {'generationId':'multi'}), (second, {'generationId':'multi'})], latest)
            manifest = json.loads(latest.read_text())['generationManifest']
            self.assertEqual(len(manifest['artifacts']), 2)
            for item, path in zip(manifest['artifacts'], (first, second)):
                self.assertEqual(item['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(latest.stat().st_mode), 0o600)



    def test_same_parent_sidecars_keep_each_file_sync_and_two_directory_barriers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); latest = root / 'latest.json'
            files = [(root / f'sidecar-{i}.json', {'generationId':'new'}) for i in range(5)]
            counts = {'file':0, 'directory':0}; original = os.fsync
            def sync(fd):
                kind = 'directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file'
                counts[kind] += 1
                return original(fd)
            with mock.patch.object(generation.os, 'fsync', side_effect=sync):
                generation.publish_generation({'generationId':'new'}, files, latest)
            self.assertEqual(counts, {'file':6, 'directory':2})
            self.assertEqual(len(json.loads(latest.read_text())['generationManifest']['artifacts']), 5)

    def test_batched_sidecar_barrier_failure_preserves_old_latest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); latest = root / 'latest.json'
            latest.write_text('{"generationId":"old"}\n')
            files = [(root / f'sidecar-{i}.json', {'generationId':'new'}) for i in range(3)]
            with mock.patch.object(generation, '_fsync_directory', side_effect=OSError('sidecar-barrier-failed')):
                with self.assertRaisesRegex(OSError, 'sidecar-barrier-failed'):
                    generation.publish_generation({'generationId':'new'}, files, latest)
            self.assertTrue(all(path.exists() for path, _ in files))
            self.assertEqual(json.loads(latest.read_text())['generationId'], 'old')


    def test_publication_reuses_one_parent_descriptor_without_removing_syncs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); latest = root / 'latest.json'
            files = [(root / f'side-{i}.json', {'generationId':'new'}) for i in range(5)]
            original = os.open; directory_opens = []
            def opened(file, flags, *args, **kwargs):
                if flags & os.O_DIRECTORY:
                    directory_opens.append(str(file))
                return original(file, flags, *args, **kwargs)
            with mock.patch.object(generation.os, 'open', side_effect=opened):
                generation.publish_generation({'generationId':'new'}, files, latest)
            self.assertEqual(directory_opens, [str(root)])

    def test_closed_or_wrong_parent_fence_cannot_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); other = root/'other'; other.mkdir()
            with generation._directory_fence(root) as fence:
                with self.assertRaises(OSError):
                    generation.write_json_atomic(other/'wrong.json', {}, _parent_fence=fence)
            with self.assertRaisesRegex(OSError, 'fence closed'):
                generation.write_json_atomic(root/'closed.json', {}, _parent_fence=fence)
            self.assertFalse((other/'wrong.json').exists())
            self.assertFalse((root/'closed.json').exists())


if __name__ == "__main__":
    unittest.main()
