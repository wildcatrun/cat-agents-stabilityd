import dataclasses
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from stability_core import content_artifact as c
from stability_core.adapter_contract import AdapterContract, AdapterDescriptor, sha256_file
from stability_core.effect_capability import EffectCapabilityProvider, EffectRequest, EffectOperation


class ContentArtifactTests(unittest.TestCase):
    def test_actual_measurement_reader_cannot_reuse_approval_after_code_change(self):
        measured = c.measure_content_artifact(self.spec)
        binary = self.root / 'module.mjs'
        binary_digest = sha256_file(str(binary))
        request = EffectRequest('openclaw.session.reset', EffectOperation.OPENCLAW_RPC,
                                'fixture-session', 'fixture-node', 'fixture-generation')
        contract = AdapterContract('fixture-api', 1, '1.0.0', '1.0.0', '1.2.3', '1.2.3',
            ('openclaw',), ('sessions.reset',), ('sessions.reset',), (),
            ((measured.digest, binary_digest),))
        def read(current):
            self.assertEqual(current, request)
            content = c.measure_content_artifact(self.spec)
            digest = sha256_file(str(binary))
            return AdapterDescriptor('openclaw', 'fixture-api', '1.2.3', '1.0.0', '',
                request.node_id, request.generation, 1000, ('sessions.reset',), 'runtime-owned',
                str(binary), str(binary), digest, digest, artifact_kind='content-manifest',
                artifact_digest=content.digest)
        provider = EffectCapabilityProvider(clock_ms=lambda: 1000,
            node_reader=lambda: (request.node_id, request.generation), api_reader=read, api_contract=contract)
        first = provider.assess(request)
        self.assertEqual(first.status, 'verified')
        self.assertFalse(first.action_authorized)
        self.assertTrue(provider.accepts(first, request))
        binary.write_text('export const fixture = false;')
        changed = provider.assess(request)
        self.assertEqual(changed.status, 'observation_only')
        self.assertFalse(provider.accepts(changed, request))

    def test_deep_parent_replaced_by_symlink_after_read_is_rejected(self):
        parent = self.root / 'a' / 'b'
        parent.mkdir(parents=True)
        module = parent / 'module.mjs'; module.write_text('export const fixture = true;')
        spec = dataclasses.replace(self.spec, files=('package.json', 'a/b/module.mjs'))
        actual = c.os.read
        changed = False
        def read(fd, size):
            nonlocal changed
            result = actual(fd, size)
            if result.startswith(b'{') and not changed:
                changed = True
                retained = parent.parent / 'retained'
                parent.rename(retained); parent.symlink_to(retained.name)
            return result
        with mock.patch.object(c.os, 'read', side_effect=read):
            with self.assertRaisesRegex(ValueError, 'manifest-drift'): c.measure_content_artifact(spec)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / 'package.json').write_text(json.dumps({'name': 'fixture-package', 'version': '1.2.3'}))
        (self.root / 'module.mjs').write_text('export const fixture = true;\n')
        self.spec = c.ContentArtifactSpec(self.root, 'fixture-package', '1.2.3', ('package.json', 'module.mjs'))

    def test_real_bytes_are_stable_and_never_action_approval(self):
        first = c.measure_content_artifact(self.spec)
        second = c.measure_content_artifact(dataclasses.replace(self.spec, files=tuple(reversed(self.spec.files))))
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.files, 2)
        self.assertFalse(first.action_authorized)
        (self.root / 'module.mjs').write_text('export const fixture = false;\n')
        self.assertNotEqual(c.measure_content_artifact(self.spec).digest, first.digest)

    def test_metadata_claim_and_bad_scope_cannot_create_measurement(self):
        for spec in (self.spec.__dict__, dataclasses.replace(self.spec, package_version='2.0.0'),
                     dataclasses.replace(self.spec, files=('module.mjs',)),
                     dataclasses.replace(self.spec, files=('package.json', '../outside')),
                     dataclasses.replace(self.spec, files=('package.json', {})),
                     dataclasses.replace(self.spec, root='relative'),
                     dataclasses.replace(self.spec, files=('package.json', 'module.mjs', 'module.mjs'))):
            with self.subTest(spec=spec), self.assertRaises((ValueError, OSError)):
                c.measure_content_artifact(spec)

    def test_measurement_cannot_claim_action_authority(self):
        with self.assertRaises(ValueError):
            c.ContentArtifactMeasurement('a' * 64, 1, 1, (), action_authorized=True)

    def test_symlink_hardlink_and_writable_file_rejected(self):
        module = self.root / 'module.mjs'
        module.rename(self.root / 'actual'); module.symlink_to('actual')
        with self.assertRaises(ValueError): c.measure_content_artifact(self.spec)
        module.unlink(); os.link(self.root / 'actual', module)
        with self.assertRaises(ValueError): c.measure_content_artifact(self.spec)
        module.unlink(); (self.root / 'actual').rename(module); module.chmod(0o666)
        with self.assertRaises(ValueError): c.measure_content_artifact(self.spec)

    def test_time_budget_fails_without_partial_proof(self):
        with mock.patch.object(c.time, 'monotonic', side_effect=[0.0, 3.0]):
            with self.assertRaisesRegex(ValueError, 'time-budget'): c.measure_content_artifact(self.spec)

    def test_changed_previous_file_is_rejected_at_final_manifest_fence(self):
        actual = c.os.read
        changed = False
        def read(fd, size):
            nonlocal changed
            result = actual(fd, size)
            if result.startswith(b'{') and not changed:
                changed = True
                (self.root / 'module.mjs').write_text('changed after its digest')
            return result
        with mock.patch.object(c.os, 'read', side_effect=read):
            with self.assertRaisesRegex(ValueError, 'manifest-drift'): c.measure_content_artifact(self.spec)


if __name__ == '__main__': unittest.main()
