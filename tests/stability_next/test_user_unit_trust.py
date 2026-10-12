import os
from pathlib import Path
import tempfile
import unittest
from stability_core.unit_capability import _file_binding
from stability_core.effect_capability import EffectRequest, EffectOperation


class UserUnitTrustTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.file = self.root / 'hermes-gateway-fixture.service'
        self.file.write_text('[Service]\nExecStart=/synthetic/hermes\n')
        self.request = EffectRequest('hermes.gateway.restart', EffectOperation.SYSTEMD_UNIT,
                                     'hermes-profile:fixture', 'fixture-node', 'fixture-generation')

    def read(self, **kwargs):
        return _file_binding(self.file, self.request, 'runtime-unit://fixture',
                             unit_roots=(self.root,), **kwargs)

    def test_explicit_owned_root(self):
        self.assertEqual(self.read(owner_uid=os.getuid()).path, self.file)

    def test_wrong_runtime_owner_refused(self):
        if os.getuid() == 0: self.skipTest('root is intentionally accepted as trusted system owner')
        with self.assertRaises(ValueError): self.read(owner_uid=os.getuid() + 1)

    def test_writable_ancestor_refused(self):
        self.root.chmod(0o777)
        with self.assertRaises(ValueError): self.read(owner_uid=os.getuid())

    def test_invalid_owner_type_refused(self):
        for uid in (True, -1, '1000'):
            with self.subTest(uid=uid), self.assertRaises(ValueError): self.read(owner_uid=uid)

    def test_global_system_roots_not_widened(self):
        with self.assertRaises(ValueError):
            _file_binding(self.file, self.request, 'runtime-unit://fixture')
