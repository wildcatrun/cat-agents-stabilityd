import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from stability_core.unit_capability import _file_binding, resolve_unit_executable, read_unit_binding
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

    def executable(self):
        binary = self.root / 'fixture-runtime'
        binary.write_bytes(b'synthetic-executable')
        binary.chmod(0o700)
        # These placeholder bytes test ownership/route binding, never execution.
        # Linux QA HOME is on /run (noexec). Model executable access for this
        # one synthetic file; retain a separate denied-access counterexample.
        real_access = os.access
        patch = mock.patch('stability_core.unit_capability.os.access',
                           side_effect=lambda path, mode: True if Path(path) == binary and mode == os.X_OK
                           else real_access(path, mode))
        patch.start()
        self.addCleanup(patch.stop)
        return binary

    def test_explicit_executable_owner_independent_of_daemon_uid(self):
        uid = os.getuid()
        binary = self.executable()
        with mock.patch('stability_core.unit_capability.os.getuid', return_value=uid + 1):
            self.assertEqual(resolve_unit_executable(binary, owner_uid=uid)[0], binary)

    def test_wrong_executable_owner_refused(self):
        if os.getuid() == 0: self.skipTest('root is a trusted system owner')
        with self.assertRaises(ValueError):
            resolve_unit_executable(self.executable(), owner_uid=os.getuid() + 1)

    def test_executable_link_route_preserves_runtime_owner(self):
        binary = self.executable()
        link = self.root / 'runtime-link'
        link.symlink_to(binary.name)
        resolved, route = resolve_unit_executable(link, owner_uid=os.getuid())
        self.assertEqual(resolved, binary)
        self.assertEqual(len(route), 2)

    def test_owner_binding_carried_through_unit_reader(self):
        binary = self.executable()
        self.file.write_text('[Service]\nExecStart=' + str(binary) + '\n')
        properties = ('Id=' + self.file.name + '\nLoadState=loaded\nFragmentPath=' + str(self.file)
                      + '\nDropInPaths=\nExecStart={ path=' + str(binary)
                      + ' ; argv[]=' + str(binary) + ' ; }\n')
        uid = os.getuid()
        with mock.patch('stability_core.unit_capability.os.getuid', return_value=uid + 1):
            binding = read_unit_binding(self.request, unit=self.file.name,
                                        read_properties=lambda unit: properties, clock_ms=lambda: 123,
                                        unit_roots=(self.root,), owner_uid=uid)
        self.assertEqual(binding.owner_uid, uid)
        self.assertEqual(binding.executable, binary)

    def test_parent_traversal_refused(self):
        nested = self.root / 'nested'
        nested.mkdir()
        with self.assertRaises(ValueError):
            _file_binding(nested / '..' / self.file.name, self.request, 'runtime-unit://fixture',
                          unit_roots=(self.root,), owner_uid=os.getuid())

    def test_denied_executable_access_still_refused(self):
        binary = self.executable()
        with mock.patch('stability_core.unit_capability.os.access', return_value=False):
            with self.assertRaisesRegex(ValueError, 'unit-executable-owner-mode'):
                resolve_unit_executable(binary, owner_uid=os.getuid())
