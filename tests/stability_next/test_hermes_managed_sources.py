import os
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
from unittest import mock
from stability_core.hermes_managed_sources import observe_managed_sources

class ManagedSourcesTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.scope = self.root / 'managed'

    def read(self):
        return observe_managed_sources({'HERMES_MANAGED_DIR': str(self.scope)},
                    known_absent=frozenset({'PYTEST_CURRENT_TEST'}), owner_uid=os.getuid())

    def test_missing_override_does_not_fall_back(self):
        r = self.read()
        self.assertFalse(r.directory_present)
        self.assertEqual(r.selected_directory, self.scope)
        self.assertEqual(r.selection, 'explicit-override')
        self.assertTrue(all(not s.present for s in r.sources))

    def test_existing_scope_with_absent_then_present_sources(self):
        self.scope.mkdir()
        self.assertTrue(self.read().directory_present)
        p = self.scope / '.env'
        p.write_text('SECRET=FIXTURE_PRIVATE\n')
        p.chmod(0o600)
        r = self.read()
        self.assertTrue(r.sources[0].present)
        self.assertNotIn('FIXTURE_PRIVATE', repr(r))
        self.assertFalse(r.sources[1].present)
        with self.assertRaises(ValueError): replace(r, effective_coverage='complete')

    def test_empty_pytest_marker_disables_only_default(self):
        r = observe_managed_sources({'PYTEST_CURRENT_TEST': ''},
                    known_absent=frozenset({'HERMES_MANAGED_DIR'}), owner_uid=os.getuid())
        self.assertEqual(r.selection, 'pytest-default-disabled')
        self.assertEqual(r.sources, ())
        r = observe_managed_sources({'PYTEST_CURRENT_TEST': '', 'HERMES_MANAGED_DIR': str(self.scope)},
                    known_absent=frozenset(), owner_uid=os.getuid())
        self.assertEqual(r.selection, 'explicit-override')

    def test_unknown_controls_and_unresolved_paths_refused(self):
        with self.assertRaises(ValueError):
            observe_managed_sources({}, known_absent=frozenset(), owner_uid=os.getuid())
        for path in ('relative', '~/managed', '/$ROOT/managed'):
            with self.assertRaises(ValueError):
                observe_managed_sources({'HERMES_MANAGED_DIR': path},
                    known_absent=frozenset({'PYTEST_CURRENT_TEST'}), owner_uid=os.getuid())

    def test_unsafe_scope_not_interpreted_as_missing(self):
        self.scope.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError): self.read()
        self.scope.unlink()
        self.scope.write_text('not directory')
        with self.assertRaises(ValueError): self.read()

    def test_source_created_between_bundle_sweeps_refused(self):
        from stability_core.hermes_environment_source import read_environment_source
        self.scope.mkdir()
        changed = False
        def observe(path, **kwargs):
            nonlocal changed
            result = read_environment_source(path, **kwargs)
            if Path(path).name == 'config.yaml' and not changed:
                target = self.scope / '.env'
                target.write_text('HERMES_HOME=/fixture\n')
                target.chmod(0o600)
                changed = True
            return result
        with mock.patch('stability_core.hermes_environment_source.read_environment_source', side_effect=observe):
            with self.assertRaises(ValueError): self.read()
        self.assertTrue(changed)

    def test_unreadable_source_refuses_without_raw_exception(self):
        self.scope.mkdir()
        target = self.scope / '.env'
        target.write_text('SECRET=PRIVATE_FIXTURE\n')
        target.chmod(0o600)
        with mock.patch('stability_core.hermes_environment_source.os.read',
                        side_effect=PermissionError('PRIVATE_FIXTURE')):
            with self.assertRaises(ValueError) as caught: self.read()
        self.assertNotIn('PRIVATE_FIXTURE', str(caught.exception))
