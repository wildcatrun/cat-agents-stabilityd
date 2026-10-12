from dataclasses import asdict
import os
from pathlib import Path
import tempfile
import unittest
from stability_core.hermes_profile_config import read_profile_config


class ProfileConfigTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / 'profiles' / 'fixture'
        self.home.mkdir(parents=True)
        self.path = self.home / 'config.yaml'

    def read(self, text):
        self.path.write_text(text)
        self.path.chmod(0o600)
        return read_profile_config(self.home, profile='fixture', runtime_root=self.root, owner_uid=os.getuid())

    def test_only_explicit_standalone_is_positive_evidence(self):
        for value, expected in (('true', True), ('false', False), ('null', False), ('"true"', False)):
            with self.subTest(value=value):
                self.assertEqual(self.read('gateway:\n  standalone: '+value+'\n').standalone, expected)

    def test_false_is_retired_not_standalone(self):
        evidence = self.read('gateway:\n  multiplex_profiles: false\n')
        self.assertTrue(evidence.multiplex_false_retired)
        self.assertFalse(evidence.standalone)
        self.assertFalse(evidence.action_authorized)

    def test_secrets_not_returned(self):
        evidence = self.read('gateway:\n  standalone: true\napi_key: FIXTURE_SECRET\n')
        self.assertNotIn('FIXTURE_SECRET', str(asdict(evidence)))

    def test_ambiguous_alias_and_invalid_yaml_refused_without_raw_error(self):
        for text in ('gateway:\n  standalone: true\n  standalone: false\n',
                     'gateway: &a {standalone: true}\nother: *a\n',
                     'gateway: [FIXTURE_SECRET\n'):
            with self.subTest(text=text), self.assertRaises(ValueError) as caught:
                self.read(text)
            self.assertNotIn('FIXTURE_SECRET', str(caught.exception))

    def test_size_and_symlink_refused(self):
        with self.assertRaises(ValueError): self.read('x' * 65537)
        self.path.unlink()
        other = self.home / 'other.yaml'
        other.write_text('gateway: {standalone: true}\n')
        self.path.symlink_to(other)
        with self.assertRaises(ValueError):
            read_profile_config(self.home, profile='fixture', runtime_root=self.root, owner_uid=os.getuid())

    def test_cross_profile_route_refused(self):
        self.read('gateway: {standalone: true}\n')
        with self.assertRaises(ValueError):
            read_profile_config(self.home, profile='other', runtime_root=self.root, owner_uid=os.getuid())

    def test_file_change_changes_evidence_digest(self):
        first = self.read('gateway: {standalone: true}\n')
        second = self.read('gateway: {standalone: false}\n')
        self.assertNotEqual(first.sha256, second.sha256)
