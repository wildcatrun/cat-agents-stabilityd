from dataclasses import asdict
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
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

    def test_standalone_matches_installed_boolean_tokens(self):
        for value, expected in (('true', True), ('false', False), ('null', False), ('"true"', True),
                                ('" ON "', True), ('"yes"', True), ('1', True), ('0', False),
                                ('"off"', False), ('"unknown"', False)):
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

    def test_retired_tokens_and_null_top_level_fallback(self):
        for value in ('false', '0', '"off"', '"no"'):
            self.assertTrue(self.read('gateway:\n  multiplex_profiles: '+value+'\n').multiplex_false_retired)
        self.assertTrue(self.read('multiplex_profiles: null\ngateway:\n  multiplex_profiles: false\n').multiplex_false_retired)
        self.assertFalse(self.read('gateway: {}\n').multiplex_false_retired)

    def test_replacement_during_read_refused(self):
        original = os.read
        changed = False
        def replace_during_read(fd, size):
            nonlocal changed
            raw = original(fd, size)
            if not changed:
                changed = True
                replacement = self.home / 'replacement.yaml'
                replacement.write_text('gateway: {standalone: false}\n')
                replacement.replace(self.path)
            return raw
        with mock.patch('stability_core.hermes_profile_config.os.read', side_effect=replace_during_read):
            with self.assertRaises(ValueError): self.read('gateway: {standalone: true}\n')

    def test_change_during_parsing_refused(self):
        import yaml
        original = yaml.load
        def changed(raw, **kwargs):
            result = original(raw, **kwargs)
            self.path.write_text('gateway: {standalone: false}\n')
            return result
        with mock.patch.object(yaml, 'load', side_effect=changed):
            with self.assertRaises(ValueError): self.read('gateway: {standalone: true}\n')

    def test_event_budget_refused_below_byte_budget(self):
        text = 'gateway: {standalone: true}\n' + ''.join('key'+str(n)+': value\n' for n in range(2200))
        self.assertLess(len(text.encode()), 65536)
        with self.assertRaises(ValueError): self.read(text)

    def test_missing_parser_dependency_refused(self):
        import builtins
        original = builtins.__import__
        def missing(name, *args, **kwargs):
            if name == 'yaml': raise ImportError('synthetic dependency absent')
            return original(name, *args, **kwargs)
        with mock.patch.object(builtins, '__import__', side_effect=missing):
            with self.assertRaisesRegex(ValueError, '^profile config interpretation refused$'):
                self.read('gateway: {standalone: true}\n')
