import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
from unittest import mock

from stability_core.hermes_dotenv_projection import (
    ParserSource, TrustedDotenvParser, CONTROL_KEYS, read_dotenv_governance,
    DotenvLayer, read_dotenv_governance_layers,
)


class DotenvProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = Path(__file__).resolve().parents[2]
        default = repo.parents[1] / '2026-10-04/execution/G2/2026-10-08/logs/hermes-launch-source/server-dotenv/dotenv'
        cls.snapshot = Path(os.environ.get('STABILITYD_QA_DOTENV_SNAPSHOT', str(default)))
        if not all((cls.snapshot / name).is_file() for name in ('parser.py', 'variables.py', 'version.py')):
            raise unittest.SkipTest('SHA-bound installed server dotenv code snapshot unavailable')
        expected = {'parser.py': '25226977de2d1a1be7ccebf83cbdc3ade5352ede6feab4caee9a7c1ba4677cbe',
                    'variables.py': '083d2a5cebefa41deae51a4140c0fda97eaf1d7ed2c96f92ba2c063054a5b74f',
                    'version.py': 'bae7f854db53340f777cc86802eafd61a7f368a2459dccd8f87d524824ae4554'}
        for name, digest in expected.items():
            if hashlib.sha256((cls.snapshot / name).read_bytes()).hexdigest() != digest:
                raise AssertionError('installed parser snapshot identity mismatch')

    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / '.env'
        functions, sources = {}, []
        for role in ('parser', 'variables', 'version'):
            path = self.root / (role + '.py')
            raw = (self.snapshot / path.name).read_bytes()
            path.write_bytes(raw)
            path.chmod(0o600)
            sources.append(ParserSource(role, path, hashlib.sha256(raw).hexdigest()))
            if role != 'version':
                spec = importlib.util.spec_from_file_location('qualified_' + role, path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                functions[role] = module
        self.parser = TrustedDotenvParser('1.2.2', tuple(sources),
                           functions['parser'].parse_stream, functions['variables'].parse_variables)
        self.write(b'HERMES_HOME=/fixture\n')

    def write(self, data):
        self.path.write_bytes(data)
        self.path.chmod(0o600)

    def read(self, **changes):
        kwargs = dict(owner_uid=os.getuid(), parser=self.parser,
                      parent_values={}, known_absent=CONTROL_KEYS)
        kwargs.update(changes)
        return read_dotenv_governance(self.path, **kwargs)

    def values(self, **changes):
        return dict(self.read(**changes).governance_values)

    def layers(self, texts, overrides=None, **changes):
        paths = []
        for index, text in enumerate(texts):
            path = self.root / ('layer-' + str(index))
            if text is not None:
                path.write_bytes(text)
                path.chmod(0o600)
            paths.append(DotenvLayer(path, optional=text is None,
                         override=True if overrides is None else overrides[index]))
        kwargs = dict(owner_uid=os.getuid(), parser=self.parser, parent_values={}, known_absent=CONTROL_KEYS)
        kwargs.update(changes)
        return read_dotenv_governance_layers(tuple(paths), **kwargs)

    def test_ordered_layers_see_previous_raw_values_and_override_policy(self):
        result = self.layers([b'HERMES_HOME=/first\n', b'HERMES_HOME=${HERMES_HOME}/second\n'])
        self.assertEqual(dict(result.governance_values)['HERMES_HOME'], '/first/second')
        # Reuse existing files, avoiding artificial directory mutations in fences.
        layers = tuple(DotenvLayer(self.root / ('layer-' + str(i)), override=flag)
                       for i, flag in enumerate((True, False)))
        result = read_dotenv_governance_layers(layers, owner_uid=os.getuid(), parser=self.parser,
                                               parent_values={}, known_absent=CONTROL_KEYS)
        self.assertEqual(dict(result.governance_values)['HERMES_HOME'], '/first')
        self.assertEqual([entry[2] for entry in result.layer_sources], [True, False])

    def test_ordered_raw_pythonpath_never_interpolates_redaction_digest(self):
        result = self.layers([b'PYTHONPATH=/fixture/code\n', b'HERMES_HOME=${PYTHONPATH}/profile\n'])
        values = dict(result.governance_values)
        self.assertEqual(values['HERMES_HOME'], '/fixture/code/profile')
        self.assertTrue(values['PYTHONPATH'].startswith('sha256:'))
        self.assertNotIn(values['PYTHONPATH'], values['HERMES_HOME'])
        self.assertIn('PYTHONPATH', result.unresolved_governance_keys)

    def test_ordered_missing_empty_and_bare_layers_preserve_publication(self):
        result = self.layers([b'HERMES_HOME=/first\n', None, b'HERMES_HOME\n'])
        self.assertEqual(dict(result.governance_values)['HERMES_HOME'], '/first')
        self.assertFalse(result.layer_sources[1][0].present)
        result = self.layers([b'HERMES_HOME=/first\n', b'HERMES_HOME=\n', b'HOME=${HERMES_HOME:-/fallback}\n'])
        self.assertEqual(dict(result.governance_values)['HOME'], '')

    def test_ordered_known_absent_default_and_unknown_remain_distinct(self):
        text = [None, b'HERMES_HOME=${HOME:-/fallback}\n']
        self.assertEqual(dict(self.layers(text).governance_values)['HERMES_HOME'], '/fallback')
        result = self.layers(text, known_absent=CONTROL_KEYS - {'HOME'},
                             unknown_dependencies=frozenset({'HOME'}))
        self.assertNotIn('HERMES_HOME', dict(result.governance_values))
        self.assertIn('HERMES_HOME', result.unresolved_governance_keys)

    def test_ordered_secret_dependencies_never_escape_between_layers(self):
        result = self.layers([b'SECRET=PRIVATE_FIXTURE\n',
                             b'HERMES_HOME=${SECRET:-/fallback}\nLD_PRELOAD=PRIVATE_FIXTURE\n'])
        self.assertNotIn('PRIVATE_FIXTURE', repr(result))
        self.assertNotIn('HERMES_HOME', dict(result.governance_values))
        self.assertEqual(result.layer_import_influence_digests[0][:2], (1, 'LD_PRELOAD'))
        self.assertFalse(result.artifact_approved)
        with self.assertRaises(ValueError): replace(result, effective_coverage='complete')

    def test_earlier_layer_mutation_during_later_parse_refused(self):
        first, second = self.root / 'first', self.root / 'second'
        first.write_bytes(b'HERMES_HOME=/first\n'); first.chmod(0o600)
        second.write_bytes(b'HOME=/second\n'); second.chmod(0o600)
        globals_ = self.parser.tokenize.__globals__
        original = globals_['Reader']
        count = 0
        def reader(stream):
            nonlocal count
            count += 1
            if count == 2: first.write_bytes(b'HERMES_HOME=/drift\n')
            return original(stream)
        with mock.patch.dict(globals_, Reader=reader):
            with self.assertRaisesRegex(ValueError, 'ordered source drift'):
                read_dotenv_governance_layers((DotenvLayer(first), DotenvLayer(second)),
                    owner_uid=os.getuid(), parser=self.parser, parent_values={}, known_absent=CONTROL_KEYS)

    def test_optional_earlier_source_appearing_during_later_parse_refused(self):
        missing, second = self.root / 'missing', self.root / 'second'
        second.write_bytes(b'HOME=/second\n'); second.chmod(0o600)
        globals_ = self.parser.tokenize.__globals__
        original = globals_['Reader']
        def reader(stream):
            missing.touch(mode=0o600)
            return original(stream)
        with mock.patch.dict(globals_, Reader=reader):
            with self.assertRaises(ValueError):
                read_dotenv_governance_layers((DotenvLayer(missing, optional=True), DotenvLayer(second)),
                    owner_uid=os.getuid(), parser=self.parser, parent_values={}, known_absent=CONTROL_KEYS)

    def test_ordered_bounds_duplicates_types_and_context(self):
        kwargs = dict(owner_uid=os.getuid(), parser=self.parser, parent_values={}, known_absent=CONTROL_KEYS)
        for layers in ((), [DotenvLayer(self.path)], (DotenvLayer(self.path),) * 33,
                       (DotenvLayer(self.path), DotenvLayer(self.path, override=False)),
                       (DotenvLayer(self.path, optional=1),), (DotenvLayer(self.path, override=None),)):
            with self.subTest(layers=layers), self.assertRaises(ValueError):
                read_dotenv_governance_layers(layers, **kwargs)
        with self.assertRaises(ValueError):
            read_dotenv_governance_layers((DotenvLayer(self.path),), context='reload', **kwargs)

    def test_actual_server_parser_identity_and_non_authority(self):
        result = self.read()
        self.assertEqual(result.parser_version, '1.2.2')
        self.assertEqual(result.source_identity.sha256, hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertFalse(result.artifact_approved)
        self.assertFalse(result.action_authorized)
        self.assertEqual(result.effective_coverage, 'incomplete')
        with self.assertRaises(ValueError): replace(result, effective_coverage='complete')

    def test_override_both_directions_and_assignment_order(self):
        self.write(b'HERMES_HOME=${HOME}/one\nHERMES_HOME=${HERMES_HOME}/two\n')
        context = dict(parent_values={'HOME': '/base', 'HERMES_HOME': '/parent'},
                       known_absent=CONTROL_KEYS - {'HOME', 'HERMES_HOME'})
        self.assertEqual(self.values(**context)['HERMES_HOME'], '/base/one/two')
        self.assertEqual(self.values(**context, override=False)['HERMES_HOME'], '/parent')
        self.assertEqual(self.values(parent_values={'HOME': '/base'},
                                    known_absent=CONTROL_KEYS - {'HOME'}, override=False)['HERMES_HOME'], '/base/one/two')

    def test_empty_bare_and_absent_defaults_are_distinct(self):
        for prefix, expected in ((b'', '/default'), (b'HOME=\n', ''), (b'HOME\n', '')):
            self.write(prefix + b'HERMES_HOME=${HOME:-/default}\n')
            self.assertEqual(self.values()['HERMES_HOME'], expected)
        self.write(b'HERMES_HOME\n')
        self.assertEqual(self.values(parent_values={'HERMES_HOME': '/parent'},
                                    known_absent=CONTROL_KEYS - {'HERMES_HOME'})['HERMES_HOME'], '/parent')
        self.write(b'HERMES_HOME=/first\nHERMES_HOME\n')
        self.assertNotIn('HERMES_HOME', self.values())
        self.assertEqual(self.values(parent_values={'HERMES_HOME': '/parent'},
                                    known_absent=CONTROL_KEYS - {'HERMES_HOME'})['HERMES_HOME'], '/parent')

    def test_unknown_parent_does_not_take_default(self):
        self.write(b'HERMES_HOME=${HOME:-/default}\n')
        result = self.read(known_absent=CONTROL_KEYS - {'HOME'}, unknown_dependencies=frozenset({'HOME'}))
        self.assertNotIn('HERMES_HOME', dict(result.governance_values))
        self.assertIn('HERMES_HOME', result.unresolved_governance_keys)

    def test_nonwhitelist_dependency_and_secret_output_refused(self):
        self.write(b'SECRET=PRIVATE_FIXTURE\nHERMES_HOME=${SECRET}/home\nAPI_KEY=PRIVATE_FIXTURE\n')
        result = self.read()
        self.assertNotIn('PRIVATE_FIXTURE', repr(result))
        self.assertNotIn('SECRET', repr(result))
        self.assertNotIn('HERMES_HOME', dict(result.governance_values))
        self.assertIn('HERMES_HOME', result.unresolved_governance_keys)

    def test_bom_latin1_export_quotes_and_comments(self):
        for prefix, suffix, expected in ((b'\xef\xbb\xbf', b'/fixture', '/fixture'),
                                         (b'', b'/caf\xe9', '/café')):
            self.write(prefix + b'export HERMES_HOME="' + suffix + b'" # comment\n')
            self.assertEqual(self.values()['HERMES_HOME'], expected)

    def test_import_values_only_digests_and_unresolved(self):
        self.write(b'PYTHONPATH=/PRIVATE_IMPORT\nLD_PRELOAD=PRIVATE_LIBRARY\n')
        result = self.read()
        self.assertNotIn('PRIVATE_IMPORT', repr(result))
        self.assertNotIn('PRIVATE_LIBRARY', repr(result))
        self.assertTrue(dict(result.governance_values)['PYTHONPATH'].startswith('sha256:'))
        self.assertIn('PYTHONPATH', result.unresolved_governance_keys)
        self.assertIn('LD_PRELOAD', dict(result.import_influence_digests))

    def test_managed_and_process_controls_cannot_disappear_from_projection(self):
        self.write(b'HERMES_MANAGED_DIR=${HOME}/managed\nPYTEST_CURRENT_TEST=\nHERMES_UPDATE_POST_SWAP=1\n')
        values = self.values(parent_values={'HOME': '/fixture'}, known_absent=CONTROL_KEYS - {'HOME'})
        self.assertEqual(values['HERMES_MANAGED_DIR'], '/fixture/managed')
        self.assertIn('PYTEST_CURRENT_TEST', values)
        self.assertEqual(values['PYTEST_CURRENT_TEST'], '')
        self.assertEqual(values['HERMES_UPDATE_POST_SWAP'], '1')

    def test_unknown_parent_presence_prevents_override_false_claim(self):
        self.write(b'HERMES_HOME=/new\n')
        result = self.read(known_absent=CONTROL_KEYS - {'HERMES_HOME'}, override=False)
        self.assertIn('HERMES_HOME', result.unresolved_governance_keys)
        self.assertNotIn('HERMES_HOME', dict(result.governance_values))

    def test_library_version_sources_and_callback_cannot_be_implicit(self):
        for parser in (replace(self.parser, version='1.2.1'),
                       replace(self.parser, sources=self.parser.sources[:-1]),
                       replace(self.parser, variables=lambda value: ())):
            with self.assertRaises(ValueError): self.read(parser=parser)
        self.parser.sources[0].path.write_text('# replaced')
        with self.assertRaises(ValueError): self.read()

    def test_parser_or_file_errors_are_fixed_and_redacted(self):
        self.write(b'HERMES_HOME="PRIVATE_FIXTURE\n')
        with self.assertRaises(ValueError) as caught: self.read()
        self.assertEqual(str(caught.exception), 'environment source projection refused')
        self.assertNotIn('PRIVATE_FIXTURE', str(caught.exception))
        self.write(b'\xff\xfePRIVATE_FIXTURE')
        with self.assertRaises(ValueError): self.read()
        self.write(b'HERMES_HOME=one\x00PRIVATE_FIXTURE')
        with self.assertRaises(ValueError): self.read()

    def test_parser_budgets_and_first_pass_scope(self):
        self.write(b'OTHER=one\n' * 1025)
        with self.assertRaises(ValueError): self.read()
        self.write(b'HERMES_HOME=' + b'x' * 4097)
        with self.assertRaises(ValueError): self.read()
        self.write(b'HERMES_HOME=/fixture\n')
        with self.assertRaises(ValueError): self.read(context='prior-pass-reload')
        with self.assertRaises(ValueError): self.read(override=1)

    def test_same_fd_projection_rejects_actual_replacement(self):
        original = self.parser.tokenize
        changed = False
        # Preserve the trusted actual function binding while injecting the drift
        # into its already-qualified parser helper, not into the interface.
        function_globals = original.__globals__
        original_reader = function_globals['Reader']
        def reader(stream):
            nonlocal changed
            if not changed:
                replacement = self.root / 'replacement'
                replacement.write_bytes(self.path.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, self.path)
                changed = True
            return original_reader(stream)
        with mock.patch.dict(function_globals, Reader=reader):
            with self.assertRaisesRegex(ValueError, 'projection drift'): self.read()
        self.assertTrue(changed)

    def test_absence_is_not_empty_file_and_no_unbound_projection(self):
        self.path.unlink()
        result = self.read(optional=True)
        self.assertFalse(result.source_identity.present)
        self.assertEqual(result.defined_governance_keys, ())
        with self.assertRaises(ValueError): self.read(parent_values={'SECRET': 'private'})
        with self.assertRaises(ValueError): self.read(parent_values={'HOME': '/base'})


if __name__ == '__main__':
    unittest.main()
