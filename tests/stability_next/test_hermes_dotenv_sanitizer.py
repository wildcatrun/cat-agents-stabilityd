import ast
import codecs
from dataclasses import replace
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from stability_core.hermes_dotenv_sanitizer import (
    observe_dotenv_sanitizer, _sanitize_lines, SANITIZE_LINES_SOURCE_SHA256,
    SANITIZER_ROUTE_SOURCE_SHA256,
)


class DotenvSanitizerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / '.env'
        self.path.touch(mode=0o600)

    def observe(self, raw, **kw):
        self.path.write_bytes(raw)
        self.path.chmod(0o600)
        return observe_dotenv_sanitizer(self.path, owner_uid=os.getuid(), **kw)

    def test_lf_crlf_and_bom_no_rewrite_and_actual_source_digest(self):
        for raw in (b'HOME=/fixture\n', b'HOME=/fixture\r\n',
                    codecs.BOM_UTF8 + b'HOME=/fixture\n', b''):
            with self.subTest(raw=raw):
                result = self.observe(raw)
                self.assertFalse(result.rewrite_required)
                self.assertEqual(result.reason, 'no-rewrite-observed')
                self.assertEqual(result.source_identity.sha256, hashlib.sha256(raw).hexdigest())
                self.assertEqual(self.path.read_bytes(), raw)

    def test_whitespace_multiline_quotes_and_final_newline_require_rewrite(self):
        for raw in (b' HOME=/fixture \n', b'HOME=/fixture',
                    b'HOME="first\n  PRIVATE_FIXTURE  \nlast"\n'):
            with self.subTest(raw=raw):
                result = self.observe(raw)
                self.assertTrue(result.rewrite_required)
                self.assertNotIn('PRIVATE_FIXTURE', repr(result))
                self.assertEqual(self.path.read_bytes(), raw)

    def test_comments_blank_and_unicode_line_separators_match_readlines(self):
        for raw in (b'  # comment  \n  \n\n', 'HOME="first\u2028last"\n'.encode()):
            self.assertFalse(self.observe(raw).rewrite_required)
        self.assertTrue(self.observe(b'# comment').rewrite_required)

    def test_utf16_and_nul_require_rewrite_without_modification(self):
        for raw in ('HOME=/fixture\r\n'.encode('utf-16'), b'HOME=/fix\x00ture\n'):
            result = self.observe(raw)
            self.assertTrue(result.rewrite_required)
            self.assertEqual(self.path.read_bytes(), raw)

    def test_utf32_invalid_utf16_and_invalid_utf8_never_mark_safe(self):
        for raw, reason in (('HOME=x\n'.encode('utf-32'), 'utf32-skipped-unqualified'),
                            (codecs.BOM_UTF16_LE + b'x', 'utf16-decode-skipped'),
                            (b'\xffHOME=x\n', 'leading-replacement-skipped'),
                            (b'HOME=/caf\xe9\n', 'invalid-utf8-unqualified')):
            with self.subTest(reason=reason):
                result = self.observe(raw)
                self.assertIsNone(result.rewrite_required)
                self.assertEqual(result.reason, reason)
                self.assertEqual(self.path.read_bytes(), raw)

    def test_missing_is_absence_not_no_rewrite_certificate(self):
        self.path.unlink()
        result = observe_dotenv_sanitizer(self.path, owner_uid=os.getuid(), optional=True)
        self.assertFalse(result.source_identity.present)
        self.assertIsNone(result.rewrite_required)
        self.assertEqual(result.reason, 'source-missing')

    def test_same_fd_parser_replacement_refuses_observation(self):
        self.path.write_bytes(b'HOME=/fixture\n')
        import stability_core.hermes_dotenv_sanitizer as module
        original = module._sanitize_lines
        def sanitizer(lines):
            replacement = self.root / 'replacement'
            replacement.write_bytes(b'HOME=/replacement\n')
            replacement.chmod(0o600)
            os.replace(replacement, self.path)
            return original(lines)
        with mock.patch.object(module, '_sanitize_lines', side_effect=sanitizer):
            with self.assertRaisesRegex(ValueError, 'projection drift'):
                observe_dotenv_sanitizer(self.path, owner_uid=os.getuid())

    def test_fixed_errors_fd_cleanup_and_non_authority(self):
        import stability_core.hermes_dotenv_sanitizer as module
        self.path.write_bytes(b'SECRET=PRIVATE_FIXTURE\n')
        close, closed = os.close, []
        def recording(fd): closed.append(fd); return close(fd)
        with mock.patch.object(module, '_sanitize_lines', side_effect=RuntimeError('PRIVATE_FIXTURE')), \
             mock.patch('os.close', side_effect=recording):
            with self.assertRaises(ValueError) as caught:
                observe_dotenv_sanitizer(self.path, owner_uid=os.getuid())
        self.assertEqual(str(caught.exception), 'environment source projection refused')
        self.assertEqual(len(closed), 1)
        result = self.observe(b'HOME=/fixture\n')
        self.assertFalse(result.action_authorized)
        self.assertFalse(result.artifact_approved)
        with self.assertRaises(ValueError): replace(result, effective_coverage='complete')
        with self.assertRaises(ValueError): replace(result, action_authorized=True)
        with self.assertRaises(ValueError): replace(result, reason='utf32-skipped-unqualified')

    def test_file_and_line_budgets_no_weakening_of_source_limit(self):
        with self.assertRaises(ValueError): self.observe(b'x' * 65537)
        result = self.observe(b'\n' * 4097)
        self.assertIsNone(result.rewrite_required)
        self.assertEqual(result.reason, 'line-budget-unqualified')

    def test_actual_snapshot_ast_hash_and_pure_mirror(self):
        repo = Path(__file__).resolve().parents[2]
        default = repo.parents[1] / '2026-10-04/execution/G2/2026-10-08/logs/hermes-launch-source'
        root = Path(os.environ.get('STABILITYD_QA_HERMES_LAUNCH_SNAPSHOT', str(default)))
        if not (root / 'config.py').is_file() or not (root / 'env_loader.py').is_file():
            self.skipTest('actual installed sanitizer source snapshot unavailable')
        function = None
        for file, name, digest in (('config.py', '_sanitize_env_lines', SANITIZE_LINES_SOURCE_SHA256),
                                   ('env_loader.py', '_sanitize_env_file_if_needed', SANITIZER_ROUTE_SOURCE_SHA256)):
            # Code source is not an environment file. This check does not raise
            # the runtime .env read budget to accommodate the large config.py.
            path = root / file
            self.assertLessEqual(path.stat().st_size, 2 * 1024 * 1024)
            source = path.read_text()
            node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(hashlib.sha256(ast.get_source_segment(source, node).encode()).hexdigest(), digest)
            if file == 'config.py': function = node
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), 'qualified-sanitize-lines', 'exec'), namespace)
        actual = namespace['_sanitize_env_lines']
        for raw in (b'HOME=x\n', b' HOME=x \n', b' # comment  \n \n', b'HOME=x',
                    'HOME="a\n  PRIVATE_FIXTURE  \nb"\n'.encode(), 'HOME="a\u2028b"\r\n'.encode()):
            with io.TextIOWrapper(io.BytesIO(raw), encoding='utf-8-sig', errors='replace', newline=None) as handle:
                lines = handle.readlines()
            self.assertEqual(_sanitize_lines(lines), actual(lines))


if __name__ == '__main__':
    unittest.main()
