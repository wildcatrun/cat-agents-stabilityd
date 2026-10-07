import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import patch_openclaw_catalog_idle as module

class PatchTests(unittest.TestCase):
    def test_unknown_source_is_rejected(self):
        with self.assertRaises(ValueError):
            module.candidate(b'unsupported')

    def test_apply_repeat_and_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'package'
            (root / 'dist').mkdir(parents=True)
            (root / 'package.json').write_text(json.dumps({'name': 'openclaw', 'version': '2026.9.7'}))
            original = (module.OLD + '\n').encode()
            target = root / 'dist' / module.NAME
            target.write_bytes(original)
            artifact = Path(td) / 'evidence'
            argv = ['patch', '--package-root', str(root), '--artifact-dir', str(artifact)]
            with patch.object(module, 'BASELINE', module.digest(original)), contextlib.redirect_stdout(io.StringIO()):
                with patch('sys.argv', argv + ['--apply']):
                    module.main()
                patched = target.read_bytes()
                self.assertIn(module.NEW.encode(), patched)
                with patch('sys.argv', argv + ['--apply']), self.assertRaises(ValueError):
                    module.main()
                target.write_bytes(patched + b'tamper')
                with patch('sys.argv', argv + ['--rollback']), self.assertRaises(ValueError):
                    module.main()
                self.assertEqual(target.read_bytes(), patched + b'tamper')
                target.write_bytes(patched)
                with patch('sys.argv', argv + ['--rollback']):
                    module.main()
                self.assertEqual(target.read_bytes(), original)

    def test_dry_run_does_not_change_live_code(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'package'
            (root / 'dist').mkdir(parents=True)
            (root / 'package.json').write_text(json.dumps({'name': 'openclaw', 'version': '2026.9.7'}))
            original = module.OLD.encode()
            target = root / 'dist' / module.NAME
            target.write_bytes(original)
            with patch.object(module, 'BASELINE', module.digest(original)), patch('sys.argv', ['patch', '--package-root', str(root), '--artifact-dir', str(Path(td) / 'evidence')]), contextlib.redirect_stdout(io.StringIO()):
                module.main()
            self.assertEqual(target.read_bytes(), original)

if __name__ == '__main__':
    unittest.main()
