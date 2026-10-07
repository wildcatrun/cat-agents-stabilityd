import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from stability_core.actuation_lock import ActuationBusy, ActuationLock, UnsafeLockFile


class ActuationLockTest(unittest.TestCase):
    def test_competing_process_is_busy_and_lock_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock"
            root = Path(__file__).resolve().parents[2]
            script = (
                "from pathlib import Path\n"
                "from stability_core.actuation_lock import ActuationLock,ActuationBusy\n"
                "import sys\n"
                "try:\n"
                " with ActuationLock(Path(sys.argv[1])):sys.exit(1)\n"
                "except ActuationBusy:sys.exit(0)\n"
            )
            with ActuationLock(path):
                inode = path.stat().st_ino
                result = subprocess.run([sys.executable, "-c", script, str(path)], cwd=root, timeout=10)
                self.assertEqual(result.returncode, 0)
            self.assertEqual(path.stat().st_ino, inode)
            with ActuationLock(path):
                pass

    def test_released_after_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock"
            with self.assertRaises(ValueError), ActuationLock(path):
                raise ValueError("fake")
            with ActuationLock(path):
                pass

    def test_unsafe_lock_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock"
            path.write_text("")
            path.chmod(0o666)
            with self.assertRaises(UnsafeLockFile):
                with ActuationLock(path):
                    pass
            path.chmod(0o600)
            link = Path(tmp) / "hardlink"
            os.link(path, link)
            with self.assertRaises(UnsafeLockFile):
                with ActuationLock(path):
                    pass

    def test_run_once_dry_and_mutating_writer_share_lock_without_running_body(self):
        spec = importlib.util.spec_from_file_location(
            "stability_lock_test", Path(__file__).resolve().parents[2] / "bin/cat_agents_stabilityd.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock"
            with mock.patch.object(module, "ACTUATION_LOCK_PATH", path), mock.patch.object(
                module, "ensure_dirs"
            ), mock.patch.object(module, "_run_once_body") as body, ActuationLock(path):
                for no_action in (False, True):
                    result = module.run_once(None, no_action=no_action)
                    self.assertEqual(result["status"], "busy")
                    self.assertFalse(result["statePublished"])
                body.assert_not_called()

    def test_body_error_is_not_misreported_as_lock_contention(self):
        spec = importlib.util.spec_from_file_location(
            "stability_lock_body_test", Path(__file__).resolve().parents[2] / "bin/cat_agents_stabilityd.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock"
            with mock.patch.object(module, "ACTUATION_LOCK_PATH", path), mock.patch.object(
                module, "ensure_dirs"
            ), mock.patch.object(module, "_run_once_body", side_effect=ActuationBusy("fake body error")):
                with self.assertRaisesRegex(ActuationBusy, "body error"):
                    module.run_once(None)
            with ActuationLock(path):
                pass


if __name__ == "__main__":
    unittest.main()
