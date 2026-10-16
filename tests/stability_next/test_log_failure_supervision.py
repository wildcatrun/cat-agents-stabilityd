"""Real local log-open failure relinquishes the daemon lock to existing supervision."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from test_self_progress import stabilityd


class LogFailureSupervisionTests(unittest.TestCase):
    def test_actual_log_open_failure_closes_lock_without_internal_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = (root/'daemon.lock').open('a+')
            lock_path = mock.Mock()
            lock_path.open.return_value = lock
            # Opening a directory for append deterministically fails; no mocked
            # log exception substitutes for the actual log_line path.
            log_target = root/'not-a-log-file'
            log_target.mkdir()
            with mock.patch.object(stabilityd,'ensure_dirs'), \
                 mock.patch.object(stabilityd,'LOCK_PATH',lock_path), \
                 mock.patch.object(stabilityd,'LOG_PATH',log_target), \
                 mock.patch.object(stabilityd.fcntl,'flock'), \
                 mock.patch.object(stabilityd.signal,'signal'), \
                 mock.patch.object(stabilityd,'init_db',return_value=object()) as init_db, \
                 mock.patch.object(stabilityd,'run_once') as run_once, \
                 mock.patch.object(stabilityd.time,'sleep') as sleep:
                with self.assertRaises(IsADirectoryError):
                    stabilityd.daemon_loop(no_action=True)
            self.assertTrue(lock.closed)
            lock_path.open.assert_called_once()
            init_db.assert_called_once()
            run_once.assert_not_called()
            sleep.assert_not_called()
            self.assertTrue(log_target.is_dir())


if __name__ == '__main__':
    unittest.main()
