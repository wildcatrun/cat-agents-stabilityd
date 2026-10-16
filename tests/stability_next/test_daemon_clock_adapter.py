import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from stability_core import daemon_clock as a
from stability_core.clock_discipline import ClockRefused


class LinuxClockAdapterTests(unittest.TestCase):
    def test_exact_linux_sources_and_no_wall_substitute(self):
        with mock.patch.object(a.Path,'read_text',return_value='11111111-2222-3333-4444-555555555555\n') as read, \
             mock.patch.object(a.time,'CLOCK_BOOTTIME',7,create=True), \
             mock.patch.object(a.time,'clock_gettime_ns',return_value=1234567890) as boot, \
             mock.patch.object(a.time,'time_ns',return_value=9999999999):
            sample=a.linux_sample()
            self.assertEqual((sample['mono_ms'],sample['wall_ms']),(1234,9999))
            boot.assert_called_once_with(7)
            read.assert_called_once_with(encoding='ascii')
        with mock.patch.object(a.Path,'read_text',return_value='untrusted-boot'),mock.patch.object(a.time,'CLOCK_BOOTTIME',7,create=True):
            with self.assertRaises(ClockRefused):a.linux_sample()

    def test_missing_kernel_source_and_non_durable_settings_fail_closed(self):
        with mock.patch.object(a.Path,'read_text',side_effect=OSError('no kernel source')),mock.patch.object(a.time,'CLOCK_BOOTTIME',7,create=True):
            with self.assertRaises(OSError):a.linux_sample()
        with tempfile.TemporaryDirectory() as temp, sqlite3.connect(Path(temp)/'state.db') as conn:
            clock=a.DaemonClock(conn,restart_ms=1800,restart_window_ms=21600,session_ms=21600,lifecycle_ms=1800,max_restarts=3)
            conn.execute('BEGIN')
            with self.assertRaisesRegex(ClockRefused,'settings'):clock.observe()
            self.assertEqual(conn.execute("SELECT count(*) FROM sqlite_master WHERE name GLOB 'stability_clock_*'").fetchone()[0],0)

if __name__=='__main__':unittest.main()
