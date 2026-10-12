import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from dataclasses import replace
from stability_core.hermes_profile_live import observe_profile_live


class ProfileLiveTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.home = self.root / 'profiles' / 'fixture'
        self.home.mkdir(parents=True)
        self.marker = self.home / 'config.yaml'
        self.marker.write_text('SYNTHETIC_SECRET')
        self.marker.chmod(0o600)

    def observe(self):
        return observe_profile_live(self.root, profile='fixture', owner_uid=os.getuid())

    def test_actual_markers_are_stat_only_no_secret_or_authority(self):
        with mock.patch('os.read', side_effect=AssertionError('content read forbidden')):
            result = self.observe()
        self.assertTrue(result.live)
        self.assertNotIn('SYNTHETIC_SECRET', repr(result))
        self.assertEqual(result.residency, 'unknown')
        self.assertFalse(result.action_authorized)
        with self.assertRaises(ValueError): replace(result, action_authorized=True)

    def test_ghost_profile_and_other_native_marker(self):
        self.marker.unlink()
        self.assertFalse(self.observe().live)
        (self.home / '.env').touch(mode=0o600)
        self.assertTrue(self.observe().live)  # named_profile_is_live, not servable identity

    def test_tombstone_present_and_missing_directory(self):
        self.assertTrue(self.observe().live)
        deleted = self.root / 'profiles' / '.deleted'
        deleted.mkdir()
        (deleted / 'fixture').touch(mode=0o600)
        result = self.observe()
        self.assertFalse(result.live)
        self.assertEqual(result.reason, 'profile-tombstoned')

    def test_missing_home_is_absence_not_healthy(self):
        self.marker.unlink()
        self.home.rmdir()
        self.assertEqual(self.observe().reason, 'profile-home-missing')
        (self.root / 'profiles').rmdir()
        self.assertEqual(self.observe().reason, 'profiles-directory-missing')

    def test_marker_and_tombstone_symlinks_refused_even_dangling(self):
        self.marker.unlink()
        self.marker.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError): self.observe()
        self.marker.unlink()
        self.marker.touch(mode=0o600)
        deleted = self.root / 'profiles' / '.deleted'
        deleted.mkdir()
        (deleted / 'fixture').symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError): self.observe()

    def test_permissions_and_hardlinks_refused(self):
        self.marker.chmod(0o666)
        with self.assertRaises(ValueError): self.observe()
        self.marker.chmod(0o600)
        os.link(self.marker, self.home / 'auth.json')
        with self.assertRaises(ValueError): self.observe()

    def test_ancestor_mode_owner_and_symlink_refused(self):
        self.home.chmod(0o777)
        try:
            with self.assertRaises(ValueError): self.observe()
        finally:
            self.home.chmod(0o700)
        original = os.stat
        def wrong_owner(name, *args, **kwargs):
            info = original(name, *args, **kwargs)
            if name == 'config.yaml' and kwargs.get('dir_fd') is not None:
                values = list(info)
                values[4] = os.getuid() + 98765
                return os.stat_result(values)
            return info
        with mock.patch('os.stat', side_effect=wrong_owner):
            with self.assertRaises(ValueError): self.observe()
        retired = self.home.parent / 'retired'
        self.home.rename(retired)
        self.home.symlink_to(retired, target_is_directory=True)
        with self.assertRaises(ValueError): self.observe()

    def test_marker_replacement_after_stat_refused(self):
        original = os.stat
        changed = False
        def observed(name, *args, **kwargs):
            nonlocal changed
            info = original(name, *args, **kwargs)
            if name == 'config.yaml' and kwargs.get('dir_fd') is not None and not changed:
                replacement = self.home / 'replace'
                replacement.touch(mode=0o600)
                os.replace(replacement, self.marker)
                changed = True
            return info
        with mock.patch('os.stat', side_effect=observed):
            with self.assertRaises(ValueError): self.observe()
        self.assertTrue(changed)

    def test_deleted_directory_appearing_after_absence_refused(self):
        original = os.stat
        changed = False
        def observed(name, *args, **kwargs):
            nonlocal changed
            try:
                return original(name, *args, **kwargs)
            except FileNotFoundError:
                if name == '.deleted' and not changed:
                    (self.root / 'profiles' / '.deleted').mkdir()
                    changed = True
                raise
        with mock.patch('os.stat', side_effect=observed):
            with self.assertRaises(ValueError): self.observe()
        self.assertTrue(changed)

    def test_directory_replacement_refused_and_descriptors_closed(self):
        original = os.fstat
        changed = False
        def observed(fd):
            nonlocal changed
            info = original(fd)
            if info.st_ino == self.home.stat().st_ino and not changed:
                self.home.rename(self.home.parent / 'retired')
                self.home.mkdir()
                changed = True
            return info
        close = os.close
        closed = []
        def recording(fd): closed.append(fd); return close(fd)
        with mock.patch('os.fstat', side_effect=observed), mock.patch('os.close', side_effect=recording):
            with self.assertRaises(ValueError): self.observe()
        self.assertTrue(changed)
        self.assertGreater(len(closed), 0)
        for fd in closed:
            with self.assertRaises(OSError): original(fd)

    def test_scope_and_reader_errors_redacted(self):
        for uid in (True, -1, '0'):
            with self.assertRaises(ValueError): observe_profile_live(self.root, profile='fixture', owner_uid=uid)
        for profile in ('default', '../fixture', 'OTHER'):
            with self.assertRaises(ValueError): observe_profile_live(self.root, profile=profile, owner_uid=os.getuid())
        with mock.patch('os.open', side_effect=PermissionError('SYNTHETIC_SECRET')):
            with self.assertRaises(ValueError) as caught: self.observe()
        self.assertNotIn('SYNTHETIC_SECRET', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
