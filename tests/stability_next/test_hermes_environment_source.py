import hashlib,os,tempfile,unittest
from unittest import mock
from dataclasses import asdict
from pathlib import Path
from stability_core.hermes_environment_source import read_environment_source
class EnvironmentSourceTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(dir=Path.home());self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.path=self.root/'.env'
    def read(self,**kw):return read_environment_source(self.path,owner_uid=os.getuid(),**kw)
    def test_digest_without_values(self):
        self.path.write_text('SECRET=synthetic-private\n');self.path.chmod(0o600)
        evidence=self.read();self.assertTrue(evidence.present)
        self.assertEqual(evidence.sha256,hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertNotIn('synthetic-private',repr(asdict(evidence)))
        self.assertFalse(evidence.action_authorized)
    def test_optional_absence_and_required_missing(self):
        self.assertFalse(self.read(optional=True).present)
        with self.assertRaises(ValueError):self.read()
    def test_symlink_hardlink_permissions_and_budget(self):
        target=self.root/'target';target.write_text('secret');target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):self.read()
        self.path.unlink();os.link(target,self.path)
        with self.assertRaises(ValueError):self.read()
        self.path.unlink();self.path.write_text('x');self.path.chmod(0o666)
        with self.assertRaises(ValueError):self.read()
        self.path.chmod(0o600);self.path.write_text('x'*65537)
        with self.assertRaises(ValueError):self.read()
    def test_invalid_owner_and_optional_type(self):
        for uid in (True,-1,'0'):
            with self.assertRaises(ValueError):read_environment_source(self.path,owner_uid=uid)
        with self.assertRaises(ValueError):self.read(optional=1)

    def test_path_replacement_during_read_refused(self):
        self.path.write_text('original');self.path.chmod(0o600)
        original=os.read;changed=False
        def read(fd,size):
            nonlocal changed
            data=original(fd,size)
            if not changed:
                replacement=self.root/'replacement';replacement.write_text('replacement');replacement.chmod(0o600)
                os.replace(replacement,self.path);changed=True
            return data
        with mock.patch('os.read',side_effect=read):
            with self.assertRaises(ValueError):self.read()
        self.assertTrue(changed)
    def test_ancestor_permissions_change_during_read_refused(self):
        self.path.write_text('original');self.path.chmod(0o600)
        original=os.read
        def read(fd,size):
            data=original(fd,size);self.root.chmod(0o777);return data
        try:
            with mock.patch('os.read',side_effect=read):
                with self.assertRaises(ValueError):self.read()
        finally:self.root.chmod(0o700)
    def test_read_failure_redacted_and_descriptor_closed(self):
        self.path.write_text('secret');self.path.chmod(0o600)
        original=os.close;closed=[]
        def close(fd):closed.append(fd);return original(fd)
        with mock.patch('os.read',side_effect=OSError('SYNTHETIC_SECRET')),mock.patch('os.close',side_effect=close):
            with self.assertRaises(ValueError) as caught:self.read()
        self.assertNotIn('SYNTHETIC_SECRET',str(caught.exception))
        self.assertEqual(len(closed),1)
    def test_ancestor_change_during_absence_refused(self):
        def missing(*args,**kwargs):
            self.root.chmod(0o777);raise FileNotFoundError()
        try:
            with mock.patch('os.open',side_effect=missing):
                with self.assertRaises(ValueError):self.read(optional=True)
        finally:self.root.chmod(0o700)

    def test_path_budget_and_type_refused(self):
        for value in (b'/secret', None, '/secret\x00value', '/'+'x'*4097, '/'+'/'.join(['x']*129)):
            with self.assertRaises(ValueError):
                read_environment_source(value,owner_uid=os.getuid())
    def test_source_evidence_cannot_authorize(self):
        from stability_core.hermes_environment_source import EnvironmentSourceIdentity
        with self.assertRaises(ValueError):
            EnvironmentSourceIdentity(self.path,False,None,None,(),action_authorized=True)
