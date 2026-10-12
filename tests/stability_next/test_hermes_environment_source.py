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
    def test_bundle_preserves_order_and_absence(self):
        from stability_core.hermes_environment_source import read_environment_sources
        self.path.write_text('fixture');self.path.chmod(0o600)
        missing=self.root/'missing'
        evidence=read_environment_sources([(self.path,False),(missing,True)],owner_uid=os.getuid())
        self.assertEqual([item.path for item in evidence],[self.path,missing])
        self.assertEqual([item.present for item in evidence],[True,False])
    def test_bundle_detects_change_between_sweeps(self):
        from stability_core import hermes_environment_source as module
        self.path.write_text('before');self.path.chmod(0o600)
        original=module.read_environment_source;calls=0
        def read(*args,**kwargs):
            nonlocal calls
            evidence=original(*args,**kwargs);calls+=1
            if calls==1:self.path.write_text('changed-longer')
            return evidence
        with mock.patch.object(module,'read_environment_source',side_effect=read):
            with self.assertRaisesRegex(ValueError,'set drift'):
                module.read_environment_sources([(self.path,False)],owner_uid=os.getuid())
    def test_bundle_invalid_and_duplicate_sources_refused(self):
        from stability_core.hermes_environment_source import read_environment_sources
        for sources in ([],[(self.path,True)]*33,[(self.path,True),(self.path,False)],[(self.path,1)],['secret']):
            with self.assertRaises(ValueError):read_environment_sources(sources,owner_uid=os.getuid())

    def test_optional_missing_parent_has_trusted_absence_anchor(self):
        path=self.root/'missing-parent'/'nested'/'.env'
        evidence=read_environment_source(path,owner_uid=os.getuid(),optional=True)
        self.assertFalse(evidence.present)
        self.assertEqual(evidence.missing_ancestor,self.root/'missing-parent')
        self.assertTrue(evidence.ancestors)
        with self.assertRaises(ValueError):read_environment_source(path,owner_uid=os.getuid())
    def test_missing_parent_symlink_is_not_absence(self):
        parent=self.root/'missing-parent';parent.symlink_to(self.root/'does-not-exist')
        with self.assertRaises(ValueError):read_environment_source(parent/'.env',owner_uid=os.getuid(),optional=True)
    def test_parent_created_during_absence_observation_refused(self):
        parent=self.root/'missing-parent';original=Path.lstat;calls=0
        def lstat(path,*args,**kwargs):
            nonlocal calls
            if path==parent:
                calls+=1
                if calls==2:parent.mkdir()
            return original(path,*args,**kwargs)
        with mock.patch.object(Path,'lstat',lstat):
            with self.assertRaises(ValueError):read_environment_source(parent/'.env',owner_uid=os.getuid(),optional=True)
    def test_optional_permission_failure_is_not_absence(self):
        parent=self.root/'missing-parent';original=Path.lstat
        def lstat(path,*args,**kwargs):
            if path==parent:raise PermissionError('PRIVATE_VALUE')
            return original(path,*args,**kwargs)
        with mock.patch.object(Path,'lstat',lstat):
            with self.assertRaises(ValueError) as caught:read_environment_source(parent/'.env',owner_uid=os.getuid(),optional=True)
        self.assertNotIn('PRIVATE_VALUE',str(caught.exception))
    def test_optional_parent_file_is_not_directory_absence(self):
        parent=self.root/'parent-file';parent.write_text('fixture')
        with self.assertRaises(ValueError):read_environment_source(parent/'.env',owner_uid=os.getuid(),optional=True)
    def test_bundle_detects_missing_parent_becoming_present(self):
        from stability_core import hermes_environment_source as module
        parent=self.root/'new-parent';path=parent/'.env';original=module.read_environment_source;count=0
        def read(*args,**kwargs):
            nonlocal count
            result=original(*args,**kwargs);count+=1
            if count==1:parent.mkdir()
            return result
        with mock.patch.object(module,'read_environment_source',side_effect=read):
            with self.assertRaises(ValueError):module.read_environment_sources([(path,True)],owner_uid=os.getuid())
