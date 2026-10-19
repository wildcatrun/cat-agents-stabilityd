import os,tempfile,unittest
from pathlib import Path
from stability_core.session_api_capability import _endpoint_identity

class SessionListenerBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.proc=Path(self.tmp.name);(self.proc/'net').mkdir();(self.proc/'42/fd').mkdir(parents=True)
        (self.proc/'42/fd/7').symlink_to('socket:[12345]');self.uid=os.getuid()
        self.write('0100007F')
    def line(self,address,inode='12345',uid=None):
        return f'0: {address}:4965 00000000:0000 0A 0:0 0:0 0 {self.uid if uid is None else uid} 0 {inode}\n'
    def write(self,address):
        (self.proc/'net/tcp').write_text('header\n'+self.line(address));(self.proc/'net/tcp6').write_text('header\n')
    def read(self,address='127.0.0.1'):
        return _endpoint_identity(self.proc,42,18789,self.uid,address)
    def test_default_loopback_and_reviewed_wildcard_bound_to_same_actual_pid(self):
        self.assertEqual(self.read(),('0100007F:4965','12345',('7',)))
        self.write('00000000');self.assertEqual(self.read('0.0.0.0'),('00000000:4965','12345',('7',)))
    def test_unapproved_wildcard_and_unknown_address_refused(self):
        self.write('00000000')
        for address in ('127.0.0.1','10.0.4.17',None):
            with self.subTest(address=address),self.assertRaises(ValueError):self.read(address)
    def test_loopback_wildcard_overlap_and_duplicate_refused(self):
        for address in ('0100007F','00000000'):
            (self.proc/'net/tcp').write_text('header\n'+self.line('00000000')+self.line(address,'99999'))
            with self.subTest(address=address),self.assertRaises(ValueError):self.read('0.0.0.0')
    def test_wrong_owner_or_pid_fd_refused(self):
        (self.proc/'net/tcp').write_text('header\n'+self.line('0100007F',uid=self.uid+1))
        with self.assertRaises(ValueError):self.read()
        self.write('0100007F');(self.proc/'42/fd/7').unlink()
        with self.assertRaises(ValueError):self.read()
    def test_ipv6_competitor_and_unavailable_ipv6_observation_refused(self):
        (self.proc/'net/tcp6').write_text('header\n'+self.line('0'*32))
        with self.assertRaises(ValueError):self.read()
        (self.proc/'net/tcp6').unlink()
        with self.assertRaises(OSError):self.read()
    def test_identity_detects_address_and_inode_changes(self):
        first=self.read();self.write('00000000');self.assertNotEqual(first,self.read('0.0.0.0'))
        self.write('0100007F');(self.proc/'net/tcp').write_text('header\n'+self.line('0100007F','55555'))
        (self.proc/'42/fd/7').unlink();(self.proc/'42/fd/7').symlink_to('socket:[55555]')
        self.assertNotEqual(first,self.read())

if __name__=='__main__':unittest.main()
