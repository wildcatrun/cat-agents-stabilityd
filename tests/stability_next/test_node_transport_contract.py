import dataclasses
import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from stability_core import node_transport_contract as m


def payload(**changes):
    data={'schemaVersion':1,'collectorVersion':'dev-host-metadata-v1','observedAtEpoch':1000,
          'bootId':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','codeCommit':'a'*40,'codeDirty':False,
          'publishedGeneration':'b'*32,'publishedCompletedAtEpoch':999}
    data.update(changes)
    return json.dumps(data).encode()


class NodeTransportTests(unittest.TestCase):
    def receipt(self,raw=None):
        with mock.patch.object(m,'_pin_is_approved',return_value=True),mock.patch.object(m,'_bounded_ssh',return_value=m._CommandResult(0,raw or payload())),mock.patch.object(m.time,'time',return_value=1000):
            return m.collect_dev_metadata()

    def test_fixed_scope_strict_pin_command_and_no_environment_override(self):
        calls=[]
        def execute(command):
            calls.append(command)
            options={command[i+1].split('=',1)[0]:command[i+1].split('=',1)[1] for i,x in enumerate(command) if x=='-o'}
            self.assertEqual(options['StrictHostKeyChecking'],'yes')
            self.assertEqual(options['GlobalKnownHostsFile'],'/dev/null')
            self.assertEqual(options['HostKeyAlgorithms'],'ssh-ed25519')
            self.assertEqual(options['UpdateHostKeys'],'no')
            self.assertEqual(options['IdentityAgent'],'none')
            self.assertEqual(options['ProxyCommand'],'none')
            self.assertEqual(options['ControlPath'],'none')
            self.assertEqual(Path(options['UserKnownHostsFile']).read_text(),m.ENDPOINT+' ssh-ed25519 '+m.PINNED_ED25519+'\n')
            return m._CommandResult(0,payload())
        with mock.patch.object(m,'_pin_is_approved',return_value=True),mock.patch.object(m,'_bounded_ssh',side_effect=execute),mock.patch.object(m.time,'time',return_value=1000),mock.patch.dict(os.environ,{'CAT_AGENTS_STABILITY_REMOTE_HOST':'prod-server','CAT_AGENTS_STABILITY_REMOTE_KEY':'evil'}):
            observation=m.collect_dev_metadata()
        self.assertTrue(m.is_trusted_observation(observation))
        self.assertEqual(calls[0][-2:],[m.REMOTE_USER+'@'+m.ENDPOINT,m.REMOTE_COMMAND])
        self.assertEqual(calls[0][:6],['/usr/bin/ssh','-F','/dev/null','-T','-i',m.REMOTE_KEY])
        self.assertEqual(m.trusted_summary(observation,now_epoch=1000)['readiness'],'unknown')
        self.assertTrue(all(service['state']=='unknown' for service in m.trusted_summary(observation,now_epoch=1000)['services']))

    def test_known_host_missing_mismatch_or_multiple_keys_fail_before_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            known=Path(tmp)/'known_hosts'
            for contents in ('',m.ENDPOINT+' ssh-ed25519 wrong\n',m.ENDPOINT+' ssh-ed25519 '+m.PINNED_ED25519+'\n'+m.ENDPOINT+' ssh-ed25519 wrong\n'):
                known.write_text(contents)
                with mock.patch.object(m,'KNOWN_HOSTS',str(known)),mock.patch.object(m,'_bounded_ssh') as ssh:
                    result=m.collect_dev_metadata()
                    self.assertEqual(result.reason,'host-key-policy-unavailable');ssh.assert_not_called()
            known.write_text(m.ENDPOINT+' ssh-ed25519 '+m.PINNED_ED25519+'\n')
            with mock.patch.object(m,'KNOWN_HOSTS',str(known)):self.assertTrue(m._pin_is_approved())

    def test_json_and_public_constructor_cannot_issue_trusted_receipt(self):
        observation=self.receipt()
        with self.assertRaises(TypeError):m.TrustedNodeObservation()
        with self.assertRaises(dataclasses.FrozenInstanceError):observation.node_id='prod-server'
        summary=m.trusted_summary(observation,now_epoch=1000)
        self.assertFalse(m.is_trusted_observation(summary))
        self.assertEqual(m.trusted_summary(summary,now_epoch=1000)['reason'],'untrusted-observation')
        forged=object.__new__(m.TrustedNodeObservation)
        self.assertFalse(m.is_trusted_observation(forged))
        self.assertNotEqual(observation.request_id,self.receipt().request_id)
        self.assertEqual(summary['requestId'],observation.request_id)

    def test_schema_and_transport_failures_are_sanitized(self):
        for raw in (b'{"sourceKind":"governed-dev-server-ssh","ready":true}',payload(schemaVersion=True),payload(bootId='SYNTHETIC_SECRET'),payload(codeDirty='true'),payload(observedAtEpoch=10**400),b'x'*40000):
            result=self.receipt(raw)
            self.assertEqual(result.reason,'metadata-invalid')
            self.assertNotIn('SYNTHETIC_SECRET',repr(result))
        for failure in ('transport-timeout','transport-output-limit','transport-error-limit'):
            with mock.patch.object(m,'_pin_is_approved',return_value=True),mock.patch.object(m,'_bounded_ssh',return_value=m._CommandResult(-1,failure=failure)):
                self.assertEqual(m.collect_dev_metadata().reason,failure)
        with mock.patch.object(m,'_pin_is_approved',return_value=True),mock.patch.object(m,'_bounded_ssh',side_effect=OSError('SYNTHETIC_SECRET')):
            self.assertEqual(m.collect_dev_metadata().reason,'transport-execution-failed')

    def test_freshness_and_missing_service_evidence_never_become_ready(self):
        observation=self.receipt()
        self.assertEqual(m.trusted_summary(observation,now_epoch=1500)['coverageStatus'],'stale')
        self.assertEqual(m.trusted_summary(observation,now_epoch=900)['reason'],'clock-skew-future')
        partial=self.receipt(payload(bootId=None,codeCommit=None,publishedGeneration=None,publishedCompletedAtEpoch=None))
        summary=m.trusted_summary(partial,now_epoch=1000)
        self.assertEqual(summary['transportLiveness'],'reachable')
        self.assertEqual(summary['coverageStatus'],'partial')
        self.assertFalse(summary['metadataComplete'])
        self.assertEqual(summary['readiness'],'unknown')

    def test_real_local_process_boundary_bounded_stdout_stderr_and_timeout(self):
        # Exercise the private subprocess boundary using local synthetic programs,
        # never invoking SSH or a real remote endpoint.
        self.assertEqual(m._bounded_ssh([sys.executable,'-c','print("ok")']).stdout,b'ok\n')
        restricted = sys.platform == 'darwin' and m._process_group_members(os.getpgrp()) is None
        expected = lambda code: 'transport-cleanup-failed' if restricted else code
        self.assertEqual(m._bounded_ssh([sys.executable,'-c','print("x"*40000)']).failure,expected('transport-output-limit'))
        self.assertEqual(m._bounded_ssh([sys.executable,'-c','import sys;sys.stderr.write("x"*5000)']).failure,expected('transport-error-limit'))
        with mock.patch.object(m,'_TIMEOUT',0.1):
            self.assertEqual(m._bounded_ssh([sys.executable,'-c','import time;time.sleep(5)']).failure,expected('transport-timeout'))

    def test_unverifiable_cleanup_fails_closed_without_output(self):
        with mock.patch.object(m,'_process_group_members',return_value=None),mock.patch.object(m,'_TIMEOUT',0.1):
            result=m._bounded_ssh([sys.executable,'-c','import time;time.sleep(5)'])
        self.assertEqual(result.failure,'transport-cleanup-failed')
        self.assertEqual(result.stdout,b'')

    def test_revoked_pin_and_uncertain_marked_host_policy_are_not_erased(self):
        with tempfile.TemporaryDirectory() as tmp:
            known=Path(tmp)/'known_hosts'
            approved=m.ENDPOINT+' ssh-ed25519 '+m.PINNED_ED25519+'\n'
            for policy in ('@revoked '+m.ENDPOINT+' ssh-ed25519 '+m.PINNED_ED25519,
                           '@revoked unrelated-host ssh-ed25519 '+m.PINNED_ED25519,
                           '@revoked |1|hashed|host ssh-ed25519 other',
                           '@revoked *.example.invalid ssh-ed25519 other',
                           '@cert-authority * ssh-ed25519 other'):
                known.write_text(approved+policy+'\n')
                with mock.patch.object(m,'KNOWN_HOSTS',str(known)),mock.patch.object(m,'_bounded_ssh') as ssh:
                    self.assertEqual(m.collect_dev_metadata().reason,'host-key-policy-unavailable')
                    ssh.assert_not_called()

    def test_exited_leader_descendant_holding_pipes_is_stopped(self):
        if sys.platform == 'darwin' and m._process_group_members(os.getpgrp()) is None:
            self.skipTest('Darwin process membership unavailable; actual descendant proof requires isolated Linux')
        with tempfile.TemporaryDirectory() as tmp:
            pidfile=Path(tmp)/'child.pid'
            code='import subprocess,sys,os; p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);open(sys.argv[1],"w").write(str(p.pid));os._exit(0)'
            child=None
            try:
                with mock.patch.object(m,'_TIMEOUT',0.3):
                    result=m._bounded_ssh([sys.executable,'-c',code,str(pidfile)])
                self.assertEqual(result.failure,'transport-timeout')
                child=int(pidfile.read_text())
                deadline=time.monotonic()+1
                while time.monotonic()<deadline:
                    listing=subprocess.run(['/bin/ps','-o','stat=','-p',str(child)],capture_output=True,text=True)
                    self.assertIn(listing.returncode,(0,1))
                    self.assertFalse(listing.stderr.strip())
                    state=listing.stdout.strip()
                    if not state or state.startswith('Z'):break
                    time.sleep(0.02)
                self.assertTrue(not state or state.startswith('Z'),state)
            finally:
                if child is not None:
                    try:os.kill(child,signal.SIGKILL)
                    except ProcessLookupError:pass

    def test_actual_remote_script_executes_without_package_or_host_reads(self):
        class FixturePath:
            def __init__(self,path):
                self.path=path
                self.assert_allowed()
            def assert_allowed(self):
                if self.path not in ('/proc/sys/kernel/random/boot_id','/home/flashcat/.openclaw/stability/latest.json'):
                    raise AssertionError('unexpected-path')
            def read_text(self):return 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            def stat(self):return type('Stat',(),{'st_size':100})()
            def open(self,*_):return io.BytesIO(b'{"generationId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","completedAtEpoch":999}')
        calls=[]
        def git(command,**options):
            calls.append(command)
            self.assertNotIn('HOME',options['env'])
            if 'rev-parse' in command:return subprocess.CompletedProcess(command,0,b'a'*40+b'\n')
            return subprocess.CompletedProcess(command,0,b'')
        output=io.StringIO()
        with mock.patch('pathlib.Path',FixturePath),mock.patch('subprocess.run',side_effect=git),contextlib.redirect_stdout(output):
            exec(compile(m.REMOTE_METADATA_SCRIPT,'<fixed-remote-script>','exec'),{'__name__':'__remote_fixture__','__package__':None})
        metadata=m._parse_metadata(output.getvalue().encode())
        self.assertEqual(metadata.code_commit,'a'*40)
        self.assertIs(metadata.code_dirty,False)
        self.assertEqual(len(calls),2)


if __name__=='__main__':unittest.main()
