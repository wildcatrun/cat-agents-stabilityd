import contextlib
import datetime as dt
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import subprocess
import os
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('hermers_probe_readiness', ROOT/'hermers/hermers_stability_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root/'tracking.db'
        self.patchers = [patch.object(probe, 'WORKFLOW_DB', self.db), patch.object(probe, 'HERMES_HOME', self.root)]
        for p in self.patchers:
            p.start(); self.addCleanup(p.stop)
        self.registry()
        probe.profiles_from_runtime_registry()
        self.state = self.root/'profiles/catheart/gateway_state.json'
        self.state.parent.mkdir(parents=True)
        self.service = {'ok':True,'ActiveState':'active','SubState':'running','MainPID':42}
    def registry(self, empty=False):
        with sqlite3.connect(self.db) as conn:
            conn.execute('CREATE TABLE runtime_agents(agent_id,runtime,status,endpoint_ref,can_receive_dispatch)')
            if not empty:
                conn.execute('INSERT INTO runtime_agents VALUES(?,?,?,?,?)', ('cat_heart','hermes','active','hermes-profile:catheart',1))
    def value(self, **updates):
        value = {'pid':42,'gateway_state':'running','updated_at':dt.datetime.now(dt.timezone.utc).isoformat(),
                 'platforms':{'telegram':{'state':'connected','writer_pid':42}},'token':'SYNTHETIC-SECRET-TOKEN'}
        value.update(updates)
        return value
    def result(self, value=None):
        if value is not None:self.state.write_text(json.dumps(value))
        with patch.object(probe,'systemctl_user_show',return_value=self.service), patch.object(probe,'runtime_summary',return_value={}):
            return probe.probe_profile('catheart', [{'cmd':'hermes_cli.main --profile catheart gateway run --token SYNTHETIC-SECRET-TOKEN','pid':'42','ppid':'1'}])
    def test_failed_service_stdout_cannot_prove_liveness(self):
        self.service['ok']=False
        result=self.result(self.value())
        self.assertFalse(result['ready']);self.assertEqual(result['liveness'],'unknown')
        self.assertEqual(result['readiness'],'unknown')
    def test_start_ticks_are_strict_positive_int(self):
        for ticks in (True,0,'123'):
            value=self.value(start_time=ticks);value['platforms']['telegram']['writer_start_time']=ticks
            self.assertFalse(self.result(value)['ready'])
        value=self.value(start_time=123);value['platforms']['telegram']['writer_start_time']=123
        self.assertTrue(self.result(value)['ready'])
    def test_state_symlink_and_inode_drift_unknown(self):
        target=self.root/'target.json';target.write_text(json.dumps(self.value()))
        self.state.symlink_to(target)
        self.assertIsNone(probe.load_json(self.state))
        self.state.unlink();self.state.write_text(json.dumps(self.value()))
        real_read=os.read
        replaced=False
        def replace_after_read(fd,count):
            nonlocal replaced
            raw=real_read(fd,count)
            if not replaced:
                new=self.root/'new.json';new.write_text(json.dumps(self.value()))
                new.replace(self.state);replaced=True
            return raw
        with patch.object(probe.os,'read',side_effect=replace_after_read):
            self.assertIsNone(probe.load_json(self.state))
    def test_numeric_service_token_not_exposed(self):
        out=subprocess.CompletedProcess([],0,'ActiveState=active\nSubState=running\nMainPID=SYNTHETIC-SECRET-TOKEN\nNRestarts=notnumeric\n','')
        with patch.object(probe,'run',return_value=out):
            result=probe.systemctl_user_show('fixture.service')
        self.assertIsNone(result['MainPID']);self.assertIsNone(result['NRestarts'])
        self.assertEqual(result['numericFieldError'],'numeric-field-invalid')
        self.assertNotIn('SYNTHETIC-SECRET-TOKEN',json.dumps(result))
    def test_connected_scope_and_secret_minimization(self):
        result=self.result(self.value())
        self.assertTrue(result['ready']);self.assertEqual(result['readinessScope'],'local-gateway-telegram-connectivity')
        self.assertFalse(result['semanticExecutionVerified']);self.assertFalse(result['actuatorQualification'])
        self.assertNotIn('SYNTHETIC-SECRET-TOKEN',json.dumps(result));self.assertNotIn('cmd',result['gatewayProcesses'][0])
    def test_active_missing_adapter_state_is_not_ready(self):
        for value in (None,self.value(platforms={}),self.value(platforms={'telegram':{'state':'disconnected','writer_pid':42}}),self.value(platforms={'telegram':{'state':'connecting','writer_pid':42}})):
            result=self.result(value);self.assertFalse(result['ready']);self.assertEqual(result['liveness'],'ok')
    def test_stale_future_wrong_pid_and_bool_pid(self):
        for value in (self.value(updated_at='2000-01-01T00:00:00+00:00'),self.value(updated_at='2099-01-01T00:00:00+00:00'),self.value(pid=43),self.value(pid=True),self.value(platforms={'telegram':{'state':'connected','writer_pid':43}})):
            self.assertFalse(self.result(value)['ready'])
    def test_unknown_state_fields_and_wrong_start_generation(self):
        self.assertFalse(self.result(self.value(gateway_state={"token":"SYNTHETIC-SECRET-TOKEN"}))["ready"])
        value=self.value(start_time="start-new");value["platforms"]["telegram"]["writer_start_time"]="start-old"
        self.assertFalse(self.result(value)["ready"])

    def test_old_transition_timestamp_not_heartbeat(self):
        value=self.value();value['platforms']['telegram']['updated_at']='2000-01-01T00:00:00+00:00'
        self.assertTrue(self.result(value)['ready'])
    def test_missing_and_empty_registry_do_not_create(self):
        self.db.unlink();profiles,meta=probe.profiles_from_runtime_registry()
        self.assertEqual(profiles,[]);self.assertFalse(self.db.exists())
        self.registry(empty=True);profiles,meta=probe.profiles_from_runtime_registry()
        self.assertEqual(profiles,[]);self.assertEqual(meta['status'],'empty')
    def test_unknown_or_path_profile_never_read(self):
        with patch.object(probe,'load_json',side_effect=AssertionError('must not read')):
            for profile in ('catnose','../catheart','catheart/../../other'):
                self.assertFalse(probe.probe_profile(profile,[])['ready'])
        with patch.object(sys,'argv',['probe','--profiles','../catheart']),patch.object(probe,'ps_rows',return_value=[]),contextlib.redirect_stdout(io.StringIO()) as output:
            probe.main()
        value=json.loads(output.getvalue());self.assertEqual(value['profileCount'],0);self.assertEqual(value['profileSource'],'runtime_agents')
    def test_sqlite_readonly_prevents_write(self):
        conn=probe.readonly_db()
        try:
            with self.assertRaises(sqlite3.OperationalError):conn.execute('CREATE TABLE forbidden(x)')
        finally:conn.close()
    def test_real_child_output_budget_and_timeout(self):
        with patch.object(probe,"PROBE_DEADLINE",None):
            result=probe.run([sys.executable,"-c","import os; os.write(1,b'x'*2000000)"],timeout=2)
            self.assertEqual(result.returncode,127);self.assertEqual(result.stdout,"");self.assertEqual(result.stderr,"ValueError")
            result=probe.run([sys.executable,"-c","import time; time.sleep(3)"],timeout=0.05)
            self.assertEqual(result.returncode,127);self.assertEqual(result.stderr,"TimeoutError")

    def test_oversize_and_invalid_json_unknown(self):
        self.state.write_bytes(b'x'*(probe.MAX_OUTPUT+1));self.assertIsNone(probe.load_json(self.state))
        self.state.write_text('[]');self.assertIsNone(probe.load_json(self.state))

if __name__=='__main__':unittest.main()
