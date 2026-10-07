"""Real fresh Python worker protocol, with exclusively synthetic probe effects."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('inspection_worker_cache_test', ROOT / 'bin/cat_agents_stabilityd.py')
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)

WRAPPER = r'''
import importlib.util,json,os,subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[1]);sys.path.insert(0,str(root))
spec=importlib.util.spec_from_file_location('synthetic_inspection_worker',root/'bin/cat_agents_stabilityd.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
def collect(name,conn,findings,profiles,updates):
    if name=='gateway':
        m._inspection_gateway_context=(int(os.environ['FIXTURE_PID']),os.environ['FIXTURE_HEALTH']=='1')
        m.inspection_revision=lambda: (os.environ['FIXTURE_REVISION'],)
        def load():
            result=subprocess.run([sys.executable,os.environ['FIXTURE_CLI'],os.environ['FIXTURE_MARKER']],capture_output=True,text=True,check=True)
            return json.loads(result.stdout)
        ttls={'version':m.INSPECTION_VERSION_TTL_SECONDS,'deep-status':m.INSPECTION_DEEP_TTL_SECONDS,'plugins':m.INSPECTION_PLUGINS_TTL_SECONDS}
        return {'observations':{key:m.cached_inspection(key,load,ttls[key],force=not m._inspection_gateway_context[1]) for key in ttls}}
    if name=='cron':
        m.shutil.which=lambda _: os.environ['FIXTURE_COMMAND']
        def command(*args,**kwargs):
            with open(os.environ['FIXTURE_MARKER'],'a') as f:f.write('sdk\n')
            return subprocess.CompletedProcess([],1,'','')
        m.run_cmd=command
        m.prepare_cron_readonly_rpc()
        return {'payload':m.cron_readonly_rpc_payload('status')}
    raise RuntimeError('fixture unsupported collector')
m._run_component_collector=collect
raise SystemExit(m._component_probe_worker([sys.argv[2],'[]']))
'''


class InspectionWorkerCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.marker = self.root / 'calls'
        self.cli = self.root / 'fake_cli.py'
        self.cli.write_text('import json,sys\nwith open(sys.argv[1],"a") as f:f.write("cli\\n")\nprint(json.dumps({"available":True,"runtimeState":"running","enabledPlugins":[]}))\n')
        self.wrapper = self.root / 'worker.py'
        self.wrapper.write_text(WRAPPER)
        (self.root / 'package.json').write_text('{"name":"openclaw"}')
        self.command = self.root / 'openclaw'
        self.command.write_text('synthetic marker only')
        self.saved = (m._inspection_cache_enabled, m._inspection_cache, m._inspection_gateway_context, m._cron_rpc_retry_after)
        m._inspection_cache_enabled = True
        m._inspection_cache = {}
        m._inspection_gateway_context = (0, False)
        m._cron_rpc_retry_after = 0

    def tearDown(self):
        m._inspection_cache_enabled, m._inspection_cache, m._inspection_gateway_context, m._cron_rpc_retry_after = self.saved
        self.tmp.cleanup()

    def worker(self, component='gateway', pid=10, health=True, revision='one', overrides=None):
        settings = {key: '60' for key in ('CAT_AGENTS_STABILITY_VERSION_PROBE_TTL_SECONDS',
                    'CAT_AGENTS_STABILITY_DEEP_PROBE_TTL_SECONDS', 'CAT_AGENTS_STABILITY_PLUGINS_PROBE_TTL_SECONDS')}
        settings.update(overrides or {})
        with mock.patch.dict(os.environ, settings):
            env = m.collector_worker_environment()
        env.update({m._INSPECTION_WORKER_ENV: json.dumps(m.inspection_worker_state()),
                    m._COMPONENT_PROBE_PARENT_PID_ENV: str(os.getpid()),
                    'FIXTURE_PID': str(pid), 'FIXTURE_HEALTH': str(int(health)),
                    'FIXTURE_REVISION': revision, 'FIXTURE_CLI': str(self.cli),
                    'FIXTURE_COMMAND': str(self.command), 'FIXTURE_MARKER': str(self.marker)})
        proc = subprocess.run([sys.executable, str(self.wrapper), str(ROOT), component],
                              env=env, capture_output=True, text=True, start_new_session=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)['data']
        state = data.pop(m._INSPECTION_WORKER_FIELD)
        m.accept_inspection_worker_state(state, component)
        return data

    def count(self):
        return len(self.marker.read_text().splitlines()) if self.marker.exists() else 0

    def test_two_fresh_workers_cache_and_current_health_generation_invalidation(self):
        self.worker()
        self.assertEqual(self.count(), 3)
        second = self.worker()
        self.assertEqual(self.count(), 3)
        self.assertTrue(all(value['inspectionCache']['cached'] for value in second['observations'].values()))
        self.worker(pid=11)
        self.assertEqual(self.count(), 6)
        self.worker(pid=11, revision='two')
        self.assertEqual(self.count(), 9)
        self.worker(pid=11, health=False, revision='two')
        self.assertEqual(self.count(), 12)
        for entry in m._inspection_cache.values():
            entry['monotonic'] -= 61
        self.worker(pid=11, revision='two')
        self.assertEqual(self.count(), 15)

    def test_cron_failure_backoff_survives_fresh_worker_and_requires_gateway_health(self):
        self.worker()
        before = self.count()
        self.assertIsNone(self.worker('cron')['payload'])
        self.assertEqual(self.count(), before + 1)
        self.assertGreater(m._cron_rpc_retry_after, m.time.monotonic())
        self.worker('cron')
        self.assertEqual(self.count(), before + 1)
        m._cron_rpc_retry_after = 0
        self.worker(health=False)
        before = self.count()
        self.worker('cron')
        self.assertEqual(self.count(), before)

    def test_state_bound_and_invalid_state_never_changes_parent(self):
        m._inspection_cache = {'version': {'revision': [], 'monotonic': 1,
            'checkedAtEpoch': 1, 'value': {'large': 'x' * 40000}}}
        self.assertEqual(m.inspection_worker_state()['cache'], {})
        with self.assertRaises(ValueError):
            m.accept_inspection_worker_state({'enabled': True, 'context': [5, True],
                'retryAfter': 0, 'cache': {'unauthorized': {}}}, 'gateway')
        with self.assertRaises(ValueError):
            m.accept_inspection_worker_state({'enabled': True, 'context': [5, True],
                'retryAfter': 10 ** 400, 'cache': {}}, 'gateway')
        self.assertEqual(m._inspection_gateway_context, (0, False))

    def test_daemon_rollback_overrides_reach_fresh_workers(self):
        settings = {key: '0' for key in ('CAT_AGENTS_STABILITY_VERSION_PROBE_TTL_SECONDS',
                    'CAT_AGENTS_STABILITY_DEEP_PROBE_TTL_SECONDS', 'CAT_AGENTS_STABILITY_PLUGINS_PROBE_TTL_SECONDS')}
        self.worker(overrides=settings)
        self.worker(overrides=settings)
        self.assertEqual(self.count(), 6)
        self.assertEqual(m._inspection_cache, {})
        before = self.count()
        self.worker('cron', overrides={'CAT_AGENTS_STABILITY_CRON_READONLY_RPC': '0'})
        self.assertEqual(self.count(), before)
        self.assertEqual(m._cron_rpc_retry_after, 0)

    def test_failed_refresh_disposes_prior_success_across_workers(self):
        self.worker()
        self.cli.write_text('import json,sys\nwith open(sys.argv[1],"a") as f:f.write("cli\\n")\nprint(json.dumps({"available":False,"runtimeState":"failed"}))\n')
        self.worker(health=False)
        self.assertEqual(m._inspection_cache, {})
        before = self.count()
        values = self.worker()['observations']
        self.assertEqual(self.count(), before + 3)
        self.assertTrue(all(value['available'] is False for value in values.values()))
        self.assertEqual(m._inspection_cache, {})


if __name__ == '__main__':
    unittest.main()
