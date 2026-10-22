"""Existing cache contract across config collector isolation."""
from __future__ import annotations
import copy
import unittest
from unittest import mock
from test_registry_safety import stabilityd as d


class ConfigWorkerCacheTests(unittest.TestCase):
    def setUp(self):
        self.before=(copy.deepcopy(d._inspection_cache),d._inspection_gateway_context,d._inspection_cache_enabled)
        d._inspection_cache={};d._inspection_gateway_context=(123,True);d._inspection_cache_enabled=True

    def tearDown(self):
        d._inspection_cache,d._inspection_gateway_context,d._inspection_cache_enabled=self.before

    def test_config_worker_only_owns_plugin_metadata_and_reuses_success(self):
        with mock.patch.object(d,'inspection_revision',return_value=('fixture',)):
            loader=mock.Mock(return_value={'available':True,'enabledPlugins':[]})
            d.cached_inspection('plugins',loader,300)
            state=d.inspection_worker_state()
            d._inspection_cache={}
            d.accept_inspection_worker_state(state,'config')
            result=d.cached_inspection('plugins',loader,300)
            self.assertTrue(result['inspectionCache']['cached']);loader.assert_called_once()

    def test_config_worker_cannot_change_gateway_version_or_cron_backoff(self):
        with mock.patch.object(d,'inspection_revision',return_value=('fixture',)):
            d.cached_inspection('version',lambda:{'available':True,'version':'original'},900)
            state=d.inspection_worker_state();state['cache']['version']['value']['version']='injected'
            before=copy.deepcopy(d._inspection_cache);retry=d._cron_rpc_retry_after
            d.accept_inspection_worker_state(state,'config')
            self.assertEqual(d._inspection_cache['version'],before['version'])
            self.assertEqual(d._cron_rpc_retry_after,retry)

    def test_gateway_generation_mismatch_is_rejected(self):
        state=d.inspection_worker_state();state['context'][0]+=1
        with self.assertRaises(ValueError):d.accept_inspection_worker_state(state,'config')

    def test_failed_plugin_refresh_does_not_reuse_prior_health(self):
        with mock.patch.object(d,'inspection_revision',return_value=('fixture',)):
            d.cached_inspection('plugins',lambda:{'available':True},300)
            result=d.cached_inspection('plugins',lambda:{'available':False},300,force=True)
            self.assertFalse(result['available']);self.assertNotIn('plugins',d._inspection_cache)

    def test_collection_registry_is_scoped_and_cleared_before_actuators(self):
        before=d._component_registry_observation
        try:
            d._component_registry_observation=None
            def inner(conn,**kwargs):
                a=d.workflow_runtime_registry_records();a['records'].append({'agent_id':'injected'})
                self.assertEqual(d.workflow_runtime_registry_records()['records'],[])
                raise RuntimeError('fixture-stop')
            with mock.patch.object(d,'_collect_snapshot',side_effect=inner):
                with self.assertRaisesRegex(RuntimeError,'fixture-stop'):
                    d.collect_snapshot(None,component_probe_runner=object())
            self.assertIsNone(d._component_registry_observation)
        finally:d._component_registry_observation=before

if __name__=='__main__':unittest.main()
