#!/usr/bin/env python3
"""Deterministic tests for daemon cache freshness and fail-open observation."""
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('stabilityd_cache_test', Path(__file__).resolve().parents[1]/'bin/cat_agents_stabilityd.py')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
calls = []
clock = [1000.0]
revision = [1]
value = [{'available': True, 'enabledPlugins': [{'id':'fixture'}]}]
def load():
    calls.append(1)
    return dict(value[0])

with patch.object(module.time, 'monotonic', lambda: clock[0]), patch.object(module, 'inspection_revision', lambda: revision[0]):
    module._inspection_gateway_context = (100, True)
    module.cached_inspection('one-shot', load, 120)
    module.cached_inspection('one-shot', load, 120)
    assert len(calls) == 2, 'one-shot diagnostics must stay fresh'
    module._inspection_cache_enabled = True
    a = module.cached_inspection('fixture', load, 120)
    b = module.cached_inspection('fixture', load, 120)
    assert len(calls) == 3 and b['inspectionCache']['cached']
    b['enabledPlugins'][0]['id'] = 'caller-mutation'
    assert module.cached_inspection('fixture', load, 120)['enabledPlugins'][0]['id'] == 'fixture'
    clock[0] += 120
    module.cached_inspection('fixture', load, 120)
    assert len(calls) == 4, 'TTL expiry must trigger a new observation'
    revision[0] += 1
    module.cached_inspection('fixture', load, 120)
    assert len(calls) == 5, 'configuration/install revision must invalidate'
    module._inspection_gateway_context = (101, True)
    module.cached_inspection('fixture', load, 120)
    assert len(calls) == 6, 'new Gateway PID must invalidate'
    module.cached_inspection('fixture', load, 120, force=True)
    assert len(calls) == 7, 'unhealthy runtime must bypass caches'
    value[0] = {'available':False, 'exitCode':1}
    module.cached_inspection('fixture', load, 120, force=True)
    module.cached_inspection('fixture', load, 120)
    assert len(calls) == 9 and 'fixture' not in module._inspection_cache, 'failed refresh must not return old success'
    value[0] = {'probe':{'exitCode':0}, 'connectivityProbeFailed':True}
    module.cached_inspection('deep-status', load, 120)
    module.cached_inspection('deep-status', load, 120)
    assert 'deep-status' not in module._inspection_cache, 'real failed connectivity must stay fresh'
    value[0] = {'probe':{'exitCode':0}, 'connectivityProbeFailed':True, 'insecurePlaintextWsBlocked':True, 'runtimeState':'running'}
    module.cached_inspection('deep-status', load, 120)
    assert module.cached_inspection('deep-status', load, 120)['inspectionCache']['cached']
    value[0] = {'available':True, 'enabledPlugins':[{'status':'error'}]}
    module.cached_inspection('plugins', load, 300)
    assert 'plugins' not in module._inspection_cache, 'plugin errors must trigger fresh observations'
    module.cached_inspection('disabled', load, 0)
    assert 'disabled' not in module._inspection_cache
print(json.dumps({'passed':True,'checks':['one-shot fresh','TTL expiry','configuration revision','PID revision','health failure bypass','failed refresh discards old result','real connectivity failure not cached','known insecure probe exception','copy isolation','TTL zero rollback']}))
