"""Read-only fixed health endpoints already announced to dev-server; no credentials."""
from __future__ import annotations
import copy
import socket
import time
import urllib.error
import urllib.request

_cache=None
_sampled_monotonic=None


def collect_dependency_health(*,clock=time.monotonic,force=False):
    global _cache,_sampled_monotonic
    now=clock()
    ttl=300 if _cache and all(v.get('status')=='observed' for v in _cache['facts']) else 60
    if not force and _cache is not None and _sampled_monotonic is not None and 0<=now-_sampled_monotonic<ttl:
        return {**copy.deepcopy(_cache),'cached':True,'ageSeconds':now-_sampled_monotonic,'ttlSeconds':ttl}
    # Failed refreshes cannot retain a previous success.
    _cache=None;_sampled_monotonic=None
    facts=[]
    proxy={'id':'proxy-egress','owner':'dev-server-network','status':'unknown','readiness':'unknown','scope':'local proxy listener only; egress unverified'}
    try:
        with socket.create_connection(('127.0.0.1',7890),timeout=0.25):proxy['status']='observed'
        proxy['listenerOpen']=True
    except OSError:proxy['listenerOpen']=False
    facts.append(proxy)
    api={'id':'suihuo-data-api','owner':'suihuo-data-api','status':'unknown','readiness':'unknown','scope':'existing HTTP health only; no dataset freshness, SQL or MCP call'}
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open('http://100.87.17.57:18080/health',timeout=1.0) as response:
            api['httpStatus']=int(response.status)
            if 200<=response.status<300:api.update(status='observed',readiness='http-health-only')
    except urllib.error.HTTPError as exc:
        api['httpStatus']=int(exc.code);api['status']='reachable-auth-required' if exc.code in (401,403) else 'health-endpoint-not-confirmed'
    except Exception as exc:api['errorClass']=type(exc).__name__
    facts.append(api)
    _cache={'checkedAtEpoch':time.time(),'facts':facts,'authorityGranted':False,'credentialsRead':False}
    _sampled_monotonic=now
    return {**copy.deepcopy(_cache),'cached':False,'ageSeconds':0,'ttlSeconds':300 if all(v.get('status')=='observed' for v in facts) else 60}
