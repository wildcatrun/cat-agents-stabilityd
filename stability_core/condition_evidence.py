"""Stable condition fingerprints: volatile resource samples are not new incidents."""
from __future__ import annotations
import hashlib
import json
from typing import Mapping


def condition_fingerprint(finding:Mapping)->str:
    targets=[]
    for item in finding.get('sample') or []:
        if isinstance(item,dict):targets.append({k:item[k] for k in ('jobId','agentId','profile') if k in item})
    record={k:finding.get(k) for k in ('key','severity','component','agentId','profile')}
    record['targets']=sorted(targets,key=lambda v:json.dumps(v,sort_keys=True))
    return hashlib.sha256(json.dumps(record,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def resource_condition_fingerprint(trigger_keys,gateway_pid):
    return hashlib.sha256(json.dumps({'keys':sorted(trigger_keys),'gatewayPid':gateway_pid},sort_keys=True).encode()).hexdigest()
