"""Bounded current-environment and delivery evidence. No workflow writes or actions."""
from __future__ import annotations
import contextlib
import datetime as dt
import hashlib
import json
import math
import re
from pathlib import Path
import sqlite3
import time
from typing import Any, Mapping
from .node_inventory import NODES
from .surface_contracts import SURFACE_CONTRACTS

def mapping(value):
    return value if isinstance(value,Mapping) else {}


_TABLE_COLUMNS={
    'runtime_runs':('status','started_at','completed_at','latency_ms'),
    'mixed_meeting_dispatches':('status','created_at','sent_at','acked_at','acknowledged_at','updated_at'),
    'telegram_outbox':('status','created_at','sent_at','delivered_at','updated_at'),
}


def timestamp(value):
    if not isinstance(value,str):return None
    try:
        t=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        return t.timestamp() if t.tzinfo is not None else None
    except (ValueError,OverflowError):return None


def delivery_metadata(database:Path,*,now:float,max_rows:int=256,window_seconds:int=86400)->dict:
    if type(max_rows) is not int or not 1<=max_rows<=256:raise ValueError('delivery-row-budget')
    result={'source':'workflow-readonly-metadata','windowSeconds':window_seconds,'tables':{},
            'ackIsExecutionResult':False,'inboxIsHumanConfirmation':False,'authorityGranted':False}
    if not database.is_file():return {**result,'coverage':'unknown','reason':'workflow-database-unavailable'}
    deadline=time.monotonic()+0.25
    try:
        with contextlib.closing(sqlite3.connect(database.resolve().as_uri()+'?mode=ro',uri=True,timeout=0.2)) as c:
            c.execute('PRAGMA query_only=ON');c.set_progress_handler(lambda:int(time.monotonic()>deadline),1000)
            for table,allowed in _TABLE_COLUMNS.items():
                columns={r[1] for r in c.execute('PRAGMA table_info('+table+')')}
                selected=[k for k in allowed if k in columns]
                clocks=[k for k in ('completed_at','delivered_at','updated_at','started_at','created_at','sent_at') if k in selected]
                if 'status' not in selected or not clocks:
                    result['tables'][table]={'coverage':'unknown','reason':'unsupported-or-missing-schema'};continue
                order='COALESCE('+','.join(clocks)+')' if len(clocks)>1 else clocks[0]
                rows=c.execute('SELECT '+','.join(selected)+' FROM '+table+' ORDER BY '+order+' DESC LIMIT ?',(max_rows+1,)).fetchall()
                truncated=len(rows)>max_rows;recent=[];invalid=0
                for values in rows[:max_rows]:
                    row=dict(zip(selected,values));observed=next((timestamp(row[k]) for k in clocks if timestamp(row[k]) is not None),None)
                    if observed is None or observed>now+30:invalid+=1;continue
                    if now-observed>window_seconds:continue
                    recent.append(row)
                known={'acked','sent','delivered','completed','succeeded','failed','error','retry_scheduled','pending','queued','running','received','cancelled'}
                counts={}
                for row in recent:
                    status=row['status'] if row['status'] in known else 'other-or-unknown'
                    counts[status]=counts.get(status,0)+1
                latencies=[]
                if table=='runtime_runs':
                    for row in recent:
                        n=row.get('latency_ms')
                        if row.get('status')=='acked' and type(n) in (int,float) and math.isfinite(n) and n>=0:latencies.append(n)
                result['tables'][table]={'coverage':'partial' if truncated or invalid else 'sampled' if recent else 'no-recent-evidence',
                    'sampleCount':len(recent),'sampleStatusCounts':counts,'truncated':truncated,'invalidTimestampCount':invalid,
                    'sampleAckLatencyMsMean':sum(latencies)/len(latencies) if latencies else None,
                    'semanticExecutionSuccessRate':None,'finalDeliveryCompletenessRate':None,
                    'rateLimitation':'Metadata states/ACK alone do not prove semantic result, user delivery or Human Gate.'}
        result['coverage']='sampled-metadata-only';return result
    except (sqlite3.Error,OSError,ValueError) as exc:
        return {**result,'coverage':'unknown','errorClass':type(exc).__name__}


def environment_report(snapshot:Mapping[str,Any],registry:Mapping[str,Any],*,now:float,node_id:str,python_version:str,dependencies_observed:Mapping[str,Any]|None=None)->dict:
    records=registry.get('records') if isinstance(registry.get('records'),list) else []
    current=[r for r in records if isinstance(r,dict) and r.get('status')=='active']
    complete=registry.get('source')=='db' and registry.get('writeEligible') is True
    checked=snapshot.get('checkedAtEpoch');age=now-checked if type(checked) in (int,float) and math.isfinite(checked) else None
    fresh=age is not None and 0<=age<=300
    targets=[]
    for row in current:
        runtime=row.get('runtime');adapter=row.get('execution_adapter');endpoint=row.get('endpoint_ref')
        if runtime=='openclaw':
            valid=(row.get('platform')=='openclaw' and adapter in {'native','openclaw'}
                   and endpoint=='openclaw-agent:'+str(row.get('agent_id')))
        elif runtime in {'hermers','hermes','hermes_acp'}:
            valid=isinstance(endpoint,str) and endpoint.startswith(('hermes-profile:','hermers-profile:')) and adapter in {'acp','hermes_acp','hermers_acp'}
        else:valid=False
        targets.append({'agentId':row.get('agent_id'),'runtime':runtime,'adapter':adapter,
                        'status':'supported' if valid and complete else 'observe_only' if valid else 'unknown',
                        'authorityGranted':False})
    gateway=snapshot.get('gateway') if isinstance(snapshot.get('gateway'),dict) else {}
    hermes=snapshot.get('hermers') if isinstance(snapshot.get('hermers'),dict) else {}
    auth=snapshot.get('auth') if isinstance(snapshot.get('auth'),dict) else {}
    profiles=hermes.get('profiles') if isinstance(hermes.get('profiles'),dict) else {};mux=any(isinstance(v,dict) and v.get('topology')=='mux' for v in profiles.values())
    dependencies=[
        {'id':'openclaw-gateway','owner':'openclaw','status':'observed-live' if fresh and gateway.get('healthOk') is True else 'unknown','scope':'gateway-health-only'},
        {'id':'hermes-runtime','owner':'hermes','status':'observed-residency' if fresh and profiles and all(isinstance(v,dict) and v.get('observationQualified') is True for v in profiles.values()) else 'unknown','scope':'profile-membership; not task/ACP success'},
        {'id':'oauth-mirror','owner':'mac-codex','status':'scope-observed' if fresh and mapping(auth.get('openclaw')).get('scopeComplete') is True else 'unknown','scope':'server auth observation; not source refresh-owner availability'},
        {'id':'proxy-egress','owner':'dev-server-network','status':'unknown','scope':'no egress test performed'},
        {'id':'suihuo-data-api','owner':SURFACE_CONTRACTS['data-plane']['owner'],'status':'unknown','scope':'no new workstation access or API request'},
        {'id':'windows-wsl-host','owner':'windows-host-owner','status':'unknown','scope':'requires existing admitted host evidence'},
    ]
    observed=mapping(dependencies_observed)
    admitted={f.get('id'):f for f in observed.get('facts',[]) if isinstance(f,dict) and f.get('id') in {'proxy-egress','suihuo-data-api'}}
    dependencies=[{**item,**admitted.get(item['id'],{}),'sourceCheckedAtEpoch':observed.get('checkedAtEpoch'),'authorityGranted':False} for item in dependencies]
    version=gateway.get('openclawVersion')
    version=version.get('version') if isinstance(version,dict) else version
    version=version if isinstance(version,str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,40})?',version) else None
    schema={name:sorted(value) for name,value in snapshot.items() if name in {'gateway','cron','session','hermers','auth'} and isinstance(value,dict)}
    return {'schemaVersion':1,'sourceNode':node_id,'checkedAtEpoch':now,'sourceAgeSeconds':age,'sourceFresh':fresh,
            'authorityGranted':False,'pythonVersion':python_version,'registrySource':registry.get('source'),
            'registryScopeComplete':complete,'targetCapabilities':targets,
            'platforms':{'openclaw':{'observedVersion':version,'capabilityBasis':'runtime/platform/endpoint/adapter'},
                         'hermes':{'runtimeShape':'multiplexed-host' if mux else 'unknown','profileCount':len(profiles)}},
            'schemaFingerprint':hashlib.sha256(json.dumps(schema,sort_keys=True).encode()).hexdigest(),
            'physicalNodes':[{'nodeId':n.node_id,'owner':n.owner_ref,'status':'locally-observed' if n.node_id==node_id and fresh else 'unobserved','authorityGranted':False} for n in NODES],
            'dependencies':dependencies,'scope':'read-only capability facts; not a platform upgrade approval or workflow plan',
            'activation':{'eventPipeline':mapping(snapshot.get('eventPipeline')).get('mode','unknown'),
                          'actionLedger':mapping(snapshot.get('actionRecovery')).get('ledgerStatus','unknown'),
                          'profileLifecycle':mapping(hermes.get('profileModes')).get('controlMode','unknown')}}


def compare_reports(before:Mapping[str,Any],after:Mapping[str,Any])->dict:
    """A before/after routing/schema comparison, not an upgrade or effect approval."""
    if before.get('schemaVersion')!=1 or after.get('schemaVersion')!=1:
        return {'status':'unknown','reason':'unsupported-report-schema','authorityGranted':False}
    if before.get('sourceNode')!=after.get('sourceNode'):
        return {'status':'blocked','reason':'source-node-mismatch','authorityGranted':False}
    if after.get('sourceFresh') is not True or after.get('registryScopeComplete') is not True:
        return {'status':'observe_only','reason':'current-coverage-or-freshness-incomplete','authorityGranted':False}
    changed=before.get('schemaFingerprint')!=after.get('schemaFingerprint')
    return {'status':'observe_only' if changed else 'supported',
            'reason':'schema-changed-adapter-review-required' if changed else 'observed-routing-and-schema-contract',
            'authorityGranted':False,'platformUpgradeAuthorized':False,
            'limitation':'Actual platform/effect qualification and exact authorization remain separate.'}
