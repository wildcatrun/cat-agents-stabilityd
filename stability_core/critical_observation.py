"""Parent-owned liveness sidecar while existing collectors wait; no scheduler or effects."""
from __future__ import annotations
import datetime as dt
import os
import socket
import subprocess
import time
import urllib.request
import uuid
from pathlib import Path
from .generation import write_json_atomic


def gateway_liveness(port: int) -> dict:
    """Fixed service and loopback only; each source is bounded and credential-free."""
    facts={'serviceActive':None,'pid':None,'portOpen':None,'healthOk':None,'readyzOk':None}
    errors={}
    try:
        p=subprocess.run(['/usr/bin/systemctl','show','openclaw-gateway.service','-p','MainPID','-p','ActiveState'],capture_output=True,text=True,timeout=1)
        if p.returncode or len(p.stdout)>4096:raise ValueError('service-evidence-unavailable')
        props=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
        facts['serviceActive']=props.get('ActiveState')=='active';facts['pid']=int(props.get('MainPID') or 0)
    except Exception as exc:errors['service']=type(exc).__name__
    try:
        with socket.create_connection(('127.0.0.1',port),timeout=0.2):facts['portOpen']=True
    except OSError:facts['portOpen']=False
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for path,key in (('/health','healthOk'),('/readyz','readyzOk')):
        try:
            with opener.open(f'http://127.0.0.1:{port}{path}',timeout=0.5) as response:facts[key]=200<=response.status<400
        except Exception as exc:errors[key]=type(exc).__name__
    values=[facts[k] for k in ('serviceActive','portOpen','healthOk','readyzOk')]
    status='unavailable' if False in values else 'unknown' if None in values else 'live'
    return {'gateway':facts,'status':status,'probeErrors':errors}


class CriticalObservation:
    def __init__(self,path:Path,port:int,*,probe=gateway_liveness,clock=time.monotonic,interval=20.0):
        if type(port) is not int or not 1<=port<=65535 or not 0<interval<=20:raise ValueError('critical-observation-config')
        self.path,self.port,self.probe,self.clock,self.interval=path,port,probe,clock,interval
        self.owner=os.getpid();self.round_id=uuid.uuid4().hex;self.last=None;self.failed=False;self.latest={}

    def tick(self,force=False):
        if os.getpid()!=self.owner:raise ValueError('critical-observation-parent-only')
        now=self.clock()
        if self.last is not None and now<self.last:raise ValueError('critical-observation-clock')
        if not force and self.last is not None and now-self.last<self.interval:return
        self.last=now
        try:
            facts=self.probe(self.port)
            payload={**facts,'schemaVersion':1,'source':'stabilityd-parent-liveness',
                     'scope':'gateway-liveness-only; not task, delivery or authorization readiness',
                     'parentRoundId':self.round_id,'checkedAt':dt.datetime.now(dt.timezone.utc).isoformat(),
                     'checkedAtEpoch':time.time(),'writerPid':self.owner,'authorityGranted':False,
                     'samplingIntervalSeconds':self.interval}
            write_json_atomic(self.path,payload);self.latest=payload
        except Exception:
            self.failed=True
            raise

    def evidence(self):
        return {'path':str(self.path),'parentRoundId':self.round_id,'lastCheckedAt':self.latest.get('checkedAt'),
                'status':self.latest.get('status','unknown'),'publicationFailed':self.failed,
                'authorityGranted':False,'scope':'gateway-liveness-only'}
