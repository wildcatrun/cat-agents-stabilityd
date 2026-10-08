"""Fixed dev-server metadata transport; no arbitrary SSH or runtime execution.

The public host key was pinned from approved mac-codex known_hosts (2026-10-08).
No enrollment/keyscan occurs. Reads may create normal remote sshd audit records;
no service/config/credential/profile/registry mutation or inspection occurs.
Private issuance separates trusted Python transport code from ordinary JSON,
not from malicious code running in the same Python process.
"""
from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import json
import math
import os
import re
import selectors
import shlex
import signal
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from .probe_runner import _process_group_members


NODE_ID = 'dev-server'
ENDPOINT = '106.54.53.146'
REMOTE_USER = 'flashcat'
REMOTE_KEY = '/Users/Flashcat/.ssh/openclaw_server'
KNOWN_HOSTS = '/Users/Flashcat/.ssh/known_hosts'
PINNED_ED25519 = 'AAAAC3NzaC1lZDI1NTE5AAAAICeeeEvL6Fl7JEUT4otjSYUWLBDSuHlPiyDhNpuktZJx'
HOST_KEY_FINGERPRINT = 'SHA256:' + base64.b64encode(hashlib.sha256(base64.b64decode(PINNED_ED25519)).digest()).decode().rstrip('=')
_TIMEOUT = 15
_STDOUT_LIMIT = 32768
_STDERR_LIMIT = 4096
_ISSUER = object()
_SERVICES = ('openclaw-gateway','hermes','codex-cli','workflow-plugin')

# Source is fixed: shell arguments never contain caller-controlled host/path/code.
# git optional locks/fsmonitor/submodules are disabled; no auth or model files read.
REMOTE_METADATA_SCRIPT = r'''
import datetime,json,math,os,re,subprocess
from pathlib import Path
root='/home/flashcat/cat-agents-stabilityd'
def git(*args):
 try:
  result=subprocess.run(['git','--no-optional-locks','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',root,*args],env={'PATH':'/usr/bin:/bin','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_OPTIONAL_LOCKS':'0'},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=False)
  if result.returncode!=0 or len(result.stdout)>4096:return None
  return result.stdout.decode('utf-8').strip()
 except Exception:return None
commit=git('rev-parse','HEAD')
if commit is not None and not re.fullmatch('[0-9a-f]{40}',commit):commit=None
try:
 result=subprocess.run(['git','--no-optional-locks','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','-C',root,'diff','--no-ext-diff','--no-textconv','--quiet','--ignore-submodules=all','HEAD','--'],env={'PATH':'/usr/bin:/bin','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_OPTIONAL_LOCKS':'0'},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3,check=False)
 dirty=False if result.returncode==0 else True if result.returncode==1 else None
except Exception:dirty=None
try:
 boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 if not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',boot):boot=None
except Exception:boot=None
generation=None;completed=None
try:
 path=Path('/home/flashcat/.openclaw/stability/latest.json')
 if path.stat().st_size<=131072:
  with path.open('rb') as f:raw=f.read(131073)
  if len(raw)<=131072:
   latest=json.loads(raw)
   g=latest.get('generationId');t=latest.get('completedAtEpoch')
   if isinstance(g,str) and re.fullmatch('[0-9a-f]{32}|[0-9a-f]{64}',g):generation=g
   if type(t) in (int,float) and abs(t)<=1e12 and math.isfinite(t) and t>=0:completed=t
except Exception:pass
print(json.dumps({'schemaVersion':1,'collectorVersion':'dev-host-metadata-v1','observedAtEpoch':datetime.datetime.now(datetime.timezone.utc).timestamp(),'bootId':boot,'codeCommit':commit,'codeDirty':dirty,'publishedGeneration':generation,'publishedCompletedAtEpoch':completed},allow_nan=False,separators=(',',':')))
'''
REMOTE_COMMAND = 'python3 -I -c ' + shlex.quote(REMOTE_METADATA_SCRIPT)
COMMAND_DIGEST = hashlib.sha256(REMOTE_COMMAND.encode()).hexdigest()


@dataclasses.dataclass(frozen=True)
class TransportFailure:
    reason: str
    node_id: str = NODE_ID
    endpoint: str = ENDPOINT


@dataclasses.dataclass(frozen=True)
class HostMetadata:
    observed_at: float
    boot_id: str | None
    code_commit: str | None
    code_dirty: bool | None
    published_generation: str | None
    published_completed_at: float | None


@dataclasses.dataclass(frozen=True, init=False)
class TrustedNodeObservation:
    request_id: str
    node_id: str
    endpoint: str
    host_key_fingerprint: str
    command_digest: str
    response_digest: str
    started_at: float
    received_at: float
    metadata: HostMetadata
    _issuer: object = dataclasses.field(repr=False,compare=False)

    def __new__(cls, *_args, **_kwargs):
        raise TypeError('transport-issued-observation-only')


def is_trusted_observation(value):
    return type(value) is TrustedNodeObservation and getattr(value,'_issuer',None) is _ISSUER


@dataclasses.dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: bytes = b''
    failure: str | None = None


def _bounded_ssh(command):
    """Private process boundary. Never return raw stderr or exception text."""
    proc=None
    selector=selectors.DefaultSelector()
    output=bytearray();stderr_size=0
    failure=None
    result=None
    cleanup_ok=True
    try:
        proc=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              start_new_session=True,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
        for stream,name in ((proc.stdout,'stdout'),(proc.stderr,'stderr')):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
        deadline=time.monotonic()+_TIMEOUT
        while selector.get_map():
            if time.monotonic()>=deadline:
                failure='transport-timeout';break
            for key,_ in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
                chunk=os.read(key.fileobj.fileno(),8192)
                if not chunk:
                    selector.unregister(key.fileobj);continue
                if key.data=='stdout':
                    if len(output)+len(chunk)>_STDOUT_LIMIT:failure='transport-output-limit';break
                    output.extend(chunk)
                else:
                    stderr_size+=len(chunk)
                    if stderr_size>_STDERR_LIMIT:failure='transport-error-limit';break
            if failure:break
        if not failure:
            try:proc.wait(timeout=max(0.01,deadline-time.monotonic()))
            except subprocess.TimeoutExpired:failure='transport-timeout'
        result = _CommandResult(proc.returncode if proc.returncode is not None else -1,bytes(output) if not failure else b'',failure)
    except Exception:
        failure='transport-execution-failed'
        result = _CommandResult(-1,failure='transport-execution-failed')
    finally:
        selector.close()
        if proc is not None:
            try:
                if failure is not None or proc.poll() is None:
                    with contextlib.suppress(ProcessLookupError,PermissionError):os.killpg(proc.pid,signal.SIGTERM)
                    # A reaped leader may leave descendants holding our pipes.
                    # TERM may not stop a resistant descendant, and the leader
                    # can already be reaped. Never condition KILL on leader state
                    # or signal-0 support; this group was created by our Popen.
                    time.sleep(0.2)
                    with contextlib.suppress(ProcessLookupError,PermissionError):os.killpg(proc.pid,signal.SIGKILL)
                    # On Darwin a zombie-only group may return EPERM instead of
                    # ESRCH. Accept only bounded positive evidence of no live
                    # members; unavailable scans or resistant children fail.
                    members=_process_group_members(proc.pid)
                    if members is None or any(state[:1] not in {'Z','X'} for _,state in members):
                        cleanup_ok=False
                    with contextlib.suppress(subprocess.TimeoutExpired):proc.wait(timeout=1)
                    if proc.poll() is None:cleanup_ok=False
            except Exception:
                cleanup_ok=False
                # The leader is an owned subprocess even if group checks fail.
                with contextlib.suppress(Exception):proc.kill()
                with contextlib.suppress(Exception):proc.wait(timeout=0.2)
            finally:
                for stream in (proc.stdout,proc.stderr):
                    if stream is not None:
                        with contextlib.suppress(Exception):stream.close()
    return result if cleanup_ok else _CommandResult(-1,failure='transport-cleanup-failed')



def _pin_is_approved():
    try:
        with open(KNOWN_HOSTS,'rb') as handle:raw=handle.read(1048577)
        if len(raw)>1048576:return False
        matching=[]
        for line in raw.decode('utf-8').splitlines():
            parts=line.split()
            if parts and parts[0].startswith('@'):
                if len(parts)<4:return False
                host_scope=parts[1]
                # Do not drop revocation/certificate policy when constructing
                # the dedicated pin file. Unresolved hashed/wildcard scope fails.
                if (ENDPOINT in host_scope.split(',') or any(char in host_scope for char in '*?!|')
                        or parts[0]=='@revoked' and parts[3]==PINNED_ED25519):return False
                continue
            if len(parts)>=3 and ENDPOINT in parts[0].split(',') and parts[1]=='ssh-ed25519':
                matching.append(parts[2])
        return bool(matching) and set(matching)=={PINNED_ED25519}
    except Exception:return False


def _number(value):
    return type(value) in (int,float) and 0<=value<=1e12 and math.isfinite(value)


def _parse_metadata(raw):
    if not isinstance(raw,bytes) or len(raw)>_STDOUT_LIMIT:raise ValueError('metadata-invalid')
    data=json.loads(raw.decode('utf-8'))
    fields={'schemaVersion','collectorVersion','observedAtEpoch','bootId','codeCommit','codeDirty','publishedGeneration','publishedCompletedAtEpoch'}
    if not isinstance(data,dict) or set(data)!=fields or type(data['schemaVersion']) is not int or data['schemaVersion']!=1 or data['collectorVersion']!='dev-host-metadata-v1':
        raise ValueError('metadata-invalid')
    if not _number(data['observedAtEpoch']):raise ValueError('metadata-invalid')
    for field,pattern in (('bootId',r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),('codeCommit',r'[0-9a-f]{40}'),('publishedGeneration',r'[0-9a-f]{32}|[0-9a-f]{64}')):
        value=data[field]
        if value is not None and (not isinstance(value,str) or re.fullmatch(pattern,value) is None):raise ValueError('metadata-invalid')
    if data['codeDirty'] is not None and type(data['codeDirty']) is not bool:raise ValueError('metadata-invalid')
    if data['publishedCompletedAtEpoch'] is not None and not _number(data['publishedCompletedAtEpoch']):raise ValueError('metadata-invalid')
    return HostMetadata(float(data['observedAtEpoch']),data['bootId'],data['codeCommit'],data['codeDirty'],data['publishedGeneration'],data['publishedCompletedAtEpoch'])


def collect_dev_metadata():
    """Fixed authorised read-only host metadata; never returns service readiness."""
    request_id=uuid.uuid4().hex
    if not _pin_is_approved():return TransportFailure('host-key-policy-unavailable')
    try:
        with tempfile.TemporaryDirectory(prefix='stabilityd-node-pin-') as directory:
            pin=Path(directory)/'known_hosts'
            pin.write_text(ENDPOINT+' ssh-ed25519 '+PINNED_ED25519+'\n');pin.chmod(0o600)
            options={'BatchMode':'yes','StrictHostKeyChecking':'yes','UserKnownHostsFile':str(pin),
                     'GlobalKnownHostsFile':'/dev/null','HostKeyAlgorithms':'ssh-ed25519','UpdateHostKeys':'no',
                     'CheckHostIP':'yes','IdentitiesOnly':'yes','IdentityAgent':'none','ForwardAgent':'no',
                     'ClearAllForwardings':'yes','ProxyCommand':'none','ProxyJump':'none','PermitLocalCommand':'no',
                     'ControlMaster':'no','ControlPath':'none','ConnectTimeout':'8','ConnectionAttempts':'1',
                     'ServerAliveInterval':'5','ServerAliveCountMax':'1','LogLevel':'ERROR'}
            command=['/usr/bin/ssh','-F','/dev/null','-T','-i',REMOTE_KEY]
            for name,value in options.items():command.extend(['-o',name+'='+value])
            command.extend([REMOTE_USER+'@'+ENDPOINT,REMOTE_COMMAND])
            started=time.time();result=_bounded_ssh(command);received=time.time()
        if result.failure:return TransportFailure(result.failure)
        if result.returncode!=0:return TransportFailure('transport-unavailable')
        try:metadata=_parse_metadata(result.stdout)
        except Exception:return TransportFailure('metadata-invalid')
        if not _number(started) or not _number(received) or received<started:return TransportFailure('local-clock-invalid')
        observation=object.__new__(TrustedNodeObservation)
        for name,value in {'request_id':request_id,'node_id':NODE_ID,'endpoint':ENDPOINT,'host_key_fingerprint':HOST_KEY_FINGERPRINT,
                           'command_digest':COMMAND_DIGEST,'response_digest':hashlib.sha256(result.stdout).hexdigest(),
                           'started_at':started,'received_at':received,'metadata':metadata,'_issuer':_ISSUER}.items():
            object.__setattr__(observation,name,value)
        return observation
    except Exception:return TransportFailure('transport-execution-failed')


def trusted_summary(observation, *, now_epoch, max_age_seconds=300, max_future_skew_seconds=30,max_clock_skew_seconds=300):
    result={'nodeId':NODE_ID,'endpoint':ENDPOINT,'transportLiveness':'unknown','readiness':'unknown',
            'coverageStatus':'partial','services':[{'serviceId':name,'state':'unknown','reason':'not-observed'} for name in _SERVICES]}
    if not is_trusted_observation(observation):
        result['reason']=observation.reason if type(observation) is TransportFailure else 'untrusted-observation'
        if type(observation) is not TransportFailure:result['coverageStatus']='invalid'
        return result
    if (not _number(now_epoch) or any(type(value) is not int or not 0<=value<=86400 for value in
            (max_age_seconds,max_future_skew_seconds,max_clock_skew_seconds))):
        result.update(reason='invalid-freshness-policy',coverageStatus='invalid');return result
    meta=observation.metadata
    if max(meta.observed_at,observation.received_at)>now_epoch+max_future_skew_seconds:
        result.update(reason='clock-skew-future',coverageStatus='invalid');return result
    if now_epoch-min(meta.observed_at,observation.received_at)>max_age_seconds:
        result.update(reason='stale-observation',coverageStatus='stale');return result
    if abs(observation.received_at-meta.observed_at)>max_clock_skew_seconds:
        result.update(reason='clock-skew-mismatch',coverageStatus='invalid');return result
    metadata_complete=all(value is not None for value in (meta.boot_id,meta.code_commit,meta.code_dirty,meta.published_generation,meta.published_completed_at))
    published_fresh=meta.published_completed_at is not None and -max_future_skew_seconds<=now_epoch-meta.published_completed_at<=max_age_seconds
    generation=hashlib.sha256(json.dumps([meta.boot_id,meta.code_commit,meta.published_generation],separators=(',',':')).encode()).hexdigest()
    result.update(transportLiveness='reachable',reason='metadata-only' if metadata_complete and published_fresh else 'partial-metadata',
                  coverageStatus='metadata-only' if metadata_complete and published_fresh else 'partial',
                  sourceKind='governed-dev-server-ssh',hostKeyFingerprint=observation.host_key_fingerprint,
                  requestId=observation.request_id,
                  commandDigest=observation.command_digest,responseDigest=observation.response_digest,
                  codeCommit=meta.code_commit,codeDirty=meta.code_dirty,bootId=meta.boot_id,
                  publishedGeneration=meta.published_generation,publishedCompletedAtEpoch=meta.published_completed_at,
                  generationDigest=generation,observedAtEpoch=meta.observed_at,receivedAtEpoch=observation.received_at,
                  startedAtEpoch=observation.started_at,
                  metadataComplete=metadata_complete,publishedFresh=published_fresh,timezone='UTC')
    return result
