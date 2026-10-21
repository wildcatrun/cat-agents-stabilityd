"""Bounded ordinary counters only. Never touches events, ledgers, incidents or backups."""
from __future__ import annotations
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from .generation import write_json_atomic

ROLE='stabilityd-ordinary-telemetry-v1'
NAME=re.compile(r'^ordinary-(\d{4}-\d{2}-\d{2})\.json$')
MAX_RAW=65536
MAX_FILES=128
MAX_BYTES=64*1024*1024


def _owned(path:Path):
    s=path.lstat()
    if path.is_symlink() or s.st_uid!=os.geteuid() or s.st_mode&0o022:raise ValueError('telemetry-owner-or-route')
    return s


def _digest(raw):return hashlib.sha256(raw).hexdigest()


def _read_owned(path:Path, expected):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as handle:
        observed=os.fstat(handle.fileno())
        if observed!=expected or not stat.S_ISREG(observed.st_mode) or observed.st_nlink!=1:
            raise ValueError('telemetry-path-drift')
        raw=handle.read(MAX_RAW+1)
        if len(raw)>MAX_RAW:raise ValueError('telemetry-read-budget')
        if path.lstat()!=expected:raise ValueError('telemetry-path-drift')
    if path.name.endswith('.gz'):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            raw=compressed.read(MAX_RAW+1)
    if len(raw)>MAX_RAW:raise ValueError('telemetry-decompression-budget')
    return raw


def maintain(root:Path,*,now:float,no_action_count:int)->dict:
    """Single daemon writer calls this under its existing writer lock."""
    _owned(root)
    folder=root/'ordinary-telemetry'
    folder.mkdir(mode=0o700,exist_ok=True);_owned(folder)
    day=dt.datetime.fromtimestamp(now,dt.timezone.utc).date().isoformat()
    today=folder/('ordinary-'+day+'.json')
    # Only this finite metadata producer can create an ordinary sample.
    if not today.exists() and not today.with_suffix('.json.gz').exists():
        write_json_atomic(today,{'kind':ROLE,'day':day,'noActionCount':max(0,no_action_count),'authorityGranted':False})
    names=sorted(folder.iterdir(),key=lambda p:p.name)
    result={'scope':ROLE,'compressionAgeDays':7,'retentionDays':30,'maxBytes':MAX_BYTES,
            'compressed':0,'removedExpired':0,'protectedHistoryTouched':False,'authorityGranted':False,'coverage':'complete'}
    if len(names)>MAX_FILES:
        return {**result,'coverage':'partial','reason':'file-count-budget-exceeded','budgetExceeded':True}
    total=0
    for path in names:
        info=_owned(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('telemetry-file-kind')
        total+=info.st_size
        raw_name=path.name[:-3] if path.name.endswith('.gz') else path.name
        match=NAME.fullmatch(raw_name)
        if not match or info.st_size>MAX_RAW:continue  # Unknown files are retained, never deleted.
        try:age=(dt.date.fromisoformat(day)-dt.date.fromisoformat(match[1])).days
        except ValueError:continue
        if age<0:continue
        raw=_read_owned(path,info)
        obj=json.loads(raw)
        if (not isinstance(obj,dict) or set(obj)!={'kind','day','noActionCount','authorityGranted'}
            or obj['kind']!=ROLE or obj['day']!=match[1] or obj['authorityGranted'] is not False
            or type(obj['noActionCount']) is not int or obj['noActionCount']<0):
            continue
        if age>=30:
            # Only the finite producer's validated, expired ordinary counter.
            if path.lstat()!=info:raise ValueError('telemetry-path-drift')
            path.unlink();result['removedExpired']+=1
        elif age>=7 and not path.name.endswith('.gz'):
            target=path.with_suffix('.json.gz')
            if target.exists():continue
            compressed=gzip.compress(raw,compresslevel=1,mtime=0)
            if _digest(gzip.decompress(compressed))!=_digest(raw):raise ValueError('telemetry-roundtrip-failed')
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as handle:handle.write(compressed);handle.flush();os.fsync(handle.fileno())
            if path.lstat()!=info:raise ValueError('telemetry-path-drift')
            path.unlink();result['compressed']+=1
    result['observedBytes']=total;result['budgetExceeded']=total>MAX_BYTES
    # Never delete fresh or protected evidence merely to make a budget pass.
    return result
