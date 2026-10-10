"""Explicit local v2 JSONL/export and immutable archive filesystem adapter.

No daemon, timer, network or activation. All writers/rotators must share this
lock; coordinated state restoration must stop writers. Unfinished records are
never deleted. Capability issuance and database frontiers belong to v2 core.
"""
import contextlib
import fcntl
import functools
import hashlib
import json
import os
import re
import stat
from pathlib import Path


class EventStreamError(RuntimeError):
    pass


def _fail(code):
    raise EventStreamError(code) from None


def _masked(code):
    def decorate(method):
        @functools.wraps(method)
        def wrapped(*args, **kwargs):
            try:return method(*args, **kwargs)
            except EventStreamError:raise
            except Exception:_fail(code)
        return wrapped
    return decorate


def _digest(content):
    return hashlib.sha256(content).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def _sync_dir(path):
    fd=os.open(path,os.O_RDONLY | getattr(os,'O_DIRECTORY',0) | getattr(os,'O_NOFOLLOW',0))
    try:os.fsync(fd)
    finally:os.close(fd)


def _read_regular(path, limit):
    fd=os.open(path,os.O_RDONLY | getattr(os,'O_NOFOLLOW',0))
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:_fail('file-budget-or-type-invalid')
        chunks=[];size=0
        while True:
            chunk=os.read(fd,min(65536,limit+1-size))
            if not chunk:break
            chunks.append(chunk);size+=len(chunk)
            if size>limit:_fail('file-budget-or-type-invalid')
        return b''.join(chunks),info
    finally:os.close(fd)


def _write_exclusive(path, content):
    fd=os.open(path,os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        view=memoryview(content)
        while view:
            written=os.write(fd,view)
            if written<=0:_fail('file-write-incomplete')
            view=view[written:]
        os.fsync(fd)
    finally:os.close(fd)
    _sync_dir(path.parent)


class EventStream:
    def __init__(self, target, *, stream_id='local-events-v2', max_active_bytes=8388608,
                 max_line_bytes=65536, max_batch_bytes=1048576):
        if (not isinstance(stream_id,str) or re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',stream_id) is None
                or any(type(v) is not int or v<=0 for v in (max_active_bytes,max_line_bytes,max_batch_bytes))
                or max_active_bytes>67108864 or max_line_bytes>65536 or max_batch_bytes>16777216):
            _fail('invalid-stream-policy')
        target_path=Path(target).absolute()
        if target_path.is_symlink():_fail('stream-target-invalid')
        self.target=target_path.resolve()
        self.stream_id=stream_id
        self.max_active_bytes=max_active_bytes
        self.max_line_bytes=max_line_bytes
        self.max_batch_bytes=max_batch_bytes
        self.lock_path=Path(str(self.target)+'.v2.lock')
        self.marker=Path(str(self.target)+'.v2.rotation')

    @contextlib.contextmanager
    def locked(self):
        fd=os.open(self.lock_path,os.O_RDWR | os.O_CREAT | getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):_fail('stream-lock-invalid')
            fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError:
            _fail('stream-busy')
        finally:os.close(fd)

    def _ensure_target(self):
        fd=os.open(self.target,os.O_RDWR | os.O_CREAT | getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):_fail('stream-target-invalid')
            os.fsync(fd)
        finally:os.close(fd)
        _sync_dir(self.target.parent)
        return info

    def _lines(self, content):
        if content and not content.endswith(b'\n'):_fail('stream-partial-tail')
        lines=content.splitlines(keepends=True)
        if any(len(line)>self.max_line_bytes or not line.endswith(b'\n') for line in lines):
            _fail('stream-line-invalid')
        for line in lines:
            try:
                if not isinstance(json.loads(line),dict):_fail('stream-line-invalid')
            except (ValueError,UnicodeError):_fail('stream-line-invalid')
        return lines

    def _recover_rotation(self):
        if not self.marker.exists():return
        raw,_=_read_regular(self.marker,4096)
        try:record=json.loads(raw)
        except (ValueError,UnicodeError):_fail('rotation-marker-invalid')
        if (not isinstance(record,dict) or set(record)!={'version','streamId','oldDev','oldInode','oldDigest','newDigest','temp'}
                or type(record['version']) is not int or record['version']!=1 or record['streamId']!=self.stream_id
                or any(type(record[k]) is not int or record[k]<0 for k in ('oldDev','oldInode'))
                or any(not isinstance(record[k],str) or re.fullmatch('[0-9a-f]{64}',record[k]) is None for k in ('oldDigest','newDigest'))
                or not isinstance(record['temp'],str)
                or re.fullmatch(r'\.stability-v2-rotation-[0-9a-f]{64}',record['temp']) is None):
            _fail('rotation-marker-invalid')
        temp=self.target.parent/record['temp']
        data,info=_read_regular(self.target,self.max_active_bytes)
        if _digest(data)==record['newDigest']:
            # Replacement already happened. A lingering temp must match before
            # removing it; unrelated files are never cleaned by recovery.
            if temp.exists():
                tmp,_=_read_regular(temp,self.max_active_bytes)
                if _digest(tmp)!=record['newDigest']:_fail('rotation-temp-conflict')
                temp.unlink()
        elif (info.st_dev,info.st_ino)==(record['oldDev'],record['oldInode']) and _digest(data)==record['oldDigest']:
            tmp,_=_read_regular(temp,self.max_active_bytes)
            if _digest(tmp)!=record['newDigest']:_fail('rotation-temp-conflict')
            os.replace(temp,self.target);_sync_dir(self.target.parent)
        else:_fail('rotation-target-conflict')
        self.marker.unlink();_sync_dir(self.target.parent)

    def _make_room(self, incoming, *, hook=None):
        self._recover_rotation()
        self._ensure_target()
        data,info=_read_regular(self.target,self.max_active_bytes)
        lines=self._lines(data)
        incoming_lines=self._lines(incoming)
        if len(incoming)>self.max_batch_bytes:_fail('stream-batch-budget')
        if len(data)+len(incoming)<=self.max_active_bytes:return
        # Preserve the exact last fifty prior lines. Together with each bounded
        # incoming batch this keeps the established latest50 consumer behavior.
        tail=b''.join(lines[-50:])
        if len(tail)+len(incoming)>self.max_active_bytes:_fail('stream-active-budget')
        digest=_digest(tail)
        temp=self.target.parent/('.stability-v2-rotation-'+digest)
        _write_exclusive(temp,tail)
        if hook:hook('rotation-temp')
        record={'version':1,'streamId':self.stream_id,'oldDev':info.st_dev,'oldInode':info.st_ino,
                'oldDigest':_digest(data),'newDigest':digest,'temp':temp.name}
        _write_exclusive(self.marker,_canonical(record))
        if hook:hook('rotation-intent')
        self._recover_rotation()
        if hook:hook('rotation-receipt')

    def _append(self, intent, *, hook=None):
        from .event_v2_contract import _issue_verified_export_receipt
        target=Path(intent.target).absolute()
        if target!=self.target or intent.stream_id!=self.stream_id:_fail('export-target-conflict')
        content=intent.content
        if (not isinstance(content,bytes) or len(content)>self.max_batch_bytes
                or type(intent.offset) is not int or intent.offset<0
                or intent.offset+len(content)>self.max_active_bytes):_fail('export-content-invalid')
        self._lines(content)
        fd=os.open(self.target,os.O_RDWR | getattr(os,'O_NOFOLLOW',0))
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev,info.st_ino)!=(intent.dev,intent.inode):
                _fail('export-inode-conflict')
            path_info=os.lstat(self.target)
            if (path_info.st_dev,path_info.st_ino)!=(info.st_dev,info.st_ino) or not stat.S_ISREG(path_info.st_mode):
                _fail('export-path-conflict')
            if info.st_size==intent.offset:
                if hook:hook('before-append')
                path_info=os.lstat(self.target)
                if (path_info.st_dev,path_info.st_ino)!=(info.st_dev,info.st_ino):_fail('export-path-conflict')
                written=os.pwrite(fd,content,intent.offset)
                if written!=len(content):_fail('export-partial-write')
                if hook:hook('append')
            elif info.st_size!=intent.offset+len(content):_fail('export-offset-conflict')
            if os.pread(fd,len(content),intent.offset)!=content:_fail('export-content-conflict')
            os.fsync(fd);_sync_dir(self.target.parent)
            if hook:hook('fsync')
        finally:os.close(fd)
        return _issue_verified_export_receipt(intent)

    def drain(self, core, *, max_batches=1, hook=None):
        if type(max_batches) is not int or not 1<=max_batches<=100:_fail('invalid-stream-batch-count')
        completed=0
        try:
            core.validate_stream_binding(self.stream_id,str(self.target))
            with self.locked():
                # Core must include exporting AND unknown intents; an unknown
                # binding is not permission to rotate or blindly append.
                intents=core.pending_export_intents(limit=50)
                for intent in intents[:max_batches]:
                    if intent.stream_id!=self.stream_id or Path(intent.target).absolute()!=self.target:
                        _fail('export-scope-conflict')
                    if getattr(intent,'state',None)!='exporting':_fail('export-unknown-blocked')
                    try:
                        receipt=self._append(intent,hook=hook)
                        core.confirm_export(receipt)
                        completed+=1
                    except Exception:
                        core.mark_export_unknown(intent,'stream-export-failed')
                        raise
                for _ in range(max_batches-completed):
                    batch=core.prepare_export_batch(max_records=50,max_bytes=self.max_batch_bytes)
                    if batch is None or not batch.content:break
                    if not core.stream_rotation_allowed(self.stream_id):_fail('export-rotation-blocked')
                    self._make_room(batch.content,hook=hook)
                    info=os.lstat(self.target)
                    intent=core.bind_export(batch,self.stream_id,str(self.target),info.st_dev,info.st_ino,info.st_size)
                    if hook:hook('export-intent')
                    try:
                        receipt=self._append(intent,hook=hook)
                        if hook:hook('before-export-receipt')
                        core.confirm_export(receipt);completed+=1
                    except Exception:
                        core.mark_export_unknown(intent,'stream-export-failed')
                        raise
                    if hook:hook('export-receipt')
            return {'exportedBatches':completed}
        except EventStreamError:raise
        except Exception:_fail('stream-export-failed')

    @_masked('stream-read-failed')
    def latest(self, limit=50):
        if type(limit) is not int or not 1<=limit<=50:_fail('invalid-latest-limit')
        with self.locked():
            if self.marker.exists():_fail('rotation-recovery-required')
            if not self.target.exists() and not self.target.is_symlink():
                return []
            data,_=_read_regular(self.target,self.max_active_bytes)
            return [json.loads(line) for line in self._lines(data)[-limit:]]


class ArchivePublisher:
    """Bounded immutable archive publisher and durable retirement witness.

    Witness advancement precedes SQL retirement: a crash can block as ahead,
    but never silently authorizes an old restored database to replay retired IDs.
    Pruning requires exact database/witness agreement and preserves pinned and
    unretired archives. No automatic orphan adoption/removal.
    """
    def __init__(self, root, *, max_files=64, max_bytes=67108864, max_segment_bytes=8388608):
        if (any(type(v) is not int or v<=0 for v in (max_files,max_bytes,max_segment_bytes))
                or max_files>4096 or max_bytes>1073741824 or max_segment_bytes>8388608):
            _fail('invalid-archive-policy')
        root_path=Path(root).absolute()
        if root_path.is_symlink():_fail('archive-root-invalid')
        self.root=root_path.resolve()
        self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
        root_stat=os.lstat(self.root)
        if not stat.S_ISDIR(root_stat.st_mode):_fail('archive-root-invalid')
        self._root_identity=(root_stat.st_dev,root_stat.st_ino)
        self.max_files=max_files;self.max_bytes=max_bytes;self.max_segment_bytes=max_segment_bytes
        self.witness_path=self.root/'witness.json'
        self.prune_marker=self.root/'prune-intent.json'

    def _fence(self):
        current=os.lstat(self.root)
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev,current.st_ino)!=self._root_identity:
            _fail('archive-root-changed')

    @contextlib.contextmanager
    def locked(self):
        self._fence()
        fd=os.open(self.root/'.archive.lock',os.O_RDWR | os.O_CREAT | getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):_fail('archive-lock-invalid')
            fcntl.flock(fd,fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._fence();yield
        except BlockingIOError:_fail('archive-busy')
        finally:os.close(fd)

    def _usage(self):
        count=0;size=0
        with os.scandir(self.root) as entries:
            for entry in entries:
                count+=1
                if count>self.max_files:_fail('archive-file-budget')
                info=entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):_fail('archive-file-invalid')
                size+=info.st_size
                if size>self.max_bytes:_fail('archive-byte-budget')
        return count,size

    def _budget(self, additions, *, reserve_files=0, reserve_bytes=0):
        count,size=self._usage()
        if count+len(additions)+reserve_files>self.max_files or size+sum(additions)+reserve_bytes>self.max_bytes:
            _fail('archive-capacity-exhausted')

    def _publish_immutable(self,path,content):
        if path.exists():
            old,_=_read_regular(path,max(len(content),1))
            if old!=content:_fail('archive-immutable-conflict')
            # The verified receipt subsequently fsyncs existing content too.
            return
        self._budget([len(content)])
        _write_exclusive(path,content)

    def _witness(self):
        raw,_=_read_regular(self.witness_path,65536)
        try:value=json.loads(raw)
        except (ValueError,UnicodeError):_fail('witness-invalid')
        fields={'version','storeId','retirementSeq','chain','frontiers'}
        if (not isinstance(value,dict) or set(value)!=fields or type(value['version']) is not int or value['version']!=2
                or type(value['retirementSeq']) is not int or value['retirementSeq']<0
                or not isinstance(value['storeId'],str) or len(value['storeId'])>128
                or not isinstance(value['chain'],str) or re.fullmatch('[0-9a-f]{64}',value['chain']) is None
                or not isinstance(value['frontiers'],dict) or len(value['frontiers'])>128
                or any(not isinstance(k,str) or len(k)>128 or type(v) is not int or v<0 for k,v in value['frontiers'].items())):
            _fail('witness-invalid')
        return value

    @_masked('witness-read-failed')
    def read_witness(self):
        with self.locked():return self._witness()

    @_masked('witness-initialize-failed')
    def initialize_witness(self, state):
        """Only virgin seq0 archives may initialize; never repair lost witness."""
        with self.locked():
            if self.witness_path.exists():
                if self._witness()!=state:_fail('witness-state-conflict')
                return
            if state.get('version')!=2 or state.get('retirementSeq')!=0 or state.get('chain')!='0'*64:
                _fail('witness-initial-state-invalid')
            if any(path.name!='.archive.lock' for path in self.root.iterdir()):
                _fail('witness-missing-history')
            body=_canonical(state);self._budget([len(body)])
            _write_exclusive(self.witness_path,body)
            self._witness()

    def publish(self, request, *, hook=None):
        from .event_v2_contract import ArchiveRequest, archive_manifest, _issue_verified_receipt
        if (not isinstance(request,ArchiveRequest) or len(request.content)>self.max_segment_bytes
                or _digest(request.content)!=request.content_digest
                or re.fullmatch('[0-9a-f]{64}',request.request_digest) is None):
            _fail('archive-request-invalid')
        try:
            with self.locked():
                if self.prune_marker.exists():_fail('prune-recovery-required')
                witness=self._witness()
                if (witness['storeId']!=request.store_id or witness['retirementSeq']!=request.prior_retirement_seq
                        or witness['chain']!=request.prior_chain):_fail('witness-request-conflict')
                segment=self.root/('segment-'+request.request_digest+'.json')
                manifest=self.root/(segment.name+'.manifest')
                manifest_content=archive_manifest(request,segment)
                if len(manifest_content)>65536:_fail('archive-manifest-budget')
                missing=[len(content) for path,content in ((segment,request.content),(manifest,manifest_content)) if not path.exists()]
                # Reserved capacity makes witness advancement and prune-intent
                # creation possible even when normal publishing reaches quota.
                self._budget(missing,reserve_files=2,reserve_bytes=131072)
                self._publish_immutable(segment,request.content)
                if hook:hook('archive-segment')
                self._publish_immutable(manifest,manifest_content)
                if hook:hook('archive-manifest')
                return _issue_verified_receipt(request,segment,manifest)
        except EventStreamError:raise
        except Exception:_fail('archive-publish-failed')

    @_masked('archive-recovery-proof-failed')
    def load_receipt(self, request):
        """Reissue verified current-head proof without publishing or rewinding.

        Intended for core's restricted exact-ahead-one recovery request. This
        filesystem proof alone never enables a general writer or any action.
        """
        from .event_v2_contract import ArchiveRequest, witness_value, _issue_verified_receipt
        if not isinstance(request,ArchiveRequest):_fail('archive-request-invalid')
        with self.locked():
            if self._witness()!=witness_value(request):_fail('witness-recovery-request-conflict')
            segment=self.root/('segment-'+request.request_digest+'.json')
            manifest=self.root/(segment.name+'.manifest')
            return _issue_verified_receipt(request,segment,manifest)

    def advance_witness(self, request, *, hook=None):
        from .event_v2_contract import witness_value, _issue_verified_receipt
        try:
            with self.locked():
                segment=self.root/('segment-'+request.request_digest+'.json')
                manifest=self.root/(segment.name+'.manifest')
                _issue_verified_receipt(request,segment,manifest)
                previous=self._witness();after=witness_value(request)
                if previous==after:return self.witness_path
                if (previous['storeId']!=request.store_id or previous['retirementSeq']!=request.prior_retirement_seq
                        or previous['chain']!=request.prior_chain
                        or previous['frontiers'].get(request.producer,0)!=request.prior_frontier):
                    _fail('witness-request-conflict')
                expected=dict(previous['frontiers']);expected[request.producer]=request.through_ordinal
                if expected!=after['frontiers']:_fail('witness-frontier-conflict')
                body=_canonical(after)
                temp=self.root/('.witness-'+after['chain']+'.tmp')
                self._publish_immutable(temp,body)
                if hook:hook('witness-temp')
                os.replace(temp,self.witness_path);_sync_dir(self.root)
                if hook:hook('witness-receipt')
                return self.witness_path
        except EventStreamError:raise
        except Exception:_fail('witness-publish-failed')

    def _recover_prune(self, state, catalog, pins):
        if not self.prune_marker.exists():return []
        raw,_=_read_regular(self.prune_marker,65536)
        try:plan=json.loads(raw)
        except (ValueError,UnicodeError):_fail('prune-intent-invalid')
        if (not isinstance(plan,dict) or set(plan)!={'version','state','files','requests'} or plan['version']!=2
                or plan['state']!=state or not isinstance(plan['files'],list) or len(plan['files'])>self.max_files
                or not isinstance(plan['requests'],list) or len(plan['requests'])>self.max_files):
            _fail('prune-state-conflict')
        for request_digest in plan['requests']:
            if not isinstance(request_digest,str) or re.fullmatch('[0-9a-f]{64}',request_digest) is None:
                _fail('prune-intent-invalid')
            if request_digest in pins:_fail('prune-pinned-request')
            entry=catalog.get(request_digest)
            names={'segment-'+request_digest+'.json','segment-'+request_digest+'.json.manifest'}
            if not entry:
                # SQL ack may commit before the marker unlink. Only already
                # absent files allow finalizing that narrow recovery case.
                if any((self.root/name).exists() for name in names):_fail('prune-catalog-missing')
                continue
            if entry['chain']==state['chain'] or entry['retirement_seq']>state['retirementSeq']:
                _fail('prune-unretired-request')
        expected_names={name for request in plan['requests'] for name in
                        ('segment-'+request+'.json','segment-'+request+'.json.manifest')}
        if {record.get('name') for record in plan['files'] if isinstance(record,dict)}!=expected_names:
            _fail('prune-intent-invalid')
        for record in plan['files']:
            if (not isinstance(record,dict) or set(record)!={'name','digest','bytes'}
                    or re.fullmatch(r'segment-[0-9a-f]{64}\.json(?:\.manifest)?',record['name']) is None):
                _fail('prune-intent-invalid')
            path=self.root/record['name']
            request_digest=record['name'][8:72]
            entry=catalog.get(request_digest)
            if entry and not record['name'].endswith('.manifest') and record['digest']!=entry['content_digest']:
                _fail('prune-catalog-conflict')
            if path.exists():
                content,_=_read_regular(path,max(self.max_segment_bytes,65536))
                if len(content)!=record['bytes'] or _digest(content)!=record['digest']:
                    _fail('prune-file-conflict')
                path.unlink();_sync_dir(self.root)
        return plan['requests']

    def _ack_prune(self, core, requests):
        if requests:core.ack_pruned(requests)
        if self.prune_marker.exists():
            self.prune_marker.unlink();_sync_dir(self.root)

    def prune_committed(self, core, *, pinned_request_digests=(), hook=None):
        """Delete only proven retired old archives; no hot DB/events deletion."""
        try:
            with self.locked():
                state=core.retention_state()
                if self._witness()!=state:_fail('witness-database-conflict')
                pins=set(pinned_request_digests)
                catalog=core.prunable_archive_requests()
                removed=self._recover_prune(state,catalog,pins)
                self._ack_prune(core,removed)
                catalog=core.prunable_archive_requests()
                self._usage()
                files=[];requests=[]
                for manifest in sorted(self.root.glob('segment-*.json.manifest')):
                    raw,_=_read_regular(manifest,65536)
                    try:meta=json.loads(raw)
                    except (ValueError,UnicodeError):_fail('archive-manifest-invalid')
                    if (meta.get('version')!=2 or meta.get('scope')!='local-archive-observations'
                            or meta.get('store_id')!=state['storeId']):_fail('archive-manifest-invalid')
                    entry=catalog.get(meta['request_digest'])
                    if entry is None:continue  # unknown/orphan evidence is pinned
                    if (meta['chain']!=entry['chain'] or meta['retirement_seq']!=entry['retirement_seq']
                            or meta['content_digest']!=entry['content_digest'] or meta['producer']!=entry['producer']
                            or meta['through_ordinal']!=entry['through_ordinal']):_fail('archive-catalog-conflict')
                    if (meta['chain']==state['chain'] or meta['retirement_seq']>state['retirementSeq']
                            or meta['request_digest'] in pins):continue
                    if meta['through_ordinal']>state['frontiers'].get(meta['producer'],0):continue
                    name='segment-'+meta['request_digest']+'.json'
                    if meta['segment']!=name or manifest.name!=name+'.manifest':_fail('archive-manifest-invalid')
                    segment=self.root/name
                    if Path(entry['segment']).absolute()!=segment or Path(entry['manifest']).absolute()!=manifest:
                        _fail('archive-catalog-path-conflict')
                    content,_=_read_regular(segment,self.max_segment_bytes)
                    if len(content)!=meta['bytes'] or _digest(content)!=meta['content_digest']:
                        _fail('archive-segment-conflict')
                    files.extend([{'name':segment.name,'digest':_digest(content),'bytes':len(content)},
                                  {'name':manifest.name,'digest':_digest(raw),'bytes':len(raw)}])
                    requests.append(meta['request_digest'])
                if not files:return {'removedRequests':removed}
                plan=_canonical({'version':2,'state':state,'files':files,'requests':requests})
                if len(plan)>65536:_fail('prune-intent-budget')
                self._budget([len(plan)])
                _write_exclusive(self.prune_marker,plan)
                if hook:hook('prune-intent')
                pruned=self._recover_prune(state,catalog,pins)
                if hook:hook('prune-files')
                self._ack_prune(core,pruned)
                removed+=pruned
                if hook:hook('prune-receipt')
                return {'removedRequests':removed}
        except EventStreamError:raise
        except Exception:_fail('archive-prune-failed')
