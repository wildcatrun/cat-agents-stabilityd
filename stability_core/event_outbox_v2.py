"""Offline v2 observation store. No runtime dispatch, action mutation or activation.

Only freshly initialized stores are supported. A schema marker rejects the
current v1 adapter, not arbitrary older binaries with unrestricted DB access.
Export/archive proofs refer to local durable files, never downstream delivery.
"""
from __future__ import annotations
import contextlib
import dataclasses
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid
from functools import wraps

from .event_outbox import EventOutboxError, _identity
from .event_store import _bounded_json_size
from .event_v2_contract import (GenerationHandle, OwnerEndedProof, ExportBatch, ExportIntent, ArchiveRequest,
    canonical, digest, fail, witness_value, _verify_export_receipt, _verify_archive_receipt,
    _read_file_verified)

SCHEMA = {
 'stability_event_outbox_version': 'CREATE TABLE stability_event_outbox_version(version INTEGER NOT NULL)',
 'event_v2_meta': 'CREATE TABLE event_v2_meta(id INTEGER PRIMARY KEY CHECK(id=1), store_id TEXT NOT NULL, protocol INTEGER NOT NULL CHECK(protocol=2), retirement_seq INTEGER NOT NULL, chain TEXT NOT NULL, witness_path TEXT NOT NULL)',
 'event_v2_producers': 'CREATE TABLE event_v2_producers(producer TEXT PRIMARY KEY, issued INTEGER NOT NULL CHECK(issued>=0), retired INTEGER NOT NULL CHECK(retired>=0 AND retired<=issued))',
 'event_v2_generations': "CREATE TABLE event_v2_generations(producer TEXT NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>0), generation TEXT NOT NULL UNIQUE, owner_epoch TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('open','sealed','interrupted')), expected_count INTEGER, batch_digest TEXT, observed_count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(producer,ordinal))",
 'event_v2_rows': "CREATE TABLE event_v2_rows(seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE, producer TEXT NOT NULL, ordinal INTEGER NOT NULL, event_seq INTEGER NOT NULL CHECK(event_seq>=0), payload_digest TEXT NOT NULL, line BLOB NOT NULL, line_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','exporting','exported','unknown')), intent_id TEXT, stream_id TEXT, target TEXT, dev INTEGER, inode INTEGER, offset INTEGER, UNIQUE(producer,ordinal,event_seq))",
 'event_v2_stream_binding': 'CREATE TABLE event_v2_stream_binding(id INTEGER PRIMARY KEY CHECK(id=1), stream_id TEXT NOT NULL UNIQUE, target TEXT NOT NULL UNIQUE)',
 'event_v2_intents': "CREATE TABLE event_v2_intents(intent_id TEXT PRIMARY KEY, batch_id TEXT NOT NULL, event_ids TEXT NOT NULL, stream_id TEXT NOT NULL, target TEXT NOT NULL, dev INTEGER NOT NULL, inode INTEGER NOT NULL, offset INTEGER NOT NULL, content_digest TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('exporting','unknown')))",
 'event_v2_receipts': 'CREATE TABLE event_v2_receipts(retirement_seq INTEGER PRIMARY KEY, producer TEXT NOT NULL, through_ordinal INTEGER NOT NULL, request_digest TEXT NOT NULL, chain TEXT NOT NULL, content_digest TEXT NOT NULL, segment TEXT NOT NULL, manifest TEXT NOT NULL)',
}

def masked(code):
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            try: return function(*args, **kwargs)
            except EventOutboxError: raise
            except Exception: fail(code)
        return call
    return decorate

class EventOutboxV2:
    @masked('v2-open-failed')
    def __init__(self, path, *, initialize=False, connection=None, connection_identity=None,
                 max_hot_records=4096, max_hot_bytes=8388608, max_generations=128,
                 max_receipts=32, max_producers=16, max_payload_bytes=65536,
                 witness_path=None, writer_lock_path=None, owner_epoch=None, recovery_open=False):
        bounds = ((max_hot_records,100000),(max_hot_bytes,67108864),(max_generations,4096),
                  (max_receipts,1024),(max_producers,128),(max_payload_bytes,65536))
        if any(type(value) is not int or not 1 <= value <= ceiling for value,ceiling in bounds):
            fail('v2-budget-invalid')
        if type(initialize) is not bool or type(recovery_open) is not bool: fail('v2-initialize-invalid')
        self.path = Path(path).absolute()
        self.connection = None
        self._requested_witness=Path(witness_path).resolve() if witness_path is not None else None
        self.witness_path=None
        self._bootstrap_pending=False
        self._recovery_only=False
        self._recovery_request=None
        canonical_lock=Path(str(self.path.resolve())+".writer.lock")
        if writer_lock_path is not None and Path(writer_lock_path).resolve()!=canonical_lock:
            fail('v2-writer-lock-path-invalid')
        self.writer_lock_path=canonical_lock
        self._writer_fd=None
        self._owner_context=object()
        self.owner_epoch=uuid.uuid4().hex if owner_epoch is None else owner_epoch
        if not _identity(self.owner_epoch):fail('v2-owner-epoch-invalid')
        self._owns_connection = connection is None
        self.max_hot_records, self.max_hot_bytes = max_hot_records,max_hot_bytes
        self.max_generations, self.max_receipts = max_generations,max_receipts
        self.max_producers,self.max_payload_bytes = max_producers,max_payload_bytes
        try:
            if str(path) == ':memory:' or self.path.is_symlink(): fail('v2-durable-path-required')
            self._writer_fd=os.open(self.writer_lock_path,os.O_RDWR|os.O_CREAT|getattr(os,'O_NOFOLLOW',0),0o600)
            lock_stat=os.fstat(self._writer_fd)
            if not stat.S_ISREG(lock_stat.st_mode):fail('v2-writer-lock-invalid')
            self._lock_identity=(lock_stat.st_dev,lock_stat.st_ino)
            fcntl.flock(self._writer_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self._check_writer_lock()
            if connection is not None:
                if not isinstance(connection,sqlite3.Connection) or connection.in_transaction:
                    fail('v2-caller-transaction-active')
                self.connection=connection
                if (not isinstance(connection_identity,tuple) or len(connection_identity)!=2
                        or any(type(value) is not int for value in connection_identity)):
                    fail('v2-borrowed-identity-required')
                self._file_identity=connection_identity
                self._check_identity()
                main=next((row[2] for row in connection.execute('PRAGMA database_list') if row[1]=='main'),'')
                if not main or Path(main).resolve()!=self.path.resolve(): fail('v2-borrowed-path-mismatch')
                if connection.execute('PRAGMA journal_mode').fetchone()[0].lower()!='wal': fail('v2-wal-required')
                if connection.execute('PRAGMA synchronous').fetchone()[0]!=2: fail('v2-full-required')
            else:
                before=os.lstat(self.path) if self.path.exists() else None
                self.connection=sqlite3.connect(str(self.path),isolation_level=None,timeout=1)
                after=os.lstat(self.path)
                self._file_identity=(after.st_dev,after.st_ino)
                if before is not None and (before.st_dev,before.st_ino)!=self._file_identity:
                    fail('v2-store-identity-changed')
                self._check_identity()
            present={row[0] for row in self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            existing=present & set(SCHEMA)
            if existing:
                if existing!=set(SCHEMA): fail('v2-schema-incomplete')
            elif not initialize:
                fail('v2-initialize-required')
            # Never auto-convert legacy history or independently initialized v1.
            if not existing and any(name.startswith('stability_retention_') or name.startswith('stability_event_outbox')
                                    for name in present): fail('v2-audited-migration-required')
            for table in ('events','stability_event_outbox'):
                if table in present and self.connection.execute('SELECT 1 FROM '+table+' LIMIT 1').fetchone():
                    fail('v2-audited-migration-required')
            if existing:
                stored=self.connection.execute('SELECT witness_path FROM event_v2_meta').fetchall()
                if len(stored)!=1 or not isinstance(stored[0][0],str) or not 1<=len(stored[0][0])<=1024:
                    fail('v2-witness-binding-invalid')
                self.witness_path=Path(stored[0][0]).resolve()
                if str(self.witness_path)!=stored[0][0]:fail('v2-witness-binding-invalid')
                if self._requested_witness is not None and self._requested_witness!=self.witness_path:
                    fail('v2-witness-path-conflict')
            else:
                self.witness_path=self._requested_witness or Path(str(self.path.resolve())+'.witness.json')
                if len(str(self.witness_path))>1024:fail('v2-witness-binding-invalid')
                self._bootstrap_pending=True
            if self._owns_connection:
                self.connection.execute('PRAGMA journal_mode=WAL')
                self.connection.execute('PRAGMA synchronous=FULL')
            with self._transaction(check_schema=bool(existing),check_witness=False):
                if not existing:
                    for statement in SCHEMA.values(): self.connection.execute(statement)
                    self.connection.execute('INSERT INTO stability_event_outbox_version VALUES(2)')
                    self.connection.execute('INSERT INTO event_v2_meta VALUES(1,?,2,0,?,?)',
                                            ('store_'+uuid.uuid4().hex,'0'*64,str(self.witness_path)))
                self._check_schema()
            self.store_id=self.connection.execute('SELECT store_id FROM event_v2_meta').fetchone()[0]
            if recovery_open:
                if self._bootstrap_pending:fail('v2-recovery-not-required')
                with self._transaction(check_witness=False):
                    self._recovery_request=self._assess_recovery()
                self._recovery_only=True
            else:
                self._check_witness(allow_bootstrap=self._bootstrap_pending)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.connection is not None:
            if self._owns_connection: self.connection.close()
            self.connection=None
        if self._writer_fd is not None:
            os.close(self._writer_fd)
            self._writer_fd=None

    def __enter__(self): return self
    def __exit__(self,*_): self.close()

    def _check_identity(self):
        try:
            value=os.lstat(self.path)
            if not stat.S_ISREG(value.st_mode) or value.st_nlink!=1 or (value.st_dev,value.st_ino)!=self._file_identity:
                fail('v2-store-identity-changed')
        except OSError: fail('v2-store-identity-changed')

    def _check_writer_lock(self):
        if self._writer_fd is None:fail('v2-writer-lock-required')
        descriptor=os.fstat(self._writer_fd)
        path=os.lstat(self.writer_lock_path)
        if (not stat.S_ISREG(path.st_mode) or path.st_nlink!=1 or (path.st_dev,path.st_ino)!=self._lock_identity
                or (descriptor.st_dev,descriptor.st_ino)!=self._lock_identity):
            fail('v2-writer-lock-changed')
        fcntl.flock(self._writer_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def _check_schema(self):
        norm=lambda text:re.sub(r'\s+','',text).lower()
        for name,statement in SCHEMA.items():
            row=self.connection.execute("SELECT substr(sql,1,?) FROM sqlite_master WHERE type='table' AND name=?",
                                        (len(statement)+1,name)).fetchone()
            if not row or norm(row[0])!=norm(statement): fail('v2-schema-invalid')
        if [tuple(row) for row in self.connection.execute('SELECT version FROM stability_event_outbox_version')]!=[(2,)]:
            fail('v2-protocol-floor')
        meta=self.connection.execute('SELECT store_id,protocol,retirement_seq,chain,witness_path FROM event_v2_meta LIMIT 2').fetchall()
        if (len(meta)!=1 or not re.fullmatch(r'store_[0-9a-f]{32}',meta[0][0]) or meta[0][1]!=2
                or type(meta[0][2]) is not int or meta[0][2]<0 or not re.fullmatch(r'[0-9a-f]{64}',meta[0][3])
                or meta[0][4]!=str(self.witness_path)
                or getattr(self,'store_id',meta[0][0])!=meta[0][0]):
            fail('v2-meta-invalid')

    @contextlib.contextmanager
    def _transaction(self, *, check_schema=True, check_witness=True, allow_bootstrap=False, allow_recovery=False):
        if self.connection.in_transaction: fail('v2-caller-transaction-active')
        if self._recovery_only and not allow_recovery:fail('v2-recovery-only')
        self._check_identity()
        self._check_writer_lock()
        self.connection.execute('BEGIN IMMEDIATE')
        try:
            if check_schema:self._check_schema()
            if check_schema and check_witness:self._check_witness(allow_bootstrap=allow_bootstrap)
            yield
            self._check_identity()
            self._check_writer_lock()
            self.connection.execute('COMMIT')
        except BaseException:
            with contextlib.suppress(sqlite3.Error):self.connection.execute('ROLLBACK')
            raise

    def _handle(self,handle):
        if (not isinstance(handle,GenerationHandle) or handle.store_id!=self.store_id
                or type(handle.ordinal) is not int or not 0<handle.ordinal<=2**63-1):
            fail('v2-generation-handle-invalid')
        row=self.connection.execute('SELECT retired FROM event_v2_producers WHERE producer=?',(handle.producer,)).fetchone()
        if row and handle.ordinal<=row[0]:fail('v2-generation-retired')
        row=self.connection.execute('SELECT generation,owner_epoch,state,expected_count,batch_digest,observed_count FROM event_v2_generations WHERE producer=? AND ordinal=?',
                                    (handle.producer,handle.ordinal)).fetchone()
        if not row or row[0]!=handle.generation_uuid or row[1]!=handle.owner_epoch:
            fail('v2-generation-unregistered')
        return row

    @masked('v2-begin-failed')
    def begin_generation(self,producer,owner_epoch):
        if not _identity(producer) or not _identity(owner_epoch):fail('v2-generation-identity-invalid')
        if owner_epoch!=self.owner_epoch:fail('v2-owner-context-mismatch')
        with self._transaction():
            if self.connection.execute('SELECT COUNT(*) FROM event_v2_generations').fetchone()[0]>=self.max_generations:
                fail('v2-generation-budget')
            existing=self.connection.execute('SELECT issued FROM event_v2_producers WHERE producer=?',(producer,)).fetchone()
            if not existing:
                if self.connection.execute('SELECT COUNT(*) FROM event_v2_producers').fetchone()[0]>=self.max_producers:
                    fail('v2-producer-budget')
                self.connection.execute('INSERT INTO event_v2_producers VALUES(?,0,0)',(producer,))
            ordinal=(existing[0] if existing else 0)+1
            if ordinal>2**63-1:fail('v2-ordinal-exhausted')
            generation=uuid.uuid4().hex
            self.connection.execute('UPDATE event_v2_producers SET issued=? WHERE producer=?',(ordinal,producer))
            self.connection.execute('INSERT INTO event_v2_generations(producer,ordinal,generation,owner_epoch,state) VALUES(?,?,?,?,\'open\')',
                                    (producer,ordinal,generation,owner_epoch))
            return GenerationHandle(self.store_id,producer,ordinal,generation,owner_epoch)

    @masked('v2-load-generation-failed')
    def load_generation(self,producer,ordinal,owner_epoch):
        if type(ordinal) is not int or not 0<ordinal<=2**63-1:fail('v2-generation-handle-invalid')
        with self._transaction():
            producer_row=self.connection.execute('SELECT retired FROM event_v2_producers WHERE producer=?',(producer,)).fetchone()
            if producer_row and ordinal<=producer_row[0]:fail('v2-generation-retired')
            row=self.connection.execute('SELECT generation FROM event_v2_generations WHERE producer=? AND ordinal=?',(producer,ordinal)).fetchone()
            if not row:fail('v2-generation-unregistered')
            handle=GenerationHandle(self.store_id,producer,ordinal,row[0],owner_epoch)
            self._handle(handle)
            return handle

    def batch_digest(self,events):
        encoded=self._encode_events(events)
        return digest(canonical([item[0] for item in encoded]))

    def _encode_events(self,events):
        if not isinstance(events,(list,tuple)) or len(events)>self.max_hot_records:fail('v2-batch-budget')
        encoded=[];total=0
        for event in events:
            if not isinstance(event,dict):fail('v2-event-invalid')
            _bounded_json_size(event,self.max_payload_bytes)
            if type(event.get('tsEpoch')) is not int or not 0<=event['tsEpoch']<=2**63-1:fail('v2-event-time-invalid')
            payload=canonical(event)
            line=(json.dumps(event,ensure_ascii=False,allow_nan=False)+'\n').encode()
            total+=len(line)
            if len(line)>self.max_payload_bytes or total>self.max_hot_bytes:fail('v2-batch-budget')
            encoded.append((digest(payload),line,digest(line)))
        return encoded

    @masked('v2-record-failed')
    def record_batch(self,handle,events,*,expected_count,batch_digest):
        return self._record_events(handle, events, expected_count, (batch_digest,))

    @masked('v2-record-failed')
    def _record_owned_batch(self,handle,events):
        # Internal producers supply original events, never prevalidated bytes.
        # Encoding, limits and digests are established together in this call.
        return self._record_events(handle, events, len(events), ())

    def _record_events(self,handle,events,expected_count,supplied_digest):
        if type(expected_count) is not int or expected_count!=len(events):fail('v2-expected-count-invalid')
        encoded=self._encode_events(events)
        actual=digest(canonical([item[0] for item in encoded]))
        if supplied_digest:
            batch_digest=supplied_digest[0]
            if not isinstance(batch_digest,str) or actual!=batch_digest:fail('v2-batch-digest-conflict')
        with self._transaction():
            row=self._handle(handle)
            if row[3] is not None:
                if row[3]!=expected_count or row[4]!=actual:fail('v2-generation-batch-conflict')
                existing=self.connection.execute('SELECT event_seq,payload_digest FROM event_v2_rows WHERE producer=? AND ordinal=? ORDER BY event_seq',
                                                 (handle.producer,handle.ordinal)).fetchall()
                if [tuple(item) for item in existing]!=[(i,value[0]) for i,value in enumerate(encoded)]:fail('v2-generation-batch-conflict')
                return {'duplicate':True,'count':expected_count,'ordinal':handle.ordinal}
            if row[2]!='open':fail('v2-generation-sealed')
            if handle.owner_epoch!=self.owner_epoch:fail('v2-owner-context-mismatch')
            count,size=self.connection.execute('SELECT COUNT(*),COALESCE(SUM(length(line)),0) FROM event_v2_rows').fetchone()
            if count+len(encoded)>self.max_hot_records or size+sum(len(item[1]) for item in encoded)>self.max_hot_bytes:
                fail('v2-hot-budget')
            for seq,(payload_hash,line,line_hash) in enumerate(encoded):
                event_id=digest(canonical([self.store_id,handle.producer,handle.ordinal,handle.generation_uuid,seq]))
                self.connection.execute('INSERT INTO event_v2_rows(event_id,producer,ordinal,event_seq,payload_digest,line,line_digest,state) VALUES(?,?,?,?,?,?,?,\'pending\')',
                                        (event_id,handle.producer,handle.ordinal,seq,payload_hash,line,line_hash))
            self.connection.execute('UPDATE event_v2_generations SET expected_count=?,batch_digest=?,observed_count=? WHERE producer=? AND ordinal=?',
                                    (expected_count,actual,expected_count,handle.producer,handle.ordinal))
            return {'duplicate':False,'count':expected_count,'ordinal':handle.ordinal}

    @masked('v2-seal-failed')
    def seal_generation(self,handle):
        with self._transaction():
            row=self._handle(handle)
            if handle.owner_epoch!=self.owner_epoch:fail('v2-owner-context-mismatch')
            if row[2]=='interrupted':fail('v2-generation-interrupted')
            if row[3] is None or row[3]!=row[5]:fail('v2-batch-incomplete')
            self.connection.execute('UPDATE event_v2_generations SET state=\'sealed\' WHERE producer=? AND ordinal=?',(handle.producer,handle.ordinal))
            return {'state':'sealed','observationsComplete':True,'actionStateChanged':False}

    @masked('v2-interrupt-failed')
    def owner_ended_proof(self,handle):
        with self._transaction():
            self._handle(handle)
            if handle.owner_epoch==self.owner_epoch:fail('v2-prior-owner-still-current')
            return OwnerEndedProof(self.store_id,handle.owner_epoch,self.owner_epoch,
                                   self._lock_identity,self._owner_context)

    @masked('v2-interrupt-failed')
    def close_interrupted_generation(self,handle,proof):
        if (not isinstance(proof,OwnerEndedProof) or proof._owner_context is not self._owner_context
                or proof.store_id!=self.store_id or proof.prior_owner_epoch!=handle.owner_epoch
                or proof.current_owner_epoch!=self.owner_epoch or proof.lock_identity!=self._lock_identity):
            fail('v2-writer-proof-required')
        with self._transaction():
            row=self._handle(handle)
            if row[2]!='open':fail('v2-generation-not-open')
            self.connection.execute('UPDATE event_v2_generations SET state=\'interrupted\' WHERE producer=? AND ordinal=?',(handle.producer,handle.ordinal))
            return {'state':'interrupted','observationsComplete':False,
                    'expectedCount':row[3],'committedCount':row[5],'actionStateChanged':False}

    def _line(self,event_id):
        row=self.connection.execute('SELECT length(line),substr(line,1,?),substr(line_digest,1,65),state,substr(payload_digest,1,65),producer,ordinal,event_seq FROM event_v2_rows WHERE event_id=?',
                                    (self.max_payload_bytes+1,event_id)).fetchone()
        if (not row or type(row[0]) is not int or not isinstance(row[1],bytes)
                or not 0<row[0]<=self.max_payload_bytes or len(row[1])!=row[0] or digest(row[1])!=row[2]):
            fail('v2-event-evidence-invalid')
        payload=json.loads(row[1])
        if not isinstance(payload,dict) or digest(canonical(payload))!=row[4]:fail('v2-event-evidence-invalid')
        generation=self.connection.execute('SELECT generation FROM event_v2_generations WHERE producer=? AND ordinal=?',(row[5],row[6])).fetchone()
        if not generation or digest(canonical([self.store_id,row[5],row[6],generation[0],row[7]]))!=event_id:
            fail('v2-event-identity-invalid')
        return row[1],row[3]

    @masked('v2-export-prepare-failed')
    def prepare_export_batch(self,*,max_records=50,max_bytes=1048576):
        if type(max_records) is not int or not 1<=max_records<=1000 or type(max_bytes) is not int or not 1<=max_bytes<=1048576:
            fail('v2-export-budget-invalid')
        with self._transaction():
            if self.connection.execute('SELECT 1 FROM event_v2_intents LIMIT 1').fetchone():fail('v2-export-recovery-required')
            ids=[];lines=[];size=0
            for row in self.connection.execute("SELECT event_id FROM event_v2_rows WHERE state='pending' ORDER BY seq LIMIT ?",(max_records,)):
                line,_=self._line(row[0])
                if size+len(line)>max_bytes:
                    if not ids:fail('v2-export-budget-invalid')
                    break
                ids.append(row[0]);lines.append(line);size+=len(line)
            if not ids:return None
            content=b''.join(lines)
            return ExportBatch(self.store_id,digest(canonical(ids)),tuple(ids),content,digest(content))

    @masked('v2-export-bind-failed')
    def bind_export(self,batch,stream_id,target,dev,inode,offset):
        if (not isinstance(batch,ExportBatch) or batch.store_id!=self.store_id or not _identity(stream_id)
                or not isinstance(batch.event_ids,tuple) or not 1<=len(batch.event_ids)<=1000
                or len(set(batch.event_ids))!=len(batch.event_ids)
                or not isinstance(batch.content,bytes) or len(batch.content)>1048576
                or any(type(value) is not int or value<0 for value in (dev,inode,offset))):fail('v2-export-bind-invalid')
        target=Path(target).absolute()
        if len(str(target))>1024 or target.is_symlink():fail('v2-export-target-invalid')
        target=target.resolve()
        file_stat=os.lstat(target)
        if not stat.S_ISREG(file_stat.st_mode) or (file_stat.st_dev,file_stat.st_ino)!=(dev,inode) or file_stat.st_size!=offset:
            fail('v2-export-target-conflict')
        with self._transaction():
            binding=self.connection.execute('SELECT stream_id,target FROM event_v2_stream_binding WHERE id=1').fetchone()
            if binding and (binding[0],binding[1])!=(stream_id,str(target)):
                fail('v2-stream-target-conflict')
            if self.connection.execute('SELECT 1 FROM event_v2_intents LIMIT 1').fetchone():fail('v2-export-recovery-required')
            content=b''.join(self._line(event_id)[0] for event_id in batch.event_ids)
            if (not batch.event_ids or content!=batch.content or digest(content)!=batch.content_digest
                    or digest(canonical(list(batch.event_ids)))!=batch.batch_id
                    or any(self._line(event_id)[1]!='pending' for event_id in batch.event_ids)):
                fail('v2-export-batch-conflict')
            intent_id='export_'+uuid.uuid4().hex
            if not binding:
                self.connection.execute('INSERT INTO event_v2_stream_binding VALUES(1,?,?)',(stream_id,str(target)))
            self.connection.execute('INSERT INTO event_v2_intents VALUES(?,?,?,?,?,?,?,?,?,\'exporting\')',
                (intent_id,batch.batch_id,json.dumps(batch.event_ids),stream_id,str(target),dev,inode,offset,batch.content_digest))
            for event_id in batch.event_ids:
                self.connection.execute('UPDATE event_v2_rows SET state=\'exporting\',intent_id=?,stream_id=?,target=?,dev=?,inode=? WHERE event_id=?',
                                        (intent_id,stream_id,str(target),dev,inode,event_id))
            return ExportIntent(self.store_id,intent_id,batch.batch_id,batch.event_ids,stream_id,str(target),dev,inode,offset,content,batch.content_digest)

    def _intent(self,intent_id):
        row=self.connection.execute('SELECT batch_id,event_ids,stream_id,target,dev,inode,offset,content_digest,state FROM event_v2_intents WHERE intent_id=?',(intent_id,)).fetchone()
        if not row:fail('v2-export-intent-missing')
        if len(row[1])>70000:fail('v2-export-intent-conflict')
        ids=json.loads(row[1])
        if (not isinstance(ids,list) or not 1<=len(ids)<=1000 or len(set(ids))!=len(ids)
                or any(not isinstance(item,str) or re.fullmatch(r'[0-9a-f]{64}',item) is None for item in ids)):
            fail('v2-export-intent-conflict')
        content=b''.join(self._line(event_id)[0] for event_id in ids)
        if len(content)>1048576:fail('v2-export-intent-conflict')
        if digest(content)!=row[7]:fail('v2-export-intent-conflict')
        return ExportIntent(self.store_id,intent_id,row[0],tuple(ids),row[2],row[3],row[4],row[5],row[6],content,row[7],row[8])

    @masked('v2-export-pending-failed')
    def pending_export_intents(self,*,limit=50):
        if type(limit) is not int or not 1<=limit<=50:fail('v2-export-budget-invalid')
        with self._transaction():
            return [self._intent(row[0]) for row in self.connection.execute('SELECT intent_id FROM event_v2_intents ORDER BY rowid LIMIT ?',(limit,))]

    @masked('v2-export-unknown-failed')
    def mark_export_unknown(self,intent,reason_code):
        if not isinstance(intent,ExportIntent) or reason_code!='stream-export-failed':fail('v2-export-unknown-invalid')
        with self._transaction():
            if not self.connection.execute('SELECT 1 FROM event_v2_intents WHERE intent_id=?',(intent.intent_id,)).fetchone():
                return {'state':'already-confirmed-or-missing','changed':False}
            actual=self._intent(intent.intent_id)
            if dataclasses.replace(actual,state=intent.state)!=intent:fail('v2-export-intent-conflict')
            if actual.state!='exporting':return {'state':actual.state,'changed':False}
            self.connection.execute('UPDATE event_v2_intents SET state=\'unknown\' WHERE intent_id=?',(intent.intent_id,))
            self.connection.execute('UPDATE event_v2_rows SET state=\'unknown\' WHERE intent_id=?',(intent.intent_id,))

    @masked('v2-export-confirm-failed')
    def confirm_export(self,receipt):
        # SQL unknown is not cleared just because formerly valid bytes remain.
        from .event_v2_contract import ExportReceipt
        if not isinstance(receipt,ExportReceipt):fail('export-receipt-required')
        with self._transaction():
            actual=self._intent(receipt.intent.intent_id)
            if actual.state!='exporting':fail('v2-export-unknown-reconciliation-required')
            receipt=_verify_export_receipt(receipt)
            if actual!=receipt.intent:fail('v2-export-intent-conflict')
            position=actual.offset
            for event_id in actual.event_ids:
                line,_=self._line(event_id)
                self.connection.execute('UPDATE event_v2_rows SET state=\'exported\',intent_id=NULL,offset=? WHERE event_id=?',(position,event_id))
                position+=len(line)
            self.connection.execute('DELETE FROM event_v2_intents WHERE intent_id=?',(actual.intent_id,))
            return {'coverage':'local-export-receipt','events':len(actual.event_ids)}

    @masked('v2-stream-state-failed')
    def stream_rotation_allowed(self,stream_id):
        with self._transaction():
            binding=self.connection.execute('SELECT stream_id FROM event_v2_stream_binding WHERE id=1').fetchone()
            if binding and binding[0]!=stream_id:fail('v2-stream-target-conflict')
            return not self.connection.execute('SELECT 1 FROM event_v2_intents WHERE stream_id=? LIMIT 1',(stream_id,)).fetchone()

    @masked('v2-stream-binding-failed')
    def validate_stream_binding(self,stream_id,target):
        """Check before publisher creates or rotates any target files."""
        target=Path(target)
        if not _identity(stream_id) or target.is_symlink():fail('v2-export-target-invalid')
        normalized=str(target.resolve())
        if len(normalized)>1024:fail('v2-export-target-invalid')
        with self._transaction():
            binding=self.connection.execute('SELECT stream_id,target FROM event_v2_stream_binding WHERE id=1').fetchone()
            if binding and (binding[0],binding[1])!=(stream_id,normalized):
                fail('v2-stream-target-conflict')
            return {'scope':'local-event-stream','bound':binding is not None}

    def _retention_state(self):
        meta=self.connection.execute('SELECT store_id,retirement_seq,chain FROM event_v2_meta').fetchone()
        frontiers=dict(self.connection.execute('SELECT producer,retired FROM event_v2_producers WHERE retired>0 ORDER BY producer'))
        return {'version':2,'storeId':meta[0],'retirementSeq':meta[1],'chain':meta[2],'frontiers':frontiers}

    @masked('v2-retention-state-failed')
    def retention_state(self):
        with self._transaction(check_witness=not self._recovery_only,allow_bootstrap=True,allow_recovery=True):
            return self._retention_state()

    def _check_witness(self, *, allow_bootstrap=False):
        state=self._retention_state()
        if self.witness_path is None:fail('v2-witness-required')
        if not self.witness_path.exists():
            # Only this exact newly-created-schema context can expose initial
            # state for publishing its first witness. No ordinary writes occur.
            if allow_bootstrap and self._bootstrap_pending and state['retirementSeq']==0:
                return
            fail('v2-witness-required')
        if self._witness(self.witness_path)!=state:fail('v2-restore-frontier-drift')
        self._bootstrap_pending=False

    def _assess_recovery(self):
        """Rebuild a single event archive transition, never whole-DB freshness."""
        state=self._retention_state()
        witness=self._witness(self.witness_path)
        if (witness.get('version')!=2 or witness.get('storeId')!=state['storeId']
                or type(witness.get('retirementSeq')) is not int
                or witness['retirementSeq']!=state['retirementSeq']+1
                or not isinstance(witness.get('frontiers'),dict)
                or len(witness['frontiers'])>self.max_producers):
            fail('v2-recovery-witness-invalid')
        changed=[producer for producer in set(state['frontiers'])|set(witness['frontiers'])
                 if witness['frontiers'].get(producer,0)!=state['frontiers'].get(producer,0)]
        if len(changed)!=1:fail('v2-recovery-frontier-invalid')
        producer=changed[0];frontier=witness['frontiers'].get(producer)
        if (not _identity(producer) or type(frontier) is not int
                or not state['frontiers'].get(producer,0)<frontier<=2**63-1):
            fail('v2-recovery-frontier-invalid')
        request=self._archive(producer,frontier,10000,8388608)
        if witness_value(request)!=witness:fail('v2-recovery-request-conflict')
        if self.connection.execute('SELECT COUNT(*) FROM event_v2_receipts').fetchone()[0]>=self.max_receipts:
            fail('v2-retirement-catalog-budget')
        return request

    @masked('v2-recovery-prepare-failed')
    def recovery_archive_request(self):
        if not self._recovery_only:fail('v2-recovery-not-required')
        with self._transaction(check_witness=False,allow_recovery=True):
            request=self._assess_recovery()
            if request!=self._recovery_request:fail('v2-recovery-request-conflict')
            return request

    def _witness(self,path):
        content,_=_read_file_verified(path,max_bytes=65536)
        parsed=json.loads(content)
        if not isinstance(parsed,dict):fail('v2-witness-invalid')
        return parsed

    def _archive(self,producer,through_ordinal,max_records,max_bytes):
        row=self.connection.execute('SELECT retired,issued FROM event_v2_producers WHERE producer=?',(producer,)).fetchone()
        if not row or not row[0]<through_ordinal<=row[1]:fail('v2-frontier-invalid')
        if through_ordinal-row[0]>self.max_generations:fail('v2-archive-budget')
        generations=self.connection.execute('SELECT ordinal,generation,owner_epoch,state,expected_count,batch_digest,observed_count FROM event_v2_generations WHERE producer=? AND ordinal>? AND ordinal<=? ORDER BY ordinal LIMIT ?',
            (producer,row[0],through_ordinal,self.max_generations+1)).fetchall()
        if len(generations)!=through_ordinal-row[0] or any(g[3]=='open' for g in generations):fail('v2-generation-not-closed')
        events=[];size=0
        for gen in generations:
            selected=self.connection.execute('SELECT event_id,event_seq,payload_digest,line_digest,state,stream_id,dev,inode,offset,target FROM event_v2_rows WHERE producer=? AND ordinal=? ORDER BY event_seq LIMIT ?',
                                             (producer,gen[0],max_records-len(events)+1)).fetchall()
            if len(events)+len(selected)>max_records:fail('v2-archive-budget')
            if len(selected)!=gen[6]:fail('v2-generation-count-conflict')
            for item in selected:
                if item[4]!='exported':fail('v2-events-not-exported')
                line,_=self._line(item[0]);size+=len(line)
                if size>max_bytes:fail('v2-archive-budget')
                events.append({'ordinal':gen[0],'eventId':item[0],'eventSeq':item[1],
                               'payloadDigest':item[2],'lineDigest':item[3],'line':line.decode(),
                               'streamId':item[5],'dev':item[6],'inode':item[7],'offset':item[8],'target':item[9]})
        state=self._retention_state()
        body={'version':2,'scope':'local-export-receipts','storeId':self.store_id,'producer':producer,
              'firstOrdinal':row[0]+1,'throughOrdinal':through_ordinal,
              'generations':[{'ordinal':g[0],'generation':g[1],'ownerEpoch':g[2],'state':g[3],
                              'expectedCount':g[4],'batchDigest':g[5],'committedCount':g[6],
                              'observationsComplete':g[3]=='sealed'} for g in generations], 'events':events}
        content=canonical(body)
        if len(content)>max_bytes:fail('v2-archive-budget')
        frontiers={**state['frontiers'],producer:through_ordinal}
        content_hash=digest(content)
        request_hash=digest(canonical([self.store_id,producer,row[0],through_ordinal,state['chain'],
                                       state['retirementSeq'],frontiers,content_hash]))
        return ArchiveRequest(self.store_id,producer,row[0],through_ordinal,state['chain'],
                              state['retirementSeq'],tuple(sorted(frontiers.items())),content,content_hash,request_hash,len(events))

    @masked('v2-archive-prepare-failed')
    def prepare_archive(self,producer,through_ordinal,*,max_records=1000,max_bytes=8388608,witness_path=None):
        if (not _identity(producer) or type(through_ordinal) is not int or not 0<through_ordinal<=2**63-1
                or type(max_records) is not int or not 1<=max_records<=10000
                or type(max_bytes) is not int or not 1<=max_bytes<=8388608):fail('v2-archive-budget-invalid')
        if witness_path is not None and Path(witness_path).resolve()!=self.witness_path:
            fail('v2-witness-path-conflict')
        with self._transaction():
            if witness_path is not None and Path(witness_path).exists():
                if self._witness(witness_path)!=self._retention_state():fail('v2-restore-frontier-drift')
            if self.connection.execute('SELECT COUNT(*) FROM event_v2_receipts').fetchone()[0]>=self.max_receipts:
                fail('v2-retirement-catalog-budget')
            return self._archive(producer,through_ordinal,max_records,max_bytes)

    @masked('v2-retire-failed')
    def retire(self,receipt,*,witness_path=None):
        receipt=_verify_archive_receipt(receipt)
        request=receipt.request
        witness_path=Path(witness_path).resolve() if witness_path is not None else self.witness_path
        if witness_path is None:fail('v2-witness-required')
        if self.witness_path is not None and witness_path!=self.witness_path:fail('v2-witness-path-conflict')
        with self._transaction(check_witness=False,allow_recovery=True):
            if self._recovery_only and request!=self._recovery_request:fail('v2-recovery-request-conflict')
            if self._witness(witness_path)!=witness_value(request):fail('v2-witness-conflict')
            current=self._archive(request.producer,request.through_ordinal,10000,8388608)
            if current!=request:fail('v2-archive-frontier-conflict')
            self.connection.execute('UPDATE event_v2_producers SET retired=? WHERE producer=?',(request.through_ordinal,request.producer))
            self.connection.execute('DELETE FROM event_v2_rows WHERE producer=? AND ordinal<=?',(request.producer,request.through_ordinal))
            self.connection.execute('DELETE FROM event_v2_generations WHERE producer=? AND ordinal<=?',(request.producer,request.through_ordinal))
            self.connection.execute('UPDATE event_v2_meta SET retirement_seq=?,chain=? WHERE id=1',(request.retirement_seq,request.chain))
            if self.connection.execute('SELECT COUNT(*) FROM event_v2_receipts').fetchone()[0]>=self.max_receipts:
                fail('v2-retirement-catalog-budget')
            self.connection.execute('INSERT INTO event_v2_receipts VALUES(?,?,?,?,?,?,?,?)',
                (request.retirement_seq,request.producer,request.through_ordinal,request.request_digest,request.chain,
                 request.content_digest,receipt.segment_path,receipt.manifest_path))
        self._recovery_only=False
        self._recovery_request=None
        self._check_witness()
        return {'retired':True,'throughOrdinal':request.through_ordinal,'actionStateChanged':False,
                'scope':'local-event-retention','actionRecoveryQualification':'separate-required',
                'actuatorReadiness':'not-qualified-by-event-recovery'}

    @masked('v2-prunable-state-failed')
    def prunable_archive_requests(self):
        with self._transaction():
            rows=self.connection.execute('SELECT retirement_seq,producer,through_ordinal,request_digest,chain,content_digest,segment,manifest FROM event_v2_receipts ORDER BY retirement_seq LIMIT ?',
                                         (self.max_receipts+1,)).fetchall()
            if len(rows)>self.max_receipts:fail('v2-retirement-catalog-budget')
            return {row[3]:{'retirement_seq':row[0],'producer':row[1],'through_ordinal':row[2],
                            'chain':row[4],'content_digest':row[5],'segment':row[6],'manifest':row[7]}
                    for row in rows}

    @masked('v2-prune-ack-failed')
    def ack_pruned(self,request_digests):
        if (not isinstance(request_digests,(list,tuple)) or len(request_digests)>self.max_receipts
                or any(not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{64}',value)
                       for value in request_digests)):fail('v2-prune-ack-invalid')
        with self._transaction():
            latest=self.connection.execute('SELECT retirement_seq FROM event_v2_meta').fetchone()[0]
            for value in request_digests:
                row=self.connection.execute('SELECT retirement_seq,segment,manifest FROM event_v2_receipts WHERE request_digest=?',(value,)).fetchone()
                if not row:continue  # idempotent ack changes nothing once durable catalog was compacted
                if row[0]==latest:fail('v2-prune-latest-prohibited')
                if any(Path(path).exists() or Path(path).is_symlink() for path in row[1:]):
                    fail('v2-prune-files-not-removed')
                self.connection.execute('DELETE FROM event_v2_receipts WHERE request_digest=?',(value,))
            return {'acked':True,'retiredWatermarksUnchanged':True}
