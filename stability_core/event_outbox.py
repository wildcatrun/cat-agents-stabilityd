"""Local durable event export candidate; no daemon integration or background work.

Legacy payloads are unchanged. No retention runs here: budgets backpressure,
including exported identities, rather than silently shrinking dedup coverage.
Borrowed connections require trusted file identity from their controlled opener.
External database restore must stop writers; log rotation must cooperate with
the export lock. Path fences are not an atomic SQLite/filesystem transaction.
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
from pathlib import Path


class EventOutboxError(RuntimeError):
    """Fixed public failure code; never transport private OS/SQL exception text."""


def _fail(code):
    raise EventOutboxError(code) from None


def _identity(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,128}', value) is not None


class EventOutbox:
    def __init__(self, path, *, connection=None, connection_identity=None,
                 max_records=4096, max_payload_bytes=65536, max_total_bytes=8388608):
        if not all(type(v) is int and v > 0 for v in (max_records, max_payload_bytes, max_total_bytes)):
            _fail('invalid-budget')
        if max_records > 100000 or max_payload_bytes > 65536 or max_total_bytes > 67108864:
            _fail('invalid-budget')
        self.path = Path(path)
        self.max_records, self.max_payload_bytes, self.max_total_bytes = max_records, max_payload_bytes, max_total_bytes
        self.connection = None
        self._owns_connection = connection is None
        try:
            if str(path) == ':memory:' or self.path.is_symlink():
                _fail('durable-path-required')
            if connection is not None:
                if not isinstance(connection,sqlite3.Connection):
                    _fail('invalid-borrowed-connection')
                self.connection = connection
                if connection.in_transaction:
                    _fail('caller-transaction-active')
                if (not isinstance(connection_identity,tuple) or len(connection_identity)!=2
                        or any(type(value) is not int or value < 0 for value in connection_identity)):
                    _fail('borrowed-identity-required')
                self._file_identity = connection_identity
                self._check_identity()
                main = next((row[2] for row in connection.execute('PRAGMA database_list')
                             if row[1] == 'main'), '')
                if not main or not Path(main).is_file() or Path(main).resolve() != self.path.resolve():
                    _fail('borrowed-path-mismatch')
                if connection.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'wal':
                    _fail('borrowed-wal-required')
                if connection.execute('PRAGMA synchronous').fetchone()[0] != 2:
                    _fail('borrowed-full-required')
            else:
                before = os.lstat(self.path) if self.path.exists() else None
                self.connection = sqlite3.connect(str(path), isolation_level=None, timeout=5)
                after = os.lstat(self.path)
                self._file_identity = (after.st_dev,after.st_ino)
                if before is not None and (before.st_dev,before.st_ino) != self._file_identity:
                    _fail('store-identity-changed')
                self._check_identity()
                if self.connection.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower() != 'wal':
                    _fail('wal-required')
                self.connection.execute('PRAGMA synchronous=FULL')
            with self._transaction():
                owned_tables = {'stability_event_outbox_version', 'stability_event_outbox',
                                'stability_event_outbox_target'}
                present_tables = {row[0] for row in self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")} & owned_tables
                if present_tables and present_tables != owned_tables:
                    _fail('outbox-schema-incomplete')
                self.connection.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts_epoch INTEGER NOT NULL, source TEXT, component TEXT, severity TEXT, key TEXT, payload TEXT NOT NULL)')
                columns = [(row[1],row[2].upper(),row[3],row[4],row[5])
                           for row in self.connection.execute('PRAGMA table_info(events)')]
                expected_legacy = [('id','INTEGER',0,None,1), ('ts_epoch','INTEGER',1,None,0),
                                   ('source','TEXT',0,None,0), ('component','TEXT',0,None,0),
                                   ('severity','TEXT',0,None,0), ('key','TEXT',0,None,0),
                                   ('payload','TEXT',1,None,0)]
                if columns != expected_legacy:
                    _fail('legacy-schema-invalid')
                self.connection.execute('CREATE TABLE IF NOT EXISTS stability_event_outbox_version (version INTEGER NOT NULL)')
                versions = [tuple(row) for row in self.connection.execute('SELECT version FROM stability_event_outbox_version')]
                if not versions and not present_tables:
                    self.connection.execute('INSERT INTO stability_event_outbox_version VALUES(1)')
                elif versions != [(1,)]:
                    _fail('outbox-schema-invalid')
                outbox_sql = """CREATE TABLE IF NOT EXISTS stability_event_outbox (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
                    producer TEXT NOT NULL, generation TEXT NOT NULL, attempt INTEGER NOT NULL,
                    producer_seq INTEGER NOT NULL, payload_digest TEXT NOT NULL, line BLOB NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','exporting','exported','unknown')),
                    legacy_id INTEGER NOT NULL, target TEXT, dev INTEGER, inode INTEGER, offset INTEGER,
                    line_digest TEXT NOT NULL, reason TEXT,
                    UNIQUE(producer,generation,attempt,producer_seq))"""
                self.connection.execute(outbox_sql)
                actual_sql = self.connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='stability_event_outbox'").fetchone()[0]
                normalize = lambda value: re.sub(r"\s+", "", value.replace("IF NOT EXISTS", "")).lower()
                if normalize(actual_sql) != normalize(outbox_sql):
                    _fail('outbox-schema-invalid')
                self.connection.execute('CREATE TABLE IF NOT EXISTS stability_event_outbox_target (id INTEGER PRIMARY KEY CHECK(id=1), path TEXT NOT NULL)')
                expected = {'seq','event_id','producer','generation','attempt','producer_seq','payload_digest','line','state','legacy_id','target','dev','inode','offset','line_digest','reason'}
                if {row[1] for row in self.connection.execute('PRAGMA table_info(stability_event_outbox)')} != expected:
                    _fail('outbox-schema-invalid')
        except EventOutboxError:
            self.close()
            raise
        except Exception:
            self.close()
            _fail('outbox-open-failed')

    def close(self):
        if self.connection is not None:
            if self._owns_connection:
                self.connection.close()
            self.connection = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _check_identity(self):
        try:
            current = os.lstat(self.path)
            if not stat.S_ISREG(current.st_mode) or (current.st_dev,current.st_ino) != self._file_identity:
                _fail('store-identity-changed')
        except OSError:
            _fail('store-identity-changed')

    @contextlib.contextmanager
    def _transaction(self):
        if self.connection.in_transaction:
            _fail('caller-transaction-active')
        self._check_identity()
        self.connection.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.connection.execute('COMMIT')
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                self.connection.execute('ROLLBACK')
            raise

    def record(self, event, *, producer, generation, attempt, seq):
        if (not _identity(producer) or not _identity(generation)
                or type(attempt) is not int or type(seq) is not int or min(attempt,seq) < 0
                or max(attempt,seq) > 2**63-1 or not isinstance(event,dict)):
            _fail('invalid-event-identity')
        if self.connection.in_transaction:
            _fail('caller-transaction-active')
        try:
            # Reject aggregate oversized structures before allocating canonical JSON.
            from .event_store import _bounded_json_size
            _bounded_json_size(event, self.max_payload_bytes)
            if type(event.get('tsEpoch')) is not int or not 0 <= event['tsEpoch'] <= 2**63-1:
                _fail('invalid-event-time')
            canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            line = (json.dumps(event, ensure_ascii=False, sort_keys=False, allow_nan=False)+'\n').encode()
            if len(line) > self.max_payload_bytes:
                _fail('payload-budget-exceeded')
            identity = json.dumps([producer,generation,attempt,seq],separators=(',',':')).encode()
            event_id = hashlib.sha256(identity).hexdigest()
            digest = hashlib.sha256(canonical).hexdigest()
            with self._transaction():
                old = self.connection.execute('SELECT seq,payload_digest,state FROM stability_event_outbox WHERE event_id=?',(event_id,)).fetchone()
                if old:
                    if old[1] != digest:
                        _fail('event-identity-conflict')
                    return {'eventId':event_id,'seq':old[0],'state':old[2],'duplicate':True}
                count,size = self.connection.execute('SELECT COUNT(*),COALESCE(SUM(length(line)),0) FROM stability_event_outbox').fetchone()
                if count >= self.max_records or size + len(line) > self.max_total_bytes:
                    _fail('outbox-budget-exceeded')
                cursor = self.connection.execute('INSERT INTO events(ts_epoch,source,component,severity,key,payload) VALUES(?,?,?,?,?,?)',
                    (event['tsEpoch'],event.get('source'),event.get('component'),event.get('severity'),event.get('key'),line[:-1].decode()))
                cursor = self.connection.execute('INSERT INTO stability_event_outbox(event_id,producer,generation,attempt,producer_seq,payload_digest,line,state,legacy_id,line_digest) VALUES(?,?,?,?,?,?,?,\'pending\',?,?)',
                    (event_id,producer,generation,attempt,seq,digest,line,cursor.lastrowid,hashlib.sha256(line).hexdigest()))
                return {'eventId':event_id,'seq':cursor.lastrowid,'state':'pending','duplicate':False}
        except EventOutboxError:
            raise
        except Exception:
            _fail('event-record-failed')

    def status(self):
        try:
            counts = dict(self.connection.execute('SELECT state,COUNT(*) FROM stability_event_outbox GROUP BY state'))
            return {'states':counts,'complete':not any(counts.get(s,0) for s in ('pending','exporting','unknown')),
                    'coverage':'unknown' if counts.get('unknown') else 'pending' if counts.get('pending') or counts.get('exporting') else 'complete'}
        except Exception:
            _fail('event-status-failed')

    def _state(self, seq, state, reason=None):
        with self._transaction():
            self.connection.execute('UPDATE stability_event_outbox SET state=?,reason=? WHERE seq=?',(state,reason,seq))

    def drain(self, target, *, max_batch=50, max_batch_bytes=1048576, hook=None):
        if (type(max_batch) is not int or not 1 <= max_batch <= 1000
                or type(max_batch_bytes) is not int or not 1 <= max_batch_bytes <= 16777216):
            _fail('invalid-export-budget')
        if self.connection.in_transaction:
            _fail('caller-transaction-active')
        target = Path(target).absolute()
        done, used = 0, 0
        row = None
        try:
            with self._transaction():
                pinned_target = self.connection.execute('SELECT path FROM stability_event_outbox_target WHERE id=1').fetchone()
                if pinned_target and pinned_target[0] != str(target):
                    _fail('export-target-conflict')
                self.connection.execute('INSERT OR IGNORE INTO stability_event_outbox_target VALUES(1,?)',(str(target),))
            flags = os.O_RDWR | os.O_CREAT | getattr(os,'O_NOFOLLOW',0)
            lockfd = os.open(str(target)+'.outbox.lock',flags,0o600)
            with os.fdopen(lockfd,'rb') as lock:
                if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
                    _fail('export-lock-invalid')
                try:
                    fcntl.flock(lock.fileno(),fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return {'exported':0,'bytes':0,'busy':True,**self.status()}
                fd = os.open(target,flags,0o600)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        _fail('export-target-invalid')
                    for _ in range(max_batch):
                        row = self.connection.execute("SELECT seq,state,substr(line,1,?),target,dev,inode,offset,line_digest,length(line) FROM stability_event_outbox WHERE state!='exported' ORDER BY seq LIMIT 1",(self.max_payload_bytes+1,)).fetchone()
                        if row is None or row[1] == 'unknown':
                            break
                        seq,state,line,pinned,dev,inode,offset,digest,line_size = row
                        if (not isinstance(line,bytes) or not 1 <= line_size <= self.max_payload_bytes
                                or len(line) != line_size or not line.endswith(b'\n')
                                or not isinstance(digest,str) or hashlib.sha256(line).hexdigest() != digest):
                            self._state(seq,'unknown','stored-line-invalid');break
                        if used + len(line) > max_batch_bytes:
                            break
                        file_stat = os.fstat(fd)
                        if state == 'pending':
                            with self._transaction():
                                self.connection.execute("UPDATE stability_event_outbox SET state='exporting',target=?,dev=?,inode=?,offset=? WHERE seq=? AND state='pending'",(str(target),file_stat.st_dev,file_stat.st_ino,file_stat.st_size,seq))
                            pinned,dev,inode,offset = str(target),file_stat.st_dev,file_stat.st_ino,file_stat.st_size
                            if hook: hook('intent')
                        if pinned != str(target) or (dev,inode) != (file_stat.st_dev,file_stat.st_ino):
                            self._state(seq,'unknown','target-identity-conflict');break
                        def path_still_matches():
                            try:
                                path_stat = os.lstat(target)
                                return stat.S_ISREG(path_stat.st_mode) and (path_stat.st_dev,path_stat.st_ino) == (dev,inode)
                            except OSError:
                                return False
                        if file_stat.st_size == offset:
                            if hook: hook('before-append')
                            if not path_still_matches():
                                self._state(seq,'unknown','target-path-changed');break
                            if os.pwrite(fd,line,offset) != len(line):
                                self._state(seq,'unknown','partial-write');break
                            if hook: hook('append')
                        elif file_stat.st_size != offset + len(line):
                            self._state(seq,'unknown','offset-conflict');break
                        content = os.pread(fd,len(line),offset)
                        if hashlib.sha256(content).hexdigest() != digest:
                            self._state(seq,'unknown','line-conflict');break
                        os.fsync(fd)
                        # Persist first-file creation as well as its contents.
                        dirfd = os.open(target.parent,os.O_RDONLY)
                        try: os.fsync(dirfd)
                        finally: os.close(dirfd)
                        if hook: hook('fsync')
                        if not path_still_matches():
                            self._state(seq,'unknown','target-path-changed');break
                        if hook: hook('before-receipt')
                        if not path_still_matches():
                            self._state(seq,'unknown','target-path-changed');break
                        self._state(seq,'exported')
                        if hook: hook('receipt')
                        done += 1;used += len(line)
                        row = None
                finally:
                    os.close(fd)
            return {'exported':done,'bytes':used,**self.status()}
        except EventOutboxError:
            raise
        except Exception:
            if row is not None:
                with contextlib.suppress(Exception):self._state(row[0],'unknown','export-failed')
            _fail('event-export-failed')
