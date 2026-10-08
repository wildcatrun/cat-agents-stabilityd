"""Opt-in retention prototype. Not safe to enable until every record uses its gate.

Finite retries require producer + generation UUID + durable ordinal. This addon
never migrates outbox v1 and never removes legacy events. Install is explicit.
"""
import hashlib
import json
import os
import stat
import re
from functools import wraps
from pathlib import Path

from .event_outbox import EventOutboxError, _identity


def fail(code):
    raise EventOutboxError(code) from None


SCHEMA_SQL = {'stability_retention_version': 'CREATE TABLE stability_retention_version(version INTEGER NOT NULL)', 'stability_retention_producers': 'CREATE TABLE stability_retention_producers(producer TEXT PRIMARY KEY, issued INTEGER NOT NULL, retired INTEGER NOT NULL)', 'stability_retention_generations': 'CREATE TABLE stability_retention_generations(producer TEXT NOT NULL, ordinal INTEGER NOT NULL, generation TEXT NOT NULL, sealed INTEGER NOT NULL CHECK(sealed IN (0,1)), PRIMARY KEY(producer,ordinal), UNIQUE(producer,generation))', 'stability_retention_archives': 'CREATE TABLE stability_retention_archives(producer TEXT NOT NULL, first_ordinal INTEGER NOT NULL, last_ordinal INTEGER NOT NULL, segment TEXT NOT NULL, digest TEXT NOT NULL, manifest TEXT NOT NULL, PRIMARY KEY(producer,last_ordinal))'}

def masked(code):
    def decorate(function):
        @wraps(function)
        def call(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except EventOutboxError:
                raise
            except Exception:
                fail(code)
        return call
    return decorate


class EventRetention:
    @masked("retention-open-failed")
    def __init__(self, outbox, archive_root, *, install=False, max_archive_bytes=67108864,
                 max_batch_records=1000, max_batch_bytes=1048576, max_generations=4096,
                 max_archive_files=8192):
        self.box = outbox
        self.db = outbox.connection
        self.root = Path(archive_root).absolute()
        if any(type(v) is not int or v <= 0 for v in
               (max_archive_bytes, max_batch_records, max_batch_bytes, max_generations, max_archive_files)):
            fail('invalid-retention-budget')
        if (max_batch_records > 100000 or max_batch_bytes > 67108864
                or max_generations > 100000 or max_archive_files > 100000):
            fail('invalid-retention-budget')
        self.max_generations = max_generations
        self.max_archive_files = max_archive_files
        self.max_archive_bytes = max_archive_bytes
        self.max_batch_records = max_batch_records
        self.max_batch_bytes = max_batch_bytes
        with self.box._transaction():
            if [tuple(r) for r in self.db.execute('SELECT version FROM stability_event_outbox_version')] != [(1,)]:
                fail('retention-outbox-version-invalid')
            tables = {'stability_retention_version', 'stability_retention_producers',
                      'stability_retention_generations', 'stability_retention_archives'}
            present = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")} & tables
            if present and present != tables:
                fail('retention-schema-incomplete')
            if not present:
                if not install:
                    fail('retention-install-required')
                for statement in SCHEMA_SQL.values():
                    self.db.execute(statement)
                self.db.execute('INSERT INTO stability_retention_version VALUES(1)')
            self._validate_schema()
            if [tuple(r) for r in self.db.execute('SELECT version FROM stability_retention_version')] != [(1,)]:
                fail('retention-schema-invalid')

    def _validate_schema(self):
        # Exact supported DDL protects PK/UNIQUE/CHECK as well as columns/types.
        # PRAGMA checks separately reject extra/hidden or reordered columns.
        normalize = lambda value: re.sub(r"\s+", "", value).lower()
        columns = {
            'stability_retention_version': [('version','INTEGER',1,0)],
            'stability_retention_producers': [('producer','TEXT',0,1),('issued','INTEGER',1,0),('retired','INTEGER',1,0)],
            'stability_retention_generations': [('producer','TEXT',1,1),('ordinal','INTEGER',1,2),('generation','TEXT',1,0),('sealed','INTEGER',1,0)],
            'stability_retention_archives': [('producer','TEXT',1,1),('first_ordinal','INTEGER',1,0),('last_ordinal','INTEGER',1,2),('segment','TEXT',1,0),('digest','TEXT',1,0),('manifest','TEXT',1,0)],
        }
        for table, statement in SCHEMA_SQL.items():
            actual = self.db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if not actual or normalize(actual[0]) != normalize(statement):
                fail('retention-schema-invalid')
            observed = [(row[1],row[2].upper(),row[3],row[5])
                        for row in self.db.execute('PRAGMA table_info(' + table + ')')]
            if observed != columns[table]:
                fail('retention-schema-invalid')
        if [tuple(row) for row in self.db.execute('SELECT version FROM stability_retention_version')] != [(1,)]:
            fail('retention-schema-invalid')

    @masked('retention-generation-failed')
    def register_generation(self, producer, generation):
        """New observations only; retries MUST use require_generation instead."""
        if not _identity(producer) or not _identity(generation):
            fail('invalid-retention-identity')
        with self.box._transaction():
            self._validate_schema()
            if self.db.execute('SELECT COUNT(*) FROM (SELECT 1 FROM stability_retention_generations LIMIT ?)',
                               (self.max_generations,)).fetchone()[0] >= self.max_generations:
                fail('retention-generation-budget')
            if self.db.execute('SELECT 1 FROM stability_event_outbox WHERE producer=? AND generation=?', (producer,generation)).fetchone():
                fail('retention-unregistered-history')
            if self.db.execute('SELECT 1 FROM stability_retention_generations WHERE producer=? AND generation=?', (producer,generation)).fetchone():
                fail('retention-generation-exists')
            self.db.execute('INSERT OR IGNORE INTO stability_retention_producers VALUES(?,0,0)', (producer,))
            ordinal = self.db.execute('SELECT issued FROM stability_retention_producers WHERE producer=?', (producer,)).fetchone()[0] + 1
            if ordinal > 2**63-1:
                fail('retention-ordinal-exhausted')
            self.db.execute('UPDATE stability_retention_producers SET issued=? WHERE producer=?', (ordinal,producer))
            self.db.execute('INSERT INTO stability_retention_generations VALUES(?,?,?,0)', (producer,ordinal,generation))
            return ordinal

    @masked('retention-generation-failed')
    def require_generation(self, producer, generation, ordinal, *, new_record=False):
        self.box._check_identity()
        self._validate_schema()
        if type(ordinal) is not int or ordinal <= 0:
            fail('invalid-retention-ordinal')
        row = self.db.execute('SELECT retired FROM stability_retention_producers WHERE producer=?', (producer,)).fetchone()
        if row and ordinal <= row[0]:
            fail('event-generation-retired')
        row = self.db.execute('SELECT generation,sealed FROM stability_retention_generations WHERE producer=? AND ordinal=?', (producer,ordinal)).fetchone()
        if not row or row[0] != generation:
            fail('event-generation-unregistered')
        if new_record and row[1]:
            fail('event-generation-sealed')
        return {'ordinal':ordinal,'sealed':bool(row[1])}

    @masked('retention-generation-failed')
    def seal_generation(self, producer, generation, ordinal):
        self.require_generation(producer,generation,ordinal)
        with self.box._transaction():
            self._validate_schema()
            self.db.execute('UPDATE stability_retention_generations SET sealed=1 WHERE producer=? AND ordinal=?', (producer,ordinal))

    def _publish(self, path, content):
        """Immutable O_EXCL; interrupted files cannot be adopted or overwritten."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
        try:
            with os.fdopen(fd,'wb',closefd=False) as stream:
                stream.write(content); stream.flush(); os.fsync(fd)
        finally:
            os.close(fd)
        dirfd = os.open(self.root,os.O_RDONLY)
        try: os.fsync(dirfd)
        finally: os.close(dirfd)

    def prepare_archive(self, producer, through_ordinal, *, hook=None):
        try:
            return self._prepare_archive(producer, through_ordinal, hook=hook)
        except EventOutboxError:
            raise
        except Exception:
            fail('retention-archive-failed')

    def _prepare_archive(self, producer, through_ordinal, *, hook=None):
        """Caller serializes record/seal/retire. File success precedes archive receipt; no rows are removed.

        No automatic archive deletion or outbox reclamation. A full archive quota safely backpressures.
        This bounded prototype blocks on orphan archive files after interrupted
        publication; maintenance must verify/remove them with writers stopped.
        This prepares evidence only: a versioned record gate is required for GC.
        """
        if not _identity(producer) or type(through_ordinal) is not int or through_ordinal <= 0:
            fail('invalid-retention-frontier')
        self.box._check_identity()
        if self.db.in_transaction:
            fail('caller-transaction-active')
        # BEGIN owns the writer lock across bounded archive publication. No other
        # connection may register/record between selection and archive receipt.
        with self.box._transaction():
            self._validate_schema()
            p = self.db.execute('SELECT retired,issued FROM stability_retention_producers WHERE producer=?', (producer,)).fetchone()
            if not p or not p[0] < through_ordinal <= p[1]:
                fail('invalid-retention-frontier')
            if through_ordinal-p[0] > self.max_batch_records:
                fail('retention-batch-budget')
            generations = [tuple(r) for r in self.db.execute('SELECT ordinal,substr(generation,1,129),sealed FROM stability_retention_generations WHERE producer=? AND ordinal>? AND ordinal<=? ORDER BY ordinal LIMIT ?', (producer,p[0],through_ordinal,self.max_batch_records+1))]
            if len(generations) != through_ordinal-p[0] or any(g[2] != 1 or not _identity(g[1]) for g in generations):
                fail('retention-generation-not-sealed')
            if len(generations) > self.max_batch_records:
                fail('retention-batch-budget')
            rows=[]; total=0
            for ordinal,generation,_ in generations:
                for row in self.db.execute('SELECT substr(event_id,1,65),substr(payload_digest,1,65),length(line),substr(line,1,?),state,seq,substr(line_digest,1,65),typeof(line),attempt,producer_seq FROM stability_event_outbox WHERE producer=? AND generation=? ORDER BY seq LIMIT ?',
                        (min(self.max_batch_bytes-total,self.box.max_payload_bytes)+1,producer,generation,self.max_batch_records-len(rows)+1)):
                    if row[4] != 'exported':
                        fail('retention-unfinished-events')
                    if (type(row[2]) is not int or row[2] < 1 or row[7] != 'blob'
                            or not isinstance(row[3],bytes)):
                        fail('retention-event-invalid')
                    total += row[2]
                    if (len(rows) >= self.max_batch_records or total > self.max_batch_bytes
                            or row[2] > self.box.max_payload_bytes):
                        fail('retention-batch-budget')
                    line = row[3]
                    if (len(line) != row[2] or not line.endswith(b'\n')
                            or type(row[5]) is not int or row[5] <= 0
                            or any(type(value) is not int or not 0 <= value <= 2**63-1
                                   for value in row[8:10])
                            or any(not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{64}',value)
                                   for value in (row[0],row[1],row[6]))
                            or hashlib.sha256(line).hexdigest() != row[6]):
                        fail('retention-event-invalid')
                    event_id = hashlib.sha256(json.dumps([producer,generation,row[8],row[9]],
                                                         separators=(',',':')).encode()).hexdigest()
                    if event_id != row[0]: fail('retention-event-invalid')
                    payload = json.loads(line)
                    if not isinstance(payload,dict): fail('retention-event-invalid')
                    canonical = json.dumps(payload,ensure_ascii=False,sort_keys=True,
                                           separators=(',',':'),allow_nan=False).encode()
                    if hashlib.sha256(canonical).hexdigest() != row[1]:
                        fail('retention-event-invalid')
                    rows.append({'ordinal':ordinal,'eventId':row[0],'payloadDigest':row[1],
                                 'line':line.decode('utf-8'),'seq':row[5]})
            segment = json.dumps({'version':1,'producer':producer,'first':p[0]+1,'last':through_ordinal,'events':rows},ensure_ascii=False,separators=(',',':')).encode()
            if len(segment) > self.max_batch_bytes:
                fail('retention-batch-budget')
            digest=hashlib.sha256(segment).hexdigest()
            name='segment-'+digest+'.json'
            manifest=json.dumps({'version':1,'segment':name,'digest':digest,'bytes':len(segment),'records':len(rows)},separators=(',',':')).encode()
            if self.root.is_symlink(): fail('retention-archive-invalid')
            self.root.mkdir(mode=0o700,parents=True,exist_ok=True)
            used=0; file_count=0
            for file_count, path in enumerate(self.root.iterdir(), 1):
                if file_count > self.max_archive_files:
                    fail('retention-archive-budget')
                s=os.lstat(path)
                if not stat.S_ISREG(s.st_mode): fail('retention-archive-invalid')
                used += s.st_size
                if used > self.max_archive_bytes: fail('retention-archive-budget')
            if file_count+2 > self.max_archive_files or used+len(segment)+len(manifest)>self.max_archive_bytes:
                fail('retention-archive-budget')
            self._publish(self.root/name,segment)
            if hook: hook('segment')
            self._publish(self.root/(name+'.manifest'),manifest)
            if hook: hook('manifest')
            self.db.execute('INSERT INTO stability_retention_archives VALUES(?,?,?,?,?,?)', (producer,p[0]+1,through_ordinal,name,digest,name+'.manifest'))
            if hook: hook('receipt')
        return {'preparedThrough':through_ordinal,'retired':False,'records':len(rows),'archive':name,'digest':digest}

    def archive_and_retire(self, producer, through_ordinal, *, hook=None):
        # v1 record has no ordinal gate and older binaries ignore addon tables.
        # A future versioned core must refuse old writers before enabling GC.
        fail('retention-integration-required')
