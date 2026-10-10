"""Bounded offline packages; never migrates or activates a running daemon.

Historical observations remain in a complete SQLite snapshot and byte-exact
JSONL. The new store contains copied control state and accepts only new events.
No API in this module confers actuator authority or edits the source.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time
import tempfile
import re
from urllib.parse import quote

from .event_pipeline_v2 import EventPipelineV2
from .event_outbox import EventOutbox
from .action_ledger import ActionLedger
from .event_v2_contract import canonical, ArchiveRequest, archive_manifest
from .action_ledger import _EXPECTED_COLUMNS, LEDGER_SCHEMA_VERSION

MAX_BYTES = 64 * 1024 * 1024
MAX_ROWS = 100000
MAX_SECONDS = 15


class MigrationError(ValueError):
    pass


def _fail(code):
    raise MigrationError(code)


def _path(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            if stat.S_ISLNK(os.lstat(part).st_mode):
                _fail('migration-symlink')
    return path


def _identity(path):
    info = os.lstat(_path(path))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        _fail('migration-file-identity')
    if info.st_size > MAX_BYTES:
        _fail('migration-byte-budget')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read(path):
    before = _identity(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) != before[:2]:
            _fail('migration-path-drift')
        chunks = []
        count = 0
        while True:
            block = os.read(descriptor, min(65536, MAX_BYTES + 1 - count))
            if not block:
                break
            count += len(block)
            if count > MAX_BYTES:
                _fail('migration-byte-budget')
            chunks.append(block)
        if _identity(path) != before:
            _fail('migration-source-changing')
        return b''.join(chunks), before
    finally:
        os.close(descriptor)


def _write(path, content):
    descriptor = os.open(_path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        raise


def _json(path, value):
    _write(path, json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n')


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _source_evidence(source):
    values = {}
    for suffix in ('', '-wal'):
        path = Path(str(source) + suffix)
        if path.exists() or path.is_symlink():
            raw, identity = _read(path)
            values[suffix] = (identity, _digest(raw))
    return values


def _check_watch(watch):
    connection, source, version, evidence = watch
    # No read transaction is kept open; data_version sees later WAL commits.
    if connection.in_transaction:
        _fail('migration-watch-transaction')
    if connection.execute('PRAGMA data_version').fetchone()[0] != version:
        _fail('migration-source-changing')
    if _source_evidence(source) != evidence:
        _fail('migration-source-changing')


def _snapshot(source, target, deadline, *, watch_source=False):
    before = _identity(source)
    for suffix in ('-wal', '-shm'):
        companion = Path(str(source) + suffix)
        if companion.exists() or companion.is_symlink():
            _identity(companion)
    connection = None
    output = None
    transferred = False
    try:
        connection = sqlite3.connect('file:' + quote(str(source)) + '?mode=ro', uri=True, timeout=0.25)
        connection.execute('PRAGMA query_only=ON')
        watch = None
        if watch_source:
            watch = (connection, source, connection.execute('PRAGMA data_version').fetchone()[0],
                     _source_evidence(source))
        _write(target, b'')
        output_identity = _identity(target)[:2]
        output = sqlite3.connect(target, timeout=0.25)
        output.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        os.chmod(target, 0o600)
        def progress(status, remaining, total):
            if time.monotonic() > deadline or total * 4096 > MAX_BYTES:
                _fail('migration-snapshot-budget')
        connection.backup(output, pages=128, progress=progress, sleep=0.01)
        if _identity(source)[:2] != before[:2]:
            _fail('migration-path-drift')
        if output.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            _fail('migration-snapshot-corrupt')
        output.close()
        output = None
        if _identity(target)[:2] != output_identity:
            _fail('migration-path-drift')
        if watch is not None:
            _check_watch(watch)
        transferred = watch is not None
        return watch
    finally:
        if output is not None:
            output.close()
        if connection is not None and not transferred:
            connection.close()


def _rows(connection, table, deadline):
    # Table names originate in SQLite metadata, never interpolated unquoted.
    name = '"' + table.replace('"', '""') + '"'
    rows = connection.execute('SELECT * FROM ' + name).fetchmany(MAX_ROWS + 1)
    if len(rows) > MAX_ROWS or time.monotonic() > deadline:
        _fail('migration-row-budget')
    return rows


def _history_check(connection, tables, raw, deadline, jsonl_path, jsonl_identity):
    if 'event_v2_meta' in tables:
        _fail('migration-already-v2')
    if 'stability_event_outbox_version' not in tables:
        if any(name.startswith('stability_event_outbox') for name in tables):
            _fail('migration-v1-marker-missing')
        return 'legacy'
    if connection.execute('SELECT version FROM stability_event_outbox_version').fetchall() != [(1,)]:
        _fail('migration-source-version')
    if 'stability_event_outbox' not in tables:
        _fail('migration-v1-incomplete')
    expected = {'seq','event_id','producer','generation','attempt','producer_seq',
                'payload_digest','line','state','legacy_id','target','dev','inode',
                'offset','line_digest','reason'}
    if {row[1] for row in connection.execute('PRAGMA table_info(stability_event_outbox)')} != expected:
        _fail('migration-v1-schema')
    connection.row_factory = sqlite3.Row
    try:
        records = _rows(connection, 'stability_event_outbox', deadline)
        for row in records:
            if row['state'] != 'exported':
                _fail('migration-unreconciled-v1')
            if (row['target'] != str(jsonl_path) or (row['dev'], row['inode']) != jsonl_identity[:2]):
                _fail('migration-v1-target-proof')
            line = bytes(row['line'])
            offset = row['offset']
            if (type(offset) is not int or offset < 0 or offset + len(line) > len(raw)
                    or _digest(line) != row['line_digest'] or raw[offset:offset + len(line)] != line):
                _fail('migration-v1-export-proof')
    finally:
        connection.row_factory = None
    return 'v1-exported-reconciled'


def _trusted_schema(destination):
    # SQL is issued only by trusted local code into a fresh disposable store.
    with tempfile.TemporaryDirectory(dir=destination) as folder:
        path = Path(folder) / 'template.sqlite'
        connection = sqlite3.connect(path)
        connection.execute('CREATE TABLE kv(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL)')
        connection.execute('CREATE TABLE actions(id INTEGER PRIMARY KEY AUTOINCREMENT,ts_epoch INTEGER NOT NULL,action_id TEXT,action TEXT,result TEXT,payload TEXT NOT NULL)')
        connection.commit()
        connection.close()
        ledger = ActionLedger(path)
        ledger.close()
        outbox = EventOutbox(path)
        outbox.close()
        connection = sqlite3.connect(path)
        try:
            return {(kind, name): sql for kind, name, sql in connection.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL")}
        finally:
            connection.close()


def _normalized_sql(sql):
    # Normalize syntax outside quoted tokens only. Literal bytes are semantic:
    # CHECK(state IN ('planned')) is different from ('PLANNED') or (' planned').
    tokens = []
    cursor = 0
    while cursor < len(sql):
        char = sql[cursor]
        if char in ("'", '"', '`', '['):
            closing = ']' if char == '[' else char
            start = cursor
            cursor += 1
            while cursor < len(sql):
                if sql[cursor] == closing:
                    if cursor + 1 < len(sql) and sql[cursor + 1] == closing:
                        cursor += 2
                        continue
                    cursor += 1
                    break
                cursor += 1
            else:
                _fail('migration-sql-quote')
            tokens.append(sql[start:cursor])
        elif char.isspace():
            cursor += 1
        elif char.isalpha() or char == '_':
            start = cursor
            while cursor < len(sql) and (sql[cursor].isalnum() or sql[cursor] == '_'):
                cursor += 1
            tokens.append(sql[start:cursor].lower())
        else:
            tokens.append(char)
            cursor += 1
    # SQLite metadata normally omits this creation-time clause. Only keyword
    # tokens may be discarded, never content inside a quoted string.
    for prefix in (['create', 'table'], ['create', 'index'], ['create', 'unique', 'index']):
        offset = len(prefix)
        if tokens[:offset] == prefix and tokens[offset:offset + 3] == ['if', 'not', 'exists']:
            tokens = tokens[:offset] + tokens[offset + 3:]
            break
    return tuple(tokens)


def _validate_schema(source, destination):
    trusted = _trusted_schema(destination)
    metadata = source.execute("SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
    if len(metadata) > 32:
        _fail('migration-schema-budget')
    for kind, name, sql in metadata:
        reference = trusted.get((kind, name))
        if reference is None or _normalized_sql(sql) != _normalized_sql(reference):
            _fail('migration-unsupported-schema')


def build_offline_package(source_db, source_jsonl, destination, *, stage_hook=None):
    """Create a fresh, non-activatable package. Failures retain partial evidence.

    The caller must separately freeze the real writer before any future live
    transition. A consistent SQLite snapshot does not prove that writer frozen.
    """
    source_db, source_jsonl, destination = map(_path, (source_db, source_jsonl, destination))
    if destination.exists() or destination in source_db.parents or destination in source_jsonl.parents:
        _fail('migration-destination-not-fresh')
    os.mkdir(destination, 0o700)
    deadline = time.monotonic() + MAX_SECONDS
    stages = []
    manifest = {'version': 1, 'status': 'partial', 'activationAllowed': False,
                'writerFreezeEstablished': False, 'stages': stages,
                'rollbackMode': 'observe-only-actuator-off-event-write-off'}
    def stage(name):
        stages.append(name)
        if stage_hook is not None:
            stage_hook(name)
        if time.monotonic() > deadline:
            _fail('migration-time-budget')
    watch = None
    try:
        raw, jsonl_identity = _read(source_jsonl)
        _write(destination / 'history.jsonl', raw)
        watch = _snapshot(source_db, destination / 'history.sqlite', deadline, watch_source=True)
        stage('immutable-history-snapshot')
        source = sqlite3.connect('file:' + quote(str(destination / 'history.sqlite')) + '?mode=ro', uri=True)
        candidate = None
        try:
            source.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            if source.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view') LIMIT 1").fetchone():
                _fail('migration-unsupported-trigger-view')
            metadata = source.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
            tables = {name for name, _ in metadata}
            allowed = {'kv', 'events', 'actions', 'action_ledger', 'stability_schema_versions',
                       'sqlite_sequence', 'stability_event_outbox_version',
                       'stability_event_outbox', 'stability_event_outbox_target'}
            if tables - allowed:
                _fail('migration-unknown-schema')
            if len(metadata) > 20:
                _fail('migration-schema-budget')
            if 'action_ledger' in tables:
                columns = {row[1] for row in source.execute('PRAGMA table_info(action_ledger)')}
                if columns != _EXPECTED_COLUMNS or 'stability_schema_versions' not in tables:
                    _fail('migration-ledger-schema')
                if source.execute("SELECT version FROM stability_schema_versions WHERE component='action_ledger'").fetchall() != [(LEDGER_SCHEMA_VERSION,)]:
                    _fail('migration-ledger-version')
            _validate_schema(source, destination)
            mode = _history_check(source, tables, raw, deadline, source_jsonl, jsonl_identity)
            # Ensure the old CLI tail remains byte-equivalent, preserving order.
            lines = raw.splitlines(keepends=True)
            if len(lines) > MAX_ROWS or any(len(line) > 1048576 for line in lines):
                _fail('migration-jsonl-budget')
            if raw and not raw.endswith(b'\n'):
                _fail('migration-jsonl-newline')
            if any(len(line) > 65536 for line in lines[-50:]) or sum(map(len, lines[-50:])) > 8388608:
                _fail('migration-tail-budget')
            for line in lines:
                if time.monotonic() > deadline:
                    _fail('migration-time-budget')
                if not isinstance(json.loads(line), dict):
                    _fail('migration-jsonl-object')
            stage('historical-delivery-reconciled')
            path = destination / 'candidate.sqlite'
            candidate = sqlite3.connect(path)
            os.chmod(path, 0o600)
            candidate.execute('PRAGMA journal_mode=WAL')
            candidate.execute('PRAGMA synchronous=FULL')
            candidate.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
            preserved = []
            for name, ddl in metadata:
                if (name == 'events' or name.startswith('stability_event_outbox')
                        or name.startswith('stability_retention_') or name.startswith('sqlite_')):
                    continue
                rows = _rows(source, name, deadline)
                candidate.execute(ddl)
                if rows:
                    quoted = '"' + name.replace('"', '""') + '"'
                    candidate.executemany('INSERT INTO ' + quoted + ' VALUES(' + ','.join('?' for _ in rows[0]) + ')', rows)
                if _rows(candidate, name, deadline) != rows:
                    _fail('migration-control-state-drift')
                preserved.append(name)
            for owner, ddl in source.execute("SELECT tbl_name,sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"):
                if owner in preserved:
                    candidate.execute(ddl)
            # Preserve AUTOINCREMENT allocation even when old maximum was deleted.
            if 'sqlite_sequence' in tables:
                for name, seq in source.execute('SELECT name,seq FROM sqlite_sequence'):
                    if name in preserved:
                        candidate.execute('DELETE FROM sqlite_sequence WHERE name=?', (name,))
                        candidate.execute('INSERT INTO sqlite_sequence VALUES(?,?)', (name, seq))
            candidate.commit()
            stage('control-state-continuity')
            _write(destination / 'events.jsonl', b''.join(lines[-50:]))
            info = os.stat(path)
            pipeline = EventPipelineV2(candidate, path, (info.st_dev, info.st_ino),
                                       destination / 'events.jsonl', destination / 'archive', initialize=True)
            try:
                pipeline.stream.latest()  # Real read-only CLI tail compatibility check.
                witness = pipeline.core.retention_state()
            finally:
                pipeline.close()
            candidate.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            stage('new-store-witness-bound')
            if _read(source_jsonl)[0] != raw or _identity(source_jsonl) != jsonl_identity:
                _fail('migration-source-changing')
            manifest.update(status='offline-qualified', sourceMode=mode,
                            historicalReplay=False, preservedTables=sorted(preserved),
                            sourceSnapshotSha256=_digest(_read(destination / 'history.sqlite')[0]),
                            historyJsonlSha256=_digest(raw), latest50Sha256=_digest(b''.join(lines[-50:])),
                            candidateSha256=_digest(_read(path)[0]),
                            eventStore=witness)
        finally:
            source.close()
            if candidate is not None:
                candidate.close()
        stage('package-complete')
        _check_watch(watch)
        os.chmod(destination / 'history.sqlite', 0o400)
        os.chmod(destination / 'history.jsonl', 0o400)
    except BaseException as exc:
        manifest['status'] = 'partial'
        manifest['failureClass'] = type(exc).__name__
        _json(destination / 'manifest.json', manifest)
        raise
    finally:
        if watch is not None:
            watch[0].close()
    _json(destination / 'manifest.json', manifest)
    directory = os.open(destination, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return manifest


def _copy_archive(source, destination, deadline):
    source = _path(source)
    before = os.lstat(source)
    if not stat.S_ISDIR(before.st_mode):
        _fail('migration-archive-root')
    os.mkdir(destination, 0o700)
    entries = list(source.iterdir())
    if len(entries) > 128:
        _fail('migration-archive-file-budget')
    digests = {}
    identities = {}
    total = 0
    for path in sorted(entries):
        if time.monotonic() > deadline:
            _fail('migration-time-budget')
        raw, identity = _read(path)  # Flat publisher files only; directories/symlinks refused.
        total += len(raw)
        if total > MAX_BYTES:
            _fail('migration-archive-byte-budget')
        _write(destination / path.name, raw)
        digests[path.name] = _digest(raw)
        identities[path.name] = identity
    if {path.name for path in source.iterdir()} != set(digests):
        _fail('migration-source-changing')
    for path in sorted(source.iterdir()):
        raw, identity = _read(path)
        if identity != identities[path.name] or _digest(raw) != digests[path.name]:
            _fail('migration-source-changing')
    after = os.lstat(source)
    if (before.st_dev, before.st_ino, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_mtime_ns):
        _fail('migration-source-changing')
    return digests


def _verify_archive(snapshot, source_root, copied_root):
    meta = snapshot.execute('SELECT store_id,retirement_seq,chain FROM event_v2_meta').fetchall()
    if len(meta) != 1:
        _fail('migration-increment-store-binding')
    frontiers = dict(snapshot.execute('SELECT producer,retired FROM event_v2_producers WHERE retired>0'))
    state = {'version': 2, 'storeId': meta[0][0], 'retirementSeq': meta[0][1],
             'chain': meta[0][2], 'frontiers': frontiers}
    witness = json.loads(_read(copied_root / 'witness.json')[0])
    if canonical(witness) != canonical(state):
        _fail('migration-increment-witness-conflict')
    if any('intent' in path.name for path in copied_root.iterdir()):
        _fail('migration-increment-unfinished-marker')
    rows = snapshot.execute('SELECT retirement_seq,producer,through_ordinal,request_digest,chain,content_digest,segment,manifest FROM event_v2_receipts ORDER BY retirement_seq').fetchmany(129)
    if len(rows) > 128 or (meta[0][1] > 0 and (not rows or rows[-1][0] != meta[0][1] or rows[-1][4] != meta[0][2])):
        _fail('migration-increment-catalog-conflict')
    for seq, producer, through, request_digest, chain, content_digest, segment, manifest_path in rows:
        name = 'segment-' + request_digest + '.json'
        if Path(segment) != source_root / name or Path(manifest_path) != source_root / (name + '.manifest'):
            _fail('migration-increment-archive-path')
        content = _read(copied_root / name)[0]
        raw = _read(copied_root / (name + '.manifest'))[0]
        record = json.loads(raw)
        if (record.get('store_id') != meta[0][0] or record.get('retirement_seq') != seq
                or record.get('producer') != producer or record.get('through_ordinal') != through
                or record.get('request_digest') != request_digest or record.get('chain') != chain
                or record.get('content_digest') != content_digest or _digest(content) != content_digest):
            _fail('migration-increment-archive-conflict')
        request = ArchiveRequest(meta[0][0], producer, record['prior_frontier'], through,
                                 record['prior_chain'], record['prior_retirement_seq'],
                                 tuple(sorted(record['frontiers'].items())), content, content_digest,
                                 request_digest, record['records'])
        computed = _digest(canonical([request.store_id, producer, request.prior_frontier, through,
                                     request.prior_chain, request.prior_retirement_seq,
                                     dict(request.frontiers), content_digest]))
        if computed != request_digest or raw != archive_manifest(request, copied_root / name):
            _fail('migration-increment-manifest-conflict')
        if request.chain != chain or request.retirement_seq != seq:
            _fail('migration-increment-catalog-conflict')
    return state


def preserve_rollback(package, increment_db, increment_jsonl, destination):
    """Retain increments and old snapshot separately; never merge old actions.

    This is an observation recovery package, not a runnable service or approval.
    Current actions are preserved for mandatory reconciliation instead of being
    overwritten by an older ledger. No old binary can be trusted to honor v2.
    """
    package, destination = _path(package), _path(destination)
    manifest = json.loads(_read(package / 'manifest.json')[0])
    if manifest.get('status') != 'offline-qualified':
        _fail('migration-package-incomplete')
    history = _read(package / 'history.sqlite')[0]
    historical_jsonl = _read(package / 'history.jsonl')[0]
    if _digest(historical_jsonl) != manifest['historyJsonlSha256']:
        _fail('migration-history-drift')
    if _digest(history) != manifest['sourceSnapshotSha256']:
        _fail('migration-history-drift')
    if destination.exists():
        _fail('migration-destination-not-fresh')
    os.mkdir(destination, 0o700)
    result = {'status': 'partial', 'activationAllowed': False,
              'requiresActionReconciliation': True,
              'requiredExternalControls': ['writer-stopped', 'observe-only', 'actuator-off', 'event-write-off'],
              'oldBinaryMarkerEnforcement': 'not-guaranteed'}
    watch = None
    deadline = time.monotonic() + MAX_SECONDS
    try:
        _write(destination / 'old-observation.sqlite', history)
        _write(destination / 'old-observation.jsonl', historical_jsonl)
        _json(destination / 'migration-source-manifest.json', manifest)
        result['oldSnapshotSha256'] = _digest(history)
        result['oldHistoryJsonlSha256'] = _digest(historical_jsonl)
        result['sourceManifestSha256'] = _digest(_read(destination / 'migration-source-manifest.json')[0])
        increment_db = _path(increment_db)
        watch = _snapshot(increment_db, destination / 'increments.sqlite', deadline, watch_source=True)
        snapshot = sqlite3.connect('file:' + quote(str(destination / 'increments.sqlite')) + '?mode=ro', uri=True)
        try:
            if snapshot.execute("SELECT 1 FROM sqlite_master WHERE name='event_v2_meta'").fetchone():
                store = snapshot.execute('SELECT store_id,witness_path FROM event_v2_meta').fetchall()
                expected_root = increment_db.parent / 'archive'
                if (len(store) != 1 or store[0][0] != manifest['eventStore']['storeId']
                        or Path(store[0][1]) != expected_root / 'witness.json'):
                    _fail('migration-increment-store-binding')
                result['archiveFileSha256'] = _copy_archive(expected_root, destination / 'increment-archive', deadline)
                result['incrementStoreId'] = store[0][0]
                result['incrementRetentionState'] = _verify_archive(snapshot, expected_root, destination / 'increment-archive')
        finally:
            snapshot.close()
        raw, jsonl_identity = _read(_path(increment_jsonl))
        _write(destination / 'increments.jsonl', raw)
        result['incrementSnapshotSha256'] = _digest(_read(destination / 'increments.sqlite')[0])
        result['incrementJsonlSha256'] = _digest(raw)
        _check_watch(watch)
        if 'archiveFileSha256' in result:
            if {path.name for path in expected_root.iterdir()} != set(result['archiveFileSha256']):
                _fail('migration-source-changing')
            for name, expected_digest in result['archiveFileSha256'].items():
                if time.monotonic() > deadline or _digest(_read(expected_root / name)[0]) != expected_digest:
                    _fail('migration-source-changing')
        if _identity(_path(increment_jsonl)) != jsonl_identity:
            _fail('migration-source-changing')
        result['status'] = 'observation-recovery-prepared'
    finally:
        if watch is not None:
            watch[0].close()
        _json(destination / 'rollback.json', result)
    return result
