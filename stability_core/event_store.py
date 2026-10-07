"""Isolated bounded SQLite event candidate; no daemon/JSONL integration.

Retention limits the idempotency horizon: identities evicted by TTL/count are
no longer remembered. Caller owns transaction commit and consistent backup.
"""
import hashlib
import json
import math
import sqlite3


def _bounded_json_size(value, max_bytes, *, depth_limit=64):
    """Preflight JSON shape and UTF-8 size without materializing large payloads."""
    active = set()

    def checked(size):
        if size > max_bytes:
            raise ValueError('payload-budget-exceeded')
        return size

    def string_size(value, budget=None):
        # Every code point needs at least one UTF-8 byte. This cheap check also
        # avoids encoding an arbitrarily large string just to reject it.
        limit = max_bytes if budget is None else budget
        if len(value) > limit:
            raise ValueError('payload-budget-exceeded')
        size = 2  # surrounding quotes
        if size > limit:
            raise ValueError('payload-budget-exceeded')
        for char in value:
            codepoint = ord(char)
            if char in ('"', '\\'):
                size += 2
            elif char in ('\b', '\f', '\n', '\r', '\t'):
                size += 2
            elif codepoint < 0x20:
                size += 6  # canonical JSON \u00xx escape
            elif codepoint < 0x80:
                size += 1
            elif codepoint < 0x800:
                size += 2
            elif 0xD800 <= codepoint <= 0xDFFF:
                raise ValueError('invalid-event-string')
            elif codepoint < 0x10000:
                size += 3
            else:
                size += 4
            if size > limit:
                raise ValueError('payload-budget-exceeded')
        return size

    def visit(item, depth):
        if depth > depth_limit:
            raise ValueError('event-depth-exceeded')
        if item is None:
            return 4
        if type(item) is bool:
            return 4 if item else 5
        if type(item) is str:
            return string_size(item)
        if type(item) is int:
            # Reject integers whose decimal representation cannot fit before
            # asking Python to materialize that representation.
            decimal_bound = max(1, (item.bit_length() * 30103 + 99999) // 100000)
            if item < 0:
                decimal_bound += 1
            if decimal_bound > max_bytes:
                raise ValueError('payload-budget-exceeded')
            try:
                return checked(len(str(item)))
            except ValueError as exc:
                raise ValueError('invalid-event-number') from exc
        if type(item) is float:
            if not math.isfinite(item):
                raise ValueError('invalid-event-number')
            return checked(len(json.dumps(item, separators=(',', ':'), allow_nan=False)))
        if type(item) not in (dict, list, tuple):
            raise ValueError('invalid-event-value')

        marker = id(item)
        if marker in active:
            raise ValueError('circular-event')
        active.add(marker)
        try:
            if type(item) is dict:
                # A JSON object member needs at least four bytes: quoted key,
                # colon, and a one-byte value. Bound before sorting keys.
                if len(item) > max_bytes // 4:
                    raise ValueError('payload-budget-exceeded')
                keys = list(item.keys())
                if any(type(key) is not str for key in keys):
                    raise ValueError('invalid-event-key')
                # Validate aggregate key size before sorting. Sorting many
                # long common-prefix keys can otherwise consume substantial
                # CPU before the total payload budget is known to be exceeded.
                key_budget = 2 + len(keys) * 4 + max(0, len(keys) - 1)
                if key_budget > max_bytes:
                    raise ValueError('payload-budget-exceeded')
                for key in keys:
                    key_size = string_size(key, max_bytes - key_budget + 2)
                    key_budget += key_size - 2
                    if key_budget > max_bytes:
                        raise ValueError('payload-budget-exceeded')
                keys.sort()
                size = 2  # braces
                for index, key in enumerate(keys):
                    size += string_size(key) + 1  # key and colon
                    size = checked(size)
                    size += visit(item[key], depth + 1)
                    if index + 1 < len(keys):
                        size += 1  # comma
                    size = checked(size)
                return size

            # Array members need at least one byte plus a separator (except
            # the final member), so cap the element count before iteration.
            if len(item) > max_bytes // 2:
                raise ValueError('payload-budget-exceeded')
            size = 2  # brackets
            for index, child in enumerate(item):
                size += visit(child, depth + 1)
                if index + 1 < len(item):
                    size += 1
                size = checked(size)
            return size
        finally:
            active.remove(marker)

    return visit(value, 0)


def _time(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError('invalid-time')
    return float(value)


def ingest_event(
    conn, event, *, event_id, now_epoch, max_forward_skew_seconds,
    ttl_seconds=86400, max_records=1000, max_payload_bytes=4096,
):
    now = _time(now_epoch)
    if (type(ttl_seconds) is not int or ttl_seconds < 2
            or type(max_forward_skew_seconds) is not int
            or not 1 <= max_forward_skew_seconds < ttl_seconds
            or type(max_records) is not int or not 1 <= max_records <= 10000):
        raise ValueError('invalid-retention-budget')
    if type(max_payload_bytes) is not int or not 1 <= max_payload_bytes <= 65536:
        raise ValueError('invalid-payload-budget')
    if not isinstance(event_id, str) or not 1 <= len(event_id) <= 128:
        raise ValueError('invalid-event-identity')
    if not isinstance(event, dict):
        raise ValueError('invalid-event')
    _time(event.get('tsEpoch'))
    _bounded_json_size(event, max_payload_bytes)
    payload = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    payload_bytes = payload.encode('utf-8')
    if len(payload_bytes) > max_payload_bytes:
        raise ValueError('payload-budget-exceeded')
    digest = hashlib.sha256(payload_bytes).hexdigest()
    conn.execute('SAVEPOINT bounded_event')
    try:
        conn.execute('CREATE TABLE IF NOT EXISTS stability_event_candidate (event_id TEXT PRIMARY KEY, digest TEXT NOT NULL, received_at REAL NOT NULL, payload TEXT NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS stability_event_candidate_clock (id INTEGER PRIMARY KEY CHECK(id=1), high_water REAL NOT NULL)')
        prior = conn.execute('SELECT high_water FROM stability_event_candidate_clock WHERE id=1').fetchone()
        prior_high_water = None
        if prior:
            try:
                prior_high_water = _time(prior[0])
            except ValueError:
                raise ValueError('invalid-stored-high-water') from None
            if now - prior_high_water > max_forward_skew_seconds:
                raise ValueError('ingest-clock-forward-jump')
        clock = max(now, prior_high_water if prior_high_water is not None else now)
        backwards = bool(prior_high_water is not None and now < prior_high_water)
        conn.execute('DELETE FROM stability_event_candidate WHERE received_at < ?', (clock-ttl_seconds,))
        existing = conn.execute('SELECT digest FROM stability_event_candidate WHERE event_id=?', (event_id,)).fetchone()
        if existing:
            if existing[0] != digest:
                raise ValueError('event-identity-conflict')
            state = 'duplicate'
        else:
            if backwards:
                raise ValueError('ingest-clock-regressed')
            conn.execute('INSERT INTO stability_event_candidate VALUES(?,?,?,?)', (event_id,digest,now,payload))
            state = 'stored'
        conn.execute('INSERT INTO stability_event_candidate_clock VALUES(1,?) ON CONFLICT(id) DO UPDATE SET high_water=excluded.high_water',(clock,))
        conn.execute('DELETE FROM stability_event_candidate WHERE event_id NOT IN (SELECT event_id FROM stability_event_candidate ORDER BY received_at DESC,event_id DESC LIMIT ?)',(max_records,))
        conn.execute('RELEASE SAVEPOINT bounded_event')
    except Exception:
        conn.execute('ROLLBACK TO SAVEPOINT bounded_event')
        conn.execute('RELEASE SAVEPOINT bounded_event')
        raise
    return {'state':state, 'clockRegressed':backwards, 'actionReplay':False,
            'idempotencyHorizon':{'ttlSeconds':ttl_seconds,'maxRecords':max_records,
                                  'maxForwardSkewSeconds':max_forward_skew_seconds}}


def read_events(conn, *, limit=50):
    """Read-only legacy-shaped event list; absent store produces empty list."""
    if type(limit) is not int or not 1 <= limit <= 10000:
        raise ValueError('invalid-limit')
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='stability_event_candidate'").fetchone():
        return []
    return [json.loads(row[0]) for row in conn.execute('SELECT payload FROM stability_event_candidate ORDER BY received_at DESC,event_id DESC LIMIT ?',(limit,))]
