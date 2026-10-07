"""Bounded SQLite persistence for already-governed observation adapter input.

This module has no transport or collection capability. Producers must supply
current registry-derived generations and explicitly authorize source kinds;
the default only stores synthetic fixtures.
"""

from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Iterable, Mapping
from typing import Any

from .observation_reconcile import (
    DEFAULT_MAX_AGE_SECONDS, DEFAULT_MAX_RECORDS, reconcile_observation_batch,
)


STORE_VERSION = 1
DEFAULT_RETENTION_SECONDS = DEFAULT_MAX_AGE_SECONDS
DEFAULT_SOURCE_ALLOWLIST = frozenset({"synthetic-fixture"})
_TABLE = "stability_observation_events"
_VERSION_TABLE = "stability_observation_schema"
_FIELDS = (
    "nodeId", "eventId", "generationDigest", "evidenceDigest", "sourceKind",
    "observedAtEpoch", "receivedAtEpoch", "status",
)


def ensure_observation_store(conn: sqlite3.Connection) -> None:
    """Create version 1 on an empty DB; reject unknown/partial prior schemas."""
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError("conn must be a sqlite3 connection")
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if _TABLE not in tables and _VERSION_TABLE not in tables:
        conn.execute("SAVEPOINT observation_schema")
        try:
            conn.execute(
                f"""CREATE TABLE {_TABLE} (
                event_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                generation_digest TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                observed_at REAL NOT NULL,
                received_at REAL NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('fresh','stale','clock-invalid','clock-skew','out-of-order'))
                )"""
            )
            conn.execute(f"CREATE INDEX {_TABLE}_node_observed ON {_TABLE}(node_id, observed_at)")
            conn.execute(f"CREATE TABLE {_VERSION_TABLE} (component TEXT PRIMARY KEY, version INTEGER NOT NULL)")
            conn.execute(f"INSERT INTO {_VERSION_TABLE}(component,version) VALUES('observation-store',?)", (STORE_VERSION,))
            conn.execute("RELEASE SAVEPOINT observation_schema")
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT observation_schema")
            conn.execute("RELEASE SAVEPOINT observation_schema")
            raise
        return
    if _TABLE not in tables or _VERSION_TABLE not in tables:
        raise ValueError("partial observation store schema; explicit recovery required")
    version = conn.execute(
        f"SELECT version FROM {_VERSION_TABLE} WHERE component='observation-store'"
    ).fetchone()
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({_TABLE})")}
    expected = {"event_id", "node_id", "generation_digest", "evidence_digest", "source_kind",
                "observed_at", "received_at", "status"}
    if not version or version[0] != STORE_VERSION or columns != expected:
        raise ValueError("unsupported observation store schema; explicit migration required")


def _row_to_record(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "eventId": row[0], "nodeId": row[1], "generationDigest": row[2],
        "evidenceDigest": row[3], "sourceKind": row[4], "observedAtEpoch": row[5],
        "receivedAtEpoch": row[6], "status": row[7],
    }


def load_observation_records(conn: sqlite3.Connection, *, limit: int = DEFAULT_MAX_RECORDS) -> list[dict[str, Any]]:
    if type(limit) is not int or not 1 <= limit <= 10_000:
        raise ValueError("limit must be within 1..10000")
    ensure_observation_store(conn)
    rows = conn.execute(
        f"""SELECT event_id,node_id,generation_digest,evidence_digest,source_kind,observed_at,received_at,status
            FROM {_TABLE} ORDER BY observed_at DESC,node_id,event_id LIMIT ?""", (limit,)
    ).fetchall()
    return [_row_to_record(row) for row in rows]


def persist_observation_batch(
    conn: sqlite3.Connection,
    incoming: Iterable[Mapping[str, Any]],
    *,
    now_epoch: float,
    current_generations: Mapping[str, str],
    authorized_source_kinds: frozenset[str] = DEFAULT_SOURCE_ALLOWLIST,
    max_records: int = DEFAULT_MAX_RECORDS,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    retention_seconds: int = DEFAULT_RETENTION_SECONDS,
    max_future_skew_seconds: int = 30,
) -> dict[str, Any]:
    """Atomically merge and retain a bounded, payload-free observation ledger."""
    if isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float)) or not math.isfinite(now_epoch) or now_epoch < 0:
        raise ValueError("now_epoch must be a finite non-negative number")
    if type(retention_seconds) is not int or retention_seconds < 0:
        raise ValueError("retention_seconds must be a non-negative integer")
    if type(max_records) is not int or not 1 <= max_records <= 10_000:
        raise ValueError("max_records must be within 1..10000")
    if not isinstance(authorized_source_kinds, frozenset) or not authorized_source_kinds.issubset(
        {"synthetic-fixture", "offline-metadata", "read-only-probe"}
    ):
        raise ValueError("authorized source kinds must be a frozen allowlist")
    ensure_observation_store(conn)
    existing = load_observation_records(conn, limit=max_records)
    old_by_id = {record["eventId"]: record for record in existing}
    allowed_incoming = []
    rejected_sources = 0
    if isinstance(incoming, (str, bytes, Mapping)) or not isinstance(incoming, Iterable):
        incoming = []
        rejected_sources = 1
    input_limit = min(10_000, max_records * 2)
    input_limit_exceeded = 0
    for index, raw in enumerate(incoming):
        if index >= input_limit:
            input_limit_exceeded = 1
            break
        source_kind = raw.get("sourceKind") if isinstance(raw, Mapping) else None
        if not isinstance(raw, Mapping) or not isinstance(source_kind, str) or source_kind not in authorized_source_kinds:
            rejected_sources += 1
            continue
        record = {key: raw.get(key) for key in _FIELDS if key != "status"}
        event_id = record.get("eventId")
        previous = old_by_id.get(event_id) if isinstance(event_id, str) else None
        # Receipt time is local ingestion time on first receipt. A byte-identical
        # retry retains its original receipt timestamp; producers cannot backdate it.
        if previous and all(record.get(key) == previous.get(key) for key in (
            "nodeId", "generationDigest", "evidenceDigest", "sourceKind", "observedAtEpoch",
        )):
            record["receivedAtEpoch"] = previous["receivedAtEpoch"]
        else:
            record["receivedAtEpoch"] = float(now_epoch)
        allowed_incoming.append(record)

    merged = reconcile_observation_batch(
        existing, allowed_incoming, now_epoch=float(now_epoch), current_generations=current_generations,
        max_records=max_records, max_age_seconds=max_age_seconds,
        max_future_skew_seconds=max_future_skew_seconds,
    )
    cutoff = float(now_epoch) - retention_seconds
    retained = [record for record in merged["records"] if float(record["receivedAtEpoch"]) >= cutoff]
    expired = len(merged["records"]) - len(retained)
    # A savepoint nests safely inside the daemon's existing state transaction.
    conn.execute("SAVEPOINT observation_batch")
    try:
        conn.execute(f"DELETE FROM {_TABLE}")
        conn.executemany(
            f"""INSERT INTO {_TABLE}
                (event_id,node_id,generation_digest,evidence_digest,source_kind,observed_at,received_at,status)
                VALUES(?,?,?,?,?,?,?,?)""",
            [tuple(record[key] for key in (
                "eventId", "nodeId", "generationDigest", "evidenceDigest", "sourceKind",
                "observedAtEpoch", "receivedAtEpoch", "status",
            )) for record in retained],
        )
        conn.execute("RELEASE SAVEPOINT observation_batch")
    except Exception:
        conn.execute("ROLLBACK TO SAVEPOINT observation_batch")
        conn.execute("RELEASE SAVEPOINT observation_batch")
        raise
    merged["records"] = retained
    merged["summary"]["accepted"] = len(retained)
    merged["summary"]["expiredPruned"] = expired
    merged["summary"]["unauthorizedSourceRejected"] = rejected_sources
    merged["summary"]["inputLimitExceeded"] = input_limit_exceeded
    merged["storedPayloads"] = False
    merged["sourceAuthorization"] = "caller-bound-explicit-allowlist; default-fixture-only"
    merged["actionReplay"] = False
    return merged
