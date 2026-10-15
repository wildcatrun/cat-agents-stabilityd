"""Durable intent-first action ledger.

This module records decisions; it deliberately has no actuator or retry facility.
``executing`` means only that an execution intent is durably claimed. It is
NEVER authority to perform a side effect. The governed boundary must separately
verify authorization, protection, identity and freshness before every operation.
A storage error raises; no claim is returned.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence


STATES = frozenset({"planned", "executing", "succeeded", "failed", "blocked", "uncertain"})
ACTIVE_STATES = ("planned", "executing", "uncertain")


def _assert_profile_scope_clear(conn, target, action_id):
    """Check fixed runtime aliases inside the caller's write transaction."""
    match = re.fullmatch(r"hermes-(?:gateway|profile):([A-Za-z0-9_-]{1,64})", target)
    if match is None:
        return
    profile = match.group(1).lower()
    reserved = conn.execute(
        """SELECT 1 FROM action_ledger
           WHERE target COLLATE NOCASE IN (?, ?)
           AND state IN ('planned','executing','uncertain')
           AND action_id != ? LIMIT 1""",
        ("hermes-gateway:" + profile, "hermes-profile:" + profile, action_id),
    ).fetchone()
    if reserved is not None:
        raise ActionConflict("Hermes profile scope is already reserved")


TERMINAL_STATES = frozenset({"succeeded", "failed", "blocked"})
_TRANSITIONS = {
    "planned": frozenset({"executing", "blocked"}),
    "executing": frozenset({"succeeded", "failed", "blocked", "uncertain"}),
    # Uncertainty is deliberately not resolvable through the generic writer.
    "uncertain": frozenset(),
}
METADATA_FIELDS = frozenset(
    {"actor", "request_source", "trace_id", "correlation_id", "dispatch_id", "workflow_id", "reason_code"}
)
LEDGER_SCHEMA_VERSION = 1
_EXPECTED_COLUMNS = frozenset({
    "action_id", "idempotency_key", "action_type", "target", "generation", "state",
    "input_digest", "authorization_ref", "policy_ref", "evidence_refs_json", "metadata_json",
    "created_at_ms", "updated_at_ms", "version", "outcome_ref", "postcheck_ref", "precheck_ref",
})


class LedgerDurabilityError(RuntimeError):
    """The ledger cannot provide durable intent semantics."""


class ActionConflict(RuntimeError):
    """An idempotency or active-scope invariant was violated."""


class InvalidTransition(RuntimeError):
    """A compare-and-swap state transition was rejected."""


@dataclasses.dataclass(frozen=True)
class ActionRecord:
    action_id: str
    idempotency_key: str
    action_type: str
    target: str
    generation: str
    state: str
    input_digest: str
    authorization_ref: Optional[str]
    policy_ref: Optional[str]
    evidence_refs: tuple[str, ...]
    metadata: Mapping[str, Any]
    created_at_ms: int
    updated_at_ms: int
    version: int
    outcome_ref: Optional[str]
    postcheck_ref: Optional[str]
    precheck_ref: Optional[str]


def _canonical_digest(value: Any) -> str:
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("input must be canonical JSON data") from exc
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _refs(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ValueError("evidence_refs must be a collection, not a single string")
    result = tuple(values)
    if any(not isinstance(item, str) or not item.strip() for item in result):
        raise ValueError("evidence_refs must contain non-empty opaque reference strings")
    return result


def _optional_ref(value: Optional[str]) -> Optional[str]:
    if value is not None and (not isinstance(value, str) or not value.strip()):
        raise ValueError("reference must be a non-empty opaque string or None")
    return value


def _scope_index_sql_matches(sql: str) -> bool:
    """Accept only our known DDL tokens; preserve literal case and whitespace."""
    tokens = []
    previous = 0
    for match in re.finditer(r"'(?:''|[^'])*'|[A-Za-z_][A-Za-z0-9_]*|[(),]", sql):
        if sql[previous:match.start()].strip():
            return False  # Comments, expressions and unknown syntax require migration.
        token = match.group()
        tokens.append(token if token.startswith("'") else token.lower())
        previous = match.end()
    if sql[previous:].strip():
        return False
    if tokens[3:6] == ["if", "not", "exists"]:
        tokens[3:6] = []
    return tokens == [
        "create", "unique", "index", "action_ledger_one_active_scope", "on",
        "action_ledger", "(", "target", ")", "where", "state", "in", "(",
        "'planned'", ",", "'executing'", ",", "'uncertain'", ")",
    ]


def _safe_metadata(metadata: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    data = dict(metadata or {})
    unknown = set(data) - METADATA_FIELDS
    if unknown:
        raise ValueError(f"metadata fields are not allowlisted: {sorted(unknown)}")
    # Ensure the allowlisted values themselves are inert JSON scalars.
    if any(value is not None and not isinstance(value, (str, int, float, bool)) for value in data.values()):
        raise ValueError("metadata values must be JSON scalars")
    _canonical_digest(data)  # Reject NaN/Infinity rather than storing non-JSON values.
    return data


class ActionLedger:
    """SQLite ledger using WAL and FULL synchronous transactions.

    A filesystem path is mandatory because ``:memory:`` cannot survive restart.
    The schema is additive and intentionally leaves legacy ``actions`` and
    ``kv`` tables untouched.
    """

    def __init__(self, path: os.PathLike[str] | str, *, timeout: float = 5.0) -> None:
        raw = os.fspath(path)
        if not raw.strip() or raw == ":memory:" or raw.startswith("file::memory:") or "mode=memory" in raw:
            raise LedgerDurabilityError("an in-memory database is not a durable action ledger")
        self.path = Path(raw)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(raw, timeout=timeout, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        try:
            journal_mode = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if str(journal_mode).lower() != "wal":
                raise LedgerDurabilityError("SQLite WAL could not be established")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._install_schema()
            synchronous = int(self._conn.execute("PRAGMA synchronous").fetchone()[0])
            if synchronous != 2:
                raise LedgerDurabilityError("SQLite synchronous=FULL could not be established")
        except Exception:
            self._conn.close()
            raise

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ActionLedger":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextlib.contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                self._conn.execute("ROLLBACK")
            raise

    def _install_schema(self) -> None:
        with self._write() as conn:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='action_ledger'"
            ).fetchone()
            if exists:
                columns = {row["name"] for row in conn.execute("PRAGMA table_info(action_ledger)")}
                if columns != _EXPECTED_COLUMNS:
                    raise LedgerDurabilityError("unsupported action_ledger schema; migration required")
            conn.execute("CREATE TABLE IF NOT EXISTS stability_schema_versions (component TEXT PRIMARY KEY, version INTEGER NOT NULL)")
            version = conn.execute(
                "SELECT version FROM stability_schema_versions WHERE component='action_ledger'"
            ).fetchone()
            if exists and version is None:
                raise LedgerDurabilityError("unversioned action_ledger schema; explicit migration required")
            if version and version["version"] != LEDGER_SCHEMA_VERSION:
                raise LedgerDurabilityError("unsupported action_ledger schema version; migration required")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS action_ledger (
                    action_id TEXT PRIMARY KEY,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    generation TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('planned','executing','succeeded','failed','blocked','uncertain')),
                    input_digest TEXT NOT NULL,
                    authorization_ref TEXT,
                    policy_ref TEXT,
                    evidence_refs_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    updated_at_ms INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    outcome_ref TEXT,
                    postcheck_ref TEXT,
                    precheck_ref TEXT
                )"""
            )
            conn.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS action_ledger_one_active_scope
                   ON action_ledger(target)
                   WHERE state IN ('planned','executing','uncertain')"""
            )
            index_columns = tuple(
                row["name"] for row in conn.execute("PRAGMA index_info(action_ledger_one_active_scope)")
            )
            if index_columns != ("target",):
                raise LedgerDurabilityError("unsupported active-scope index; explicit migration required")
            indexes = {row["name"]: row for row in conn.execute("PRAGMA index_list(action_ledger)")}
            scope_index = indexes.get("action_ledger_one_active_scope")
            sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name='action_ledger_one_active_scope'"
            ).fetchone()
            if (
                scope_index is None or scope_index["unique"] != 1 or scope_index["partial"] != 1
                or not sql or not _scope_index_sql_matches(sql["sql"] or "")
            ):
                raise LedgerDurabilityError("unsupported active-scope index constraints; migration required")
            conn.execute(
                "INSERT OR IGNORE INTO stability_schema_versions(component,version) VALUES('action_ledger',?)",
                (LEDGER_SCHEMA_VERSION,),
            )

    @staticmethod
    def stable_action_id(idempotency_key: str) -> str:
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("idempotency_key is required")
        return "act_" + hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()[:32]

    def plan_action(
        self,
        *,
        idempotency_key: str,
        action_type: str,
        target: str,
        generation: str,
        input_data: Any,
        authorization_ref: Optional[str] = None,
        policy_ref: Optional[str] = None,
        evidence_refs: Sequence[str] = (),
        metadata: Optional[Mapping[str, Any]] = None,
        action_id: Optional[str] = None,
    ) -> ActionRecord:
        if not all(isinstance(v, str) and v.strip() for v in (idempotency_key, action_type, target, generation)):
            raise ValueError("idempotency_key, action_type, target, and generation are required strings")
        authorization_ref = _optional_ref(authorization_ref)
        policy_ref = _optional_ref(policy_ref)
        if action_id is not None and (not isinstance(action_id, str) or not action_id.strip()):
            raise ValueError("action_id must be a non-empty string")
        digest = _canonical_digest(input_data)
        refs = _refs(evidence_refs)
        safe_metadata = _safe_metadata(metadata)
        action_id = action_id or self.stable_action_id(idempotency_key)
        fingerprint = (action_id, action_type, target, generation, digest, authorization_ref, policy_ref, refs, safe_metadata)
        now = time.time_ns() // 1_000_000
        try:
            with self._write() as conn:
                row = conn.execute("SELECT * FROM action_ledger WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                if row is not None:
                    existing = self._record(row)
                    existing_fingerprint = (
                        existing.action_id, existing.action_type, existing.target, existing.generation,
                        existing.input_digest, existing.authorization_ref, existing.policy_ref,
                        existing.evidence_refs, dict(existing.metadata),
                    )
                    if existing_fingerprint != fingerprint:
                        raise ActionConflict("idempotency key was reused with different input or references")
                    return existing
                # Both actions operate on the same Hermes profile. Resolve only
                # these fixed ASCII namespaces; tool metadata cannot add aliases.
                # This read shares the BEGIN IMMEDIATE insertion transaction, so
                # another current writer cannot reserve the other alias between
                # the check and INSERT. Keep stored targets and schema unchanged.
                _assert_profile_scope_clear(conn, target, action_id)
                conn.execute(
                    """INSERT INTO action_ledger
                    (action_id,idempotency_key,action_type,target,generation,state,input_digest,
                     authorization_ref,policy_ref,evidence_refs_json,metadata_json,created_at_ms,updated_at_ms,version)
                    VALUES (?,?,?,?,?,'planned',?,?,?,?,?,?,?,0)""",
                    (action_id, idempotency_key, action_type, target, generation, digest,
                     authorization_ref, policy_ref, json.dumps(refs), json.dumps(safe_metadata, sort_keys=True), now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ActionConflict("an action id or active target is already reserved") from exc
        record = self.get(action_id)
        assert record is not None
        return record

    def get(self, action_id: str) -> Optional[ActionRecord]:
        row = self._conn.execute("SELECT * FROM action_ledger WHERE action_id=?", (action_id,)).fetchone()
        return self._record(row) if row else None

    def begin_execution(
        self, action_id: str, *, expected_version: int, precheck_ref: Optional[str] = None
    ) -> ActionRecord:
        """Claim durable intent only; caller still needs independently verified authority."""
        record = self.get(action_id)
        if record is None or not (record.authorization_ref and record.policy_ref and record.evidence_refs):
            raise InvalidTransition("execution intent requires authorization, policy and evidence references")
        return self.transition(
            action_id, expected_state="planned", expected_version=expected_version,
            new_state="executing", precheck_ref=precheck_ref,
        )

    def abandon_unstarted_plan(self, action_id: str, *, expected_version: int) -> ActionRecord:
        """Atomically abandon only an unclaimed plan; never reconcile possible effects.

        This is an explicit local ledger operation, not a daemon startup policy.
        Its CAS races safely with ``begin_execution``: exactly one can move the
        planned row, and the executor invokes no operation unless its claim wins.
        Executing and uncertain rows require action-specific external evidence and
        remain reserved for manual reconciliation.
        """
        if type(expected_version) is not int or expected_version < 0:
            raise InvalidTransition("expected version must be a non-negative integer")
        return self.transition(
            action_id, expected_state="planned", expected_version=expected_version,
            new_state="blocked",
            outcome_ref=(
                "outcome://action-ledger/abandoned-before-claim/"
                f"v{expected_version}-to-v{expected_version + 1}"
            ),
        )

    def refresh_execution_precheck(
        self, action_id: str, *, expected_version: int, precheck_ref: str
    ) -> ActionRecord:
        """Durably bind the final pre-effect boundary check to this executing claim."""
        precheck_ref = _optional_ref(precheck_ref)
        if not precheck_ref:
            raise InvalidTransition("final precheck evidence reference is required")
        now = time.time_ns() // 1_000_000
        with self._write() as conn:
            claimed = conn.execute(
                "SELECT target FROM action_ledger WHERE action_id=? AND state='executing' AND version=?",
                (action_id, expected_version),
            ).fetchone()
            if claimed is not None:
                _assert_profile_scope_clear(conn, claimed["target"], action_id)
            cursor = conn.execute(
                """UPDATE action_ledger SET updated_at_ms=?, version=version+1, precheck_ref=?
                   WHERE action_id=? AND state='executing' AND version=?""",
                (now, precheck_ref, action_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise InvalidTransition("executing precheck compare-and-swap failed")
        record = self.get(action_id)
        assert record is not None
        return record

    def transition(
        self,
        action_id: str,
        *,
        expected_state: str,
        expected_version: int,
        new_state: str,
        outcome_ref: Optional[str] = None,
        postcheck_ref: Optional[str] = None,
        precheck_ref: Optional[str] = None,
    ) -> ActionRecord:
        """Record an ordinary state transition; never resolve uncertain executions here."""
        if new_state not in STATES or new_state not in _TRANSITIONS.get(expected_state, frozenset()):
            raise InvalidTransition(f"transition {expected_state}->{new_state} is not allowed")
        outcome_ref = _optional_ref(outcome_ref)
        postcheck_ref = _optional_ref(postcheck_ref)
        precheck_ref = _optional_ref(precheck_ref)
        if new_state in {"succeeded", "failed"} and not (outcome_ref and postcheck_ref):
            raise InvalidTransition("terminal outcome requires operation and post-check references")
        now = time.time_ns() // 1_000_000
        with self._write() as conn:
            if new_state == "executing":
                planned = conn.execute(
                    "SELECT target FROM action_ledger WHERE action_id=? AND state=? AND version=?",
                    (action_id, expected_state, expected_version),
                ).fetchone()
                if planned is not None:
                    _assert_profile_scope_clear(conn, planned["target"], action_id)
            cursor = conn.execute(
                """UPDATE action_ledger SET state=?, updated_at_ms=?, version=version+1,
                   outcome_ref=?, postcheck_ref=?, precheck_ref=COALESCE(?,precheck_ref)
                   WHERE action_id=? AND state=? AND version=?""",
                (new_state, now, outcome_ref, postcheck_ref, precheck_ref, action_id, expected_state, expected_version),
            )
            if cursor.rowcount != 1:
                raise InvalidTransition("state/version compare-and-swap failed")
        record = self.get(action_id)
        assert record is not None
        return record

    def startup_reconcile_candidates(self) -> list[ActionRecord]:
        """List ambiguous prior executions.  This never transitions or retries them."""
        rows = self._conn.execute(
            "SELECT * FROM action_ledger WHERE state IN ('executing','uncertain') ORDER BY created_at_ms, action_id"
        ).fetchall()
        return [self._record(row) for row in rows]

    @staticmethod
    def _record(row: sqlite3.Row) -> ActionRecord:
        return ActionRecord(
            action_id=row["action_id"], idempotency_key=row["idempotency_key"],
            action_type=row["action_type"], target=row["target"], generation=row["generation"],
            state=row["state"], input_digest=row["input_digest"], authorization_ref=row["authorization_ref"],
            policy_ref=row["policy_ref"], evidence_refs=tuple(json.loads(row["evidence_refs_json"])),
            metadata=json.loads(row["metadata_json"]), created_at_ms=row["created_at_ms"],
            updated_at_ms=row["updated_at_ms"], version=row["version"], outcome_ref=row["outcome_ref"],
            postcheck_ref=row["postcheck_ref"],
            precheck_ref=row["precheck_ref"],
        )
