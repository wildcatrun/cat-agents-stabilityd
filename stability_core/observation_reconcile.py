"""Bounded, idempotent reconciliation contract for read-only observations.

This is a pure merge function for existing governed adapters. It contains no
network transport, scheduler, retry loop, action intent, or actuator payload.
"""

from __future__ import annotations

import math
import re
import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_MAX_RECORDS = 2048
DEFAULT_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_RECORDS_HARD_LIMIT = 10_000


def _valid_record(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    node_id = value.get("nodeId")
    source = value.get("sourceKind")
    times = (value.get("observedAtEpoch"), value.get("receivedAtEpoch"))
    return (
        isinstance(node_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", node_id) is not None
        and isinstance(source, str) and source in {"synthetic-fixture", "offline-metadata", "read-only-probe"}
        and all(isinstance(item, (int, float)) and not isinstance(item, bool) and math.isfinite(item) and item >= 0 for item in times)
        and all(isinstance(value.get(key), str) and _SHA256.fullmatch(value[key]) for key in ("eventId", "generationDigest", "evidenceDigest"))
    )


def _normalize(value: Mapping[str, Any], now_epoch: float, max_age_seconds: int, max_future_skew_seconds: int) -> dict[str, Any]:
    record = {
        key: value[key]
        for key in ("nodeId", "eventId", "generationDigest", "evidenceDigest", "sourceKind", "observedAtEpoch", "receivedAtEpoch")
    }
    observed = float(record["observedAtEpoch"])
    received = float(record["receivedAtEpoch"])
    record["observedAtEpoch"] = observed
    record["receivedAtEpoch"] = received
    if observed > now_epoch + max_future_skew_seconds or received > now_epoch + max_future_skew_seconds:
        record["status"] = "clock-invalid"
    elif abs(received - observed) > max_future_skew_seconds:
        record["status"] = "clock-skew"
    elif now_epoch - observed > max_age_seconds or now_epoch - received > max_age_seconds:
        record["status"] = "stale"
    else:
        record["status"] = "fresh"
    return record


def reconcile_observation_batch(
    existing: Iterable[Mapping[str, Any]],
    incoming: Iterable[Mapping[str, Any]],
    *,
    now_epoch: float,
    current_generations: Mapping[str, str],
    max_records: int = DEFAULT_MAX_RECORDS,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    max_future_skew_seconds: int = 30,
) -> dict[str, Any]:
    """Merge bounded evidence records; never accepts or replays actions."""
    if isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float)) or not math.isfinite(now_epoch):
        raise ValueError("now_epoch must be finite")
    if type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS_HARD_LIMIT:
        raise ValueError("max_records must be within the bounded record limit")
    if type(max_age_seconds) is not int or max_age_seconds < 0:
        raise ValueError("max_age_seconds must be a non-negative integer")
    if type(max_future_skew_seconds) is not int or max_future_skew_seconds < 0:
        raise ValueError("max_future_skew_seconds must be a non-negative integer")
    if not isinstance(current_generations, Mapping) or any(
        not isinstance(key, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", key) is None
        or not isinstance(value, str) or not _SHA256.fullmatch(value)
        for key, value in current_generations.items()
    ):
        raise ValueError("current_generations must map node IDs to SHA-256 digests")
    if len(current_generations) > MAX_RECORDS_HARD_LIMIT:
        raise ValueError("current_generations exceeds bounded node limit")

    rejected: dict[str, int] = {}
    candidates: list[dict[str, Any]] = []
    duplicate_count = 0
    conflict_ids: set[str] = set()
    seen: dict[str, str] = {}
    out_of_order_count = 0
    last_received: dict[str, float] = {}
    def add_batch(batch: Iterable[Mapping[str, Any]], batch_limit: int) -> None:
        nonlocal duplicate_count, out_of_order_count
        batch_count = 0
        for raw in batch:
            if batch_count >= batch_limit:
                rejected["input-limit-exceeded"] = rejected.get("input-limit-exceeded", 0) + 1
                break
            batch_count += 1
            if not _valid_record(raw):
                rejected["invalid-record"] = rejected.get("invalid-record", 0) + 1
                continue
            node_id = raw["nodeId"]
            expected_generation = current_generations.get(node_id)
            if expected_generation is None:
                rejected["generation-unfenced-node"] = rejected.get("generation-unfenced-node", 0) + 1
                continue
            if raw["generationDigest"] != expected_generation:
                rejected["generation-mismatch"] = rejected.get("generation-mismatch", 0) + 1
                continue
            record = _normalize(raw, float(now_epoch), max_age_seconds, max_future_skew_seconds)
            previous_received = last_received.get(node_id)
            if previous_received is not None and record["receivedAtEpoch"] < previous_received:
                out_of_order_count += 1
                if record["status"] == "fresh":
                    record["status"] = "out-of-order"
            last_received[node_id] = max(float(record["receivedAtEpoch"]), previous_received or 0)
            event_id = record["eventId"]
            identity = hashlib.sha256(json.dumps(
                {key: record[key] for key in (
                    "nodeId", "generationDigest", "evidenceDigest", "sourceKind",
                    "observedAtEpoch", "receivedAtEpoch",
                )},
                sort_keys=True, separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")).hexdigest()
            if event_id in seen:
                if seen[event_id] == identity:
                    duplicate_count += 1
                else:
                    conflict_ids.add(event_id)
                    rejected["event-id-conflict"] = rejected.get("event-id-conflict", 0) + 1
                continue
            seen[event_id] = identity
            candidates.append(record)

    if isinstance(existing, (str, bytes, Mapping)) or not isinstance(existing, Iterable):
        rejected["existing-batch-invalid"] = 1
    else:
        add_batch(existing, max_records)
    if isinstance(incoming, (str, bytes, Mapping)) or not isinstance(incoming, Iterable):
        rejected["incoming-batch-invalid"] = 1
    else:
        add_batch(incoming, min(MAX_RECORDS_HARD_LIMIT, max_records * 2))

    candidates = [item for item in candidates if item["eventId"] not in conflict_ids]
    candidates.sort(key=lambda item: (float(item["observedAtEpoch"]), item["nodeId"], item["eventId"]))
    overflow = max(0, len(candidates) - max_records)
    if overflow:
        candidates = candidates[overflow:]
    return {
        "schemaVersion": 1,
        "mode": "read-only-observation-reconcile",
        "actionReplay": False,
        "records": candidates,
        "summary": {
            "accepted": len(candidates),
            "duplicatesSuppressed": duplicate_count,
            "eventConflictsRemoved": len(conflict_ids),
            "outOfOrderCount": out_of_order_count,
            "overflowDropped": overflow,
            "rejected": rejected,
            "statusCounts": {
                state: sum(1 for item in candidates if item["status"] == state)
                for state in ("fresh", "stale", "clock-invalid", "clock-skew", "out-of-order")
            },
        },
    }
