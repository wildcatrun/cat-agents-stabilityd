"""Offline synthetic producer contract. No collector, transport or runtime hook."""
from dataclasses import dataclass
import hashlib
import json
import math
import re
from collections.abc import Mapping
from .observation_store import persist_observation_batch

SHA = re.compile(r"^[0-9a-f]{64}$")

@dataclass(frozen=True)
class ProducerGrant:
    adapter_version: str
    node_scope: frozenset[str]
    source_kind: str = "synthetic-fixture"

def evidence_digest(evidence):
    # Deliberately closed synthetic schema; no arbitrary text or secrets.
    if (not isinstance(evidence, dict) or set(evidence) != {"coverage", "sampleCount"}
            or evidence["coverage"] is not True or type(evidence["sampleCount"]) is not int
            or not 1 <= evidence["sampleCount"] <= 10000):
        raise ValueError("invalid-coverage-evidence")
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

def ingest_synthetic_observation(conn, envelope, *, trusted_producer_id, grants, current_generations, now_epoch):
    """Caller supplies provenance independently of untrusted envelope contents.

    Caller remains responsible for authenticating producer_id. This API only
    characterizes synthetic data; it cannot establish real node readiness.
    """
    if (isinstance(now_epoch, bool) or not isinstance(now_epoch, (int, float))
            or not math.isfinite(now_epoch) or now_epoch < 0):
        raise ValueError("invalid-ingest-time")
    def reject(reason):
        return {"observationFreshness": None, "rejected": [reason], "readinessEvaluated": False,
                "actionReplay": False, "syntheticOnly": True}
    if not isinstance(grants, Mapping) or not isinstance(trusted_producer_id, str):
        return reject("unknown-producer")
    grant = grants.get(trusted_producer_id)
    if not isinstance(grant, ProducerGrant):
        return reject("unknown-producer")
    required = {"producerId", "adapterVersion", "nodeId", "sourceKind", "eventId", "generationDigest",
                "evidenceDigest", "observedAtEpoch", "evidence"}
    if not isinstance(envelope, dict) or set(envelope) != required:
        return reject("invalid-envelope-fields")
    if envelope["producerId"] != trusted_producer_id:
        return reject("producer-mismatch")
    if envelope["adapterVersion"] != grant.adapter_version:
        return reject("adapter-version-mismatch")
    node = envelope["nodeId"]
    # Synthetic IDs are intentionally disjoint from every deployed node.
    if (not isinstance(node, str) or re.fullmatch(r"fixture-[A-Za-z0-9_-]{1,56}", node) is None
            or not isinstance(grant.node_scope, frozenset) or node not in grant.node_scope):
        return reject("node-scope-denied")
    if grant.source_kind != "synthetic-fixture" or envelope["sourceKind"] != grant.source_kind:
        return reject("source-kind-denied")
    if (not isinstance(current_generations, Mapping) or node not in current_generations
            or envelope["generationDigest"] != current_generations[node]):
        return reject("generation-mismatch")
    for field in ("eventId", "generationDigest", "evidenceDigest"):
        if not isinstance(envelope[field], str) or not SHA.fullmatch(envelope[field]):
            return reject("invalid-digest")
    try:
        digest = evidence_digest(envelope["evidence"])
    except ValueError:
        return reject("invalid-coverage-evidence")
    if digest != envelope["evidenceDigest"]:
        return reject("evidence-digest-mismatch")
    observed = envelope["observedAtEpoch"]
    if isinstance(observed, bool) or not isinstance(observed, (int, float)) or not math.isfinite(observed) or observed < 0:
        return reject("invalid-observed-time")
    record = {key: envelope[key] for key in ("nodeId", "sourceKind", "eventId", "generationDigest", "evidenceDigest", "observedAtEpoch")}
    record["receivedAtEpoch"] = now_epoch
    result = persist_observation_batch(conn, [record], now_epoch=now_epoch,
                                      current_generations=current_generations)
    matching = [r for r in result["records"] if r["eventId"] == record["eventId"]]
    return {"observationFreshness": matching[0]["status"] if matching else None,
            "rejected": sorted(result["summary"]["rejected"]), "summary": result["summary"],
            "readinessEvaluated": False, "actionReplay": False, "syntheticOnly": True}
