"""Atomic generation artifact writers and latest-pointer publication."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(str(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_replace(path: Path, writer) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{int(time.time() * 1000)}.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as handle:
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(path)
        _fsync_directory(path.parent)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return artifact_metadata(path)


def write_json_atomic(path: Path, payload: Any) -> Dict[str, Any]:
    def write(handle) -> None:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=False)
        handle.write("\n")
    return _atomic_replace(path, write)


def write_text_atomic(path: Path, text: str) -> Dict[str, Any]:
    return _atomic_replace(path, lambda handle: handle.write(text))


def artifact_metadata(path: Path) -> Dict[str, Any]:
    raw = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def publish_generation(
    snapshot: Dict[str, Any], artifacts: Iterable[Tuple[Path, Any]], latest_path: Path,
    extra_metadata: Iterable[Dict[str, Any]] = (),
) -> Dict[str, Any]:
    """Write generation sidecars, then atomically publish latest as commit pointer."""
    artifact_metas = [write_json_atomic(path, payload) for path, payload in artifacts]
    snapshot["generationManifest"] = {
        "schemaVersion": 1,
        "generationId": snapshot.get("generationId"),
        "createdAt": snapshot.get("completedAt"),
        "status": "committed",
        "artifacts": artifact_metas + list(extra_metadata),
    }
    write_json_atomic(latest_path, snapshot)
    return snapshot
