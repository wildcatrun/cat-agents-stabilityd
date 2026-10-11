"""Atomic generation artifact writers and latest-pointer publication."""

from __future__ import annotations

import hashlib
import json
import os
import time
import stat
from contextlib import contextmanager, ExitStack
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple


@contextmanager
def _directory_fence(path: Path):
    """Hold directory identity until publication completes; refuse replacement."""
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    expected = os.fstat(fd)
    def check():
        current = path.lstat()
        if (not stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino)):
            raise OSError("publication directory identity changed")
    try:
        check()
        check.identity = (expected.st_dev, expected.st_ino)
        yield check
        check()
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    fd = os.open(str(path), flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_replace(path: Path, writer, *, directory_identity=None, sync_directory=True) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _directory_fence(path.parent) as check:
        if directory_identity is not None and check.identity != directory_identity:
            raise OSError("publication directory identity changed")
        fd = os.open(str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
        tmp_name = f"{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
        try:
            if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != check.identity:
                raise OSError("publication directory identity changed")
            tmp_fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=fd)
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as handle:
                writer(handle)
                handle.flush()
                os.fsync(handle.fileno())
            check()
            os.replace(tmp_name, path.name, src_dir_fd=fd, dst_dir_fd=fd)
            if sync_directory:
                _fsync_directory(path.parent)
            check()
            return artifact_metadata(path)
        except Exception:
            try:
                os.unlink(tmp_name, dir_fd=fd)
            except OSError:
                pass
            raise
        finally:
            os.close(fd)


def write_json_atomic(path: Path, payload: Any, *, directory_identity=None, _sync_directory=True) -> Dict[str, Any]:
    def write(handle) -> None:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=False)
        handle.write("\n")
    return _atomic_replace(path, write, directory_identity=directory_identity, sync_directory=_sync_directory)


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
    artifacts = list(artifacts)
    parents = dict.fromkeys([path.parent for path, _ in artifacts] + [latest_path.parent])
    with ExitStack() as stack:
        checks = []
        identities = {}
        for parent in parents:
            parent.mkdir(parents=True, exist_ok=True)
            check = stack.enter_context(_directory_fence(parent))
            checks.append(check)
            identities[parent] = check.identity
        artifact_metas = []
        for path, payload in artifacts:
            for check in checks:
                check()
            artifact_metas.append(write_json_atomic(path, payload, directory_identity=identities[path.parent], _sync_directory=False))
        for check in checks:
            check()
        # All sidecar files are synced; commit each distinct rename directory
        # before the independent latest-pointer file/directory barrier.
        for parent in dict.fromkeys(path.parent for path, _ in artifacts):
            _fsync_directory(parent)
        for check in checks:
            check()
        snapshot["generationManifest"] = {
            "schemaVersion": 1,
            "generationId": snapshot.get("generationId"),
            "createdAt": snapshot.get("completedAt"),
            "status": "committed",
            "artifacts": artifact_metas + list(extra_metadata),
        }
        write_json_atomic(latest_path, snapshot, directory_identity=identities[latest_path.parent])
    return snapshot
