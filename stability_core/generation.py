"""Atomic generation artifact writers and latest-pointer publication."""

from __future__ import annotations

import hashlib
import json
import os
import time
import stat
from contextlib import contextmanager, ExitStack, nullcontext
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple


@contextmanager
def _directory_fence(path: Path):
    """Hold directory identity until publication completes; refuse replacement."""
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    expected = os.fstat(fd)
    active = True
    def check():
        if not active:
            raise OSError("publication directory fence closed")
        held = os.fstat(fd)
        if (held.st_dev, held.st_ino) != (expected.st_dev, expected.st_ino):
            raise OSError("publication directory descriptor changed")
        current = path.lstat()
        if (not stat.S_ISDIR(current.st_mode)
                or (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino)):
            raise OSError("publication directory identity changed")
    try:
        check()
        check.identity = (expected.st_dev, expected.st_ino)
        check.fd = fd
        check.path = path
        yield check
        check()
    finally:
        active = False
        os.close(fd)


def _fsync_directory(path: Path, *, _fence=None) -> None:
    if _fence is not None:
        if _fence.path != path:
            raise OSError("publication directory fence scope changed")
        _fence()
        os.fsync(_fence.fd)
        _fence()
        return
    with _directory_fence(path) as check:
        os.fsync(check.fd)


def _atomic_replace(path: Path, writer, *, directory_identity=None, sync_directory=True, parent_fence=None, return_metadata=True) -> Dict[str, Any]:
    parent = path.parent
    filename = path.name
    if parent_fence is not None:
        if parent_fence.path != parent:
            raise OSError("publication directory fence scope changed")
        parent_fence()
    else:
        parent.mkdir(parents=True, exist_ok=True)
    with (nullcontext(parent_fence) if parent_fence is not None else _directory_fence(parent)) as check:
        check()
        if directory_identity is not None and check.identity != directory_identity:
            raise OSError("publication directory identity changed")
        fd = check.fd
        tmp_name = f"{filename}.{os.getpid()}.{time.time_ns()}.tmp"
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
            os.replace(tmp_name, filename, src_dir_fd=fd, dst_dir_fd=fd)
            if sync_directory:
                _fsync_directory(parent, _fence=check)
            check()
            return artifact_metadata(path) if return_metadata else {}
        except Exception:
            try:
                os.unlink(tmp_name, dir_fd=fd)
            except OSError:
                pass
            raise


def write_json_atomic(path: Path, payload: Any, *, directory_identity=None, _sync_directory=True, _parent_fence=None, _return_metadata=True, compact=False) -> Dict[str, Any]:
    if type(compact) is not bool:
        raise ValueError("publication JSON format must be boolean")
    def write(handle) -> None:
        options = {"separators": (",", ":")} if compact else {"indent": 2}
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=False, **options) + "\n"
        if handle.write(encoded) != len(encoded):
            raise OSError("publication JSON short write")
    return _atomic_replace(path, write, directory_identity=directory_identity, sync_directory=_sync_directory, parent_fence=_parent_fence, return_metadata=_return_metadata)


def write_text_atomic(path: Path, text: str) -> Dict[str, Any]:
    return _atomic_replace(path, lambda handle: handle.write(text))


def artifact_metadata(path: Path) -> Dict[str, Any]:
    raw = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def publish_generation(
    snapshot: Dict[str, Any], artifacts: Iterable[Tuple[Path, Any]], latest_path: Path,
    extra_metadata: Iterable[Dict[str, Any]] = (),
    *, compact_sidecars: bool = False,
) -> Dict[str, Any]:
    """Write generation sidecars, then atomically publish latest as commit pointer."""
    if type(compact_sidecars) is not bool:
        raise ValueError("publication sidecar JSON format must be boolean")
    artifacts = [(path, payload, path.parent) for path, payload in artifacts]
    latest_parent = latest_path.parent
    parents = dict.fromkeys([parent for _, _, parent in artifacts] + [latest_parent])
    with ExitStack() as stack:
        checks = []
        identities = {}
        fences = {}
        for parent in parents:
            parent.mkdir(parents=True, exist_ok=True)
            check = stack.enter_context(_directory_fence(parent))
            checks.append(check)
            identities[parent] = check.identity
            fences[parent] = check
        artifact_metas = []
        for path, payload, parent in artifacts:
            for check in checks:
                check()
            artifact_metas.append(write_json_atomic(path, payload, directory_identity=identities[parent], _sync_directory=False, _parent_fence=fences[parent], compact=compact_sidecars))
        for check in checks:
            check()
        # All sidecar files are synced; commit each distinct rename directory
        # before the independent latest-pointer file/directory barrier.
        for parent in dict.fromkeys(parent for _, _, parent in artifacts):
            _fsync_directory(parent, _fence=fences[parent])
        for check in checks:
            check()
        snapshot["generationManifest"] = {
            "schemaVersion": 1,
            "generationId": snapshot.get("generationId"),
            "createdAt": snapshot.get("completedAt"),
            "status": "committed",
            "artifacts": artifact_metas + list(extra_metadata),
        }
        # Latest is the commit pointer, not a self-listed artifact. Its returned
        # metadata was unused; retain both durability barriers without rereading it.
        write_json_atomic(latest_path, snapshot, directory_identity=identities[latest_parent], _parent_fence=fences[latest_parent], _return_metadata=False, compact=True)
    return snapshot
