"""Code-only content identity measurement, never artifact approval.

Construct specs only from trusted runtime-owned code roots and reviewed file
lists. Tool payloads, profile/config roots and self-reported hashes are not specs.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import time


@dataclass(frozen=True)
class ContentArtifactSpec:
    root: Path
    package_name: str
    package_version: str
    files: tuple[str, ...]


@dataclass(frozen=True)
class ContentArtifactMeasurement:
    digest: str
    files: int
    bytes: int
    records: tuple
    artifact_kind: str = 'content-manifest'
    action_authorized: bool = False

    def __post_init__(self):
        if self.action_authorized is not False:
            raise ValueError('content-measurement-is-not-authority')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink, info.st_mode, info.st_uid)


def measure_content_artifact(spec, *, budget_ms=1000):
    if type(spec) is not ContentArtifactSpec or type(budget_ms) is not int or not 1 <= budget_ms <= 2000:
        raise ValueError('content-spec-or-budget-invalid')
    if not isinstance(spec.root, Path):
        raise ValueError('content-root-type-invalid')
    root = spec.root
    if (not root.is_absolute() or any(p.is_symlink() for p in (root, *root.parents))
            or type(spec.files) is not tuple or not 1 <= len(spec.files) <= 1024
            or any(type(value) is not str for value in spec.files)
            or len(set(spec.files)) != len(spec.files) or 'package.json' not in spec.files
            or any(type(v) is not str or not v or len(v) > 128 for v in (spec.package_name, spec.package_version))):
        raise ValueError('content-root-or-manifest-invalid')
    root_stat = root.stat()
    if (not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid not in {0, os.getuid()}
            or root_stat.st_mode & 0o022):
        raise ValueError('content-root-owner-invalid')
    deadline = time.monotonic() + budget_ms / 1000
    records, identities, total, package = [], {}, 0, None
    for relative in sorted(spec.files):
        if (type(relative) is not str or len(relative) > 4096 or '\\' in relative
                or str(PurePosixPath(relative)) != relative or PurePosixPath(relative).is_absolute()
                or '..' in PurePosixPath(relative).parts):
            raise ValueError('content-relative-path-invalid')
        if time.monotonic() > deadline: raise ValueError('content-time-budget')
        path = root / relative
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('content-file-symlink')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 2 * 1024 * 1024
                    or before.st_uid not in {0, os.getuid()} or before.st_mode & 0o022):
                raise ValueError('content-file-owner-or-budget')
            digest, count, metadata = hashlib.sha256(), 0, bytearray()
            while True:
                if time.monotonic() > deadline: raise ValueError('content-time-budget')
                raw = os.read(descriptor, 65536)
                if not raw: break
                count += len(raw); total += len(raw)
                if count > 2 * 1024 * 1024 or total > 8 * 1024 * 1024:
                    raise ValueError('content-byte-budget')
                digest.update(raw)
                if relative == 'package.json': metadata.extend(raw)
            after = os.fstat(descriptor)
            final = path.lstat()
            if _identity(before) != _identity(after) or _identity(after) != _identity(final):
                raise ValueError('content-file-drift')
            identities[path] = _identity(final)
            records.append((relative, digest.hexdigest(), count))
            if relative == 'package.json': package = json.loads(metadata)
        finally:
            os.close(descriptor)
    if not isinstance(package, dict) or package.get('name') != spec.package_name or package.get('version') != spec.package_version:
        raise ValueError('content-package-identity-mismatch')
    if _identity(root.stat()) != _identity(root_stat):
        raise ValueError('content-root-drift')
    for path, identity in identities.items():
        if time.monotonic() > deadline: raise ValueError('content-time-budget')
        if path.is_symlink() or _identity(path.lstat()) != identity:
            raise ValueError('content-manifest-drift')
    payload = dict(schemaVersion=1, packageName=spec.package_name, packageVersion=spec.package_version,
                   files=records)
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return ContentArtifactMeasurement(hashlib.sha256(canonical).hexdigest(), len(records), total, tuple(records))
