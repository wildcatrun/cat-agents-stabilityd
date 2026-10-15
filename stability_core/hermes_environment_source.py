"""Bound environment source identities; never exposes values or claims completeness."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

@dataclass(frozen=True)
class EnvironmentSourceIdentity:
    path: Path
    present: bool
    sha256: str | None
    identity: tuple | None
    ancestors: tuple
    action_authorized: bool = False
    missing_ancestor: Path | None = None

    def __post_init__(self):
        if self.action_authorized is not False:
            raise ValueError("environment source identity is not authority")

def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode)


def _read_environment_source_projection(path, *, owner_uid, optional=False, projector=None):
    """Internal trusted-parser boundary, not a caller-supplied tool callback.

    Path must originate in a trusted launch resolver, never an action payload.
    Projector must bound its work and return only the permitted governance
    projection, never source bytes or secret assignments. Digest and parsing
    share the same bounded FD bytes; identity is fenced again after parsing.
    This primitive provides neither dotenv semantics nor source completeness.
    """
    if not isinstance(path, (str, Path)):
        raise ValueError("environment source path refused")
    if "\x00" in str(path) or len(str(path)) > 4096:
        raise ValueError("environment source path refused")
    path = Path(path)
    if len(path.parts) > 128:
        raise ValueError("environment source path budget")
    if (type(owner_uid) is not int or owner_uid < 0 or type(optional) is not bool
            or not path.is_absolute() or '..' in path.parts):
        raise ValueError('environment source scope refused')
    if projector is not None and not callable(projector):
        raise ValueError('environment source projector refused')
    fd = None
    try:
        ancestors = []
        missing_ancestor = None
        for parent in reversed(path.parents):
            try:
                info = parent.lstat()
            except FileNotFoundError:
                if not optional:
                    raise ValueError('environment source parent missing')
                missing_ancestor = parent
                break
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner_uid}
                    or info.st_mode & 0o022):
                raise ValueError('environment source ancestor refused')
            ancestors.append((parent, _directory_identity(info)))
        def fence():
            if any(_directory_identity(parent.lstat()) != identity for parent, identity in ancestors):
                raise ValueError('environment source scope drift')
        if missing_ancestor is not None:
            fence()
            try: missing_ancestor.lstat()
            except FileNotFoundError: pass
            else: raise ValueError('environment source parent absence drift')
            fence()
            return EnvironmentSourceIdentity(path, False, None, None, tuple(ancestors),
                                             missing_ancestor=missing_ancestor), None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            if not optional: raise ValueError('environment source missing')
            fence()
            # Recheck absence; replaced symlinks are present even when dangling.
            try: path.lstat()
            except FileNotFoundError: pass
            else: raise ValueError('environment source absence drift')
            fence()
            return EnvironmentSourceIdentity(path, False, None, None, tuple(ancestors)), None
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in {0, owner_uid} or before.st_mode & 0o022
                or before.st_size > 65536):
            raise ValueError('environment source file refused')
        digest = hashlib.sha256(); size = 0
        blocks = [] if projector is not None else None
        while size <= 65536:
            block = os.read(fd, min(8192, 65537-size))
            if not block: break
            size += len(block); digest.update(block)
            if blocks is not None: blocks.append(block)
        if (size > 65536 or size != before.st_size or _identity(os.fstat(fd)) != _identity(before)
                or _identity(path.lstat()) != _identity(before)):
            raise ValueError('environment source file drift')
        fence()
        projection = None
        if projector is not None:
            try:
                projection = projector(b''.join(blocks))
            except Exception:
                raise ValueError('environment source projection refused') from None
            if (_identity(os.fstat(fd)) != _identity(before)
                    or _identity(path.lstat()) != _identity(before)):
                raise ValueError('environment source projection drift')
            fence()
        return EnvironmentSourceIdentity(path, True, digest.hexdigest(), _identity(before), tuple(ancestors)), projection
    except OSError:
        raise ValueError('environment source read refused') from None
    finally:
        if fd is not None: os.close(fd)

def read_environment_source(path, *, owner_uid, optional=False):
    """Identity-only public reader; no raw source bytes escape this boundary."""
    return _read_environment_source_projection(path, owner_uid=owner_uid, optional=optional)[0]

def read_environment_sources(sources, *, owner_uid):
    """Double-observe a bounded resolver-owned file set; not effective-env proof.

    The caller must supply every resolved source, including optional missing
    files. Completeness and loading order remain responsibilities of the qualified
    runtime resolver, not this identity collector.
    """
    if type(sources) not in (list, tuple) or not 1 <= len(sources) <= 32:
        raise ValueError('environment source set budget')
    sources = tuple(sources)
    paths = []
    for item in sources:
        if type(item) is not tuple or len(item) != 2 or type(item[1]) is not bool:
            raise ValueError('environment source set refused')
        if not isinstance(item[0], (str, Path)):
            raise ValueError('environment source set refused')
        path = Path(item[0])
        if path in paths:
            raise ValueError('environment source duplicate')
        paths.append(path)
    first = tuple(read_environment_source(path, owner_uid=owner_uid, optional=optional)
                  for path, optional in sources)
    second = tuple(read_environment_source(path, owner_uid=owner_uid, optional=optional)
                   for path, optional in sources)
    if first != second:
        raise ValueError('environment source set drift')
    return second
