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

    def __post_init__(self):
        if self.action_authorized is not False:
            raise ValueError("environment source identity is not authority")

def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def read_environment_source(path, *, owner_uid, optional=False):
    """Path must originate in a trusted launch resolver, never an action payload."""
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
    fd = None
    try:
        ancestors = []
        for parent in path.parents:
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner_uid}
                    or info.st_mode & 0o022):
                raise ValueError('environment source ancestor refused')
            ancestors.append((parent, _identity(info)))
        def fence():
            if any(_identity(parent.lstat()) != identity for parent, identity in ancestors):
                raise ValueError('environment source scope drift')
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
            return EnvironmentSourceIdentity(path, False, None, None, tuple(ancestors))
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in {0, owner_uid} or before.st_mode & 0o022
                or before.st_size > 65536):
            raise ValueError('environment source file refused')
        digest = hashlib.sha256(); size = 0
        while size <= 65536:
            block = os.read(fd, min(8192, 65537-size))
            if not block: break
            size += len(block); digest.update(block)
        if (size > 65536 or size != before.st_size or _identity(os.fstat(fd)) != _identity(before)
                or _identity(path.lstat()) != _identity(before)):
            raise ValueError('environment source file drift')
        fence()
        return EnvironmentSourceIdentity(path, True, digest.hexdigest(), _identity(before), tuple(ancestors))
    except OSError:
        raise ValueError('environment source read refused') from None
    finally:
        if fd is not None: os.close(fd)
