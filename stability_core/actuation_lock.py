"""One local writer lock shared by daemon and CLI/MCP loop entrypoints."""

from __future__ import annotations

import errno
import fcntl
import os
import stat
from pathlib import Path


class ActuationBusy(RuntimeError):
    pass


class UnsafeLockFile(RuntimeError):
    pass


class ActuationLock:
    """Do not remove this file: unlinking a held lock would create a second inode."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fd = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise UnsafeLockFile("writer lock must be an owned regular file with one link")
            if info.st_mode & 0o022:
                raise UnsafeLockFile("writer lock must not be writable by other users")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise ActuationBusy("another local writer holds the actuation lock") from exc
                raise
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def __exit__(self, *_):
        fd, self._fd = self._fd, None
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
