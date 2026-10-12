"""Metadata-only named-profile existence evidence, not residency or authority."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

MARKERS = ('config.yaml', '.env', 'SOUL.md', 'profile.yaml', 'auth.json', 'state.db')


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@dataclass(frozen=True)
class ProfileLiveObservation:
    profile: str
    home: Path
    live: bool
    reason: str
    metadata: tuple
    scope: str = 'owned-nonsymlink-profile-identity'
    residency: str = 'unknown'
    channel_readiness: str = 'unknown'
    action_authorized: bool = False

    def __post_init__(self):
        if (self.scope != 'owned-nonsymlink-profile-identity'
                or self.residency != 'unknown' or self.channel_readiness != 'unknown'
                or self.action_authorized is not False):
            raise ValueError('profile live observation is not runtime authority')


def observe_profile_live(runtime_root, *, profile, owner_uid):
    """Observe a registry/adapter-owned route without reading marker contents.

    Implements the nonsymlink owned subset of installed named_profile_is_live:
    existing home + one regular identity marker + no tombstone. Missing entries
    are fenced at their existing directory. Symlink/unsafe/unknown objects are
    refused, never interpreted as missing or as permission to start a profile.
    Does not require a running Gateway/socket, certify code or grant repair.
    """
    if (not isinstance(runtime_root, (str, Path)) or type(owner_uid) is not int
            or owner_uid < 0 or type(profile) is not str
            or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', profile) or profile == 'default'):
        raise ValueError('profile live scope refused')
    text = str(runtime_root)
    if '\x00' in text or len(text) > 4096:
        raise ValueError('profile live path refused')
    root = Path(text)
    if not root.is_absolute() or '..' in root.parts or len(root.parts) > 128:
        raise ValueError('profile live path refused')
    home = root / 'profiles' / profile
    fds, directories, observed = [], [], []
    directory_flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | os.O_NOFOLLOW
    try:
        def trusted(info, directory=False):
            if (info.st_uid not in {0, owner_uid} or info.st_mode & 0o022
                    or stat.S_ISLNK(info.st_mode)
                    or (directory and not stat.S_ISDIR(info.st_mode))):
                raise ValueError('profile live ownership refused')

        def metadata(parent_fd, name, path):
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                result = None
            else:
                trusted(info)
                result = _identity(info)
            observed.append((parent_fd, name, path, result))
            return result

        def open_directory(path, parent_fd=None, name=None):
            fd = os.open(str(path) if parent_fd is None else name,
                         directory_flags, **({} if parent_fd is None else {'dir_fd': parent_fd}))
            fds.append(fd)
            info = os.fstat(fd)
            trusted(info, directory=True)
            if _identity(info) != _identity(path.lstat()):
                raise ValueError('profile live directory drift')
            directories.append((fd, path, _identity(info)))
            return fd

        def fence():
            for fd, path, expected in directories:
                if _identity(os.fstat(fd)) != expected or _identity(path.lstat()) != expected:
                    raise ValueError('profile live directory drift')
            for fd, name, path, expected in observed:
                try:
                    current = _identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
                except FileNotFoundError:
                    current = None
                if current != expected:
                    raise ValueError('profile live metadata drift')
                try:
                    current_path = _identity(path.lstat())
                except FileNotFoundError:
                    current_path = None
                if current_path != expected:
                    raise ValueError('profile live path drift')

        def result(live, reason):
            fence()
            records = tuple((str(path), identity) for _fd, _name, path, identity in observed)
            records += tuple((str(path), identity) for _fd, path, identity in directories)
            fence()
            return ProfileLiveObservation(profile, home, live, reason, records)

        current_path = Path('/')
        current_fd = open_directory(current_path)
        for part in root.parts[1:]:
            current_path = current_path / part
            current_fd = open_directory(current_path, current_fd, part)
        profiles = root / 'profiles'
        profiles_info = metadata(current_fd, 'profiles', profiles)
        if profiles_info is None:
            return result(False, 'profiles-directory-missing')
        profiles_fd = open_directory(profiles, current_fd, 'profiles')
        deleted = profiles / '.deleted'
        deleted_info = metadata(profiles_fd, '.deleted', deleted)
        tombstone = None
        if deleted_info is not None:
            deleted_fd = open_directory(deleted, profiles_fd, '.deleted')
            tombstone = metadata(deleted_fd, profile, deleted / profile)
            if tombstone is not None and not (stat.S_ISREG(tombstone[3]) or stat.S_ISDIR(tombstone[3])):
                raise ValueError('profile tombstone type unknown')
        home_info = metadata(profiles_fd, profile, home)
        if home_info is None:
            return result(False, 'profile-home-missing')
        home_fd = open_directory(home, profiles_fd, profile)
        if tombstone is not None:
            return result(False, 'profile-tombstoned')
        markers = [metadata(home_fd, marker, home / marker) for marker in MARKERS]
        for identity in markers:
            if identity is not None and (not stat.S_ISREG(identity[3]) or identity[4] != 1):
                raise ValueError('profile identity marker type unknown')
        return result(any(identity is not None for identity in markers),
                      'identity-present' if any(identity is not None for identity in markers) else 'ghost-profile')
    except OSError:
        raise ValueError('profile live observation unavailable') from None
    finally:
        for fd in reversed(fds):
            os.close(fd)
