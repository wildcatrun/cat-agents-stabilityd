"""Bound profile topology evidence; never returns config contents or credentials."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat


def standalone_value(value):
    # Installed profiles._standalone_truthy: strings use the shared token
    # parser, all other safely parsed YAML values use bool(value).
    return value.strip().lower() in {'1', 'true', 'yes', 'on'} if isinstance(value, str) else bool(value)


def retired_multiplex_value(value):
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() in {'0', 'false', 'no', 'off'}
    return not bool(value)


@dataclass(frozen=True)
class ProfileConfigEvidence:
    home: Path
    profile: str
    sha256: str
    identity: tuple
    standalone: bool
    multiplex_false_retired: bool
    action_authorized: bool = False

    def __post_init__(self):
        if self.action_authorized is not False: raise ValueError('config evidence is not authority')


def read_profile_config(home: Path, *, profile: str, runtime_root: Path, owner_uid: int):
    """Trusted caller supplies registry route and runtime root, not payload paths.

    Explicit standalone true is evidence of the installed compatibility shim,
    not an artifact/version approval or a full exclusive-owner certificate.
    """
    if (type(owner_uid) is not int or owner_uid < 0 or not isinstance(profile, str)
            or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', profile) or profile == 'default'):
        raise ValueError('profile config scope refused')
    home, root = Path(home), Path(runtime_root)
    if (not root.is_absolute() or '..' in root.parts or '..' in home.parts
            or home != root / 'profiles' / profile):
        raise ValueError('profile home route refused')
    path = home / 'config.yaml'
    identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    directory_identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_mode)
    ancestors = []
    for parent in path.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner_uid}
                or info.st_mode & 0o022):
            raise ValueError('profile config ancestor refused')
        ancestors.append((parent, directory_identity(info)))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError('profile config open refused') from None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != owner_uid
                or before.st_mode & 0o022 or before.st_size > 65536):
            raise ValueError('profile config file refused')
        raw = bytearray()
        while len(raw) <= 65536:
            chunk = os.read(fd, min(8192, 65537 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
        if (len(raw) > 65536 or identity(before) != identity(os.fstat(fd))
                or identity(before) != identity(path.lstat())):
            raise ValueError('profile config file drift')
    finally:
        os.close(fd)
    try:
        import yaml
        class StrictLoader(yaml.SafeLoader): pass
        def mapping(loader, node):
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node)
                if not isinstance(key, str) or key in result: raise ValueError('ambiguous mapping')
                result[key] = loader.construct_object(value_node)
            return result
        StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        for count, event in enumerate(yaml.parse(bytes(raw))):
            if count >= 4096 or isinstance(event, yaml.AliasEvent): raise ValueError('YAML budget')
        config = yaml.load(bytes(raw), Loader=StrictLoader)
        if not isinstance(config, dict): raise ValueError('config mapping required')
        gateway = config.get('gateway', {})
        if not isinstance(gateway, dict): raise ValueError('gateway mapping required')
        standalone = standalone_value(gateway.get('standalone'))
        multiplex = config.get('multiplex_profiles')
        if multiplex is None:
            multiplex = gateway.get('multiplex_profiles')
        retired = retired_multiplex_value(multiplex)
    except Exception:
        raise ValueError('profile config interpretation refused') from None
    if (identity(path.lstat()) != identity(before)
            or any(directory_identity(parent.lstat()) != expected for parent, expected in ancestors)):
        raise ValueError('profile config scope drift')
    return ProfileConfigEvidence(home, profile, hashlib.sha256(raw).hexdigest(), identity(before), standalone, retired)
