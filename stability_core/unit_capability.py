"""Bound actual systemd properties and owned unit files; no service mutations."""
import hashlib
import os
from pathlib import Path
import re
import shlex
import stat

from .adapter_contract import sha256_file
from .effect_capability import FileBinding, SchemaBinding, UnitBinding, UnitEffectiveConfiguration


UNIT_ROOTS = (Path('/etc/systemd/system'), Path('/usr/lib/systemd/system'))
PROPERTIES = ('Id', 'LoadState', 'FragmentPath', 'DropInPaths', 'ExecStart')


def parse_unit_properties(text, unit):
    if type(text) is not str or len(text.encode()) > 32768:
        raise ValueError('unit-properties-budget')
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key not in PROPERTIES or key in values:
            raise ValueError('unit-properties-invalid')
        values[key] = value
    if set(values) != set(PROPERTIES) or values['Id'] != unit or values['LoadState'] != 'loaded':
        raise ValueError('unit-properties-incomplete')
    # systemctl's native property serialization. Reject expansion/escaped or
    # multiple command records rather than interpreting them as shell input.
    commands = re.findall(r'argv\[\]=(.*?)\s*;', values['ExecStart'])
    if len(commands) != 1 or values['ExecStart'].count('{') != 1 or values['ExecStart'].count('}') != 1:
        raise ValueError('unit-execstart-unsupported')
    command = commands[0].strip()
    if any(char in command for char in ('\\', '$', '%', '\n', '\r')):
        raise ValueError('unit-execstart-expansion')
    argv = tuple(shlex.split(command))
    if not argv or len(argv) > 128 or not Path(argv[0]).is_absolute():
        raise ValueError('unit-execstart-invalid')
    executable_paths = re.findall(r'\bpath=(.*?)\s*;', values['ExecStart'])
    if executable_paths != [argv[0]]:
        raise ValueError('unit-effective-executable-conflict')
    paths = values['DropInPaths'].split()
    if len(paths) > 16 or len(set(paths)) != len(paths) or any('\\' in p for p in paths):
        raise ValueError('unit-dropins-invalid')
    fragment = Path(values['FragmentPath'])
    drops = tuple(Path(p) for p in paths)
    if not fragment.is_absolute() or any(not p.is_absolute() for p in drops):
        raise ValueError('unit-file-path-invalid')
    return fragment, drops, argv


def _file_binding(path, request, owner, *, unit_roots=None, owner_uid=None):
    roots = UNIT_ROOTS if unit_roots is None else unit_roots
    uid = os.getuid() if owner_uid is None else owner_uid
    if type(uid) is not int or uid < 0 or not isinstance(roots, tuple) or not roots:
        raise ValueError('unit-trust-scope-invalid')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('unit-file-symlink')
    root = next((r for r in roots if isinstance(r, Path) and r.is_absolute() and r in path.parents), None)
    if root is None:
        raise ValueError('unit-file-owner-root')
    root_info = root.stat()
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid not in {0, uid}
            or root_info.st_mode & 0o022):
        raise ValueError('unit-root-owner-mode')
    if unit_roots is not None:
        for ancestor in path.parents:
            info = ancestor.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}
                    or info.st_mode & 0o022):
                raise ValueError('unit-ancestor-owner-mode')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 65536
                or before.st_uid not in {0, uid} or before.st_mode & 0o022):
            raise ValueError('unit-file-owner-mode')
        raw = bytearray()
        while len(raw) <= 65536:
            part = os.read(fd, min(8192, 65537 - len(raw)))
            if not part: break
            raw.extend(part)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        after = os.fstat(fd)
        final = path.lstat()
        if len(raw) > 65536 or identity(before) != identity(after) or identity(after) != identity(final):
            raise ValueError('unit-file-read-drift')
        return FileBinding(request, root, path, (before.st_dev, before.st_ino),
                           hashlib.sha256(raw).hexdigest(), SchemaBinding('systemd-unit-v1', request.target, owner))
    finally:
        os.close(fd)


def resolve_unit_executable(entry):
    """Resolve only owned final-component links, retaining every birth identity."""
    path = Path(entry)
    if not path.is_absolute():
        raise ValueError('unit-executable-path-invalid')
    route, seen = [], set()
    for _ in range(9):
        if any(p.is_symlink() for p in path.parents) or path in seen:
            raise ValueError('unit-executable-route-invalid')
        seen.add(path)
        parent = path.parent.stat()
        if parent.st_uid not in {0, os.getuid()} or parent.st_mode & 0o022:
            raise ValueError('unit-executable-parent-untrusted')
        before = path.lstat()
        if before.st_uid not in {0, os.getuid()}:
            raise ValueError('unit-executable-owner-invalid')
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_uid)
        if stat.S_ISLNK(before.st_mode):
            target = os.readlink(path)
            if identity(before) != identity(path.lstat()):
                raise ValueError('unit-executable-link-drift')
            route.append((str(path), identity(before), target))
            path = Path(os.path.abspath(path.parent / target))
            continue
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & 0o022 or not os.access(path, os.X_OK)):
            raise ValueError('unit-executable-owner-mode')
        route.append((str(path), identity(before), None))
        return path, tuple(route)
    raise ValueError('unit-executable-link-budget')


def read_unit_binding(request, *, unit, read_properties, clock_ms, unit_roots=None, owner_uid=None):
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', unit):
        raise ValueError('unit-name-invalid')
    fragment, drops, argv = parse_unit_properties(read_properties(unit), unit)
    owner = 'runtime-unit://' + unit
    file = _file_binding(fragment, request, owner, unit_roots=unit_roots, owner_uid=owner_uid)
    drop_files = tuple(_file_binding(p, request, owner, unit_roots=unit_roots, owner_uid=owner_uid) for p in drops)
    entry = Path(argv[0])
    executable, route = resolve_unit_executable(entry)
    digest = sha256_file(str(executable))
    if resolve_unit_executable(entry) != (executable, route):
        raise ValueError('unit-executable-route-drift')
    return UnitBinding(request, unit, file, executable, digest, owner,
                       drop_files, UnitEffectiveConfiguration(fragment, drops, argv, request.node_id,
                       request.generation, clock_ms(), 'complete'), entry, route)


def binding_identity(binding):
    """Exclude observation time; pin configuration and artifact across claims."""
    return (binding.unit, binding.fragment, binding.dropin_files, binding.executable,
            binding.executable_sha256, binding.runtime_owner_ref, binding.effective_config.fragment_path,
            binding.effective_config.dropin_paths, binding.effective_config.execstart_argv,
            binding.effective_config.node_id, binding.effective_config.generation,
            binding.executable_entry, binding.executable_route)
