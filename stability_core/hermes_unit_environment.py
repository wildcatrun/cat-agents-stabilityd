"""Redacted systemd environment property projection, not effective-env proof."""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shlex

PROPERTIES = frozenset({'Environment', 'EnvironmentFiles', 'PassEnvironment', 'UnsetEnvironment'})
GOVERNANCE_KEYS = frozenset({'HERMES_HOME', 'GATEWAY_MULTIPLEX_PROFILES', 'PYTHONPATH',
                             'HERMES_MANAGED_DIR', 'PYTEST_CURRENT_TEST', 'HERMES_UPDATE_POST_SWAP'})


@dataclass(frozen=True)
class EnvironmentProjection:
    source_sha256: str
    governance_values: tuple
    unset_governance_keys: tuple
    environment_files_present: bool
    pass_environment_present: bool
    effective_coverage: str = 'incomplete'
    action_authorized: bool = False

    def __post_init__(self):
        if self.effective_coverage != 'incomplete' or self.action_authorized is not False:
            raise ValueError('property projection cannot certify effective environment')


def project_environment_properties(text):
    if type(text) is not str or len(text.encode()) > 32768:
        raise ValueError('environment properties budget refused')
    properties = {}
    for line in text.splitlines():
        name, sep, value = line.partition('=')
        if not sep or name not in PROPERTIES or name in properties:
            raise ValueError('environment property coverage refused')
        properties[name] = value
    if set(properties) != PROPERTIES:
        raise ValueError('environment property coverage refused')
    try:
        values = {}
        tokens = shlex.split(properties['Environment'])
        if len(tokens) > 256: raise ValueError('too many environment variables')
        names = set()
        for token in tokens:
            name, sep, value = token.partition('=')
            if (not sep or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name)
                    or name in names or len(token) > 4096 or any(ord(c) < 32 for c in token)):
                raise ValueError('ambiguous environment variable')
            names.add(name)
            if name in GOVERNANCE_KEYS:
                if name == 'HERMES_HOME' and (not Path(value).is_absolute() or '..' in Path(value).parts):
                    raise ValueError('noncanonical runtime home')
                if name == 'HERMES_MANAGED_DIR':
                    value = value.strip()
                    if not value:
                        value = 'default-scope'
                    elif not Path(value).is_absolute() or '..' in Path(value).parts:
                        raise ValueError('noncanonical managed scope')
                if name == 'PYTEST_CURRENT_TEST':
                    value = 'present'  # Installed resolver tests membership, even for empty value.
                if name == 'HERMES_UPDATE_POST_SWAP':
                    value = 'true' if value == '1' else 'false'
                if name == 'GATEWAY_MULTIPLEX_PROFILES':
                    normalized = value.strip().lower()
                    value = ('true' if normalized in {'1', 'true', 'yes', 'on'} else
                             'false' if normalized in {'0', 'false', 'no', 'off'} else 'unknown')
                if name == 'PYTHONPATH':
                    value = 'sha256:' + hashlib.sha256(value.encode()).hexdigest()
                values[name] = value
        unset = {token.partition('=')[0] for token in shlex.split(properties['UnsetEnvironment'])}
    except Exception:
        raise ValueError('environment property interpretation refused') from None
    return EnvironmentProjection(hashlib.sha256(text.encode()).hexdigest(), tuple(sorted(values.items())),
                                 tuple(sorted(unset & GOVERNANCE_KEYS)),
                                 bool(properties['EnvironmentFiles'].strip()),
                                 bool(properties['PassEnvironment'].strip()))

def resolve_environment_file_sources(text):
    """Closed observed systemctl representation; not full launch environment.

    Trusted caller must obtain properties from the bound unit, and bind each
    returned path using the environment-source reader before consuming it.
    """
    project_environment_properties(text)
    value = next(line.partition('=')[2] for line in text.splitlines()
                 if line.partition('=')[0] == 'EnvironmentFiles')
    try:
        if "\\" in value:
            raise ValueError("escaped file representation unknown")
        tokens = shlex.split(value)
        if len(tokens) > 64 or len(tokens) % 2:
            raise ValueError('file source budget')
        result = []
        seen = set()
        for index in range(0, len(tokens), 2):
            raw, marker = tokens[index:index+2]
            path = Path(raw)
            if (not path.is_absolute() or '..' in path.parts or str(path) != raw
                    or len(raw) > 4096 or any(ord(c) < 32 for c in raw)
                    or any(c in raw for c in '*?[%') or path in seen
                    or marker not in {'(ignore_errors=yes)', '(ignore_errors=no)'}):
                raise ValueError('file source representation unknown')
            seen.add(path)
            result.append((path, marker == '(ignore_errors=yes)'))
        return tuple(result)
    except Exception:
        raise ValueError('environment file sources unresolved') from None
