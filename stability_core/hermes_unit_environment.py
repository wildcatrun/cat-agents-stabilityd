"""Redacted systemd environment property projection, not effective-env proof."""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import shlex

PROPERTIES = frozenset({'Environment', 'EnvironmentFiles', 'PassEnvironment', 'UnsetEnvironment'})
GOVERNANCE_KEYS = frozenset({'HERMES_HOME', 'GATEWAY_MULTIPLEX_PROFILES', 'PYTHONPATH'})


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
