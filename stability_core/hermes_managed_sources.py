"""Owned managed-scope source observations; no overlay execution or authority."""
from dataclasses import dataclass
from pathlib import Path
from .hermes_environment_source import read_environment_sources

@dataclass(frozen=True)
class ManagedSources:
    selected_directory: object
    selection: str
    directory_present: object
    sources: tuple
    effective_coverage: str = 'incomplete'
    action_authorized: bool = False

    def __post_init__(self):
        if self.effective_coverage != 'incomplete' or self.action_authorized is not False:
            raise ValueError('managed sources cannot authorize launch')


def observe_managed_sources(values, *, known_absent, owner_uid):
    """Mirror installed POSIX selection for resolved controls, then fence sources.

    Runtime resolver supplies genuinely resolved controls and absence knowledge.
    A missing explicit override does not fall back to /etc/hermes. Unknown
    controls, unsafe paths and unreadable sources are refused, not disabled.
    Observes both config and dotenv identities; does not execute either overlay.
    """
    keys = {'HERMES_MANAGED_DIR', 'PYTEST_CURRENT_TEST'}
    if (type(values) is not dict or not set(values) <= keys
            or type(known_absent) is not frozenset or not known_absent <= keys
            or set(values) & known_absent or set(values) | known_absent != keys
            or any(type(v) is not str or len(v) > 4096 or '\x00' in v for v in values.values())
            or type(owner_uid) is not int or owner_uid < 0):
        raise ValueError('managed scope context unresolved')
    override = values.get('HERMES_MANAGED_DIR', '').strip()
    if override:
        directory = Path(override)
        if (not directory.is_absolute() or '..' in directory.parts or str(directory) != override
                or '$' in override or '~' in override or any(ord(c) < 32 for c in override)):
            raise ValueError('managed scope path unresolved')
        selection = 'explicit-override'
    elif 'PYTEST_CURRENT_TEST' in values:
        return ManagedSources(None, 'pytest-default-disabled', None, ())
    else:
        directory, selection = Path('/etc/hermes'), 'posix-default'
    sources = read_environment_sources(((directory / '.env', True),
                                       (directory / 'config.yaml', True)), owner_uid=owner_uid)
    presence = tuple(s.missing_ancestor is None for s in sources)
    if presence[0] != presence[1]:
        raise ValueError('managed scope presence drift')
    return ManagedSources(directory, selection, presence[0], sources)
