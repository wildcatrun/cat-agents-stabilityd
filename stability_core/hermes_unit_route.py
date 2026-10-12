"""Validate the known profile launch route, separately from topology/authority."""
from pathlib import Path
import re


def validate_profile_argv(argv, profile):
    """Closed installed Python-module launch shape; no shell or extra options.

    The caller must independently bind executable/code, unit ownership, home,
    registry scope and nonmultiplex topology before any mechanical operation.
    """
    if not isinstance(profile, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', profile):
        raise ValueError('profile route target refused')
    if (type(argv) is not tuple or len(argv) != 7 or any(type(a) is not str for a in argv)
            or not Path(argv[0]).is_absolute() or '..' in Path(argv[0]).parts
            or Path(argv[0]).name not in {'python', 'python3', 'python3.12'}
            or argv[1:] != ('-m', 'hermes_cli.main', '--profile', profile, 'gateway', 'run')):
        raise ValueError('profile unit launch route unknown')
    return profile

from dataclasses import dataclass

@dataclass(frozen=True)
class ProfilePreparseHome:
    profile: str
    runtime_root: Path
    home: Path
    stage: str = 'profile-preparse-before-dotenv'
    effective_coverage: str = 'incomplete'
    action_authorized: bool = False

    def __post_init__(self):
        if (self.stage != 'profile-preparse-before-dotenv'
                or self.effective_coverage != 'incomplete' or self.action_authorized is not False):
            raise ValueError('preparse home is not effective environment authority')


def resolve_explicit_profile_home(argv, profile, environment):
    """Measured installed root/profile semantics for resolved POSIX inputs only.

    Caller must supply genuinely resolved launch variables, not a property
    projection masquerading as effective env. This calculates a candidate path;
    it does not prove the installed CLI accepted a live, nontombstoned profile.
    Identity/liveness must be observed separately. Dotenv may subsequently change
    HERMES_HOME, so this result cannot be used as final profile residency.
    """
    validate_profile_argv(argv, profile)
    if profile == 'default' or type(environment) is not dict:
        raise ValueError('explicit named profile context required')
    def canonical(value):
        if (type(value) is not str or not value or len(value) > 4096
                or any(ord(c) < 32 for c in value) or '$' in value or '~' in value):
            raise ValueError('profile launch home unresolved')
        path = Path(value)
        if not path.is_absolute() or '..' in path.parts or str(path) != value:
            raise ValueError('profile launch home unresolved')
        return path
    exported = environment.get('HERMES_HOME', '')
    if type(exported) is not str:
        raise ValueError('profile launch home unresolved')
    exported = exported.strip()
    if exported == '':
        root = canonical(environment.get('HOME')) / '.hermes'
    else:
        if type(exported) is not str:
            raise ValueError('profile launch home unresolved')
        # Installed profile_root_for_env_home strips exported HERMES_HOME.
        home = canonical(exported.strip())
        root = home.parent.parent if home.parent.name == 'profiles' else home
    return ProfilePreparseHome(profile, root, root / 'profiles' / profile)
