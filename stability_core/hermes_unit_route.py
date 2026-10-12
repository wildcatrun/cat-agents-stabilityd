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
