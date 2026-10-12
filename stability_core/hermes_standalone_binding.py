"""Compose trusted launch observations; not runtime qualification or authority.

No effective-environment reader is installed here. A unit Environment projection
is insufficient: only a runtime-owned reader resolving every source below may
construct LaunchEnvironmentEvidence. Action payloads/metadata are not readers.
Source digests bind observations; they do not approve a runtime artifact.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat

from .effect_capability import (UnitBinding, UnitEffectiveConfiguration, EffectOperation,
                                FileBinding, EffectRequest, SchemaBinding)
from .hermes_profile_config import ProfileConfigEvidence
from .hermes_unit_route import validate_profile_argv

ENVIRONMENT_SOURCES = frozenset({
    'unit-properties', 'environment-files', 'manager-environment',
    'launcher-environment', 'dotenv-resolution', 'profile-home-resolution',
})
_HASH = re.compile(r'[0-9a-f]{64}')


@dataclass(frozen=True)
class LaunchSourceEvidence:
    source: str
    reference: str  # Reader-owned origin, e.g. unit/property or resolved file.
    sha256: str     # Digest of the bounded source snapshot, not credentials.


@dataclass(frozen=True)
class LaunchEnvironmentEvidence:
    unit: str
    owner_uid: int
    node_id: str
    generation: str
    runtime_root: Path
    effective_home: Path
    sources: tuple[LaunchSourceEvidence, ...]
    # Real reader must resolve these, not merely assert coverage=True. Missing
    # sources, unresolved substitutions or unsupported launch paths are refused.
    unresolved: tuple[str, ...] = ()
    action_authorized: bool = False

    def __post_init__(self):
        if self.action_authorized is not False:
            raise ValueError('launch evidence is not authority')


@dataclass(frozen=True)
class StandaloneShimEvidence:
    profile_parser_sha256: str
    gateway_route_sha256: str
    home_resolver_sha256: str
    semantics: str  # Qualified source interpretation, not a version allowlist.
    action_authorized: bool = False

    def __post_init__(self):
        if self.action_authorized is not False:
            raise ValueError('shim evidence is not authority')


@dataclass(frozen=True)
class StandaloneProfileEvidence:
    profile: str
    unit: str
    owner_uid: int
    home: Path
    evidence_digest: str
    topology: str = 'explicit-standalone-shim'
    artifact_approved: bool = False
    action_authorized: bool = False

    def __post_init__(self):
        if self.action_authorized is not False or self.artifact_approved is not False:
            raise ValueError('topology evidence cannot qualify or authorize runtime')


def _hash(value):
    return type(value) is str and _HASH.fullmatch(value) is not None


def bind_standalone_profile(binding, config, environment, shim, *, profile):
    """Trusted-reader composition only; caller still owns freshness/capability.

    Positive output proves agreement of supplied observations. It is not proof
    that typed objects came from real readers, nor proof of exclusive residency.
    Missing effective source coverage never produces positive output. No default
    reader, fallback, artifact allowlist or mutation is provided.
    """
    if (type(binding) is not UnitBinding or type(config) is not ProfileConfigEvidence
            or type(environment) is not LaunchEnvironmentEvidence
            or type(shim) is not StandaloneShimEvidence):
        raise ValueError('standalone reader evidence missing')
    uid = binding.owner_uid
    if type(uid) is not int or uid < 0:
        raise ValueError('explicit runtime owner required')
    if (type(profile) is not str or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', profile)
            or profile == 'default'):
        raise ValueError('standalone profile target refused')
    request = binding.request
    if type(request) is not EffectRequest:
        raise ValueError('standalone request evidence missing')
    expected_target = {'hermes.profile.lifecycle': f'hermes-profile:{profile}',
                       'hermes.gateway.restart': f'hermes-gateway:{profile}'}.get(request.action_type)
    if request.operation is not EffectOperation.SYSTEMD_UNIT or request.target != expected_target or expected_target is None:
        raise ValueError('standalone request target mismatch')
    unit = f'hermes-gateway-{profile}.service'
    effective = binding.effective_config
    if (binding.unit != unit or type(effective) is not UnitEffectiveConfiguration
            or type(binding.fragment) is not FileBinding or binding.fragment.request != request
            or effective.coverage != 'complete' or effective.node_id != request.node_id
            or effective.generation != request.generation
            or effective.fragment_path != binding.fragment.path
            or binding.fragment.path.name != unit
            or effective.dropin_paths != tuple(item.path for item in binding.dropin_files)):
        raise ValueError('standalone effective unit scope incomplete')
    if (type(binding.runtime_owner_ref) is not str or not binding.runtime_owner_ref
            or not _hash(binding.executable_sha256)
            or any(type(item) is not FileBinding or item.request != request or not _hash(item.sha256)
                   or item.schema != SchemaBinding('systemd-unit-v1', request.target, binding.runtime_owner_ref)
                   for item in (binding.fragment, *binding.dropin_files))):
        raise ValueError('standalone unit source binding incomplete')
    validate_profile_argv(effective.execstart_argv, profile)
    if effective.execstart_argv[0] != str(binding.executable_entry or binding.executable):
        raise ValueError('standalone executable route mismatch')
    root, home = environment.runtime_root, environment.effective_home
    if (not isinstance(root, Path) or not isinstance(home, Path)
            or not root.is_absolute() or '..' in root.parts
            or home != root / 'profiles' / profile
            or config.home != home or config.profile != profile):
        raise ValueError('standalone effective home mismatch')
    if (environment.unit != unit or type(environment.owner_uid) is not int
            or environment.owner_uid != uid or environment.node_id != request.node_id
            or environment.generation != request.generation
            or type(environment.unresolved) is not tuple or environment.unresolved):
        raise ValueError('standalone effective environment unresolved')
    sources = environment.sources
    if (type(sources) is not tuple or len(sources) != len(ENVIRONMENT_SOURCES)
            or any(type(item) is not LaunchSourceEvidence for item in sources)
            or {item.source for item in sources} != ENVIRONMENT_SOURCES
            or any(type(item.reference) is not str or not item.reference
                   or len(item.reference) > 1024 or not _hash(item.sha256) for item in sources)):
        raise ValueError('standalone environment source coverage incomplete')
    if (config.standalone is not True or not _hash(config.sha256)
            or type(config.identity) is not tuple or len(config.identity) != 7
            or any(type(value) is not int or value < 0 for value in config.identity)
            or config.identity[2] != uid or not stat.S_ISREG(config.identity[3])
            or config.identity[3] & 0o022 or config.identity[4] > 65536):
        raise ValueError('explicit standalone config evidence missing')
    if (shim.semantics != 'named-profile-standalone-truthy-before-multiplex-v1'
            or not all(_hash(value) for value in (shim.profile_parser_sha256,
                       shim.gateway_route_sha256, shim.home_resolver_sha256))):
        raise ValueError('standalone shim semantics missing')
    manifest = {
        'profile': profile, 'unit': unit, 'ownerUid': uid, 'node': request.node_id,
        'generation': request.generation, 'home': str(home),
        'argv': effective.execstart_argv, 'executableSha256': binding.executable_sha256,
        'unitSources': [(str(item.path), item.sha256, item.identity)
                        for item in (binding.fragment, *binding.dropin_files)],
        'configSha256': config.sha256, 'configIdentity': config.identity,
        'sources': sorted((s.source, s.reference, s.sha256) for s in sources),
        'shim': (shim.semantics, shim.profile_parser_sha256,
                 shim.gateway_route_sha256, shim.home_resolver_sha256),
    }
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    return StandaloneProfileEvidence(profile, unit, uid, home, digest)
