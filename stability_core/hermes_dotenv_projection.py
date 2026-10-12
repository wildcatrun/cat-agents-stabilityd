"""Fresh-start dotenv governance projection; never a complete launch certificate.

The runtime-owned caller supplies measured parser functions, not an implicit
import of the host's dotenv package. No sanitizer, reload history, secret manager
or managed overlay is executed. Those remain unresolved launch sources.
"""
from dataclasses import dataclass
import ast
import hashlib
import io
from pathlib import Path
import re

from .hermes_environment_source import (
    _read_environment_source_projection, read_environment_sources,
)

CONTROL_KEYS = frozenset({'HOME', 'HERMES_HOME', 'GATEWAY_MULTIPLEX_PROFILES', 'PYTHONPATH',
                          'HERMES_MANAGED_DIR', 'PYTEST_CURRENT_TEST', 'HERMES_UPDATE_POST_SWAP'})
IMPORT_KEYS = frozenset({'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONINSPECT',
                         'LD_PRELOAD', 'LD_LIBRARY_PATH'})
_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}')
_HASH = re.compile(r'[0-9a-f]{64}')
_UNKNOWN, _ABSENT, _BARE = object(), object(), object()


@dataclass(frozen=True)
class ParserSource:
    role: str
    path: Path
    sha256: str


@dataclass(frozen=True)
class TrustedDotenvParser:
    version: str
    sources: tuple
    tokenize: object
    variables: object


@dataclass(frozen=True)
class DotenvLayer:
    path: Path
    optional: bool = False
    override: bool = True


@dataclass(frozen=True)
class DotenvLayersProjection:
    layer_sources: tuple
    parser_version: str
    parser_sources: tuple
    governance_values: tuple
    defined_governance_keys: tuple
    unresolved_governance_keys: tuple
    layer_import_influence_digests: tuple
    scope: str = 'fresh-first-pass-ordered-layers'
    effective_coverage: str = 'incomplete'
    artifact_approved: bool = False
    action_authorized: bool = False

    def __post_init__(self):
        if (self.scope != 'fresh-first-pass-ordered-layers' or self.effective_coverage != 'incomplete'
                or self.artifact_approved is not False or self.action_authorized is not False):
            raise ValueError('dotenv layers cannot certify or authorize launch')


@dataclass(frozen=True)
class DotenvGovernanceProjection:
    source_identity: object
    parser_version: str
    parser_sources: tuple
    governance_values: tuple
    defined_governance_keys: tuple
    unresolved_governance_keys: tuple
    import_influence_digests: tuple
    scope: str = 'fresh-first-pass-single-layer'
    effective_coverage: str = 'incomplete'
    artifact_approved: bool = False
    action_authorized: bool = False

    def __post_init__(self):
        if (self.scope != 'fresh-first-pass-single-layer' or self.effective_coverage != 'incomplete'
                or self.artifact_approved is not False or self.action_authorized is not False):
            raise ValueError('dotenv projection cannot certify or authorize launch')


def _parser_identity(parser, uid):
    if (type(parser) is not TrustedDotenvParser or type(parser.sources) is not tuple
            or len(parser.sources) != 3 or type(parser.version) is not str
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', parser.version)
            or {s.role for s in parser.sources if type(s) is ParserSource} != {'parser', 'variables', 'version'}):
        raise ValueError('dotenv parser identity refused')
    by_role = {s.role: s for s in parser.sources}
    for source in parser.sources:
        if (type(source.path) is not type(Path('/')) or type(source.sha256) is not str
                or _HASH.fullmatch(source.sha256) is None):
            raise ValueError('dotenv parser identity refused')
    for role, function, name in (('parser', parser.tokenize, 'parse_stream'),
                                 ('variables', parser.variables, 'parse_variables')):
        code = getattr(function, '__code__', None)
        if (not callable(function) or code is None or code.co_name != name
                or Path(code.co_filename) != by_role[role].path):
            raise ValueError('dotenv parser function binding refused')
    evidence = read_environment_sources(tuple((s.path, False) for s in parser.sources), owner_uid=uid)
    if any(e.sha256 != s.sha256 for e, s in zip(evidence, parser.sources)):
        raise ValueError('dotenv parser source drift')
    def version(raw):
        tree = ast.parse(raw)
        values = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == '__version__' for t in node.targets)
                  and isinstance(node.value, ast.Constant)]
        if values != [parser.version]: raise ValueError('version mismatch')
        return parser.version
    version_evidence, _ = _read_environment_source_projection(by_role['version'].path,
                                        owner_uid=uid, projector=version)
    if version_evidence.sha256 != by_role['version'].sha256:
        raise ValueError('dotenv parser source drift')
    return evidence


def _parent_states(parent_values, known_absent, unknown_dependencies, context):
    if (context != 'fresh-first-pass'
            or type(parent_values) is not dict or not set(parent_values) <= CONTROL_KEYS
            or type(known_absent) is not frozenset or type(unknown_dependencies) is not frozenset
            or len(known_absent) + len(unknown_dependencies) > 256
            or any(type(k) is not str or _NAME.fullmatch(k) is None
                   for k in known_absent | unknown_dependencies)
            or set(parent_values) & (known_absent | unknown_dependencies)
            or known_absent & unknown_dependencies
            or any(type(v) is not str or len(v) > 4096 or '\x00' in v for v in parent_values.values())):
        raise ValueError('dotenv projection context refused')
    return {k: parent_values.get(k, _ABSENT if k in known_absent else _UNKNOWN) for k in CONTROL_KEYS}


def _project_layer(raw, *, parser, parent, override):
    """Private ephemeral states: never feed redacted public values into a layer."""
    if b'\x00' in raw or raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        raise ValueError('dotenv sanitizer required')
    try: text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        text = (raw[3:] if raw.startswith(b'\xef\xbb\xbf') else raw).decode('latin-1')
    resolved, output, defined, influences = {}, dict(parent), set(), {}
    for count, assignment in enumerate(parser.tokenize(io.StringIO(text))):
        if count >= 1024 or assignment.error is not False:
            raise ValueError('dotenv tokenizer refused')
        name, value = assignment.key, assignment.value
        if name is None: continue
        if type(name) is not str or _NAME.fullmatch(name) is None:
            raise ValueError('dotenv assignment refused')
        if value is not None and (type(value) is not str or len(value) > 4096 or '\x00' in value):
            raise ValueError('dotenv assignment budget')
        if name in IMPORT_KEYS:
            influences[name] = hashlib.sha256((value or '').encode()).hexdigest()
        if name not in CONTROL_KEYS:
            resolved[name] = _BARE if value is None else _UNKNOWN
            continue
        defined.add(name)
        state = _BARE if value is None else ''
        if value is not None:
            parts, unresolved = [], False
            for atom_count, atom in enumerate(parser.variables(value)):
                if atom_count >= 256: raise ValueError('dotenv interpolation budget')
                if hasattr(atom, 'name'):
                    dependency, default = atom.name, atom.default
                    if (type(dependency) is not str or len(dependency) > 128
                            or (default is not None and (type(default) is not str or len(default) > 4096))):
                        raise ValueError('dotenv interpolation refused')
                    if dependency not in CONTROL_KEYS:
                        unresolved = True; continue
                    lookup = resolved.get(dependency, parent.get(dependency, _UNKNOWN)) if override else parent.get(dependency, _UNKNOWN)
                    if not override and lookup is _ABSENT:
                        lookup = resolved.get(dependency, _ABSENT)
                    if lookup is _UNKNOWN: unresolved = True
                    elif lookup is _ABSENT: parts.append(default if default is not None else '')
                    elif lookup is _BARE: parts.append('')
                    else: parts.append(lookup)
                else:
                    literal = getattr(atom, 'value', None)
                    if type(literal) is not str or len(literal) > 4096:
                        raise ValueError('dotenv literal refused')
                    parts.append(literal)
                if sum(map(len, parts)) > 4096: raise ValueError('dotenv resolved value budget')
            state = _UNKNOWN if unresolved else ''.join(parts)
        resolved[name] = state
    # Hermes resolves the whole assignment list first, then publishes the
    # final value per key. A later bare duplicate suppresses the earlier
    # assignment rather than publishing that earlier value.
    for name, state in resolved.items():
        if name not in CONTROL_KEYS: continue
        if state is _BARE: continue  # bare key is not published into os.environ
        if override or parent[name] is _ABSENT:
            output[name] = state
        elif parent[name] is _UNKNOWN:
            output[name] = _UNKNOWN  # Unknown presence cannot authorize override=False.
    return output, defined, influences
def _redact_states(output):
    values, unresolved = [], []
    for key, value in sorted(output.items()):
        if value is _UNKNOWN: unresolved.append(key)
        elif value is not _ABSENT:
            if key == 'PYTHONPATH':
                values.append((key, 'sha256:' + hashlib.sha256(value.encode()).hexdigest()))
                if value: unresolved.append(key)  # Import route itself is unqualified.
            else: values.append((key, value))
    return tuple(values), tuple(sorted(set(unresolved)))


def read_dotenv_governance(path, *, owner_uid, parser, parent_values,
                           known_absent=frozenset(), unknown_dependencies=frozenset(),
                           override=True, optional=False, context='fresh-first-pass'):
    """One same-FD projection; preserves the existing redacted public contract."""
    if type(override) is not bool or type(optional) is not bool:
        raise ValueError('dotenv projection context refused')
    parent = _parent_states(parent_values, known_absent, unknown_dependencies, context)
    before_parser = _parser_identity(parser, owner_uid)
    identity, projection = _read_environment_source_projection(path, owner_uid=owner_uid,
        optional=optional, projector=lambda raw: _project_layer(raw, parser=parser, parent=parent, override=override))
    if _parser_identity(parser, owner_uid) != before_parser:
        raise ValueError('dotenv parser identity changed')
    output, defined, influences = projection if projection is not None else (parent, set(), {})
    values, unresolved = _redact_states(output)
    return DotenvGovernanceProjection(identity, parser.version, before_parser, values,
               tuple(sorted(defined)), unresolved, tuple(sorted(influences.items())))


def read_dotenv_governance_layers(layers, *, owner_uid, parser, parent_values,
                                  known_absent=frozenset(), unknown_dependencies=frozenset(),
                                  context='fresh-first-pass'):
    """Observe a trusted resolver's ordered fresh-pass layer set, not its completeness.

    The caller determines actual installed loading order/selection. There is no
    discovery of managed/external sources or implicit default path. Missing
    optional layers are fenced absence, not empty publications. Internal raw
    controls exist only while resolving; outputs are redacted once at the end.
    A final full ordered source sweep rejects earlier-layer drift while parsing
    later files. No os.environ writes, sanitizer or prior-pass peeling occurs.
    """
    if type(layers) is not tuple or not 1 <= len(layers) <= 32:
        raise ValueError('dotenv layer set budget refused')
    paths = []
    for layer in layers:
        if (type(layer) is not DotenvLayer or not isinstance(layer.path, Path)
                or type(layer.optional) is not bool or type(layer.override) is not bool
                or layer.path in paths):
            raise ValueError('dotenv layer set refused')
        paths.append(layer.path)
    state = _parent_states(parent_values, known_absent, unknown_dependencies, context)
    before_parser = _parser_identity(parser, owner_uid)
    identities, defined, influences = [], set(), []
    for index, layer in enumerate(layers):
        identity, projection = _read_environment_source_projection(layer.path, owner_uid=owner_uid,
            optional=layer.optional,
            projector=lambda raw, parent=state, override=layer.override:
                _project_layer(raw, parser=parser, parent=parent, override=override))
        identities.append(identity)
        if projection is not None:
            state, layer_defined, layer_influences = projection
            defined.update(layer_defined)
            influences.extend((index, key, digest) for key, digest in sorted(layer_influences.items()))
    final_sources = read_environment_sources(tuple((l.path, l.optional) for l in layers), owner_uid=owner_uid)
    if tuple(identities) != final_sources:
        raise ValueError('dotenv ordered source drift')
    if _parser_identity(parser, owner_uid) != before_parser:
        raise ValueError('dotenv parser identity changed')
    values, unresolved = _redact_states(state)
    return DotenvLayersProjection(tuple((identity, layer.optional, layer.override)
                                       for identity, layer in zip(final_sources, layers)),
        parser.version, before_parser, values, tuple(sorted(defined)), unresolved, tuple(influences))
