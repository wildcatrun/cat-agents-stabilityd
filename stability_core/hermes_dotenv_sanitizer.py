"""Observe installed sanitizer's no-rewrite subset; never sanitize live files."""
from dataclasses import dataclass
import codecs
import io

from .hermes_environment_source import _read_environment_source_projection

# Semantic lineage only. Tests qualify the pure mirror against these exact
# source functions; these are not an installed-runtime artifact allowlist.
SANITIZE_LINES_SOURCE_SHA256 = 'a612cbc18eb91ba7b4d2da9df636bf8951659f876378d86487d246ab6ca7598f'
SANITIZER_ROUTE_SOURCE_SHA256 = 'dab8917fb632ad9b7286e6f398978c105c09b76de84afd5654398d59d44d311d'
SOURCE_LINEAGE = (('config._sanitize_env_lines', SANITIZE_LINES_SOURCE_SHA256),
                  ('env_loader._sanitize_env_file_if_needed', SANITIZER_ROUTE_SOURCE_SHA256))


@dataclass(frozen=True)
class DotenvSanitizerObservation:
    source_identity: object
    rewrite_required: object
    reason: str
    source_semantics: tuple = SOURCE_LINEAGE
    effective_coverage: str = 'incomplete'
    artifact_approved: bool = False
    action_authorized: bool = False

    def __post_init__(self):
        allowed = {'no-rewrite-observed', 'rewrite-required', 'utf16-rewrite-required',
                   'source-missing', 'utf32-skipped-unqualified', 'utf16-decode-skipped',
                   'leading-replacement-skipped', 'invalid-utf8-unqualified', 'line-budget-unqualified'}
        expected = (False if self.reason == 'no-rewrite-observed' else
                    True if self.reason in {'rewrite-required', 'utf16-rewrite-required'} else None)
        if (self.rewrite_required is not expected
                or self.reason not in allowed or self.source_semantics != SOURCE_LINEAGE
                or self.effective_coverage != 'incomplete' or self.artifact_approved is not False
                or self.action_authorized is not False):
            raise ValueError('sanitizer observation cannot certify or authorize launch')


def _sanitize_lines(lines):
    """Pure mirror of qualified config.py function; inputs/outputs stay private."""
    sanitized = []
    for line in lines:
        raw = line.rstrip('\r\n')
        stripped = raw.strip()
        sanitized.append((raw if not stripped or stripped.startswith('#') else stripped) + '\n')
    return sanitized


def _observe(raw):
    # UTF32 must be checked before its UTF16 prefix, matching installed route.
    if raw.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return None, 'utf32-skipped-unqualified'
    force_rewrite = raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE))
    try:
        with io.TextIOWrapper(io.BytesIO(raw), encoding='utf-16' if force_rewrite else 'utf-8-sig',
                              errors='strict' if force_rewrite else 'replace', newline=None) as handle:
            original = handle.readlines()
    except UnicodeDecodeError:
        return None, 'utf16-decode-skipped'
    if len(original) > 4096:
        return None, 'line-budget-unqualified'
    if not force_rewrite:
        if original and original[0].startswith('\ufffd'):
            return None, 'leading-replacement-skipped'
        # Installed errors=replace may alter interior undecodable data before
        # rewrite. Its parser can later fall back to latin1. Don't call that safe.
        try: raw.decode('utf-8-sig')
        except UnicodeDecodeError: return None, 'invalid-utf8-unqualified'
    stripped = [line.replace('\x00', '') for line in original]
    sanitized = _sanitize_lines(stripped)
    if force_rewrite:
        return True, 'utf16-rewrite-required'
    changed = sanitized != original
    return changed, 'rewrite-required' if changed else 'no-rewrite-observed'


def observe_dotenv_sanitizer(path, *, owner_uid, optional=False):
    """Inspect real owned FD bytes under final file/ancestor fences, no writes.

    False means no rewrite in this measured source-semantic subset, not complete
    dotenv/environment safety. Missing, skipped and unsupported encodings return
    None. Importability of the actual sanitizer and runtime artifact identity
    remain caller qualification responsibilities.
    """
    identity, projection = _read_environment_source_projection(path, owner_uid=owner_uid,
                                                              optional=optional, projector=_observe)
    required, reason = projection if projection is not None else (None, 'source-missing')
    return DotenvSanitizerObservation(identity, required, reason)
