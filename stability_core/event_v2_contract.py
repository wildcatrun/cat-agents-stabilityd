"""Typed local observation proofs. These never grant action execution rights."""
from __future__ import annotations
import dataclasses
import hashlib
import json
import os
import stat
from pathlib import Path

from .event_outbox import EventOutboxError

_AUTHORITY = object()

def fail(code):
    raise EventOutboxError(code) from None

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()

def digest(content):
    return hashlib.sha256(content).hexdigest()

@dataclasses.dataclass(frozen=True)
class GenerationHandle:
    store_id: str
    producer: str
    ordinal: int
    generation_uuid: str
    owner_epoch: str

@dataclasses.dataclass(frozen=True)
class OwnerEndedProof:
    store_id: str
    prior_owner_epoch: str
    current_owner_epoch: str
    lock_identity: tuple[int, int]
    _owner_context: object = dataclasses.field(repr=False, compare=False)

@dataclasses.dataclass(frozen=True)
class ExportBatch:
    store_id: str
    batch_id: str
    event_ids: tuple[str, ...]
    content: bytes
    content_digest: str

@dataclasses.dataclass(frozen=True)
class ExportIntent:
    store_id: str
    intent_id: str
    batch_id: str
    event_ids: tuple[str, ...]
    stream_id: str
    target: str
    dev: int
    inode: int
    offset: int
    content: bytes
    content_digest: str
    state: str = 'exporting'

    @property
    def length(self):
        return len(self.content)

@dataclasses.dataclass(frozen=True)
class ExportReceipt:
    intent: ExportIntent
    file_identity: tuple[int, int]
    _authority: object = dataclasses.field(repr=False, compare=False)

@dataclasses.dataclass(frozen=True)
class ArchiveRequest:
    store_id: str
    producer: str
    prior_frontier: int
    through_ordinal: int
    prior_chain: str
    prior_retirement_seq: int
    frontiers: tuple[tuple[str, int], ...]
    content: bytes
    content_digest: str
    request_digest: str
    row_count: int

    @property
    def first_ordinal(self):
        return self.prior_frontier + 1

    @property
    def chain(self):
        return digest(canonical([self.prior_chain, self.request_digest]))

    @property
    def retirement_seq(self):
        return self.prior_retirement_seq + 1

@dataclasses.dataclass(frozen=True)
class ArchiveReceipt:
    request: ArchiveRequest
    segment_path: str
    manifest_path: str
    segment_identity: tuple[int, int]
    manifest_identity: tuple[int, int]
    _authority: object = dataclasses.field(repr=False, compare=False)

def archive_manifest(request, segment_path):
    return canonical({'version': 2, 'scope': 'local-archive-observations',
        'store_id': request.store_id, 'producer': request.producer,
        'prior_frontier': request.prior_frontier, 'through_ordinal': request.through_ordinal,
        'prior_chain': request.prior_chain, 'chain': request.chain,
        'prior_retirement_seq': request.prior_retirement_seq,
        'retirement_seq': request.retirement_seq, 'frontiers': dict(request.frontiers),
        'content_digest': request.content_digest, 'request_digest': request.request_digest,
        'bytes': len(request.content), 'records': request.row_count,
        'segment': Path(segment_path).name})

def witness_value(request):
    return {'version': 2, 'storeId': request.store_id, 'retirementSeq': request.retirement_seq,
            'chain': request.chain, 'frontiers': dict(request.frontiers)}

def _read_file_verified(path, *, max_bytes, offset=0, length=None, identity=None):
    fd = None
    try:
        path = Path(path)
        if path.is_symlink(): fail('proof-file-invalid')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        before = os.fstat(fd)
        actual_identity = (before.st_dev, before.st_ino)
        if not stat.S_ISREG(before.st_mode) or identity is not None and actual_identity != identity:
            fail('proof-file-identity-changed')
        if type(offset) is not int or offset < 0: fail('proof-range-invalid')
        if length is None:
            if before.st_size > max_bytes: fail('proof-byte-budget')
            length = before.st_size
        if type(length) is not int or not 0 <= length <= max_bytes or before.st_size < offset + length:
            fail('proof-range-invalid')
        os.lseek(fd, offset, os.SEEK_SET)
        chunks = bytearray()
        while len(chunks) < length:
            part = os.read(fd, min(65536, length-len(chunks)))
            if not part: fail('proof-range-invalid')
            chunks.extend(part)
        # Receipts follow file and containing directory durability, not caller booleans.
        os.fsync(fd)
        after = os.fstat(fd)
        current = os.lstat(path)
        if ((after.st_dev, after.st_ino) != actual_identity
                or (current.st_dev, current.st_ino) != actual_identity
                or not stat.S_ISREG(current.st_mode)):
            fail('proof-file-identity-changed')
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try: os.fsync(directory)
        finally: os.close(directory)
        return bytes(chunks), actual_identity
    except EventOutboxError:
        raise
    except Exception:
        fail('proof-file-unavailable')
    finally:
        if fd is not None: os.close(fd)

def _issue_verified_export_receipt(intent):
    if not isinstance(intent, ExportIntent): fail('export-intent-invalid')
    content, identity = _read_file_verified(intent.target, max_bytes=1048576,
        offset=intent.offset, length=intent.length, identity=(intent.dev,intent.inode))
    if content != intent.content or digest(content) != intent.content_digest:
        fail('export-proof-conflict')
    return ExportReceipt(intent, identity, _AUTHORITY)

def _verify_export_receipt(receipt):
    if not isinstance(receipt, ExportReceipt) or receipt._authority is not _AUTHORITY:
        fail('export-receipt-required')
    return _issue_verified_export_receipt(receipt.intent)

def _issue_verified_receipt(request, segment_path, manifest_path):
    if not isinstance(request, ArchiveRequest): fail('archive-request-invalid')
    segment, segment_identity = _read_file_verified(segment_path, max_bytes=8388608)
    manifest, manifest_identity = _read_file_verified(manifest_path, max_bytes=65536)
    if (segment != request.content or digest(segment) != request.content_digest
            or manifest != archive_manifest(request, segment_path)):
        fail('archive-proof-conflict')
    return ArchiveReceipt(request, str(segment_path), str(manifest_path),
                          segment_identity, manifest_identity, _AUTHORITY)

def _verify_archive_receipt(receipt):
    if not isinstance(receipt, ArchiveReceipt) or receipt._authority is not _AUTHORITY:
        fail('archive-receipt-required')
    result = _issue_verified_receipt(receipt.request, receipt.segment_path, receipt.manifest_path)
    if (result.segment_identity != receipt.segment_identity or
            result.manifest_identity != receipt.manifest_identity):
        fail('archive-proof-identity-changed')
    return result
