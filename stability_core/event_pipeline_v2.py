"""In-process local observation pipeline. Never grants runtime execution rights."""
from __future__ import annotations

import datetime as dt

from .event_outbox import EventOutboxError
from .event_outbox_v2 import EventOutboxV2
from .event_stream_v2 import ArchivePublisher, EventStream, EventStreamError
from .preflight_recovery import load_action_ledger_connection_readonly
from .event_v2_contract import canonical


# Nine segments (eight retained plus one publication) fit the publisher's
# 64 MiB byte quota even at the admitted segment ceiling, with control reserve.
ARCHIVE_BYTES = 6 * 1024 * 1024
ARCHIVE_RECORDS = 4096


class EventPipelineV2:
    def __init__(self, connection, path, connection_identity, target, archive_root, *,
                 initialize=False, keep_generations=32, keep_archives=8):
        if type(keep_generations) is not int or not 1 <= keep_generations <= 64:
            raise EventOutboxError("pipeline-retry-window-invalid")
        if type(keep_archives) is not int or not 1 <= keep_archives <= 16:
            raise EventOutboxError("pipeline-archive-window-invalid")
        self.connection = connection
        self.core = None
        self.keep_generations = keep_generations
        self.keep_archives = keep_archives
        self.producer = "stabilityd"
        self.recovery = None
        self.last_error = None
        self.archive = ArchivePublisher(archive_root,
            max_bytes=max(67108864, (keep_archives + 2) * ARCHIVE_BYTES + 131072))
        self.stream = EventStream(target)
        kwargs = dict(connection=connection, connection_identity=connection_identity,
                      witness_path=self.archive.witness_path)
        try:
            try:
                self.core = EventOutboxV2(path, initialize=initialize, **kwargs)
            except EventOutboxError as exc:
                if str(exc) != "v2-restore-frontier-drift":
                    raise
                self.core = EventOutboxV2(path, recovery_open=True, **kwargs)
                request = self.core.recovery_archive_request()
                self.recovery = self.core.retire(self.archive.load_receipt(request))
            self.archive.initialize_witness(self.core.retention_state())
            # The core owns the canonical writer lock. Only prior contexts can
            # be interrupted; this is observation cleanup, not action recovery.
            rows = connection.execute(
                "SELECT producer,ordinal,owner_epoch FROM event_v2_generations "
                "WHERE state='open' ORDER BY ordinal LIMIT 129"
            ).fetchall()
            if len(rows) > 128:
                raise EventOutboxError("pipeline-generation-budget")
            for producer, ordinal, owner in rows:
                if owner != self.core.owner_epoch:
                    handle = self.core.load_generation(producer, ordinal, owner)
                    self.core.close_interrupted_generation(handle, self.core.owner_ended_proof(handle))
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.core is not None:
            self.core.close()
            self.core = None

    def _pins(self, catalog):
        """Conservatively retain archives while any action remains unresolved.

        Event archives do not currently have a complete action-reference index.
        Incomplete/unknown ledger coverage cannot authorize evidence removal.
        """
        loaded = load_action_ledger_connection_readonly(self.connection, limit=20, budget_ms=250)
        status = loaded.get("status")
        if status == "not-initialized":
            return set()
        if status != "available" or loaded.get("candidateCount", 0):
            return set(catalog)
        return set()

    def maintain(self):
        self.stream.drain(self.core, max_batches=2)
        catalog = self.core.prunable_archive_requests()
        ordered = sorted(catalog, key=lambda key: catalog[key]["retirement_seq"])
        pins = self._pins(catalog) | set(ordered[-self.keep_archives:])
        self.archive.prune_committed(self.core, pinned_request_digests=pins)
        row = self.connection.execute(
            "SELECT issued,retired FROM event_v2_producers WHERE producer=?", (self.producer,)
        ).fetchone()
        if row is None or row[0] - self.keep_generations <= row[1]:
            return
        # Retire one atomic observation at a time. Combining a backlog of
        # individually admissible observations can exceed the segment budget.
        frontier = min(row[0] - self.keep_generations, row[1] + 1)
        # Never skip an unfinished prefix merely because later batches finished.
        blocked = self.connection.execute(
            "SELECT 1 FROM event_v2_generations WHERE producer=? AND ordinal<=? "
            "AND state NOT IN ('sealed','interrupted') LIMIT 1", (self.producer, frontier)
        ).fetchone()
        unfinished = self.connection.execute(
            "SELECT 1 FROM event_v2_rows WHERE producer=? AND ordinal<=? "
            "AND state!='exported' LIMIT 1", (self.producer, frontier)
        ).fetchone()
        if blocked or unfinished:
            return
        request = self.core.prepare_archive(self.producer, frontier,
                                            max_records=ARCHIVE_RECORDS, max_bytes=ARCHIVE_BYTES)
        receipt = self.archive.publish(request)
        self.archive.advance_witness(request)
        self.core.retire(receipt)

    def record(self, events):
        if not isinstance(events, list):
            raise EventOutboxError("pipeline-batch-required")
        try:
            handle = self.core.begin_generation(self.producer, self.core.owner_epoch)
            # Reserve for JSON string escaping plus bounded identity/receipt
            # metadata. Reject an unarchivable observation before committing
            # any of its rows, rather than permanently pinning a valid batch.
            bound = (2 * len(canonical(events)) + 65536
                     + len(events) * (1024 + len(canonical(str(self.stream.target)))))
            if len(events) > ARCHIVE_RECORDS or bound > ARCHIVE_BYTES:
                raise EventOutboxError("pipeline-batch-archive-budget")
            receipt = self.core.record_batch(handle, events, expected_count=len(events),
                                            batch_digest=self.core.batch_digest(events))
            self.core.seal_generation(handle)
        except (EventOutboxError, ValueError, TypeError, OverflowError):
            self.close()
            raise EventOutboxError("pipeline-record-failed") from None
        except BaseException:
            # End this local writer context. A later owned context can retain
            # explicit interrupted-generation evidence instead of pinning an
            # open prefix forever after a rejected batch.
            self.close()
            raise
        try:
            self.maintain()
            self.last_error = None
        except (EventOutboxError, EventStreamError) as exc:
            # The observation batch is durable. Export/archive failure is
            # distinct from the independently governed action ledger.
            self.last_error = type(exc).__name__
        return {"record": receipt, "export": self.evidence(),
                "generationOrdinal": handle.ordinal, "scope": "local-export-receipts"}

    def evidence(self):
        now = dt.datetime.now(dt.timezone.utc)
        states = dict(self.connection.execute("SELECT state,COUNT(*) FROM event_v2_rows GROUP BY state"))
        return {"mode": "outbox-v2", "checkedAt": now.isoformat(),
                "checkedAtEpoch": int(now.timestamp()), "scope": "local-export-receipts",
                "coverage": "unknown" if self.last_error or states.get("unknown") else "pending" if states.get("pending") or states.get("exporting") else "receipt-clear",
                "states": states, "transactionalExport": True,
                "retryKeepGenerations": self.keep_generations,
                "archiveKeepSegments": self.keep_archives,
                "historyCoverage": "finite-local-history", "automaticReplay": False,
                "eventRecovery": self.recovery,
                "errorClass": self.last_error,
                "actuatorReadiness": "not-qualified-by-event-recovery"}
