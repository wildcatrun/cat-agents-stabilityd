"""Whole in-process pipeline qualification with the actual action ledger schema."""
import json
from collections import deque
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from stability_core.action_ledger import ActionLedger
from stability_core.event_pipeline_v2 import EventPipelineV2


class RotationEvidence:
    """Check chronological byte accounting, not historical inode uniqueness.

    Freed inode numbers can be allocated again. Each replacement still changes
    the adjacent identity because the old target and new temporary file coexist.
    """
    def __init__(self, max_active_bytes=8388608):
        self.limit = max_active_bytes
        self.identity = None
        self.active_bytes = 0
        self.tail = deque(maxlen=50)
        self.rotations = 0

    def observe(self, identity, active_bytes, events):
        lines = [(json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n").encode()
                 for event in events]
        incoming_bytes = sum(map(len, lines))
        must_rotate = self.active_bytes + incoming_bytes > self.limit
        changed = self.identity is not None and identity != self.identity
        if must_rotate:
            if not events or not changed:
                raise AssertionError("required rotation did not replace the adjacent file identity")
            expected_bytes = sum(map(len, self.tail)) + incoming_bytes
            if active_bytes != expected_bytes:
                raise AssertionError("rotation did not preserve exactly the prior fifty lines and incoming bytes")
            self.rotations += 1
        else:
            if changed:
                raise AssertionError("unexpected file replacement below the default capacity")
            if active_bytes != self.active_bytes + incoming_bytes:
                raise AssertionError("append byte accounting changed without eligible rotation")
        if active_bytes > self.limit:
            raise AssertionError("active stream exceeded its configured capacity")
        self.identity = identity
        self.active_bytes = active_bytes
        self.tail.extend(lines)
        return must_rotate

    def require_rotations(self, minimum=2):
        if self.rotations < minimum:
            raise AssertionError("actual default-size JSONL rotation must occur at least twice")


class EventPipelineContinuousQualificationTests(unittest.TestCase):
    def test_4208_mixed_healthy_cycles_with_actual_ledger_and_owner_recovery(self):
        start = time.monotonic()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "state.db"
            with ActionLedger(path):
                pass
            connection = sqlite3.connect(path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            info = path.stat()
            identity = (info.st_dev, info.st_ino)
            pipeline = None
            samples, expected = [], []
            rotation_evidence = RotationEvidence()
            def reopen(initialize=False):
                return EventPipelineV2(connection, path, identity, root / "events.jsonl",
                                       root / "archive", initialize=initialize)
            try:
                pipeline = reopen(True)
                self.assertEqual(pipeline.stream.max_active_bytes, 8388608)
                for n in range(4208):
                    # Empty healthy cycles are the normal daemon path; real
                    # findings still retain exact CLI order through retirement.
                    events = [] if n % 3 else [{"tsEpoch": n, "cycle": n, "message": "synthetic" + "x" * 16384}]
                    expected.extend(events)
                    result = pipeline.record(events)
                    self.assertEqual(result["export"]["coverage"], "receipt-clear")
                    self.assertLessEqual(connection.execute("SELECT COUNT(*) FROM event_v2_generations").fetchone()[0], 32)
                    self.assertLessEqual(len(pipeline.core.prunable_archive_requests()), 9)
                    self.assertLessEqual(len(list(pipeline.archive.root.iterdir())), 20)
                    stream_info = (root/"events.jsonl").stat()
                    rotated = rotation_evidence.observe(
                        (stream_info.st_dev, stream_info.st_ino), stream_info.st_size, events)
                    if rotated:
                        self.assertEqual(pipeline.stream.latest(), expected[-50:])
                    if n and n % 257 == 0:
                        pipeline.close()
                        pipeline = reopen()
                    if (n + 1) % 512 == 0 or n == 4207:
                        sample = {"cycles": n + 1, "elapsedSeconds": round(time.monotonic()-start, 2),
                                  "hotRows": connection.execute("SELECT COUNT(*) FROM event_v2_rows").fetchone()[0],
                                  "hotGenerations": connection.execute("SELECT COUNT(*) FROM event_v2_generations").fetchone()[0],
                                  "catalog": len(pipeline.core.prunable_archive_requests()),
                                  "archiveFiles": len(list(pipeline.archive.root.iterdir())),
                                  "archiveBytes": sum(p.stat().st_size for p in pipeline.archive.root.iterdir()),
                                  "pages": connection.execute("PRAGMA page_count").fetchone()[0],
                                  "dbAndSidecarsBytes": sum(p.stat().st_size for p in root.glob("state.db*") if p.is_file()),
                                  "activeBytes": (root/"events.jsonl").stat().st_size,
                                  "actualRotations": rotation_evidence.rotations}
                        samples.append(sample)
                        print(json.dumps({"qualification":"pipeline-v2-continuous", **sample}), flush=True)
                        self.assertLess(sample["dbAndSidecarsBytes"]+sample["archiveBytes"]+sample["activeBytes"], 16*1024*1024)
                        self.assertLessEqual(sample["activeBytes"], 8388608)
                self.assertEqual(pipeline.core.retention_state()["frontiers"], {"stabilityd": 4176})
                self.assertEqual(pipeline.core.retention_state(), pipeline.archive.read_witness())
                self.assertEqual(pipeline.stream.latest(), expected[-50:])
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM action_ledger").fetchone()[0], 0)
                rotation_evidence.require_rotations()
                late = samples[-4:]
                self.assertTrue(all(s["hotGenerations"] == 32 and s["catalog"] == 9 and s["archiveFiles"] == 20 for s in late))
                self.assertLessEqual(max(s["pages"] for s in late)-min(s["pages"] for s in late), 16)
                self.assertLessEqual(max(s["archiveBytes"] for s in late)-min(s["archiveBytes"] for s in late), 16384)
            finally:
                if pipeline is not None:
                    pipeline.close()
                connection.close()


if __name__ == "__main__":
    unittest.main()
