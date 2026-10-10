"""Whole in-process pipeline qualification with the actual action ledger schema."""
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest

from stability_core.action_ledger import ActionLedger
from stability_core.event_pipeline_v2 import EventPipelineV2


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
            samples, expected, stream_inodes = [], [], set()
            def reopen(initialize=False):
                return EventPipelineV2(connection, path, identity, root / "events.jsonl",
                                       root / "archive", initialize=initialize)
            try:
                pipeline = reopen(True)
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
                    stream_inodes.add((root/"events.jsonl").stat().st_ino)
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
                                  "activeBytes": (root/"events.jsonl").stat().st_size}
                        samples.append(sample)
                        print(json.dumps({"qualification":"pipeline-v2-continuous", **sample}), flush=True)
                        self.assertLess(sample["dbAndSidecarsBytes"]+sample["archiveBytes"]+sample["activeBytes"], 16*1024*1024)
                        self.assertLessEqual(sample["activeBytes"], 8388608)
                self.assertEqual(pipeline.core.retention_state()["frontiers"], {"stabilityd": 4176})
                self.assertEqual(pipeline.core.retention_state(), pipeline.archive.read_witness())
                self.assertEqual(pipeline.stream.latest(), expected[-50:])
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM action_ledger").fetchone()[0], 0)
                self.assertGreaterEqual(len(stream_inodes), 3, "actual default-size JSONL rotation must occur")
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
