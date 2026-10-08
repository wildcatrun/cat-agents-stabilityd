"""Opt-in event bridge fixtures. No live config, workflow or runtime writes."""
import importlib.util
import json
import os
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from stability_core.event_outbox import EventOutbox

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('event_pipeline_bridge_test', ROOT / 'bin/cat_agents_stabilityd.py')
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


class EventPipelineBridgeTests(unittest.TestCase):
    def test_replaced_path_is_not_initialized_before_writer_rejection(self):
        replacement = self.root / 'replacement.db'
        # Uncoordinated restore is prohibited. Even rejection must not open
        # and initialize a second database at the old connection's filename.
        self.conn.execute('PRAGMA journal_mode=DELETE')
        with sqlite3.connect(replacement) as other:
            other.execute('CREATE TABLE replacement_sentinel(value TEXT)')
            other.execute("INSERT INTO replacement_sentinel VALUES('unchanged')")
            other.commit()
        os.replace(replacement, self.path)
        before = self.path.read_bytes()
        with self.assertRaises(m.EventOutboxError):
            m.db_record_event(self.conn, self.event, generation='fixture', seq=0)
        self.assertEqual(before, self.path.read_bytes())
        with sqlite3.connect(self.path) as other:
            tables = {row[0] for row in other.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertEqual(tables, {'replacement_sentinel'})
            self.assertEqual(other.execute('PRAGMA journal_mode').fetchone()[0], 'delete')

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / 'state.db'
        self.log = self.root / 'events.jsonl'
        self.patches = [mock.patch.object(m, 'STATE_DB', self.path),
                        mock.patch.object(m, 'EVENTS_JSONL', self.log),
                        mock.patch.object(m, 'ensure_dirs'),
                        mock.patch.object(m, 'EVENT_OUTBOX_ENABLED', True)]
        for patch in self.patches:
            patch.start()
        self.conn = m.init_db()
        self.event = {'ts': '2026-10-08T10:00:00+08:00', 'tsEpoch': 1000,
                      'source': 'fixture', 'component': 'fixture', 'severity': 'high',
                      'key': 'fixture', 'message': 'synthetic'}

    def tearDown(self):
        self.conn.close()
        for patch in reversed(self.patches):
            patch.stop()
        self.tmp.cleanup()

    def test_opt_in_bridge_same_context_retry_preserves_payload_and_producer(self):
        first = m.db_record_event(self.conn, self.event, generation='cycle-fixture', seq=0)
        second = m.db_record_event(self.conn, self.event, generation='cycle-fixture', seq=0)
        self.assertFalse(first['record']['duplicate'])
        self.assertTrue(second['record']['duplicate'])
        self.assertEqual(first['record']['eventId'], second['record']['eventId'])
        self.assertEqual([json.loads(line) for line in self.log.read_text().splitlines()], [self.event])
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)
        self.assertEqual(m.event_pipeline_evidence(self.conn)['coverage'], 'receipt-clear')

    def test_export_failure_is_explicit_unknown_and_retry_does_not_insert_or_append_twice(self):
        with mock.patch('stability_core.event_outbox.os.fsync', side_effect=OSError('SYNTHETIC_PRIVATE_ERROR')):
            receipt = m.db_record_event(self.conn, self.event, generation='cycle-fixture', seq=0)
        self.assertEqual(receipt['export']['coverage'], 'unknown')
        self.assertNotIn('SYNTHETIC_PRIVATE_ERROR', str(receipt))
        self.assertEqual(m.event_pipeline_evidence(self.conn)['coverage'], 'unknown')
        retry = m.db_record_event(self.conn, self.event, generation='cycle-fixture', seq=0)
        self.assertTrue(retry['record']['duplicate'])
        self.assertEqual(self.conn.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)
        self.assertEqual(len(self.log.read_text().splitlines()), 1)

    def test_existing_cycle_drains_committed_pending_once(self):
        with EventOutbox(self.path) as outbox:
            outbox.record(self.event, producer='fixture-node', generation='fixture', attempt=1, seq=0)
        self.assertEqual(m.event_pipeline_evidence(self.conn)['coverage'], 'pending')
        m.drain_event_exports(self.conn)
        m.drain_event_exports(self.conn)
        self.assertEqual(m.event_pipeline_evidence(self.conn)['coverage'], 'receipt-clear')
        self.assertEqual(len(self.log.read_text().splitlines()), 1)

    def test_legacy_mode_does_not_create_outbox_or_claim_transactional_delivery(self):
        with mock.patch.object(m, 'EVENT_OUTBOX_ENABLED', False):
            m.db_record_event(self.conn, self.event)
            meta = m.event_pipeline_evidence(self.conn)
        tables = {row[0] for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn('stability_event_outbox', tables)
        self.assertEqual(meta['coverage'], 'legacy-unverified')
        self.assertFalse(meta['transactionalExport'])

    def test_cycle_governance_evidence_sees_post_export_receipt_state(self):
        findings = [{'key': 'fixture', 'severity': 'high', 'component': 'fixture', 'message': 'synthetic'}]
        snapshot = {'checkedAt': self.event['ts'], 'checkedAtEpoch': 1000, 'severity': 'high',
                    'findings': findings, 'hermers': {}, 'authMaintenance': {}}
        policy = {'mode': 'fixture', 'lanes': {}}
        seen = []
        def evidence(value):
            seen.append(value['eventPipeline']['coverage'])
            self.assertEqual(len(self.log.read_text().splitlines()), 1)
            return {'written': False}
        with mock.patch.object(m, 'collect_snapshot', return_value=(snapshot, findings, policy)), \
             mock.patch.object(m, 'control_plane_backpressure', return_value={}), \
             mock.patch.object(m, 'actuate_collected_snapshot', return_value=[]), \
             mock.patch.object(m, 'write_workflow_stability_evidence', side_effect=evidence), \
             mock.patch.object(m, 'write_legacy_watchdog_health', return_value={}), \
             mock.patch.object(m, 'publish_generation', side_effect=lambda value, *_: value), \
             mock.patch.object(m, 'log_line'):
            result = m._run_once_body(self.conn, no_action=True)
        self.assertEqual(seen, ['receipt-clear'])
        self.assertEqual(result['eventPipeline']['coverage'], 'receipt-clear')
