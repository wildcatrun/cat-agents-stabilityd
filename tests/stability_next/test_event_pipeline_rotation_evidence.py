"""Cheap negative checks for the continuous qualification's independent oracle."""
from collections import deque
import json
import unittest

from test_event_pipeline_v2_continuous import RotationEvidence


class RotationEvidenceTests(unittest.TestCase):
    def drive(self, mode):
        evidence = RotationEvidence(max_active_bytes=1024)
        tail = deque(maxlen=50)
        size = 0
        identity = (1, 100)
        identities = set()
        for n in range(300):
            events = [{'n': n}]
            content = (json.dumps(events[0])+'\n').encode()
            if size + len(content) > 1024:
                if mode != 'no-rotation':
                    identity = (1, 101 if identity[1] == 100 else 100)
                    size = 0 if mode == 'truncate' else sum(map(len, tail))
            size += len(content)
            evidence.observe(identity, size, events)
            identities.add(identity)
            tail.append(content)
        return evidence, identities

    def test_inode_reuse_a_b_a_counts_each_actual_transition(self):
        evidence, identities = self.drive('reuse')
        self.assertEqual(len(identities), 2)
        self.assertGreaterEqual(evidence.rotations, 3)
        evidence.require_rotations()

    def test_default_capacity_r45_byte_trace_matches_two_rotations_with_reuse(self):
        # Pure byte-oracle replay only: no pipeline, SQLite, filesystem or long
        # qualification execution. Keep the real 8MiB/16KiB input contract.
        evidence = RotationEvidence()
        tail = deque(maxlen=50)
        size = 0
        identity = (1, 100)
        observed = []
        for n in range(4208):
            events = [] if n % 3 else [{"tsEpoch": n, "cycle": n,
                                       "message": "synthetic" + "x" * 16384}]
            incoming = [(json.dumps(event, ensure_ascii=False, allow_nan=False)+'\n').encode()
                        for event in events]
            if size + sum(map(len, incoming)) > 8388608:
                identity = (1, 101 if identity[1] == 100 else 100)
                size = sum(map(len, tail))
            size += sum(map(len, incoming))
            evidence.observe(identity, size, events)
            tail.extend(incoming)
            if (n+1) % 512 == 0 or n == 4207:
                observed.append(size)
        self.assertEqual(observed, [2810993, 5622078, 854932, 3666343, 6477754,
                                    1709864, 4521275, 7332686, 7941003])
        self.assertEqual(evidence.rotations, 2)
        evidence.require_rotations()

    def test_disabling_rotation_cannot_pass(self):
        with self.assertRaisesRegex(AssertionError, 'required rotation'):
            self.drive('no-rotation')

    def test_replacement_with_truncation_cannot_fake_tail_preservation(self):
        with self.assertRaisesRegex(AssertionError, 'prior fifty lines'):
            self.drive('truncate')

    def test_no_actual_rotation_cannot_pass_final_requirement(self):
        evidence = RotationEvidence()
        evidence.observe((1, 100), 0, [])
        with self.assertRaisesRegex(AssertionError, 'at least twice'):
            evidence.require_rotations()

    def test_empty_input_cannot_replace_file(self):
        evidence = RotationEvidence()
        evidence.observe((1, 100), 0, [])
        with self.assertRaisesRegex(AssertionError, 'unexpected file replacement'):
            evidence.observe((1, 101), 0, [])


if __name__ == '__main__':
    unittest.main()
