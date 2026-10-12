import json
from pathlib import Path
import unittest
from stability_core.hermes_control import ControlObservation, decode_response, query_readonly


class HermesControlTests(unittest.TestCase):
    def envelope(self, verb='identify', **changes):
        result = {'protocol': 1, 'pid': 42} if verb == 'identify' else {
            'protocol': 1, 'answering_pid': 42, 'answered_at': 123.0}
        answer = {'protocol': 1, 'ok': True, 'id': 'fixture', 'result': result}
        answer.update(changes)
        return json.dumps(answer).encode() + b'\n'

    def test_both_read_verbs_bind_actual_peer(self):
        for verb in ('identify', 'status'):
            with self.subTest(verb=verb):
                result = decode_response(self.envelope(verb), verb, 'fixture', 42, 1000)
                self.assertFalse(result.action_authorized)
                self.assertEqual(result.peer_pid, 42)

    def test_wrong_peer_refused(self):
        with self.assertRaises(ValueError):
            decode_response(self.envelope(), 'identify', 'fixture', 43, 1000)

    def test_unknown_protocol_boolean_and_bad_envelope_refused(self):
        for changes in ({'protocol': True}, {'protocol': 2}, {'ok': 1}, {'id': 'other'}, {'result': []}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                decode_response(self.envelope(**changes), 'identify', 'fixture', 42, 1000)

    def test_duplicate_field_refused(self):
        with self.assertRaises(ValueError):
            decode_response(b'{"ok":true,"ok":false}\n', 'identify', 'fixture', 42, 1000)

    def test_nonfinite_status_refused(self):
        raw = self.envelope('status').replace(b'123.0', b'NaN')
        with self.assertRaises(ValueError):
            decode_response(raw, 'status', 'fixture', 42, 1000)

    def test_truncated_and_multiple_frames_refused(self):
        for raw in (self.envelope()[:-1], self.envelope() + self.envelope()):
            with self.assertRaises(ValueError):
                decode_response(raw, 'identify', 'fixture', 42, 1000)

    def test_effect_verbs_refused_before_connect(self):
        for verb in ('serve-profile', 'unserve-profile', 'rescan-profiles', 'pause-for-update'):
            with self.subTest(verb=verb), self.assertRaises(ValueError):
                query_readonly(Path('/nonexistent/socket'), verb, expected_uid=1000)

    def test_observation_cannot_grant_effect_authority(self):
        with self.assertRaises(ValueError):
            ControlObservation('identify', 42, 1000, {}, True)
