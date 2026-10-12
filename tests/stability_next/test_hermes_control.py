import json
import os
import socket
import tempfile
import threading
import time
from unittest import mock
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


@unittest.skipUnless(hasattr(socket, 'SO_PEERCRED') and os.environ.get('TEST_SOCKET_ROOT'),
                     'requires isolated Linux owned socket root')
class HermesSocketTransportTests(unittest.TestCase):
    def fixture(self, mode, verb='identify'):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_SOCKET_ROOT']) as directory:
            path = Path(directory) / 'gateway.sock'
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(1)
            listener.settimeout(2)
            failures = []
            def serve():
                try:
                    with listener.accept()[0] as connection:
                        request = json.loads(connection.recv(4096))
                        self.assertEqual(request['verb'], verb)
                        self.assertEqual(set(request), {'verb', 'id', 'protocol'})
                        if mode == 'timeout':
                            time.sleep(0.15)
                            return
                        result = {'protocol': 1, 'pid': os.getpid()} if verb == 'identify' else {
                            'protocol': 1, 'answering_pid': os.getpid(), 'answered_at': time.time()}
                        if mode == 'wrong-pid': result['pid'] += 1
                        if mode == 'old-status': result['answered_at'] -= 60
                        if mode == 'future-status': result['answered_at'] += 60
                        if mode == 'oversize': result['padding'] = 'x' * (512 * 1024)
                        if mode == 'replace':
                            path.unlink()
                            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as replacement:
                                replacement.bind(str(path))
                                path.chmod(0o600)
                        answer = json.dumps({'ok': True, 'protocol': 1, 'id': request['id'], 'result': result}).encode() + b'\n'
                        try: connection.sendall(answer)
                        except BrokenPipeError:
                            if mode != 'oversize': raise
                except Exception as exc:
                    failures.append(exc)
            worker = threading.Thread(target=serve)
            worker.start()
            try:
                if mode == 'ok':
                    observed = query_readonly(path, verb, expected_uid=os.getuid())
                    self.assertEqual(observed.peer_pid, os.getpid())
                    self.assertFalse(observed.action_authorized)
                else:
                    with self.assertRaises((ValueError, TimeoutError)):
                        query_readonly(path, verb, expected_uid=os.getuid(),
                                       timeout=0.05 if mode == 'timeout' else 2)
            finally:
                worker.join(3)
                listener.close()
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])

    def test_actual_identify(self): self.fixture('ok')
    def test_actual_status(self): self.fixture('ok', 'status')
    def test_actual_timeout(self): self.fixture('timeout')
    def test_actual_oversize(self): self.fixture('oversize')
    def test_actual_peer_mismatch(self): self.fixture('wrong-pid')
    def test_actual_socket_replacement(self): self.fixture('replace')
    def test_actual_stale_status(self): self.fixture('old-status', 'status')
    def test_actual_future_status(self): self.fixture('future-status', 'status')
    def test_actual_process_instance_drift(self):
        from stability_core import hermes_control
        reader = hermes_control.read_process_identity
        count = 0
        def drift(pid):
            nonlocal count
            identity = reader(pid)
            count += 1
            if count == 2: identity['starttime'] += 1
            return identity
        with mock.patch.object(hermes_control, 'read_process_identity', side_effect=drift):
            self.fixture('process-drift')
