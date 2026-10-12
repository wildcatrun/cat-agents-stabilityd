"""Read-only Hermes control-socket observation; never grants effect authority."""
from dataclasses import dataclass, field, replace
import json
import math
import re
from pathlib import Path
import socket
import stat
import struct
import time
import uuid
from .process_identity import read_process_identity, identities_match

MAX_RESPONSE = 512 * 1024
READ_VERBS = frozenset({'identify', 'status'})

@dataclass(frozen=True)
class ControlObservation:
    verb: str
    peer_pid: int
    peer_uid: int
    payload: dict
    action_authorized: bool = False
    process_identity: dict = field(default_factory=dict)
    received_monotonic: float = 0.0

    def __post_init__(self):
        if self.action_authorized is not False:
            raise ValueError('observation cannot authorize effects')

def decode_response(raw, verb, request_id, peer_pid, peer_uid):
    if type(peer_pid) is not int or peer_pid <= 0 or type(peer_uid) is not int or peer_uid < 0:
        raise ValueError('control peer identity refused')
    if verb not in READ_VERBS or len(raw) > MAX_RESPONSE or not raw.endswith(b'\n'):
        raise ValueError('control framing refused')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('duplicate control field')
            result[key] = value
        return result
    answer = json.loads(raw, object_pairs_hook=pairs,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if (not isinstance(answer, dict) or answer.get('ok') is not True
            or type(answer.get('protocol')) is not int or answer['protocol'] != 1
            or answer.get('id') != request_id):
        raise ValueError('control envelope refused')
    result = answer.get('result')
    if (not isinstance(result, dict) or type(result.get('protocol')) is not int
            or result['protocol'] != 1):
        raise ValueError('control payload refused')
    pid = result.get('pid' if verb == 'identify' else 'answering_pid')
    if type(pid) is not int or pid <= 0 or pid != peer_pid:
        raise ValueError('control peer mismatch')
    if verb == 'status':
        answered = result.get('answered_at')
        if type(answered) not in (int, float) or not math.isfinite(answered):
            raise ValueError('control timestamp refused')
    return ControlObservation(verb, peer_pid, peer_uid, result)

def query_readonly(socket_path: Path, verb: str, *, expected_uid: int, timeout: float = 2.0):
    """Query an explicitly resolved trusted socket; unsupported peer PID => refuse.

    Caller still owns node, owning-home, artifact and cached-observation freshness
    checks. No pointer resolution, profile discovery, fallback or mutation verbs.
    """
    if verb not in READ_VERBS: raise ValueError('effect verb refused')
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 2:
        raise ValueError('control timeout refused')
    if type(expected_uid) is not int or expected_uid < 0:
        raise ValueError('control owner refused')
    if not hasattr(socket, 'SO_PEERCRED'): raise ValueError('peer PID unavailable')
    path = Path(socket_path)
    if not path.is_absolute() or '..' in path.parts: raise ValueError('absolute canonical socket required')
    identity = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_ctime_ns)
    ancestors = []
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError('socket ancestor refused')
        if info.st_uid not in {0, expected_uid} or info.st_mode & 0o022:
            raise ValueError('socket ancestor permissions refused')
        ancestors.append((parent, identity(info)))
    before = path.lstat()
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != expected_uid or before.st_mode & 0o077:
        raise ValueError('socket identity refused')
    def unchanged():
        return (identity(path.lstat()) == identity(before)
                and all(identity(parent.lstat()) == expected for parent, expected in ancestors))
    deadline = time.monotonic() + timeout
    wall_started = time.time()
    mono_started = time.monotonic()
    request_id = uuid.uuid4().hex
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(max(0.001, deadline - time.monotonic()))
        connection.connect(str(path))
        pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != expected_uid or pid <= 0 or not unchanged():
            raise ValueError('socket peer refused')
        process_before = read_process_identity(pid)
        if (process_before.get('status') != 'known' or process_before.get('uid') != uid
                or process_before.get('euid') != uid):
            raise ValueError('control process identity unavailable')
        connection.sendall(json.dumps({'verb': verb, 'id': request_id, 'protocol': 1}).encode() + b'\n')
        raw = bytearray()
        while b'\n' not in raw:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError('control deadline')
            connection.settimeout(remaining)
            chunk = connection.recv(min(8192, MAX_RESPONSE + 1 - len(raw)))
            if not chunk: raise ValueError('control truncated')
            raw.extend(chunk)
            if len(raw) > MAX_RESPONSE: raise ValueError('control response budget')
        if not unchanged() or time.monotonic() > deadline:
            raise ValueError('control identity or deadline drift')
        observed = decode_response(bytes(raw), verb, request_id, pid, uid)
        process_after = read_process_identity(pid)
        if not identities_match(process_before, process_after)[0]:
            raise ValueError('control process instance drift')
        wall_finished = time.time()
        mono_finished = time.monotonic()
        if (mono_finished > deadline or wall_finished < wall_started
                or abs((wall_finished - wall_started) - (mono_finished - mono_started)) > 0.25):
            raise ValueError('control observation clock drift')
        if verb == 'status' and not wall_started <= observed.payload['answered_at'] <= wall_finished:
            raise ValueError('control response outside observation window')
        return replace(observed, process_identity=dict(process_after), received_monotonic=mono_finished)


def profile_residency(identify: ControlObservation, status: ControlObservation,
                      *, expected_home: Path, profile: str, now_monotonic: float):
    """Compose fresh peer-bound observations; membership is not channel readiness.

    No absence inference from missing metadata or unreachable sockets. Callers
    derive home/profile from runtime registry routing, never local enumeration.
    """
    if not isinstance(profile, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', profile):
        raise ValueError('profile scope refused')
    home = Path(expected_home)
    if not home.is_absolute() or '..' in home.parts:
        raise ValueError('home scope refused')
    if identify.verb != 'identify' or status.verb != 'status':
        raise ValueError('observation roles refused')
    if (identify.peer_pid != status.peer_pid or identify.peer_uid != status.peer_uid
            or not identities_match(identify.process_identity, status.process_identity)[0]):
        raise ValueError('observation process drift')
    if type(now_monotonic) not in (int, float) or not math.isfinite(now_monotonic):
        raise ValueError('observation clock refused')
    for observed in (identify, status):
        if (not 0 < observed.received_monotonic <= now_monotonic
                or now_monotonic - observed.received_monotonic > 2
                or observed.process_identity.get('pid') != observed.peer_pid
                or observed.process_identity.get('uid') != observed.peer_uid
                or observed.process_identity.get('euid') != observed.peer_uid
                or observed.payload.get('hermes_home') != str(home)):
            raise ValueError('observation freshness or home refused')
    if status.received_monotonic < identify.received_monotonic:
        raise ValueError('observation sequence refused')
    memberships = []
    for observed in (identify, status):
        names = observed.payload.get('served_profiles')
        if (not isinstance(names, list) or not names or len(names) > 1024
                or any(not isinstance(n, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', n) for n in names)
                or len(set(names)) != len(names)):
            raise ValueError('explicit served profile scope unavailable')
        memberships.append(set(names))
    if memberships[0] != memberships[1]:
        raise ValueError('served profile scope changed')
    return {'profile': profile, 'residency': 'served' if profile in memberships[1] else 'unserved',
            'peerPid': status.peer_pid, 'channelReadiness': 'unknown', 'actionAuthorized': False}
