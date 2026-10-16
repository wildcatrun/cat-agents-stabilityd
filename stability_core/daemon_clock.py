"""Finite local timing adapter; no scheduler, action authority, or live effects."""
import datetime
import hashlib
import json
import re
import time
from pathlib import Path
from .clock_discipline import ClockDiscipline, ClockRefused

# Trusted candidate constants; 2s permits sampling/normal clock slew, 60s of
# stable boot-relative progression permits recovery. Deployment values need review.
TOLERANCE_MS = 2000
RECOVERY_STABLE_MS = 60000
MAX_HISTORY = 4096


def linux_sample():
    if not hasattr(time, 'CLOCK_BOOTTIME'):
        raise ClockRefused('clock-linux-boottime-unavailable')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', boot):
        raise ClockRefused('clock-linux-boot-invalid')
    return dict(boot_id=boot.lower(), wall_ms=time.time_ns()//1000000,
                mono_ms=time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000)


class DaemonClock:
    def __init__(self, conn, *, restart_ms, restart_window_ms, session_ms, lifecycle_ms,
                 max_restarts, sampler=linux_sample):
        self.db = conn
        self.core = ClockDiscipline(conn, tolerance_ms=TOLERANCE_MS,
                                    recovery_stable_ms=RECOVERY_STABLE_MS, max_history=MAX_HISTORY)
        self.restart_ms, self.window_ms = restart_ms, restart_window_ms
        self.session_ms, self.lifecycle_ms = session_ms, lifecycle_ms
        self.max_restarts, self.sampler = max_restarts, sampler
        if any(type(v) is not int or v <= 0 for v in (restart_ms,restart_window_ms,session_ms,lifecycle_ms,max_restarts)):
            raise ClockRefused('clock-duration-policy-invalid')

    def observe(self):
        if not self.db.in_transaction:
            raise ClockRefused('clock-transaction-required')
        if not any(r[1]=='main' and r[2] for r in self.db.execute('PRAGMA database_list')):
            raise ClockRefused('clock-durable-daemon-store-required')
        if str(self.db.execute('PRAGMA journal_mode').fetchone()[0]).lower() != 'wal' or self.db.execute('PRAGMA synchronous').fetchone()[0] != 2:
            raise ClockRefused('clock-durable-settings-required')
        self.core.install()
        proof = self.core.sample(**self.sampler())
        complete = self.db.execute('SELECT legacy_complete FROM stability_clock_version').fetchone()[0]
        if not complete:
            if not proof.usable:
                return proof
            self._migrate(proof)
        return proof

    def _migrate(self, proof):
        # Closed key families only. No wall-age credit; bound before parsing.
        rows = self.db.execute("SELECT key,value FROM kv WHERE key IN ('stabilityd_last_gateway_restart_at','stabilityd_gateway_restart_history','stabilityd_hermers_gateway_restart_history') OR key GLOB 'hermers_gateway_restart:*' OR key GLOB 'session_reset:sha256:*' OR key GLOB 'hermers_profile_mode:*' LIMIT ?", (MAX_HISTORY+1,)).fetchall()
        if len(rows)>MAX_HISTORY:
            raise ClockRefused('clock-legacy-budget')
        for key, raw in rows:
            value = json.loads(raw)
            scope = None
            if key == 'stabilityd_last_gateway_restart_at': scope, duration = 'openclaw.gateway', self.restart_ms
            elif re.fullmatch(r'hermers_gateway_restart:[a-z][a-z0-9_-]{0,63}', key): scope, duration = 'hermes.gateway:'+key.split(':',1)[1], self.restart_ms
            elif re.fullmatch(r'session_reset:sha256:[a-f0-9]{64}', key): scope, duration = 'openclaw.session:'+key.rsplit(':',1)[1], self.session_ms
            elif re.fullmatch(r'hermers_profile_mode:[a-z][a-z0-9_-]{0,63}:(?:hot|hibernate)', key): scope, duration = 'hermes.lifecycle:'+key.split(':',1)[1], self.lifecycle_ms
            elif key in ('stabilityd_gateway_restart_history', 'stabilityd_hermers_gateway_restart_history'):
                if type(value) is not list or len(value)>MAX_HISTORY:
                    raise ClockRefused('clock-legacy-history-invalid')
                for n, item in enumerate(value):
                    stamp = item.get('tsEpoch') if type(item) is dict else item
                    if type(stamp) is not int or stamp<0:
                        raise ClockRefused('clock-legacy-history-invalid')
                    if not stamp: continue
                    digest = hashlib.sha256((key+':'+str(n)+':'+json.dumps(item,sort_keys=True)).encode()).hexdigest()
                    self.core.import_legacy_history(action_id='legacy:'+digest, scope='hermes.gateway.history' if 'hermers' in key else 'openclaw.gateway.history', history_ms=self.window_ms, proof=proof)
                continue
            else:
                # Planned-state metadata is not a timing record.
                continue
            if type(value) is not int or value<0:
                raise ClockRefused('clock-legacy-window-invalid')
            if value:
                self.core.import_legacy_window(scope, duration, proof)
        self.core.complete_legacy_import(proof)

    def scope(self, spec):
        kind, data = spec.action_type, spec.input_data
        if kind == 'openclaw.gateway.restart': return 'openclaw.gateway', self.restart_ms, 'openclaw.gateway.history'
        if kind == 'hermes.gateway.restart':
            profile = data.get('profile')
            if not isinstance(profile,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,63}',profile): raise ClockRefused('clock-profile-invalid')
            return 'hermes.gateway:'+profile, self.restart_ms, 'hermes.gateway.history'
        if kind == 'openclaw.session.reset':
            digest = data.get('sessionKeyDigest')
            if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest): raise ClockRefused('clock-session-invalid')
            return 'openclaw.session:'+digest, self.session_ms, 'openclaw.session.history'
        if kind == 'hermes.profile.lifecycle':
            profile, mode = data.get('profile'), data.get('targetMode')
            if not isinstance(profile,str) or not re.fullmatch('[a-z][a-z0-9_-]{0,63}',profile) or mode not in ('hot','hibernate'): raise ClockRefused('clock-profile-invalid')
            return 'hermes.lifecycle:'+profile+':'+mode, self.lifecycle_ms, 'hermes.lifecycle.history'
        raise ClockRefused('clock-action-outside-scope')

    def check(self, spec, epoch=None):
        proof = self.observe()
        if not proof.usable or epoch is not None and proof.epoch != epoch:
            return False, proof
        scope, duration, history = self.scope(spec)
        self.core.preflight_capacity(scope, proof)
        allowed = self.core.remaining_ms(scope, proof)==0
        if spec.action_type in ('openclaw.gateway.restart','hermes.gateway.restart'):
            allowed = allowed and self.core.history_count(history,proof)<self.max_restarts
        return allowed, proof

    def effect(self, spec, record):
        proof = self.observe()
        scope, duration, history = self.scope(spec)
        self.core.record_success(action_id=record.action_id, scope=scope, cooldown_ms=duration,
            history_ms=self.window_ms if spec.action_type.endswith('gateway.restart') else duration,
            history_scope=history, proof=proof)
        now = self.db.execute('SELECT lastwall FROM stability_clock_anchor WHERE id=1').fetchone()[0]//1000
        def put(key,value):
            self.db.execute('INSERT INTO kv(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at', (key,json.dumps(value,ensure_ascii=False),now))
        if spec.action_type=='openclaw.gateway.restart':
            put('stabilityd_last_gateway_restart_at',now)
            key='stabilityd_gateway_restart_history'
            old=self.db.execute('SELECT value FROM kv WHERE key=?',(key,)).fetchone()
            values=json.loads(old[0]) if old else []
            put(key,(values+[now])[-self.max_restarts:])
        elif spec.action_type=='hermes.gateway.restart':
            profile=spec.input_data['profile'];put('hermers_gateway_restart:'+profile,now)
            put('stabilityd_last_hermers_gateway_restart_at',now)
            key='stabilityd_hermers_gateway_restart_history'
            old=self.db.execute('SELECT value FROM kv WHERE key=?',(key,)).fetchone()
            values=json.loads(old[0]) if old else []
            put(key,(values+[{'tsEpoch':now,'profile':profile}])[-self.max_restarts:])
        elif spec.action_type=='openclaw.session.reset': put('session_reset:sha256:'+spec.input_data['sessionKeyDigest'],now)
        else:
            profile, mode = spec.input_data['profile'], spec.input_data['targetMode']
            put('hermers_profile_mode:'+profile+':'+mode,now)
            if mode=='hibernate' and record.state=='succeeded':
                put('hermers_profile_mode:planned:'+profile,
                    {'profile':profile,'targetMode':mode,'unit':spec.input_data['unit'],
                     'reason':spec.input_data['reasonCode'],
                     'setAt':datetime.datetime.fromtimestamp(now,datetime.timezone.utc).isoformat(),
                     'setAtEpoch':now,'source':'cat-agents-stabilityd'})
