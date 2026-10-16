"""Transactional, boot-relative timing only; never authorizes an action.

The trusted caller supplies Linux boot_id/CLOCK_BOOTTIME milliseconds (or an
independently qualified equivalent), wall time, and fixed constructor policy.
All APIs require the caller's SQLite transaction; this module never commits,
rolls back, changes connection settings, or touches the action ledger.
"""
from dataclasses import dataclass
import uuid


class ClockRefused(ValueError):
    pass


@dataclass(frozen=True)
class ClockProof:
    epoch: str
    boot_id: str
    mono_ms: int
    usable: bool


class ClockDiscipline:
    def __init__(self, connection, *, tolerance_ms, recovery_stable_ms,
                 max_history=256):
        for value in (tolerance_ms, recovery_stable_ms, max_history):
            if type(value) is not int or value <= 0:
                raise ClockRefused('clock-policy-invalid')
        self.db = connection
        self.tolerance = tolerance_ms
        self.recovery = recovery_stable_ms
        self.max_history = max_history

    def _transaction(self):
        if not self.db.in_transaction:
            raise ClockRefused('clock-caller-transaction-required')

    _DDL = (
        'CREATE TABLE stability_clock_version(version INTEGER NOT NULL,legacy_complete INTEGER NOT NULL)',
        'CREATE TABLE stability_clock_anchor(id INTEGER PRIMARY KEY CHECK(id=1),boot TEXT NOT NULL,epoch TEXT NOT NULL,wall INTEGER NOT NULL,mono INTEGER NOT NULL,lastmono INTEGER NOT NULL,lastwall INTEGER NOT NULL,quarantine INTEGER NOT NULL,stable_since INTEGER NOT NULL,tolerance INTEGER NOT NULL,recovery INTEGER NOT NULL,historycap INTEGER NOT NULL)',
        'CREATE TABLE stability_clock_windows(scope TEXT PRIMARY KEY,duration INTEGER NOT NULL,deadline INTEGER NOT NULL)',
        'CREATE TABLE stability_clock_history(action_id TEXT PRIMARY KEY,scope TEXT NOT NULL,duration INTEGER NOT NULL,deadline INTEGER NOT NULL)',
    )

    def install(self):
        self._transaction()
        actual = {r[0]: r[1] for r in self.db.execute("SELECT name,sql FROM sqlite_master WHERE (name GLOB 'stability_clock_*' OR tbl_name GLOB 'stability_clock_*') AND name NOT GLOB 'sqlite_autoindex_*' AND type IN ('table','view','trigger','index')")}
        expected = {ddl.split('(')[0].split()[-1]: ddl for ddl in self._DDL}
        if actual:
            # Exact owned DDL also fences PK, constraints, defaults and triggers.
            if actual != expected:
                raise ClockRefused('clock-schema-refused')
            self._validate_state()
            return
        for statement in self._DDL:
            self.db.execute(statement)
        self.db.execute('INSERT INTO stability_clock_version VALUES(1,0)')

    def _validate_state(self):
        version = [tuple(r) for r in self.db.execute('SELECT version,legacy_complete FROM stability_clock_version')]
        if len(version) != 1 or any(type(v) is not int for v in version[0]) or version[0][0] != 1 or version[0][1] not in (0,1):
            raise ClockRefused('clock-state-corrupt')
        anchors = self.db.execute('SELECT * FROM stability_clock_anchor').fetchall()
        if len(anchors) > 1:
            raise ClockRefused('clock-state-corrupt')
        for raw in anchors:
            row = tuple(raw)
            if (len(row) != 12 or row[0] != 1 or type(row[0]) is not int
                    or any(type(row[i]) is not str or not row[i] or len(row[i]) > 128 for i in (1,2))
                    or any(type(v) is not int or not 0 <= v <= 2**62 for v in row[3:])
                    or row[7] not in (0,1) or min(row[9:]) <= 0
                    or row[4] > row[5] or row[8] > row[5]):
                raise ClockRefused('clock-state-corrupt')
        total = 0
        for table in ('stability_clock_windows', 'stability_clock_history'):
            rows = self.db.execute(f'SELECT * FROM {table}').fetchall()
            if len(rows) > self.max_history:
                raise ClockRefused('clock-state-corrupt')
            total += len(rows)
            for raw in rows:
                row = tuple(raw)
                strings, duration, deadline = row[:-2], row[-2], row[-1]
                if (any(type(v) is not str or not v or len(v)>256 for v in strings)
                        or type(duration) is not int or not 0 < duration <= 31536000000
                        or type(deadline) is not int or not duration <= deadline <= 2**62):
                    raise ClockRefused('clock-state-corrupt')
        if total and not anchors:
            raise ClockRefused('clock-state-corrupt')

    def complete_legacy_import(self, proof):
        """Same TX as the one-time trusted legacy map, including empty map."""
        self._proof(proof)
        self.db.execute('UPDATE stability_clock_version SET legacy_complete=1')

    def _legacy_open(self):
        if self.db.execute('SELECT legacy_complete FROM stability_clock_version').fetchone()[0]:
            raise ClockRefused('clock-legacy-import-closed')

    def _prune(self, mono_ms):
        # Validate BEFORE any prune: corrupt evidence is never erased as expiry.
        self._validate_state()
        if self.db.execute('SELECT legacy_complete FROM stability_clock_version').fetchone()[0]:
            self.db.execute('DELETE FROM stability_clock_history WHERE deadline<=?', (mono_ms,))
            self.db.execute('DELETE FROM stability_clock_windows WHERE deadline<=?', (mono_ms,))

    @staticmethod
    def _time(boot, wall, mono):
        if type(boot) is not str or not boot or len(boot) > 128 or any(ord(c) < 33 for c in boot):
            raise ClockRefused('clock-boot-invalid')
        if any(type(v) is not int or v < 0 or v > 2**62 for v in (wall, mono)):
            raise ClockRefused('clock-sample-invalid')

    def sample(self, *, boot_id, wall_ms, mono_ms):
        self._transaction()
        self._validate_state()
        self._time(boot_id, wall_ms, mono_ms)
        row = self.db.execute('SELECT boot,epoch,wall,mono,lastmono,lastwall,quarantine,stable_since,tolerance,recovery,historycap FROM stability_clock_anchor WHERE id=1').fetchone()
        if row is None:
            epoch = uuid.uuid4().hex
            self.db.execute('INSERT INTO stability_clock_anchor VALUES(1,?,?,?,?,?,?,?,?,?,?,?)',
                            (boot_id, epoch, wall_ms, mono_ms, mono_ms, wall_ms, 0, mono_ms, self.tolerance, self.recovery, self.max_history))
            return ClockProof(epoch, boot_id, mono_ms, True)
        boot, epoch, wall, mono, lastmono, lastwall, quarantine, stable, tolerance, recovery, cap = tuple(row)
        if (tolerance, recovery, cap) != (self.tolerance, self.recovery, self.max_history):
            raise ClockRefused('clock-policy-drift')
        if boot != boot_id:
            # No wall-time credit across boots. Only already-expired rows may go.
            self._prune(lastmono)
            for table in ('stability_clock_windows', 'stability_clock_history'):
                self.db.execute(f'UPDATE {table} SET deadline=?+duration', (mono_ms,))
            epoch, wall, mono, quarantine, stable = uuid.uuid4().hex, wall_ms, mono_ms, 0, mono_ms
        elif mono_ms < lastmono:
            # A broken trusted monotonic source cannot safely rebase deadlines.
            raise ClockRefused('clock-monotonic-regression')
        elif not quarantine and abs((wall_ms-wall)-(mono_ms-mono)) > tolerance:
            epoch, quarantine, stable, wall, mono = uuid.uuid4().hex, 1, mono_ms, wall_ms, mono_ms
        elif quarantine:
            if abs((wall_ms-wall)-(mono_ms-mono)) > tolerance:
                stable, wall, mono = mono_ms, wall_ms, mono_ms
            elif mono_ms-stable >= recovery:
                # Rebase only wall anchor. Existing deadlines are untouched.
                epoch, wall, mono, quarantine = uuid.uuid4().hex, wall_ms, mono_ms, 0
        self.db.execute('UPDATE stability_clock_anchor SET boot=?,epoch=?,wall=?,mono=?,lastmono=?,lastwall=?,quarantine=?,stable_since=? WHERE id=1',
                        (boot_id, epoch, wall, mono, mono_ms, wall_ms, quarantine, stable))
        self._prune(mono_ms)
        return ClockProof(epoch, boot_id, mono_ms, not quarantine)

    def _proof(self, proof):
        self._transaction()
        self._validate_state()
        row = self.db.execute('SELECT epoch,boot,lastmono,quarantine FROM stability_clock_anchor WHERE id=1').fetchone()
        if not isinstance(proof, ClockProof) or row is None or tuple(row) != (proof.epoch, proof.boot_id, proof.mono_ms, 0) or not proof.usable:
            raise ClockRefused('clock-proof-stale-or-quarantined')

    @staticmethod
    def _scope(scope, duration):
        if type(scope) is not str or not scope or len(scope) > 256 or type(duration) is not int or not 0 < duration <= 31536000000:
            raise ClockRefused('clock-window-invalid')

    def remaining_ms(self, scope, proof):
        self._proof(proof)
        row = self.db.execute('SELECT deadline FROM stability_clock_windows WHERE scope=?', (scope,)).fetchone()
        return max(0, row[0]-proof.mono_ms) if row else 0

    def _scope_budget(self, scope):
        if not self.db.execute("SELECT 1 FROM stability_clock_windows WHERE scope=?", (scope,)).fetchone() and self.db.execute("SELECT count(*) FROM stability_clock_windows").fetchone()[0] >= self.max_history:
            raise ClockRefused("clock-scope-budget")

    def import_legacy_window(self, scope, duration_ms, proof):
        """Explicit conservative once-only migration; wall age gives no credit."""
        self._proof(proof)
        self._legacy_open()
        self._scope(scope, duration_ms)
        self._scope_budget(scope)
        self.db.execute('INSERT OR IGNORE INTO stability_clock_windows VALUES(?,?,?)', (scope, duration_ms, proof.mono_ms+duration_ms))

    def preflight_capacity(self, scope, proof):
        """Check inside the same exclusive writer boundary held through effects."""
        self._proof(proof)
        self._scope_budget(scope)
        if self.db.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0] >= self.max_history:
            raise ClockRefused('clock-history-budget')

    def import_legacy_history(self, *, action_id, scope, history_ms, proof):
        """Known successful stabilityd entries only; no wall-age discount."""
        self._proof(proof)
        self._legacy_open()
        self._scope(scope, history_ms)
        if type(action_id) is not str or not action_id or len(action_id) > 256:
            raise ClockRefused('clock-action-id-invalid')
        old = self.db.execute('SELECT scope,duration FROM stability_clock_history WHERE action_id=?', (action_id,)).fetchone()
        if old:
            if tuple(old) != (scope, history_ms):
                raise ClockRefused('clock-action-conflict')
            return
        self.preflight_capacity(scope, proof)
        self.db.execute('INSERT INTO stability_clock_history VALUES(?,?,?,?)', (action_id, scope, history_ms, proof.mono_ms+history_ms))

    def record_success(self, *, action_id, scope, cooldown_ms, history_ms, proof, history_scope=None):
        """Only caller-confirmed complete stabilityd commands, in terminal TX.

        action_id is stable ledger identity; idempotent retries never extend time.
        Health postcheck failure does not erase a confirmed command. A passive
        OS/runtime startup is not an effect and must never call this.
        """
        self._proof(proof)
        self._scope(scope, cooldown_ms)
        history_scope = scope if history_scope is None else history_scope
        self._scope(history_scope, history_ms)
        if type(action_id) is not str or not action_id or len(action_id) > 256:
            raise ClockRefused('clock-action-id-invalid')
        self._scope_budget(scope)
        previous = self.db.execute('SELECT scope,duration FROM stability_clock_history WHERE action_id=?', (action_id,)).fetchone()
        if previous:
            if tuple(previous) != (history_scope, history_ms):
                raise ClockRefused('clock-action-conflict')
            return
        if self.db.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0] >= self.max_history:
            raise ClockRefused('clock-history-budget')
        self.db.execute('INSERT INTO stability_clock_history VALUES(?,?,?,?)', (action_id, history_scope, history_ms, proof.mono_ms+history_ms))
        self.db.execute('INSERT INTO stability_clock_windows VALUES(?,?,?) ON CONFLICT(scope) DO UPDATE SET duration=max(duration,excluded.duration),deadline=max(deadline,excluded.deadline)', (scope, cooldown_ms, proof.mono_ms+cooldown_ms))

    def history_count(self, scope, proof):
        self._proof(proof)
        return self.db.execute('SELECT count(*) FROM stability_clock_history WHERE scope=? AND deadline>?', (scope, proof.mono_ms)).fetchone()[0]
