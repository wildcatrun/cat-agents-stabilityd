"""Actual daemon entry + actual ledger/executor with confined fake effect leaves."""
import dataclasses
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
from stability_core.daemon_clock import DaemonClock
from stability_core.action_ledger import ActionLedger

S=importlib.util.spec_from_file_location('clock_bridge_daemon', Path(__file__).resolve().parents[2]/'bin/cat_agents_stabilityd.py')
m=importlib.util.module_from_spec(S);sys.modules[S.name]=m;S.loader.exec_module(m)


class DaemonClockBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'state.db'
        conn=sqlite3.connect(self.path)
        conn.execute('CREATE TABLE kv(key TEXT PRIMARY KEY,value TEXT,updated_at INTEGER)');conn.commit();conn.close()
        self.wall,self.mono,self.boot=1000000,100000,'11111111-2222-3333-4444-555555555555'
        self.effects=[]
        self.poststatus='verified'
        self.phase_jump=False
        self.postcheck_jump=False
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(m,'STATE_DB',self.path).start()
        mock.patch.object(m,'ACTUATION_LOCK_PATH',self.path.with_suffix('.lock')).start()
        mock.patch.object(m,'epoch',side_effect=lambda:self.wall//1000).start()
        self.original_factory=m.daemon_clock
        def factory(conn):
            return DaemonClock(conn,restart_ms=1800000,restart_window_ms=21600000,
                session_ms=21600000,lifecycle_ms=1800000,max_restarts=3,
                sampler=lambda:dict(boot_id=self.boot,wall_ms=self.wall,mono_ms=self.mono))
        self.factory=factory
        mock.patch.object(m,'daemon_clock',side_effect=factory).start()

    def spec(self,kind,key='one',profile='catbody'):
        policy=dict(updatedAtEpoch=self.wall//1000,validUntilEpoch=self.wall//1000+60,
            canRestartGateway=True,canRestartHermersGateway=True,canResetSession=True,
            hermersProfileModeActuateEnabled=True)
        with ActionLedger(self.path) as ledger:
            with ledger._write() as conn:
                proof = self.factory(conn).observe()
        policy['clockDiscipline'] = {
            'state': 'available' if proof.usable else 'unavailable-or-quarantined',
            'epoch': proof.epoch if proof.usable else None,
            'executionFence': 'required-for-time-dependent-effects',
        }
        digest,ref=m.policy_reference(policy)
        data={'profile':profile,'targetMode':'hibernate','unit':'hermes-gateway-'+profile+'.service',
              'reasonCode':'policy','sessionKeyDigest':'a'*64}
        target={'openclaw.gateway.restart':'openclaw-gateway:dev-server','hermes.gateway.restart':'hermes-gateway:'+profile,'openclaw.session.reset':'openclaw-session:sha256:'+'a'*64,'hermes.profile.lifecycle':'hermes-profile:'+profile}[kind]
        return m.ActionSpec(key,kind,target,'birth','stabilityd-daemon',data,
            m.STANDING_RULES[kind].authority_ref,ref,
            ('evidence://snapshot/test',ref,'policy-digest:sha256:'+digest),{'actor':'cat-agents-stabilityd'}),policy

    def execute(self,kind,key='one',**kwargs):
        spec,policy=self.spec(kind,key,**kwargs)
        def precheck(*args):
            # The second precheck is after executing CAS, immediately before timing check.
            if self.phase_jump and args[1].state=='executing':self.wall+=10000000
            return m.BoundaryCheck('approved','check://eligible')
        def effect(*args):
            self.effects.append(kind)
            # Verify actual existing lock spans the effect (not only preflight).
            from stability_core.actuation_lock import ActuationBusy,ActuationLock
            with self.assertRaises(ActuationBusy):
                with ActuationLock(m.ACTUATION_LOCK_PATH):pass
            return m.OperationResult('complete','outcome://confirmed')
        def postcheck(*args):
            if self.postcheck_jump:
                self.wall += 10000000
            return m.PostcheckResult(self.poststatus,'check://health')
        return m.execute_governed_effect(spec,policy,eligibility_evidence=lambda *a:('evidence://snapshot/test',),
            precheck=precheck,operation=effect,postcheck=postcheck)

    def test_four_real_entry_scopes_cooldown_and_mirrors(self):
        for n,kind in enumerate(sorted(m._CLOCK_ACTIONS)):
            result=self.execute(kind,str(n))
            self.assertEqual(result.record.state,'succeeded',kind)
            self.assertEqual(self.execute(kind,str(n)+'-new').record.state,'blocked',kind)
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM stability_clock_windows').fetchone()[0],4)
            self.assertEqual(conn.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0],4)
            keys={r[0] for r in conn.execute('SELECT key FROM kv')}
            self.assertTrue({'stabilityd_last_gateway_restart_at','hermers_gateway_restart:catbody',
                'session_reset:sha256:'+'a'*64,'hermers_profile_mode:catbody:hibernate'}<=keys)

    def test_policy_epoch_cannot_be_missing_or_survive_clock_recovery(self):
        spec, policy = self.spec('openclaw.gateway.restart', 'old-epoch')
        self.wall += 10000000
        with ActionLedger(self.path) as ledger:
            with ledger._write() as conn:
                self.assertFalse(self.factory(conn).observe().usable)
        self.wall += 60000
        self.mono += 60000
        # Keep the old wall TTL apparently valid: epoch is an independent fence.
        policy['updatedAtEpoch'] = self.wall//1000
        policy['validUntilEpoch'] = self.wall//1000 + 60
        def attempt(metadata):
            policy['clockDiscipline'] = metadata
            digest, ref = m.policy_reference(policy)
            current = dataclasses.replace(spec, policy_ref=ref,
                idempotency_key='old-epoch-'+str(metadata),
                evidence_refs=('evidence://snapshot/test', ref, 'policy-digest:sha256:'+digest))
            return m.execute_governed_effect(current, policy,
                eligibility_evidence=lambda *a:('evidence://snapshot/test',),
                precheck=lambda *a:m.BoundaryCheck('approved','check://eligible'),
                operation=lambda *a:self.fail('stale policy must never effect'),
                postcheck=lambda *a:self.fail('no postcheck without effect'))
        old = dict(policy['clockDiscipline'])
        self.assertEqual(attempt(old).record.state, 'blocked')
        self.assertEqual(attempt(None).record.state, 'blocked')

    def test_forward_jump_rejected_then_monotonic_expiry_recovers(self):
        self.execute('openclaw.gateway.restart')
        self.wall+=100000000
        self.assertEqual(self.execute('openclaw.gateway.restart','jump').record.state,'blocked')
        self.wall+=60000;self.mono+=60000
        self.assertEqual(self.execute('openclaw.gateway.restart','recovered').record.state,'blocked')
        self.wall+=1740000;self.mono+=1740000
        self.assertEqual(self.execute('openclaw.gateway.restart','expired').record.state,'succeeded')
        self.assertEqual(len(self.effects),2)

    def test_backward_jump_recovery_uses_mono_not_future_legacy_wall(self):
        self.execute('openclaw.gateway.restart')
        self.wall-=900000
        self.assertEqual(self.execute('openclaw.gateway.restart','back').record.state,'blocked')
        self.wall+=60000;self.mono+=60000
        self.assertEqual(self.execute('openclaw.gateway.restart','still').record.state,'blocked')
        self.wall+=1740000;self.mono+=1740000
        self.assertEqual(self.execute('openclaw.gateway.restart','expires').record.state,'succeeded')

    def test_after_cas_jump_blocks_known_no_effect(self):
        self.phase_jump=True
        result=self.execute('openclaw.session.reset')
        self.assertEqual((result.record.state,len(self.effects)),('blocked',0))

    def test_failed_health_counts_confirmed_restart_and_global_hermes_history(self):
        self.poststatus='failed'
        self.assertEqual(self.execute('hermes.gateway.restart').record.state,'failed')
        self.assertEqual(self.execute('hermes.gateway.restart','second').record.state,'blocked')
        self.assertEqual(self.execute('hermes.gateway.restart','other',profile='catnose').record.state,'failed')
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM stability_clock_history WHERE scope='hermes.gateway.history'").fetchone()[0],2)

    def test_existing_numeric_and_case_alias_profiles_share_cooldown(self):
        self.assertEqual(self.execute('hermes.gateway.restart', 'numeric', profile='1Cat').record.state, 'succeeded')
        self.assertEqual(self.execute('hermes.gateway.restart', 'case-alias', profile='1cat').record.state, 'blocked')
        self.assertEqual(len(self.effects), 1)

    def test_historical_receipt_requires_no_new_clock_or_authorizer(self):
        first=self.execute('openclaw.gateway.restart')
        with (mock.patch.object(m,'daemon_clock',side_effect=AssertionError('no clock read')),
              mock.patch.object(m.TrustedPolicyAuthorizer,'__call__',side_effect=AssertionError('no new authority'))):
            again=self.execute('openclaw.gateway.restart')
        self.assertEqual(again.record,first.record)
        self.assertEqual(len(self.effects),1)

    def test_legacy_once_no_forward_wall_credit_and_no_reimport(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute('INSERT INTO kv VALUES(?,?,?)',('stabilityd_last_gateway_restart_at','1',0))
        self.assertEqual(self.execute('openclaw.gateway.restart').record.state,'blocked')
        self.wall+=1800000;self.mono+=1800000
        self.assertEqual(self.execute('openclaw.gateway.restart','after').record.state,'succeeded')
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute('SELECT legacy_complete FROM stability_clock_version').fetchone()[0],1)

    def test_projection_recovers_wall_admission_and_restores_normal_sync(self):
        self.execute('openclaw.gateway.restart')
        with sqlite3.connect(self.path) as conn:
            conn.execute('PRAGMA synchronous=NORMAL')
            first=m.mechanical_timing_projection(conn)
            self.assertEqual(first['windows']['openclaw.gateway'],1800000)
            self.assertEqual(conn.execute('PRAGMA synchronous').fetchone()[0],1)
            self.wall-=900000
            self.assertIsNone(m.mechanical_timing_projection(conn))
            self.wall+=60000;self.mono+=60000
            self.assertGreater(m.mechanical_timing_projection(conn)['windows']['openclaw.gateway'],0)
            self.wall+=1740000;self.mono+=1740000
            self.assertEqual(m.mechanical_timing_projection(conn)['windows'].get('openclaw.gateway',0),0)
            self.assertEqual(conn.execute('PRAGMA synchronous').fetchone()[0],1)
            conn.execute("INSERT INTO kv VALUES('uncommitted','1',0)")
            self.assertIsNone(m.mechanical_timing_projection(conn))
            self.assertTrue(conn.in_transaction)
            with sqlite3.connect(self.path) as observer:
                self.assertIsNone(observer.execute("SELECT value FROM kv WHERE key='uncommitted'").fetchone())
            conn.rollback()

    def test_real_policy_uses_monotonic_expiry_after_backward_recovery(self):
        self.execute('openclaw.gateway.restart')
        snapshot={'gateway':{'active':False,'portOk':False,'startupGraceActive':False},
                  'cron':{'storageStatus':{'storage':'json'}}}
        findings=[{'key':'gateway_service_down','severity':'critical','component':'fixture','message':'synthetic'}]
        streaks={'gateway_service_down':{'count':2}}
        def stable(*args):
            return {'domains':{name:{'healthyStreak':0} for name in ('cron','session','channel','auth','hermers','resource')}}
        with sqlite3.connect(self.path) as conn, mock.patch.object(m,'update_lane_recovery',side_effect=stable), mock.patch.multiple(m,
            GATEWAY_RESTART_ENABLED=True,GATEWAY_RESTART_ACTUATOR_SUPPORTED=True,
            SOFT_GATEWAY_RESTART_ENABLED=False,SOFT_RESCUE_RESTART_ENABLED=False,ACTION_STREAK_THRESHOLD=2):
            self.assertFalse(m.policy_from_findings(conn,findings,snapshot,streaks)['canRestartGateway'])
            self.wall-=900000
            self.assertFalse(m.policy_from_findings(conn,findings,snapshot,streaks)['canRestartGateway'])
            self.wall+=60000;self.mono+=60000
            self.assertFalse(m.policy_from_findings(conn,findings,snapshot,streaks)['canRestartGateway'])
            self.wall+=1740000;self.mono+=1740000
            policy=m.policy_from_findings(conn,findings,snapshot,streaks)
            self.assertTrue(policy['canRestartGateway'],policy['restartBlockedReasons'])

    def test_terminal_mirror_failure_keeps_executing_and_does_not_repeat(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute("CREATE TRIGGER fixture_failure BEFORE INSERT ON kv WHEN NEW.key='stabilityd_last_gateway_restart_at' BEGIN SELECT RAISE(ABORT,'fixture-disk-error'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.execute('openclaw.gateway.restart')
        self.assertEqual(len(self.effects),1)
        with ActionLedger(self.path) as ledger:
            self.assertEqual(ledger.startup_reconcile_candidates()[0].state,'executing')
            self.assertEqual(ledger._conn.execute('SELECT count(*) FROM stability_clock_history').fetchone()[0],0)
            self.assertEqual(ledger._conn.execute('SELECT count(*) FROM kv').fetchone()[0],0)
        self.assertEqual(self.execute('openclaw.gateway.restart').disposition,'existing')
        self.assertEqual(len(self.effects),1)

    def test_postcheck_clock_jump_keeps_executing_and_prior_timing(self):
        from stability_core.clock_discipline import ClockRefused
        self.execute('hermes.gateway.restart', 'prior')
        with sqlite3.connect(self.path) as conn:
            before = {table: conn.execute('SELECT * FROM '+table+' ORDER BY 1').fetchall()
                      for table in ('stability_clock_windows','stability_clock_history','kv')}
        self.postcheck_jump = True
        with self.assertRaises(ClockRefused):
            self.execute('openclaw.gateway.restart', 'postcheck-jump')
        with ActionLedger(self.path) as ledger:
            self.assertEqual(ledger.startup_reconcile_candidates()[0].state, 'executing')
            for table, rows in before.items():
                self.assertEqual([tuple(row) for row in ledger._conn.execute('SELECT * FROM '+table+' ORDER BY 1')], rows)
        self.postcheck_jump = False
        self.assertEqual(self.execute('openclaw.gateway.restart', 'postcheck-jump').disposition, 'existing')
        self.assertEqual(len(self.effects), 2)

    def test_lock_context_same_thread_reuse_other_thread_refused(self):
        import concurrent.futures, contextvars
        from stability_core.actuation_lock import ActuationBusy
        with m.governed_actuation_context():
            with m.governed_actuation_context():pass
            copied=contextvars.copy_context()
            def attempt():
                with self.assertRaises(ActuationBusy):
                    with m.governed_actuation_context():pass
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(copied.run,attempt).result(timeout=3)
            with mock.patch.object(m.os,'getpid',return_value=-1):
                with self.assertRaises(ActuationBusy):
                    with m.governed_actuation_context():pass

    def test_time_independent_effect_does_not_touch_clock(self):
        spec,policy=self.spec('openclaw.gateway.restart')
        policy=dict(updatedAtEpoch=self.wall//1000,validUntilEpoch=self.wall//1000+60,canReapHermersOrphanWorkers=True)
        digest,ref=m.policy_reference(policy)
        kind='hermes.process.orphan_reap'
        spec=dataclasses.replace(spec,action_type=kind,target='hermes-process:fixture',
            authorization_ref=m.STANDING_RULES[kind].authority_ref,policy_ref=ref,
            evidence_refs=('evidence://snapshot/test',ref,'policy-digest:sha256:'+digest))
        with mock.patch.object(m,'daemon_clock',side_effect=AssertionError('clock must not gate this effect')):
            result=m.execute_governed_effect(spec,policy,eligibility_evidence=lambda *a:('evidence://snapshot/test',),
                precheck=lambda *a:m.BoundaryCheck('approved','check://eligible'),
                operation=lambda *a:m.OperationResult('complete','outcome://done'),
                postcheck=lambda *a:m.PostcheckResult('verified','check://verified'))
        self.assertEqual(result.record.state,'succeeded')

if __name__=='__main__':unittest.main()
