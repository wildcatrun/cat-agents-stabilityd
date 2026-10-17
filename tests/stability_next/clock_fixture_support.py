"""Declared test-only Linux-clock stand-in; production admission is unchanged."""
import contextlib
import unittest
from stability_core.daemon_clock import DaemonClock
from stability_core.action_ledger import ActionLedger


def install_clock_fixture(testcase, module, lock_path):
    from unittest import mock
    def factory(conn):
        # Old isolated ledger tests did not install the daemon's legacy KV table.
        conn.execute('CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY,value TEXT,updated_at INTEGER)')
        return DaemonClock(conn, restart_ms=module.RESTART_COOLDOWN_SECONDS*1000,
            restart_window_ms=module.RESTART_WINDOW_SECONDS*1000,
            session_ms=module.SESSION_RESET_COOLDOWN_SECONDS*1000,
            lifecycle_ms=module.HERMERS_PROFILE_LIFECYCLE_COOLDOWN_SECONDS*1000,
            max_restarts=module.MAX_RESTARTS_PER_WINDOW,
            sampler=lambda:dict(boot_id='11111111-2222-3333-4444-555555555555',
                wall_ms=module.epoch()*1000,mono_ms=100000))
    original_policy_reference = module.policy_reference
    epochs = {}
    def fixture_policy_reference(policy):
        # Bind before hashing. A separate real FULL/WAL ledger connection creates
        # the synthetic epoch, just as collection precedes effect admission.
        # Cache only this test's policy epoch: replay must not require a new clock
        # sample or silently rebind old evidence to a different current epoch.
        if isinstance(policy, dict) and 'clockDiscipline' not in policy:
            key = str(module.STATE_DB)
            if key not in epochs:
                with ActionLedger(module.STATE_DB) as ledger:
                    with ledger._write():
                        proof = factory(ledger._conn).observe()
                        if not proof.usable:
                            raise AssertionError('synthetic fixture clock unavailable')
                        epochs[key] = proof.epoch
            policy['clockDiscipline'] = {'state':'available', 'epoch':epochs[key],
                'executionFence':'required-for-time-dependent-effects'}
        return original_policy_reference(policy)
    for patch in (mock.patch.object(module,'policy_reference',side_effect=fixture_policy_reference),
                  mock.patch.object(module,'daemon_clock',side_effect=factory),
                  mock.patch.object(module,'ACTUATION_LOCK_PATH',lock_path)):
        patch.start();testcase.addCleanup(patch.stop)


@contextlib.contextmanager
def clock_fixture_context(module, lock_path):
    owner = unittest.TestCase()
    try:
        install_clock_fixture(owner, module, lock_path)
        yield
    finally:
        owner.doCleanups()
