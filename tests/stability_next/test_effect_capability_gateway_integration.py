"""Actual restart prechecks/ledger and files, synthetic systemctl transport only."""
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from stability_core import unit_capability
from stability_core.protected_scope import ProtectionDecision

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('gateway_capability_fixture', ROOT / 'bin/cat_agents_stabilityd.py')
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


class GatewayCapabilityIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.binary = self.root / 'runtime'; self.binary.write_bytes(b'synthetic-runtime')
        self.binary.chmod(0o700)
        self.unit = self.root / 'openclaw-gateway.service'
        self.unit.write_text('[Service]\nExecStart=' + str(self.binary) + ' --fixture\n')
        self.props = ('Id=openclaw-gateway.service\nLoadState=loaded\nFragmentPath=' + str(self.unit)
                      + '\nDropInPaths=\nExecStart={ path=' + str(self.binary) + ' ; argv[]='
                      + str(self.binary) + ' --fixture ; ignore_errors=no ; }\n')
        self.effects = []
        self.reads = 0
        self.generation = 'fixture-node:fixture-boot'
        self.scope = ProtectionDecision('clear', 'fixture', ('cat_voice',), (), self.generation)
        registry = dict(source='db', writeEligible=True, records=[dict(agent_id='cat_voice',
            runtime='openclaw', platform='openclaw', execution_adapter='openclaw',
            endpoint_ref='openclaw-agent:cat_voice', status='active', can_receive_dispatch=1,
            can_start_workflow=1, gateway_proxy_allowed=1)])
        def command(argv, **kwargs):
            if argv[:3] == ['systemctl', 'show', 'openclaw-gateway.service']:
                self.reads += 1
                return SimpleNamespace(returncode=0, stdout=self.props, stderr='')
            if argv == ['sudo', '-n', 'systemctl', 'restart', 'openclaw-gateway.service']:
                self.effects.append(tuple(argv))
                return SimpleNamespace(returncode=0, stdout='', stderr='')
            raise AssertionError('unexpected external command')
        patches = [mock.patch.object(unit_capability, 'UNIT_ROOTS', (self.root,)),
            mock.patch.object(m, 'epoch', return_value=1000),
            mock.patch.object(m, 'now_ms', return_value=1000000),
            mock.patch.object(m, 'STATE_DB', self.root / 'ledger.db'),
            mock.patch.object(m, 'current_host_generation', return_value=self.generation),
            mock.patch.object(m, 'workflow_runtime_registry_records', return_value=registry),
            mock.patch.object(m, 'run_cmd', side_effect=command),
            mock.patch.object(m, 'gateway_collect', side_effect=AssertionError('Gateway disabled')),
            mock.patch.object(m, 'systemctl_show_gateway', return_value=dict(ActiveState='active', SubState='running')),
            mock.patch.object(m, 'tcp_ok', return_value=True),
            mock.patch.object(m, 'gateway_http_health', return_value=dict(ok=True)),
            mock.patch.object(m, 'record_restart_time')]
        for patch in patches:
            patch.start(); self.addCleanup(patch.stop)

    def call(self):
        now = m.epoch()
        policy = dict(canRestartGateway=True, restartCandidate=True, restartReason='fixture-hard-fault',
                      updatedAtEpoch=now - 1, validUntilEpoch=now + 60)
        return m.gateway_restart(mock.Mock(), 'fixture-hard-fault', self.scope,
                                 policy=policy, snapshot_generation='fixture-snapshot')

    def test_verified_mechanical_restart_survives_gateway_unavailable_and_deduplicates(self):
        first = self.call()
        self.assertEqual(first['result'], 'ok')
        self.assertEqual(first['capabilityEvidence']['status'], 'verified')
        self.assertFalse(first['capabilityEvidence']['actionAuthorized'])
        self.assertGreaterEqual(self.reads, 2)
        self.assertEqual(len(self.effects), 1)
        duplicate = self.call()
        self.assertEqual(duplicate['result'], 'existing')
        self.assertTrue(duplicate['historicalExisting'])
        self.assertFalse(duplicate['authorizationReused'])
        self.assertEqual(duplicate['ledgerDisposition'], 'existing')
        self.assertEqual(len(self.effects), 1)

    def test_incomplete_effective_properties_block_before_restart(self):
        self.props = self.props.replace('LoadState=loaded', 'LoadState=not-found')
        self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])

    def test_unknown_properties_do_not_persist_raw_diagnostics(self):
        sentinel = 'SYNTHETIC_PRIVATE_DIAGNOSTIC'
        self.props += 'Unexpected=' + sentinel + '\n'
        result = self.call()
        self.assertEqual(result['result'], 'blocked')
        self.assertNotIn(sentinel, str(result))
        self.assertNotIn(sentinel.encode(), (self.root / 'ledger.db').read_bytes())
        self.assertEqual(self.effects, [])

    def test_changed_unit_bytes_after_claim_block_restart(self):
        original = m.ActionLedger.begin_execution
        def change(ledger, *args, **kwargs):
            result = original(ledger, *args, **kwargs)
            self.unit.write_text(self.unit.read_text() + '# changed after claim\n')
            return result
        with mock.patch.object(m.ActionLedger, 'begin_execution', change):
            self.assertEqual(self.call()['result'], 'blocked')
        self.assertGreaterEqual(self.reads, 2)
        self.assertEqual(self.effects, [])

    def test_effective_command_conflict_blocks_restart(self):
        self.props = self.props.replace(' --fixture ;', ' --different ;')
        self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])

    def test_unit_symlink_blocks_restart(self):
        actual = self.root / 'actual-unit'
        self.unit.rename(actual)
        self.unit.symlink_to(actual)
        self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])

    def test_owned_executable_symlink_preserves_mechanical_restart(self):
        actual = self.root / 'actual-runtime'
        self.binary.rename(actual)
        self.binary.symlink_to(actual.name)
        self.assertEqual(self.call()['result'], 'ok')
        self.assertEqual(len(self.effects), 1)

    def test_executable_link_retarget_with_same_bytes_after_claim_blocks_restart(self):
        actual = self.root / 'actual-runtime'
        other = self.root / 'other-runtime'
        self.binary.rename(actual)
        other.write_bytes(actual.read_bytes()); other.chmod(0o700)
        self.binary.symlink_to(actual.name)
        original = m.ActionLedger.begin_execution
        def change(ledger, *args, **kwargs):
            result = original(ledger, *args, **kwargs)
            self.binary.unlink(); self.binary.symlink_to(other.name)
            return result
        with mock.patch.object(m.ActionLedger, 'begin_execution', change):
            self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])

    def test_executable_link_cycle_blocks_restart(self):
        self.binary.unlink()
        self.binary.symlink_to('cycle')
        (self.root / 'cycle').symlink_to(self.binary.name)
        self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])

    def test_executable_link_depth_budget_blocks_restart(self):
        actual = self.root / 'actual-runtime'
        self.binary.rename(actual)
        links = [self.binary] + [self.root / ('hop-' + str(n)) for n in range(9)]
        for index, link in enumerate(links):
            link.symlink_to((links[index + 1] if index + 1 < len(links) else actual).name)
        self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])

    def test_link_target_under_writable_parent_blocks_restart(self):
        parent = self.root / 'untrusted'
        parent.mkdir(); parent.chmod(0o777)
        actual = parent / 'actual-runtime'
        self.binary.rename(actual)
        self.binary.symlink_to('untrusted/actual-runtime')
        try:
            self.assertEqual(self.call()['result'], 'blocked')
            self.assertEqual(self.effects, [])
        finally:
            parent.chmod(0o700)

    def test_effective_executable_path_conflict_blocks_restart(self):
        self.props = self.props.replace('path=' + str(self.binary), 'path=/unknown/runtime')
        self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])

    def test_nonexecutable_runtime_blocks_restart(self):
        self.binary.chmod(0o600)
        self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])

    def test_writable_untrusted_unit_root_blocks_restart(self):
        self.root.chmod(0o777)
        try:
            self.assertEqual(self.call()['result'], 'blocked')
            self.assertEqual(self.effects, [])
        finally:
            self.root.chmod(0o700)

    def test_unobserved_dropin_cannot_claim_complete_effective_config(self):
        self.props = self.props.replace('DropInPaths=', 'DropInPaths=' + str(self.root / 'missing.conf'))
        self.assertEqual(self.call()['result'], 'blocked')
        self.assertEqual(self.effects, [])


if __name__ == '__main__': unittest.main()
