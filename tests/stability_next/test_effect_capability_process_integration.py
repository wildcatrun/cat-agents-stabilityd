"""Actual process leaf/prechecks/SQLite ledger, only effect and kernel fixture IO fake."""
import importlib.util
from dataclasses import replace
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from stability_core.process_identity import read_process_identity

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('effect_process_integration',ROOT/'bin/cat_agents_stabilityd.py')
m=importlib.util.module_from_spec(SPEC);sys.modules[SPEC.name]=m;SPEC.loader.exec_module(m)
REAL_PROTOCOL=m.process_effect_pidfd_protocol_available


class ProcessCapabilityIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.proc=self.root/'proc';self.pid=987654321
        self.directory=self.proc/str(self.pid);self.directory.mkdir(parents=True)
        self.raw_boot='12345678-1234-1234-1234-123456789abc'
        kernel=self.proc/'sys/kernel/random';kernel.mkdir(parents=True);self.boot=kernel/'boot_id';self.boot.write_text(self.raw_boot)
        self.fields=['S']+['0']*19;self.fields[19]='1234'
        self.write_stat()
        (self.directory/'status').write_text('Uid:\t1000\t1000\t1000\t1000\n')
        self.command='/opt/hermes -p catnose acp --accept-hooks'
        (self.directory/'cmdline').write_bytes(self.command.encode()+b'\0')
        (self.directory/'cgroup').write_bytes(b'0::/synthetic\n')
        self.identity=read_process_identity(self.pid,self.proc)
        self.worker={'pid':str(self.pid),'ppid':'1','cmd':self.command,'profile':'catnose',
                     'processIdentity':self.identity,'agentIds':['cat_nose'],'registryProfile':'catnose',
                     'registryProfileMatched':True,'registryScopeComplete':True,'ageSeconds':5000}
        self.registry={'source':'db','writeEligible':True,'records':[{'agent_id':'cat_nose','runtime':'hermes_acp',
            'platform':'hermes','execution_adapter':'hermes_acp','endpoint_ref':'hermes-profile:catnose',
            'status':'active','can_receive_dispatch':1}]}
        self.policy={'canReapHermersOrphanWorkers':True,'updatedAtEpoch':999999,'validUntilEpoch':1000060}
        self.patches=[mock.patch.object(m,'STATE_DB',self.root/'state.db'),
            mock.patch.object(m,'epoch',return_value=1000000),mock.patch.object(m.platform,'node',return_value='fixture-host'),
            mock.patch.object(m,'current_host_generation',return_value='fixture-host:'+self.raw_boot),
            mock.patch.object(m,'workflow_runtime_registry_records',side_effect=lambda:self.registry),
            mock.patch.object(m,'read_process_identity',side_effect=lambda pid:read_process_identity(pid,self.proc)),
            mock.patch('stability_core.effect_capability.read_local_boot_id',side_effect=lambda:self.boot.read_text()),
            mock.patch.object(m,'process_effect_pidfd_protocol_available',return_value=True)]
        for patch in self.patches:patch.start();self.addCleanup(patch.stop)

    def write_stat(self):
        (self.directory/'stat').write_text(str(self.pid)+' (fixture) '+' '.join(self.fields))

    def call(self,operation):
        with mock.patch.object(m,'terminate_process_instance',side_effect=operation):
            return m.execute_hermers_process_signal(self.worker,'hermes.process.orphan_reap',
                'canReapHermersOrphanWorkers',m.verify_hermers_orphan_worker,lambda:[self.worker],self.policy,'fixture-snapshot')

    def successful_effect(self,identity):
        self.assertEqual(identity,self.identity)
        shutil.rmtree(self.directory)
        return {'result':'succeeded','reason':'process-exited'}

    def test_actual_leaf_preserves_mechanical_action_with_gateway_main_unavailable(self):
        with mock.patch.object(m,'gateway_collect',side_effect=AssertionError('Gateway must not be needed')):
            operation=mock.Mock(side_effect=self.successful_effect);result=self.call(operation)
        self.assertEqual(result['result'],'ok');self.assertEqual(result['ledgerState'],'succeeded')
        self.assertEqual(result['capabilityEvidence']['status'],'verified')
        operation.assert_called_once_with(self.identity)

    def test_actual_two_prechecks_and_duplicate_never_repeat_effect(self):
        real_factory=m.process_effect_capability_provider
        with mock.patch.object(m,'process_effect_capability_provider',wraps=real_factory) as factory:
            operation=mock.Mock(side_effect=self.successful_effect);first=self.call(operation);second=self.call(operation)
        self.assertEqual(factory.call_count,2)
        self.assertEqual(first['result'],'ok');self.assertEqual(second['ledgerDisposition'],'existing')
        operation.assert_called_once()

    def test_protocol_missing_or_reader_stale_blocks_real_ledger_operation(self):
        for mode in ('protocol','generation'):
            # Fresh ledger for each deterministic refusal.
            with self.subTest(mode=mode),mock.patch.object(m,'STATE_DB',self.root/(mode+'.db')):
                real_factory=m.process_effect_capability_provider
                def factory(*args, **kwargs):
                    provider=real_factory(*args, **kwargs)
                    if mode=='protocol':provider.process_protocol_reader=lambda:False
                    else:provider.node_reader=lambda:('fixture-host','old-generation')
                    return provider
                operation=mock.Mock()
                with mock.patch.object(m,'process_effect_capability_provider',side_effect=factory):result=self.call(operation)
                self.assertEqual(result['result'],'blocked');self.assertEqual(result['ledgerState'],'blocked')
                operation.assert_not_called()

    def test_identity_change_after_claim_blocks_before_effect(self):
        real_factory=m.process_effect_capability_provider;calls=[]
        def factory(*args, **kwargs):
            calls.append(1)
            if len(calls)==2:self.fields[19]='1235';self.write_stat()
            return real_factory(*args, **kwargs)
        operation=mock.Mock()
        with mock.patch.object(m,'process_effect_capability_provider',side_effect=factory):result=self.call(operation)
        self.assertEqual(len(calls),2);self.assertEqual(result['result'],'blocked');operation.assert_not_called()

    def test_owner_revocation_inside_provider_blocks_effect(self):
        real_factory=m.process_effect_capability_provider
        def factory(*args, **kwargs):
            self.registry['records'][0]['status']='inactive'
            return real_factory(*args, **kwargs)
        operation=mock.Mock()
        with mock.patch.object(m,'process_effect_capability_provider',side_effect=factory):result=self.call(operation)
        self.assertEqual(result['result'],'blocked');operation.assert_not_called()

    def test_live_facts_cannot_be_replaced_by_item_metadata(self):
        self.fields[19]='1235';self.write_stat()
        self.worker['metadata']={'verified':True,'capability':'process.pidfd-reap'}
        operation=mock.Mock();result=self.call(operation)
        self.assertEqual(result['result'],'blocked');operation.assert_not_called()

    def test_factory_binds_exact_action_target_operation_node_and_generation(self):
        from stability_core.effect_capability import EffectOperation, EffectRequest
        generation='fixture-host:'+self.raw_boot
        provider=m.process_effect_capability_provider('catnose',['cat_nose'],generation,self.identity,
                                                     action_type='hermes.process.orphan_reap')
        request=EffectRequest('hermes.process.orphan_reap',EffectOperation.PIDFD_SIGNAL,
                             f'hermes-process:catnose:{self.pid}','fixture-host',generation)
        self.assertEqual(provider.assess(request).status,'verified')
        for changed in (replace(request,target=f'hermes-process:other:{self.pid}'),
                        replace(request,action_type='hermes.process.idle_lsp_reap'),
                        replace(request,operation=EffectOperation.SYSTEMD_UNIT),
                        replace(request,node_id='other-node'),replace(request,generation='old-generation')):
            with self.subTest(changed=changed):
                self.assertNotEqual(provider.assess(changed).status,'verified')
        with self.assertRaises(ValueError):
            m.process_effect_capability_provider('catnose',['cat_nose'],generation,self.identity,
                                                  action_type='workflow.dispatch')

    def test_real_protocol_probe_darwin_missing_api_is_unknown(self):
        with mock.patch.object(m.os,'pidfd_open',None,create=True):
            self.assertFalse(REAL_PROTOCOL())


if __name__=='__main__':unittest.main()
