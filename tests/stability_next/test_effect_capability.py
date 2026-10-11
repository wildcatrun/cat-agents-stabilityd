"""Provider tests use actual temporary bytes and synthetic runtime-owned readers."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from stability_core.adapter_contract import AdapterContract, AdapterDescriptor
from stability_core.effect_capability import (
    CapabilityReceipt, EffectCapabilityProvider, EffectOperation as Op,
    EffectRequest, FileBinding, ProcessBinding, SchemaBinding, UnitBinding, UnitEffectiveConfiguration, resolve_requirement,
)
from stability_core.process_identity import IDENTITY_FIELDS, read_process_identity


class EffectCapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.now=1000000
        self.raw_boot='12345678-1234-1234-1234-123456789abc'
        self.node=('fixture-node','fixture-host:'+self.raw_boot)
        self.boot_path=self.root/'boot-id';self.boot_path.write_text(self.raw_boot)
        self.request=EffectRequest('cron.expired_lease.repair',Op.LEASE_FILES,'cron-lease:fixture',*self.node)
        self.lease=self.root/'lease.json';self.lease.write_text(json.dumps({'version':1,'target':self.request.target,'owner':'runtime:cron-runner'}))
        self.file=self.bind_file(self.lease,self.request,SchemaBinding('openclaw-lease-files-v1',self.request.target,'runtime:cron-runner'))
        self.binary=self.root/'binary';self.binary.write_bytes(b'synthetic-approved-binary')
        self.binary_sha=hashlib.sha256(self.binary.read_bytes()).hexdigest()

    def bind_file(self,path,request,schema):
        info=path.stat()
        return FileBinding(request,self.root,path,(info.st_dev,info.st_ino),hashlib.sha256(path.read_bytes()).hexdigest(),schema)

    def schema(self,raw):
        data=json.loads(raw)
        if data.get('version')!=1:raise ValueError('PRIVATE-FIXTURE-DETAIL')
        return SchemaBinding('openclaw-lease-files-v1',data['target'],data['owner'])

    def provider(self,**overrides):
        values=dict(clock_ms=lambda:self.now,node_reader=lambda:self.node,
                    file_reader=lambda request:self.file,schema_validator=self.schema,
                    boot_id_reader=lambda:self.boot_path.read_text().strip())
        values.update(overrides)
        return EffectCapabilityProvider(**values)

    def api(self, action='openclaw.session.reset', operation=Op.OPENCLAW_RPC, runtime='openclaw', capability='sessions.reset'):
        request=replace(self.request,action_type=action,operation=operation,target='runtime:fixture')
        contract=AdapterContract('fixture-api',1,'1.0.0','1.9.9','1.0.0','1.9.9',(runtime,),(capability,),(capability,),(('a'*40,self.binary_sha),))
        descriptor=AdapterDescriptor(runtime,'fixture-api','1.1.0','1.0.0','a'*40,request.node_id,request.generation,self.now,
            (capability,),'runtime-owned',str(self.binary),str(self.binary),self.binary_sha,self.binary_sha)
        return request,contract,descriptor

    def unit(self):
        request=replace(self.request,action_type='openclaw.gateway.restart',operation=Op.SYSTEMD_UNIT,target='openclaw-gateway:fixture')
        fragment=self.root/'openclaw-gateway.service';fragment.write_text('[Service]\nExecStart='+str(self.binary)+' --fixture\n')
        binding=UnitBinding(request,fragment.name,self.bind_file(fragment,request,SchemaBinding('systemd-unit-v1',request.target,'runtime:openclaw')),
                            self.binary,self.binary_sha,'runtime:openclaw',effective_config=UnitEffectiveConfiguration(
                                fragment,(),(str(self.binary),'--fixture'),request.node_id,request.generation,self.now,'complete'))
        return request,binding

    def test_closed_effect_resolver_distinguishes_cli_from_unit_and_unknown(self):
        self.assertEqual(resolve_requirement('hermes.gateway.restart',Op.HERMES_CLI).kind,'runtime-api')
        self.assertEqual(resolve_requirement('hermes.profile.lifecycle',Op.SYSTEMD_UNIT).kind,'local-mechanical')
        self.assertIsNone(resolve_requirement('openclaw.session.reset',Op.SYSTEMD_UNIT))
        self.assertIsNone(resolve_requirement('workflow.dispatch',Op.SYSTEMD_UNIT))
        self.assertIsNone(resolve_requirement('hermes.gateway.restart','systemd-unit'))

    def test_actual_file_schema_identity_and_receipt_have_no_action_authority(self):
        provider=self.provider();receipt=provider.assess(self.request)
        self.assertEqual(receipt.status,'verified');self.assertFalse(receipt.action_authorized)
        self.assertTrue(provider.accepts(receipt,self.request))
        self.assertNotIn('bound_request', receipt.evidence())
        self.assertNotIn(self.request.target, str(receipt))
        self.assertFalse(provider.accepts(receipt,replace(self.request,target='different-target')))
        self.assertFalse(self.provider().accepts(receipt,self.request))
        self.assertFalse(provider.accepts(CapabilityReceipt('verified','invented',receipt.requirement),self.request))
        with self.assertRaises(ValueError):CapabilityReceipt('verified','invented',receipt.requirement,action_authorized=True)

    def test_plain_dict_metadata_and_untrusted_provider_never_issue_verified(self):
        self.assertEqual(self.provider().assess(self.request.__dict__).status,'unknown')
        self.assertEqual(self.provider(file_reader=lambda _:self.file.__dict__).assess(self.request).status,'unknown')
        self.assertEqual(self.provider(schema_validator=lambda _:self.file.schema.__dict__).assess(self.request).status,'unknown')
        self.assertEqual(self.provider(source_kind='request-payload').assess(self.request).status,'unknown')
        self.assertEqual(self.provider(file_reader=None).assess(self.request).status,'unknown')

    def test_wrong_schema_owner_target_or_byte_digest_rejected(self):
        for field,value in [('schema',replace(self.file.schema,schema_id='unknown')),('schema',replace(self.file.schema,owner_ref='different')),
                            ('request',replace(self.request,target='different')),('sha256','0'*64)]:
            with self.subTest(field=field,value=value):
                self.assertEqual(self.provider(file_reader=lambda _,binding=replace(self.file,**{field:value}):binding).assess(self.request).status,'unknown')
        self.lease.write_text('{"version":2}')
        self.file=self.bind_file(self.lease,self.request,self.file.schema)
        result=self.provider().assess(self.request)
        self.assertEqual(result.status,'unknown');self.assertNotIn('PRIVATE-FIXTURE-DETAIL',str(result))

    def test_file_path_replacement_hardlink_and_symlink_rejected(self):
        provider=self.provider();self.lease.rename(self.root/'old-lease.json');self.lease.write_bytes((self.root/'old-lease.json').read_bytes())
        self.assertEqual(provider.assess(self.request).status,'unknown')
        self.file=self.bind_file(self.lease,self.request,self.file.schema)
        os.link(self.lease,self.root/'alias');self.assertEqual(provider.assess(self.request).status,'unknown')
        (self.root/'alias').unlink();self.lease.unlink();self.lease.symlink_to(self.root/'old-lease.json')
        self.assertEqual(provider.assess(self.request).status,'unknown')

    def test_receipt_stale_future_clock_and_generation_drift_fail_closed(self):
        provider=self.provider();receipt=provider.assess(self.request);self.now+=60001
        self.assertFalse(provider.accepts(receipt,self.request));self.now=1
        self.assertFalse(provider.accepts(receipt,self.request));self.node=('fixture-node','new-boot')
        self.assertEqual(provider.assess(self.request).status,'unknown');self.now=True
        self.assertEqual(provider.assess(self.request).status,'unknown')

    def test_api_real_binary_version_ttl_and_capability_negotiate(self):
        request,contract,descriptor=self.api()
        provider=self.provider(api_reader=lambda _:descriptor,api_contract=contract)
        self.assertEqual(provider.assess(request).status,'verified')
        for field,value in [('observed_at_ms',1),('observed_at_ms',self.now+5001),('generation','old'),
                            ('api_version','2.0.0'),('runtime','future'),('advertised_capabilities',()),('active_binary_sha256','0'*64)]:
            with self.subTest(field=field):
                current=replace(descriptor,**{field:value})
                self.assertNotEqual(self.provider(api_reader=lambda _,d=current:d,api_contract=contract).assess(request).status,'verified')

    def test_api_reader_node_or_clock_drift_cannot_issue_verified_receipt(self):
        request, contract, descriptor = self.api()
        for drift in ('node', 'slow', 'backwards'):
            with self.subTest(drift=drift):
                node = [self.node]
                clock = [self.now]
                def read(_):
                    if drift == 'node': node[0] = (self.node[0], 'changed')
                    elif drift == 'slow': clock[0] += 60001
                    else: clock[0] -= 1
                    return descriptor
                provider = self.provider(api_reader=read, api_contract=contract,
                    node_reader=lambda: node[0], clock_ms=lambda: clock[0])
                result = provider.assess(request)
                self.assertEqual(result.status, 'unknown')
                self.assertIsNone(result.evidence_ref)
                self.assertFalse(provider.accepts(result, request))
        self.binary.write_bytes(b'changed-real-bytes')
        self.assertNotEqual(provider.assess(request).status,'verified')

    def test_api_missing_dict_reader_and_wrong_artifact_pair_are_observation_only(self):
        request,contract,descriptor=self.api()
        self.assertEqual(self.provider().assess(request).status,'unknown')
        self.assertEqual(self.provider(api_reader=lambda _:descriptor.__dict__,api_contract=contract).assess(request).status,'unknown')
        result=self.provider(api_reader=lambda _:descriptor,api_contract=replace(contract,allowed_artifacts=(('b'*40,self.binary_sha),))).assess(request)
        self.assertEqual(result.status,'observation_only');self.assertFalse(result.action_authorized)

    def test_gateway_main_unavailable_keeps_actual_unit_mechanical_path(self):
        # No Gateway readiness/ACP callback is configured: only actual owned bytes.
        request,binding=self.unit();provider=self.provider(unit_reader=lambda _:binding)
        self.assertEqual(provider.assess(request).status,'verified')
        self.assertEqual(provider.assess(replace(request,action_type='openclaw.session.reset',operation=Op.OPENCLAW_RPC)).status,'unknown')
        self.binary.write_bytes(b'identity-drift')
        self.assertEqual(provider.assess(request).status,'unknown')

    def test_unit_reader_must_bind_fragment_execstart_target_and_owner(self):
        request,binding=self.unit()
        for altered in (replace(binding,request=replace(request,target='other')),replace(binding,runtime_owner_ref='other'),
                        replace(binding,unit='different.service')):
            self.assertEqual(self.provider(unit_reader=lambda _,b=altered:b).assess(request).status,'unknown')
        binding.fragment.path.write_text('[Service]\nExecStart=/other/binary\n')
        binding=replace(binding,fragment=self.bind_file(binding.fragment.path,request,binding.fragment.schema))
        self.assertEqual(self.provider(unit_reader=lambda _:binding).assess(request).status,'unknown')

    def test_actual_process_identity_owner_and_signal_protocol_without_acp(self):
        proc=self.root/'proc';pid=42;directory=proc/str(pid);directory.mkdir(parents=True)
        boot=proc/'sys/kernel/random';boot.mkdir(parents=True);(boot/'boot_id').write_text(self.raw_boot)
        fields=['S']+['0']*19;fields[19]='1234'
        (directory/'stat').write_text('42 (fixture) '+' '.join(fields));(directory/'status').write_text('Uid:\t1000\t1000\t1000\t1000\n')
        (directory/'cmdline').write_bytes(b'synthetic-worker\0');(directory/'cgroup').write_bytes(b'0::/synthetic\n')
        identity=read_process_identity(pid,proc)
        request=replace(self.request,action_type='hermes.process.orphan_reap',operation=Op.PIDFD_SIGNAL,target='hermes-process:fixture:42')
        binding=ProcessBinding(request,tuple(identity[k] for k in IDENTITY_FIELDS),'registry:fixture-profile')
        provider=self.provider(process_reader=lambda _:binding,process_owner_reader=lambda _:'registry:fixture-profile',
                               process_identity_reader=lambda p:read_process_identity(p,proc),process_protocol_reader=lambda:True)
        self.assertEqual(provider.assess(request).status,'verified')
        fields[19]='1235';(directory/'stat').write_text('42 (fixture) '+' '.join(fields))
        self.assertEqual(provider.assess(request).status,'unknown')
        fields[19]='1234';(directory/'stat').write_text('42 (fixture) '+' '.join(fields))
        provider.process_owner_reader=lambda _:'revoked-owner'
        self.assertEqual(provider.assess(request).status,'unknown')
        provider.process_owner_reader=lambda _:'registry:fixture-profile';provider.process_protocol_reader=lambda:False
        self.assertEqual(provider.assess(request).status,'unknown')

    def process_binding(self):
        proc=self.root/'process-fixture';pid=42;directory=proc/str(pid);directory.mkdir(parents=True)
        kernel=proc/'sys/kernel/random';kernel.mkdir(parents=True);(kernel/'boot_id').write_text(self.raw_boot)
        fields=['S']+['0']*19;fields[19]='1234'
        (directory/'stat').write_text('42 (fixture) '+' '.join(fields))
        (directory/'status').write_text('Uid:\t1000\t1000\t1000\t1000\n')
        (directory/'cmdline').write_bytes(b'synthetic-worker\0');(directory/'cgroup').write_bytes(b'0::/synthetic\n')
        observed=read_process_identity(pid,proc)
        request=replace(self.request,action_type='hermes.process.orphan_reap',operation=Op.PIDFD_SIGNAL,target='hermes-process:fixture:42')
        binding=ProcessBinding(request,tuple(observed[k] for k in IDENTITY_FIELDS),'registry:fixture-profile')
        provider=self.provider(process_reader=lambda _:binding,process_owner_reader=lambda _:'registry:fixture-profile',
                               process_identity_reader=lambda p:read_process_identity(p,proc),process_protocol_reader=lambda:True)
        return request,binding,provider

    def test_canonical_host_generation_and_raw_kernel_boot_are_independent(self):
        request,binding,provider=self.process_binding()
        self.assertEqual(request.generation,'fixture-host:'+self.raw_boot)
        self.assertEqual(binding.instance[4],self.raw_boot)
        receipt=provider.assess(request)
        self.assertEqual(receipt.status,'verified');self.assertTrue(provider.accepts(receipt,request))
        self.boot_path.write_text('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
        self.assertEqual(provider.assess(request).status,'unknown')
        self.assertFalse(provider.accepts(receipt,request))

    def test_boot_reader_is_not_request_mapping_and_both_readers_rechecked(self):
        request,binding,provider=self.process_binding()
        provider.boot_id_reader=lambda:request.generation
        self.assertEqual(provider.assess(request).status,'unknown')
        readings=iter([self.raw_boot,'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'])
        provider.boot_id_reader=lambda:next(readings)
        self.assertEqual(provider.assess(request).status,'unknown')
        provider.boot_id_reader=lambda:self.raw_boot
        nodes=iter([self.node,('fixture-node','changed-host-generation')])
        provider.node_reader=lambda:next(nodes)
        self.assertEqual(provider.assess(request).status,'unknown')

    def test_unit_complete_dropin_set_and_effective_argv_are_verified(self):
        request,binding=self.unit();path=self.root/'override.conf'
        path.write_text('[Service]\nExecStart=\nExecStart='+str(self.binary)+' "argument with spaces"\n')
        file=self.bind_file(path,request,binding.fragment.schema)
        config=replace(binding.effective_config,dropin_paths=(path,),execstart_argv=(str(self.binary),'argument with spaces'))
        complete=replace(binding,dropin_files=(file,),effective_config=config)
        self.assertEqual(self.provider(unit_reader=lambda _:complete).assess(request).status,'verified')
        for bad in (replace(complete,dropin_files=()),replace(complete,effective_config=None),
                    replace(complete,effective_config=replace(config,coverage='partial')),
                    replace(complete,effective_config=replace(config,execstart_argv=(str(self.binary),'wrong'))),
                    replace(complete,effective_config=replace(config,generation='old')),
                    replace(complete,effective_config=replace(config,observed_at_ms=1))):
            self.assertEqual(self.provider(unit_reader=lambda _,b=bad:b).assess(request).status,'unknown')
        path.write_text('[Service]\nExecStart=\nExecStart=/different/binary\n')
        self.assertEqual(self.provider(unit_reader=lambda _:complete).assess(request).status,'unknown')

    def test_unit_minimal_systemd_syntax_refuses_expansion_escape_and_multiple(self):
        request,binding=self.unit()
        for command in ('-'+str(self.binary),'@'+str(self.binary),str(self.binary)+' $TOKEN',
                        str(self.binary)+' %i',str(self.binary)+' argument\\ with\\ spaces',
                        str(self.binary)+' "mixed"token',str(self.binary)+'\nExecStart='+str(self.binary)):
            with self.subTest(command=command):
                binding.fragment.path.write_text('[Service]\nExecStart='+command+'\n')
                updated=replace(binding,fragment=self.bind_file(binding.fragment.path,request,binding.fragment.schema))
                self.assertEqual(self.provider(unit_reader=lambda _:updated).assess(request).status,'unknown')

    def test_constructor_budget_bounds_and_callback_failures_redacted(self):
        for bound in (True,0,60001):
            with self.assertRaises(ValueError):self.provider(max_age_ms=bound)
        def unavailable(_):raise RuntimeError('SYNTHETIC-PRIVATE-CONTENT')
        result=self.provider(file_reader=unavailable).assess(self.request)
        self.assertEqual(result.reason,'provider-evidence-unavailable');self.assertNotIn('SYNTHETIC-PRIVATE-CONTENT',str(result))


if __name__=='__main__':unittest.main()
