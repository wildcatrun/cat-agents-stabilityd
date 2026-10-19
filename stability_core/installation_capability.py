"""Artifact-bound installation contracts; registry owns targets, not this file.

Approved source semantics/layout are immutable release inputs. Current process
birth/boot and protocol observations remain the responsibility of route readers.
No environment, action payload or measured hash can approve an installation.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re

from .adapter_contract import AdapterContract
from .content_artifact import ContentArtifactSpec
from .effect_capability import read_local_boot_id, EffectRequest
from .hermes_native_route import NativeQualification, MuxQualification, _read_program_source
from .hermes_profile_config import read_profile_config
from .session_api_capability import SessionApiQualification, SessionSdkQualification

PACKAGED_MANIFEST = Path(__file__).with_name('qualified_installations_v1.json')
PACKAGED_MANIFEST_SHA256 = 'c2f5af4169e685caabe6d13222e9bb4b22c30f760fa2c67ddbcb419b95c6e95f'
PROFILE = re.compile(r'[A-Za-z0-9_-]{1,64}')
SHA = re.compile(r'[0-9a-f]{64}')


@dataclass(frozen=True)
class InstallationDecision:
    status: str
    reason: str
    qualification: object | None = None
    contract_id: str | None = None
    action_authorized: bool = False

    def __post_init__(self):
        if self.action_authorized is not False:
            raise ValueError('installation contract cannot authorize effects')


def _path(value):
    if (type(value) is not str or not value or len(value)>512
            or not Path(value).is_absolute() or '..' in Path(value).parts
            or re.search(r'[\x00-\x1f\x7f]',value)):
        raise ValueError('installation path refused')
    return Path(value)


def _relative(value):
    if (type(value) is not str or not value or PurePosixPath(value).is_absolute()
            or str(PurePosixPath(value))!=value or '..' in PurePosixPath(value).parts
            or '\\' in value):raise ValueError('installation source path refused')
    return value


def _digest(value):
    if type(value) is not str or SHA.fullmatch(value) is None:
        raise ValueError('installation digest refused')
    return value


def _render_template(value, values):
    if type(value) is not str:
        raise ValueError('installation template type refused')
    # Only the three declared routing placeholders are templates. Literal
    # braces in a fixed argv element (e.g. Python -c code) are ordinary bytes.
    return re.sub(r'\{(profile|home|runtime_root)\}',lambda match:values[match[1]],value)


def _unique(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('installation duplicate field')
        result[key]=value
    return result


def _unknown_reason(exc):
    # Typed fixed categories only: never persist paths, source bodies or env.
    return {
        'installation scope unknown or ambiguous':'installation-scope-unknown-or-ambiguous',
        'installation layout qualification pending':'installation-layout-pending',
        'installation execution owner refused':'installation-owner-mismatch',
        'installation source contract unknown':'installation-source-contract-unknown',
        'installation source semantics unsupported':'installation-source-semantics-unapproved',
        'installation authoritative registry unavailable':'installation-registry-unavailable',
        'installation registry owner unknown or ambiguous':'installation-registry-owner-unknown',
        'installation boot generation changed':'installation-runtime-generation-changed',
    }.get(str(exc),'installation-input-or-observation-unavailable')


class InstallationFactory:
    """Construct existing qualification types from a reviewed artifact only.

    Tests may supply a separately pinned owned fixture artifact. Production
    calls load_packaged_installations(), never a path/digest from a request.
    """
    def __init__(self, manifest, *, boot_reader=read_local_boot_id, plugin_root=None):
        self._manifest=manifest
        self._boot_reader=boot_reader
        self._plugin_root=Path(__file__).parent if plugin_root is None else plugin_root

    @classmethod
    def from_artifact(cls, path, expected_sha256, *, owner_uid=None, boot_reader=read_local_boot_id):
        uid=os.geteuid() if owner_uid is None else owner_uid
        record,raw=_read_program_source(_path(str(path)),owner_uid=uid,include_bytes=True)
        if record[1]!=_digest(expected_sha256):raise ValueError('installation artifact identity mismatch')
        data=json.loads(raw,object_pairs_hook=_unique)
        if (type(data) is not dict or set(data)!={'schemaVersion','sourceContracts','installations'}
                or type(data['schemaVersion']) is not int or data['schemaVersion']!=1
                or type(data['sourceContracts']) is not list or not data['sourceContracts']
                or type(data['installations']) is not list or not data['installations']
                or len(data['sourceContracts'])>16 or len(data['installations'])>16):
            raise ValueError('installation artifact schema refused')
        contract_ids=[c.get('id') for c in data['sourceContracts'] if type(c) is dict]
        installation_ids=[c.get('id') for c in data['installations'] if type(c) is dict]
        if (len(contract_ids)!=len(data['sourceContracts']) or len(set(contract_ids))!=len(contract_ids)
                or len(installation_ids)!=len(data['installations']) or len(set(installation_ids))!=len(installation_ids)):
            raise ValueError('installation artifact duplicate identities')
        # Keep no externally supplied mutable references.
        return cls(json.loads(json.dumps(data)),boot_reader=boot_reader,plugin_root=Path(path).parent)

    def _installation(self, request, family):
        matches=[i for i in self._manifest['installations']
                 if i.get('nodeId')==request.node_id and i.get('family')==family]
        if len(matches)!=1:raise ValueError('installation scope unknown or ambiguous')
        item=matches[0]
        if item.get('status')!='qualified':raise ValueError('installation layout qualification pending')
        if type(item.get('ownerUid')) is not int or item['ownerUid']!=os.geteuid():
            raise ValueError('installation execution owner refused')
        return item

    def _contract(self, contract_id, family, kind):
        matches=[c for c in self._manifest['sourceContracts'] if c.get('id')==contract_id]
        if len(matches)!=1:raise ValueError('installation source contract unknown')
        contract=matches[0]
        expected={'native':'reviewed-hermes-profile-standalone-source-window-v1',
                  'mux':'reviewed-hermes-mux-cli-logical-membership-v1',
                  'session':'v1'}[kind]
        if (contract.get('status','reviewed')!='reviewed'
                or contract.get('family')!=family or contract.get('kind')!=kind
                or contract.get('semantics')!=expected):
            raise ValueError('installation source semantics unsupported')
        return contract

    def _sources(self, contract, root):
        files=contract.get('files')
        if type(files) is not list or not 1<=len(files)<=64:raise ValueError('installation source budget')
        records=[]
        for item in files:
            if type(item) is not dict or not {'path','sha256'}<=set(item):raise ValueError('installation source schema')
            records.append((root/_relative(item['path']),_digest(item['sha256'])))
        if len({p for p,_ in records})!=len(records):raise ValueError('installation duplicate source')
        return tuple(records)

    def _owner(self, records, *, family, profile=None, agent_id=None):
        if type(records) is not list:raise ValueError('installation registry records unavailable')
        matches=[]
        for row in records:
            if (type(row) is not dict or row.get('status')!='active'
                    or row.get('can_receive_dispatch') not in (1,True)):continue
            values={str(row.get(k) or '') for k in ('runtime','platform','execution_adapter','workflow_ingress_adapter')}
            if 'openclaw_route_shell' in values:continue
            if family=='hermes':
                if row.get('runtime') not in {'hermes','hermers','hermes_acp','hermers_acp'}:continue
                endpoint=str(row.get('endpoint_ref') or '')
                endpoint_match=re.fullmatch(r'herm(?:es|ers)-profile:([A-Za-z0-9_-]{1,64})',endpoint,re.I)
                if not (values & {'hermes','hermers','hermes_acp','hermers_acp'}) or endpoint_match is None:continue
                if endpoint_match[1].lower()!=profile.lower():continue
            else:
                if row.get('runtime')!='openclaw' or row.get('agent_id')!=agent_id:continue
                if row.get('endpoint_ref')!='openclaw-agent:'+agent_id:continue
            matches.append(row)
        if len(matches)!=1 or not matches[0].get('agent_id'):
            raise ValueError('installation registry owner unknown or ambiguous')
        return matches[0]

    def hermes(self, request, registry, profile):
        try:
            if (type(request) is not EffectRequest or type(profile) is not str
                    or PROFILE.fullmatch(profile) is None or profile=='default'
                    or request.action_type not in {'hermes.gateway.restart','hermes.profile.lifecycle'}
                    or request.target!=('hermes-gateway:' if request.action_type=='hermes.gateway.restart' else 'hermes-profile:')+profile):
                raise ValueError('installation Hermes target refused')
            self._registry_gate(registry)
            self._owner(registry['records'],family='hermes',profile=profile)
            item=self._installation(request,'hermes')
            root=_path(item['runtimeRoot']);code=_path(item['codeRoot']);home=root/'profiles'/profile
            kind='native' if read_profile_config(home,profile=profile,runtime_root=root,owner_uid=item['ownerUid']).standalone else 'mux'
            contract=self._contract(item['contracts'][kind],'hermes',kind)
            sources=self._sources(contract,code)
            values={'profile':profile,'home':str(home),'runtime_root':str(root)}
            def render(value):
                return _render_template(value,values)
            common=dict(owner_uid=item['ownerUid'],runtime_root=root,target_profile=profile,
                        sources=sources,provenance_ref='evidence://installation-contract/'+contract['id'])
            if kind=='native':
                alternatives = ()
                if 'unitEnvironmentSha256s' in item:
                    raw_digests = item['unitEnvironmentSha256s']
                    if (type(raw_digests) is not list or not 1 <= len(raw_digests) <= 16
                            or 'unitEnvironmentSha256' in item or 'unitEnvironmentTemplate' in item):
                        raise ValueError('installation environment digest set refused')
                    alternatives = tuple(_digest(value) for value in raw_digests)
                    if len(set(alternatives)) != len(alternatives):
                        raise ValueError('installation environment digest duplicate')
                    environment_digest = ''
                else:
                    environment_digest = (_digest(item['unitEnvironmentSha256']) if 'unitEnvironmentSha256' in item else
                        hashlib.sha256(render(item['unitEnvironmentTemplate']).encode()).hexdigest())
                q=NativeQualification(**common,unit_roots=tuple(_path(p) for p in item['unitRoots']),
                    argv=tuple(render(v) for v in item['nativeArgv']),
                    executable_sha256=_digest(item['interpreterSha256']),
                    absent_sources=tuple(_path(render(p)) for p in item['absentSources']),
                    manager_sha256=_digest(item['managerSha256']),
                    environment_sha256=environment_digest, environment_sha256s=alternatives)
            else:
                # Expected command bytes come from approved launch shape. Boot
                # is current kernel instance evidence, not semantic approval.
                boot=self._boot_reader()
                if type(boot) is not str or request.generation!=request.node_id+':'+boot.lower():
                    raise ValueError('installation boot generation changed')
                # Peer argv is an exact launch declaration, never a template:
                # even a literal '{profile}' inside -c code must stay intact.
                peer_argv=tuple(item['muxPeerArgv'])
                if (not 1<=len(peer_argv)<=64 or any(type(v) is not str or not v
                        or len(v)>65536 or '\x00' in v for v in peer_argv)):
                    raise ValueError('installation peer argv refused')
                q=MuxQualification(**common,interpreter_entry=_path(item['interpreterEntry']),
                    interpreter_sha256=_digest(item['interpreterSha256']),cli_entry=_path(item['cliEntry']),
                    cli_sha256=_digest(item['cliSha256']),
                    environment=tuple((key,render(value)) for key,value in item['muxEnvironment']),cwd=home,
                    socket_path=_path(render(item['socketPath'])),host_home=_path(render(item['hostHome'])),
                    peer_cmdline_digest=hashlib.sha256(b'\0'.join(v.encode() for v in peer_argv)+b'\0').hexdigest(),
                    peer_boot_id=boot,code_root=code,
                    bridge_entry=self._plugin_root/'hermes_mux_bridge.py',
                    bridge_sha256=_digest(contract['bridgeSha256']))
            return InstallationDecision('supported-'+kind,'reviewed-installation-contract',q,contract['id'])
        except (ValueError,KeyError,TypeError,OSError) as exc:
            return InstallationDecision('unknown',_unknown_reason(exc))

    @staticmethod
    def _registry_gate(registry):
        if (type(registry) is not dict or registry.get('source')!='db' or registry.get('writeEligible') is not True):
            raise ValueError('installation authoritative registry unavailable')

    def session(self, request, registry, agent_id):
        try:
            if type(request) is not EffectRequest or not request.target.startswith('openclaw-session:'):
                raise ValueError('installation session target refused')
            self._registry_gate(registry)
            self._owner(registry['records'],family='openclaw',agent_id=agent_id)
            if request.action_type!='openclaw.session.reset':raise ValueError('installation session action refused')
            item=self._installation(request,'openclaw')
            contract=self._contract(item['contract'],'openclaw','session')
            root=_path(item['codeRoot']);sources=self._sources(contract,root)
            spec=ContentArtifactSpec(root,contract['packageName'],contract['packageVersion'],tuple(str(p.relative_to(root)) for p,_ in sources))
            records=tuple((row['path'],row['sha256'],row['bytes']) for row in sorted(contract['files'],key=lambda r:r['path']))
            digest=hashlib.sha256(json.dumps(dict(schemaVersion=1,packageName=spec.package_name,packageVersion=spec.package_version,files=records),
                sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
            cli_relative=_relative(item['cliRelative'])
            cli_sha=next(d for p,d in sources if p==root/cli_relative)
            adapter=AdapterContract('installation-session-sdk-v1',4,'4.0.0','4.0.0',spec.package_version,spec.package_version,
                ('openclaw',),('sessions.describe','sessions.reset'),('sessions.describe','sessions.reset'),(),((digest,cli_sha),))
            sdk=SessionSdkQualification(_relative(contract['sdkEntry']),self._plugin_root/'session_sdk_bridge.mjs',
                _digest(contract['wrapperSha256']),contract['serverVersion'],contract['serverBuildId'])
            listener_address=item.get('listenerAddress','127.0.0.1')
            if type(listener_address) is not str or listener_address not in {'127.0.0.1','0.0.0.0'}:
                raise ValueError('installation listener address refused')
            q=SessionApiQualification(spec,adapter,_path(item.get('cliEntry',str(root/cli_relative))),cli_relative,'',item['ownerUid'],
                'evidence://session-api-qualification/installation/'+contract['id'],item['endpointPort'],
                tuple(_path(p) for p in item['unitRoots']),proc_root=_path(item.get('procRoot','/proc')),rpc_environment=tuple(tuple(v) for v in item['rpcEnvironment']),sdk=sdk,
                listener_address=listener_address)
            return InstallationDecision('supported-session','reviewed-installation-contract',q,contract['id'])
        except (ValueError,KeyError,TypeError,OSError,StopIteration) as exc:
            return InstallationDecision('unknown',_unknown_reason(exc))


def load_packaged_installations():
    return InstallationFactory.from_artifact(PACKAGED_MANIFEST,PACKAGED_MANIFEST_SHA256)
