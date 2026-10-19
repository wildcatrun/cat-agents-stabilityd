"""Translate reviewed test declarations to an owned release-artifact fixture.

No runtime observations are approved here. The declarations are independently
fixed expected source/launch contracts already used by existing route fixtures.
"""
import hashlib
import json
import os
from pathlib import Path
from stability_core.installation_capability import InstallationFactory


def artifact(path, contracts, layouts, *, boot='boot'):
    raw=(json.dumps(dict(schemaVersion=1,sourceContracts=contracts,installations=layouts),sort_keys=True)+'\n').encode()
    path.write_bytes(raw);path.chmod(0o600)
    return InstallationFactory.from_artifact(path,hashlib.sha256(raw).hexdigest(),boot_reader=lambda:boot)


def native_artifact(q, path, *, node_id, environment_template):
    root=Path(os.path.commonpath([str(p.parent) for p,_ in q.sources]))
    contract=dict(id='fixture-native-v1',family='hermes',kind='native',semantics=q.semantics,
        files=[dict(path=str(p.relative_to(root)),sha256=digest) for p,digest in q.sources])
    layout=dict(id='fixture-hermes-installation',family='hermes',nodeId=node_id,status='qualified',ownerUid=q.owner_uid,
        codeRoot=str(root),runtimeRoot=str(q.runtime_root),contracts=dict(native=contract['id']),unitRoots=[str(p) for p in q.unit_roots],
        nativeArgv=['{profile}' if value==q.target_profile else value for value in q.argv],
        interpreterSha256=q.executable_sha256,absentSources=[str(p) for p in q.absent_sources],
        managerSha256=q.manager_sha256,unitEnvironmentTemplate=environment_template)
    return artifact(path,[contract],[layout])


def session_artifact(q, path, raw_files, *, node_id):
    contract=dict(id='fixture-session-v1',family='openclaw',kind='session',semantics='v1',
        packageName=q.code.package_name,packageVersion=q.code.package_version,sdkEntry=q.sdk.entry_relative,
        wrapperSha256=q.sdk.wrapper_sha256,serverVersion=q.sdk.server_version,serverBuildId=q.sdk.server_build_id,
        files=[dict(path=name,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw)) for name,raw in raw_files.items()])
    layout=dict(id='fixture-openclaw-installation',family='openclaw',nodeId=node_id,status='qualified',ownerUid=q.runtime_uid,
        codeRoot=str(q.code.root),contract=contract['id'],cliRelative=q.gateway_entry_relative,
        endpointPort=q.endpoint_port,unitRoots=[str(p) for p in q.unit_roots],procRoot=str(q.proc_root),
        rpcEnvironment=[list(row) for row in q.rpc_environment])
    return artifact(path,[contract],[layout])


def mux_artifact(q, path, *, node_id, peer_argv):
    contract=dict(id='fixture-mux-v1',family='hermes',kind='mux',semantics=q.semantics,
        bridgeSha256=q.bridge_sha256,
        files=[dict(path=str(p.relative_to(q.code_root)),sha256=digest) for p,digest in q.sources])
    values={str(q.runtime_root/'profiles'/q.target_profile):'{home}'}
    def template(value):
        for old,new in values.items():value=value.replace(old,new)
        return value
    layout=dict(id='fixture-hermes-mux',family='hermes',nodeId=node_id,status='qualified',ownerUid=q.owner_uid,
        codeRoot=str(q.code_root),runtimeRoot=str(q.runtime_root),contracts=dict(mux=contract['id']),
        interpreterEntry=str(q.interpreter_entry),interpreterSha256=q.interpreter_sha256,
        cliEntry=str(q.cli_entry),cliSha256=q.cli_sha256,muxPeerArgv=list(peer_argv),
        muxEnvironment=[[key,template(value)] for key,value in q.environment],socketPath=str(q.socket_path),hostHome=str(q.host_home),
        pmBinding=dict(q.pm_binding))
    return artifact(path,[contract],[layout],boot=q.peer_boot_id)
