#!/usr/bin/env python3
"""Exact-version managed Codex idle pool hotfix, dry-run by default."""
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED = {
    'shared-client-DqyTMYug.mjs': 'a37bdb0d992ed569e6538c17a3f60e4b6d7c436080e1873929b9dd23d3c08fe1',
    'shared-client-lifecycle-DJIgqgMw.mjs': '116208102bdef2d30d61575accc9d4a0f480c5c2d1ff49df136bb5c7c6ab2c36',
}
LEAF = 'resource-idle-pool-local.mjs'
GUARD = '''
function installCodexPoolIdleGuard(client) {
\tconst entry = getCurrentSharedClientEntry(client);
\tif (!entry) return;
\tentry.poolIdleGuard = () => {
\t\tconst runtime = configuredClients.get(client);
\t\tif (!runtime || runtime.closed) return { safe: false, reason: "runtime-unknown" };
\t\tfor (const field of ["retainedThreads", "claimedThreads", "releasingThreads", "protectedThreads", "workspaceReferences"]) {
\t\t\tif (!(runtime[field] instanceof Map)) return { safe: false, reason: "runtime-unknown" };
\t\t\tif (runtime[field].size) return { safe: false, reason: "thread-or-workspace-binding" };
\t\t}
\t\tif (!(client.pending instanceof Map) || !(client.serverRequests?.active instanceof Map)) return { safe: false, reason: "rpc-unknown" };
\t\tif (client.pending.size || client.serverRequests.active.size || client.catalogWorker?.continuation || client.decoder?.hasPending) return { safe: false, reason: "pending-rpc-or-decode" };
\t\tif (client.nativeExecutionObserved) return { safe: false, reason: "native-work-continuity" };
\t\treturn { safe: true };
\t};
}
'''

def replace_once(text, original, replacement):
    if text.count(original) != 1:
        raise ValueError('Unsupported source layout; no files written')
    return text.replace(original, replacement)

def candidates(setup):
    sources = {name: (setup/name).read_bytes() for name in EXPECTED}
    for name, content in sources.items():
        if hashlib.sha256(content).hexdigest() != EXPECTED[name]:
            raise ValueError('Source hash mismatch for ' + name + '; no files written')
    lifecycle = sources['shared-client-lifecycle-DJIgqgMw.mjs'].decode()
    lifecycle = 'import { armIdlePoolSweep, touchIdlePoolEntry } from "./' + LEAF + '";\n' + lifecycle
    lifecycle = replace_once(lifecycle, 'function retainSharedClientEntry(entry, counter = "activeLeases") {', 'function retainSharedClientEntry(entry, counter = "activeLeases") {\n\ttouchIdlePoolEntry(entry);\n\tarmIdlePoolSweep(getSharedCodexAppServerClientState(), retireSharedCodexAppServerClientIfCurrent);')
    lifecycle = replace_once(lifecycle, 'function releaseSharedClientEntry(entry, counter) {', 'function releaseSharedClientEntry(entry, counter) {\n\ttouchIdlePoolEntry(entry);')
    shared = sources['shared-client-DqyTMYug.mjs'].decode()
    shared = replace_once(shared, 'function ensureCodexAppServerClientRuntime(client, context) {', GUARD + '\nfunction ensureCodexAppServerClientRuntime(client, context) {\n\tinstallCodexPoolIdleGuard(client);')
    shared = replace_once(shared, '\tentry.startupAbort ??= new AbortController();', '\t// Durable inferred/adopted generation bindings outlive ordinary leases.\n\tentry.poolArtifactBound ||= options?.expectedRuntimeArtifact !== undefined;\n\tentry.startupAbort ??= new AbortController();')
    leaf = Path(__file__).resolve().parents[1]/'patches/codex-pool-2026.9.7/idle-pool.mjs'
    return sources, {'shared-client-lifecycle-DJIgqgMw.mjs': lifecycle.encode(), 'shared-client-DqyTMYug.mjs': shared.encode(), LEAF: leaf.read_bytes()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--setup-dir', required=True, type=Path)
    parser.add_argument('--artifact-dir', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    if args.apply and args.rollback:
        parser.error('apply and rollback are mutually exclusive')
    if args.rollback:
        manifest = json.loads((args.artifact_dir/'patch-manifest.json').read_text())
        if set(manifest['patched']) != set(EXPECTED) | {LEAF} or manifest['original'] != EXPECTED:
            raise ValueError('Unsupported rollback manifest')
        backups = {name: (args.artifact_dir/'backups'/name).read_bytes() for name in EXPECTED}
        for name, content in backups.items():
            if hashlib.sha256(content).hexdigest() != EXPECTED[name]:
                raise ValueError('Backup hash mismatch; no files written')
        for name, digest in manifest['patched'].items():
            if hashlib.sha256((args.setup_dir/name).read_bytes()).hexdigest() != digest:
                raise ValueError('Live code differs from patch; no files written')
        for name, content in backups.items():
            temp = args.setup_dir/(name+'.resource-rollback.tmp')
            temp.write_bytes(content)
            temp.replace(args.setup_dir/name)
        (args.setup_dir/LEAF).unlink()
        manifest['applied'] = False
        manifest['rolledBack'] = True
        (args.artifact_dir/'patch-manifest.json').write_text(json.dumps(manifest, indent=2))
        print(json.dumps({'rolledBack': True, 'artifact': str(args.artifact_dir), 'reloadRequired': True}))
        return
    originals, patched = candidates(args.setup_dir)
    if (args.setup_dir/LEAF).exists():
        raise ValueError('Local hotfix already exists; inspect instead of overwriting')
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    for folder in ['backups', 'candidate']:
        (args.artifact_dir/folder).mkdir(exist_ok=True)
    for name, content in originals.items():
        (args.artifact_dir/'backups'/name).write_bytes(content)
    for name, content in patched.items():
        (args.artifact_dir/'candidate'/name).write_bytes(content)
    manifest = {'original': EXPECTED, 'patched': {n: hashlib.sha256(v).hexdigest() for n,v in patched.items()}, 'applied': False, 'newFile': LEAF, 'scope': 'managed Codex idle-unbound clients only; no auth/routing/session edits'}
    (args.artifact_dir/'patch-manifest.json').write_text(json.dumps(manifest, indent=2))
    if args.apply:
        # All source/layout checks and backups are complete before any live write.
        for name, content in patched.items():
            temp = args.setup_dir/(name+'.resource-patch.tmp')
            temp.write_bytes(content)
            temp.replace(args.setup_dir/name)
        manifest['applied'] = True
        (args.artifact_dir/'patch-manifest.json').write_text(json.dumps(manifest, indent=2))
    print(json.dumps({'applied': args.apply, 'artifact': str(args.artifact_dir), 'files': list(patched)}))

if __name__ == '__main__':
    main()
