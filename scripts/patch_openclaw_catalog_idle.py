#!/usr/bin/env python3
"""Version/hash guarded opt-in catalog worker idle retirement; dry-run by default."""
import argparse
import hashlib
import json
from pathlib import Path

NAME = 'prepared-model-catalog-worker-BlxTBWOf.mjs'
BASELINE = 'eefbd7e4feec511583542f1644c53ee008cd4b6eb590b7b89eff68c407389a87'
OLD = '\t\tmaxWorkers: GATEWAY_CATALOG_WORKERS,\n\t\tidleTimeoutMs: 0,'
NEW = '\t\tmaxWorkers: GATEWAY_CATALOG_WORKERS,\n\t\tidleTimeoutMs: 6e4,'

def digest(data):
    return hashlib.sha256(data).hexdigest()

def candidate(data):
    if digest(data) != BASELINE:
        raise ValueError('Unsupported source hash; no live writes')
    text = data.decode()
    if text.count(OLD) != 1:
        raise ValueError('Unsupported source layout; no live writes')
    return text.replace(OLD, NEW).encode()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package-root', required=True, type=Path)
    p.add_argument('--artifact-dir', required=True, type=Path)
    action = p.add_mutually_exclusive_group()
    action.add_argument('--apply', action='store_true')
    action.add_argument('--rollback', action='store_true')
    a = p.parse_args()
    package = json.loads((a.package_root / 'package.json').read_text())
    if package.get('name') != 'openclaw' or package.get('version') != '2026.9.7':
        raise ValueError('Unsupported package; no live writes')
    live = a.package_root / 'dist' / NAME
    manifest = a.artifact_dir / 'catalog-idle-manifest.json'
    backup = a.artifact_dir / 'backups' / NAME
    before = live.read_bytes()
    if a.rollback:
        m = json.loads(manifest.read_text())
        original = backup.read_bytes()
        patched = candidate(original)
        if m.get('originalHash') != BASELINE or m.get('patchedHash') != digest(patched) or digest(before) != digest(patched):
            raise ValueError('Rollback hash mismatch; no live writes')
        temp = live.with_suffix('.catalog-idle-rollback.tmp')
        temp.write_bytes(original)
        temp.replace(live)
        m['applied'] = False
        m['rolledBack'] = True
        manifest.write_text(json.dumps(m, indent=2))
        print(json.dumps({'rolledBack': True, 'reloadRequired': True}))
        return
    after = candidate(before)
    # Preserve the first rollback evidence; repeated apply/dry-run is fail-closed.
    if manifest.exists() or backup.exists():
        raise ValueError('Artifact already contains rollback evidence; use a new dry-run directory')
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup.write_bytes(before)
    m = {'originalHash': BASELINE, 'patchedHash': digest(after), 'applied': False, 'scope': 'model catalog worker idle retirement only; native pool guards unchanged'}
    manifest.write_text(json.dumps(m, indent=2))
    if a.apply:
        temp = live.with_suffix('.catalog-idle-patch.tmp')
        temp.write_bytes(after)
        temp.replace(live)
        m['applied'] = True
        manifest.write_text(json.dumps(m, indent=2))
    print(json.dumps({'applied': a.apply, 'reloadRequired': a.apply, 'manifest': str(manifest), 'idleTimeoutMs': 60000}))

if __name__ == '__main__':
    main()
