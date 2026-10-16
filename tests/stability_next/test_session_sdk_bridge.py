"""Real Node bridge process against a synthetic SDK; no live Gateway coverage."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = ROOT / 'stability_core/session_sdk_bridge.mjs'

@unittest.skipUnless(shutil.which('node'), 'Node required')
class SessionSdkBridgeTests(unittest.TestCase):
    def run_bridge(self, *, mode='call', method='sessions.reset', change=None, vendor=''):
        # Avoid shared writable /tmp ancestors: the production bridge rejects those.
        with tempfile.TemporaryDirectory(prefix='.sdk-test-', dir=Path.home()) as directory:
            sdk = Path(directory) / 'sdk.mjs'
            sdk.write_text('''import fs from 'node:fs';
export async function r(o) {
 if(o.url!==undefined || o.expectUrl!=='ws://127.0.0.1:18789' || o.minProtocol!==4 || o.maxProtocol!==4 ||
 o.sharedStateMode!=='read-only' || o.clientName!=='cli' || o.mode!=='cli' ||
 JSON.stringify(o.scopes)!==JSON.stringify([o.method==='sessions.reset'?'operator.admin':'operator.read']) ||
 JSON.stringify(o.requiredMethods)!==JSON.stringify([o.method])) throw Error('options');
 let h={protocol:4,server:{version:'v1',buildId:'build1',bootId:'boot1'},
 features:{methods:['health','sessions.describe','sessions.reset']}};
''' + vendor + '''
 console.log('secret vendor diagnostic'); console.error('secret stderr');
 try {o.onHelloOk(h);} catch {}
 o.assertDispatchCurrent();
 return {done:true};
}
''')
            payload = dict(schema=1, mode=mode, sdkEntry=str(sdk),
                sources=[dict(path=str(sdk), sha256=hashlib.sha256(sdk.read_bytes()).hexdigest())],
                endpoint='ws://127.0.0.1:18789', server=dict(version='v1', buildId='build1', bootId=None if mode=='probe' else 'boot1'),
                method='health' if mode=='probe' else method,
                params={} if mode=='probe' else dict(key='agent:main:main', agentId='main'))
            if mode=='call' and method=='sessions.reset':
                payload['params']['expectedSessionId']='session1'
            if change:
                change(payload)
            result = subprocess.run([shutil.which('node'), str(BRIDGE), json.dumps(payload)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.stderr, '')
            self.assertNotIn('secret', result.stdout)
            return result.returncode, json.loads(result.stdout)

    def refused(self, **kwargs):
        code, result = self.run_bridge(**kwargs)
        self.assertEqual(code, 75)
        self.assertEqual(result, dict(ok=False,errorClass='SessionSdkBridgeRefused'))

    def test_probe(self):
        code, result = self.run_bridge(mode='probe')
        self.assertEqual(code, 0)
        self.assertIsNone(result['result'])
        self.assertEqual(result['hello']['bootId'], 'boot1')

    def test_reset_and_describe_scopes(self):
        for method in ['sessions.reset','sessions.describe']:
            code, result = self.run_bridge(method=method)
            self.assertEqual(code, 0)
            self.assertEqual(result['result'], {'done':True})

    def test_partial_probe_is_observed(self):
        code, result = self.run_bridge(mode='probe', vendor="h.features.methods=['health','sessions.describe'];")
        self.assertEqual(code, 0)
        self.assertEqual(result['hello']['methods'], ['sessions.describe'])

    def test_hello_mismatch(self):
        for vendor in ["h.protocol=3;", "h.server.version='wrong';", "h.server.buildId='wrong';",
                       "h.server.bootId='wrong';", "delete h.server.bootId;", "h.features.methods=['health'];"]:
            with self.subTest(vendor=vendor):
                self.refused(vendor=vendor)

    def test_explicit_build_absence_is_exact(self):
        absent=lambda p:p['server'].update(buildId=None)
        for mode in ('probe','call'):
            code,result=self.run_bridge(mode=mode,change=absent,vendor="delete h.server.buildId;")
            self.assertEqual(code,0)
            self.assertIsNone(result['hello']['buildId'])
            for vendor in ("", "h.server.buildId=null;", "h.server.buildId='';"):
                with self.subTest(mode=mode,vendor=vendor):
                    self.refused(mode=mode,change=absent,vendor=vendor)
        for vendor in ("delete h.server.buildId;", "h.server.buildId=null;", "h.server.buildId='';"):
            self.refused(vendor=vendor)

    def test_source_changed_after_import(self):
        self.refused(vendor="fs.appendFileSync(new URL(import.meta.url),'\\n// drift');")

    def test_unpinned_sdk(self):
        self.refused(change=lambda p:p['sources'][0].update(sha256='0'*64))

    def test_no_dispatch_callback(self):
        self.refused(vendor="return {fake:true};")

    def test_unknown_fields_and_methods(self):
        for change in [lambda p:p.update(token='secret'), lambda p:p.update(method='exec'),
                       lambda p:p['params'].update(command='exec'),
                       lambda p:p.update(endpoint='ws://example.com:80'),
                       lambda p:p['server'].update(bootId=None)]:
            self.refused(change=change)

if __name__ == '__main__':
    unittest.main()
