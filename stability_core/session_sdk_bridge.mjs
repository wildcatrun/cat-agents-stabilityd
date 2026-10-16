/** One-shot bridge to the qualified official SDK. No credentials in its wire format. */
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const fail = () => { throw new Error('refused'); };
const record = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const exact = (x, keys) => record(x) && Object.keys(x).sort().join('|') === [...keys].sort().join('|');
const bounded = x => typeof x === 'string' && x.length > 0 && x.length <= 512 && !/[\x00-\x1f\x7f]/.test(x);
function owned(p, directory = false) {
  const s = fs.lstatSync(p);
  if (s.isSymbolicLink() || (directory ? !s.isDirectory() : !s.isFile()) ||
      ![0, process.getuid()].includes(s.uid) || (s.mode & 0o022)) fail();
  return s;
}
function sourceWindow(sources) {
  for (const item of sources) {
    let parent = path.dirname(item.path);
    while (true) {
      owned(parent, true);
      if (parent === path.dirname(parent)) break;
      parent = path.dirname(parent);
    }
    const before = owned(item.path);
    if (before.size > 8 * 1024 * 1024 || before.nlink !== 1) fail();
    const fd = fs.openSync(item.path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    try {
      const opened = fs.fstatSync(fd);
      const body = fs.readFileSync(fd);
      const after = fs.fstatSync(fd);
      const current = owned(item.path);
      for (const s of [opened, after, current]) {
        for (const key of ['dev','ino','uid','mode','size','mtimeMs','ctimeMs']) if (s[key] !== before[key]) fail();
      }
      if (createHash('sha256').update(body).digest('hex') !== item.sha256) fail();
    } finally { fs.closeSync(fd); }
  }
}
function validate(p) {
  if (!exact(p, ['schema','mode','sdkEntry','sources','endpoint','server','method','params']) || p.schema !== 1 ||
      !['probe','call'].includes(p.mode) || !bounded(p.sdkEntry) || !path.isAbsolute(p.sdkEntry) ||
      !/^ws:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})$/.test(p.endpoint) || Number(p.endpoint.split(':').at(-1)) > 65535 ||
      !exact(p.server,['version','buildId','bootId']) || !bounded(p.server.version) || p.server.version.length > 256 || (p.server.buildId !== null && (!bounded(p.server.buildId) || p.server.buildId.length > 256)) ||
      !Array.isArray(p.sources) || p.sources.length < 1 || p.sources.length > 64) fail();
  const seen = new Set();
  for (const s of p.sources) {
    if (!exact(s,['path','sha256']) || !bounded(s.path) || !path.isAbsolute(s.path) || path.normalize(s.path) !== s.path ||
        !/^[a-f0-9]{64}$/.test(s.sha256) || seen.has(s.path)) fail();
    seen.add(s.path);
  }
  if (!seen.has(p.sdkEntry)) fail();
  if (p.mode === 'probe') {
    if (p.server.bootId !== null || p.method !== 'health' || !exact(p.params,[])) fail();
  } else {
    if (!bounded(p.server.bootId) || p.server.bootId.length > 256 || !['sessions.describe','sessions.reset'].includes(p.method) ||
        !exact(p.params, p.method === 'sessions.reset' ? ['key','agentId','expectedSessionId'] : ['key','agentId']) ||
        !Object.values(p.params).every(bounded)) fail();
  }
}
async function main() {
  if (process.argv.length !== 3 || Buffer.byteLength(process.argv[2]) > 65536) fail();
  const p = JSON.parse(process.argv[2]);
  validate(p);
  sourceWindow(p.sources);
  // Only this finite, independently qualified window is attested, not all SDK dependencies.
  const sdk = await import(pathToFileURL(p.sdkEntry).href);
  sourceWindow(p.sources);
  if (typeof sdk.r !== 'function') fail();
  let hello;
  let dispatched = false;
  const result = await sdk.r({
    expectUrl:p.endpoint, method:p.method, params:p.params,
    scopes:[p.method === 'sessions.reset' ? 'operator.admin' : 'operator.read'],
    clientName:'cli', mode:'cli', minProtocol:4, maxProtocol:4,
    sharedStateMode:'read-only', timeoutMs:10000, requiredMethods:[p.method],
    onHelloOk(value) {
      // The SDK swallows this callback's exceptions; rejection belongs to dispatch fence.
      hello = undefined;
      if (!record(value) || value.protocol !== 4 || !record(value.server) ||
          value.server.version !== p.server.version ||
          (p.server.buildId === null ? Object.hasOwn(value.server,'buildId') :
            (!Object.hasOwn(value.server,'buildId') || value.server.buildId !== p.server.buildId)) ||
          !bounded(value.server.bootId) || value.server.bootId.length > 256 || !record(value.features) ||
          !Array.isArray(value.features.methods) || value.features.methods.length > 4096 ||
          !value.features.methods.every(bounded)) return;
      hello = {protocol:4,version:value.server.version,buildId:p.server.buildId,
        bootId:value.server.bootId,methods:['sessions.describe','sessions.reset'].filter(m => value.features.methods.includes(m))};
    },
    assertDispatchCurrent() {
      if (!hello || dispatched || (p.mode === 'call' && (hello.bootId !== p.server.bootId || !hello.methods.includes(p.method)))) fail();
      sourceWindow(p.sources);
      dispatched = true;
    }
  });
  if (!dispatched || !hello || (p.mode === 'call' && !record(result))) fail();
  const output = JSON.stringify({ok:true,hello,result:p.mode === 'probe' ? null : result});
  if (Buffer.byteLength(output) > 65536) fail();
  return output;
}
// Suppress vendor diagnostics; only the bounded bridge envelope reaches the caller.
const publish = process.stdout.write.bind(process.stdout);
process.stdout.write = () => true;
process.stderr.write = () => true;
main().then(output => {
  publish(output + '\n', () => process.exit(0));
}).catch(() => {
  publish('{"ok":false,"errorClass":"SessionSdkBridgeRefused"}\n', () => process.exit(75));
});
