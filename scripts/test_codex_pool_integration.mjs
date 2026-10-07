// Test the generated vendor guard and actual lifecycle module in this process only.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { pathToFileURL } from 'node:url';
const folder = process.argv[2];
assert(folder, 'pass the generated candidate .setup directory');
const source = fs.readFileSync(path.join(folder,'shared-client-DqyTMYug.mjs'),'utf8');
const start = source.indexOf('function installCodexPoolIdleGuard(');
const end = source.indexOf('function ensureCodexAppServerClientRuntime(',start);
assert(start > 0 && end > start);
const runtime = { closed:false };
for (const field of ['retainedThreads','claimedThreads','releasingThreads','protectedThreads','workspaceReferences']) runtime[field]=new Map();
const client = { pending:new Map(), serverRequests:{active:new Map()}, nativeExecutionObserved:false, decoder:{hasPending:false}, catalogWorker:{continuation:undefined} };
const entry = { client };
const ctx = { Map, configuredClients:new WeakMap([[client,runtime]]), getCurrentSharedClientEntry:c=>c===client ? entry:undefined };
vm.runInNewContext(source.slice(start,end)+'\ninstallCodexPoolIdleGuard(testClient);',{...ctx,testClient:client});
assert.equal(entry.poolIdleGuard().safe,true);
for (const field of ['retainedThreads','claimedThreads','releasingThreads','protectedThreads','workspaceReferences']) {
  runtime[field].set('fixture',{});
  assert.equal(entry.poolIdleGuard().safe,false,field+' must pin a client');
  runtime[field].clear();
}
client.pending.set(1,{}); assert.equal(entry.poolIdleGuard().safe,false); client.pending.clear();
client.serverRequests.active.set(1,{}); assert.equal(entry.poolIdleGuard().safe,false); client.serverRequests.active.clear();
client.nativeExecutionObserved=true; assert.equal(entry.poolIdleGuard().safe,false); client.nativeExecutionObserved=false;
client.decoder.hasPending=true; assert.equal(entry.poolIdleGuard().safe,false); client.decoder.hasPending=false;
client.catalogWorker.continuation={}; assert.equal(entry.poolIdleGuard().safe,false); client.catalogWorker.continuation=undefined;
runtime.retainedThreads=undefined; assert.equal(entry.poolIdleGuard().safe,false); runtime.retainedThreads=new Map();
assert.equal(entry.poolIdleGuard().safe,true);

const lifecycle = await import(pathToFileURL(path.join(folder,'shared-client-lifecycle-DJIgqgMw.mjs')));
const leaf = await import(pathToFileURL(path.join(folder,'resource-idle-pool-local.mjs')));
const state=lifecycle.r();
function own(pid,leased=false) {
  let closed=0;
  const c={child:{pid},closed:false,close(){closed++;this.closed=true;},getCloseError(){return undefined;}};
  const e={key:Symbol(),client:c,activeLeases:0,pendingAcquires:0,poolIdleGuard:()=>({safe:true})};
  state.clients.set(e.key,e);state.entriesByClient.set(c,e);state.liveClients.add(c);
  const release=lifecycle.c(e);
  if(!leased)release();
  return {c,e,release,closed:()=>closed};
}
const idle=own(101), busy=own(102,true);
const now=idle.e.poolLastUseAt+400000;
const result=leaf.sweepIdlePool(state,lifecycle.d,{ttlMs:300000,graceMs:60000,maxIdle:8},now);
assert.deepEqual(result.retiredPids,[101]);assert.equal(idle.closed(),1);assert.equal(busy.closed(),0);
busy.release();
leaf.sweepIdlePool(state,lifecycle.d,{ttlMs:300000,graceMs:60000,maxIdle:8},busy.e.poolLastUseAt+400000);
assert.equal(busy.closed(),1);
assert.equal(state.clients.size,0);
assert(state.poolSweepTimer?.hasRef()===false,'maintenance timer must not keep process alive');
clearInterval(state.poolSweepTimer);
console.log(JSON.stringify({passed:true,scope:'generated vendor guard and actual patched lifecycle, fake clients, no live Gateway',checks:['each runtime ownership map protected','pending outbound/inbound RPC protected','native continuity protected','decode/catalog work protected','unknown schema fail closed','existing retirement closes idle','active lease protected','released idle reclaimed','unreferenced timer']}));
