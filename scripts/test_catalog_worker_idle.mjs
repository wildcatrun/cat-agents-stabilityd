// Run against the server's installed native WorkerTaskPool. No Gateway state changes.
import assert from 'node:assert/strict';
import {mkdir,mkdtemp,writeFile,rm} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {setTimeout as sleep} from 'node:timers/promises';
import {channel} from 'node:diagnostics_channel';

const root=process.argv[2];
const artifact=process.argv[3];
assert(root && artifact);
const {t:WorkerTaskPool}=await import(pathToFileURL(path.join(root,'dist/worker-task-pool-CqZMVo9-.mjs')));
await mkdir(artifact,{recursive:true});
const directory=await mkdtemp(path.join(artifact,'catalog-worker-fixture-'));
const fixture=path.join(directory,'worker.mjs');
await writeFile(fixture,`import {t as serveWorkerTasks} from ${JSON.stringify(pathToFileURL(path.join(root,'dist/worker-task-server-Dj9rLvzH.mjs')).href)};\nserveWorkerTasks(async x=>{await new Promise(r=>setTimeout(r,x.delay));return x.value;});\n`);
let released=0;
const pool=new WorkerTaskPool({workerUrl:pathToFileURL(fixture),maxWorkers:1,idleTimeoutMs:80,prepareWorker:()=>({releaseResources:()=>{released++;}}),validateResult:()=>{}});
const until=async predicate=>{for(let i=0;i<200;i++){if(predicate())return;await sleep(20);}throw Error('fixture timeout');};
try {
  const first=pool.run({delay:250,value:17},{});
  await until(()=>pool.getSnapshot().activeTasks===1);
  await sleep(110);
  channel('openclaw.memory.critical').publish(undefined);
  assert.equal(pool.getSnapshot().activeTasks,1);
  assert.equal(await first,17);
  await until(()=>pool.getSnapshot().workers===0 && released===1);
  assert.equal(pool.isClosed,false);
  assert.equal(await pool.run({delay:1,value:23},{}),23);
  assert.equal(pool.getSnapshot().workersCreated,2);
  channel('openclaw.memory.critical').publish(undefined);
  await until(()=>pool.getSnapshot().workers===0 && released===2);
  assert.equal(pool.isClosed,false);
  console.log(JSON.stringify({activeTaskProtected:true,idleRetired:true,recreated:true,resourceCleanup:true,pressureRetirement:true}));
} finally {await pool.close();await rm(directory,{recursive:true,force:true});}
