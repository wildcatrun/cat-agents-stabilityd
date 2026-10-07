// Foreground, bounded read-only adapter to the installed OpenClaw SDK.
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export function enrichCronStatus(job) {
  const state = job.state && typeof job.state === 'object' && !Array.isArray(job.state) ? job.state : {};
  const status = state.runningAtMs ? 'running' : !job.enabled ? 'disabled' : typeof state.lastRunStatus === 'string' ? state.lastRunStatus : typeof state.lastStatus === 'string' ? state.lastStatus : 'idle';
  return {...job,status};
}

export async function readCompleteCronInventory(call) {
  const pageSize = 200;
  for (let restart=0; restart<3; restart++) {
    let offset=0, revision, total, first;
    const jobs=[];
    for (let pageNumber=0; pageNumber<50; pageNumber++) {
      const page=await call('cron.list',{includeDisabled:false,limit:pageSize,offset});
      if (!page || !Array.isArray(page.jobs) || typeof page.snapshotRevision!=='string' || !page.snapshotRevision || !Number.isSafeInteger(page.total) || page.total<0 || page.offset!==offset || !Number.isSafeInteger(page.limit) || page.limit<1 || page.limit>pageSize || page.jobs.length>page.limit || typeof page.hasMore!=='boolean') throw Error('invalid-inventory-page');
      if (page.jobs.some(j=>!j || typeof j.id!=='string' || !j.id || typeof j.enabled!=='boolean')) throw Error('invalid-job-record');
      if (revision!==undefined && (page.snapshotRevision!==revision || page.total!==total)) break;
      first??=page;revision??=page.snapshotRevision;total??=page.total;
      jobs.push(...page.jobs);
      if (!page.hasMore) {
        if (page.nextOffset!==null || jobs.length!==total || new Set(jobs.map(j=>j.id)).size!==jobs.length) throw Error('incomplete-inventory');
        return {...first,jobs:jobs.map(enrichCronStatus),total,hasMore:false,nextOffset:null};
      }
      if (!Number.isSafeInteger(page.nextOffset) || page.nextOffset!==offset+page.jobs.length || page.nextOffset<=offset) throw Error('nonadvancing-inventory-page');
      offset=page.nextOffset;
    }
  }
  throw Error('unstable-or-excessive-inventory');
}

async function main() {
  const root=process.argv[2];
  if (!root) throw Error('missing-installed-sdk-root');
  const packageInfo=JSON.parse(await fs.readFile(path.join(root,'package.json'),'utf8'));
  if (packageInfo.name!=='openclaw') throw Error('unexpected-sdk-package');
  const sdk=await import(pathToFileURL(path.join(root,'dist/plugin-sdk/gateway-runtime.js')));
  if (typeof sdk.callGatewayFromCli!=='function') throw Error('unsupported-sdk');
  const controller=new AbortController();
  const deadline=setTimeout(()=>controller.abort(),8000);deadline.unref();
  try {
    // No caller-controlled method, URL, auth header, or writable operation.
    const call=(method,params)=> {
      if (!['cron.status','cron.list'].includes(method)) throw Error('read-only-method-required');
      return sdk.callGatewayFromCli(method,{json:true,timeout:'4000'},params,{scopes:['operator.read'],sharedStateMode:'read-only',progress:false,signal:controller.signal});
    };
    const status=await call('cron.status',{});
    if (!status || typeof status.enabled!=='boolean' || !Number.isSafeInteger(status.jobs) || status.jobs<0) throw Error('invalid-cron-status');
    const inventory=await readCompleteCronInventory(call);
    // stdout is an internal pipe to the existing daemon, never an ops log.
    console.log(JSON.stringify({schemaVersion:1,ok:true,status,inventory,transport:'gateway-sdk-read-only'}));
  } finally { clearTimeout(deadline); }
}

if (process.argv[1] && import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href) {
  try { await main(); }
  catch {
    // Do not serialize transport/config/auth errors or private job payloads.
    console.log(JSON.stringify({schemaVersion:1,ok:false,error:'gateway-read-only-probe-failed'}));
    process.exitCode=1;
  }
}
