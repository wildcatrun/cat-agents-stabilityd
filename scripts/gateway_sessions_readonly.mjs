// Fixed official SDK read only. No session content, mutation or action authority.
import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';

export function projectSessionInventory(value,agentIds) {
 if (!Array.isArray(agentIds)||agentIds.length>512||agentIds.some(x=>typeof x!=='string'||!/^[A-Za-z0-9_-]{1,64}$/.test(x))) throw Error('invalid-scope');
 if (!value||!Array.isArray(value.sessions)||value.sessions.length>1024||!Number.isSafeInteger(value.totalCount)||value.totalCount<0||typeof value.hasMore!=='boolean') throw Error('unknown-session-schema');
 const allowed=new Set(agentIds),sessions=[];
 for(const row of value.sessions) {
   if (!row||typeof row.agentId!=='string'||typeof row.key!=='string') throw Error('unknown-session-identity');
   if (!allowed.has(row.agentId)) continue;
   if(!row.key.startsWith(`agent:${row.agentId}:`)||row.key.length>512) throw Error('session-identity-mismatch');
   sessions.push({agentId:row.agentId,sessionKey:row.key,
     updatedAt:Number.isSafeInteger(row.updatedAt)?row.updatedAt:null,
     hasActiveRun:typeof row.hasActiveRun==='boolean'?row.hasActiveRun:null,
     abortedLastRun:typeof row.abortedLastRun==='boolean'?row.abortedLastRun:null});
 }
 const observed=[...new Set(sessions.map(x=>x.agentId))].sort();
 const missing=agentIds.filter(x=>!observed.includes(x));
 const complete=value.hasMore===false&&value.nextOffset===null&&value.totalCount===value.sessions.length;
 return {schemaVersion:1,available:true,source:'gateway-sdk-read-only',inventoryComplete:complete,
   scopeComplete:complete&&agentIds.length>0&&missing.length===0,expectedAgentIds:agentIds,
   observedAgentIds:observed,missingAgentIds:missing,sessions,
   activityCoverage:'active-run metadata only; no transcript or idle/reset eligibility',
   authorityGranted:false,resetEligibility:'requires existing fresh qualified describe/activity/protection gates'};
}

async function main() {
 const [root,raw]=process.argv.slice(2),ids=JSON.parse(raw);
 if((await fs.readFile(path.join(root,'package.json'),'utf8').then(JSON.parse)).name!=='openclaw')throw Error('unexpected-sdk-package');
 const sdk=await import(pathToFileURL(path.join(root,'dist/plugin-sdk/gateway-runtime.js')));
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),6000);timer.unref();
 try {
   const data=await sdk.callGatewayFromCli('sessions.list',{json:true,timeout:'4000'},
     {includeGlobal:false,includeUnknown:false,limit:1024},
     {scopes:['operator.read'],sharedStateMode:'read-only',progress:false,signal:controller.signal});
   console.log(JSON.stringify(projectSessionInventory(data,ids)));
 } finally {clearTimeout(timer);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href) {
 try {await main();} catch {console.log(JSON.stringify({schemaVersion:1,available:false,scopeComplete:false,errorClass:'SessionInventoryUnavailable',authorityGranted:false}));process.exitCode=1;}
}
