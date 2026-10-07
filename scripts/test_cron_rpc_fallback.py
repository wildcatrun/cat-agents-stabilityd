import importlib.util,json,sys,tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('cron_rpc_fallback_test',Path(__file__).resolve().parents[1]/'bin/cat_agents_stabilityd.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as tmp:
    root=Path(tmp);(root/'package.json').write_text('{"name":"openclaw"}');(root/'openclaw.mjs').write_text('')
    inventory={'jobs':[{'id':'fixture','enabled':True,'status':'running','state':{'runningAtMs':123}}]}
    good={'schemaVersion':1,'ok':True,'status':{'enabled':True,'jobs':1},'inventory':inventory}
    calls=[]
    def run(args,timeout):
        calls.append(args)
        return SimpleNamespace(returncode=0,stdout=json.dumps(good),stderr='')
    with patch.object(m.shutil,'which',lambda name:str(root/'openclaw.mjs') if name=='openclaw' else '/usr/bin/node'),patch.object(m,'run_cmd',run):
        m._inspection_cache_enabled=True;m.CRON_READONLY_RPC_ENABLED=True
        m._inspection_gateway_context=(1,True)
        m.prepare_cron_readonly_rpc()
        assert m.collect_cron_storage_status()['inspectionTransport']=='gateway-sdk-read-only'
        status=m.collect_cron_cli_status();assert status['byJob']['fixture']['status']=='running'
        assert status['inspectionTransport']=='gateway-sdk-read-only' and len(calls)==1
        m.prepare_cron_readonly_rpc();assert len(calls)==2, 'every daemon cycle must read fresh'
        m._inspection_gateway_context=(1,False)
        m.prepare_cron_readonly_rpc();assert m._cron_rpc_cycle is None and len(calls)==2
        m._inspection_gateway_context=(1,True)
        m._inspection_cache_enabled=False
        m.prepare_cron_readonly_rpc();assert m._cron_rpc_cycle is None and len(calls)==2
        m._inspection_cache_enabled=True
        with patch.object(m,'run_cmd',lambda args,timeout:SimpleNamespace(returncode=1,stdout='{}',stderr='sensitive error must not be stored')):
            m.prepare_cron_readonly_rpc();assert m._cron_rpc_cycle is None
        with patch.object(m,'_collect_cron_storage_status_cli',lambda:{'available':True}):
            assert m.collect_cron_storage_status()['inspectionTransport']=='cli-fallback'
        m.prepare_cron_readonly_rpc();assert len(calls)==2, 'failed SDK probe must back off while CLI remains fresh'
        assert m._cron_rpc_cycle is None
        m._cron_rpc_retry_after=0
        m._cron_rpc_cycle={'status':{},'observedMonotonic':m.time.monotonic()-15}
        assert m.cron_readonly_rpc_payload('status') is None, 'stale cycle cannot masquerade as current'
        m.CRON_READONLY_RPC_ENABLED=False
        m.prepare_cron_readonly_rpc();assert m._cron_rpc_cycle is None
print(json.dumps({'passed':True,'checks':['one process supplies both fresh observations','each cycle refreshes','one-shot remains CLI','RPC failure falls back','failure backoff avoids extra spawn storm','stale cycle rejected','explicit disable rollback']}))
