"""Pure launcher gates and injected failure cleanup; no actual open/App/signals."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
from window_bridge import window_app_launch_v3 as d


def require(value, why):
    if not value: raise ValueError(why)


def cases():
    checks=[]
    def good(name, action): action(); checks.append({'name':name,'result':'PASS'})
    def reject(name, action):
        try: action()
        except (ValueError, TypeError, KeyError): checks.append({'name':name,'result':'REJECTED'}); return
        raise ValueError('accepted invalid '+name)
    app=Path('/private/tmp/pe-aot-noarg-ls-v3-synthetic/relocation with spaces/PE AOT Integer Tile V3.app')
    exe=d.package.executable(app);run=Path('/private/tmp/synthetic-support')/d.APP_ID/'Runs/12345678-1234-1234-1234-123456789ABC'
    identity={'pid':424242,'uid':os.geteuid(),'ppid':1,'path':str(exe),'start_seconds':100,'start_microseconds':3}
    entry={'schema':1,'status':'ENTRY_STARTED_NOT_ACCEPTED','pid':424242,'uid':os.geteuid(),'run_id':run.name,
        'bundle_identifier':d.APP_ID,'bundle_path':str(app),'argument_count':1,'run_directory':str(run),
        'data_directory':'/private/tmp/synthetic-support/'+d.APP_ID+'/Data','instance_lock_held':True,
        'test_queue_requested':False,'host_arguments':['--data-dir','/private/tmp/synthetic-support/'+d.APP_ID+'/Data','--budget',str(d.BUDGET)]}
    good('identity_exact',lambda:d.identity_ok(identity,exe,100))
    for key,value in [('pid',True),('uid',os.geteuid()+1),('path','/different'),('start_seconds',99),('start_microseconds',1000000)]:
        wrong={**identity,key:value};reject('identity_'+key,lambda wrong=wrong:d.identity_ok(wrong,exe,100))
    good('entry_exact',lambda:d.authenticate_entry(entry,run,app,'/private/tmp/synthetic-support',identity,[]))
    for key,value in [('argument_count',2),('pid',424243),('bundle_path','/different'),('run_id','different'),('test_queue_requested',True),('host_arguments',[])]:
        wrong={**entry,key:value};reject('entry_'+key,lambda wrong=wrong:d.authenticate_entry(wrong,run,app,'/private/tmp/synthetic-support',identity,[]))
    reject('previous_uuid',lambda:d.authenticate_entry(entry,run,app,'/private/tmp/synthetic-support',identity,[run.name]))
    good('marker_complete',lambda:require(d.marker('dyld[1]: ignored\nPE_AOT_NOARG_RUN '+str(run)+'\n')==run,'marker'))
    good('marker_incomplete_waits',lambda:require(d.marker('PE_AOT_NOARG_RUN '+str(run)) is None,'partial'))
    reject('duplicate_marker',lambda:d.marker('PE_AOT_NOARG_RUN '+str(run)+'\nPE_AOT_NOARG_RUN '+str(run)+'\n'))
    # Inject exactly the post-Popen persistence failure found by independent
    # review. Popen and os.kill are replaced; no process or signal is created.
    for mode in ('late_identity','permission_error','no_identity'):
        out=Path(tempfile.mkdtemp(prefix='pe-aot-ls-mock-',dir='/private/tmp'))
        for name in ('started.json','app.stdout','app.stderr','open.stdout','open.stderr'):
            (out/name).write_text('{}\n' if name in ('started.json','app.stdout') else '')
        (out/'helper-build.json').write_text('{}')
        fake_id={**identity,'start_seconds':9999999999}
        start={'helper':str(out/'helper'),'app':str(app),'executable':str(exe),'command':['fake-open'],
               'environment':{},'support_directory':'/private/tmp/synthetic-support'}
        class Child:
            pid=424241;returncode=None
            def poll(self): return self.returncode
            def terminate(self): self.returncode=-15
            def kill(self): self.returncode=-9
            def wait(self,timeout=None): return self.returncode
        child=Child();signals=[];real_write=d.write
        def broken_write(path,value):
            if Path(path).name=='open-started.json':raise OSError('injected persistence failure')
            return real_write(path,value)
        def fake_query(helper,args,log=None):
            if args[0]=='find':return {'matches':[] if mode=='no_identity' else [fake_id]}
            if signals and mode=='late_identity':raise ValueError('already exited')
            return fake_id
        def fake_kill(pid,sig):
            signals.append((pid,int(sig)))
            if mode=='permission_error':raise PermissionError('injected denied signal')
        with patch.object(d,'output',lambda path:Path(path)),patch.object(d,'prepare',lambda *args:(start,{},None,{'nodes':{}})),\
             patch.object(d.subprocess,'Popen',lambda *args,**kw:child),patch.object(d,'write',broken_write),\
             patch.object(d,'query',fake_query),patch.object(d.os,'kill',fake_kill),patch.object(d.time,'sleep',lambda *args:None),\
             patch.object(d,'snapshot_data',lambda *args:{}),patch.object(d.package,'tree',lambda *args:{}),\
             patch.object(d,'input_identity',lambda *args:{}),patch.object(d.binding.graphics,'loaded_images',lambda *args:[]):
            try:d.run(out)
            except ValueError:pass
            else:raise ValueError('injected failure was accepted')
        rec=json.loads((out/'observed.json').read_text())
        require(child.returncode==-15 and rec['status']=='FAILED_OBSERVATION_PRESERVED','owned open child was orphaned')
        require(all(pid==424242 for pid,_ in signals),'signaled another PID')
        actions=[a['action'] for a in rec['cleanup_actions']]
        require(('unresolved_residual' in actions) if mode=='no_identity' else ('late_exact_identity_found_for_cleanup' in actions),'late discovery evidence')
        if mode=='permission_error':require('signal_failed' in actions,'permission failure not retained')
        if mode=='no_identity':require(not signals,'unidentified process signaled')
        checks.append({'name':'post_popen_failure_'+mode,'result':'PASS_MOCK_ONLY'})
    return checks


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    rows=cases();sources=[Path(__file__),Path(d.__file__),Path(d.ROOT/'window_bridge/noarg_launch_probe_v1.mm')]
    result={'status':'PASS_PURE_LAUNCH_GATES_AND_MOCK_CLEANUP','cases':rows,'count':len(rows),
      'source_sha256':{str(x.resolve()):hashlib.sha256(x.read_bytes()).hexdigest() for x in sources},
      'scope':{'actual_App_launches':0,'actual_GUI':0,'actual_GPU':0,'actual_signals':0,'actual_event_posts':0}}
    a.out.parent.mkdir(parents=True,exist_ok=True);d.write(a.out,result);print(json.dumps(result,indent=2))
