#!/usr/bin/env python3
"""Independent native queue and hidden-Cocoa tests. No guest or D3D calls."""
from pathlib import Path
import argparse,json,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as base
OUT=ROOT/'build/window-bridge/cocoa-host/final'
SOURCES=[Path(__file__),ROOT/'window_bridge/cocoa_host.mm',ROOT/'window_bridge/cocoa_host.h',
         ROOT/'window_bridge/message_queue.h',ROOT/'window_bridge/test_host_queue.cpp',ROOT/'window_bridge/test_cocoa_host.mm']
def require(v,m):
    if not v:raise RuntimeError(m)
def save(path,d):path.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
def build():
    require(not OUT.exists(),'preserve prior build');OUT.mkdir(parents=True)
    t=base.tools(OUT)
    options=[t['clang++'],'-arch','arm64','-isysroot',t['sdk'],'-std=c++20','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations']
    inputs=[*SOURCES,Path(base.__file__),*[Path(v) for k,v in t.items() if k!='sdk']];depfiles=[]
    for source in (SOURCES[1],SOURCES[4],SOURCES[5]):
        args=[*options,'-M','-MT','probe',str(source)];p=subprocess.run(args,capture_output=True,text=True)
        path=OUT/(source.name+'.dependencies.json');save(path,{'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});depfiles.append(path)
        require(p.returncode==0,'dependency discovery failed');inputs+=base.dependency_paths(p.stdout)
    before=base.hashes(inputs);commands=[]
    for mode,sources,extra in [('queue',[SOURCES[4]],[]),('cocoa',[SOURCES[5],SOURCES[1]],['-framework','Cocoa','-framework','Metal','-framework','QuartzCore'])]:
        args=[*options,*map(str,sources),*extra,'--ld-path='+t['ld'],'-o',str(OUT/mode)]
        p=subprocess.run(args,capture_output=True,text=True);path=OUT/(mode+'-build.json')
        save(path,{'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});commands.append(path)
        require(p.returncode==0,'build failed: '+mode)
    after=base.hashes(inputs);require(before==after,'inputs changed during build')
    r={'status':'BUILT_NOT_EXECUTED','tools':t,'inputs_before':before,'inputs_after':after,
       'artifacts':base.hashes([OUT/'queue',OUT/'cocoa',*commands,*depfiles])};save(OUT/'build.json',r);return {'status':r['status'],'inputs':len(before)}
def run(mode):
    r=base.read_json(OUT/'build.json');base.same(r['inputs_after']);base.same(r['artifacts'])
    require(not (OUT/(mode+'.json')).exists(),'execution already recorded')
    before=base.hashes([OUT/'build.json',*map(Path,r['inputs_after']),*map(Path,r['artifacts'])])
    args=[str(OUT/mode)];env=base.environment(OUT)
    with (OUT/(mode+'.stdout')).open('w') as so,(OUT/(mode+'.stderr')).open('w') as se:
        child=subprocess.Popen(args,env=env,stdout=so,stderr=se);timed_out=False
        try:exit_code=child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            timed_out=True;child.terminate()
            try:exit_code=child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();exit_code=child.wait(timeout=3)
    text=(OUT/(mode+'.stdout')).read_text();result=base.strict_json(text) if text.strip() else None
    after=base.hashes(list(map(Path,before)))
    record={'status':'PASS' if exit_code==0 and not timed_out and result and result.get('status')=='PASS' and before==after else 'FAIL',
            'command':args,'environment':env,'pid':child.pid,'child_exit_code':exit_code,'timed_out':timed_out,'result':result,
            'inputs_before':before,'inputs_after':after,'artifacts':base.hashes([OUT/(mode+'.stdout'),OUT/(mode+'.stderr')])}
    save(OUT/(mode+'.json'),record);require(record['status']=='PASS','actual host test failed');return record['result']
def verify():
    r=base.read_json(OUT/'build.json');require(r['status']=='BUILT_NOT_EXECUTED' and r['tools']==base.tools(OUT),'build status/tools differ')
    t=r['tools'];options=[t['clang++'],'-arch','arm64','-isysroot',t['sdk'],'-std=c++20','-O2','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations']
    files=[*SOURCES,Path(base.__file__),*[Path(v) for k,v in t.items() if k!='sdk']]
    for source in (SOURCES[1],SOURCES[4],SOURCES[5]):
        p=subprocess.run([*options,'-M','-MT','probe',str(source)],capture_output=True,text=True)
        require(p.returncode==0,'current header discovery failed');files+=base.dependency_paths(p.stdout)
    require(r['inputs_before']==r['inputs_after']==base.hashes(files),'exact build input set differs')
    artifacts=[OUT/'queue',OUT/'cocoa',OUT/'queue-build.json',OUT/'cocoa-build.json',
               *[OUT/(s.name+'.dependencies.json') for s in (SOURCES[1],SOURCES[4],SOURCES[5])]]
    require(r['artifacts']==base.hashes(artifacts),'exact build artifact set differs')
    results={}
    for mode in ('queue','cocoa'):
        d=base.read_json(OUT/(mode+'.json'));base.same(d['inputs_after']);base.same(d['artifacts'])
        expected=base.hashes([OUT/'build.json',*map(Path,r['inputs_after']),*map(Path,r['artifacts'])])
        require(d['inputs_before']==d['inputs_after']==expected and d['status']=='PASS' and type(d['child_exit_code']) is int and d['child_exit_code']==0 and not d['timed_out'],'execution not passed')
        require(d['command']==[str(OUT/mode)] and d['environment']==base.environment(OUT) and d['artifacts']==base.hashes([OUT/(mode+'.stdout'),OUT/(mode+'.stderr')]),'execution command/environment/artifact set differs')
        raw=base.strict_json((OUT/(mode+'.stdout')).read_text());require(raw==d['result'] and raw['status']=='PASS' and raw['gpu_calls']==0 and raw['guest_executions']==0,'scope/result mismatch')
        require(type(raw['checks']) is int and raw['checks']=={'queue':42,'cocoa':26}[mode],'check count differs')
        results[mode]=raw
    return {'status':'HOST_QUEUE_AND_HIDDEN_COCOA_CURRENT','results':results,'additional_executions':0}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['build','queue','cocoa','verify']);a=p.parse_args()
    print(json.dumps(build() if a.mode=='build' else verify() if a.mode=='verify' else run(a.mode),indent=2))
