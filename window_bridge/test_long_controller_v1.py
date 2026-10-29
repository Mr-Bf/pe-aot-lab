#!/usr/bin/env python3
"""Actual C scheduler tests using synthetic timestamps, no native window/guest."""
from __future__ import annotations
import argparse,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as g
HERE=Path(__file__).resolve().parent
OUT=ROOT/'build/window-bridge/long-controller-tests-v1-03'
MODES={'O0':['-O0'],'O3':['-O3'],'ASan_UBSan':['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all']}
def require(x,m):
    if not x:raise ValueError(m)
def write(p,x):
    with p.open('x') as f:json.dump(x,f,indent=2,sort_keys=True);f.write('\n')
def commands(out):
    clang=g.invoke(['/usr/bin/xcrun','--find','clang'],g.environment(out)).strip();sdk=g.invoke(['/usr/bin/xcrun','--show-sdk-path'],g.environment(out)).strip()
    base=[clang,'-arch','arm64','-isysroot',sdk,'-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-function','-I',str(ROOT)]
    result=[]
    for name,flags in MODES.items():
        result.append((name+'-deps',[*base,*flags,'-M','-MT','probe',str(HERE/'test_long_controller_v1.c')]))
        result.append((name+'-compile',[*base,*flags,str(HERE/'test_long_controller_v1.c'),'-o',str(out/name)]))
        result.append((name+'-run',[str(out/name)]))
    return [x for x in result if x[0].endswith('-deps')]+[x for x in result if not x[0].endswith('-deps')],clang,sdk

def run(out):
    require(not out.exists(),'use fresh output directory');out.mkdir(parents=True)
    try:
        plans,clang,sdk=commands(out);deps=[];records=[];results={};source_hash=g.hashes([__file__,HERE/'test_long_controller_v1.c',HERE/'long_controller_v1.h']);inputs=None
        ld=g.invoke(['/usr/bin/xcrun','--find','ld'],g.environment(out)).strip()
        asan=g.invoke([clang,'-print-file-name=libclang_rt.asan_osx_dynamic.dylib'],g.environment(out)).strip()
        require(Path(asan).is_file(),'actual sanitizer runtime not located')
        for name,args in plans:
            if inputs is None and not name.endswith('-deps'):inputs=g.hashes([*source_hash,*deps,clang,ld,asan,'/usr/bin/xcrun',sys.executable])
            env=g.environment(out);env.update(ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
            p=subprocess.run(args,capture_output=True,text=True,env=env,timeout=60)
            path=out/(name+'.json');write(path,{'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});records.append(path)
            require(p.returncode==0,'command failed '+str(path))
            if name.endswith('-deps'):deps+=g.dependency_paths(p.stdout)
            if name.endswith('-run'):
                require(p.stderr=='','unexpected test stderr');r=g.strict_json(p.stdout);require(r['status']=='PASS_SYNTHETIC_CONTROLLER_ONLY','test status differs');results[name[:-4]]=r
        require(len({json.dumps(r,sort_keys=True) for r in results.values()})==1,'optimization/sanitizer outputs differ')
        # Bind actual linker and loaded sanitizer dylib named by the compiler.
        ld=g.invoke(['/usr/bin/xcrun','--find','ld'],g.environment(out)).strip()
        asan=g.invoke([clang,'-print-file-name=libclang_rt.asan_osx_dynamic.dylib'],g.environment(out)).strip()
        require(Path(asan).is_file(),'actual sanitizer runtime not located')
        g.same(inputs);g.same(source_hash)
        record={'status':'PASS_SYNTHETIC_CONTROLLER_ONLY','results':results,'inputs_before':inputs,'inputs_after':g.hashes(inputs),
            'commands':[{ 'path':str(p),'sha256':g.sha(p)} for p in records],
            'artifacts':g.hashes([*records,*[out/n for n in MODES]]),'clang':clang,'sdk':sdk,'asan_runtime':asan,
            'scope':{'actual_c_processes':3,'synthetic_scenarios_per_mode':next(iter(results.values()))['scenarios'],'guest_executions':0,'windows':0,'gpu_executions':0,'elapsed_duration_claim':False}}
        write(out/'evidence.json',record);return verify(out)
    except Exception as e:write(out/'first-failure.json',{'status':'FAIL','error':repr(e)});raise

def verify(out=OUT):
    r=g.read_json(out/'evidence.json');require(r['status']=='PASS_SYNTHETIC_CONTROLLER_ONLY','status differs')
    g.same(r['inputs_before']);g.same(r['artifacts']);require(r['inputs_before']==r['inputs_after'],'inputs changed')
    plans,clang,sdk=commands(out);require(r['clang']==clang and r['sdk']==sdk,'tools differ')
    records=[];deps=[];results={}
    for name,args in plans:
        path=out/(name+'.json');d=g.read_json(path);require(d['command']==args and type(d['returncode']) is int and d['returncode']==0,'command differs');records.append(path)
        if name.endswith('-deps'):
            current=g.invoke(args,g.environment(out));require(current==d['stdout'],'dependencies changed');deps+=g.dependency_paths(current)
        if name.endswith('-run'):
            require(d['stderr']=='','run stderr');results[name[:-4]]=g.strict_json(d['stdout'])
    ld=g.invoke(['/usr/bin/xcrun','--find','ld'],g.environment(out)).strip();asan=g.invoke([clang,'-print-file-name=libclang_rt.asan_osx_dynamic.dylib'],g.environment(out)).strip()
    require(r['inputs_before']==g.hashes([__file__,HERE/'test_long_controller_v1.c',HERE/'long_controller_v1.h',*deps,clang,ld,asan,'/usr/bin/xcrun',sys.executable]),'input closure differs')
    require(r['artifacts']==g.hashes([*records,*[out/n for n in MODES]]) and r['commands']==[{'path':str(p),'sha256':g.sha(p)} for p in records],'artifact/command closure differs')
    require(r['results']==results and len({json.dumps(d,sort_keys=True) for d in results.values()})==1,'test results differ')
    return r
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=OUT);p.add_argument('--run',action='store_true');a=p.parse_args();out=a.out.resolve();r=run(out) if a.run else verify(out)
    print(json.dumps({'status':r['status'],'scope':r['scope'],'results':r['results']}))
