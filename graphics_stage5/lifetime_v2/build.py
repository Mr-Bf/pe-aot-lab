#!/usr/bin/env python3
"""Build an isolated DXMT lifetime fix from the verified frozen headless source.

No original source/library is changed. Build success is not GPU acceptance.
"""
import argparse,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as base
from graphics_stage5 import bootstrap_dxmt as bootstrap
WORK=ROOT.parents[1]/'work/draw-lifetime-v2'
SOURCE=WORK/'dxmt-source-r2';BUILD=WORK/'dxmt-build-r2'
OUT=ROOT/'build/graphics-stage5/lifetime-v2-r2'
PATCH=HERE/'dxmt-lifetime-v2.patch'
STATUS='BUILT_DXMT_LIFETIME_V2_NOT_EXECUTED'

def require(value,message):
    if not value:raise RuntimeError(message)
def bound(path):return bootstrap.bound_tree(Path(path))
def config():return {'dxmt_source':str(SOURCE),'dxmt_build':str(BUILD)}
def frozen():
    c={'dxmt_source':str(base.WORK/('sources/dxmt-'+base.DXMT)),'dxmt_build':str(base.WORK/'dxmt-build')}
    _,records,_=base.provenance(c)
    return c,records
def run(args,path,env):
    args=list(map(str,args));require(not path.exists(),'refusing to overwrite command log')
    with path.open('x') as f:
        f.write(json.dumps(args)+'\n');f.flush()
        p=subprocess.run(args,stdout=f,stderr=subprocess.STDOUT,env=env)
    require(p.returncode==0,'backend command failed: '+str(path))
    return {'command':args,'log':str(path),'sha256':base.sha(path)}
def discover():
    _,records=frozen();receipt=base.read_json(bootstrap.OUT/'evidence.json')
    install=Path(receipt['dxmt_provenance']['inputs_after']['llvm_install']['root'])
    t=base.tools(OUT)
    for name in ('clang','ar','metal','metallib'):
        t[name]=str(Path(subprocess.check_output(['/usr/bin/xcrun','--find',name],text=True,env=base.environment(OUT)).strip()).resolve())
    for name in ('cc','c++','touch','xxd'):
        t['shim_'+name]=str(Path(shutil.which(name)).resolve())
    files=[Path(__file__),PATCH,Path(base.__file__),Path(bootstrap.__file__),*records,
           *[Path(v) for k,v in t.items() if k!='sdk'],bootstrap.NINJA,Path('/usr/bin/patch'),Path(sys.executable)]
    return {'files':base.hashes(files),'source':bound(SOURCE),
            'original_source':receipt['dxmt_provenance']['inputs_after']['source'],
            'llvm_install':bound(install),'meson':bound(base.WORK/'python')},t,install
def verify_source():
    c,_=frozen()
    with tempfile.TemporaryDirectory(prefix='verify-',dir=WORK) as temp:
        reference=Path(temp)/'source';shutil.copytree(c['dxmt_source'],reference,symlinks=True)
        p=subprocess.run(list(map(str,['/usr/bin/patch','-p1','--batch','--forward','-i',PATCH,'-d',reference])),capture_output=True,text=True)
        require(p.returncode==0,'exact lifetime transform failed: '+p.stderr)
        require(bound(reference)['tree_identity']==bound(SOURCE)['tree_identity'],'lifetime source differs from pinned baseline plus patch')
def verify():
    r=base.read_json(OUT/'evidence.json')
    require(r.get('schema')==1 and r.get('status')==STATUS and r.get('config')==config(),'lifetime backend not built or wrong configuration')
    verify_source();current,t,_=discover()
    require(r['inputs_before']==r['inputs_after']==current and r['tools']==t,'lifetime inputs changed')
    require(set(r['outputs'])=={str(p.resolve()) for p in BUILD.rglob('*.dylib') if p.is_file()},'output closure changed')
    base.same(r['outputs']);base.same(r['artifacts'])
    expected=[OUT/'prepared.json',OUT/'compilers.json',*[Path(c['log']) for c in r['commands']]]
    require(r['artifacts']==base.hashes(expected),'artifact closure omitted or changed')
    require([Path(c['log']).name for c in r['commands']]==['patch.log','configure.log','build.log'],'build command chain incomplete')
    for c in r['commands']:
        require(c['sha256']==base.sha(c['log']),'command log identity changed')
        require(json.loads(Path(c['log']).read_text().splitlines()[0])==c['command'],'recorded command differs from log')
    p=base.read_json(OUT/'prepared.json')
    require(p=={'original':current['original_source'],'source':current['source'],'patch':base.sha(PATCH)},'source preparation receipt changed')
    library=BUILD/'src/d3d11/d3d11.dylib'
    graph=base.library_graph(library,OUT/'future-probe',[library.parent])
    require(graph==r['library_graph'] and set(graph['nodes'])<=set(r['outputs']),'backend load graph changed')
    require(all(Path(p).is_relative_to(BUILD) for p in graph['nodes']),'mixed backend libraries')
    return r
def provenance(requested):
    require(requested==config(),'unknown lifetime backend configuration');r=verify()
    paths=[OUT/'evidence.json',Path(__file__),PATCH,*map(Path,r['inputs_after']['files']),*map(Path,r['artifacts'])]
    return BUILD/'src/d3d11/d3d11.dylib',paths,r['outputs']
def main(jobs=2):
    require(type(jobs) is int and 1<=jobs<=8,'invalid build parallelism')
    require(not SOURCE.exists() and not BUILD.exists() and not (OUT/'evidence.json').exists(),
            'version already attempted: preserve it; verify success or create a new version')
    OUT.mkdir(parents=True,exist_ok=True);WORK.mkdir(parents=True,exist_ok=True)
    r={'schema':1,'status':'PREPARING_NOT_EXECUTED','config':config(),'commands':[],
       'scope':'terminal device GPU wait, compiler scheduler destruction order and synchronized stop notification; no GPU/guest acceptance'}
    base.save(OUT/'evidence.json',r)
    try:
        c,_=frozen();original=bound(c['dxmt_source']);shutil.copytree(c['dxmt_source'],SOURCE,symlinks=True)
        env={**base.environment(OUT),'PYTHONPATH':str(base.WORK/'python'),'PYTHONDONTWRITEBYTECODE':'1',
             'PATH':str(bootstrap.NINJA.parent)+':'+os.environ.get('PATH','')}
        r['commands'].append(run(['/usr/bin/patch','-p1','--batch','--forward','-i',PATCH,'-d',SOURCE],OUT/'patch.log',env))
        require(original==bound(c['dxmt_source']),'frozen source changed')
        base.save(OUT/'prepared.json',{'original':original,'source':bound(SOURCE),'patch':base.sha(PATCH)})
        before,t,install=discover();r.update(inputs_before=before,tools=t)
        r['commands'].append(run([sys.executable,'-m','mesonbuild.mesonmain','setup',BUILD,SOURCE,'--buildtype=release',
            '-Dnative_llvm_path='+str(install),'-Denable_nvapi=false','-Denable_nvngx=false','-Denable_d3d12=false'],OUT/'configure.log',env))
        r['commands'].append(run([sys.executable,'-m','mesonbuild.mesonmain','compile','-C',BUILD,'-j',str(jobs)],OUT/'build.log',env))
        after,after_t,_=discover();require(before==after and t==after_t,'backend build inputs changed')
        info=base.read_json(BUILD/'meson-info/intro-compilers.json')
        require(all(info[realm]['c']['exelist']==['cc'] and info[realm]['cpp']['exelist']==['c++'] for realm in ('host','build')),'unexpected compiler')
        shutil.copy2(BUILD/'meson-info/intro-compilers.json',OUT/'compilers.json')
        outputs=base.hashes(p for p in BUILD.rglob('*.dylib') if p.is_file())
        library=BUILD/'src/d3d11/d3d11.dylib';graph=base.library_graph(library,OUT/'future-probe',[library.parent])
        require(set(graph['nodes'])<=set(outputs) and all(Path(p).is_relative_to(BUILD) for p in graph['nodes']),'foreign backend library')
        r.update(status=STATUS,inputs_after=after,outputs=outputs,library_graph=graph,
                 artifacts=base.hashes([OUT/'prepared.json',OUT/'compilers.json',*[Path(c['log']) for c in r['commands']]]),
                 validation_scope='clean separate build; all command stdout/stderr preserved; execution pending')
        base.save(OUT/'evidence.json',r);verify()
        print(json.dumps({'status':STATUS,'evidence':str(OUT/'evidence.json')}))
    except Exception as e:
        r.update(status='FAIL_NOT_EXECUTION_ACCEPTANCE',error=str(e));base.save(OUT/'evidence.json',r);raise
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--jobs',type=int,default=2);p.add_argument('--verify',action='store_true');a=p.parse_args()
    if a.verify:verify();print('{"status":"LIFETIME_BACKEND_CURRENT_NOT_EXECUTED"}')
    else:main(a.jobs)
