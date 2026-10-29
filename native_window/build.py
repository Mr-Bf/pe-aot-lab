#!/usr/bin/env python3
"""Independent native-window DXMT source transform/build; never modifies frozen DXMT."""
import argparse,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent;WORK=ROOT.parents[1]/'work/native-window'
sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as base
from graphics_stage5 import bootstrap_dxmt as bootstrap
OUT=ROOT/'build/native-window/backend-v1'

def require(x,m):
    if not x:raise RuntimeError(m)
def run(args,log,env):
    args=list(map(str,args))
    with log.open('w') as stream:
        stream.write(json.dumps(args)+'\n');stream.flush()
        p=subprocess.run(args,stdout=stream,stderr=subprocess.STDOUT,env=env)
    require(p.returncode==0,'native-window command failed: '+str(log));return {'command':args,'log':str(log),'sha256':base.sha(log)}
def bound(path):return bootstrap.bound_tree(Path(path))
def frozen():
    config={'dxmt_source':str((base.WORK/('sources/dxmt-'+base.DXMT)).resolve()),'dxmt_build':str((base.WORK/'dxmt-build').resolve())}
    library,records,proof=base.provenance(config)
    return config,records,proof

def discover(out,source):
    config,records,proof=frozen();receipt=base.read_json(bootstrap.OUT/'evidence.json')
    install=Path(receipt['dxmt_provenance']['inputs_after']['llvm_install']['root'])
    tools=base.tools(out)
    for name in ('clang','ar','metal','metallib'):
        tools[name]=str(Path(subprocess.check_output(['/usr/bin/xcrun','--find',name],text=True,env=base.environment(out)).strip()).resolve())
    for name in ('cc','c++','touch','xxd'):
        tools['shim_'+name]=str(Path(shutil.which(name)).resolve())
    paths=[Path(__file__),HERE/'native_wsi.h',HERE/'native_wsi.c',HERE/'native-wsi-v1.patch',Path(base.__file__),Path(bootstrap.__file__),
           *records,*[Path(v) for k,v in tools.items() if k!='sdk'],bootstrap.NINJA,Path('/usr/bin/patch')]
    return {'files':base.hashes(paths),'original_source':receipt['dxmt_provenance']['inputs_after']['source'],
            'source':bound(source),'llvm_install':bound(install),'meson':bound(base.WORK/'python')},tools,install

def verify_source_transform(source):
    config,_,_=frozen();original=Path(config['dxmt_source'])
    with tempfile.TemporaryDirectory(prefix='verify-source-',dir=WORK) as directory:
        reference=Path(directory)/'source';shutil.copytree(original,reference,symlinks=True)
        p=subprocess.run(list(map(str,['/usr/bin/patch','-p1','--batch','--forward','-i',HERE/'native-wsi-v1.patch','-d',reference])),capture_output=True,text=True)
        require(p.returncode==0,'exact source transform cannot be reproduced: '+p.stderr)
        shutil.copy2(HERE/'native_wsi.h',reference/'include/native_wsi.h');shutil.copy2(HERE/'native_wsi.c',reference/'src/nativemetal/native_wsi.c')
        require(bound(reference)['tree_identity']==bound(source)['tree_identity'],'new source differs from pinned baseline plus exact patch/header/C adapter')

def verify(out=OUT):
    out=Path(out).resolve();r=base.read_json(out/'evidence.json');require(r.get('status')=='BUILT_NATIVE_WINDOW_BACKEND_NOT_EXECUTED' and r.get('schema')==1,'window backend not built')
    source=Path(r['source']);verify_source_transform(source);current,tools,install=discover(out,source)
    require(r['inputs_before']==r['inputs_after']==current and tools==r['tools'],'backend source/tool/dependency identity changed')
    require(r['source']==str(WORK/'dxmt-source-v1') and r['build']==str(WORK/'dxmt-build-v1'),'unknown build paths')
    require(base.hashes(r['outputs'])==r['outputs'],'backend dylib changed')
    require(set(r['outputs'])=={str(p.resolve()) for p in Path(r['build']).rglob('*.dylib') if p.is_file()},'backend output closure omitted')
    library=Path(r['library']);graph=base.library_graph(library,out/'future-probe',[library.parent]);require(graph==r['library_graph'],'actual backend library graph changed')
    require(set(graph['nodes'])<=set(r['outputs']) and all(Path(p).is_relative_to(Path(r['build'])) for p in graph['nodes']),'mixed backend provenance')
    required=[out/'prepared.json',out/'patch.log',out/'configure.log',out/'build.log',out/'compilers.json']
    require(base.hashes(required)==r['artifacts'],'build evidence artifact missing or changed')
    p=base.read_json(out/'prepared.json');require(p['transforms']==base.hashes([HERE/'native_wsi.h',HERE/'native_wsi.c',HERE/'native-wsi-v1.patch']) and p['source']==current['source'] and p['original']==current['original_source'],'source preparation receipt incomplete or changed')
    return r

def main(out=OUT,jobs=2):
    out=Path(out).resolve();require(out.is_relative_to(ROOT/'build/native-window'),'independent output required');out.mkdir(parents=True,exist_ok=True);WORK.mkdir(parents=True,exist_ok=True)
    evidence=out/'evidence.json';source=WORK/'dxmt-source-v1';build=WORK/'dxmt-build-v1'
    if evidence.exists():
        history=out/'history'/base.sha(evidence);history.mkdir(parents=True,exist_ok=True)
        for prior in [x for x in out.iterdir() if x.is_file()]:shutil.copy2(prior,history/(base.sha(prior)+'-'+prior.name))
    record={'schema':1,'status':'PREPARING_NOT_EXECUTED','source':str(source),'build':str(build),'commands':[],'scope':'native single-window WSI callback backend only; no GPU/window/guest acceptance'};base.save(evidence,record)
    try:
        config,records,proof=frozen();original=Path(config['dxmt_source']);before_original=bound(original)
        package=base.WORK/'python';env={**base.environment(out),'PYTHONPATH':str(package),'PYTHONDONTWRITEBYTECODE':'1','PATH':str(bootstrap.NINJA.parent)+':'+os.environ.get('PATH','')}
        prepared=out/'prepared.json';transforms=base.hashes([HERE/'native_wsi.h',HERE/'native_wsi.c',HERE/'native-wsi-v1.patch'])
        if source.exists():
            require(prepared.exists(),'existing source lacks preparation receipt')
            p=base.read_json(prepared);require(p['transforms']==transforms and p['original']==before_original and p['source']==bound(source),'prepared source or transform changed; preserve and create a new version')
        else:
            shutil.copytree(original,source,symlinks=True)
            record['commands'].append(run(['/usr/bin/patch','-p1','--batch','--forward','-i',HERE/'native-wsi-v1.patch','-d',source],out/'patch.log',env))
            shutil.copy2(HERE/'native_wsi.h',source/'include/native_wsi.h');shutil.copy2(HERE/'native_wsi.c',source/'src/nativemetal/native_wsi.c')
            require(before_original==bound(original),'frozen source changed during copy')
            base.save(prepared,{'original':before_original,'transforms':transforms,'source':bound(source)})
        before,tools,install=discover(out,source);record.update(inputs_before=before,tools=tools)
        configure=[sys.executable,'-m','mesonbuild.mesonmain','setup',build,source,'--buildtype=release','-Dnative_llvm_path='+str(install),'-Denable_nvapi=false','-Denable_nvngx=false','-Denable_d3d12=false']
        if (build/'meson-private/coredata.dat').exists():configure.append('--reconfigure')
        record['commands'].append(run(configure,out/'configure.log',env));record['commands'].append(run([sys.executable,'-m','mesonbuild.mesonmain','compile','-C',build,'-j',str(jobs)],out/'build.log',env))
        after,after_tools,_=discover(out,source);require(before==after and tools==after_tools,'inputs changed during build')
        compiler_info=base.read_json(build/'meson-info/intro-compilers.json')
        require(all(compiler_info[realm]['c']['exelist']==['cc'] and compiler_info[realm]['cpp']['exelist']==['c++'] for realm in ('host','build')),'unexpected Meson compiler selection')
        shutil.copy2(build/'meson-info/intro-compilers.json',out/'compilers.json')
        outputs=base.hashes(p for p in build.rglob('*.dylib') if p.is_file());library=build/'src/d3d11/d3d11.dylib'
        graph=base.library_graph(library,out/'future-probe',[library.parent]);require(set(graph['nodes'])<=set(outputs),'linked non-system dependency absent from output receipt')
        require(all(Path(p).is_relative_to(build) for p in graph['nodes']),'old backend mixed with new window libraries')
        record.update(status='BUILT_NATIVE_WINDOW_BACKEND_NOT_EXECUTED',validation_scope='existing native source build plus current incremental/no-op verification; not a clean empty-directory rebuild',historical_log_limit='initial 166-target successful build stdout convenience file was overwritten by early no-op verification before complete log archival was added; prior receipt SHA retained; no fabricated reconstruction',inputs_after=after,outputs=outputs,library=str(library),library_graph=graph,
                      artifacts=base.hashes([prepared,out/'patch.log',out/'configure.log',out/'build.log',out/'compilers.json']))
        base.save(evidence,record);verify(out);print(json.dumps({'status':record['status'],'library':str(library),'evidence':str(evidence)}))
    except Exception as error:
        record.update(status='FAIL_NOT_EXECUTION_ACCEPTANCE',error=str(error));base.save(evidence,record)
        h=out/'history'/base.sha(evidence);h.mkdir(parents=True,exist_ok=True)
        for p in [HERE/'native_wsi.h',HERE/'native_wsi.c',HERE/'native-wsi-v1.patch',Path(__file__),*[p for p in out.iterdir() if p.is_file()]]:shutil.copy2(p,h/(base.sha(p)+'-'+p.name))
        raise
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=OUT);p.add_argument('--jobs',type=int,default=2);p.add_argument('--verify',action='store_true');a=p.parse_args()
    if a.verify:verify(a.out);print('{"status":"BACKEND_CURRENT_NOT_EXECUTED"}')
    else:main(a.out,a.jobs)
