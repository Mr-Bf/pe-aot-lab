#!/usr/bin/env python3
"""Clean isolated DXMT native WSI + lifetime-r2 build, with no library execution.

The v1 window backend and headless Draw backend remain immutable. All configure
and build output is created exclusively; a second invocation must use --verify.
"""
import argparse,ast,json,os,re,shutil,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as base
from graphics_stage5 import bootstrap_dxmt as bootstrap
WORK=ROOT.parents[1]/'work/native-window-v2'
SOURCE=WORK/'dxmt-source-v2';BUILD=WORK/'dxmt-build-v2'
OUT=ROOT/'build/native-window/backend-v2'
WSI=HERE/'native-wsi-v1.patch';LIFETIME=ROOT/'graphics_stage5/lifetime_v2/dxmt-lifetime-v2.patch'
STATUS='BUILT_NATIVE_WINDOW_LIFETIME_V2_NOT_EXECUTED'
PROFILE='native-window-wsi-v1-plus-lifetime-v2-r2'
PINNED={
    WSI:'f4b92bacacb3f8ffbb6b1f34f872f1e846e61baf2592415c112d43dde70b4d03',
    LIFETIME:'f4e3dd3ef84726d03b3fabb06464336bfe77451be1ab487656d30604b27b9ef5',
    HERE/'native_wsi.h':'a8af60b64dcb8085ae9f382a35c89a0176e25397421e2d9dea8c6cc8dd7f9135',
    HERE/'native_wsi.c':'3f81cf7face4894e95e502ad4fa2747ab0dadabd94519abe257bf361e558554a',
}
ADAPTERS={HERE/'native_wsi.h':'include/native_wsi.h',HERE/'native_wsi.c':'src/nativemetal/native_wsi.c'}
SCOPE={'library_loads':0,'gpu_executions':0,'window_executions':0,'guest_executions':0}
LOGS=('patch-wsi.log','patch-lifetime.log','configure.log','build.log')

def require(value,message):
    if not value:raise RuntimeError(message)
def bound(path):return bootstrap.bound_tree(Path(path))
def config():return {'dxmt_source':str(SOURCE),'dxmt_build':str(BUILD)}
def output(out):
    out=Path(out).resolve();require(out==OUT,'only the new native-window/backend-v2 output is writable');return out

def python_closure(start):
    pending=[Path(start).resolve()];seen=set()
    while pending:
        path=pending.pop()
        if path in seen:continue
        seen.add(path)
        for node in ast.walk(ast.parse(path.read_text(),filename=str(path))):
            modules=[]
            if isinstance(node,ast.Import):modules=[n.name for n in node.names]
            elif isinstance(node,ast.ImportFrom) and node.module:
                require(node.level==0,'new relative Python dependency requires explicit support')
                modules=[node.module,*[node.module+'.'+n.name for n in node.names]]
            for module in modules:
                relative=ROOT.joinpath(*module.split('.'))
                for candidate in (relative.with_suffix('.py'),relative/'__init__.py'):
                    if candidate.is_file():pending.append(candidate.resolve())
    return seen

def transforms():
    require(base.hashes(PINNED)=={str(p):h for p,h in PINNED.items()},'frozen WSI/lifetime/adapter identity changed')
    targets={}
    for patch in (WSI,LIFETIME):
        old=re.findall(r'^--- a/([^\n]+)$',patch.read_text(),re.M)
        new=re.findall(r'^\+\+\+ b/([^\n]+)$',patch.read_text(),re.M)
        require(old==new and len(set(old))==len(old) and old,'patch target declaration differs')
        require(all(not Path(p).is_absolute() and '..' not in Path(p).parts for p in old),'patch target escapes source')
        targets[str(patch)]=old
    require(not set(targets[str(WSI)])&set(targets[str(LIFETIME)]),'patches unexpectedly overlap')
    return {'order':[str(WSI),str(LIFETIME)],'files':base.hashes(PINNED),'targets':targets,
            'adapter_destinations':{str(p):v for p,v in ADAPTERS.items()}}

def frozen():
    c={'dxmt_source':str(base.WORK/('sources/dxmt-'+base.DXMT)),'dxmt_build':str(base.WORK/'dxmt-build')}
    _,records,_=base.provenance(c)
    return c,records

def patch_command(patch,source):
    return list(map(str,['/usr/bin/patch','-p1','-F','0','--batch','--forward','-i',patch,'-d',source]))
def validate_patch_output(text):
    require(not re.search(r'\b(?:offset|fuzz|FAILED|Reversed|previously applied)\b',text,re.I),'patch was not an exact clean application')

def run(args,log,env):
    args=list(map(str,args));require(not log.exists(),'refusing to overwrite full command log: '+str(log))
    launch_error=None
    with log.open('x') as stream:
        stream.write(json.dumps(args)+'\n');stream.flush()
        try:returncode=subprocess.run(args,stdout=stream,stderr=subprocess.STDOUT,env=env).returncode
        except OSError as error:
            returncode=None;launch_error=str(error);stream.write('\nlaunch error: '+launch_error+'\n')
    result={'command':args,'log':str(log),'sha256':base.sha(log),'returncode':returncode}
    if launch_error is not None:result['launch_error']=launch_error
    return result

def execute(record,args,log,env):
    command=run(args,log,env);record['commands'].append(command)
    require(command['returncode']==0,'native-window-v2 command failed: '+str(log))

def tools():
    t=base.tools(OUT)
    for name in ('clang','ar','metal','metallib'):
        t[name]=str(Path(subprocess.check_output(['/usr/bin/xcrun','--find',name],text=True,env=base.environment(OUT)).strip()).resolve())
    for name in ('cc','c++','touch','xxd'):
        resolved=shutil.which(name);require(resolved is not None,'missing build command: '+name);t['shim_'+name]=str(Path(resolved).resolve())
    return t

def discover():
    _,records=frozen();receipt=base.read_json(bootstrap.OUT/'evidence.json')
    install=Path(receipt['dxmt_provenance']['inputs_after']['llvm_install']['root']);t=tools()
    paths=[*python_closure(__file__),*PINNED,*records,*[Path(v) for k,v in t.items() if k!='sdk'],bootstrap.NINJA,Path('/usr/bin/patch')]
    return {'files':base.hashes(paths),'original_source':receipt['dxmt_provenance']['inputs_after']['source'],
            'source':bound(SOURCE),'llvm_install':bound(install),'meson':bound(base.WORK/'python')},t,install

def verify_source_transform():
    transform=transforms();c,_=frozen();original=Path(c['dxmt_source'])
    with tempfile.TemporaryDirectory(prefix='verify-composition-',dir=WORK) as temp:
        reference=Path(temp)/'source';shutil.copytree(original,reference,symlinks=True)
        for patch in (WSI,LIFETIME):
            p=subprocess.run(patch_command(patch,reference),capture_output=True,text=True)
            require(p.returncode==0,'independent exact transform failed: '+p.stderr);validate_patch_output(p.stdout+p.stderr)
        for source,dest in ADAPTERS.items():shutil.copy2(source,reference/dest)
        require(bound(reference)['tree_identity']==bound(SOURCE)['tree_identity'],'source differs from pinned base plus exact two patches and adapters')
    require(bound(original/'include/native/directx')['tree_identity']==bound(SOURCE/'include/native/directx')['tree_identity'],
            'original DirectX header closure changed')
    require(bound(original/'include/native/windows')['tree_identity']==bound(SOURCE/'include/native/windows')['tree_identity'],
            'original Windows header closure changed')
    return transform

def command_plan(install,jobs):
    return [patch_command(WSI,SOURCE),patch_command(LIFETIME,SOURCE),
            list(map(str,[sys.executable,'-m','mesonbuild.mesonmain','setup',BUILD,SOURCE,'--buildtype=release',
                '-Dnative_llvm_path='+str(install),'-Denable_nvapi=false','-Denable_nvngx=false','-Denable_d3d12=false'])),
            list(map(str,[sys.executable,'-m','mesonbuild.mesonmain','compile','-C',BUILD,'-j',str(jobs)]))]

def verify(out=OUT):
    out=output(out);r=base.read_json(out/'evidence.json')
    require(r.get('schema')==1 and r.get('profile')==PROFILE and r.get('status')==STATUS,'new backend not successfully built')
    require(r.get('config')==config() and r.get('source')==str(SOURCE) and r.get('build')==str(BUILD),'backend paths differ')
    require(r.get('scope')==SCOPE and all(type(v) is int for v in r['scope'].values()),'build scope claims execution')
    transform=verify_source_transform();current,t,install=discover()
    require(r['inputs_before']==r['inputs_after']==current and r['tools']==t,'complete backend input closure changed or omitted')
    require(type(r['jobs']) is int and 1<=r['jobs']<=8,'invalid recorded parallelism')
    expected_commands=command_plan(install,r['jobs'])
    require(len(r['commands'])==len(LOGS),'command chain incomplete')
    for record,name,args in zip(r['commands'],LOGS,expected_commands):
        require(set(record)=={'command','log','sha256','returncode'} and record['returncode']==0 and type(record['returncode']) is int,'invalid command result')
        require(record['command']==args and record['log']==str(out/name),'build command changed')
        log=out/name;require(base.sha(log)==record['sha256'],'full command log changed')
        require(json.loads(log.read_text().splitlines()[0])==args,'command log header differs')
        if name.startswith('patch-'):validate_patch_output(log.read_text())
    expected_artifacts=[out/'prepared.json',out/'compilers.json',*[out/name for name in LOGS]]
    require(r['artifacts']==base.hashes(expected_artifacts),'required build artifacts omitted or changed')
    prepared={'original':current['original_source'],'source':current['source'],'transforms':transform}
    require(base.read_json(out/'prepared.json')==prepared,'source preparation receipt differs')
    info=base.read_json(out/'compilers.json')
    require(info==base.read_json(BUILD/'meson-info/intro-compilers.json'),'actual compiler selection changed')
    require(all(info[realm]['c']['exelist']==['cc'] and info[realm]['cpp']['exelist']==['c++'] for realm in ('host','build')),'unexpected Meson compiler selection')
    paths={str(p.resolve()) for p in BUILD.rglob('*.dylib') if p.is_file()}
    require(bool(paths) and set(r['outputs'])==paths,'exact dylib output closure changed or omitted');base.same(r['outputs'])
    for path in paths:base.macho(path)  # all emitted dylibs must be ARM64 Mach-O, not just the reachable subset
    library=BUILD/'src/d3d11/d3d11.dylib';graph=base.library_graph(library,out/'future-probe',[library.parent])
    require(r['library']==str(library) and graph==r['library_graph'],'parsed actual library graph changed')
    require(set(graph['nodes'])<=paths and all(Path(p).is_relative_to(BUILD) for p in graph['nodes']),'old or external non-system backend mixed in')
    require(r.get('validation_scope')=='clean separate build; exact composition; all command output preserved; not loaded or executed','unknown validation scope')
    return r

def provenance(requested):
    require(requested==config(),'unknown window lifetime-v2 configuration');r=verify()
    records=[OUT/'evidence.json',Path(__file__),*PINNED,*map(Path,r['inputs_after']['files']),*map(Path,r['artifacts'])]
    return Path(r['library']),records,r['outputs']

def main(jobs=2):
    require(type(jobs) is int and 1<=jobs<=8,'invalid build parallelism')
    require(not SOURCE.exists() and not BUILD.exists() and not (OUT/'evidence.json').exists(),
            'version already attempted; preserve all logs and use --verify, or create a distinct new version')
    require(not OUT.exists() or not any(OUT.iterdir()),'nonempty output is not a clean build')
    OUT.mkdir(parents=True,exist_ok=True);WORK.mkdir(parents=True,exist_ok=True)
    r={'schema':1,'profile':PROFILE,'status':'PREPARING_NOT_EXECUTED','config':config(),'source':str(SOURCE),'build':str(BUILD),
       'scope':SCOPE,'jobs':jobs,'commands':[]};base.save(OUT/'evidence.json',r)
    try:
        transform=transforms();c,_=frozen();original=bound(c['dxmt_source']);shutil.copytree(c['dxmt_source'],SOURCE,symlinks=True)
        env={**base.environment(OUT),'PYTHONPATH':str(base.WORK/'python'),'PYTHONDONTWRITEBYTECODE':'1',
             'PATH':str(bootstrap.NINJA.parent)+':'+os.environ.get('PATH','')}
        for patch,name in zip((WSI,LIFETIME),LOGS):
            execute(r,patch_command(patch,SOURCE),OUT/name,env);validate_patch_output((OUT/name).read_text())
        for source,dest in ADAPTERS.items():shutil.copy2(source,SOURCE/dest)
        require(original==bound(c['dxmt_source']),'frozen base changed during preparation')
        base.save(OUT/'prepared.json',{'original':original,'source':bound(SOURCE),'transforms':transform})
        verify_source_transform();before,t,install=discover();r.update(inputs_before=before,tools=t)
        plans=command_plan(install,jobs)
        for command,name in zip(plans[2:],LOGS[2:]):execute(r,command,OUT/name,env)
        after,after_tools,_=discover();require(before==after and t==after_tools,'source/tool dependencies changed during compilation')
        shutil.copy2(BUILD/'meson-info/intro-compilers.json',OUT/'compilers.json')
        library=BUILD/'src/d3d11/d3d11.dylib';graph=base.library_graph(library,OUT/'future-probe',[library.parent])
        r.update(status=STATUS,inputs_after=after,library=str(library),library_graph=graph,
                 outputs=base.hashes(p for p in BUILD.rglob('*.dylib') if p.is_file()),
                 artifacts=base.hashes([OUT/'prepared.json',OUT/'compilers.json',*[OUT/name for name in LOGS]]),
                 validation_scope='clean separate build; exact composition; all command output preserved; not loaded or executed')
        base.save(OUT/'evidence.json',r);verify();print(json.dumps({'status':STATUS,'evidence':str(OUT/'evidence.json'),'library':str(library),'gpu_executions':0}))
    except Exception as error:
        r.update(status='FAIL_NOT_EXECUTION_ACCEPTANCE',error=str(error));base.save(OUT/'evidence.json',r)
        history=OUT/'history'/base.sha(OUT/'evidence.json');history.mkdir(parents=True,exist_ok=True)
        for path in [Path(__file__),*PINNED,*[p for p in OUT.iterdir() if p.is_file()]]:
            saved=history/(base.sha(path)+'-'+path.name)
            if not saved.exists():shutil.copy2(path,saved)
        raise
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--jobs',type=int,default=2);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    if args.verify:verify();print('{"status":"WINDOW_LIFETIME_V2_BACKEND_CURRENT_NOT_EXECUTED","gpu_executions":0}')
    else:main(args.jobs)
