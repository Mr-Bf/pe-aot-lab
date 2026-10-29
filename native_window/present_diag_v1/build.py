"""Build the prepared diagnostic DXMT tree without loading its libraries.

Default is read-only verification. SDK/resource/source/tool trees are recorded
before and after compilation; Ninja's actual compiler dependencies are retained.
Meson/compiler feature probes are build activity, not guest or GPU acceptance.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from graphics_stage5 import d3d11_probe as g, bootstrap_dxmt as bootstrap
from native_window import build_v2 as old
from native_window.present_diag_v1 import prepare as source

ROOT=source.ROOT
OUT=ROOT/'build/native-present-diag-v1/backend-01'
BUILD=source.DEST.parent/'dxmt-build-v1'
SOURCE_SHA='494a7cac268d1537475fbc93ee07744e22ab201743a871514813f51d47bca65a'
STATUS='BUILT_DIAGNOSTIC_LIBRARIES_NOT_LOADED_OR_RENDER_VERIFIED'
SCOPE={'library_loads':0,'guest_executions':0,'window_executions':0,'gpu_executions':0}
HOOKS=('thread_token','register_queue','publish_queue')
API=('_DXMTPresentDiagConfigureV1','_DXMTPresentDiagReadV1')
DEPENDENCY_SCOPE='source/LLVM/Meson/SDK/resource/toolchain-include trees before+after; actual compiler dependency paths after build, including generated headers; not hostile transient-write attestation'
need=source.need
write=source.write

class Reads:
    def __init__(self): self.values={}
    def take(self,path,want=None):
        p=Path(path).resolve();raw=p.read_bytes()
        need(p not in self.values or self.values[p]==raw,'changed bytes '+str(p))
        need(want is None or source.sha(raw)==want,'wrong byte identity '+str(p))
        self.values[p]=raw;return raw
    def parsed(self,path,want=None):return g.strict_json(self.take(path,want).decode())
    def finish(self):
        for p,raw in self.values.items():need(p.read_bytes()==raw,'read drift '+str(p))

def environment():
    return {**g.environment(OUT),'PYTHONPATH':str(g.WORK/'python'),
            'PYTHONDONTWRITEBYTECODE':'1',
            'PATH':str(bootstrap.NINJA.parent)+':/usr/bin:/bin:/usr/sbin:/sbin'}

def configuration():
    need(g.sha(source.OUT/'evidence.json')==SOURCE_SHA,'frozen prepared source receipt')
    source.verify()
    r=Reads();e=r.parsed(source.BACKEND,source.BACKEND_SHA);t=e['tools']
    live=g.tools(OUT)
    for name in ('ar','clang','metal','metallib'):
        live[name]=str(Path(subprocess.check_output(['/usr/bin/xcrun','--find',name],env=environment(),text=True).strip()).resolve())
    for name in ('cc','c++','touch','xxd'):
        resolved=shutil.which(name,path=environment()['PATH'])
        need(resolved is not None,'actual build shim absent '+name)
        live['shim_'+name]=str(Path(resolved).resolve())
    need(live==t and Path(sys.executable).resolve()==Path(t['python']).resolve(),'actual Xcode/PATH/Python tool selection differs from pinned build')
    files={Path(p) for p in t.values() if p!=t['sdk']}
    need(all(g.sha(p)==e['inputs_before']['files'][str(p.resolve())] for p in files),'original actual build tool identity')
    llvm=Path(e['inputs_before']['llvm_install']['root'])
    meson=Path(e['inputs_before']['meson']['root'])
    need(source.tree(llvm)==e['inputs_before']['llvm_install']['tree_identity'],'original LLVM install changed')
    need(source.tree(meson)==e['inputs_before']['meson']['tree_identity'],'original Meson install changed')
    resource=subprocess.check_output([t['clang'],'-print-resource-dir'],env=environment(),text=True).strip()
    roots={'source':source.DEST,'llvm':llvm,'meson':meson,
           'sdk':Path(t['sdk']).resolve(),'clang_resource':Path(resource).resolve(),
           'toolchain_include':(Path(t['clang']).parent.parent/'include').resolve()}
    need(all(p.is_dir() and p==p.resolve() for p in roots.values()),'real tool/source roots')
    r.finish();return t,roots

def inputs(t,roots):
    paths=old.python_closure(__file__)|set(source.sources())|{source.OUT/'evidence.json',
        source.OUT/'started.json',source.OUT/'changes.json',source.OUT/'present-diagnostics-v1.patch',
        source.BACKEND,bootstrap.NINJA,Path(sys.executable),Path('/usr/bin/nm'),Path('/usr/bin/otool')}
    paths|={Path(v) for k,v in t.items() if k!='sdk'}
    return {'files':g.hashes(paths),'trees':{k:{'root':str(p),'identity':source.tree(p)} for k,p in roots.items()}}

def plan(llvm,jobs):
    return [[sys.executable,'-m','mesonbuild.mesonmain','setup',str(BUILD),str(source.DEST),
             '--buildtype=release','-Dnative_llvm_path='+str(llvm),'-Denable_nvapi=false',
             '-Denable_nvngx=false','-Denable_d3d12=false'],
            [sys.executable,'-m','mesonbuild.mesonmain','compile','-C',str(BUILD),'-j',str(jobs)]]

def command(args,name,cwd=ROOT):
    args=list(map(str,args));p=OUT/name
    with p.open('x') as stream:
        stream.write(json.dumps(args)+'\n');stream.flush()
        completed=subprocess.run(args,cwd=cwd,env=environment(),stdout=stream,stderr=subprocess.STDOUT)
    value={'argv':args,'cwd':str(cwd),'returncode':completed.returncode,'log':name,'sha256':g.sha(p)}
    need(completed.returncode==0,'command failed; preserved '+str(p));return value

def inspect_libraries():
    paths=sorted(p.resolve() for p in BUILD.rglob('*.dylib') if p.is_file())
    need(paths,'no emitted libraries')
    before=g.hashes(paths)
    for p in paths:need(g.macho(p)['filetype']==6,'output is not a dylib '+str(p))
    library=BUILD/'src/d3d11/d3d11.dylib'
    graph=g.library_graph(library,OUT/'future-host',[library.parent])
    provider=BUILD/'src/nativemetal/winemetal.dylib'
    need(set(graph['nodes'])=={str(library),str(BUILD/'src/dxgi/dxgi.dylib'),str(provider)},'unexpected reachable native graph')
    need(all(Path(p).is_relative_to(BUILD) for p in graph['nodes']),'old/external native library mixed in')
    symbols={}
    for i,p in enumerate(paths):
        defined=subprocess.check_output(['/usr/bin/nm','-gjU',str(p)],text=True,env=environment()).splitlines()
        undefined=subprocess.check_output(['/usr/bin/nm','-gju',str(p)],text=True,env=environment()).splitlines()
        symbols[str(p)]={'defined':defined,'undefined':undefined}
    definitions=symbols[str(provider)]['defined'];selected={name:name for name in API}
    for hook in HOOKS:
        found=[s for s in definitions if s.startswith('__ZN4dxmt15present_diag_v1') and hook in s]
        need(len(found)==1,'unique provider hook '+hook);selected[hook]=found[0]
    for symbol in selected.values():
        need([p for p in symbols if symbol in symbols[p]['defined']]==[str(provider)],'provider duplicated or absent '+symbol)
    need(set(selected[h] for h in HOOKS)<=set(symbols[str(library)]['undefined']),'D3D11 did not reference the one provider')
    need(g.hashes(paths)==before,'library changed while reading graph/symbols')
    return {'outputs':before,'graph':graph,'symbols':symbols,'provider':str(provider),'selected_symbols':selected}

def parse_dep_blocks(raw):
    text=raw.decode();names=set();target_names=set();target=None;declared=0;block=set()
    def complete():
        need(target is None or len(block)==declared,'Ninja block dependency count differs')
    for line in text.splitlines():
        if not line:continue
        if line.startswith('    '):
            name=line[4:]
            need(target is not None and name and name not in block,'orphan/empty/duplicate dependency')
            block.add(name);names.add(name)
        else:
            complete()
            match=re.fullmatch(r'(.+): #deps ([0-9]+), deps mtime [0-9]+ \(VALID\)',line)
            need(match is not None,'invalid/stale Ninja dependency record '+line)
            target=str((BUILD/match[1]).resolve());need(target not in target_names,'duplicate Ninja target');target_names.add(target)
            declared=int(match[2]);block=set()
    complete();need(target_names,'empty Ninja target list')
    return names,target_names

def dependencies(raw,compile_raw,roots):
    names,target_names=parse_dep_blocks(raw)
    commands=g.strict_json(compile_raw.decode());need(type(commands) is list and commands,'compile database absent')
    provider=source.DEST/'src/nativemetal/present_diagnostics_v1.cpp'
    found=[];expected_targets=set();untracked=[]
    for item in commands:
        directory=Path(item['directory']);file=Path(item['file'])
        file=(directory/file).resolve() if not file.is_absolute() else file.resolve()
        if file==provider:found.append(item)
        args=shlex.split(item['command'])
        if '-MD' in args:
            need(args.count('-o')==1 and args.count('-MQ')==1,'actual dependency target flags')
            output=Path(args[args.index('-o')+1]);quoted=Path(args[args.index('-MQ')+1])
            output=(directory/output).resolve();quoted=(directory/quoted).resolve()
            need(output==quoted and str(output) not in expected_targets,'ambiguous compile target')
            expected_targets.add(str(output))
        else:untracked.append(item)
    need(expected_targets==target_names,'actual Ninja targets differ from all -MD compile targets')
    paths=set()
    for name in names:
        p=Path(name);p=(BUILD/p).resolve() if not p.is_absolute() else p.resolve()
        need(p.is_file(),'actual compiler dependency missing '+str(p))
        need(p.is_relative_to(BUILD) or any(p.is_relative_to(root) for root in roots.values()),'unbound external compiler dependency '+str(p))
        paths.add(p)
    need(len(found)==1 and '-MD' in shlex.split(found[0]['command']),'provider actual compiler dependency flags absent')
    need(provider in paths and source.DEST/'include/dxmt_present_diag_internal_v1.hpp' in paths and
         source.DEST/'include/dxmt_present_diagnostics_v1.h' in paths,'provider/header not in actual compiler dependency closure')
    need(target_names and paths,'empty actual dependencies')
    return {'target_count':len(target_names),'targets':sorted(target_names),'paths':g.hashes(paths),
            'provider_compile':found[0],'non_MD_compile_commands':untracked}

def compiler_gate(raw):
    info=g.strict_json(raw.decode())
    need(all(info[realm][language]['exelist']==[driver] and info[realm][language]['id']=='clang'
             for realm in ('host','build') for language,driver in (('c','cc'),('cpp','c++'))),'actual Meson compiler selection')

def artifact_paths():
    return [OUT/n for n in ('started.json','configure.log','build.log','ninja-deps.log',
        'compile_commands.json','compilers.json','library-inspection.json','dependencies.json')]

def build(jobs=2):
    need(type(jobs) is int and 1<=jobs<=4,'bounded build parallelism')
    need(not OUT.exists() and not BUILD.exists(),'fresh output/build required; preserve previous attempts')
    OUT.mkdir(parents=True)
    try:
        t,roots=configuration();before=inputs(t,roots);commands=plan(roots['llvm'],jobs)
        write(OUT/'started.json',{'status':'BUILD_STARTED_NOT_LOADED','source_receipt_sha256':SOURCE_SHA,
            'inputs':before,'tools':t,'roots':{k:str(p) for k,p in roots.items()},'jobs':jobs,'plan':commands,'scope':SCOPE})
        records=[]
        for args,name in zip(commands,('configure.log','build.log')):
            print(json.dumps({'phase':name,'guest_gpu':0}),flush=True);records.append(command(args,name))
        records.append(command([bootstrap.NINJA,'-C',BUILD,'-t','deps'],'ninja-deps.log'))
        for name,src in [('compile_commands.json',BUILD/'compile_commands.json'),('compilers.json',BUILD/'meson-info/intro-compilers.json')]:
            with (OUT/name).open('xb') as stream:stream.write(src.read_bytes())
        raw=(OUT/'ninja-deps.log').read_bytes().split(b'\n',1)[1]
        compiler_gate((OUT/'compilers.json').read_bytes())
        dep=dependencies(raw,(OUT/'compile_commands.json').read_bytes(),roots);write(OUT/'dependencies.json',dep)
        libraries=inspect_libraries();write(OUT/'library-inspection.json',libraries)
        after=inputs(t,roots);need(before==after,'source/tool/SDK/resource input changed during build');source.verify()
        record={'schema':1,'status':STATUS,'scope':SCOPE,'source_receipt_sha256':SOURCE_SHA,'jobs':jobs,
            'inputs_before':before,'inputs_after':after,'tools':t,'roots':{k:str(p) for k,p in roots.items()},
            'commands':records,'libraries':libraries,'dependencies':dep,'artifacts':g.hashes(artifact_paths()),
            'dependency_scope':DEPENDENCY_SCOPE}
        write(OUT/'evidence.json',record);return verify()
    except BaseException as error:
        write(OUT/'failure.json',{'status':'BUILD_FAILED_PRESERVED_NOT_EXECUTION_ACCEPTANCE','error':repr(error),'scope':SCOPE})
        raise

def verify():
    r=Reads();e=r.parsed(OUT/'evidence.json')
    need(set(e)=={'schema','status','scope','source_receipt_sha256','jobs','inputs_before','inputs_after',
        'tools','roots','commands','libraries','dependencies','artifacts','dependency_scope'},'exact receipt fields')
    need(set(p.name for p in OUT.iterdir())=={p.name for p in artifact_paths()}|{'evidence.json'},'exact successful build artifact set')
    need(e['schema']==1 and e['status']==STATUS and e['scope']==SCOPE and e['source_receipt_sha256']==SOURCE_SHA,'build status/scope/source')
    need(type(e['schema']) is int and all(type(v) is int for v in e['scope'].values()) and
         e['dependency_scope']==DEPENDENCY_SCOPE,'typed build scope')
    need(type(e['jobs']) is int and 1<=e['jobs']<=4,'recorded parallelism')
    t,roots=configuration();current=inputs(t,roots)
    need(e['inputs_before']==e['inputs_after']==current and e['tools']==t and e['roots']=={k:str(p) for k,p in roots.items()},'current source/tool/SDK identity')
    need(set(e['artifacts'])==set(map(str,artifact_paths())),'required build artifact omitted')
    values={str(p):r.take(p,e['artifacts'][str(p)]) for p in artifact_paths()}
    started=g.strict_json(values[str(OUT/'started.json')].decode())
    commands=plan(roots['llvm'],e['jobs'])
    need(started=={'status':'BUILD_STARTED_NOT_LOADED','source_receipt_sha256':SOURCE_SHA,'inputs':current,
        'tools':t,'roots':e['roots'],'jobs':e['jobs'],'plan':commands,'scope':SCOPE},'actual start fields')
    expected=[*commands,list(map(str,[bootstrap.NINJA,'-C',BUILD,'-t','deps']))]
    need(len(e['commands'])==3,'command count')
    for item,args,name in zip(e['commands'],expected,('configure.log','build.log','ninja-deps.log')):
        raw=values[str(OUT/name)]
        need(item=={'argv':args,'cwd':str(ROOT),'returncode':0,'log':name,'sha256':source.sha(raw)} and
             g.strict_json(raw.split(b'\n',1)[0].decode())==args,'actual command/log mismatch')
    for name,path in [('compile_commands.json',BUILD/'compile_commands.json'),('compilers.json',BUILD/'meson-info/intro-compilers.json')]:
        need(r.take(path)==values[str(OUT/name)],'live build metadata differs')
    compiler_gate(values[str(OUT/'compilers.json')])
    dep=dependencies(values[str(OUT/'ninja-deps.log')].split(b'\n',1)[1],values[str(OUT/'compile_commands.json')],roots)
    need(e['dependencies']==g.strict_json(values[str(OUT/'dependencies.json')].decode())==dep,'actual compiler dependency closure')
    libraries=inspect_libraries()
    need(e['libraries']==g.strict_json(values[str(OUT/'library-inspection.json')].decode())==libraries,'actual library/provider closure')
    after_tools,after_roots=configuration()
    need(after_tools==t and after_roots==roots and inputs(t,roots)==current,'inputs changed during read-only verification')
    need(g.hashes(libraries['outputs'])==libraries['outputs'],'libraries changed before verification completed')
    r.finish();return {'status':STATUS+'_CURRENT','evidence_sha256':g.sha(OUT/'evidence.json'),
        'provider':libraries['provider'],'libraries':len(libraries['outputs']),
        'dependency_files':len(dep['paths']),'scope':SCOPE}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',action='store_true');p.add_argument('--jobs',type=int,default=2)
    a=p.parse_args();print(json.dumps(build(a.jobs) if a.build else verify(),sort_keys=True))
