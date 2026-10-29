#!/usr/bin/env python3
"""Self-contained native window App, static preparation only.

Combines frozen v1 host sources with the separately verified WSI+lifetime-r2
backend. No dlopen, process launch, Cocoa, or GPU operation is performed here.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as base
from native_window import build_v2 as backend
HERE=Path(__file__).resolve().parent
OUT=ROOT/'build/native-window/probe-v2-package3'
STATUS='SELF_CONTAINED_APP_STATICALLY_VERIFIED_NOT_EXECUTED'
FROZEN_HOST={
    HERE/'cocoa_registry.h':'c53f30bce1a420850cedd3b1effbc621df7331b53ba79739728c2ed0da3f0c34',
    HERE/'cocoa_registry.mm':'2cd8dc641d03fdd10ad911d35de17b92e892ad52bb6d05da528d4f4a64d8805c',
    HERE/'probe.cpp':'56b1d8dfa0e981e1e729d6f7a07ba89d1c5ac175d7be508d570cb443dbdf3407',
}
PLIST={'CFBundleIdentifier':'org.peaotlab.NativeWindowProbeV2',
       'CFBundleName':'PE AOT Window Probe V2','CFBundleDisplayName':'PE AOT Window Probe V2',
       'CFBundleExecutable':'native-window-probe','CFBundlePackageType':'APPL',
       'CFBundleVersion':'2','NSHighResolutionCapable':True}
SCOPE={'library_loads':0,'process_launches':0,'gpu_executions':0,'window_executions':0,'guest_executions':0}
PACKAGE_NAMES={'d3d11.dylib','dxgi.dylib','winemetal.dylib'}


def require(value,message):
    if not value:raise RuntimeError(message)


def app_path(out=OUT):return Path(out)/'PE AOT Window Probe V2.app'
def executable(app):return Path(app)/'Contents/MacOS/native-window-probe'
def framework(app):return Path(app)/'Contents/Frameworks'
def relocation_path(out=OUT):return Path(out)/'relocation with spaces/Window Relocated.app'


def environment(out):
    return base.environment(Path(out))


def tools():
    found=base.tools(OUT)
    for name in ('install_name_tool','codesign','otool'):
        found[name]=str(Path(shutil.which(name) or '/usr/bin/'+name).resolve())
        require(Path(found[name]).is_file(),'missing tool: '+name)
    return found


def command(args,name,commands):
    args=list(map(str,args));log=OUT/(name+'.json')
    require(not log.exists(),'refusing to overwrite command evidence: '+str(log))
    p=subprocess.run(args,env=environment(OUT),capture_output=True,text=True)
    record={'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    log.write_text(json.dumps(record,indent=2)+'\n')
    commands.append({'name':name,'path':str(log),'sha256':base.sha(log),'returncode':p.returncode})
    require(p.returncode==0,'static App command failed: '+str(log))
    return p.stdout


def source_flags(record,t):
    common=['-arch','arm64','-isysroot',t['sdk'],'-std=c++20','-O2','-Wall','-Wextra','-Werror']
    source=Path(record['source'])
    return {'cpp':[*common,'-Wno-extern-c-compat','-I'+str(source/'include/native/windows'),'-I'+str(source/'include/native/directx')],
            'objc':[*common,'-Wno-deprecated-declarations']}


def discover(t,write=False,commands=None):
    r=backend.verify()
    require(base.hashes(FROZEN_HOST)=={str(p):h for p,h in FROZEN_HOST.items()},'v1 host sources changed; create a versioned host source')
    flags=source_flags(r,t)
    paths=[*FROZEN_HOST,HERE/'native_wsi.h',Path(__file__),Path(base.__file__),Path(backend.__file__),
           backend.OUT/'evidence.json',*map(Path,r['inputs_after']['files']),*map(Path,r['outputs']),
           *map(Path,r['artifacts']),*[Path(v) for k,v in t.items() if k!='sdk']]
    for kind,source in [('cpp',HERE/'probe.cpp'),('objc',HERE/'cocoa_registry.mm')]:
        args=[t['clang++'],*flags[kind],'-M','-MT','probe',source]
        text=command(args,'dependencies-'+kind,commands) if write else base.invoke(args,environment(OUT))
        paths+=base.dependency_paths(text)
    return base.hashes(paths),r


def tree(app):
    app=Path(app)
    require(app.is_dir() and not app.is_symlink(),'App root must be a real directory')
    result={}
    for p in sorted(app.rglob('*')):
        require(not p.is_symlink(),'App links are not supported in this fixture')
        if p.is_file():result[str(p.relative_to(app))]={'sha256':base.sha(p),'mode':p.stat().st_mode&0o777}
        else:require(p.is_dir(),'special App path rejected')
    require(result,'empty App')
    return result


def normalize_graph(graph,app):
    app=Path(app).resolve()
    def local(p):
        p=Path(p)
        return str(p.relative_to(app)) if p.is_relative_to(app) else str(p)
    return {'nodes':{local(p):v for p,v in graph['nodes'].items()},
            'edges':[[local(owner),name,local(target),command] for owner,name,target,command in graph['edges']],
            'system_images':graph['system_images'],'scope':graph['scope']}


def package_graph(app):
    app=Path(app).resolve();exe=executable(app);libs=framework(app)
    require(set(p.name for p in libs.iterdir())==PACKAGE_NAMES,'incorrect actual bundled library set')
    require(plistlib.loads((app/'Contents/Info.plist').read_bytes())==PLIST,'App metadata differs')
    graph=base.library_graph(exe,exe)
    expected={str(exe),*[str(libs/name) for name in PACKAGE_NAMES]}
    require(set(graph['nodes'])==expected,'non-system graph escapes bundle or omits a bundled library')
    for path,node in graph['nodes'].items():
        is_exe=path==str(exe)
        require(node['rpaths']==(['@executable_path/../Frameworks'] if is_exe else ['@loader_path/']),
                'unexpected residual search path: '+path)
        if not is_exe:require(node['id']=='@rpath/'+Path(path).name,'non-relative install name')
        require(node['filetype']==(2 if is_exe else 6),'incorrect Mach-O type')
        require(Path(path).stat().st_mode&0o111,'code file is not executable')
        for dep in node['dependencies']:
            require(base.system_image(dep['name']) or dep['name'] in {'@rpath/'+n for n in PACKAGE_NAMES},
                    'external/non-relative dependency: '+dep['name'])
    for owner,name,target,kind in graph['edges']:
        require(base.system_image(target) or Path(target).is_relative_to(app),'load graph references work/Documents library')
    return graph


def install_plan(original_graph,mapping,t):
    plans={}
    for original,path in mapping.items():
        node=original_graph['nodes'][original]
        args=[t['install_name_tool'],'-id','@rpath/'+path.name]
        for old in node['rpaths']:
            if old!='@loader_path/':args+=['-delete_rpath',old]
        if '@loader_path/' not in node['rpaths']:args+=['-add_rpath','@loader_path/']
        for owner,name,target,kind in original_graph['edges']:
            if owner==original and target in mapping:
                args+=['-change',name,'@rpath/'+mapping[target].name]
        args.append(path)
        plans[path.name]=list(map(str,args))
    return plans


def build():
    require(not OUT.exists() or not any(OUT.iterdir()),'v2 output already attempted; preserve it and use verify')
    OUT.mkdir(parents=True,exist_ok=True)
    t=tools();commands=[]
    initial={'schema':1,'status':'PREPARING_NOT_EXECUTED','scope':SCOPE,'commands':commands}
    (OUT/'attempt.json').write_text(json.dumps(initial,indent=2)+'\n')
    try:
        before,r=discover(t,True,commands)
        app=app_path();exe=executable(app);libs=framework(app)
        exe.parent.mkdir(parents=True);libs.mkdir(parents=True)
        (app/'Contents/Info.plist').write_bytes(plistlib.dumps(PLIST,sort_keys=True))
        original_graph=r['library_graph']
        require({Path(p).name for p in original_graph['nodes']}==PACKAGE_NAMES and
                len(original_graph['nodes'])==len(PACKAGE_NAMES),'backend reachable set changed; inspect before packaging')
        mapping={p:libs/Path(p).name for p in original_graph['nodes']}
        copied={}
        for original,destination in mapping.items():
            shutil.copy2(original,destination)
            require(base.sha(destination)==r['outputs'][original],'copy differs from fixed backend')
            copied[destination.name]={'source':original,'before_transform_sha256':base.sha(destination)}
        plans=install_plan(original_graph,mapping,t)
        for name,args in plans.items():command(args,'install-name-'+name,commands)
        flags=source_flags(r,t)
        for kind,source,output in [('cpp',HERE/'probe.cpp',OUT/'probe.o'),('objc',HERE/'cocoa_registry.mm',OUT/'registry.o')]:
            command([t['clang++'],*flags[kind],'-c',source,'-o',output],'compile-'+kind,commands)
        command([t['clang++'],'-arch','arm64','-isysroot',t['sdk'],'--ld-path='+t['ld'],
                 OUT/'probe.o',OUT/'registry.o',libs/'d3d11.dylib',libs/'winemetal.dylib',
                 '-framework','Cocoa','-framework','Metal','-framework','QuartzCore',
                 '-Wl,-rpath,@executable_path/../Frameworks','-o',exe],'link',commands)
        # Sign innermost code first; no entitlements or hardened-runtime bypass.
        for name in sorted(PACKAGE_NAMES):
            command([t['codesign'],'--force','--sign','-','--timestamp=none',libs/name],'sign-'+name,commands)
        command([t['codesign'],'--force','--sign','-','--timestamp=none',app],'sign-app',commands)
        command([t['codesign'],'--verify','--deep','--strict','--verbose=2',app],'verify-signature',commands)
        graph=package_graph(app)
        relocation=relocation_path();relocation.parent.mkdir(parents=True)
        shutil.copytree(app,relocation)
        require(tree(app)==tree(relocation),'relocation changed App bytes/modes')
        moved_graph=package_graph(relocation)
        require(normalize_graph(graph,app)==normalize_graph(moved_graph,relocation),'relocated static load graph changed')
        command([t['codesign'],'--verify','--deep','--strict','--verbose=2',relocation],'verify-relocated-signature',commands)
        after,again=discover(t)
        require(before==after and r==again,'packaging modified inputs or backend')
        artifacts=[OUT/'probe.o',OUT/'registry.o',*[Path(c['path']) for c in commands]]
        record={'schema':1,'status':STATUS,'scope':SCOPE,'tools':t,'inputs_before':before,'inputs_after':after,
                'backend_evidence_sha256':base.sha(backend.OUT/'evidence.json'),'backend_profile':r['profile'],
                'backend_output_count':len(r['outputs']),'reachable_library_count':len(mapping),
                'copied_libraries':copied,'install_name_plan':plans,'commands':commands,
                'app':str(app),'app_tree':tree(app),'library_graph':graph,
                'relocation':str(relocation),'relocation_tree':tree(relocation),'relocation_graph':moved_graph,
                'normalized_graph':normalize_graph(graph,app),'artifacts':base.hashes(artifacts),
                'signature':'ad-hoc local development signature; not Developer ID or notarization',
                'runtime_relocation_verified':False,'cocoa_initialization_issue_fixed':False,
                'identity_scope':'fixed backend + actual C/C++ headers/tools + bundle bytes/modes/signature and static load graph; no dynamic load claim'}
        (OUT/'evidence.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
        return verify()
    except Exception as error:
        (OUT/'attempt.json').write_text(json.dumps({**initial,'status':'FAIL_NOT_EXECUTION_ACCEPTANCE','error':repr(error)},indent=2)+'\n')
        raise


def verify():
    r=base.read_json(OUT/'evidence.json')
    require(r['schema']==1 and r['status']==STATUS and r['scope']==SCOPE and
            all(type(v) is int for v in r['scope'].values()),'static App record claims execution')
    t=tools();require(t==r['tools'],'selected packaging tools differ')
    current,backend_record=discover(t)
    require(current==r['inputs_before']==r['inputs_after'],'App input dependency set changed')
    require(r['backend_evidence_sha256']==base.sha(backend.OUT/'evidence.json') and
            r['backend_profile']==backend_record['profile'],'backend identity mismatch')
    require(r['backend_output_count']==len(backend_record['outputs']) and r['reachable_library_count']==3,'library counts differ')
    app=app_path();moved=relocation_path()
    require(r['app']==str(app) and r['relocation']==str(moved),'unexpected App path')
    require(tree(app)==r['app_tree']==r['relocation_tree']==tree(moved),'App bytes/modes changed')
    graph=package_graph(app);moved_graph=package_graph(moved)
    require(graph==r['library_graph'] and moved_graph==r['relocation_graph'] and
            normalize_graph(graph,app)==r['normalized_graph']==normalize_graph(moved_graph,moved),'bundle graph differs')
    mapping={p:framework(app)/Path(p).name for p in backend_record['library_graph']['nodes']}
    require(r['install_name_plan']==install_plan(backend_record['library_graph'],mapping,t),'transform plan changed')
    expected_copy={Path(p).name:{'source':p,'before_transform_sha256':backend_record['outputs'][p]} for p in mapping}
    require(r['copied_libraries']==expected_copy,'copy provenance changed')
    expected_names={'dependencies-cpp','dependencies-objc','compile-cpp','compile-objc','link','sign-app',
                    'verify-signature','verify-relocated-signature'}
    expected_names|={'install-name-'+n for n in PACKAGE_NAMES}|{'sign-'+n for n in PACKAGE_NAMES}
    require(len(r['commands'])==len(expected_names) and {c['name'] for c in r['commands']}==expected_names,'command chain omitted/duplicated')
    artifacts=[OUT/'probe.o',OUT/'registry.o',*[OUT/(name+'.json') for name in expected_names]]
    require(r['artifacts']==base.hashes(artifacts),'static artifacts changed or omitted')
    for c in r['commands']:
        path=OUT/(c['name']+'.json');detail=base.read_json(path)
        require(c=={'name':c['name'],'path':str(path),'sha256':base.sha(path),'returncode':0}
                and type(detail['returncode']) is int and detail['returncode']==0,'command result invalid')
        if c['name'].startswith('install-name-'):
            require(detail['command']==r['install_name_plan'][c['name'][len('install-name-'):]],'install-name command differs')
    for path in (app,moved):
        p=subprocess.run([t['codesign'],'--verify','--deep','--strict',str(path)],env=environment(OUT),capture_output=True,text=True)
        require(p.returncode==0,'actual code signature verification failed: '+p.stderr)
    require(r['runtime_relocation_verified'] is False and r['cocoa_initialization_issue_fixed'] is False,'unexecuted runtime claim')
    return {'status':'SELF_CONTAINED_APP_CURRENT_NOT_EXECUTED','evidence_sha256':base.sha(OUT/'evidence.json'),
            'app':str(app),'reachable_libraries':3,'backend_dylib_outputs':len(backend_record['outputs']),
            'relocated_graph_verified':True,'ad_hoc_signature_verified':True,'scope':SCOPE,
            'runtime_relocation_verified':False,'cocoa_initialization_issue_fixed':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--verify-only',action='store_true');args=parser.parse_args()
    print(json.dumps(verify() if args.verify_only else build(),indent=2))
