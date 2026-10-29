#!/usr/bin/env python3
"""Build-only long TEST_QUEUE host over fixed original save/load PE objects.

No build/verify path loads DXMT, creates windows or executes the guest. A separate
supervisor must launch and judge observations. Ten-second smoke is never a
thirty-minute result. Native clock/resource fields are measurements, not FPS.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from window_bridge import save_load_bindings_v1 as baseline
from window_bridge import long_host_recipe_v1 as recipe
from window_bridge import pixel_observer_build as object_tools
from graphics_stage5 import d3d11_probe as g

SOURCE=ROOT/'build/window-bridge/save-load-program-v1-01'
SOURCE_SHA='7384ae558ceb05fb6761219a629f04c14138bdade45ad7a83deb02f42d0f4391'
PE_SHA='0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976'
EXE_SHA='9a404deef5f0ae807d12ded1d28915f6eea5c31f4935b808dff1da1f743b2609'
OUT=ROOT/'build/window-bridge/long-program-v1-03'
STATUS='BUILT_LONG_TEST_QUEUE_SAVE_LOAD_PE_NOT_EXECUTED'
SCOPE=dict.fromkeys(('guest_executions','window_executions','gpu_executions','library_loads','long_duration_runs','smoke_runs'),0)


def require(value,message):
    if not value:raise ValueError(message)


def write(path,data):
    with Path(path).open('x') as stream:json.dump(data,stream,indent=2,sort_keys=True);stream.write('\n')


def output(path):
    p=Path(path).absolute();parent=ROOT/'build/window-bridge'
    require(p==p.resolve() and p.parent==parent and p.name.startswith('long-'),'fresh direct long-* directory required')
    return p


def source_program():
    require(g.sha(SOURCE/'program-build.json')==SOURCE_SHA,'frozen source receipt differs')
    p=baseline.Program.from_build(SOURCE)
    require(p.optimization=='O3' and p.source_sha256==PE_SHA and p.executable_sha256==EXE_SHA,'source PE/executable differs')
    return p


def source_objects(p):
    return {'runtime.o':p.out/'window_runtime__runtime.c.o','native-backend.o':p.out/'native_backend.cpp.o',
            'window-backend.o':p.out/'native_backend_window.cpp.o','cocoa.o':p.out/'cocoa_host.mm.o',
            'main.o':Path(p.roots[0]['directory'])/'arm64.o','wndproc.o':Path(p.roots[1]['directory'])/'arm64.o',
            'ret.o':p.out/'ret-shim/arm64.o'}


def host_unit(p):
    compiler,flags={n:(c,f) for n,c,f in p.compilation_units()}['window_host.c']
    return HERE/'window_host_long_v1.c',compiler,flags


def command(out,name,args):
    args=list(map(str,args));path=out/'commands'/(name+'.json');path.parent.mkdir(exist_ok=True)
    require(not path.exists(),'command evidence exists')
    run=subprocess.run(args,capture_output=True,text=True,env=g.environment(out))
    write(path,{'command':args,'returncode':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
    require(run.returncode==0,'static command failed: '+str(path));return run.stdout


def discover(out,p,writing=False):
    source,compiler,flags=host_unit(p)
    require(source.read_text()==recipe.expected_host(),'controller host differs from exact transformation')
    args=[compiler,*flags,'-M','-MT','probe',source]
    graph=command(out,'deps-host',args) if writing else g.invoke(args,g.environment(out))
    dep_path=out/'host.d'
    if writing:dep_path.write_text(graph)
    else:require(dep_path.read_text()==graph,'actual native header graph differs')
    deps=g.dependency_paths(graph)
    require(p.out/'native_image.h' in deps,'actual host omits source PE header')
    require(HERE/'long_controller_v1.h' in deps,'actual host omits controller header')
    old=p.build_manifest
    paths=[*old['native_inputs'],*old['artifacts'],SOURCE/'program-build.json',
           *baseline.python_closure([Path(__file__),HERE/'long_validation_v1.py']),*deps,dep_path]
    return g.hashes(paths),graph


def link_plan(out,p):
    libraries=p.build_manifest['library_graph']['nodes'];library=Path(p.build_manifest['library'])
    return list(map(str,[p.tools['clang++'],'-arch','arm64','-isysroot',p.tools['sdk'],'--ld-path='+p.tools['ld'],
        *[out/'reused'/n for n in source_objects(p)],out/'host.o',library,
        next(n for n in libraries if Path(n).name=='winemetal.dylib'),
        '-framework','Cocoa','-framework','Metal','-framework','QuartzCore',
        *['-Wl,-rpath,'+n for n in sorted({str(Path(x).parent) for x in libraries})],'-o',out/'linked-native']))


def plans(out,p):
    source,compiler,flags=host_unit(p)
    return [('deps-host',list(map(str,[compiler,*flags,'-M','-MT','probe',source]))),
            ('compile-host',list(map(str,[compiler,*flags,'-c',source,'-o',out/'host.o']))),
            ('exports-host',[p.tools['nm'],'-gU',str(out/'host.o')]),('link',link_plan(out,p)),
            ('sign',[p.tools['codesign'],'--force','--sign','-','--identifier','org.peaotlab.window.longv1',str(out/'linked-native')]),
            ('signature',[p.tools['codesign'],'--verify','--strict',str(out/'linked-native')])]


def artifact_paths(out,p,exe):
    return [out/'started.json',out/'linked-native',exe,*[out/'reused'/n for n in source_objects(p)],out/'host.o',out/'host.d',
            *[out/'commands'/(n+'.json') for n,_ in plans(out,p)]]


def start_record():
    return {'schema':1,'status':'BUILD_STARTED_NOT_EXECUTED','scope':SCOPE,
        'producer_sha256':g.sha(__file__),'derived_host_sha256':g.sha(HERE/'window_host_long_v1.c'),
        'controller_sha256':g.sha(HERE/'long_controller_v1.h'),'source_program':str(SOURCE),'source_program_sha256':SOURCE_SHA}


class Program:
    def __init__(self,out_dir=OUT):
        self.out=output(out_dir);require(not self.out.exists(),'preserve attempted output; choose new long-* directory')
        self.out.mkdir(parents=True);write(self.out/'started.json',start_record())
        try:
            self.original=source_program();p=self.original;before,graph=discover(self.out,p,True)
            (self.out/'reused').mkdir();reused={}
            for name,source in source_objects(p).items():
                destination=self.out/'reused'/name;shutil.copy2(source,destination)
                require(g.sha(source)==g.sha(destination),'reused object copy differs')
                reused[name]={'source':str(source),'sha256':g.sha(source)}
            for name,args in plans(self.out,p)[1:3]:command(self.out,name,args)
            object_tools.arm_object(self.out/'host.o')
            require(object_tools.symbols(g.read_json(self.out/'commands/exports-host.json')['stdout'])=={'_main'},'host exports differ')
            link_inputs=g.hashes([*[self.out/'reused'/n for n in source_objects(p)],self.out/'host.o'])
            for name,args in plans(self.out,p)[3:]:command(self.out,name,args)
            self.executable_sha256=g.sha(self.out/'linked-native');self.executable=self.out/('long-'+self.executable_sha256)
            shutil.copy2(self.out/'linked-native',self.executable)
            libraries=g.library_graph(self.executable,self.executable)
            require(set(libraries['nodes'])=={str(self.executable),*p.build_manifest['library_graph']['nodes']},'actual native library graph differs')
            after,graph_after=discover(self.out,p);p.verify_build();g.same(link_inputs)
            require(before==after and graph==graph_after,'build inputs changed')
            self.build_manifest={'schema':1,'status':STATUS,'scope':SCOPE,'source_program':str(SOURCE),'source_program_sha256':SOURCE_SHA,
                'input_sha256':PE_SHA,'native_executable':str(self.executable),'native_sha256':self.executable_sha256,
                'tools':p.tools,'inputs_before':before,'inputs_after':after,'dependency_graph':graph,
                'reused_objects':reused,'link_inputs':link_inputs,'library_graph':libraries,
                'commands':[{'name':n,'path':str(self.out/'commands'/(n+'.json')),'sha256':g.sha(self.out/'commands'/(n+'.json'))} for n,_ in plans(self.out,p)],
                'artifacts':g.hashes(artifact_paths(self.out,p,self.executable)),
                'controller_profile':'bounded-duration-controller-v1','physical_input':False,'duration_accepted':False,'performance_accepted':False}
            write(self.out/'program-build.json',self.build_manifest);self.verify_build()
        except Exception as error:
            write(self.out/'first-build-failure.json',{'status':'FAIL_BUILD_NOT_EXECUTED','error':repr(error),'scope':SCOPE});raise

    @classmethod
    def from_build(cls,out_dir=OUT):
        self=cls.__new__(cls);self.out=output(out_dir);self.original=source_program()
        self.build_manifest=g.read_json(self.out/'program-build.json');self.executable=Path(self.build_manifest['native_executable'])
        self.executable_sha256=self.build_manifest['native_sha256'];self.verify_build();return self

    def verify_build(self):
        r=g.read_json(self.out/'program-build.json');p=self.original
        require(r==self.build_manifest and r['schema']==1 and r['status']==STATUS and r['scope']==SCOPE and all(type(v) is int for v in r['scope'].values()),'build scope/status differs')
        require(r['source_program']==str(SOURCE) and r['source_program_sha256']==SOURCE_SHA and r['input_sha256']==PE_SHA,'source identity differs')
        p.verify_build();current,graph=discover(self.out,p)
        require(r['inputs_before']==r['inputs_after']==current and r['dependency_graph']==graph and r['tools']==p.tools,'source/header/tool closure differs')
        require(g.read_json(self.out/'started.json')==start_record(),'immutable start differs')
        reused={n:{'source':str(src),'sha256':g.sha(src)} for n,src in source_objects(p).items()}
        require(r['reused_objects']==reused,'reused object set differs')
        for name,item in reused.items():require(g.sha(self.out/'reused'/name)==item['sha256'],'copied object differs')
        require(r['link_inputs']==g.hashes([*[self.out/'reused'/n for n in source_objects(p)],self.out/'host.o']),'link inputs differ')
        require(self.executable==self.out/('long-'+self.executable_sha256) and g.sha(self.executable)==self.executable_sha256==g.sha(self.out/'linked-native'),'immutable executable differs')
        require(r['artifacts']==g.hashes(artifact_paths(self.out,p,self.executable)),'artifact closure differs')
        expected_commands=[]
        for name,args in plans(self.out,p):
            path=self.out/'commands'/(name+'.json');detail=g.read_json(path)
            require(detail['command']==args and type(detail['returncode']) is int and detail['returncode']==0 and set(detail)=={'command','returncode','stdout','stderr'},'actual command evidence differs')
            expected_commands.append({'name':name,'path':str(path),'sha256':g.sha(path)})
        require(r['commands']==expected_commands,'required commands differ')
        object_tools.arm_object(self.out/'host.o')
        require(object_tools.symbols(g.invoke([p.tools['nm'],'-gU',self.out/'host.o'],g.environment(self.out)))=={'_main'},'host exports differ')
        graph=g.library_graph(self.executable,self.executable)
        require(graph==r['library_graph'] and set(graph['nodes'])=={str(self.executable),*p.build_manifest['library_graph']['nodes']},'actual library graph differs')
        g.invoke([p.tools['codesign'],'--verify','--strict',self.executable],g.environment(self.out))
        require(r['controller_profile']=='bounded-duration-controller-v1' and all(r[k] is False for k in ('physical_input','duration_accepted','performance_accepted')),'build-only scope differs')
        from window_bridge.long_validation_v1 import verify_common_source
        verify_common_source();return r

    def validate_execution(self,result,returncode,base=None,budget=None):
        from window_bridge.long_validation_v1 import validate_execution
        return validate_execution(self.original,result,returncode,base,budget)

    def command(self,*,io_directory,duration_ms=None,smoke=False,base=None,budget=100000000):
        require(type(smoke) is bool,'explicit boolean smoke required')
        if duration_ms is None:duration_ms=10000 if smoke else 1800000
        require(type(duration_ms) is int and (duration_ms==10000 if smoke else 1800000<=duration_ms<=2047000),'unsupported duration')
        require(type(budget) is int and 1<=budget<=100000000,'bounded guest budget required')
        directory=Path(io_directory).absolute()
        require(directory==directory.resolve() and directory.is_dir(),'existing real absolute trusted data directory required')
        args=[str(self.executable),'--data-dir',str(directory),'--smoke-duration-ms' if smoke else '--duration-ms',str(duration_ms),'--event-period-ms','250','--budget',str(budget)]
        if base is not None:
            require(type(base) is int and 0<=base<=0xffffffffffffffff,'invalid base');args+=['--base',str(base)]
        return args


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--build',action='store_true')
    args=parser.parse_args();p=Program(args.out) if args.build else Program.from_build(args.out)
    print(json.dumps({'status':STATUS,'receipt_sha256':g.sha(p.out/'program-build.json'),'executable':str(p.executable),
        'executable_sha256':p.executable_sha256,'inputs':len(p.build_manifest['inputs_before']),'artifacts':len(p.build_manifest['artifacts']),'scope':SCOPE}))

if __name__=='__main__':main()
