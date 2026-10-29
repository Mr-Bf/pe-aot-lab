"""Build a native no-argument entry over frozen save/load PE objects; never run it."""
import argparse
import json
from pathlib import Path
import shutil

from window_bridge import save_load_bindings_v1 as baseline
from window_bridge import pixel_observer_build as object_tools
from graphics_stage5 import d3d11_probe as g

ROOT,HERE=baseline.ROOT,baseline.HERE
SOURCE=ROOT/'build/window-bridge/save-load-program-v1-01'
SOURCE_SHA='7384ae558ceb05fb6761219a629f04c14138bdade45ad7a83deb02f42d0f4391'
PE_SHA='0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976'
EXE_SHA='9a404deef5f0ae807d12ded1d28915f6eea5c31f4935b808dff1da1f743b2609'
HOST_SHA='b83c847bf33e98fefab70d8c01ce7db64b2eb846024a40b1ccda2f8f450c1c38'
OUT=ROOT/'build/window-bridge/noarg-program-v1-04'
STATUS='BUILT_NO_ARGUMENT_SAVE_LOAD_APP_ENTRY_NOT_EXECUTED'
SCOPE=dict.fromkeys(('app_launches','guest_executions','window_executions','gpu_executions','library_loads'),0)
PROFILE='noarg-entry-v1; Foundation ApplicationSupport; private dirs; guest-session flock; frozen host main renamed only'

def require(x,m):
    if not x:raise ValueError(m)
def write(path,value):
    with Path(path).open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
def output(path):
    p=Path(path).absolute()
    require(p==p.resolve() and p.parent==ROOT/'build/window-bridge' and p.name.startswith('noarg-program-v1-'),'new noarg-program-v1-* required')
    return p

def source_program():
    require(g.sha(SOURCE/'program-build.json')==SOURCE_SHA and g.sha(HERE/'window_host.c')==HOST_SHA,'frozen source identity differs')
    p=baseline.Program.from_build(SOURCE)
    require(p.optimization=='O3' and p.source_sha256==PE_SHA and p.executable_sha256==EXE_SHA,'fixed original PE/program required')
    return p

def reused_objects(p):
    return {'runtime.o':p.out/'window_runtime__runtime.c.o','native-backend.o':p.out/'native_backend.cpp.o',
        'window-backend.o':p.out/'native_backend_window.cpp.o','cocoa.o':p.out/'cocoa_host.mm.o',
        'main.o':Path(p.roots[0]['directory'])/'arm64.o','wndproc.o':Path(p.roots[1]['directory'])/'arm64.o','ret.o':p.out/'ret-shim/arm64.o'}

def units(p):
    flags={n:(compiler,list(f)) for n,compiler,f in p.compilation_units()}
    c,cf=flags['window_host.c'];cpp,cppf=flags['cocoa_host.mm']
    return [('host-renamed',HERE/'window_host.c',c,[*cf,'-Dmain=aot_window_main']),
            ('entry',HERE/'noarg_entry_v1.mm',cpp,[*cppf,'-fno-objc-arc'])]

def execute(out,name,args):
    import subprocess
    args=list(map(str,args));path=out/'commands'/(name+'.json');path.parent.mkdir(exist_ok=True)
    require(not path.exists(),'preserve command log')
    r=subprocess.run(args,text=True,capture_output=True,env=g.environment(out))
    write(path,{'command':args,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
    require(r.returncode==0,'command failed: '+str(path));return r.stdout

def discover(out,p,writing=False):
    require(g.sha(HERE/'window_host.c')==HOST_SHA,'renamed host source differs')
    deps=[];graphs={}
    for name,src,compiler,flags in units(p):
        args=list(map(str,[compiler,*flags,'-M','-MT','probe',src]))
        text=execute(out,'deps-'+name,args) if writing else g.invoke(args,g.environment(out))
        actual=g.dependency_paths(text)
        generated=[x for x in actual if x.name in ('native_image.h','native_imports.h')]
        require(generated==([p.out/'native_image.h'] if name=='host-renamed' else []),'wrong generated host header')
        if name=='entry':require(HERE/'noarg_files_v1.h' in actual,'private-file helper missing')
        path=out/(name+'.d')
        if writing:path.write_text(text)
        else:require(path.read_text()==text,'dependency output changed')
        deps += [*actual,path];graphs[name]=text
    paths=[*p.build_manifest['native_inputs'],*p.build_manifest['artifacts'],SOURCE/'program-build.json',
           *baseline.python_closure([Path(__file__)]),*deps]
    return g.hashes(paths),graphs

def link_plan(out,p):
    libs=p.build_manifest['library_graph']['nodes']
    return list(map(str,[p.tools['clang++'],'-arch','arm64','-isysroot',p.tools['sdk'],'--ld-path='+p.tools['ld'],
        *[out/'reused'/n for n in reused_objects(p)],out/'host-renamed.o',out/'entry.o',p.build_manifest['library'],
        next(n for n in libs if Path(n).name=='winemetal.dylib'),'-framework','Cocoa','-framework','Metal','-framework','QuartzCore',
        *['-Wl,-rpath,'+n for n in sorted({str(Path(n).parent) for n in libs})],'-o',out/'linked-native']))

def plans(out,p):
    result=[('deps-'+n,list(map(str,[c,*f,'-M','-MT','probe',s]))) for n,s,c,f in units(p)]
    for n,s,c,f in units(p):
        result += [('compile-'+n,list(map(str,[c,*f,'-c',s,'-o',out/(n+'.o')]))),('exports-'+n,[p.tools['nm'],'-gU',str(out/(n+'.o'))])]
    return result+[('link',link_plan(out,p)),('sign',[p.tools['codesign'],'--force','--sign','-','--identifier','org.peaotlab.IntegerTileV3',str(out/'linked-native')]),('signature',[p.tools['codesign'],'--verify','--strict',str(out/'linked-native')])]

def exports(name):
    if name=='host-renamed':return {'_aot_window_main'}
    return {'_main','_OBJC_CLASS_$_NADelegate','_OBJC_METACLASS_$_NADelegate',
            *('_OBJC_IVAR_$_NADelegate.'+x for x in ('active_ever','active_notifications','close_requests',
                'guest_window_class','key_ever','key_notifications','terminate_requests')),
            '__OBJC_LABEL_PROTOCOL_$_NSApplicationDelegate','__OBJC_LABEL_PROTOCOL_$_NSObject',
            '__OBJC_PROTOCOL_$_NSApplicationDelegate','__OBJC_PROTOCOL_$_NSObject'}

def artifacts(out,p,exe):
    return [out/'started.json',out/'linked-native',exe,*[out/'reused'/n for n in reused_objects(p)],
            *[out/(n+s) for n,_,_,_ in units(p) for s in ('.o','.d')],*[out/'commands'/(n+'.json') for n,_ in plans(out,p)]]

def start_record():
    return {'schema':1,'status':'BUILD_STARTED_NOT_EXECUTED','source_program':str(SOURCE),'source_program_sha256':SOURCE_SHA,
            'producer_sha256':g.sha(__file__),'entry_sha256':g.sha(HERE/'noarg_entry_v1.mm'),'files_helper_sha256':g.sha(HERE/'noarg_files_v1.h'),'frozen_host_sha256':HOST_SHA,'scope':SCOPE}

class Program:
    def __init__(self,out_dir=OUT):
        self.out=output(out_dir);require(not self.out.exists(),'preserve prior build output');self.out.mkdir(parents=True)
        write(self.out/'started.json',start_record())
        try:
            self.original=p=source_program();before,graphs=discover(self.out,p,True)
            (self.out/'reused').mkdir()
            for n,src in reused_objects(p).items():
                shutil.copy2(src,self.out/'reused'/n);require(g.sha(src)==g.sha(self.out/'reused'/n),'copy changed object')
            for n,s,c,f in units(p):
                execute(self.out,'compile-'+n,[c,*f,'-c',s,'-o',self.out/(n+'.o')]);object_tools.arm_object(self.out/(n+'.o'))
                actual=execute(self.out,'exports-'+n,[p.tools['nm'],'-gU',self.out/(n+'.o')])
                require(object_tools.symbols(actual)==exports(n),'entry/renamed-host exports differ')
            linked=g.hashes([*[self.out/'reused'/n for n in reused_objects(p)],self.out/'host-renamed.o',self.out/'entry.o'])
            for name,args in plans(self.out,p)[-3:]:execute(self.out,name,args)
            self.executable_sha256=g.sha(self.out/'linked-native');self.executable=self.out/('noarg-'+self.executable_sha256)
            shutil.copy2(self.out/'linked-native',self.executable)
            graph=g.library_graph(self.executable,self.executable)
            require(set(graph['nodes'])=={str(self.executable),*p.build_manifest['library_graph']['nodes']},'native library graph differs')
            after,after_graphs=discover(self.out,p);p.verify_build();g.same(linked)
            require(before==after and graphs==after_graphs,'build inputs changed')
            self.build_manifest={'schema':1,'status':STATUS,'scope':SCOPE,'profile':PROFILE,
                'source_program':str(SOURCE),'source_program_sha256':SOURCE_SHA,'input_sha256':PE_SHA,
                'native_executable':str(self.executable),'native_sha256':self.executable_sha256,'tools':p.tools,
                'inputs_before':before,'inputs_after':after,'dependency_graphs':graphs,
                'reused_objects':{n:{'source':str(s),'sha256':g.sha(s)} for n,s in reused_objects(p).items()},
                'link_inputs':linked,'library_graph':graph,'commands':[{'name':n,'path':str(self.out/'commands'/(n+'.json')),'sha256':g.sha(self.out/'commands'/(n+'.json'))} for n,_ in plans(self.out,p)],
                'artifacts':g.hashes(artifacts(self.out,p,self.executable)),'no_argument_launch_verified':False,'physical_input_verified':False}
            write(self.out/'program-build.json',self.build_manifest);self.verify_build()
        except Exception as e:
            write(self.out/'first-build-failure.json',{'status':'FAIL_BUILD_NOT_EXECUTED','error':repr(e),'scope':SCOPE});raise
    @classmethod
    def from_build(cls,out_dir=OUT):
        self=cls.__new__(cls);self.out=output(out_dir);self.original=source_program();self.build_manifest=g.read_json(self.out/'program-build.json')
        self.executable=Path(self.build_manifest['native_executable']);self.executable_sha256=self.build_manifest['native_sha256'];self.verify_build();return self
    def verify_build(self):
        r=g.read_json(self.out/'program-build.json');p=self.original
        require(set(r)=={'schema','status','scope','profile','source_program','source_program_sha256','input_sha256','native_executable','native_sha256','tools','inputs_before','inputs_after','dependency_graphs','reused_objects','link_inputs','library_graph','commands','artifacts','no_argument_launch_verified','physical_input_verified'},'manifest field closure')
        require(r==self.build_manifest and type(r['schema']) is int and r['schema']==1 and r['status']==STATUS and r['scope']==SCOPE and all(type(v)is int for v in r['scope'].values()) and r['profile']==PROFILE,'build claim differs')
        require(r['source_program']==str(SOURCE) and r['source_program_sha256']==SOURCE_SHA and r['input_sha256']==PE_SHA,'source PE identity')
        require(g.read_json(self.out/'started.json')==start_record(),'start identity')
        p.verify_build();current,graphs=discover(self.out,p)
        require(r['inputs_before']==r['inputs_after']==current and r['dependency_graphs']==graphs and r['tools']==p.tools,'source/tool/header closure')
        expected={n:{'source':str(s),'sha256':g.sha(s)} for n,s in reused_objects(p).items()}
        require(expected==r['reused_objects'] and all(g.sha(self.out/'reused'/n)==v['sha256'] for n,v in expected.items()),'reused object set')
        require(r['link_inputs']==g.hashes([*[self.out/'reused'/n for n in reused_objects(p)],self.out/'host-renamed.o',self.out/'entry.o']),'link input set')
        require(self.executable==self.out/('noarg-'+self.executable_sha256) and g.sha(self.executable)==self.executable_sha256==g.sha(self.out/'linked-native'),'immutable executable')
        require(r['artifacts']==g.hashes(artifacts(self.out,p,self.executable)),'artifact closure')
        commands=[]
        for n,args in plans(self.out,p):
            path=self.out/'commands'/(n+'.json');detail=g.read_json(path)
            require(set(detail)=={'command','returncode','stdout','stderr'} and detail['command']==args and type(detail['returncode'])is int and detail['returncode']==0,'command evidence')
            commands.append({'name':n,'path':str(path),'sha256':g.sha(path)})
        require(r['commands']==commands,'command set')
        for n,_,_,_ in units(p):
            object_tools.arm_object(self.out/(n+'.o'));actual=g.invoke([p.tools['nm'],'-gU',self.out/(n+'.o')],g.environment(self.out))
            require(object_tools.symbols(actual)==exports(n),'actual exports')
        graph=g.library_graph(self.executable,self.executable)
        require(graph==r['library_graph'] and set(graph['nodes'])=={str(self.executable),*p.build_manifest['library_graph']['nodes']},'actual dylib graph')
        g.invoke([p.tools['codesign'],'--verify','--strict',self.executable],g.environment(self.out))
        require(r['no_argument_launch_verified'] is False and r['physical_input_verified'] is False,'build-only claim')
        return r

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--build',action='store_true');args=parser.parse_args()
    p=Program(args.out) if args.build else Program.from_build(args.out)
    print(json.dumps({'status':STATUS,'receipt_sha256':g.sha(p.out/'program-build.json'),'executable':str(p.executable),'executable_sha256':p.executable_sha256,'scope':SCOPE},indent=2))
