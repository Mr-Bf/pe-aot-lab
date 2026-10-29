#!/usr/bin/env python3
"""Fixed new skip-Draw PE with native pixel observation; build is not a run.

No admission rule in the frozen normal/pixel Program is changed. This profile
accepts exactly its source-derived negative PE and its own generated metadata.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from window_bridge import prepare_skip_draw_v1 as negative
from window_bridge import pixel_bindings_v1 as pixel
from window_bridge import window_bindings as baseline
from window_bridge import loader
from graphics_stage5 import d3d11_probe as g

OUT=ROOT/'build/window-bridge/pixel-negative-v1-01'
NEGATIVE_SHA='5e01e0351cd336217388f61f752bd2e44991aa4d263b07992d3b2434654d0ad0'
PREPARED_SHA='ba2698d794e9adc302692264b7a948959e8f41cf2baa1c10bc1fc67206ab4f69'
PIXEL_BUILD_SHA='066d10ee8b0a5bedab189ff930a02cb855fc3b0e51b6e43bb5cd5fed9f472c16'
STATUS='BUILT_FIXED_SKIP_DRAW_PIXEL_NEGATIVE_NOT_EXECUTED'
SCOPE=dict.fromkeys(('guest_executions','window_executions','gpu_executions','library_loads','pixel_frames'),0)


def require(value,message):
    if not value:raise ValueError(message)


def write(path,record):
    with Path(path).open('x') as stream:json.dump(record,stream,indent=2,sort_keys=True);stream.write('\n')


def output(path):
    path=Path(path).absolute()
    require(path==path.resolve() and path.parent==ROOT/'build/window-bridge' and path.name.startswith('pixel-negative-v1-'),
            'separate pixel-negative-v1-* output required')
    return path


def source_program():
    require(g.sha(negative.OUT/'evidence.json')==PREPARED_SHA,'negative preparation identity changed')
    proof=negative.verify()
    require(proof['negative_pe_sha256']==NEGATIVE_SHA,'only fixed skip-Draw negative PE is admitted')
    require(g.sha(pixel.OUT/'program-build.json')==PIXEL_BUILD_SHA,'frozen positive pixel build changed')
    return pixel.Program.from_build()


def reused_objects(source):
    return {'main.o':negative.OUT/'compiler/main/arm64.o',
            'wndproc.o':negative.OUT/'compiler/window-proc-1000/arm64.o',
            'ret.o':negative.OUT/'ret-shim/arm64.o',
            'native-backend.o':source.out/'reused/native-backend.o',
            'cocoa.o':source.out/'reused/cocoa.o',
            'window.o':source.out/'window.o',
            'observer.o':source.out/'observer.o'}


def units(out,source):
    # Replacing the include directory (not appending another one) is essential:
    # host and runtime must compile the new image and actual callsite tables.
    result=[]
    for name,compiler,flags in source.original.compilation_units():
        if name not in ('window_host.c','window_runtime/runtime.c'):continue
        require(flags.count(str(source.original.out))==1,'original generated-header include flag differs')
        flags=[str(out) if value==str(source.original.out) else value for value in flags]
        actual=HERE/('window_host_pixel_v1.c' if name=='window_host.c' else name)
        result.append(('host' if name=='window_host.c' else 'runtime',actual,compiler,flags))
    require(len(result)==2,'explicit two-C-unit recipe differs')
    return result


def command(out,name,args):
    args=list(map(str,args));path=out/'commands'/(name+'.json');path.parent.mkdir(exist_ok=True)
    require(not path.exists(),'command evidence exists')
    p=subprocess.run(args,capture_output=True,text=True,env=g.environment(out))
    write(path,{'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    require(p.returncode==0,'negative static command failed: '+str(path));return p.stdout


def discover(out,source,writing=False):
    require(g.sha(negative.OUT/'evidence.json')==PREPARED_SHA,'negative preparation changed')
    negative.verify();source.verify_build()
    require((HERE/'window_host_pixel_v1.c').read_text()==pixel.expected_host(),'frozen observer host transform differs')
    for name in ('native_image.h','native_imports.h'):
        require((out/name).read_bytes()==(negative.OUT/name).read_bytes(),'negative generated header was substituted')
    dependencies=[];graphs={}
    for name,path,compiler,flags in units(out,source):
        args=[compiler,*flags,'-M','-MT','probe',path]
        text=command(out,'deps-'+name,args) if writing else g.invoke(args,g.environment(out))
        graph=g.dependency_paths(text);graphs[name]=text
        required=out/('native_image.h' if name=='host' else 'native_imports.h')
        require(required in graph,'actual compiler did not consume the negative generated header')
        require(not {source.original.out/'native_image.h',source.original.out/'native_imports.h'} & set(graph),
                'normal generated header leaked into negative compilation')
        depfile=out/(name+'.d')
        if writing:depfile.write_text(text)
        else:require(depfile.read_text()==text,'actual compiler header graph changed')
        dependencies += [*graph,depfile]
    prep=g.read_json(negative.OUT/'evidence.json');r=source.build_manifest
    paths=[*r['inputs_before'],*r['artifacts'],source.out/'program-build.json',
           *prep['inputs_before'],*[negative.OUT/name for name in prep['artifacts']],negative.OUT/'evidence.json',
           *baseline.python_closure([Path(__file__)]),*dependencies]
    return g.hashes(paths),graphs


def expected_exports(name,source):
    if name=='host':return {'_main'}
    return pixel.observer.symbols(g.invoke([source.original.tools['nm'],'-gU',source.original.out/'window_runtime__runtime.c.o'],g.environment(source.out)))


def link_plan(out,source):
    p=source.original;libraries=p.build_manifest['library_graph']['nodes']
    return list(map(str,[p.tools['clang++'],'-arch','arm64','-isysroot',p.tools['sdk'],'--ld-path='+p.tools['ld'],
        *[out/'reused'/name for name in reused_objects(source)],*[out/(name+'.o') for name,_,_,_ in units(out,source)],
        p.build_manifest['library'],next(n for n in libraries if Path(n).name=='winemetal.dylib'),
        '-framework','Cocoa','-framework','Metal','-framework','QuartzCore',
        *['-Wl,-rpath,'+n for n in sorted({str(Path(x).parent) for x in libraries})],'-o',out/'linked-negative']))


def plans(out,source):
    result=[]
    for name,path,compiler,flags in units(out,source):result.append(('deps-'+name,list(map(str,[compiler,*flags,'-M','-MT','probe',path]))))
    for name,path,compiler,flags in units(out,source):
        result += [('compile-'+name,list(map(str,[compiler,*flags,'-c',path,'-o',out/(name+'.o')]))),
                   ('exports-'+name,[source.original.tools['nm'],'-gU',str(out/(name+'.o'))])]
    return result+[('link',link_plan(out,source)),
        ('sign',[source.original.tools['codesign'],'--force','--sign','-','--identifier','org.peaotlab.window.skipdrawv1',str(out/'linked-negative')]),
        ('signature',[source.original.tools['codesign'],'--verify','--strict',str(out/'linked-negative')])]


def artifacts(out,source,exe):
    return [out/'started.json',out/'native_image.h',out/'native_imports.h',out/'linked-negative',exe,
            *[out/'reused'/n for n in reused_objects(source)],*[out/(n+'.o') for n,_,_,_ in units(out,source)],
            *[out/(n+'.d') for n,_,_,_ in units(out,source)],*[out/'commands'/(n+'.json') for n,_ in plans(out,source)]]


class NegativeExecutionContract:
    """Read-only output schema reuse, not a normal Program build/admission."""
    def __init__(self):
        require(g.sha(negative.OUT/'integer-tile.exe')==NEGATIVE_SHA,'fixed negative PE changed')
        self.source_sha256=NEGATIVE_SHA;self.image=loader.load_image(negative.OUT/'integer-tile.exe')
        self.build_manifest={'observations':g.read_json(negative.OUT/'fixture-metadata.json')['observations']}
    def validate_execution(self,result,returncode,base=None,budget=None):
        return baseline.Program.validate_execution(self,result,returncode,base,budget)


class Program:
    validate_execution=pixel.Program.validate_execution
    validate_capture=pixel.Program.validate_capture

    def __init__(self,out_dir=OUT):
        self.out=output(out_dir);require(not self.out.exists(),'preserve attempted negative output');self.out.mkdir(parents=True)
        self.original=NegativeExecutionContract()
        write(self.out/'started.json',{'schema':1,'status':'NEGATIVE_BUILD_STARTED_NOT_EXECUTED','scope':SCOPE,
            'producer_sha256':g.sha(__file__),'prepared_sha256':PREPARED_SHA,'negative_pe_sha256':NEGATIVE_SHA,'pixel_source_build_sha256':PIXEL_BUILD_SHA})
        try:
            self.source=source_program()
            for name in ('native_image.h','native_imports.h'):shutil.copy2(negative.OUT/name,self.out/name)
            before,graphs=discover(self.out,self.source,True)
            (self.out/'reused').mkdir();reused={}
            for name,original in reused_objects(self.source).items():
                destination=self.out/'reused'/name;shutil.copy2(original,destination)
                require(g.sha(original)==g.sha(destination),'negative reused object copy differs')
                reused[name]={'source':str(original),'sha256':g.sha(original)}
            for name,path,compiler,flags in units(self.out,self.source):
                command(self.out,'compile-'+name,[compiler,*flags,'-c',path,'-o',self.out/(name+'.o')])
                pixel.observer.arm_object(self.out/(name+'.o'))
                exports=command(self.out,'exports-'+name,[self.source.original.tools['nm'],'-gU',self.out/(name+'.o')])
                require(pixel.observer.symbols(exports)==expected_exports(name,self.source),'negative host/runtime exports differ')
            link_inputs=g.hashes([*[self.out/'reused'/n for n in reused_objects(self.source)],*[self.out/(n+'.o') for n,_,_,_ in units(self.out,self.source)]])
            for name,args in plans(self.out,self.source)[-3:]:command(self.out,name,args)
            self.executable_sha256=g.sha(self.out/'linked-negative');self.executable=self.out/('negative-'+self.executable_sha256)
            shutil.copy2(self.out/'linked-negative',self.executable)
            graph=g.library_graph(self.executable,self.executable)
            require(set(graph['nodes'])=={str(self.executable),*self.source.original.build_manifest['library_graph']['nodes']},'negative actual library graph differs')
            after,graphs_after=discover(self.out,self.source)
            require(before==after and graphs==graphs_after,'negative build input changed');g.same(link_inputs)
            self.build_manifest={'schema':1,'status':STATUS,'scope':SCOPE,'negative_pe_sha256':NEGATIVE_SHA,
                'prepared_sha256':PREPARED_SHA,'pixel_source_build_sha256':PIXEL_BUILD_SHA,
                'native_executable':str(self.executable),'native_sha256':self.executable_sha256,
                'inputs_before':before,'inputs_after':after,'dependency_graphs':graphs,'tools':self.source.original.tools,
                'reused_objects':reused,'link_inputs':link_inputs,'library_graph':graph,
                'commands':[{'name':n,'path':str(self.out/'commands'/(n+'.json')),'sha256':g.sha(self.out/'commands'/(n+'.json'))} for n,_ in plans(self.out,self.source)],
                'artifacts':g.hashes(artifacts(self.out,self.source,self.executable)),
                'native_image_sha256':g.sha(self.out/'native_image.h'),'native_imports_sha256':g.sha(self.out/'native_imports.h'),
                'pixel_predicate_executed':False,'performance_sample':False,'normal_program_admission_modified':False}
            write(self.out/'program-build.json',self.build_manifest);self.verify_build()
        except Exception as error:
            failures=self.out/'failure-sources';failures.mkdir()
            (failures/Path(__file__).name).write_bytes(Path(__file__).read_bytes())
            write(self.out/'first-build-failure.json',{'status':'NEGATIVE_BUILD_FAILED_NOT_EXECUTED','error':repr(error),'scope':SCOPE});raise

    @classmethod
    def from_build(cls,out_dir=OUT):
        self=cls.__new__(cls);self.out=output(out_dir);self.source=source_program();self.original=NegativeExecutionContract()
        self.build_manifest=g.read_json(self.out/'program-build.json');self.executable=Path(self.build_manifest['native_executable']);self.executable_sha256=self.build_manifest['native_sha256']
        self.verify_build();return self

    def verify_build(self):
        r=g.read_json(self.out/'program-build.json');source=self.source
        require(r==self.build_manifest and type(r['schema']) is int and r['schema']==1 and r['status']==STATUS and
                r['scope']==SCOPE and all(type(n) is int for n in r['scope'].values()),'negative build status/scope differs')
        require(r['negative_pe_sha256']==NEGATIVE_SHA and r['prepared_sha256']==PREPARED_SHA and
                r['pixel_source_build_sha256']==PIXEL_BUILD_SHA,'fixed negative identity differs')
        current,graphs=discover(self.out,source)
        require(r['inputs_before']==r['inputs_after']==current and graphs==r['dependency_graphs'] and r['tools']==source.original.tools,'negative dependency closure changed')
        require(g.read_json(self.out/'started.json')=={'schema':1,'status':'NEGATIVE_BUILD_STARTED_NOT_EXECUTED','scope':SCOPE,
            'producer_sha256':g.sha(__file__),'prepared_sha256':PREPARED_SHA,'negative_pe_sha256':NEGATIVE_SHA,'pixel_source_build_sha256':PIXEL_BUILD_SHA},'immutable negative start differs')
        reused={name:{'source':str(path),'sha256':g.sha(path)} for name,path in reused_objects(source).items()}
        require(reused==r['reused_objects'],'negative reused object source set differs')
        for name,record in reused.items():require(g.sha(self.out/'reused'/name)==record['sha256'],'negative copied object differs')
        expected_link=g.hashes([*[self.out/'reused'/n for n in reused_objects(source)],*[self.out/(n+'.o') for n,_,_,_ in units(self.out,source)]])
        require(expected_link==r['link_inputs'],'negative actual link closure differs')
        require(self.executable==self.out/('negative-'+self.executable_sha256) and
                g.sha(self.executable)==self.executable_sha256==g.sha(self.out/'linked-negative'),'negative immutable executable differs')
        require(NEGATIVE_SHA.encode() in self.executable.read_bytes() and negative.ORIGINAL_PE_SHA.encode() not in self.executable.read_bytes(),
                'linked negative PE marker missing or positive marker leaked')
        require(r['artifacts']==g.hashes(artifacts(self.out,source,self.executable)),'negative exact artifacts differ')
        expected=[]
        for name,args in plans(self.out,source):
            path=self.out/'commands'/(name+'.json');detail=g.read_json(path)
            require(detail['command']==args and type(detail['returncode']) is int and detail['returncode']==0 and
                    set(detail)=={'command','returncode','stdout','stderr'},'negative static command differs')
            expected.append({'name':name,'path':str(path),'sha256':g.sha(path)})
        require(expected==r['commands'],'negative command chain incomplete')
        for name,_,_,_ in units(self.out,source):
            pixel.observer.arm_object(self.out/(name+'.o'))
            require(pixel.observer.symbols(g.invoke([source.original.tools['nm'],'-gU',self.out/(name+'.o')],g.environment(self.out)))==expected_exports(name,source),'actual negative symbol set differs')
        graph=g.library_graph(self.executable,self.executable)
        require(graph==r['library_graph'] and set(graph['nodes'])=={str(self.executable),*source.original.build_manifest['library_graph']['nodes']},'negative dependency graph differs')
        require(r['native_image_sha256']==g.sha(self.out/'native_image.h') and r['native_imports_sha256']==g.sha(self.out/'native_imports.h'),'negative image/callsite header binding differs')
        g.invoke([source.original.tools['codesign'],'--verify','--strict',self.executable],g.environment(self.out))
        require(r['pixel_predicate_executed'] is False and r['performance_sample'] is False and r['normal_program_admission_modified'] is False,'static negative claims execution/performance/gate changes')
        return r


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--verify-only',action='store_true');args=parser.parse_args()
    program=Program.from_build(args.out) if args.verify_only else Program(args.out)
    print(json.dumps({'status':program.build_manifest['status'],'program':str(program.out),'executable':str(program.executable),
        'sha256':program.executable_sha256,'inputs':len(program.build_manifest['inputs_before']),'scope':SCOPE},indent=2))
