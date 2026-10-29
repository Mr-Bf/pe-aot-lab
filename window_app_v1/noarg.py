"""Compile a configured App entry and relink the caller's actual AOT objects."""
import json
from pathlib import Path
import re
import shutil
import subprocess

from window_profile_v1 import bindings as b
from window_profile_v1.build import verify as verify_product
from window_bridge import pixel_observer_build as object_tools
from graphics_stage5 import d3d11_probe as g

ROOT=b.ROOT
HERE=Path(__file__).resolve().parent
STATUS='BUILT_CONFIGURED_NO_ARGUMENT_ENTRY_NOT_EXECUTED'


def require(ok,message):
    if not ok:raise ValueError(message)


def write(path,value):
    with Path(path).open('x') as stream:
        json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')


def spec(value):
    require(type(value) is dict and set(value)=={'identifier','name'},'App spec requires identifier and name')
    identifier,name=value['identifier'],value['name']
    require(type(identifier) is str and len(identifier)<=120 and
            re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*){2,}',identifier),
            'invalid reverse-domain App identifier')
    require(type(name) is str and 1<=len(name)<=80 and name.strip()==name and
            all(ord(c)>=32 and ord(c)!=127 for c in name),'invalid App display name')
    return dict(identifier=identifier,name=name)


def header(value):
    value=spec(value)
    return '/* Build configuration only; no guest state. */\nstatic NSString *const kApplication = @'+json.dumps(value['identifier'])+';\n'


def source(product):
    product=Path(product).resolve(strict=True);verify_product(product)
    program=b.Program.from_build(product/'native')
    require(program.optimization=='O3','configured App currently requires O3 window build')
    return program


def reused(p):
    result={'runtime.o':p.out/'window_runtime__runtime.c.o','native-backend.o':p.out/'native_backend.cpp.o',
            'window-backend.o':p.out/'native_backend_window.cpp.o','cocoa.o':p.out/'cocoa_host.mm.o',
            'ret.o':p.out/'ret-shim/arm64.o'}
    result.update({('root-%d.o'%index):Path(root['directory'])/'arm64.o' for index,root in enumerate(p.roots)})
    return result


def units(out,p):
    flags={n:(c,list(f)) for n,c,f in p.compilation_units()}
    c,cf=flags['window_host.c'];cpp,cppf=flags['cocoa_host.mm']
    return [('host',b.HERE/'window_host.c',c,[*cf,'-Dmain=aot_window_main']),
            ('entry',HERE/'entry.mm',cpp,[*cppf,'-I',str(out),'-I',str(b.HERE),'-fno-objc-arc'])]


def expected_exports(name):
    if name=='host':return {'_aot_window_main'}
    return {'_main','_OBJC_CLASS_$_NADelegate','_OBJC_METACLASS_$_NADelegate',
            *('_OBJC_IVAR_$_NADelegate.'+x for x in ('active_ever','active_notifications','close_requests',
                'guest_window_class','key_ever','key_notifications','terminate_requests')),
            '__OBJC_LABEL_PROTOCOL_$_NSApplicationDelegate','__OBJC_LABEL_PROTOCOL_$_NSObject',
            '__OBJC_PROTOCOL_$_NSApplicationDelegate','__OBJC_PROTOCOL_$_NSObject'}


def command(out,name,args):
    args=list(map(str,args));path=out/'commands'/(name+'.json');path.parent.mkdir(exist_ok=True)
    require(not path.exists(),'preserve command record')
    result=subprocess.run(args,capture_output=True,text=True,env=g.environment(out))
    write(path,dict(command=args,returncode=result.returncode,stdout=result.stdout,stderr=result.stderr))
    require(result.returncode==0,'command failed: '+str(path))
    return result.stdout


def plans(out,p,value):
    rows=[]
    for name,path,compiler,flags in units(out,p):
        rows += [('deps-'+name,[compiler,*flags,'-M','-MT','probe',path]),
                 ('compile-'+name,[compiler,*flags,'-c',path,'-o',out/(name+'.o')]),
                 ('exports-'+name,[p.tools['nm'],'-gU',out/(name+'.o')])]
    libs=p.build_manifest['library_graph']['nodes']
    rows += [('link',[p.tools['clang++'],'-arch','arm64','-isysroot',p.tools['sdk'],'--ld-path='+p.tools['ld'],
                      *[out/'reused'/name for name in reused(p)],out/'host.o',out/'entry.o',p.build_manifest['library'],
                      next(n for n in libs if Path(n).name=='winemetal.dylib'),'-framework','Cocoa','-framework','Metal','-framework','QuartzCore',
                      *['-Wl,-rpath,'+n for n in sorted({str(Path(n).parent) for n in libs})],'-o',out/'linked-native']),
             ('sign',[p.tools['codesign'],'--force','--sign','-','--identifier',value['identifier'],out/'linked-native']),
             ('signature',[p.tools['codesign'],'--verify','--strict',out/'linked-native'])]
    return [(name,list(map(str,args))) for name,args in rows]


def input_closure(out,p,product,graphs):
    require(set(graphs)=={'host','entry'},'entry dependency graph closure differs')
    deps=[]
    for name,text in graphs.items():
        actual=g.dependency_paths(text)
        if name=='host':require([x for x in actual if x.name=='native_image.h']==[p.out/'native_image.h'],'wrong PE image header')
        if name=='entry':
            require([x for x in actual if x.name=='app_config.h']==[out/'app_config.h'],'wrong App configuration header')
            require(b.HERE/'noarg_files_v1.h' in actual,'private filesystem helper absent')
        deps.extend(actual)
    paths=[*p.build_manifest['native_inputs'],*p.build_manifest['artifacts'],p.out/'program-build.json',
           product/'result.json',product/'profile.json',out/'app-spec.json',out/'app_config.h',
           *b.python_closure([Path(__file__)]),HERE/'entry-derivation.json',*deps]
    return g.hashes(paths)


def build(product,out,value):
    product=Path(product).resolve(strict=True);out=Path(out).resolve();value=spec(value)
    require(not out.exists(),'fresh no-argument build directory required');out.mkdir(parents=True)
    write(out/'app-spec.json',value);(out/'app_config.h').write_text(header(value))
    write(out/'started.json',dict(status='STARTED_NOT_EXECUTED',source_product=str(product),
                                source_receipt_sha256=g.sha(product/'result.json'),spec=value))
    try:
        p=source(product);plan=plans(out,p,value);graphs={}
        for name,args in plan:
            if name.startswith('deps-'):graphs[name[5:]]=command(out,name,args)
        before=input_closure(out,p,product,graphs)
        (out/'reused').mkdir()
        for name,path in reused(p).items():
            shutil.copy2(path,out/'reused'/name)
            require(g.sha(path)==g.sha(out/'reused'/name),'copied AOT/runtime object differs')
        for name,args in plan:
            if name.startswith('deps-'):continue
            result=command(out,name,args)
            if name.startswith('exports-'):
                unit=name[8:];object_tools.arm_object(out/(unit+'.o'))
                require(object_tools.symbols(result)==expected_exports(unit),'unexpected entry/host exports')
        executable=out/'linked-native';g.macho(executable)
        graph=g.library_graph(executable,executable)
        require(set(graph['nodes'])=={str(executable),*p.build_manifest['library_graph']['nodes']},'native dependency closure differs')
        g.same(before);p.verify_build();verify_product(product)
        commands={name:dict(path=str(out/'commands'/(name+'.json')),sha256=g.sha(out/'commands'/(name+'.json'))) for name,_ in plan}
        artifacts=g.hashes([out/'started.json',executable,*[out/'reused'/name for name in reused(p)],
                           out/'host.o',out/'entry.o',*[row['path'] for row in commands.values()]])
        record=dict(schema=1,status=STATUS,source_product=str(product),source_receipt_sha256=g.sha(product/'result.json'),
                    pe_sha256=p.source_sha256,spec=value,inputs_before=before,inputs_after=g.hashes(before),
                    dependency_graphs=graphs,reused_objects={name:dict(source=str(path),sha256=g.sha(path)) for name,path in reused(p).items()},
                    native_executable=str(executable),native_sha256=g.sha(executable),library_graph=graph,
                    commands=commands,artifacts=artifacts,guest_executions=0)
        write(out/'entry-build.json',record)
        verify(out)
        return record
    except Exception as error:
        write(out/'first-failure.json',dict(status='FAIL_NOT_EXECUTED',error=repr(error)))
        raise


def verify(out):
    out=Path(out).resolve(strict=True);r=g.read_json(out/'entry-build.json');value=spec(r['spec'])
    require(r['status']==STATUS and r['guest_executions']==0,'entry build scope')
    require(g.read_json(out/'app-spec.json')==value and (out/'app_config.h').read_text()==header(value),'App configuration differs')
    require(r['inputs_before']==r['inputs_after'],'entry inputs changed');g.same(r['inputs_before']);g.same(r['artifacts'])
    product=Path(r['source_product']);require(g.sha(product/'result.json')==r['source_receipt_sha256'],'source product receipt differs')
    p=source(product);expected=input_closure(out,p,product,r['dependency_graphs'])
    require(expected==r['inputs_before'] and p.source_sha256==r['pe_sha256'],'entry source closure differs')
    required=[out/'started.json',out/'linked-native',out/'host.o',out/'entry.o',
              *[out/'reused'/name for name in reused(p)],
              *[out/'commands'/(name+'.json') for name,_ in plans(out,p,value)]]
    require(r['artifacts']==g.hashes(required),'entry artifact closure differs')
    require(r['reused_objects']=={name:dict(source=str(path),sha256=g.sha(path)) for name,path in reused(p).items()},'object provenance differs')
    for name,row in r['reused_objects'].items():require(g.sha(out/'reused'/name)==row['sha256'],'copied object bytes differ')
    plan=plans(out,p,value);require(set(r['commands'])=={name for name,_ in plan},'entry command closure')
    for name,args in plan:
        row=r['commands'][name];path=out/'commands'/(name+'.json')
        require(row==dict(path=str(path),sha256=g.sha(path)),'command receipt differs')
        actual=g.read_json(path);require(actual['command']==args and type(actual['returncode']) is int and actual['returncode']==0,'actual command differs')
        if name.startswith('deps-'):require(actual['stdout']==r['dependency_graphs'][name[5:]],'actual dependency output differs')
        if name.startswith('exports-'):require(object_tools.symbols(actual['stdout'])==expected_exports(name[8:]),'actual symbol table differs')
    executable=out/'linked-native';require(r['native_executable']==str(executable) and r['native_sha256']==g.sha(executable),'entry executable identity')
    require(g.library_graph(executable,executable)==r['library_graph'],'actual entry library graph differs')
    return r
