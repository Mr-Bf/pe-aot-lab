#!/usr/bin/env python3
"""Independent native Present-readback host over the frozen original-PE build.

Build/verify never runs the executable. Explicit run records capture provenance;
RGBA content needs a separate image predicate, and this is not a timing profile.
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
from window_bridge import window_bindings as baseline
from window_bridge import pixel_observer_build as observer
from graphics_stage5 import d3d11_probe as g

SOURCE=ROOT/'build/window-bridge/program-build-03'
SOURCE_SHA='052159cb1f173102a07786fd22367941fa385f9b4a3b121d1787f1e59adbca03'
HOST_SHA='b83c847bf33e98fefab70d8c01ce7db64b2eb846024a40b1ccda2f8f450c1c38'
OBSERVER_SHA='747896f89a36d0698ea5640c5e9fb3425c71ca3d060afb6b337b5ed1c38759d2'
OUT=ROOT/'build/window-bridge/pixel-program-v1-01'
STATUS='BUILT_INSTRUMENTED_ORIGINAL_PE_NOT_EXECUTED'
SCOPE=dict.fromkeys(('guest_executions','window_executions','gpu_executions','library_loads','pixel_frames'),0)
PIXEL_BYTES=640*360*4
STATS32=('version','size','active','first_error','first_errno','last_present_hr','reserved0','reserved1')
STATS64=('attempts','present_calls','captured_frames','records_written','raw_bytes_written','rgba_bytes_reserved',
         'copy_calls','map_calls','unmap_calls','refs_acquired','refs_released','live_refs','live_maps',
         'failures','capacity_rejections','unconfigured_calls','reentrant_calls')
PRINT_OBSERVER=r'''static void print_observer(const Run*r){
    printf("{\"begin_called\":%u,\"begin_status\":%u,\"end_called\":%u,\"end_status\":%u,\"max_frames\":%u,\"max_total_rgba_bytes\":%" PRIu64 ",\"stats\":{",r->observer_begin_called,r->observer_begin,r->observer_end_called,r->observer_end,AOT_PIXEL_MAX_FRAMES,(uint64_t)AOT_PIXEL_MAX_FRAMES*AOT_PIXEL_RGBA_BYTES);
#define U32(field) printf("\"" #field "\":%u,",r->observer.field)
    U32(version);U32(size);U32(active);U32(first_error);U32(first_errno);U32(last_present_hr);U32(reserved0);U32(reserved1);
#undef U32
#define U64(field) printf("\"" #field "\":%" PRIu64 ",",r->observer.field)
    U64(attempts);U64(present_calls);U64(captured_frames);U64(records_written);U64(raw_bytes_written);U64(rgba_bytes_reserved);U64(copy_calls);U64(map_calls);U64(unmap_calls);U64(refs_acquired);U64(refs_released);U64(live_refs);U64(live_maps);U64(failures);U64(capacity_rejections);U64(unconfigured_calls);
#undef U64
    printf("\"reentrant_calls\":%" PRIu64 "}}",r->observer.reentrant_calls);
}
'''
# These exact, single-use edits define the whole native-host delta. They add
# observation/configuration only; no guest register, image, shader or API edit.
HOST_REPLACEMENTS=[
    ('#include "cocoa_host.h"\n','#include "cocoa_host.h"\n#include "pixel_observer_v1.h"\n'),
    ('WBHost *host;const char *directory;uint64_t base,budget;',
     'WBHost *host;const char *directory,*pixel_directory;uint64_t base,budget;\n    uint32_t observer_begin_called,observer_begin,observer_end_called,observer_end;AotPixelObserverStats observer;'),
    ('Run*r=opaque;int d3d=0,files=0,callbacks=0,user32=0;',
     'Run*r=opaque;int d3d=0,files=0,callbacks=0,user32=0,observing=0;\n    r->observer_begin=AOT_PIXEL_NOT_CONFIGURED;r->observer_end=AOT_PIXEL_NOT_CONFIGURED;'),
    ('    r->status=aot_execute(aot_entry,r->state,r->ctx,r->base+kEntryRva);',
     '    AotPixelObserverConfig pixel_config={AOT_PIXEL_OBSERVER_VERSION,sizeof pixel_config,AOT_PIXEL_MAX_FRAMES,0,(uint64_t)AOT_PIXEL_MAX_FRAMES*AOT_PIXEL_RGBA_BYTES,r->pixel_directory};\n    r->observer_begin_called=1;r->observer_begin=aot_window_observer_begin(&pixel_config);\n    if(r->observer_begin){r->setup_status=AOT_INVALID;goto done;}observing=1;\n    r->status=aot_execute(aot_entry,r->state,r->ctx,r->base+kEntryRva);'),
    ('    /* No cleanup path executes WndProc, synthesizes QUIT, or writes a save.',
     '    if(observing){r->observer_end_called=1;r->observer_end=aot_window_observer_end(&r->observer);}\n    else aot_window_observer_stats(&r->observer);\n    /* No cleanup path executes WndProc, synthesizes QUIT, or writes a save.'),
    ('typedef struct {uint32_t message;uint64_t key;int64_t bits;const char*name;} TestEvent;',
     PRINT_OBSERVER+'typedef struct {uint32_t message;uint64_t key;int64_t bits;const char*name;} TestEvent;'),
    ('        else if(!strcmp(argv[i],"--base")&&i+1<argc)',
     '        else if(!strcmp(argv[i],"--pixel-dir")&&i+1<argc)r.pixel_directory=argv[++i];\n        else if(!strcmp(argv[i],"--base")&&i+1<argc)'),
    ('usage: --data-dir directory [--base value]', 'usage: --data-dir directory --pixel-dir dedicated-directory [--base value]'),
    ('    if((r.base&65535)',
     '    if(!r.pixel_directory||r.pixel_directory[0]!=\'/\')return host_error("absolute dedicated pixel directory required");\n    struct stat data_stat,pixel_stat;if(stat(r.directory,&data_stat)||stat(r.pixel_directory,&pixel_stat)||!S_ISDIR(data_stat.st_mode)||!S_ISDIR(pixel_stat.st_mode)||(data_stat.st_dev==pixel_stat.st_dev&&data_stat.st_ino==pixel_stat.st_ino))return host_error("separate existing data and pixel directories required");\n    if((r.base&65535)'),
    ('||timed_out||inject_error?64:', '||timed_out||inject_error||r.observer_begin||r.observer_end||r.observer.first_error?64:'),
    ('print_file(r.directory);printf("}\\n");',
     'print_file(r.directory);printf(",\\"pixel_observer\\":");print_observer(&r);printf("}\\n");')]


def require(value,message):
    if not value:raise ValueError(message)


def write(path,data):
    with Path(path).open('x') as stream:json.dump(data,stream,indent=2,sort_keys=True);stream.write('\n')


def output(path):
    p=Path(path).absolute();parent=ROOT/'build/window-bridge'
    require(p==p.resolve() and p.parent==parent and p.name.startswith('pixel-'),'fresh direct pixel-* directory required')
    return p


def expected_host():
    original=HERE/'window_host.c';require(g.sha(original)==HOST_SHA,'frozen normal host changed')
    text=original.read_text()
    for before,after in HOST_REPLACEMENTS:
        require(text.count(before)==1,'host transform anchor differs: '+before[:90]);text=text.replace(before,after)
    return text


def source_program():
    require(g.sha(SOURCE/'program-build.json')==SOURCE_SHA,'frozen source build differs')
    p=baseline.Program.from_build(SOURCE)
    require(p.optimization=='O3' and p.executable_sha256=='2ea542a520900ee985001f2eb0b363c65651f06a2eb908641808eb92be691e21','source executable differs')
    return p


def source_objects(p):
    return {'runtime.o':p.out/'window_runtime__runtime.c.o','native-backend.o':p.out/'native_backend.cpp.o',
            'cocoa.o':p.out/'cocoa_host.mm.o','main.o':Path(p.roots[0]['directory'])/'arm64.o',
            'wndproc.o':Path(p.roots[1]['directory'])/'arm64.o','ret.o':p.out/'ret-shim/arm64.o'}


def units(p):
    flags={name:(compiler,flags) for name,compiler,flags in p.compilation_units()}
    c,cf=flags['window_host.c'];cpp,cppf=flags['native_backend_window.cpp']
    return [('host',HERE/'window_host_pixel_v1.c',c,cf),
            ('window',HERE/'native_backend_window.cpp',cpp,[*cppf,observer.MACRO]),
            ('observer',HERE/'pixel_observer_v1.cpp',cpp,cppf)]


def command(out,name,args):
    args=list(map(str,args));path=out/'commands'/(name+'.json');path.parent.mkdir(exist_ok=True)
    require(not path.exists(),'command evidence exists')
    p=subprocess.run(args,capture_output=True,text=True,env=g.environment(out))
    write(path,{'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    require(p.returncode==0,'static build command failed: '+str(path));return p.stdout


def discover(out,p,writing=False):
    require((HERE/'window_host_pixel_v1.c').read_text()==expected_host(),'instrumented host differs from exact approved transform')
    require(g.sha(observer.OUT/'evidence.json')==OBSERVER_SHA,'frozen observer preparation differs')
    obs=observer.verify();dependencies=[];graphs={}
    for name,source,compiler,flags in units(p):
        args=[compiler,*flags,'-M','-MT','probe',source]
        text=command(out,'deps-'+name,args) if writing else g.invoke(args,g.environment(out))
        graphs[name]=text;path=out/(name+'.d')
        if writing:path.write_text(text)
        else:require(path.read_text()==text,'actual compile dependency graph changed')
        dependencies += [*g.dependency_paths(text),path]
    before=p.build_manifest
    paths=[*before['native_inputs'],*before['artifacts'],SOURCE/'program-build.json',
           *obs['inputs_before'],*obs['artifacts'],observer.OUT/'evidence.json',
           *baseline.python_closure([Path(__file__)]),*dependencies]
    return g.hashes(paths),graphs


def link_plan(out,p):
    libraries=p.build_manifest['library_graph']['nodes'];library=Path(p.build_manifest['library'])
    return list(map(str,[p.tools['clang++'],'-arch','arm64','-isysroot',p.tools['sdk'],'--ld-path='+p.tools['ld'],
        *[out/'reused'/name for name in source_objects(p)],*[out/(n+'.o') for n,_,_,_ in units(p)],
        library,next(n for n in libraries if Path(n).name=='winemetal.dylib'),
        '-framework','Cocoa','-framework','Metal','-framework','QuartzCore',
        *['-Wl,-rpath,'+n for n in sorted({str(Path(x).parent) for x in libraries})],'-o',out/'linked-native']))


def plans(out,p):
    result=[]
    for name,source,compiler,flags in units(p):
        result.append(('deps-'+name,list(map(str,[compiler,*flags,'-M','-MT','probe',source]))))
    for name,source,compiler,flags in units(p):
        result.append(('compile-'+name,list(map(str,[compiler,*flags,'-c',source,'-o',out/(name+'.o')]))))
        result.append(('exports-'+name,[p.tools['nm'],'-gU',str(out/(name+'.o'))]))
    result += [('link',link_plan(out,p)),
               ('sign',[p.tools['codesign'],'--force','--sign','-','--identifier','org.peaotlab.window.pixelv1',str(out/'linked-native')]),
               ('signature',[p.tools['codesign'],'--verify','--strict',str(out/'linked-native')])]
    return result


def expected_exports(name):
    return {'host':{'_main'},'window':observer.EXPECTED_WINDOW,'observer':observer.EXPECTED_OBSERVER}[name]


def artifact_paths(out,p,exe):
    return [out/'started.json',out/'linked-native',exe,*[out/'reused'/n for n in source_objects(p)],
            *[out/(n+'.o') for n,_,_,_ in units(p)],*[out/(n+'.d') for n,_,_,_ in units(p)],
            *[out/'commands'/(n+'.json') for n,_ in plans(out,p)]]


class Program:
    def __init__(self,out_dir=OUT):
        self.out=output(out_dir);require(not self.out.exists(),'preserve attempted output; choose a new pixel-* directory')
        self.out.mkdir(parents=True)
        write(self.out/'started.json',{'schema':1,'status':'BUILD_STARTED_NOT_EXECUTED','scope':SCOPE,
            'producer_sha256':g.sha(__file__),'derived_host_sha256':g.sha(HERE/'window_host_pixel_v1.c'),
            'source_program':str(SOURCE),'source_program_sha256':SOURCE_SHA,'observer_receipt_sha256':OBSERVER_SHA})
        try:
            self.original=source_program();p=self.original
            before,graphs=discover(self.out,p,True)
            (self.out/'reused').mkdir()
            reused={}
            for name,source in source_objects(p).items():
                destination=self.out/'reused'/name;shutil.copy2(source,destination)
                require(g.sha(source)==g.sha(destination),'reused object copy differs')
                reused[name]={'source':str(source),'sha256':g.sha(source)}
            for name,source,compiler,flags in units(p):
                command(self.out,'compile-'+name,[compiler,*flags,'-c',source,'-o',self.out/(name+'.o')])
                observer.arm_object(self.out/(name+'.o'))
                text=command(self.out,'exports-'+name,[p.tools['nm'],'-gU',self.out/(name+'.o')])
                require(observer.symbols(text)==expected_exports(name),'compiled symbol closure differs')
            link_inputs=g.hashes([*[self.out/'reused'/n for n in source_objects(p)],*[self.out/(n+'.o') for n,_,_,_ in units(p)]])
            for name,args in plans(self.out,p)[-3:]:command(self.out,name,args)
            self.executable_sha256=g.sha(self.out/'linked-native');self.executable=self.out/('pixel-'+self.executable_sha256)
            shutil.copy2(self.out/'linked-native',self.executable)
            graph=g.library_graph(self.executable,self.executable)
            require(set(graph['nodes'])=={str(self.executable),*p.build_manifest['library_graph']['nodes']},'actual native library graph differs')
            after,graphs_after=discover(self.out,p)
            p.verify_build();g.same(link_inputs)
            require(before==after and graphs==graphs_after,'build dependencies changed')
            self.build_manifest={'schema':1,'status':STATUS,'scope':SCOPE,'source_program':str(SOURCE),
                'source_program_sha256':SOURCE_SHA,'observer_receipt_sha256':OBSERVER_SHA,
                'input_sha256':p.source_sha256,'native_executable':str(self.executable),'native_sha256':self.executable_sha256,
                'tools':p.tools,'inputs_before':before,'inputs_after':after,'dependency_graphs':graphs,
                'reused_objects':reused,'link_inputs':link_inputs,'library_graph':graph,
                'commands':[{'name':n,'path':str(self.out/'commands'/(n+'.json')),'sha256':g.sha(self.out/'commands'/(n+'.json'))} for n,_ in plans(self.out,p)],
                'artifacts':g.hashes(artifact_paths(self.out,p,self.executable)),
                'observer_profile':'readback before original Present; native temporary objects only; no guest rules/data mutation',
                'performance_sample':False,'pixels_verified':False}
            write(self.out/'program-build.json',self.build_manifest);self.verify_build()
        except Exception as error:
            write(self.out/'first-build-failure.json',{'status':'FAIL_BUILD_NOT_EXECUTED','error':repr(error),'scope':SCOPE})
            raise

    @classmethod
    def from_build(cls,out_dir=OUT):
        self=cls.__new__(cls);self.out=output(out_dir);self.original=source_program()
        self.build_manifest=g.read_json(self.out/'program-build.json');self.executable=Path(self.build_manifest['native_executable'])
        self.executable_sha256=self.build_manifest['native_sha256'];self.verify_build();return self

    def verify_build(self):
        r=g.read_json(self.out/'program-build.json');p=self.original
        require(r==self.build_manifest and r['schema']==1 and r['status']==STATUS and r['scope']==SCOPE and
                all(type(v) is int for v in r['scope'].values()),'instrumented build scope/status differs')
        require(r['source_program']==str(SOURCE) and r['source_program_sha256']==SOURCE_SHA and
                r['observer_receipt_sha256']==OBSERVER_SHA and r['input_sha256']==p.source_sha256,'source identity differs')
        p.verify_build();current,graphs=discover(self.out,p)
        require(r['inputs_before']==r['inputs_after']==current and r['dependency_graphs']==graphs and r['tools']==p.tools,
                'instrumented source/header/tool closure differs')
        require(g.read_json(self.out/'started.json')=={'schema':1,'status':'BUILD_STARTED_NOT_EXECUTED','scope':SCOPE,
            'producer_sha256':g.sha(__file__),'derived_host_sha256':g.sha(HERE/'window_host_pixel_v1.c'),
            'source_program':str(SOURCE),'source_program_sha256':SOURCE_SHA,'observer_receipt_sha256':OBSERVER_SHA},'immutable start differs')
        expected_reuse={n:{'source':str(src),'sha256':g.sha(src)} for n,src in source_objects(p).items()}
        require(r['reused_objects']==expected_reuse,'reused object source set differs')
        for name,item in expected_reuse.items():require(g.sha(self.out/'reused'/name)==item['sha256'],'copied reused object changed')
        expected_link=g.hashes([*[self.out/'reused'/n for n in source_objects(p)],*[self.out/(n+'.o') for n,_,_,_ in units(p)]])
        require(r['link_inputs']==expected_link,'actual link object closure differs')
        require(self.executable==self.out/('pixel-'+self.executable_sha256) and
                g.sha(self.executable)==self.executable_sha256==g.sha(self.out/'linked-native'),'immutable executable differs')
        require(r['artifacts']==g.hashes(artifact_paths(self.out,p,self.executable)),'artifact closure changed/omitted')
        expected_commands=[]
        for name,args in plans(self.out,p):
            path=self.out/'commands'/(name+'.json');detail=g.read_json(path)
            require(detail['command']==args and type(detail['returncode']) is int and detail['returncode']==0 and
                    set(detail)=={'command','returncode','stdout','stderr'},'actual command evidence differs')
            expected_commands.append({'name':name,'path':str(path),'sha256':g.sha(path)})
        require(r['commands']==expected_commands,'required commands changed/omitted')
        for name,_,_,_ in units(p):
            observer.arm_object(self.out/(name+'.o'))
            require(observer.symbols(g.invoke([p.tools['nm'],'-gU',self.out/(name+'.o')],g.environment(self.out)))==expected_exports(name),'actual object exports differ')
        graph=g.library_graph(self.executable,self.executable)
        require(graph==r['library_graph'] and set(graph['nodes'])=={str(self.executable),*p.build_manifest['library_graph']['nodes']},'loaded-library graph differs')
        g.invoke([p.tools['codesign'],'--verify','--strict',self.executable],g.environment(self.out))
        require(r['pixels_verified'] is False and r['performance_sample'] is False,'build-only receipt claims pixel/timing acceptance')
        return r

    def validate_execution(self,result,returncode,base=None,budget=None):
        require(isinstance(result,dict),'invalid host JSON')
        if result.get('outcome')=='HOST_ERROR':
            self.original.validate_execution(result,returncode,base,budget);return None
        require('pixel_observer' in result,'actual observer fields absent')
        normal={k:v for k,v in result.items() if k!='pixel_observer'}
        self.original.validate_execution(normal,returncode,base,budget)
        pix=result['pixel_observer'];fields={'begin_called','begin_status','end_called','end_status','max_frames','max_total_rgba_bytes','stats'}
        require(isinstance(pix,dict) and set(pix)==fields,'observer field closure differs')
        require(all(g.uint(pix[k],0xffffffffffffffff) for k in fields-{'stats'}),'observer scalar type differs')
        stats=pix['stats'];require(isinstance(stats,dict) and set(stats)==set(STATS32+STATS64),'observer stats set differs')
        require(all(g.uint(stats[k]) for k in STATS32) and all(g.uint(stats[k],0xffffffffffffffff) for k in STATS64),'observer stats type differs')
        require(pix['max_frames']==64 and pix['max_total_rgba_bytes']==64*PIXEL_BYTES,'observer configuration differs')
        return normal

    def validate_capture(self,result,pixel_directory):
        """Successful capture file contract only, not an image-content predicate."""
        pix=result['pixel_observer'];stats=pix['stats'];directory=Path(pixel_directory).absolute()
        require(set(stats)==set(STATS32+STATS64) and all(g.uint(stats[k]) for k in STATS32) and
                all(g.uint(stats[k],0xffffffffffffffff) for k in STATS64),'capture requires typed actual host statistics')
        require(directory==directory.resolve() and directory.is_dir(),'real capture directory required')
        require(pix['begin_called']==pix['end_called']==1 and pix['begin_status']==pix['end_status']==0,'observer begin/end failed or absent')
        require(stats['version']==1 and stats['size']==168 and all(stats[k]==0 for k in
            ('active','first_error','first_errno','reserved0','reserved1','live_refs','live_maps','failures','capacity_rejections','unconfigured_calls','reentrant_calls')),'observer error/lifetime failure')
        count=stats['attempts'];require(1<=count<=64 and count==result['d3d_before_cleanup']['present_calls'],'captured attempt count differs from guest Present')
        require(all(stats[k]==count for k in ('present_calls','captured_frames','records_written','copy_calls','map_calls','unmap_calls')),'capture operation counts differ')
        require(stats['refs_acquired']==stats['refs_released']==4*count and stats['raw_bytes_written']==stats['rgba_bytes_reserved']==count*PIXEL_BYTES,'capture refs/byte counts differ')
        files={'observer-summary.json',*[f'frame-{i:06d}.{suffix}' for i in range(1,count+1) for suffix in ('json','rgba')]}
        require({p.name for p in directory.iterdir()}==files and all(p.is_file() and not p.is_symlink() for p in directory.iterdir()),'capture file set differs or alias/special file')
        summary=g.read_json(directory/'observer-summary.json')
        expected={'schema':1,'profile':'window-pixel-observer-v1',**{k:stats[k] for k in STATS32+STATS64 if k not in ('version','size','reserved0','reserved1')},
            'max_frames':64,'max_total_rgba_bytes':64*PIXEL_BYTES,'pixels_verified':False,'performance_sample':False}
        require(summary==expected and summary['pixels_verified'] is False and summary['performance_sample'] is False and
                all(g.uint(summary[k],0xffffffffffffffff) for k in set(expected)-{'profile','pixels_verified','performance_sample'}),
                'observer summary differs from actual end-returned stats')
        fields={'schema','profile','frame','error','errno','interval','flags','called_mask','device_hr','buffer_hr','staging_hr','map_hr','removed_hr','present_hr','row_pitch','depth_pitch','descriptor','refs_acquired','refs_released','mapped','unmapped','packed','raw_complete','rgba_file','rgba_bytes','source','padding_copied'}
        frames=[]
        for index in range(1,count+1):
            path=directory/f'frame-{index:06d}.json';frame=g.read_json(path);raw=directory/f'frame-{index:06d}.rgba'
            require(set(frame)==fields,'frame field closure differs')
            require(frame['schema']==1 and frame['profile']=='window-pixel-observer-v1' and frame['frame']==index and
                frame['source']=='actual_backbuffer_before_present' and frame['padding_copied'] is False and
                frame['packed'] is True and frame['raw_complete'] is True,'frame origin/packing differs')
            numerics=fields-{'profile','source','padding_copied','packed','raw_complete','descriptor','rgba_file'}
            require(all(g.uint(frame[k],0xffffffffffffffff) for k in numerics),'frame scalar type differs')
            require(all(frame[k]==0 for k in ('error','errno','interval','flags')) and frame['called_mask']==255 and
                all(frame[k]<0x80000000 for k in ('device_hr','buffer_hr','staging_hr','map_hr','removed_hr','present_hr')),'failed/missing native observation')
            require(frame['descriptor']==[640,360,1,1,28,1,0,0,32,0,0] and
                all(type(x) is int for x in frame['descriptor']),'actual backbuffer descriptor differs')
            require(frame['refs_acquired']==frame['refs_released']==4 and frame['mapped']==frame['unmapped']==1 and
                2560<=frame['row_pitch']<=0xffffffff and frame['depth_pitch']<=0xffffffff,'frame ownership/layout differs')
            require(frame['rgba_file']==raw.name and frame['rgba_bytes']==PIXEL_BYTES and raw.stat().st_size==PIXEL_BYTES,'raw complete pixel extent differs')
            frames.append(frame)
        require(stats['last_present_hr']==frames[-1]['present_hr'],'final Present result differs')
        return {'status':'CAPTURE_FILES_VALID_NOT_PIXEL_ACCEPTANCE','frames':count,'raw_bytes':count*PIXEL_BYTES,
                'artifacts':g.hashes(directory/name for name in files),'pixels_verified':False,'performance_sample':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--verify-only',action='store_true');args=parser.parse_args()
    program=Program.from_build(args.out) if args.verify_only else Program(args.out)
    print(json.dumps({'status':program.build_manifest['status'],'program':str(program.out),
        'executable':str(program.executable),'sha256':program.executable_sha256,
        'inputs':len(program.build_manifest['inputs_before']),'scope':SCOPE},indent=2))
