"""Compile/link only the independent Present observer. Never loads/runs it."""
import argparse,json,struct,subprocess,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as g
from native_window import build_v2 as backend
from draw_bridge.bindings_v2 import python_closure
OUT=ROOT/'build/window-bridge/pixel-observer-static-v1-r3'
STATUS='COMPILED_LINKED_OBSERVER_NOT_LOADED_OR_EXECUTED'
MACRO='-Daot_window_native_present=aot_window_native_present_plain'
SCOPE={'library_loads':0,'guest_executions':0,'window_executions':0,'gpu_executions':0,'pixel_frames':0}
EXPECTED_WINDOW={'_aot_window_native_'+n for n in ('create_device_swapchain','get_buffer','present_plain','clear_state','flush','release_swap')}
EXPECTED_OBSERVER={'_aot_window_observer_'+n for n in ('begin','end','stats')}|{'_aot_window_native_present'}
HEADER='#include "pixel_observer_v1.h"\n_Static_assert(sizeof(AotPixelObserverConfig)==32,"config ABI");\n_Static_assert(sizeof(AotPixelObserverStats)==168,"stats ABI");\n'
def require(v,message):
    if not v:raise RuntimeError(message)
def output(path):
    p=Path(path).resolve();parent=ROOT/'build/window-bridge'
    require(p.parent==parent and p.name.startswith('pixel-observer-'),'only a new pixel-observer-* output directory is allowed')
    return p
def invoke(args,out,name):
    record=out/(name+'.json');require(not record.exists(),'command log already exists')
    args=list(map(str,args));p=subprocess.run(args,capture_output=True,text=True,env=g.environment(out))
    record.write_text(json.dumps({'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr},indent=2)+'\n')
    require(p.returncode==0,'compile/link command failed: '+str(record));return p.stdout
def units(config,tools,out):
    common=['-arch','arm64','-isysroot',tools['sdk'],'-O2','-Wall','-Wextra','-Werror']
    cpp=[*common,'-std=c++17','-Wno-extern-c-compat','-fno-exceptions','-fno-rtti',
         '-I'+config['dxmt_source']+'/include/native/windows','-I'+config['dxmt_source']+'/include/native/directx']
    return [('window',HERE/'native_backend_window.cpp',tools['clang++'],[*cpp,MACRO]),
            ('observer',HERE/'pixel_observer_v1.cpp',tools['clang++'],cpp),
            ('header',out/'header.c',tools['clang'],[*common,'-std=c11','-I',str(HERE)])]
def arm_object(path):
    data=Path(path).read_bytes();require(len(data)>=32,'short object')
    magic,cpu,subtype,kind,count,size,flags,reserved=struct.unpack_from('<8I',data)
    require(magic==0xfeedfacf and cpu==0x100000c and kind==1 and size<=len(data)-32,'not thin ARM64 Mach-O object')
    at=32
    for _ in range(count):
        require(at+8<=32+size,'short object load command')
        cmd,n=struct.unpack_from('<II',data,at);require(n>=8 and n%8==0 and n<=32+size-at,'invalid object command size');at+=n
    require(at==32+size,'object command bytes differ')
    return {'filetype':kind}
def symbols(text):return {line.split()[-1] for line in text.splitlines() if line.strip()}
def discover(out,write=False):
    config=backend.config();library,receipts,bound=backend.provenance(config)
    tools=g.tools(out);tools['clang']=g.invoke(['/usr/bin/xcrun','--find','clang'],g.environment(out)).strip();tools['nm']='/usr/bin/nm'
    require((out/'header.c').read_text()==HEADER,'C ABI test header changed')
    dependencies=[]
    for name,source,tool,flags in units(config,tools,out):
        cmd=[tool,*flags,'-M','-MT','probe',source]
        text=invoke(cmd,out,name+'-dependencies') if write else g.invoke(cmd,g.environment(out))
        dependencies+=g.dependency_paths(text)
    graph=g.library_graph(library,out/'observer.dylib',[library.parent]);g.require_graph_provenance(graph,bound)
    closure=g.hashes([*dependencies,*python_closure([Path(__file__)]),*receipts,*graph['nodes'],
                      *[v for k,v in tools.items() if k!='sdk']])
    return closure,tools,config,library,graph

def verify(path=OUT):
    out=output(path);r=g.read_json(out/'evidence.json')
    require(r.get('schema')==1 and r.get('status')==STATUS and r.get('scope')==SCOPE,'not an observer compile-only receipt')
    current,tools,config,library,graph=discover(out)
    require(r['inputs_before']==r['inputs_after']==current and r['tools']==tools and r['backend_config']==config,'complete observer input closure changed/omitted')
    require(r['library_graph']==graph,'backend graph changed')
    required={'header.c','window.o','observer.o','header.o','observer.dylib',
        'window-dependencies.json','observer-dependencies.json','header-dependencies.json',
        'window-compile.json','observer-compile.json','header-compile.json',
        'window-exports.json','observer-exports.json','link.json'}
    require(set(r['artifacts'])=={str(out/n) for n in required},'required artifacts changed/omitted');g.same(r['artifacts'])
    for name,source,tool,flags in units(config,tools,out):
        for suffix,cmd in [('dependencies',[tool,*flags,'-M','-MT','probe',source]),('compile',[tool,*flags,'-c',source,'-o',out/(name+'.o')])]:
            record=g.read_json(out/(name+'-'+suffix+'.json'))
            require(record['command']==list(map(str,cmd)) and type(record['returncode']) is int and record['returncode']==0,'recorded command differs')
        require(arm_object(out/(name+'.o'))['filetype']==1,'object is not thin ARM64')
    for name,expected in [('window',EXPECTED_WINDOW),('observer',EXPECTED_OBSERVER)]:
        cmd=[tools['nm'],'-gU',str(out/(name+'.o'))]
        require(symbols(g.invoke(cmd,g.environment(out)))==expected,'C exports differ')
        record=g.read_json(out/(name+'-exports.json'))
        require(record['command']==cmd and record['returncode']==0 and symbols(record['stdout'])==expected,'symbol evidence differs')
    link=[tools['clang++'],'-arch','arm64','-isysroot',tools['sdk'],'--ld-path='+tools['ld'],
          '-dynamiclib',str(out/'window.o'),str(out/'observer.o'),str(library),'-Wl,-rpath,'+str(library.parent),'-o',str(out/'observer.dylib')]
    record=g.read_json(out/'link.json');require(record['command']==link and record['returncode']==0,'link command differs')
    require(g.macho(out/'observer.dylib')['filetype']==6,'linked output is not ARM64 dylib')
    actual=g.library_graph(out/'observer.dylib',out/'observer.dylib')
    require(actual==r['observer_library_graph'] and set(actual['nodes'])==set(graph['nodes'])|{str(out/'observer.dylib')},'actual link graph differs')
    g.same(current);return r

def build(path=OUT):
    out=output(path);require(not out.exists(),'preserve existing output; choose a new pixel-observer-* directory')
    out.mkdir(parents=True);(out/'header.c').write_text(HEADER)
    try:
        before,tools,config,library,graph=discover(out,True)
        for name,source,tool,flags in units(config,tools,out):
            invoke([tool,*flags,'-c',source,'-o',out/(name+'.o')],out,name+'-compile')
            require(arm_object(out/(name+'.o'))['filetype']==1,'not thin ARM64 object')
        for name,expected in [('window',EXPECTED_WINDOW),('observer',EXPECTED_OBSERVER)]:
            require(symbols(invoke([tools['nm'],'-gU',out/(name+'.o')],out,name+'-exports'))==expected,'unexpected exports')
        link_before=g.hashes([out/(name+'.o') for name,_,_,_ in units(config,tools,out)])
        invoke([tools['clang++'],'-arch','arm64','-isysroot',tools['sdk'],'--ld-path='+tools['ld'],
            '-dynamiclib',out/'window.o',out/'observer.o',library,'-Wl,-rpath,'+str(library.parent),'-o',out/'observer.dylib'],out,'link')
        require(g.macho(out/'observer.dylib')['filetype']==6,'not thin ARM64 dylib')
        g.same(link_before)
        actual=g.library_graph(out/'observer.dylib',out/'observer.dylib')
        require(set(actual['nodes'])==set(graph['nodes'])|{str(out/'observer.dylib')},'unexpected non-system image')
        after,t2,c2,l2,g2=discover(out)
        require((after,t2,c2,l2,g2)==(before,tools,config,library,graph),'inputs changed while building');g.same(before)
        r={'schema':1,'status':STATUS,'scope':SCOPE,'inputs_before':before,'inputs_after':after,'tools':tools,'backend_config':config,
           'library_graph':graph,'observer_library_graph':actual,'artifacts':g.hashes(p for p in out.iterdir() if p.is_file()),
           'notes':'original adapter source unchanged; only its Present symbol renamed at compile time; no dynamic load, native call, PE, window or GPU execution'}
        (out/'evidence.json').write_text(json.dumps(r,indent=2)+'\n');verify(out);return r
    except Exception as error:
        (out/'failure.json').write_text(json.dumps({'status':'FAILED_STATIC_BUILD_NOT_EXECUTED','error':str(error),'traceback':traceback.format_exc(),'scope':SCOPE},indent=2)+'\n')
        raise
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=OUT);p.add_argument('--verify',action='store_true');a=p.parse_args()
    r=verify(a.out) if a.verify else build(a.out)
    print(json.dumps({'status':'STATIC_OBSERVER_CURRENT' if a.verify else r['status'],'inputs':len(r['inputs_before']),'artifacts':len(r['artifacts']),'scope':r['scope']}))
