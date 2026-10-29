#!/usr/bin/env python3
"""Real PE/register CALL runtime probe. No GUI, D3D method or GPU is invoked."""
import argparse,json,os,subprocess,sys,traceback,tempfile
from pathlib import Path
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from window_bridge.loader import load_image,THUNK_START
from window_bridge.lift import validate_register_instruction
from native_window import build_v2 as backend
from graphics_stage5 import d3d11_probe as graphics
from draw_bridge.bindings_v2 import generate_headers,python_closure,snapshot,unchanged,sha
FIXTURES=ROOT/'build/window-bridge/register-fixtures'
MODULES=ROOT/'build/window-bridge/register-modules'
OUT=ROOT/'build/window-bridge/register-runtime'
WORK=ROOT.parents[1]/'work/window-register-probe'

def require(value,message):
    if not value:raise RuntimeError(message)
def command(args,log,env=None):
    args=list(map(str,args));p=subprocess.run(args,capture_output=True,text=True,env=env)
    with log.open('a') as f:f.write(json.dumps(args)+'\n'+p.stdout+p.stderr)
    require(p.returncode==0,'command failed: '+str(log));return p.stdout
def verify_module(directory,symbol,pe_sha):
    m=graphics.read_json(directory/'manifest.json')
    require(m.get('status')=='PASS' and m.get('validation_level')=='BUILD_STATIC_NOT_EXECUTED','module not built')
    require(m.get('symbol')==m.get('function_symbol')==symbol and m['input_sha256']==pe_sha,'module root/input mismatch')
    source_set={'window_bridge/lift.py','window_bridge/build_lifter.py','integration_stage3/lifter_layout.cpp',
        *{'window_bridge/'+p for p in ('xed-only-v1.patch','transactions-v1.patch','aot-profile-v1.patch',
            'import-calls-v1.patch','vtable-calls-v1.patch','window-calls-v1.patch')}}
    external={'memory_stage2/image_loader.py','window_bridge/loader.py','callback_bridge/imports_v1.py','fixtures.py'}
    require(set(m['source_sha256'])==source_set and set(m['external_source_sha256'])==external,'producer source closure incomplete')
    for group in ('source_sha256','external_source_sha256'):
        require(all(sha(ROOT/p)==h for p,h in m[group].items()),'producer source changed')
    require(m['inputs_before']==m['inputs_after'],'producer inputs changed during lift');unchanged(m['inputs_before'])
    require(set(m['artifact_sha256'])=={'text.bin','instructions-raw.json','lifted.ll','arm64.ll','arm64.o','arm64-o0.o'},'module artifact closure differs')
    require(all(sha(directory/p)==h for p,h in m['artifact_sha256'].items()),'module artifact changed')
    for n in ('arm64.o','arm64-o0.o'):
        exports=subprocess.check_output(['/usr/bin/nm','-gU',directory/n],text=True)
        require([l.split()[-1] for l in exports.splitlines() if l.strip()]==['_'+symbol],'module exports differ')
    return m
def select_fixture(name):
    if name=='bad-release-target':
        root=ROOT/'build/window-bridge/register-release-target';path=root/'fixture.json'
        return graphics.read_json(path),path,root/'module'
    require(name in ('good','bad-offset','bad-guest','bad-method'),'unknown fixture')
    path=FIXTURES/'manifest.json'
    return graphics.read_json(path)['fixtures'][name],path,MODULES/name
def headers(out,fixture,m,file_directory=None):
    pe=Path(fixture['pe']);p=SimpleNamespace(image=load_image(pe),source_bytes=pe.read_bytes(),source_sha256=sha(pe),manifest=m,out=out)
    metadata={'observations':{'after_exit':{'rva':fixture['symbols']['after_exit'],'size':4}}}
    generate_headers(p,metadata)
    rows=m['register_calls'];require(len(rows)==1 and not m['virtual_calls'],'probe needs one register CALL and no COM calls')
    row=rows[0];require(row['call_rva']==fixture['symbols']['register_call'] and row['operand_reg']=='R14' and row['operand_register']==14,'actual register operand differs')
    actual=[validate_register_instruction(i) for i in m['instructions'] if i['kind']==4]
    require(actual==rows,'register side table differs from instruction operand/shape')
    text='\n#define AOT_REGISTER_CALL_COUNT 1\nstatic const AotRegisterCall aot_register_calls[]={{%du,14u}};\n'%row['call_rva']
    text+='#define AOT_IMPORT_TARGET_COUNT %d\nstatic const AotImportTarget aot_import_targets[]={\n'%len(p.image.imports)
    text+=''.join('{%du,%du},\n'%(i['target_rva'],i['signature']) for i in p.image.imports)+'};\n'
    require({i['signature'] for i in p.image.imports}=={8,9},'probe import closure differs')
    with (out/'native_imports.h').open('a') as f:f.write(text)
    files=file_directory or out/'files'
    if file_directory is None:files.mkdir()
    with (out/'native_image.h').open('a') as f:f.write('\nstatic const char kFileDirectory[]='+json.dumps(str(files))+';\n')
    return p.image
def actual_tools(out):
    t=graphics.tools(out)
    t['clang']=str(Path(subprocess.check_output(['/usr/bin/xcrun','--find','clang'],text=True).strip()).resolve())
    t.update(nm='/usr/bin/nm',codesign='/usr/bin/codesign');return t
def units(out,mode,tools,config):
    require(mode in ('O3','O0'),'unknown compiler mode')
    common=['-arch','arm64','-isysroot',tools['sdk'],'-'+mode,'-Wall','-Wextra','-Werror','-I',str(out)]
    cpp=[*common,'-std=c++17','-Wno-extern-c-compat','-fno-exceptions','-fno-rtti',
         '-I'+config['dxmt_source']+'/include/native/windows','-I'+config['dxmt_source']+'/include/native/directx']
    return [('register_host.c','clang',[*common,'-std=c11']),('runtime.c','clang',[*common,'-std=c11']),('native_backend.cpp','clang++',cpp)]
def discover(out,name,mode):
    fixture,fixture_path,module=select_fixture(name)
    require(sha(fixture['pe'])==fixture['sha256'],'fixture changed')
    m=verify_module(module,'aot_entry',fixture['sha256'])
    ret=MODULES/'ret';rm=verify_module(ret,'aot_import_ret',sha(ret/'synthetic-ret.exe'))
    require((ret/'text.bin').read_bytes()==b'\xc3','RET shim changed')
    config=backend.config();library,receipts,bound=backend.provenance(config)
    graph=graphics.library_graph(library,out/'future-exe',[library.parent]);graphics.require_graph_provenance(graph,bound)
    tools=actual_tools(out);dependencies=[];dep_graphs={}
    for file,tool,flags in units(out,mode,tools,config):
        output=subprocess.check_output(list(map(str,[tools[tool],*flags,'-M','-MT','probe',HERE/file])),text=True)
        dep_graphs[file]=output;dependencies+=graphics.dependency_paths(output)
    paths=[*dependencies,*python_closure([Path(__file__)]),*receipts,*graph['nodes'],fixture_path,
           *[v for k,v in tools.items() if k!='sdk'],module/'manifest.json',ret/'manifest.json',fixture['pe']]
    identities={**snapshot(paths),**m['inputs_before'],**rm['inputs_before']}
    identities.update(snapshot([module/p for p in m['artifact_sha256']]+[ret/p for p in rm['artifact_sha256']]))
    return identities,dep_graphs,tools,config,library,graph,fixture,module,m
def build(name,mode,out):
    out=Path(out).resolve();require(out.is_relative_to(OUT) and not out.exists(),'new independent probe directory required');out.mkdir(parents=True)
    fixture,_,module=select_fixture(name)
    require(sha(fixture['pe'])==fixture['sha256'],'fixture changed')
    m=verify_module(module,'aot_entry',fixture['sha256'])
    ret=MODULES/'ret';rm=verify_module(ret,'aot_import_ret',sha(ret/'synthetic-ret.exe'))
    require((ret/'text.bin').read_bytes()==b'\xc3','RET shim changed')
    headers(out,fixture,m)
    before,dep_graphs,tools,config,library,graph,_,_,_=discover(out,name,mode)
    log=out/'build.log';log.write_text('')
    objects=[]
    for file,tool,flags in units(out,mode,tools,config):
        obj=out/(file+'.o');command([tools[tool],*flags,'-c',HERE/file,'-o',obj],log);objects.append(obj)
    objname='arm64.o' if mode=='O3' else 'arm64-o0.o';exe=out/'register-probe'
    command([tools['clang++'],'-arch','arm64','-isysroot',tools['sdk'],'--ld-path='+tools['ld'],*objects,
             module/objname,ret/objname,library,'-Wl,-rpath,'+str(library.parent),'-o',exe],log)
    command(['/usr/bin/codesign','--force','--sign','-',exe],log);command(['/usr/bin/codesign','--verify','--strict',exe],log)
    require(graphics.macho(exe)['filetype']==2,'not ARM64 executable')
    executable_graph=graphics.library_graph(exe,exe)
    require(set(executable_graph['nodes'])==set(graph['nodes'])|{str(exe)},'linked library closure differs')
    unchanged(before)
    artifacts=snapshot([*objects,exe,out/'native_imports.h',out/'native_image.h',log])
    result={'status':'BUILT_REGISTER_CALL_PROBE_NOT_EXECUTED','fixture':fixture,'name':name,'mode':mode,
            'inputs_before':before,'inputs_after':snapshot(before),'artifacts':artifacts,'tools':tools,
            'executable':str(exe),'graph':executable_graph,'backend_graph':graph,'dependencies':dep_graphs,
            'config':config,'scope':'original small PE register CALL and file LastError/ExitProcess; no GUI/GPU call'}
    graphics.save(out/'build.json',result);verify(out);return result
def verify(out):
    out=Path(out).resolve();r=graphics.read_json(out/'build.json')
    require(out.is_relative_to(OUT) and r['status']=='BUILT_REGISTER_CALL_PROBE_NOT_EXECUTED','probe build not current')
    before,deps,t,config,library,graph,fixture,module,m=discover(out,r['name'],r['mode'])
    require(before==r['inputs_before']==r['inputs_after'] and deps==r['dependencies'],'actual input/dependency closure omitted or changed')
    require(r['tools']==t and r['config']==config and r['fixture']==fixture and r['backend_graph']==graph,'actual configuration differs')
    exe=out/'register-probe';require(r['executable']==str(exe),'executable path escaped build')
    required=[exe,*[out/(name+'.o') for name,_,_ in units(out,r['mode'],t,config)],out/'native_imports.h',out/'native_image.h',out/'build.log']
    require(r['artifacts']==snapshot(required),'mandatory build artifacts omitted or changed')
    WORK.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='verify-headers-',dir=WORK) as temporary:
        reference=Path(temporary);headers(reference,fixture,m,out/'files')
        for name in ('native_imports.h','native_image.h'):
            require((reference/name).read_bytes()==(out/name).read_bytes(),'generated header differs from actual PE/metadata')
    require(graphics.library_graph(exe,exe)==r['graph'] and set(r['graph']['nodes'])==set(graph['nodes'])|{str(exe)},'probe graph changed')
    subprocess.run(['/usr/bin/codesign','--verify','--strict',exe],check=True,capture_output=True)
    return r
def run_command(r,budget,base):
    cmd=[r['executable']]
    if budget is not None:cmd+=['--budget',str(budget)]
    if base is not None:cmd+=['--base',str(base)]
    return cmd
def check_result(r,result,returncode,budget,base):
    """Explicit fixed-PE semantics; a budget run is never an unchecked PASS."""
    fixture,_,module=select_fixture(r['name']);m=graphics.read_json(module/'manifest.json')
    image=load_image(Path(fixture['pe']));base=image.preferred_base if base is None else base
    rows=m['instructions'];call=fixture['symbols']['register_call']
    prefix=[i for i in rows if i['rva']<call]
    require(all(i['kind']==0 and i['iclass'] in ('PUSH','SUB','MOV','ADD','LEA') for i in prefix),'unexpected prefix control flow')
    require([i['rva']+i['length'] for i in prefix]==[i['rva'] for i in prefix[1:]]+[call],'prefix is not straight line')
    count=len(prefix);initial_rsp=0x70000000+65536-0x108;normal=r['name']=='good'
    require(budget is None or (type(budget) is int and (budget in (3,4,5,6,7) if normal else budget==count)),
            'budget has no explicitly supported expectation')
    target=base+THUNK_START+8*4096
    if r['name']=='bad-offset':target+=1
    elif r['name']=='bad-guest':target=base+fixture['symbols']['guest_entry']
    elif r['name']=='bad-method':target=THUNK_START+150*4096 # historical absolute-address fixture, not a registered method
    elif r['name']=='bad-release-target':target=base+THUNK_START+101*4096
    status=11 if normal and (budget is None or budget>=7) else 4 if budget is not None else 13
    steps=7 if status==11 else budget if status==4 else count+1
    api=int(normal and (budget is None or budget>=5));depth=int(normal and (status==11 or budget==4))
    rsp=initial_rsp-40-8*depth
    exit_row=next(i for i in rows if i.get('signature')==9)
    if status==11:rip=base+THUNK_START+9*4096
    elif normal and budget==4:rip=target
    elif normal and budget==5:rip=base+fixture['symbols']['after_register_call']
    elif normal and budget==6:rip=base+exit_row['rva']
    else:rip=base+call
    expected={'pe_sha256':fixture['sha256'],'image_base':base,'entry_rva':image.entry_rva,'entry_arguments':0,
              'outcome':'PROCESS_EXITED' if status==11 else 'FAULT','aot_status':status,'steps':steps,
              'get_last_error_calls':api,'last_error':0,'exit_requested':int(status==11),'exit_code':0,
              'returned':0,'call_depth':depth,'rsp':rsp,'rip':rip,'r14':target,'rax':0,'d3d_cleanup_result':0,
              'observations':{'after_exit':'00000000'}}
    for key,value in expected.items():require(result.get(key)==value,'unexpected '+key+': '+str(result.get(key))+' != '+str(value))
    require(returncode==(0 if status==11 else 3),'actual process exit differs')
    if status==11:
        require(result['fault']==dict(status=0,pc=0,address=0,width=0,access=0),'exited process has fault')
        require((result['exit_pc'],result['exit_rsp'],result['exit_depth'])==(rip,rsp,1),'exit boundary differs')
    else:
        address=target if status==13 else rip
        require(result['fault']==dict(status=status,pc=rip,address=address,width=0,access=4 if status==13 else 0),'fault boundary differs')
        require((result['exit_pc'],result['exit_rsp'],result['exit_depth'])==(0,0,0),'nonexit has termination state')
    for key in ('d3d_before_cleanup','d3d_after_cleanup'):
        require(all(value==(int(status==11) if name=='exit_calls' else 0) for name,value in result[key].items()),'unexpected graphics/object effect')
    state=bytes.fromhex(result['state_hex']);stack=bytes.fromhex(result['stack_hex'])
    require(len(state)==3504 and len(stack)==65536,'full State/stack missing')
    offsets=[2216,2248,2264,2232,2312,2328,2280,2296,2344,2360,2376,2392,2408,2424,2440,2456,2472]
    registers=[int.from_bytes(state[o:o+8],'little') for o in offsets]
    expected_registers=[0]*17;expected_registers[4]=rsp;expected_registers[14]=target;expected_registers[16]=rip
    require(registers==expected_registers,'full GPRs differ from fixed PE contract')
    expected_stack=bytearray(65536);index=initial_rsp-0x70000000
    expected_stack[index:index+8]=(0x7fff00000000).to_bytes(8,'little')
    if normal and (budget is None or budget>=4):
        return_rva=exit_row['rva']+exit_row['length'] if status==11 else fixture['symbols']['after_register_call']
        expected_stack[index-48:index-40]=(base+return_rva).to_bytes(8,'little')
    require(stack==expected_stack,'complete guest stack differs, including CALL write/rollback')
    require(result['below_rsp']==stack[rsp-0x70000000-8:rsp-0x70000000].hex(),'below-RSP observation inconsistent')
    return {'status':status,'steps':steps,'api_calls':api,'call_depth':depth,'complete_stack_checked':True,
            'full_gprs_checked':True,'oracle':'explicit self-authored PE contract, not Windows execution'}
def run_inputs(out,r):return {**r['inputs_before'],**r['artifacts'],**snapshot([out/'build.json'])}
def verify_run(directory):
    directory=Path(directory).resolve();out=directory.parent;r=verify(out);e=graphics.read_json(directory/'evidence.json')
    require(e['status']=='PASS_REGISTER_CALL_EXECUTION' and e['new_guest_executions']==1 and e['gpu_api_calls']==0,'run not accepted')
    require(e['build_sha256']==sha(out/'build.json') and e['command']==run_command(r,e['budget'],e['base']),'run/build/config differs')
    require(e['inputs_before']==e['inputs_after']==run_inputs(out,r),'execution input closure changed or omitted')
    require(e['artifacts']==snapshot([directory/'stdout',directory/'stderr']),'mandatory run artifact omitted/changed')
    result=graphics.strict_json((directory/'stdout').read_text())
    require(result==e['result'],'stdout and reported result differ')
    require(graphics.loaded_images((directory/'stderr').read_text(),Path(r['executable']),r['backend_graph']['nodes'])==e['loaded_images'],'actual loaded images differ')
    require(check_result(r,result,e['returncode'],e['budget'],e['base'])==e['expectation'],'execution expectation differs')
    return e
def run(out,budget=None,base=None):
    out=Path(out).resolve();r=verify(out);directory=out/('run-'+str(base)+'-'+str(budget));require(not directory.exists(),'run directory exists');directory.mkdir()
    cmd=run_command(r,budget,base);before=run_inputs(out,r)
    evidence={'status':'RUN_STARTED','command':cmd,'budget':budget,'base':base,'inputs_before':before,
              'build_sha256':sha(out/'build.json'),'new_guest_executions':0,'gpu_api_calls':0}
    graphics.save(directory/'started.json',evidence)
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=60,env=graphics.environment(directory,images=True))
        (directory/'stdout').write_text(p.stdout);(directory/'stderr').write_text(p.stderr)
        evidence.update(returncode=p.returncode,new_guest_executions=1,inputs_after=snapshot(before),
                        artifacts=snapshot([directory/'stdout',directory/'stderr']))
        result=graphics.strict_json(p.stdout);evidence['result']=result
        evidence['loaded_images']=graphics.loaded_images(p.stderr,Path(r['executable']),r['backend_graph']['nodes'])
        verify(out);unchanged(before)
        evidence['expectation']=check_result(r,result,p.returncode,budget,base)
        evidence['status']='PASS_REGISTER_CALL_EXECUTION';graphics.save(directory/'evidence.json',evidence);verify_run(directory)
    except Exception as error:
        evidence.update(status='RUN_FAILED',error=str(error),traceback=traceback.format_exc())
        if isinstance(error,subprocess.TimeoutExpired):
            for name,value in [('stdout',error.stdout),('stderr',error.stderr)]:
                (directory/name).write_bytes(value if isinstance(value,bytes) else (value or '').encode())
            evidence.update(timeout=True,new_guest_executions=1,artifacts=snapshot([directory/'stdout',directory/'stderr']))
        graphics.save(directory/'failure.json',evidence);raise
    return {'status':evidence['status'],'name':r['name'],'mode':r['mode'],'outcome':result['outcome'],'steps':result['steps'],
            'get_last_error_calls':result['get_last_error_calls'],'evidence':str(directory/'evidence.json')}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--name',choices=('good','bad-offset','bad-guest','bad-method','bad-release-target'));p.add_argument('--mode',choices=('O3','O0'),default='O3');p.add_argument('--out',type=Path,required=True)
    p.add_argument('--run',action='store_true');p.add_argument('--verify',action='store_true');p.add_argument('--budget',type=int);p.add_argument('--base',type=lambda x:int(x,0));a=p.parse_args()
    if a.verify:verify(a.out);print('{"status":"CURRENT_BUILD_NO_EXECUTION"}')
    elif a.run:print(json.dumps(run(a.out,a.budget,a.base)))
    else:
        try:
            require(a.name,'build requires --name');build(a.name,a.mode,a.out);print('{"status":"BUILD_ONLY_NOT_EXECUTED"}')
        except Exception as e:
            if a.out.exists():graphics.save(a.out/'failure.json',{'status':'BUILD_FAILED_NOT_EXECUTED','error':str(e),'traceback':traceback.format_exc(),'producer_sha256':sha(__file__)})
            raise
