"""Lifetime-v2 backend binding; original guest/runtime semantics unchanged.

Build and launch an independent ARM64 executable from an original PE.

Python is a build/test driver only. The emitted executable directly embeds and
runs the guest image with a native C host; it does not load a Python runtime.
"""
import ast,fcntl,hashlib,json,os,re,shlex,shutil,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from draw_bridge.loader import load_image,THUNK_START
from graphics_stage5 import d3d11_probe as graphics
from graphics_stage5.lifetime_v2 import build as backend
METHOD_SIGNATURES=(101,110,111,112,120,121,122,123,130,131,132,140,141,142,143,144,145,146)
VIRTUAL_SLOTS=frozenset((2,5,9,11,12,13,14,15,22,24,33,39,43,44,47,50))
STATS_FIELDS=frozenset(('create_device_calls','create_texture_calls','create_rtv_calls','clear_calls',
    'copy_calls','map_calls','unmap_calls','get_removed_calls','release_calls','exit_calls','this_checks',
    'created','guest_released','cleanup_releases','cleanup_unmaps','map_bytes_copied','map_postcall_failures',
    'live_objects','active_maps','last_native_release',
    'create_vs_calls','create_ps_calls','create_rasterizer_calls','om_set_calls','rs_set_calls',
    'viewport_calls','topology_calls','vs_set_calls','ps_set_calls','draw_calls'))
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def snapshot(paths):return {str(Path(p).resolve()):sha(p) for p in sorted(set(map(Path,paths)))}
def unchanged(before):
    if snapshot(before)!=before:raise ValueError('build input or artifact changed')

def python_closure(paths):
    pending=[Path(p).resolve() for p in paths];seen=set()
    while pending:
        path=pending.pop()
        if path in seen:continue
        seen.add(path)
        for node in ast.walk(ast.parse(path.read_text(),filename=str(path))):
            modules=[]
            if isinstance(node,ast.Import):modules=[x.name for x in node.names]
            elif isinstance(node,ast.ImportFrom) and node.module:
                prefix=path.parent.relative_to(ROOT).parts
                modules=['.'.join((*prefix[:len(prefix)-node.level+1],node.module)) if node.level else node.module]
            for module in modules:
                candidates=[module]
                if isinstance(node,ast.ImportFrom):candidates += [module+'.'+alias.name for alias in node.names]
                for candidate in candidates:
                    file=ROOT.joinpath(*candidate.split('.')).with_suffix('.py')
                    if file.is_file():pending.append(file.resolve())
                    package=ROOT.joinpath(*candidate.split('.'))/'__init__.py'
                    if package.is_file():pending.append(package.resolve())
    return seen

def run_command(command,log=None,env=None):
    command=list(map(str,command))
    result=subprocess.run(command,capture_output=True,text=True,env=env)
    if log:
        with log.open('a') as f:f.write(json.dumps(command)+'\n'+result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('command failed: '+result.stderr)
    return result.stdout

def verify_lift(directory,manifest,input_sha256,symbol):
    """Bind actual link objects to this exact producer result, before/after link.

    Manifests are build provenance, not signatures from an untrusted authority.
    Comparing the frozen returned manifest also detects same-directory rebuilds.
    """
    directory=Path(directory).resolve()
    current=json.loads((directory/'manifest.json').read_text())
    if current!=manifest or current.get('status')!='PASS':
        raise ValueError('lift manifest changed or is not successful')
    if current.get('validation_level')!='BUILD_STATIC_NOT_EXECUTED':raise ValueError('unknown lift validation level')
    if current.get('input_sha256')!=input_sha256 or current.get('function_symbol')!=symbol or current.get('symbol')!=symbol:
        raise ValueError('lift input or entry symbol identity mismatch')
    required={'text.bin','instructions-raw.json','lifted.ll','arm64.ll','arm64.o','arm64-o0.o'}
    artifacts=current.get('artifact_sha256',{})
    if set(artifacts)!=required:raise ValueError('lift artifact closure incomplete or unknown')
    if Path(current.get('object','')).resolve()!=directory/'arm64.o':
        raise ValueError('lift object path mismatch')
    for name,expected in artifacts.items():
        if sha(directory/name)!=expected:raise ValueError('lift artifact changed: '+name)
    required_sources={
        'source_sha256':{'draw_bridge/lift.py','draw_bridge/build_lifter.py','integration_stage3/lifter_layout.cpp',
                         'draw_bridge/xed-only-v1.patch','draw_bridge/transactions-v1.patch',
                         'draw_bridge/aot-profile-v1.patch','draw_bridge/import-calls-v1.patch','draw_bridge/vtable-calls-v1.patch'},
        'external_source_sha256':{'memory_stage2/image_loader.py','draw_bridge/loader.py','callback_bridge/imports_v1.py','fixtures.py'}}
    for collection,required_names in required_sources.items():
        if set(current.get(collection,{}))!=required_names:raise ValueError('lift source closure incomplete or unknown: '+collection)
        for name,expected in current[collection].items():
            path=(ROOT/name).resolve()
            path.relative_to(ROOT)
            if sha(path)!=expected:raise ValueError('lift source changed: '+name)
    if symbol=='aot_import_ret' and (directory/'text.bin').read_bytes()!=b'\xc3':
        raise ValueError('RET shim is not one actual C3 instruction')
    if current.get('inputs_before')!=current.get('inputs_after'):raise ValueError('lift inputs changed during build')
    unchanged(current['inputs_before'])
    for obj in ('arm64.o','arm64-o0.o'):
        output=subprocess.check_output(['nm','-g','-U',str(directory/obj)],text=True)
        if {line.split()[-1] for line in output.splitlines() if line.strip()}!={'_'+symbol}:
            raise ValueError('unexpected exported lifted symbols')
    return current

def generate_headers(program,metadata):
    image=program.image;calls=[];rows=[];virtual_calls=[]
    registers={name:index for index,name in enumerate(('RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI',
               'R8','R9','R10','R11','R12','R13','R14','R15')) if name!='RSP'}
    by_slot={row['iat_rva']:row for row in image.imports}
    for ins in program.manifest['instructions']:
        kind=ins['kind'];kind={'NORMAL':0,'CALL':1,'RET':2,'VTABLE_MEM64':3}[kind.upper()] if isinstance(kind,str) else kind
        rva,length=ins['rva'],ins['length'];target=ins.get('target_rva') or 0
        if bytes(image.data[rva:rva+length])!=bytes.fromhex(ins['bytes']):raise ValueError('decoded bytes differ from image')
        if kind==3:
            base=ins.get('base_reg');displacement=ins.get('displacement');slot=ins.get('slot')
            if (base not in registers or type(slot) is not int or slot not in VIRTUAL_SLOTS or
                type(displacement) is not int or displacement!=8*slot or
                ins.get('call_form')!='VTABLE_MEM64' or 'method_signature' in ins or 'signature' in ins or
                target!=0 or ins.get('iat_slot_rva',0)!=0):
                raise ValueError('invalid virtual-call producer metadata')
            virtual_calls.append({'call_rva':rva,'base_reg':base,'base_register':registers[base],
                                  'displacement':displacement,'slot':slot})
        if ins.get('iat_slot_rva'):
            slot=ins['iat_slot_rva']
            if kind!=1 or slot not in by_slot:raise ValueError('unbound IAT call')
            binding=by_slot[slot];target=binding['target_rva']
            calls.append({'call_rva':rva,'iat_rva':slot,'target_rva':target,'signature':binding['signature']})
        rows.append((rva,length,kind,target))
    if virtual_calls!=program.manifest.get('virtual_calls',[]):raise ValueError('virtual-call side table differs from instructions')
    method_thunks=[THUNK_START+signature*4096 for signature in METHOD_SIGNATURES]
    thunks=sorted({row['target_rva'] for row in image.imports}|set(method_thunks))
    rows += [(rva,1,2,0) for rva in thunks]
    native='/* Exact decoded import sites; a count-zero sentinel registers no API. */\n'
    native+='#define AOT_IMPORT_CALL_COUNT %d\n'%len(calls)
    native+='static const AotImportCall aot_import_calls[] = {\n'
    native+=''.join('    {%du,%du,%du,%du},\n'%(r['call_rva'],r['iat_rva'],r['target_rva'],r['signature']) for r in calls)
    native+=('' if calls else '    {0,0,0,0},\n')+'};\n'
    native+='#define AOT_VIRTUAL_CALL_COUNT %d\n'%len(virtual_calls)
    native+='static const AotVirtualCall aot_virtual_calls[] = {\n'
    native+=''.join('    {%du,%du,%du},\n'%(r['call_rva'],r['base_register'],r['slot']) for r in virtual_calls)
    native+=('' if virtual_calls else '    {0,0,0},\n')+'};\n'
    (program.out/'native_imports.h').write_text(native)
    observations=[]
    for name,record in sorted(metadata.get('observations',{}).items()):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name):raise ValueError('invalid observation name')
        rva,size=record['rva'],record['size']
        if type(rva) is not int or type(size) is not int or not 0<=rva<=len(image.data) or not 0<size<=len(image.data)-rva:
            raise ValueError('observation outside image')
        observations.append((name,rva,size))
    pe,=struct.unpack_from('<I',program.source_bytes,0x3c)
    reloc_dir=struct.unpack_from('<II',program.source_bytes,pe+24+112+5*8)
    characteristics=struct.unpack_from('<H',program.source_bytes,pe+22)[0]
    text='/* Generated validated preferred-base image, including zero-filled BSS. */\n'
    text+='typedef struct {uint32_t rva;uint64_t value;} NativeRelocation;\n'
    text+='typedef struct {uint32_t iat_rva,target_rva;} NativeImport;\n'
    text+='typedef struct {const char *name;uint32_t rva,size;} NativeObservation;\n'
    text+='static const char kPeSha256[]="%s";\n'%program.source_sha256
    text+='static const uint64_t kPreferredBase=UINT64_C(%d);\n'%image.preferred_base
    text+='static const uint32_t kEntryRva=%du;\n'%image.entry_rva
    text+='static const int kCanRebase=%d;\n'%bool(reloc_dir[0] and reloc_dir[1] and not characteristics&1)
    text+='static const uint8_t kImageBytes[]={'+','.join(map(str,image.data))+'};\n'
    text+='static const uint8_t kImagePermissions[]={'+','.join(map(str,image.permissions))+'};\n'
    text+='static const NativeRelocation kRelocations[]={'+(','.join('{%du,UINT64_C(%d)}'%(r['rva'],r['old']) for r in image.relocations) or '{0,0}')+'};\n'
    text+='static const size_t kRelocationCount=%d;\n'%len(image.relocations)
    text+='static const NativeImport kImports[]={'+(','.join('{%du,%du}'%(r['iat_rva'],r['target_rva']) for r in image.imports) or '{0,0}')+'};\n'
    text+='static const size_t kImportCount=%d;\n'%len(image.imports)
    text+='static const uint32_t kThunks[]={'+(','.join(str(r)+'u' for r in thunks) or '0')+'};\n'
    text+='static const size_t kThunkCount=%d;\n'%len(thunks)
    text+='static const uint32_t kD3DMethodThunks[]={'+','.join(str(r)+'u' for r in method_thunks)+'};\n'
    text+='static const AotInstruction kInstructions[]={'+','.join('{%du,%du,%du,0,UINT64_C(%d)}'%r for r in rows)+'};\n'
    text+='static const size_t kInstructionCount=%d;\n'%len(rows)
    text+='static const NativeObservation kObservations[]={'+(','.join('{"%s",%du,%du}'%r for r in observations) or '{"",0,0}')+'};\n'
    text+='static const size_t kObservationCount=%d;\n'%len(observations)
    (program.out/'native_image.h').write_text(text)
    program.virtual_calls=virtual_calls
    return calls,rows,observations


def output_directory(path):
    path=Path(path).resolve();base=ROOT/'build/draw-bridge'
    if not path.is_relative_to(base) or path==base:
        raise ValueError('D3D11 outputs must remain in their new profile; previous profiles are immutable')
    if not path.relative_to(base).parts[0].endswith('-v2'):
        raise ValueError('lifetime-v2 output requires a new -v2 root; old evidence is immutable')
    if path.relative_to(base).parts[0] in ('fixtures','fixtures-optimized-python','lifter','lift-tests'):
        raise ValueError('producer fixture/tool evidence is not a Program output directory')
    return path


def default_dxmt_config():
    return backend.config()


def preserve_diagnostics(out,paths):
    """Bind failure bytes before a retry can overwrite convenience paths."""
    directory=out/'failure-artifacts';directory.mkdir(exist_ok=True)
    copies={}
    for path in paths:
        path=Path(path)
        if not path.is_file():continue
        saved=directory/(sha(path)+'-'+path.name)
        if saved.exists():
            if sha(saved)!=sha(path):raise ValueError('immutable failure diagnostic changed')
        else:shutil.copy2(path,saved)
        copies[str(saved)]=sha(saved)
    return copies


class Program:
    def __init__(self,pe_path,out_dir=None,optimization='O3',metadata=None,metadata_sources=()):
        from draw_bridge.lift import lift_pe,build_ret_shim
        if optimization not in ('O3','O0'):raise ValueError('unsupported native optimization')
        self.out=output_directory(out_dir or ROOT/'build/draw-bridge/program-v2'/Path(pe_path).stem)
        self.path=Path(pe_path).resolve(strict=True);self.source_bytes=self.path.read_bytes()
        self.source_sha256=hashlib.sha256(self.source_bytes).hexdigest();self.optimization=optimization
        self.out.mkdir(parents=True,exist_ok=True);(self.out/'cache/dxmt').mkdir(parents=True,exist_ok=True)
        self.config=default_dxmt_config();metadata=json.loads(json.dumps(metadata or {}))
        if metadata.get('pe_sha256',self.source_sha256)!=self.source_sha256:raise ValueError('metadata refers to another PE')
        self.metadata_sources=[str(Path(p).resolve(strict=True)) for p in metadata_sources]
        with (self.out/'.program-build.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            attempt={'schema':1,'status':'BUILD_STARTED_NOT_EXECUTED','input_sha256':self.source_sha256,
                     'producer_sha256':sha(__file__),'optimization':optimization}
            graphics.save(self.out/'build-attempt.json',attempt)
            (self.out/'native-build.log').write_text('')
            try:
                # Fail dependency discovery before any expensive lift, and never
                # substitute a stub when real DXMT is not ready.
                library,_,_=backend.provenance(self.config)
                self.image=load_image(self.source_bytes)
                if {r['signature'] for r in self.image.imports}!={9,100}:raise ValueError('Program requires the closed ExitProcess/D3D11CreateDevice imports')
                (self.out/'input.exe').write_bytes(self.source_bytes)
                (self.out/'fixture-metadata.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
                self.manifest=json.loads(json.dumps(lift_pe(self.out/'input.exe',self.out/'compiler')))
                verify_lift(self.out/'compiler',self.manifest,self.source_sha256,'aot_entry')
                self.ret_manifest=json.loads(json.dumps(build_ret_shim(self.out/'ret-shim')))
                self.ret_source_sha256=sha(self.out/'ret-shim/synthetic-ret.exe');self.verify_lifts()
                calls,self.instructions,self.observations=generate_headers(self,metadata)
                log=self.out/'native-build.log';log.write_text('')
                self.tools=self.discover_tools(log)
                before,graphs,library,library_graph=self.discover_inputs(write=True,log=log)
                objects=[];commands=[]
                for name,compiler,flags in self.compilation_units():
                    obj=self.out/(name+'.o');command=[compiler,*flags,'-c',HERE/name,'-o',obj]
                    run_command(command,log,graphics.environment(self.out));objects.append(obj);commands.append(list(map(str,command)))
                unchanged(before);self.verify_lifts()
                # Generated C/C++ objects enter the link identity before link.
                link_inputs={**before,**snapshot(objects)}
                obj=self.out/'compiler'/('arm64-o0.o' if optimization=='O0' else 'arm64.o')
                ret_obj=self.out/'ret-shim'/('arm64-o0.o' if optimization=='O0' else 'arm64.o')
                fd,name=tempfile.mkstemp(prefix='.draw-',dir=self.out);os.close(fd);temporary=Path(name)
                command=[self.tools['clang++'],'-arch','arm64','-isysroot',self.tools['sdk'],
                         '--ld-path='+self.tools['ld'],*objects,obj,ret_obj,library,
                         '-Wl,-rpath,'+str(library.parent),'-o',temporary]
                try:
                    run_command(command,log,graphics.environment(self.out))
                    run_command([self.tools['codesign'],'--force','--sign','-','--identifier','org.peaotlab.draw',temporary],log)
                    run_command([self.tools['codesign'],'--verify','--strict',temporary],log)
                    info=graphics.macho(temporary)
                    if info['filetype']!=2:raise ValueError('linked output is not thin ARM64 executable')
                    actual_graph=graphics.library_graph(temporary,temporary)
                    if set(actual_graph['nodes'])-{str(temporary)}!=set(library_graph['nodes']):raise ValueError('actual executable library graph differs from pinned DXMT closure')
                    unchanged(link_inputs);self.verify_lifts()
                    after,graphs_after,library_after,graph_after=self.discover_inputs()
                    if before!=after or graphs!=graphs_after or library!=library_after or library_graph!=graph_after:
                        raise ValueError('C/C++/DXMT build input closure changed')
                    self.executable_sha256=sha(temporary);self.executable=self.out/('draw-'+self.executable_sha256)
                    if self.executable.exists():
                        if sha(self.executable)!=self.executable_sha256:raise ValueError('immutable executable path changed')
                    else:shutil.copy2(temporary,self.executable)
                    self.executable.chmod(0o755)
                finally:temporary.unlink(missing_ok=True)
                executable_graph=graphics.library_graph(self.executable,self.executable)
                artifacts=[self.executable,*objects,self.out/'native_imports.h',self.out/'native_image.h',
                           self.out/'native-build.log',*[self.out/(name+'.d') for name,_,_ in self.compilation_units()]]
                self.build_manifest={'schema':1,'status':'BUILT_NATIVE_DRAW_LIFETIME_V2_NOT_EXECUTED',
                    'input_path':str(self.path),'input_sha256':self.source_sha256,'optimization':optimization,
                    'config':self.config,'tools':self.tools,'metadata_sources':self.metadata_sources,
                    'native_inputs':link_inputs,'native_inputs_after':snapshot(link_inputs),
                    'compile_inputs_before':before,'compile_inputs_after':after,'dependency_graphs':graphs,
                    'native_executable':str(self.executable),'native_sha256':self.executable_sha256,
                    'calls':calls,'virtual_calls':self.virtual_calls,'imports':self.image.imports,
                    'observations':metadata.get('observations',{}),'library':str(library),
                    'library_graph':library_graph,'executable_graph':executable_graph,
                    'commands':commands+[list(map(str,command))],'artifacts':snapshot(artifacts),
                    'scope':'original Windows PE -> Remill ARM64 + typed D3D11 host + real native DXMT; build only, no guest/GPU result'}
                graphics.save(self.out/'program-build.json',self.build_manifest)
                graphics.save(self.out/'build-attempt.json',{**attempt,'status':self.build_manifest['status'],
                    'program_build_sha256':sha(self.out/'program-build.json')})
            except Exception as error:
                failure={**attempt,'status':'FAIL_NOT_EXECUTION_ACCEPTANCE','error':str(error),
                         'diagnostic_artifacts':preserve_diagnostics(self.out,[self.out/'native-build.log',
                             self.out/'compiler/commands.log',self.out/'ret-shim/commands.log'])}
                graphics.save(self.out/'build-attempt.json',failure)
                if not (self.out/'first-build-failure.json').exists():graphics.save(self.out/'first-build-failure.json',failure)
                raise

    def discover_tools(self,log=None):
        env=graphics.environment(self.out)
        tools={name:str(Path(run_command(['/usr/bin/xcrun','--find',name],log,env).strip()).resolve())
               for name in ('clang','clang++','ld')}
        tools['sdk']=run_command(['/usr/bin/xcrun','--show-sdk-path'],log,env).strip()
        tools.update(xcrun='/usr/bin/xcrun',python=str(Path(sys.executable).resolve()),nm='/usr/bin/nm',codesign='/usr/bin/codesign')
        return tools

    def compilation_units(self):
        common=['-arch','arm64','-isysroot',self.tools['sdk'],'-'+self.optimization,
                '-fno-lto','-I',str(self.out),'-Wall','-Wextra','-Werror']
        cpp=[*common,'-std=c++17','-Wno-extern-c-compat','-fno-rtti','-fno-exceptions',
             '-I'+self.config['dxmt_source']+'/include/native/windows',
             '-I'+self.config['dxmt_source']+'/include/native/directx']
        return [('native_host.c',self.tools['clang'],[*common,'-std=c11']),
                ('runtime.c',self.tools['clang'],[*common,'-std=c11']),
                ('native_backend.cpp',self.tools['clang++'],cpp)]

    def discover_inputs(self,write=False,log=None):
        library,receipts,bound=backend.provenance(self.config)
        graph=graphics.library_graph(library,self.out/'placeholder-executable',[library.parent])
        graphics.require_graph_provenance(graph,bound)
        dependencies=[];graphs={}
        for name,compiler,flags in self.compilation_units():
            command=[compiler,*flags,'-M','-MT','probe',HERE/name]
            text=run_command(command,log,graphics.environment(self.out));graphs[name]=text
            path=self.out/(name+'.d')
            if write:path.write_text(text)
            elif path.read_text()!=text:raise ValueError('C/C++ actual dependency graph changed: '+name)
            dependencies.extend(graphics.dependency_paths(text));dependencies.append(path)
        obj='arm64-o0.o' if self.optimization=='O0' else 'arm64.o'
        paths=[*dependencies,*python_closure([Path(__file__),HERE/'lift.py',HERE/'loader.py',Path(graphics.__file__)]),
               *[value for key,value in self.tools.items() if key!='sdk'],*self.metadata_sources,self.path,
               self.out/'input.exe',self.out/'fixture-metadata.json',
               self.out/'compiler'/obj,self.out/'ret-shim'/obj,
               self.out/'compiler/manifest.json',self.out/'ret-shim/manifest.json',
               *receipts,graphics.SOURCE,*graph['nodes']]
        identities=snapshot(paths)
        identities.update(self.manifest['inputs_before']);identities.update(self.ret_manifest['inputs_before'])
        return identities,graphs,library,graph

    def verify_lifts(self):
        if sha(self.out/'input.exe')!=self.source_sha256 or sha(self.out/'ret-shim/synthetic-ret.exe')!=self.ret_source_sha256:
            raise ValueError('frozen PE input changed')
        verify_lift(self.out/'compiler',self.manifest,self.source_sha256,'aot_entry')
        verify_lift(self.out/'ret-shim',self.ret_manifest,self.ret_source_sha256,'aot_import_ret')

    @classmethod
    def from_build(cls,out_dir):
        self=cls.__new__(cls);self.out=output_directory(out_dir)
        record=graphics.read_json(self.out/'program-build.json');self.build_manifest=record
        self.path=Path(record['input_path']);self.source_sha256=record['input_sha256']
        self.source_bytes=(self.out/'input.exe').read_bytes();self.image=load_image(self.source_bytes)
        self.optimization=record['optimization'];self.config=record['config'];self.tools=record['tools']
        self.metadata_sources=record['metadata_sources'];self.executable=Path(record['native_executable'])
        self.executable_sha256=record['native_sha256']
        self.manifest=graphics.read_json(self.out/'compiler/manifest.json')
        self.ret_manifest=graphics.read_json(self.out/'ret-shim/manifest.json')
        self.ret_source_sha256=sha(self.out/'ret-shim/synthetic-ret.exe')
        self.verify_build();return self

    def verify_build(self):
        record=graphics.read_json(self.out/'program-build.json')
        if record!=self.build_manifest or record.get('schema')!=1 or record.get('status')!='BUILT_NATIVE_DRAW_LIFETIME_V2_NOT_EXECUTED':
            raise ValueError('build record changed or not ready')
        if self.optimization not in ('O3','O0') or self.config!=default_dxmt_config():raise ValueError('unknown build profile')
        if self.executable!=self.out/('draw-'+self.executable_sha256) or sha(self.executable)!=self.executable_sha256:
            raise ValueError('actual immutable native executable changed')
        unchanged(record['native_inputs']);unchanged(record['artifacts']);self.verify_lifts()
        if record['native_inputs']!=record['native_inputs_after'] or record['compile_inputs_before']!=record['compile_inputs_after']:
            raise ValueError('recorded build inputs differ')
        if self.discover_tools()!=self.tools:raise ValueError('selected actual compiler/linker/SDK changed')
        identities,graphs,library,graph=self.discover_inputs()
        objects=[self.out/(name+'.o') for name,_,_ in self.compilation_units()]
        if identities!=record['compile_inputs_before'] or {**identities,**snapshot(objects)}!=record['native_inputs']:
            raise ValueError('native source/tool/header/object closure omitted or changed')
        if graphs!=record['dependency_graphs'] or str(library)!=record['library'] or graph!=record['library_graph']:
            raise ValueError('actual D3D11 library or dependency graph changed')
        expected_artifacts=[self.executable,*objects,self.out/'native_imports.h',self.out/'native_image.h',
                            self.out/'native-build.log',*[self.out/(name+'.d') for name,_,_ in self.compilation_units()]]
        if snapshot(expected_artifacts)!=record['artifacts']:raise ValueError('build artifact closure incomplete')
        if graphics.library_graph(self.executable,self.executable)!=record['executable_graph']:
            raise ValueError('actual executable loading graph changed')
        run_command([self.tools['codesign'],'--verify','--strict',self.executable])
        return record

    def validate_execution(self,result,returncode,base=None):
        if type(returncode) is not int or not isinstance(result,dict):raise ValueError('invalid execution result type')
        if result.get('outcome')=='HOST_ERROR':
            if returncode!=64 or set(result) not in ({'outcome','error'},{'outcome','session_error','setup_status'}):
                raise ValueError('host error contract mismatch')
            return
        fields={'outcome','aot_status','pe_sha256','image_base','entry_rva','entry_arguments',
                'exit_requested','exit_code','exit_pc','exit_rsp','exit_depth','returned','steps','call_depth',
                'fault','rax','rsp','rip','d3d_cleanup_result','d3d_before_cleanup','d3d_after_cleanup','observations'}
        if set(result)!=fields:raise ValueError('host result fields missing or unknown')
        integers=fields-{'outcome','pe_sha256','fault','d3d_before_cleanup','d3d_after_cleanup','observations'}
        if any(not graphics.uint(result[name],0xffffffffffffffff) for name in integers):raise ValueError('host result is not unsigned integer')
        fault=result['fault']
        if not isinstance(fault,dict) or set(fault)!={'status','pc','address','width','access'} or any(not graphics.uint(v,0xffffffffffffffff) for v in fault.values()):
            raise ValueError('invalid fault result')
        for key in ('d3d_before_cleanup','d3d_after_cleanup'):
            if not isinstance(result[key],dict) or set(result[key])!=STATS_FIELDS or any(not graphics.uint(v,0xffffffffffffffff) for v in result[key].values()):
                raise ValueError('D3D statistics fields/types differ')
        expected_observations=self.build_manifest['observations']
        if not isinstance(result['observations'],dict) or set(result['observations'])!=set(expected_observations):raise ValueError('observation closure differs')
        for name,item in expected_observations.items():
            value=result['observations'][name]
            if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{%d}'%(item['size']*2),value):raise ValueError('invalid observation bytes')
        if result['pe_sha256']!=self.source_sha256 or result['entry_rva']!=self.image.entry_rva or result['entry_arguments']!=0:
            raise ValueError('actual guest identity/entry mismatch')
        if result['image_base']!=(self.image.base if base is None else base):raise ValueError('actual image base mismatch')
        expected={'PROCESS_EXITED':0,'FUNCTION_RETURN':2,'FAULT':3}.get(result['outcome'])
        if expected is None or returncode!=expected:raise ValueError('host outcome/exit mismatch')
        if result['outcome']=='PROCESS_EXITED':
            if result['aot_status']!=11 or result['exit_requested']!=1 or result['returned']!=0 or fault['status']!=0 or result['exit_code']>0xffffffff:
                raise ValueError('explicit process-exit contract differs')
        elif result['outcome']=='FUNCTION_RETURN':
            if result['aot_status']!=0 or result['exit_requested'] or result['returned']!=1 or fault['status']:
                raise ValueError('function-return contract differs')
        elif not (1<=result['aot_status']<=17 and result['aot_status']!=11 and fault['status']==result['aot_status']):
            raise ValueError('fault endpoint contract differs')

    def run(self,*,base=None,budget=None,log_path=None):
        for value,name in ((base,'base'),(budget,'budget')):
            if value is not None and (type(value) is not int or not 0<=value<=0xffffffffffffffff):raise ValueError('invalid '+name)
        self.verify_build()
        command=[str(self.executable)]
        if base is not None:command+=['--base',str(base)]
        if budget is not None:command+=['--budget',str(budget)]
        if log_path is None:
            directory=self.out/'runs';directory.mkdir(exist_ok=True)
            directory=Path(tempfile.mkdtemp(prefix='run-',dir=directory));record_path=directory/'evidence.json'
        else:
            record_path=Path(log_path).resolve();output_directory(record_path.parent);record_path.parent.mkdir(parents=True,exist_ok=True)
        stdout_path=record_path.with_suffix('.stdout');stderr_path=record_path.with_suffix('.stderr')
        inputs={**self.build_manifest['native_inputs'],**self.build_manifest['artifacts'],**snapshot([self.out/'program-build.json'])}
        record={'schema':1,'status':'STARTED_NOT_ACCEPTED','command':command,'program_out':str(self.out),
                'requested_base':base,'requested_budget':budget,
                'inputs_before':inputs,'stdout_path':str(stdout_path),'stderr_path':str(stderr_path),
                'scope':'actual guest execution observation; pixel success requires test_program checks'}
        graphics.save(record_path,record)
        try:
            completed=subprocess.run(command,env=graphics.environment(self.out,images=True),capture_output=True,text=True)
            stdout_path.write_text(completed.stdout);stderr_path.write_text(completed.stderr)
            record.update(returncode=completed.returncode,outputs=snapshot([stdout_path,stderr_path]))
            unchanged(inputs);self.verify_build()
            loaded=graphics.loaded_images(completed.stderr,self.executable,self.build_manifest['library_graph']['nodes'])
            result=graphics.strict_json(completed.stdout)
            self.validate_execution(result,completed.returncode,base)
            record.update(status='ACTUAL_EXECUTION_OBSERVED_NOT_PIXEL_ACCEPTED',result=result,
                          inputs_after=snapshot(inputs),loaded_images=loaded,
                          diagnostic_lines=[line for line in completed.stderr.splitlines() if not line.startswith('dyld[')])
            graphics.save(record_path,record)
            return {**result,'host_returncode':completed.returncode,'actual_executable_sha256':self.executable_sha256,
                    'run_evidence':str(record_path),'loaded_images':loaded}
        except Exception as error:
            record.update(status='FAIL_NOT_EXECUTION_ACCEPTANCE',error=str(error),
                          diagnostic_artifacts=preserve_diagnostics(self.out,[stdout_path,stderr_path]))
            graphics.save(record_path,record)
            first=self.out/'first-run-failure.json'
            if not first.exists():graphics.save(first,record)
            raise


def verify_run(path):
    """Read saved stdout/stderr and actual dependency identities; never run guest."""
    record=graphics.read_json(path)
    if record.get('status')!='ACTUAL_EXECUTION_OBSERVED_NOT_PIXEL_ACCEPTED':raise ValueError('run not verified')
    unchanged(record['inputs_before']);unchanged(record['outputs'])
    if record['inputs_before']!=record['inputs_after']:raise ValueError('run input identities differ')
    program=Program.from_build(record['program_out'])
    expected_inputs={**program.build_manifest['native_inputs'],**program.build_manifest['artifacts'],
                     **snapshot([program.out/'program-build.json'])}
    if record['inputs_before']!=expected_inputs:raise ValueError('run input closure incomplete')
    if record['outputs']!=snapshot([record['stdout_path'],record['stderr_path']]):raise ValueError('run output closure incomplete')
    expected_command=[str(program.executable)]
    for key,flag in (('requested_base','--base'),('requested_budget','--budget')):
        value=record[key]
        if value is not None:
            if not graphics.uint(value,0xffffffffffffffff):raise ValueError('invalid recorded command argument')
            expected_command += [flag,str(value)]
    if record['command']!=expected_command:raise ValueError('recorded executed command differs')
    parsed=graphics.strict_json(Path(record['stdout_path']).read_text())
    if parsed!=record['result']:raise ValueError('saved actual stdout differs from result')
    program.validate_execution(parsed,record['returncode'],record['requested_base'])
    loaded=graphics.loaded_images(Path(record['stderr_path']).read_text(),program.executable,program.build_manifest['library_graph']['nodes'])
    if loaded!=record['loaded_images']:raise ValueError('saved actual dyld image set differs')
    return record
