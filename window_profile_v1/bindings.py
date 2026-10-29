"""Versioned save/load Win32 PE + isolated INC producer build and observation.

Build and launch an independent ARM64 executable from an original PE.

Python is a build/test driver only. The emitted executable directly embeds and
runs the guest image with a native C host; it does not load a Python runtime.
"""
import ast,fcntl,hashlib,json,os,re,shlex,shutil,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=ROOT/'window_bridge'
sys.path.insert(0,str(ROOT))
from window_inc_v1.loader import load_image,THUNK_START
from window_inc_v1 import lift as lifter
from window_profile_v1.profile import validate as validate_profile
from graphics_stage5 import d3d11_probe as graphics
from native_window import build_v2 as backend
METHOD_SIGNATURES=(101,110,111,112,120,121,122,123,130,131,132,140,141,142,143,144,145,146,150,151,152,153)
TEST_EVENTS=frozenset(('right','left','escape','close','right-repeat','left-repeat','right-up','left-up'))
VIRTUAL_SLOTS=lifter.VIRTUAL_SLOTS
STATS_FIELDS=frozenset(('create_device_calls','create_texture_calls','create_rtv_calls','clear_calls',
    'copy_calls','map_calls','unmap_calls','get_removed_calls','release_calls','exit_calls','this_checks',
    'created','guest_released','cleanup_releases','cleanup_unmaps','map_bytes_copied','map_postcall_failures',
    'live_objects','active_maps','last_native_release',
    'create_vs_calls','create_ps_calls','create_rasterizer_calls','om_set_calls','rs_set_calls',
    'viewport_calls','topology_calls','vs_set_calls','ps_set_calls','draw_calls',
    'create_swapchain_calls','present_calls','get_buffer_calls','clear_state_calls','flush_calls',
    'cleanup_clear_state_calls','cleanup_flush_calls'))
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
        'source_sha256':{'window_inc_v1/lift.py','window_inc_v1/build_lifter.py','window_inc_v1/BASELINE.json','window_inc_v1/inc-base32-v1.patch','integration_stage3/lifter_layout.cpp',
                         'window_bridge/xed-only-v1.patch','window_bridge/transactions-v1.patch',
                         'window_bridge/aot-profile-v1.patch','window_bridge/import-calls-v1.patch','window_bridge/vtable-calls-v1.patch','window_bridge/window-calls-v1.patch'},
        'external_source_sha256':{'memory_stage2/image_loader.py','window_inc_v1/loader.py','callback_bridge/imports_v1.py','fixtures.py'}}
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
    if (current.get('lifter_sha256')!=sha(lifter.LIFTER) or
        current.get('lifter_build_manifest_sha256')!=sha(lifter.TOOL_OUT/'build-manifest.json') or
        current.get('semantics_sha256')!=sha(lifter.BUILD/'lib/Arch/X86/Runtime/amd64.bc')):
        raise ValueError('actual lifter/semantics/build receipt changed')
    lifter.validate_inc_metadata(current['instructions'])
    for obj in ('arm64.o','arm64-o0.o'):
        output=subprocess.check_output(['nm','-g','-U',str(directory/obj)],text=True)
        if {line.split()[-1] for line in output.splitlines() if line.strip()}!={'_'+symbol}:
            raise ValueError('unexpected exported lifted symbols')
    return current

def generate_headers(program,metadata,write=True):
    image=program.image;merged={};virtual=[];register=[];calls=[]
    import_slots={r['iat_rva']:r for r in image.imports}
    for root in program.roots:
        manifest=root['manifest']
        root_virtual=[];root_register=[]
        for ins in manifest['instructions']:
            rva,length=ins['rva'],ins['length'];kind=ins['kind']
            if type(rva) is not int or type(length) is not int or not 0<=rva<=len(image.data) or not 0<length<=15 or length>len(image.data)-rva:
                raise ValueError('instruction bounds/shape differs')
            if bytes(image.data[rva:rva+length])!=bytes.fromhex(ins['bytes']):raise ValueError('decoded bytes differ from original PE')
            if kind==3:root_virtual.append(lifter.validate_virtual_instruction(ins))
            elif kind==4:root_register.append(lifter.validate_register_instruction(ins))
            elif kind not in (0,1,2):raise ValueError('unknown instruction kind')
            if rva in merged and merged[rva]!=ins:raise ValueError('conflicting multi-root instruction')
            merged[rva]=ins
        if root_virtual!=manifest.get('virtual_calls') or root_register!=manifest.get('register_calls'):
            raise ValueError('root callsite table differs from actual instructions')
    for rva,ins in sorted(merged.items()):
        if ins['kind']==3:virtual.append(lifter.validate_virtual_instruction(ins))
        elif ins['kind']==4:register.append(lifter.validate_register_instruction(ins))
        if ins.get('iat_slot_rva'):
            slot=ins['iat_slot_rva']
            if ins['kind']!=1 or slot not in import_slots:raise ValueError('unbound IAT call')
            binding=import_slots[slot]
            if ins.get('signature')!=binding['signature'] or ins.get('target_rva')!=binding['target_rva']:
                raise ValueError('IAT metadata target/signature differs')
            calls.append({'call_rva':rva,'iat_rva':slot,'target_rva':binding['target_rva'],'signature':binding['signature']})
    if [merged[r] for r in sorted(merged)]!=program.root_manifest['instructions']:raise ValueError('multi-root merged side table differs')
    method_thunks=[THUNK_START+signature*4096 for signature in METHOD_SIGNATURES]
    thunks=sorted({r['target_rva'] for r in image.imports}|set(method_thunks))
    if len(thunks)!=len(image.imports)+len(METHOD_SIGNATURES):raise ValueError('import/method thunk collision')
    rows=[(r,i['length'],i['kind'],i.get('target_rva',0)) for r,i in sorted(merged.items())]
    for thunk in thunks:
        if any(r<=thunk<r+n or thunk<=r<thunk+1 for r,n,_,_ in rows):raise ValueError('synthetic RET overlaps actual guest code')
        rows.append((thunk,1,2,0))
    rows.sort()
    native='/* Exact per-image import closure and per-callsite metadata. */\n'
    for macro,ctype,name,records,fields in [
        ('AOT_IMPORT_CALL_COUNT','AotImportCall','aot_import_calls',calls,('call_rva','iat_rva','target_rva','signature')),
        ('AOT_VIRTUAL_CALL_COUNT','AotVirtualCall','aot_virtual_calls',virtual,('call_rva','base_register','slot')),
        ('AOT_REGISTER_CALL_COUNT','AotRegisterCall','aot_register_calls',register,('call_rva','operand_register')),
        ('AOT_IMPORT_TARGET_COUNT','AotImportTarget','aot_import_targets',image.imports,('target_rva','signature'))]:
        native+='#define %s %d\nstatic const %s %s[]={\n'%(macro,len(records),ctype,name)
        native+=''.join('{'+','.join(str(r[f])+'u' for f in fields)+'},\n' for r in records)
        native+=('' if records else '{'+','.join('0' for f in fields)+'},\n')+'};\n'
    if write:(program.out/'native_imports.h').write_text(native)
    observations=[]
    for name,record in sorted(metadata['observations'].items()):
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name):raise ValueError('invalid observation name')
        rva,size=record['rva'],record['size']
        if type(rva) is not int or type(size) is not int or not 0<=rva<=len(image.data) or not 0<size<=len(image.data)-rva:raise ValueError('observation outside image')
        observations.append((name,rva,size))
    pe,=struct.unpack_from('<I',program.source_bytes,0x3c)
    reloc_dir=struct.unpack_from('<II',program.source_bytes,pe+24+112+5*8);characteristics=struct.unpack_from('<H',program.source_bytes,pe+22)[0]
    text='/* Original preferred-base PE image including BSS, no host game state. */\n'
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
    text+='static const uint32_t kThunks[]={'+','.join(str(r)+'u' for r in thunks)+'};\n'
    text+='static const size_t kThunkCount=%d;\n'%len(thunks)
    text+='static const uint32_t kD3DMethodThunks[]={'+','.join(str(r)+'u' for r in method_thunks)+'};\n'
    text+='static const AotInstruction kInstructions[]={'+','.join('{%du,%du,%du,0,UINT64_C(%d)}'%r for r in rows)+'};\n'
    text+='static const size_t kInstructionCount=%d;\n'%len(rows)
    text+='static const NativeObservation kObservations[]={'+(','.join('{"%s",%du,%du}'%r for r in observations) or '{0,0,0}')+'};\n'
    text+='static const size_t kObservationCount=%d;\n'%len(observations)
    for root in program.roots[1:]:text+='extern void *%s(void*,uint64_t,void*);\n'%root['symbol']
    text+='static const AotWindowCallback kCallbacks[]={'+','.join('{%du,AOT_WINDOW_WNDPROC,%s}'%(r['rva'],r['symbol']) for r in program.roots[1:])+'};\n'
    text+='static const size_t kCallbackCount=%d;\n'%len(program.roots[1:])
    text+='static const char kSaveName[]='+json.dumps(metadata['save_observation'])+';\n'
    if write:(program.out/'native_image.h').write_text(text)
    program.generated_headers={'native_imports.h':native,'native_image.h':text}
    program.virtual_calls=virtual;program.register_calls=register
    return calls,rows,observations

def output_directory(path):
    path=Path(path).absolute()
    bases=[ROOT/'build/window-profile-v1',ROOT/'build/migration-v3']
    if path!=path.resolve() or not any(path.is_relative_to(base) and path!=base for base in bases):
        raise ValueError('fresh output beneath build/window-profile-v1 or build/migration-v3 required')
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


# Configuration is supplied by the caller and bound to the input PE hash.


class Program:
    def __init__(self,pe_path,out_dir=None,optimization='O3',metadata=None,metadata_sources=()):
        from window_inc_v1.lift import lift_roots,build_ret_shim
        if optimization not in ('O3','O0'):raise ValueError('unsupported native optimization')
        self.out=output_directory(out_dir or ROOT/'build/window-profile-v1/program-default')
        self.path=Path(pe_path).resolve(strict=True);self.source_bytes=self.path.read_bytes()
        self.source_sha256=hashlib.sha256(self.source_bytes).hexdigest();self.optimization=optimization
        self.out.mkdir(parents=True,exist_ok=True);(self.out/'cache/dxmt').mkdir(parents=True,exist_ok=True)
        if (self.out/'started.json').exists():raise ValueError('preserve existing build attempt; use a new output directory')
        with (self.out/'started.json').open('x') as stream:
            json.dump({'status':'STARTED_NOT_BUILT_NOT_EXECUTED','input_sha256':self.source_sha256,
                'producer_sha256':sha(__file__),'optimization':optimization,'gpu_executions':0,'windows_executions':0,'guest_executions':0},stream,indent=2)
            stream.write('\n')
        self.config=default_dxmt_config()
        metadata,self.image,_=validate_profile(self.source_bytes,metadata)
        self.metadata_sources=sorted({str(Path(p).resolve(strict=True)) for p in metadata_sources})
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
                metadata,self.image,_=validate_profile(self.source_bytes,metadata)
                (self.out/'input.exe').write_bytes(self.source_bytes)
                (self.out/'window-profile.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
                self.root_manifest=json.loads(json.dumps(lift_roots(self.out/'input.exe',self.out/'compiler',metadata['callback_rvas'])))
                self.roots=[self.root_manifest['main'],*self.root_manifest['roots']]
                self.manifest=self.roots[0]['manifest']
                self.ret_manifest=json.loads(json.dumps(build_ret_shim(self.out/'ret-shim')))
                self.ret_source_sha256=sha(self.out/'ret-shim/synthetic-ret.exe');self.verify_lifts()
                calls,self.instructions,self.observations=generate_headers(self,metadata)
                log=self.out/'native-build.log';log.write_text('')
                self.tools=self.discover_tools(log)
                before,graphs,library,library_graph=self.discover_inputs(write=True,log=log)
                objects=[];commands=[]
                for name,compiler,flags in self.compilation_units():
                    obj=self.out/(name.replace('/','__')+'.o');command=[compiler,*flags,'-c',HERE/name,'-o',obj]
                    run_command(command,log,graphics.environment(self.out));objects.append(obj);commands.append(list(map(str,command)))
                unchanged(before);self.verify_lifts()
                # Generated C/C++ objects enter the link identity before link.
                link_inputs={**before,**snapshot(objects)}
                root_objects=[Path(r['directory'])/('arm64-o0.o' if optimization=='O0' else 'arm64.o') for r in self.roots]
                ret_obj=self.out/'ret-shim'/('arm64-o0.o' if optimization=='O0' else 'arm64.o')
                fd,name=tempfile.mkstemp(prefix='.window-',dir=self.out);os.close(fd);temporary=Path(name)
                command=[self.tools['clang++'],'-arch','arm64','-isysroot',self.tools['sdk'],
                         '--ld-path='+self.tools['ld'],*objects,*root_objects,ret_obj,library,
                         next(p for p in library_graph['nodes'] if Path(p).name=='winemetal.dylib'),
                         '-framework','Cocoa','-framework','Metal','-framework','QuartzCore',
                         *['-Wl,-rpath,'+p for p in sorted({str(Path(node).parent) for node in library_graph['nodes']})],'-o',temporary]
                try:
                    run_command(command,log,graphics.environment(self.out))
                    run_command([self.tools['codesign'],'--force','--sign','-','--identifier','org.peaotlab.window',temporary],log)
                    run_command([self.tools['codesign'],'--verify','--strict',temporary],log)
                    info=graphics.macho(temporary)
                    if info['filetype']!=2:raise ValueError('linked output is not thin ARM64 executable')
                    actual_graph=graphics.library_graph(temporary,temporary)
                    if set(actual_graph['nodes'])-{str(temporary)}!=set(library_graph['nodes']):raise ValueError('actual executable library graph differs from pinned DXMT closure')
                    unchanged(link_inputs);self.verify_lifts()
                    after,graphs_after,library_after,graph_after=self.discover_inputs()
                    if before!=after or graphs!=graphs_after or library!=library_after or library_graph!=graph_after:
                        raise ValueError('C/C++/DXMT build input closure changed')
                    self.executable_sha256=sha(temporary);self.executable=self.out/('window-'+self.executable_sha256)
                    if self.executable.exists():
                        if sha(self.executable)!=self.executable_sha256:raise ValueError('immutable executable path changed')
                    else:shutil.copy2(temporary,self.executable)
                    self.executable.chmod(0o755)
                except Exception:
                    preserve_diagnostics(self.out,[temporary]);raise
                finally:temporary.unlink(missing_ok=True)
                executable_graph=graphics.library_graph(self.executable,self.executable)
                artifacts=[self.executable,*objects,self.out/'native_imports.h',self.out/'native_image.h',
                           self.out/'native-build.log',*[self.out/(name.replace('/','__')+'.d') for name,_,_ in self.compilation_units()]]
                self.build_manifest={'schema':1,'status':'BUILT_NATIVE_SAVE_LOAD_WINDOW_PE_NOT_EXECUTED',
                    'input_path':str(self.path),'input_sha256':self.source_sha256,'optimization':optimization,
                    'config':self.config,'tools':self.tools,'metadata_sources':self.metadata_sources,
                    'native_inputs':link_inputs,'native_inputs_after':snapshot(link_inputs),
                    'compile_inputs_before':before,'compile_inputs_after':after,'dependency_graphs':graphs,
                    'native_executable':str(self.executable),'native_sha256':self.executable_sha256,
                    'calls':calls,'virtual_calls':self.virtual_calls,'register_calls':self.register_calls,'imports':self.image.imports,
                    'callbacks':[{k:r[k] for k in ('rva','symbol','directory')} for r in self.roots[1:]],
                    'observations':metadata.get('observations',{}),'library':str(library),
                    'library_graph':library_graph,'executable_graph':executable_graph,
                    'commands':commands+[list(map(str,command))],'artifacts':snapshot(artifacts),
                    'scope':'caller PE and explicit profile -> real Remill ARM64; all native units rebuilt; closed window-inc-v1/runtime/backend limits remain; build is not execution acceptance'}
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
        # Preserve clang++'s invoked basename: resolving its symlink to clang
        # silently changes the object-only link driver's default C++ libraries.
        tools={name:str(Path(run_command(['/usr/bin/xcrun','--find',name],log,env).strip()).absolute())
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
        return [('window_host.c',self.tools['clang'],[*common,'-std=c11']),
                ('window_runtime/runtime.c',self.tools['clang'],[*common,'-std=c11']),
                ('native_backend.cpp',self.tools['clang++'],cpp),
                ('native_backend_window.cpp',self.tools['clang++'],cpp),
                ('cocoa_host.mm',self.tools['clang++'],[*common,'-std=c++20','-Wno-deprecated-declarations'])]

    def discover_inputs(self,write=False,log=None):
        library,receipts,bound=backend.provenance(self.config)
        graph=graphics.library_graph(library,self.out/'placeholder-executable',[library.parent])
        graphics.require_graph_provenance(graph,bound)
        dependencies=[];graphs={}
        for name,compiler,flags in self.compilation_units():
            command=[compiler,*flags,'-M','-MT','probe',HERE/name]
            text=run_command(command,log,graphics.environment(self.out));graphs[name]=text
            path=self.out/(name.replace('/','__')+'.d')
            if write:path.write_text(text)
            elif path.read_text()!=text:raise ValueError('C/C++ actual dependency graph changed: '+name)
            actual=graphics.dependency_paths(text)
            generated={'window_host.c':'native_image.h','window_runtime/runtime.c':'native_imports.h'}.get(name)
            if generated:
                wanted=(self.out/generated).resolve()
                same_name=[Path(p).resolve() for p in actual if Path(p).name==generated]
                if same_name!=[wanted]:raise ValueError('compilation did not consume exact new generated '+generated)
            dependencies.extend(actual);dependencies.append(path)
        obj='arm64-o0.o' if self.optimization=='O0' else 'arm64.o'
        paths=[*dependencies,*python_closure([Path(__file__),ROOT/'window_inc_v1/lift.py',ROOT/'window_inc_v1/loader.py',Path(graphics.__file__)]),
               *[value for key,value in self.tools.items() if key!='sdk'],*self.metadata_sources,self.path,
               self.out/'input.exe',self.out/'window-profile.json',
               *[Path(r['directory'])/obj for r in self.roots],self.out/'ret-shim'/obj,
               *[Path(r['directory'])/'manifest.json' for r in self.roots],self.out/'compiler/roots.json',self.out/'ret-shim/manifest.json',
               *receipts,graphics.SOURCE,*graph['nodes']]
        identities=snapshot(paths)
        for root in self.roots:identities.update(root['manifest']['inputs_before'])
        identities.update(self.ret_manifest['inputs_before'])
        return identities,graphs,library,graph

    def verify_lifts(self):
        if sha(self.out/'input.exe')!=self.source_sha256 or sha(self.out/'ret-shim/synthetic-ret.exe')!=self.ret_source_sha256:
            raise ValueError('frozen PE input changed')
        if graphics.read_json(self.out/'compiler/roots.json')!=self.root_manifest:raise ValueError('multi-root manifest changed')
        expected=[self.root_manifest['main'],*self.root_manifest['roots']]
        if expected!=self.roots or self.root_manifest['input_sha256']!=self.source_sha256:raise ValueError('root descriptor identity differs')
        metadata=graphics.read_json(self.out/'window-profile.json')
        if [r['rva'] for r in self.roots[1:]]!=metadata['callback_rvas']:raise ValueError('explicit callback root set changed')
        seen=set()
        for index,root in enumerate(self.roots):
            symbol='aot_entry' if index==0 else 'aot_window_proc_%x'%root['rva']
            directory=self.out/'compiler'/('main' if index==0 else 'window-proc-%x'%root['rva'])
            if root['symbol']!=symbol or Path(root['directory']).resolve()!=directory:raise ValueError('root namespace/directory differs')
            if root['rva'] in seen or root['manifest']['root_rva']!=root['rva'] or root['manifest']['original_entry_rva']!=self.image.entry_rva:raise ValueError('duplicate/mismatched root')
            seen.add(root['rva']);verify_lift(root['directory'],root['manifest'],self.source_sha256,root['symbol'])
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
        self.root_manifest=graphics.read_json(self.out/'compiler/roots.json');self.roots=[self.root_manifest['main'],*self.root_manifest['roots']]
        self.manifest=self.roots[0]['manifest']
        self.ret_manifest=graphics.read_json(self.out/'ret-shim/manifest.json')
        self.ret_source_sha256=sha(self.out/'ret-shim/synthetic-ret.exe')
        self.verify_build();return self

    def verify_build(self):
        record=graphics.read_json(self.out/'program-build.json')
        if record!=self.build_manifest or record.get('schema')!=1 or record.get('status')!='BUILT_NATIVE_SAVE_LOAD_WINDOW_PE_NOT_EXECUTED':
            raise ValueError('build record changed or not ready')
        if self.optimization not in ('O3','O0') or self.config!=default_dxmt_config():raise ValueError('unknown build profile')
        if self.executable!=self.out/('window-'+self.executable_sha256) or sha(self.executable)!=self.executable_sha256:
            raise ValueError('actual immutable native executable changed')
        unchanged(record['native_inputs']);unchanged(record['artifacts']);self.verify_lifts()
        metadata=graphics.read_json(self.out/'window-profile.json')
        validate_profile(self.source_bytes,metadata)
        calls,instructions,observations=generate_headers(self,metadata,write=False)
        if any((self.out/name).read_text()!=text for name,text in self.generated_headers.items()):raise ValueError('generated header differs from verified PE/root metadata')
        callbacks=[{k:r[k] for k in ('rva','symbol','directory')} for r in self.roots[1:]]
        if calls!=record['calls'] or self.virtual_calls!=record['virtual_calls'] or self.register_calls!=record['register_calls'] or callbacks!=record['callbacks'] or self.image.imports!=record['imports'] or metadata['observations']!=record['observations']:raise ValueError('recorded API/root/observation metadata differs')
        if record['native_inputs']!=record['native_inputs_after'] or record['compile_inputs_before']!=record['compile_inputs_after']:
            raise ValueError('recorded build inputs differ')
        if self.discover_tools()!=self.tools:raise ValueError('selected actual compiler/linker/SDK changed')
        identities,graphs,library,graph=self.discover_inputs()
        objects=[self.out/(name.replace('/','__')+'.o') for name,_,_ in self.compilation_units()]
        if identities!=record['compile_inputs_before'] or {**identities,**snapshot(objects)}!=record['native_inputs']:
            raise ValueError('native source/tool/header/object closure omitted or changed')
        if graphs!=record['dependency_graphs'] or str(library)!=record['library'] or graph!=record['library_graph']:
            raise ValueError('actual D3D11 library or dependency graph changed')
        expected_artifacts=[self.executable,*objects,self.out/'native_imports.h',self.out/'native_image.h',
                            self.out/'native-build.log',*[self.out/(name.replace('/','__')+'.d') for name,_,_ in self.compilation_units()]]
        if snapshot(expected_artifacts)!=record['artifacts']:raise ValueError('build artifact closure incomplete')
        if graphics.library_graph(self.executable,self.executable)!=record['executable_graph']:
            raise ValueError('actual executable loading graph changed')
        run_command([self.tools['codesign'],'--verify','--strict',self.executable])
        return record

    def validate_execution(self,result,returncode,base=None,budget=None):
        if type(returncode) is not int or not isinstance(result,dict):raise ValueError('invalid execution result')
        if result.get('outcome')=='HOST_ERROR':
            if returncode!=64 or set(result)!={'outcome','error'} or not isinstance(result['error'],str):raise ValueError('host error contract')
            return
        fields={'outcome','aot_status','setup_status','pe_sha256','image_base','entry_rva','entry_arguments',
            'host_exit_code','proc_translated','proc_translated_errno','timed_out','join_status','host_finished',
            'exit_requested','exit_code','exit_pc','exit_rsp','exit_depth','returned','steps','call_depth',
            'fault','rax','rsp','rip','d3d_cleanup_result','d3d_before_cleanup','d3d_after_cleanup',
            'callback_stats','user32_stats','user32_end_status','host_before_finish','host_after_finish',
            'files','test_queue','observations','saved_file'}
        if set(result)!=fields:raise ValueError('host result field closure differs')
        nested={'outcome','pe_sha256','timed_out','host_finished','fault','d3d_before_cleanup','d3d_after_cleanup','callback_stats','user32_stats','host_before_finish','host_after_finish','files','test_queue','observations','saved_file'}
        if any(not graphics.uint(result[k],0xffffffffffffffff) for k in fields-nested):raise ValueError('host scalar type differs')
        if type(result['timed_out']) is not bool or type(result['host_finished']) is not bool:raise ValueError('host boolean types')
        if result['host_exit_code']!=returncode or result['proc_translated']!=0:raise ValueError('actual child exit/ISA differs')
        if budget is not None and (type(budget) is not int or not 1<=budget<=0xffffffffffffffff or result['steps']>budget):raise ValueError('observed guest steps exceed the executed budget')
        def uint_dict(value,expected):
            if not isinstance(value,dict) or set(value)!=set(expected) or any(not graphics.uint(v,0xffffffffffffffff) for v in value.values()):raise ValueError('statistics type/field closure differs')
        uint_dict(result['fault'],('status','pc','address','width','access'))
        for k in ('d3d_before_cleanup','d3d_after_cleanup'):uint_dict(result[k],STATS_FIELDS)
        uint_dict(result['callback_stats'],('calls','returns','rejections','depth','max_depth','end_status'))
        host_fields=('windows_created','windows_destroyed','forced_cleanup_windows','views_created','views_released','active_views','cocoa_key_events','cocoa_window_events','test_queue_events','focus_recovery_events','guest_queue_events','ignored_keys','messages_taken','waits','quit_messages','queue_overflows','main_dispatches','event_pumps','close_requests','resize_events','api_focus_transitions','sent_notifications','pending_messages','error','stopped','worker_bound','paint_invalid','tombstones')
        for k in ('host_before_finish','host_after_finish'):uint_dict(result[k],host_fields)
        user=result['user32_stats'];uint_dict({k:v for k,v in user.items() if k!='api_calls'},('callbacks','sent_notifications','posted_dispatches','discarded_stale','classes_registered','classes_unregistered','windows_created','windows_destroyed','registered','window_state','hwnd'))
        if not isinstance(user.get('api_calls'),list) or len(user['api_calls'])!=14 or any(not graphics.uint(v,0xffffffffffffffff) for v in user['api_calls']):raise ValueError('User32 call vector differs')
        files=result['files'];uint_dict({k:v for k,v in files.items() if k!='api_calls_4_to_9'},('last_error','open_before_cleanup','open_after_cleanup','cleanup_closes','cleanup_errors','bytes_read','bytes_written'))
        if not isinstance(files.get('api_calls_4_to_9'),list) or len(files['api_calls_4_to_9'])!=6 or any(not graphics.uint(v,0xffffffffffffffff) for v in files['api_calls_4_to_9']):raise ValueError('file call vector differs')
        queue=result['test_queue'];uint_dict({k:v for k,v in queue.items() if k!='events'},('requested','posted','injection_error','observed_hwnd'))
        if not isinstance(queue.get('events'),list) or len(queue['events'])!=queue['posted'] or queue['posted']>queue['requested'] or queue['requested']>64:raise ValueError('queue count differs')
        previous=0
        for event in queue['events']:
            if set(event)!={'name','origin','wait_count'} or event['name'] not in TEST_EVENTS or event['origin']!=3 or not graphics.uint(event['wait_count'],0xffffffffffffffff) or event['wait_count']<=previous:raise ValueError('queue origin/wait boundary differs')
            previous=event['wait_count']
        saved=result['saved_file']
        if set(saved)!={'name','errno','truncated','data_hex'} or saved['name']!=graphics.read_json(self.out/'window-profile.json')['save_observation'] or not graphics.uint(saved['errno'],0xffffffff) or type(saved['truncated']) is not bool:raise ValueError('saved file observation differs')
        if saved['errno']:
            if saved['data_hex'] is not None:raise ValueError('failed file read claims bytes')
        elif not isinstance(saved['data_hex'],str) or not re.fullmatch(r'(?:[0-9a-f]{2}){0,4096}',saved['data_hex']):raise ValueError('invalid saved bytes')
        expected=self.build_manifest['observations']
        if set(result['observations'])!=set(expected):raise ValueError('guest observation set differs')
        for name,item in expected.items():
            value=result['observations'][name]
            if not isinstance(value,str) or not (result['setup_status'] and value=='') and not re.fullmatch('[0-9a-f]{%d}'%(item['size']*2),value):raise ValueError('guest observation bytes differ')
        if result['pe_sha256']!=self.source_sha256 or result['entry_rva']!=self.image.entry_rva or result['entry_arguments']!=0 or result['image_base']!=(self.image.base if base is None else base):raise ValueError('actual PE/entry/base differs')
        if result['outcome']=='SETUP_ERROR':
            if not result['setup_status'] or returncode!=64:raise ValueError('setup error contract')
            return
        if result['setup_status']:raise ValueError('execution with setup failure')
        status=result['aot_status'];fault=result['fault']['status']
        if result['outcome']=='PROCESS_EXITED':
            if status!=11 or result['exit_requested']!=1 or result['returned'] or fault or result['exit_code']>0xffffffff:raise ValueError('ExitProcess endpoint differs')
        elif result['outcome']=='FUNCTION_RETURN':
            if status or result['exit_requested'] or result['returned']!=1 or fault:raise ValueError('function return endpoint differs')
        elif result['outcome']=='FAULT':
            if not 1<=status<=17 or status==11 or fault!=status:raise ValueError('fault endpoint differs')
        else:raise ValueError('unknown outcome')
        cleanup_bad=(result['join_status'] or not result['host_finished'] or result['host_after_finish']['active_views'] or result['d3d_after_cleanup']['live_objects'] or result['d3d_after_cleanup']['active_maps'] or files['cleanup_errors'] or files['open_after_cleanup'] or result['callback_stats']['end_status'] or result['user32_end_status'] or result['timed_out'] or queue['injection_error'])
        expected_exit=64 if cleanup_bad else {'PROCESS_EXITED':0,'FUNCTION_RETURN':2,'FAULT':3}[result['outcome']]
        if returncode!=expected_exit:raise ValueError('cleanup/host exit contract differs')

    def run(self,*,base=None,budget=None,io_directory=None,test_sequence=None,timeout_ms=45000,log_path=None):
        if budget is None:budget=10000000
        for value,name in ((base,'base'),(budget,'budget')):
            if value is not None and (type(value) is not int or not 0<=value<=0xffffffffffffffff):raise ValueError('invalid '+name)
        if type(timeout_ms) is not int or not 1<=timeout_ms<=55000:raise ValueError('supervised wrapper requires timeout within 55 seconds')
        if test_sequence is not None:
            if not isinstance(test_sequence,(tuple,list)) or not 1<=len(test_sequence)<=64 or any(type(x) is not str or x not in TEST_EVENTS for x in test_sequence):raise ValueError('invalid explicit test sequence')
            test_sequence=list(test_sequence)
        self.verify_build()
        command=[str(self.executable)]
        if base is not None:command+=['--base',str(base)]
        if budget is not None:command+=['--budget',str(budget)]
        if log_path is None:
            directory=self.out/'runs';directory.mkdir(exist_ok=True)
            directory=Path(tempfile.mkdtemp(prefix='run-',dir=directory));record_path=directory/'evidence.json'
        else:
            record_path=Path(log_path).resolve();output_directory(record_path.parent);record_path.parent.mkdir(parents=True,exist_ok=True)
        if record_path.exists():raise ValueError('preserve previous run evidence')
        requested_dir=Path(io_directory).absolute() if io_directory is not None else record_path.parent/'data'
        if requested_dir.is_symlink():raise ValueError('trusted real data directory required')
        requested_dir.mkdir(parents=True,exist_ok=True);data_dir=requested_dir.resolve()
        if not data_dir.is_dir():raise ValueError('trusted real data directory required')
        command+=['--data-dir',str(data_dir),'--timeout-ms',str(timeout_ms)]
        if test_sequence is not None:command+=['--test-sequence',','.join(test_sequence)]
        stdout_path=record_path.with_suffix('.stdout');stderr_path=record_path.with_suffix('.stderr')
        inputs={**self.build_manifest['native_inputs'],**self.build_manifest['artifacts'],**snapshot([self.out/'program-build.json'])}
        record={'schema':1,'status':'STARTED_NOT_ACCEPTED','command':command,'program_out':str(self.out),
                'requested_base':base,'requested_budget':budget,'data_directory':str(data_dir),'timeout_ms':timeout_ms,'test_sequence':test_sequence,
                'inputs_before':inputs,'stdout_path':str(stdout_path),'stderr_path':str(stderr_path),
                'scope':'actual original Windows PE/API/WSI observation; TEST_QUEUE is not OS keyboard input; startup ReadFile observation alone is not two-process restore or pixel acceptance'}
        started_path=record_path.with_suffix('.started.json')
        with started_path.open('x') as stream:json.dump(record,stream,indent=2);stream.write('\n')
        record.update(started_path=str(started_path),started_sha256=sha(started_path))
        graphics.save(record_path,record)
        try:
            child=subprocess.Popen(command,env=graphics.environment(self.out,images=True),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            supervised_timeout=False
            try:stdout,stderr=child.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                supervised_timeout=True;child.terminate()
                try:stdout,stderr=child.communicate(timeout=3)
                except subprocess.TimeoutExpired:child.kill();stdout,stderr=child.communicate(timeout=3)
            stdout_path.write_text(stdout);stderr_path.write_text(stderr)
            record.update(pid=child.pid,returncode=child.returncode,external_timeout=supervised_timeout,outputs=snapshot([stdout_path,stderr_path]))
            if supervised_timeout:raise RuntimeError('external 60-second supervision expired; termination is not clean guest exit')
            unchanged(inputs);self.verify_build()
            loaded=graphics.loaded_images(stderr,self.executable,self.build_manifest['library_graph']['nodes'])
            result=graphics.strict_json(stdout)
            self.validate_execution(result,child.returncode,base,budget)
            if result.get('outcome')!='HOST_ERROR':
                events=result['test_queue']['events']
                if [e['name'] for e in events]!=(test_sequence or [])[:len(events)] or result['test_queue']['requested']!=len(test_sequence or []):raise ValueError('actual injected sequence differs')
            record.update(status='ACTUAL_WINDOW_EXECUTION_OBSERVED_NOT_ACCEPTED',result=result,
                          inputs_after=snapshot(inputs),loaded_images=loaded,
                          diagnostic_lines=[line for line in stderr.splitlines() if not line.startswith('dyld[')])
            graphics.save(record_path,record)
            return {**result,'host_returncode':child.returncode,'actual_executable_sha256':self.executable_sha256,
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
    if record.get('status')!='ACTUAL_WINDOW_EXECUTION_OBSERVED_NOT_ACCEPTED' or record.get('external_timeout') is not False:raise ValueError('run not verified')
    started_path=Path(record['started_path'])
    if started_path!=Path(path).resolve().with_suffix('.started.json') or sha(started_path)!=record['started_sha256']:raise ValueError('immutable run start identity differs')
    started=graphics.read_json(started_path)
    expected_start={'schema','status','command','program_out','requested_base','requested_budget','data_directory','timeout_ms','test_sequence','inputs_before','stdout_path','stderr_path','scope'}
    if set(started)!=expected_start or started['status']!='STARTED_NOT_ACCEPTED' or any(started[k]!=record[k] for k in expected_start-{'status'}):raise ValueError('completed record differs from original started command/inputs')
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
    if type(record['timeout_ms']) is not int or not 1<=record['timeout_ms']<=55000:raise ValueError('invalid supervision')
    expected_command+=['--data-dir',record['data_directory'],'--timeout-ms',str(record['timeout_ms'])]
    if record['test_sequence'] is not None:
        sequence=record['test_sequence']
        if not isinstance(sequence,list) or not 1<=len(sequence)<=64 or any(x not in TEST_EVENTS for x in sequence):raise ValueError('invalid recorded test sequence')
        expected_command+=['--test-sequence',','.join(sequence)]
    if record['command']!=expected_command:raise ValueError('recorded executed command differs')
    parsed=graphics.strict_json(Path(record['stdout_path']).read_text())
    if parsed!=record['result']:raise ValueError('saved actual stdout differs from result')
    program.validate_execution(parsed,record['returncode'],started['requested_base'],started['requested_budget'])
    if parsed.get('outcome')!='HOST_ERROR':
        events=parsed['test_queue']['events'];sequence=record['test_sequence'] or []
        if [e['name'] for e in events]!=sequence[:len(events)] or parsed['test_queue']['requested']!=len(sequence):raise ValueError('actual test queue sequence differs')
    loaded=graphics.loaded_images(Path(record['stderr_path']).read_text(),program.executable,program.build_manifest['library_graph']['nodes'])
    if loaded!=record['loaded_images']:raise ValueError('saved actual dyld image set differs')
    if set(map(int,re.findall(r'^dyld\[(\d+)\]:',Path(record['stderr_path']).read_text(),re.M)))!={record['pid']}:raise ValueError('dyld PID differs from actual child')
    return record


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description='Build/verify only; never launch a GUI or GPU from this CLI.')
    parser.add_argument('--pe',type=Path,default=PREPARED/'integer-tile.exe')
    parser.add_argument('--out',type=Path,required=True);parser.add_argument('--optimization',choices=['O3','O0'],default='O3')
    parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    program=Program.from_build(args.out) if args.verify else Program(args.pe,args.out,optimization=args.optimization)
    record=program.verify_build()
    print(json.dumps({'status':record['status'],'program_build':str(program.out/'program-build.json'),
        'executable':str(program.executable),'executable_sha256':program.executable_sha256,
        'roots':len(program.roots),'imports':len(program.image.imports),'methods':len(METHOD_SIGNATURES),
        'gpu_executions':0,'guest_executions':0,'window_executions':0}))
