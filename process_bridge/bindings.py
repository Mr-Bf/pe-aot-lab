"""Build and launch an independent ARM64 executable from an original PE.

Python is a build/test driver only. The emitted executable directly embeds and
runs the guest image with a native C host; it does not load a Python runtime.
"""
import ast,fcntl,hashlib,json,os,re,shlex,shutil,struct,subprocess,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from process_bridge.loader import load_image
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
                file=ROOT.joinpath(*module.split('.')).with_suffix('.py')
                if file.is_file():pending.append(file.resolve())
    return seen

def run_command(command,log):
    command=list(map(str,command))
    result=subprocess.run(command,capture_output=True,text=True)
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
        'source_sha256':{'process_bridge/lift.py','native_bridge/build_lifter.py','integration_stage3/lifter_layout.cpp',
                         'integration_stage3/xed-only.patch','integration_stage3/transactions.patch',
                         'integration_stage3/aot-profile.patch','native_bridge/import_calls.patch'},
        'external_source_sha256':{'memory_stage2/image_loader.py','process_bridge/loader.py','callback_bridge/imports_v1.py','fixtures.py'}}
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
    image=program.image;calls=[];rows=[]
    by_slot={row['iat_rva']:row for row in image.imports}
    for ins in program.manifest['instructions']:
        kind=ins['kind'];kind={'NORMAL':0,'CALL':1,'RET':2}[kind.upper()] if isinstance(kind,str) else kind
        rva,length=ins['rva'],ins['length'];target=ins.get('target_rva') or 0
        if bytes(image.data[rva:rva+length])!=bytes.fromhex(ins['bytes']):raise ValueError('decoded bytes differ from image')
        if ins.get('iat_slot_rva'):
            slot=ins['iat_slot_rva']
            if kind!=1 or slot not in by_slot:raise ValueError('unbound IAT call')
            binding=by_slot[slot];target=binding['target_rva']
            calls.append({'call_rva':rva,'iat_rva':slot,'target_rva':target,'signature':binding['signature']})
        rows.append((rva,length,kind,target))
    thunks=sorted({row['target_rva'] for row in image.imports})
    rows += [(rva,1,2,0) for rva in thunks]
    native='/* Exact decoded import sites; a count-zero sentinel registers no API. */\n'
    native+='#define AOT_IMPORT_CALL_COUNT %d\n'%len(calls)
    native+='static const AotImportCall aot_import_calls[] = {\n'
    native+=''.join('    {%du,%du,%du,%du},\n'%(r['call_rva'],r['iat_rva'],r['target_rva'],r['signature']) for r in calls)
    native+=('' if calls else '    {0,0,0,0},\n')+'};\n'
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
    text+='static const AotInstruction kInstructions[]={'+','.join('{%du,%du,%du,0,UINT64_C(%d)}'%r for r in rows)+'};\n'
    text+='static const size_t kInstructionCount=%d;\n'%len(rows)
    text+='static const NativeObservation kObservations[]={'+(','.join('{"%s",%du,%du}'%r for r in observations) or '{"",0,0}')+'};\n'
    text+='static const size_t kObservationCount=%d;\n'%len(observations)
    (program.out/'native_image.h').write_text(text)
    return calls,rows,observations

class Program:
    def __init__(self,pe_path,out_dir=None,optimization='O3',metadata=None,metadata_sources=()):
        from process_bridge.lift import lift_pe,build_ret_shim
        if optimization not in ('O3','O0'):raise ValueError('unsupported native optimization')
        self.path=Path(pe_path).resolve(strict=True);self.source_bytes=self.path.read_bytes()
        self.source_sha256=hashlib.sha256(self.source_bytes).hexdigest()
        self.out=Path(out_dir or ROOT/'build/process-bridge/program'/self.path.stem).resolve()
        if any(self.out.is_relative_to(ROOT/'build'/p) for p in ('file-bridge','callback-bridge','native-bridge')):
            raise ValueError('previous profile artifacts are immutable')
        self.out.mkdir(parents=True,exist_ok=True);metadata=json.loads(json.dumps(metadata or {}))
        declared=metadata.get('pe_sha256',metadata.get('source_pe_sha256',self.source_sha256))
        if declared!=self.source_sha256:raise ValueError('fixture metadata refers to another PE')
        with (self.out/'.program-build.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            self.image=load_image(self.source_bytes)
            frozen=self.out/'input.exe';frozen.write_bytes(self.source_bytes)
            (self.out/'fixture-metadata.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
            self.manifest=json.loads(json.dumps(lift_pe(frozen,self.out/'compiler')))
            verify_lift(self.out/'compiler',self.manifest,self.source_sha256,'aot_entry')
            self.ret_manifest=json.loads(json.dumps(build_ret_shim(self.out/'ret-shim')))
            self.ret_source_sha256=sha(self.out/'ret-shim/synthetic-ret.exe')
            self.verify_lifts()
            calls,self.instructions,self.observations=generate_headers(self,metadata)
            log=self.out/'native-build.log';log.write_text('')
            clang=Path(run_command(['xcrun','--find','clang'],log).strip())
            linker=Path(run_command(['xcrun','--find','ld'],log).strip())
            sdk=Path(run_command(['xcrun','--show-sdk-path'],log).strip())
            flags=['-arch','arm64','-std=c11','-isysroot',sdk,'-'+optimization,'-I',self.out,'-Wall','-Wextra','-Werror']
            dependencies=[];graphs=[]
            for name in ('native_host.c','runtime.c'):
                command=[clang,*flags,'-M','-MT','process',HERE/name]
                graph=run_command(command,log);graphs.append((command,graph))
                (self.out/(name+'.d')).write_text(graph)
                dependencies += [Path(p).resolve(strict=True) for p in shlex.split(graph.replace('\\\n',' ').split(':',1)[1])]
            obj=self.out/'compiler'/('arm64-o0.o' if optimization=='O0' else 'arm64.o')
            ret_obj=self.out/'ret-shim'/('arm64-o0.o' if optimization=='O0' else 'arm64.o')
            tools=[clang,linker,Path('/usr/bin/xcrun'),Path(sys.executable),*[Path(shutil.which(n)) for n in ('nm','file','otool','codesign')]]
            inputs=snapshot([*dependencies,*python_closure([Path(__file__),HERE/'lift.py',HERE/'loader.py']),
                *tools,*metadata_sources,self.path,frozen,self.out/'fixture-metadata.json',obj,ret_obj,
                self.out/'compiler/manifest.json',self.out/'ret-shim/manifest.json'])
            inputs.update(self.manifest['inputs_before']);inputs.update(self.ret_manifest['inputs_before'])
            self.verify_lifts()
            fd,name=tempfile.mkstemp(prefix='.process-',dir=self.out);os.close(fd);temporary=Path(name)
            command=[clang,*flags,HERE/'native_host.c',HERE/'runtime.c',obj,ret_obj,'-o',temporary]
            try:
                run_command(command,log)
                run_command(['codesign','--force','--sign','-','--identifier','org.peaotlab.process',temporary],log)
                run_command(['codesign','--verify','--strict',temporary],log)
                file_type=run_command(['file',temporary],log)
                if 'Mach-O 64-bit executable arm64' not in file_type:raise ValueError('native executable is not ARM64 Mach-O')
                dylibs=run_command(['otool','-L',temporary],log)
                linked=[line.strip().split(' (',1)[0] for line in dylibs.splitlines()[1:] if line.strip()]
                if linked!=['/usr/lib/libSystem.B.dylib']:raise ValueError('unexpected executable runtime dependency: '+str(linked))
                unchanged(inputs);self.verify_lifts()
                for dependency_command,graph in graphs:
                    if run_command(dependency_command,log)!=graph:raise ValueError('native C dependency graph changed')
                self.executable_sha256=sha(temporary)
                self.executable=self.out/('process-'+self.executable_sha256)
                if self.executable.exists():
                    if sha(self.executable)!=self.executable_sha256:raise ValueError('immutable native executable changed')
                else:shutil.copy2(temporary,self.executable)
                self.executable.chmod(0o755)
            finally:temporary.unlink(missing_ok=True)
            self.build_manifest={'schema':1,'status':'BUILT_NATIVE_NOT_EXECUTED','input_sha256':self.source_sha256,
                'optimization':optimization,'native_inputs':inputs,'native_inputs_after':snapshot(inputs),
                'native_executable':str(self.executable),'native_sha256':self.executable_sha256,
                'calls':calls,'imports':self.image.imports,'observations':metadata.get('observations',{}),
                'runtime_dependencies':linked,'command':list(map(str,command)),
                'scope':'standalone ARM64 no-argument restricted PE entry; no Python or Rosetta runtime dependency'}
            (self.out/'program-build.json').write_text(json.dumps(self.build_manifest,indent=2)+'\n')
    def verify_lifts(self):
        if sha(self.out/'input.exe')!=self.source_sha256 or sha(self.out/'ret-shim/synthetic-ret.exe')!=self.ret_source_sha256:
            raise ValueError('frozen PE input changed')
        verify_lift(self.out/'compiler',self.manifest,self.source_sha256,'aot_entry')
        verify_lift(self.out/'ret-shim',self.ret_manifest,self.ret_source_sha256,'aot_import_ret')
    def run(self,io_directory,*,base=None,budget=None,log_path=None):
        if sha(self.executable)!=self.executable_sha256:raise ValueError('actual native executable changed')
        command=[str(self.executable),'--data-dir',str(Path(io_directory).absolute())]
        if base is not None:command+=['--base',str(base)]
        if budget is not None:command+=['--budget',str(budget)]
        before=snapshot([self.executable]);execution=subprocess.run(command,capture_output=True,text=True)
        unchanged(before)
        if log_path:Path(log_path).write_text(json.dumps(command)+'\n'+execution.stdout+execution.stderr)
        if execution.stderr:raise RuntimeError('native host stderr: '+execution.stderr)
        try:result=json.loads(execution.stdout)
        except json.JSONDecodeError as error:raise RuntimeError('native host did not emit JSON: '+execution.stdout) from error
        if result.get('outcome')!='HOST_ERROR' and result.get('pe_sha256')!=self.source_sha256:
            raise ValueError('executed native PE identity mismatch')
        result['host_returncode']=execution.returncode
        result['actual_executable_sha256']=self.executable_sha256
        return result

