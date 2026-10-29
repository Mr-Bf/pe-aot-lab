"""Multi-root ARM64 harness: real PE -> native import -> guest callback -> RET.

This is a scalar import profile, not a Windows process loader. Raw C allocations,
metadata and region lifetime are trusted; PE/guest addresses are checked.
"""
import ast
import ctypes as C
from dataclasses import dataclass
import hashlib
import fcntl
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
HERE=Path(__file__).resolve().parent
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from callback_bridge.loader import load_image
from integration_stage3.bindings import (Region,RunResult,GuestMemory,Instruction,Fault,
    NativeResult,REGISTERS,STATUS,EXIT_VA,READ,WRITE,EXEC)

@dataclass
class BridgeResult(RunResult):
    api_calls:int=0
    callback_calls:int=0
    max_callback_depth:int=0
    callback_returns:int=0

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

def validate_callbacks(callbacks,image):
    if not callbacks:raise ValueError('an explicit nonempty callback registry is required')
    result=[];rvas=set();symbols={'aot_entry','aot_import_ret'}
    for row in callbacks:
        if not isinstance(row,dict) or set(row)!={'rva','symbol','signature'}:raise ValueError('callback registry fields')
        rva,symbol,signature=row['rva'],row['symbol'],row['signature']
        if type(rva) is not int or not 0<rva<len(image.data) or rva>0xffffffff:raise ValueError('callback RVA range')
        if type(signature) is not int or signature!=1:raise ValueError('unknown callback signature')
        if not isinstance(symbol,str) or not re.fullmatch(r'aot_callback_[0-9a-f]+',symbol):raise ValueError('callback symbol format')
        if symbol!='aot_callback_'+format(rva,'x'):raise ValueError('callback symbol/RVA mismatch')
        if rva==image.entry_rva or rva in rvas or symbol in symbols:raise ValueError('duplicate callback root')
        if not image.permissions[rva//4096]&EXEC:raise ValueError('callback root is not executable')
        rvas.add(rva);symbols.add(symbol);result.append(dict(row))
    return sorted(result,key=lambda row:row['rva'])

def merge_instructions(roots,image):
    merged={}
    for root in roots:
        manifest=root['manifest']
        if manifest.get('preferred_base')!=image.preferred_base:raise ValueError('root image base mismatch')
        for ins in manifest['instructions']:
            rva=ins['rva'];size=ins['length']
            if type(rva) is not int or type(size) is not int or not 0<=rva<=len(image.data)-size or not 0<size<=15:
                raise ValueError('root instruction interval invalid')
            if bytes(image.data[rva:rva+size])!=bytes.fromhex(ins['bytes']):raise ValueError('root instruction bytes mismatch')
            if rva in merged and merged[rva]!=ins:raise ValueError('overlapping roots disagree on decoded instruction')
            merged[rva]=dict(ins)
    ordered=[merged[rva] for rva in sorted(merged)]
    for left,right in zip(ordered,ordered[1:]):
        if left['rva']+left['length']>right['rva']:raise ValueError('overlapping root instructions')
    if any(root['rva'] not in merged for root in roots):raise ValueError('root entry missing from instruction union')
    return ordered

def run_command(command,log):
    command=list(map(str,command))
    result=subprocess.run(command,capture_output=True,text=True)
    with log.open('a') as f:f.write(json.dumps(command)+'\n'+result.stdout+result.stderr)
    if result.returncode:raise RuntimeError('command failed: '+result.stderr)
    return result.stdout

def verify_lift(directory,manifest,input_sha256,symbol,root_rva=None):
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
    if root_rva is not None and (current.get('entry_rva')!=root_rva or current.get('root_rva')!=root_rva):
        raise ValueError('lift root RVA mismatch')
    required={'text.bin','instructions-raw.json','lifted.ll','arm64.ll','arm64.o','arm64-o0.o'}
    artifacts=current.get('artifact_sha256',{})
    if set(artifacts)!=required:raise ValueError('lift artifact closure incomplete or unknown')
    if Path(current.get('object','')).resolve()!=directory/'arm64.o':
        raise ValueError('lift object path mismatch')
    for name,expected in artifacts.items():
        if sha(directory/name)!=expected:raise ValueError('lift artifact changed: '+name)
    required_sources={
        'source_sha256':{'callback_bridge/lift.py','native_bridge/build_lifter.py','integration_stage3/lifter_layout.cpp',
                         'integration_stage3/xed-only.patch','integration_stage3/transactions.patch',
                         'integration_stage3/aot-profile.patch','native_bridge/import_calls.patch'},
        'external_source_sha256':{'memory_stage2/image_loader.py','callback_bridge/loader.py','callback_bridge/imports_v1.py','fixtures.py'}}
    for collection,required_names in required_sources.items():
        if set(current.get(collection,{}))!=required_names:raise ValueError('lift source closure incomplete or unknown: '+collection)
        for name,expected in current[collection].items():
            path=(ROOT/name).resolve()
            path.relative_to(ROOT)
            if sha(path)!=expected:raise ValueError('lift source changed: '+name)
    if symbol=='aot_import_ret' and (directory/'text.bin').read_bytes()!=b'\xc3':
        raise ValueError('RET shim is not one actual C3 instruction')
    for object_name in ['arm64.o','arm64-o0.o']:
        output=subprocess.check_output(['nm','-g','-U',str(directory/object_name)],text=True)
        names={line.split()[-1] for line in output.splitlines() if line.strip()}
        if names!={'_'+symbol}:raise ValueError('lift object exported symbol closure mismatch')
    return current

class Program:
    def __init__(self,pe_path,out_dir=None,optimization='O3',callbacks=None):
        from callback_bridge.lift import lift_pe,build_ret_shim
        if optimization not in ('O3','O0'):raise ValueError('unsupported optimization mode')
        self.path=Path(pe_path).resolve(strict=True)
        self.source_bytes=self.path.read_bytes()
        self.source_sha256=hashlib.sha256(self.source_bytes).hexdigest()
        self.out=Path(out_dir).resolve() if out_dir else ROOT/'build/callback-bridge/program'/self.path.stem
        if self.out.is_relative_to(ROOT/'build/native-bridge'):raise ValueError('old native-bridge evidence is immutable')
        self.out.mkdir(parents=True,exist_ok=True)
        with (self.out/'.program-build.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            self.image=load_image(self.source_bytes)
            frozen=self.out/'input.exe';frozen.write_bytes(self.source_bytes)
            self.callbacks=validate_callbacks(callbacks,self.image)
            self.roots=[]
            for callback in [{'rva':self.image.entry_rva,'symbol':'aot_entry','signature':0},*self.callbacks]:
                directory=self.out/('compiler' if callback['signature']==0 else 'callback-'+format(callback['rva'],'x'))
                manifest=json.loads(json.dumps(lift_pe(frozen,directory,entry_rva=callback['rva'],entry_symbol=callback['symbol'])))
                if manifest.get('original_entry_rva')!=self.image.entry_rva:raise ValueError('lift changed original PE entry identity')
                root={**callback,'directory':directory,'manifest':manifest}
                verify_lift(directory,manifest,self.source_sha256,callback['symbol'],callback['rva'])
                self.roots.append(root)
            self.main_manifest=self.roots[0]['manifest']
            self.manifest={**self.main_manifest,'instructions':merge_instructions(self.roots,self.image)}
            self.ret_manifest=json.loads(json.dumps(build_ret_shim(self.out/'ret-shim')))
            self.ret_source_sha256=sha(self.out/'ret-shim/synthetic-ret.exe')
            self._verify_lifts()
            rows=[];calls=[]
            imports={item['iat_rva']:item for item in self.image.imports}
            for ins in self.manifest['instructions']:
                kind=ins['kind']
                if isinstance(kind,str):kind={'NORMAL':0,'CALL':1,'RET':2}[kind.upper()]
                target=ins.get('target_rva') or 0
                slot=ins.get('iat_slot_rva')
                if slot:
                    if kind!=1 or slot not in imports:raise ValueError('indirect call is not bound to a known import slot')
                    binding=imports[slot];target=binding['target_rva']
                    calls.append({'call_rva':ins['rva'],'iat_rva':slot,'target_rva':target,'signature':binding['signature']})
                rows.append(Instruction(ins['rva'],ins['length'],kind,0,target))
            if not calls:raise ValueError('native bridge profile requires at least one decoded imported call')
            self.thunks=sorted({item['target_rva'] for item in self.image.imports})
            rows.extend(Instruction(rva,1,2,0,0) for rva in self.thunks)
            self.instructions=(Instruction*len(rows))(*rows)
            header=self.out/'native_imports.h'
            header.write_text('/* Generated explicit named-import call bindings. */\n'
                'static const AotImportCall aot_import_calls[] = {\n'+
                ''.join('    {%du,%du,%du,%du},\n'%(x['call_rva'],x['iat_rva'],x['target_rva'],x['signature']) for x in calls)+'};\n')
            (self.out/'callbacks.h').write_text('/* Explicit lifted callback roots; no guest VA is a host pointer. */\n'+
                ''.join('extern void *%s(void *,uint64_t,void *);\n'%row['symbol'] for row in self.callbacks)+
                'static const AotCallback callbacks[] = {\n'+
                ''.join('    {%du,%du,%s},\n'%(row['rva'],row['signature'],row['symbol']) for row in self.callbacks)+'};\n')
            identity=self.out/'identity.c'
            identity.write_text('const char *aot_input_sha256(void) { return "'+self.source_sha256+'"; }\n')
            log=self.out/'native-build.log';log.write_text('')
            clang=Path(run_command(['xcrun','--find','clang'],log).strip())
            linker=Path(run_command(['xcrun','--find','ld'],log).strip())
            sdk=Path(run_command(['xcrun','--show-sdk-path'],log).strip())
            flags=['-arch','arm64','-std=c11','-isysroot',sdk,'-'+optimization,'-I',self.out,
                   '-Wall','-Wextra','-Werror']
            deps_text=run_command([clang,*flags,'-M','-MT','runtime',HERE/'runtime.c'],log)
            (self.out/'runtime.d').write_text(deps_text)
            _,sep,body=deps_text.replace('\\\n',' ').partition(':')
            if not sep:raise ValueError('invalid C dependency output')
            dependencies=[Path(p).resolve(strict=True) for p in shlex.split(body)]
            objects=[row['directory']/('arm64-o0.o' if optimization=='O0' else 'arm64.o') for row in self.roots]
            ret_obj=self.out/'ret-shim'/('arm64-o0.o' if optimization=='O0' else 'arm64.o')
            # The closure names every input actually consumed by this native link;
            # each lifter manifest independently describes its LLVM pipeline.
            self._verify_lifts()
            python_sources=python_closure([Path(__file__),HERE/'loader.py',HERE/'lift.py'])
            inputs=snapshot([*dependencies,*python_sources,identity,*objects,ret_obj,frozen,clang,linker,Path('/usr/bin/xcrun'),
                             Path(shutil.which('nm')),*[row['directory']/'manifest.json' for row in self.roots],
                             Path(sys.executable),Path(__file__),HERE/'loader.py',
                             ROOT/'integration_stage3/bindings.py',ROOT/'memory_stage2/image_loader.py',
                             self.out/'compiler/manifest.json',self.out/'ret-shim/manifest.json'])
            fd,tmp=tempfile.mkstemp(prefix='.native-',suffix='.dylib',dir=self.out);os.close(fd)
            temporary=Path(tmp)
            command=[clang,*flags,'-dynamiclib','-Wl,-install_name,@rpath/pe-aot-callback-bridge.dylib',
                     HERE/'runtime.c',identity,*objects,ret_obj,'-o',temporary]
            try:
                run_command(command,log);unchanged(inputs);self._verify_lifts()
                self.library_sha256=sha(temporary)
                self.library_path=self.out/('program-'+self.library_sha256+'.dylib')
                if self.library_path.exists():
                    if sha(self.library_path)!=self.library_sha256:raise ValueError('immutable library modified')
                else:shutil.copyfile(temporary,self.library_path)
                shutil.copyfile(temporary,self.out/'program.dylib')
            finally:temporary.unlink(missing_ok=True)
            self.lib=C.CDLL(str(self.library_path))
            for name,args,result in [
                ('aot_input_sha256',[],C.c_char_p),('aot_bridge_api_calls',[],C.c_uint64),
                ('aot_bridge_callback_calls',[],C.c_uint64),('aot_bridge_max_callback_depth',[],C.c_uint32),
                ('aot_bridge_callback_returns',[],C.c_uint64),
                ('aot_state_create',[],C.c_void_p),('aot_state_destroy',[C.c_void_p],None),
                ('aot_get_register',[C.c_void_p,C.c_uint32],C.c_uint64),
                ('aot_set_register',[C.c_void_p,C.c_uint32,C.c_uint64],None),('aot_get_flags',[C.c_void_p],C.c_uint32),
                ('aot_context_create',[C.c_uint64,C.POINTER(Instruction),C.c_size_t,C.c_uint64,C.c_uint64,C.c_uint64],C.c_void_p),
                ('aot_context_destroy',[C.c_void_p],None),('aot_add_region',[C.c_void_p,C.POINTER(GuestMemory)],C.c_uint32),
                ('aot_execute',[C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint64],C.c_uint32),
                ('aot_result',[C.c_void_p,C.POINTER(NativeResult)],None)]:
                fn=getattr(self.lib,name);fn.argtypes=args;fn.restype=result
            if self.lib.aot_input_sha256().decode('ascii')!=self.source_sha256:
                raise ValueError('loaded library has the wrong PE identity')
            self.build_manifest={'schema':1,'status':'BUILT_LOADED_NOT_RUNTIME_VERIFIED',
                'input_sha256':self.source_sha256,'optimization':optimization,'native_inputs':inputs,
                'native_library':str(self.library_path),'native_sha256':self.library_sha256,
                'calls':calls,'imports':self.image.imports,'callbacks':self.callbacks,
                'roots':[{'rva':r['rva'],'symbol':r['symbol'],'signature':r['signature'],
                          'directory':str(r['directory']),'manifest_sha256':sha(r['directory']/'manifest.json')} for r in self.roots],
                'command':list(map(str,command)),
                'limits':['explicit synchronous scalar callback registry only','trusted stable C metadata and allocations',
                          'no Windows DLL implementation or Windows process startup']}
            (self.out/'program-build.json').write_text(json.dumps(self.build_manifest,indent=2)+'\n')
    def _verify_lifts(self):
        if sha(self.out/'input.exe')!=self.source_sha256 or sha(self.out/'ret-shim/synthetic-ret.exe')!=self.ret_source_sha256:
            raise ValueError('frozen lift input changed')
        for row in self.roots:verify_lift(row['directory'],row['manifest'],self.source_sha256,row['symbol'],row['rva'])
        verify_lift(self.out/'ret-shim',self.ret_manifest,self.ret_source_sha256,'aot_import_ret')

    def run(self,gpr=None,regions=None,base=None,stack=None,rsp=None,return_address=None,
            stack_args=None,max_steps=100000):
        if sha(self.library_path)!=self.library_sha256:raise ValueError('loaded native file changed')
        base=self.image.preferred_base if base is None else base
        if not 0<=base<=0xffffffffffffffff or not 0<max_steps<=0xffffffffffffffff:raise ValueError('Invalid execution configuration')
        # An instantiated Program always runs the exact frozen PE version that
        # produced its artifact, even if the on-disk path is subsequently edited.
        image=load_image(self.source_bytes,load_base=base)
        regions=list(regions or [])
        mapped=next((r for r in regions if r.base==base and len(r.data)>=len(image.data)),None)
        if mapped is None:
            mapped=Region(base,image.data,bytearray(image.permissions));regions.append(mapped)
        # The AOT cache is valid only for the lifted executable bytes. Data may
        # vary; trusted host setup may alter permissions for fault experiments.
        for ins in self.manifest['instructions']:
            rva=ins['rva'];size=ins['length']
            if mapped.data[rva:rva+size]!=bytes.fromhex(ins['bytes']):
                raise ValueError('Executable bytes changed after translation')
        # Synthetic compatibility code has its own RX mappings; its C3 byte is
        # checked again by the native bridge before any host API invocation.
        for thunk in self.thunks:
            address=base+thunk
            if not any(r.base==address and len(r.data)>=4096 for r in regions):
                regions.append(Region(address,bytearray(b'\xc3'+b'\0'*4095),bytearray([READ|EXEC])))
        stack=stack or Region(0x70000000,bytearray(65536))
        if stack is mapped:raise ValueError('Initial stack must be a separate guest mapping')
        if all(r is not stack for r in regions):regions.append(stack)
        # Reject aliased backing before the host writes its initial return slot.
        # Executable bytes must not be mutable through a second writable guest VA.
        for i,region in enumerate(regions):
            host=C.addressof(C.c_uint8.from_buffer(region.data))
            for other in regions[:i]:
                if region.base<other.base+len(other.data) and other.base<region.base+len(region.data):
                    raise ValueError('Overlapping guest mappings')
                other_host=C.addressof(C.c_uint8.from_buffer(other.data))
                if host<other_host+len(other.data) and other_host<host+len(region.data):
                    raise ValueError('Aliased host backing is unsupported')
        rsp=stack.base+len(stack.data)-0x108 if rsp is None else rsp
        if not 0<=rsp<=0xffffffffffffffff-8:raise ValueError('Invalid initial RSP')
        ret=EXIT_VA if return_address is None else return_address
        off=rsp-stack.base
        setup=[]
        if not 0<=ret<=0xffffffffffffffff:raise ValueError('Invalid return address')
        if 0<=off<=len(stack.data)-8:setup.append((off,struct.pack('<Q',ret)))
        for i,value in enumerate(stack_args or []):
            pos=off+40+i*8
            if not 0<=pos<=len(stack.data)-8:raise ValueError('Host stack argument setup out of range')
            setup.append((pos,struct.pack('<Q',value&0xffffffffffffffff)))
        state=self.lib.aot_state_create()
        if not state:raise MemoryError('State allocation failed')
        ctx=None
        try:
            self.lib.aot_set_register(state,REGISTERS.index('RSP'),rsp)
            for reg,value in (gpr or {}).items():
                if reg not in REGISTERS:raise ValueError('Unknown register '+reg)
                if reg in ('RSP','RIP'):raise ValueError('Use rsp/base options for execution addresses')
                self.lib.aot_set_register(state,REGISTERS.index(reg),value&0xffffffffffffffff)
            ctx=self.lib.aot_context_create(base,self.instructions,len(self.instructions),max_steps,EXIT_VA,rsp)
            if not ctx:raise ValueError('Rejected instruction manifest or execution descriptor')
            backing=[]
            for region in regions:
                data=(C.c_uint8*len(region.data)).from_buffer(region.data)
                perm=(C.c_uint8*len(region.permissions)).from_buffer(region.permissions)
                descriptor=GuestMemory(region.base,len(region.data),C.addressof(data),C.addressof(perm),len(perm))
                if self.lib.aot_add_region(ctx,C.byref(descriptor))!=0:raise ValueError('Overlapping or invalid guest mappings')
                backing.append((data,perm,descriptor))
            # Commit host setup only after every descriptor/configuration check.
            for pos,value in setup:stack.data[pos:pos+8]=value
            status=self.lib.aot_execute(C.cast(self.lib.aot_entry,C.c_void_p),state,ctx,base+self.image.entry_rva)
            out=NativeResult();self.lib.aot_result(ctx,C.byref(out))
            regs={name:self.lib.aot_get_register(state,i) for i,name in enumerate(REGISTERS)}
            fault={name:getattr(out.fault,name) for name,_ in Fault._fields_}
            return BridgeResult(status,bool(out.returned),regs,fault,out.steps,out.call_depth,self.lib.aot_get_flags(state),stack,self.lib.aot_bridge_api_calls(),self.lib.aot_bridge_callback_calls(),self.lib.aot_bridge_max_callback_depth(),self.lib.aot_bridge_callback_returns())
        finally:
            if ctx:self.lib.aot_context_destroy(ctx)
            self.lib.aot_state_destroy(state)
