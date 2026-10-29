"""Trusted host harness for the real Remill/guest-memory execution chain.

This module constructs an explicit initial CPU state, not Windows process startup.
Guest integers are never host pointers. Region backing remains stable during run.
"""
import ctypes as C
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from memory_stage2.image_loader import load_image

REGISTERS=['RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI','R8','R9','R10','R11','R12','R13','R14','R15','RIP']
STATUS={0:'OK',1:'BOUNDS',2:'PROTECTION',3:'INVALID',4:'BUDGET',5:'BAD_RETURN',
        6:'BAD_INSTRUCTION',7:'MULTIWRITE',8:'CALL_DEPTH',9:'UNSUPPORTED',10:'NOT_RETURNED'}
EXIT_VA=0x7fff00000000
READ=1;WRITE=2;EXEC=4

@dataclass
class Region:
    base:int
    data:bytearray
    permissions:bytearray=None
    def __post_init__(self):
        if not isinstance(self.data,bytearray):self.data=bytearray(self.data)
        if self.permissions is None:self.permissions=bytearray([READ|WRITE])*((len(self.data)+4095)//4096)
        else:self.permissions=bytearray(self.permissions)
        if not self.data or self.base<0 or self.base%4096 or self.base+len(self.data)>0xffffffffffffffff:
            raise ValueError('Invalid guest region')
        if len(self.permissions)!=(len(self.data)+4095)//4096:raise ValueError('Wrong permission page count')

@dataclass
class RunResult:
    status:int
    returned:bool
    registers:dict
    fault:dict
    steps:int
    call_depth:int
    flags:int
    stack:Region=field(repr=False)

class GuestMemory(C.Structure):
    _fields_=[('base',C.c_uint64),('size',C.c_size_t),('bytes',C.c_void_p),
              ('permissions',C.c_void_p),('page_count',C.c_size_t)]
class Instruction(C.Structure):
    _fields_=[('rva',C.c_uint32),('length',C.c_uint16),('kind',C.c_uint8),
              ('reserved',C.c_uint8),('target_rva',C.c_uint64)]
class Fault(C.Structure):
    _fields_=[('status',C.c_uint32),('access',C.c_uint32),('pc',C.c_uint64),
              ('address',C.c_uint64),('width',C.c_uint64)]
class NativeResult(C.Structure):
    _fields_=[('fault',Fault),('steps',C.c_uint64),('call_depth',C.c_uint32),('returned',C.c_uint32)]

class Program:
    def __init__(self,pe_path,out_dir=None):
        from integration_stage3.lift import lift_pe
        self.path=Path(pe_path).resolve()
        self.source_bytes=self.path.read_bytes()
        self.source_sha256=hashlib.sha256(self.source_bytes).hexdigest()
        self.out=Path(out_dir).resolve() if out_dir else ROOT/'build/integration-stage3'/self.path.stem
        self.out.mkdir(parents=True,exist_ok=True)
        self.image=load_image(self.source_bytes)
        self.manifest=lift_pe(self.path,self.out)
        if self.manifest['input_sha256']!=self.source_sha256:
            raise ValueError('Source PE changed while building the AOT artifact')
        obj=self.out/'arm64.o'
        if not obj.exists():raise RuntimeError('lifter did not produce '+str(obj))
        # dlopen caches a path for the lifetime of this host process. Never load
        # a mutable output name: two Programs must not share an old loaded image.
        fd,temporary=tempfile.mkstemp(prefix='.native-',suffix='.dylib',dir=self.out)
        os.close(fd);dylib=Path(temporary)
        command=['xcrun','clang','-arch','arm64','-std=c11','-O3','-Wall','-Wextra','-Werror',
                 '-dynamiclib','-Wl,-install_name,@rpath/pe-aot-stage3.dylib',
                 str(ROOT/'integration_stage3/runtime.c'),str(obj),'-o',str(dylib)]
        completed=subprocess.run(command,capture_output=True,text=True)
        (self.out/'runtime-build.json').write_text(json.dumps({'command':command,'returncode':completed.returncode,
            'stdout':completed.stdout,'stderr':completed.stderr},indent=2)+'\n')
        if completed.returncode:
            dylib.unlink(missing_ok=True)
            raise RuntimeError('runtime link failed: '+completed.stderr)
        native_sha=hashlib.sha256(dylib.read_bytes()).hexdigest()
        self.library_path=self.out/('program-'+native_sha+'.dylib')
        try:
            if self.library_path.exists():
                if hashlib.sha256(self.library_path.read_bytes()).hexdigest()!=native_sha:
                    raise ValueError('Immutable native artifact changed')
            else:shutil.copyfile(dylib,self.library_path)
            # Convenience copy for inspection and old scripts; never passed to dlopen.
            shutil.copyfile(dylib,self.out/'program.dylib')
        finally:dylib.unlink(missing_ok=True)
        (self.out/'native-artifact.json').write_text(json.dumps({'input_sha256':self.source_sha256,
            'library_path':str(self.library_path),'library_sha256':native_sha,
            'object_sha256':hashlib.sha256(obj.read_bytes()).hexdigest()},indent=2)+'\n')
        self.lib=C.CDLL(str(self.library_path))
        for name,args,result in [
            ('aot_state_create',[],C.c_void_p),('aot_state_destroy',[C.c_void_p],None),
            ('aot_get_register',[C.c_void_p,C.c_uint32],C.c_uint64),
            ('aot_set_register',[C.c_void_p,C.c_uint32,C.c_uint64],None),
            ('aot_get_flags',[C.c_void_p],C.c_uint32),
            ('aot_context_create',[C.c_uint64,C.POINTER(Instruction),C.c_size_t,C.c_uint64,C.c_uint64,C.c_uint64],C.c_void_p),
            ('aot_context_destroy',[C.c_void_p],None),('aot_add_region',[C.c_void_p,C.POINTER(GuestMemory)],C.c_uint32),
            ('aot_execute',[C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint64],C.c_uint32),
            ('aot_result',[C.c_void_p,C.POINTER(NativeResult)],None)]:
            fn=getattr(self.lib,name);fn.argtypes=args;fn.restype=result
        rows=[]
        for ins in self.manifest['instructions']:
            kind=ins['kind']
            if isinstance(kind,str):kind={'NORMAL':0,'CALL':1,'RET':2}[kind.upper()]
            rows.append(Instruction(ins['rva'],ins['length'],kind,0,ins.get('target_rva') or 0))
        self.instructions=(Instruction*len(rows))(*rows)

    def run(self,gpr=None,regions=None,base=None,stack=None,rsp=None,return_address=None,
            stack_args=None,max_steps=100000):
        base=self.image.preferred_base if base is None else base
        if not 0<=base<=0xffffffffffffffff or max_steps<=0:raise ValueError('Invalid execution configuration')
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
        if 0<=off<=len(stack.data)-8:struct.pack_into('<Q',stack.data,off,ret)
        for i,value in enumerate(stack_args or []):
            pos=off+40+i*8
            if not 0<=pos<=len(stack.data)-8:raise ValueError('Host stack argument setup out of range')
            struct.pack_into('<Q',stack.data,pos,value&0xffffffffffffffff)
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
            status=self.lib.aot_execute(C.cast(self.lib.aot_entry,C.c_void_p),state,ctx,base+self.image.entry_rva)
            out=NativeResult();self.lib.aot_result(ctx,C.byref(out))
            regs={name:self.lib.aot_get_register(state,i) for i,name in enumerate(REGISTERS)}
            fault={name:getattr(out.fault,name) for name,_ in Fault._fields_}
            return RunResult(status,bool(out.returned),regs,fault,out.steps,out.call_depth,self.lib.aot_get_flags(state),stack)
        finally:
            if ctx:self.lib.aot_context_destroy(ctx)
            self.lib.aot_state_destroy(state)
