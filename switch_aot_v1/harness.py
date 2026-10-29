"""Admitted fixture -> finite Remill IR -> native ARM64 O0/O3 transaction tests.
The native C return-value reference is not an original-x86 machine oracle.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import traceback

from portable_lifter_v1 import build as b
from switch_aot_v1.admission import prove_switch, validate_switch
from memory_stage2.image_loader import load_image
from integration_stage3.bindings import Region, GuestMemory, Instruction, NativeResult, EXIT_VA

REPO=Path(__file__).resolve().parents[1]
HERE=Path(__file__).resolve().parent
RSP=0x7000fef8
OFFSETS=[2216,2248,2264,2232,2312,2328,2280,2296,2344,2360,2376,2392,2408,2424,2440,2456,2472]
SOURCES=[HERE/'harness.py',HERE/'runtime.c',HERE/'runtime.h',HERE/'admission.py',
         REPO/'memory_stage2/guest_memory.h',REPO/'memory_stage2/image_loader.py',
         REPO/'integration_stage3/bindings.py',REPO/'switch_supported_fixture_v1/switch8.c',
         REPO/'switch_variant_fixture_v1/switch8_variant.c',REPO/'LICENSE',
         REPO/'integration_stage3/LICENSE.remill']


def require(ok,message):
    if not ok:raise RuntimeError(message)


def retarget(raw,area,llvm,run):
    ir=raw.read_text()
    require('switch i64 ' in ir and '@aot_switch_miss' in ir,'finite switch/default absent in IR')
    require(not any(x in ir for x in ('inttoptr','x86_fp80','llvm.x86.')),'target-specific/host-pointer IR')
    require(not re.search(r'call.*@__remill_(?:jump|missing_block|function_call)\b',ir),'generic indirect control helper remains')
    empty=area/'empty.c';empty.write_text('int empty;\n')
    run([llvm/'clang','-target','arm64-apple-macos11','-S','-emit-llvm',empty,'-o',area/'empty.ll'],'empty-target')
    lines=(area/'empty.ll').read_text().splitlines()
    layout=next(x for x in lines if x.startswith('target datalayout'))
    triple=next(x for x in lines if x.startswith('target triple'))
    ir=re.sub(r'^target datalayout.*$',layout,ir,flags=re.M)
    ir=re.sub(r'^target triple.*$',triple,ir,flags=re.M)
    ir=re.sub(r' "(?:target-cpu|target-features|tune-cpu)"="[^"]*"','',ir)
    ir=re.sub(r'@sub_140001000\b','@aot_entry',ir)
    require('@aot_entry(' in ir,'entry symbol absent')
    # Inspect the actual State type retargeted by LLVM, in the final loaded library.
    expressions=['getelementptr (%struct.State, ptr null, i32 1)']
    expressions += [f'getelementptr (%struct.State, ptr null, i32 0, i32 0, i32 6, i32 {1+2*i}, i32 0, i32 0)' for i in range(17)]
    expressions += [f'getelementptr (%struct.State, ptr null, i32 0, i32 0, i32 2, i32 {1+2*i})' for i in range(7)]
    for index,expression in enumerate(expressions):
        ir+=f'\ndefine i64 @aot_layout_{index}() {{ ret i64 ptrtoint (ptr {expression} to i64) }}\n'
    path=area/'arm64.ll';path.write_text(ir)
    run([llvm/'opt','-passes=verify','-disable-output',path],'verify-arm-ir')
    return path


class Program:
    def __init__(self,library,proof,source):
        self.lib=C.CDLL(str(library));self.proof=proof;self.source=source
        expected=[3504]+list(range(2216,2473,16))+list(range(2065,2078,2))
        actual=[]
        for index in range(len(expected)):
            fn=getattr(self.lib,f'aot_layout_{index}');fn.restype=C.c_uint64;fn.argtypes=[];actual.append(fn())
        require(actual==expected,'actual LLVM State layout mismatch')
        self.layout=actual
        signatures=[('aot_state_create',[],C.c_void_p),('aot_state_destroy',[C.c_void_p],None),
         ('aot_get_register',[C.c_void_p,C.c_uint32],C.c_uint64),('aot_set_register',[C.c_void_p,C.c_uint32,C.c_uint64],None),
         ('aot_get_flags',[C.c_void_p],C.c_uint32),
         ('aot_context_create',[C.c_uint64,C.POINTER(Instruction),C.c_size_t,C.c_uint64,C.c_uint64,C.c_uint64],C.c_void_p),
         ('aot_context_destroy',[C.c_void_p],None),('aot_add_region',[C.c_void_p,C.POINTER(GuestMemory)],C.c_uint32),
         ('aot_configure_switch',[C.c_void_p,C.c_uint64,C.POINTER(C.c_uint64),C.c_size_t],C.c_uint32),
         ('aot_bind_switch',[C.c_void_p,C.c_uint64,C.POINTER(C.c_uint8),C.c_size_t],C.c_uint32),
         ('aot_begin',[C.c_void_p,C.c_uint64,C.c_void_p],C.c_uint32),
         ('aot_commit',[C.c_void_p,C.c_uint64,C.c_void_p],C.c_uint32),
         ('__remill_write_memory_32',[C.c_void_p,C.c_uint64,C.c_uint32],C.c_void_p),
         ('aot_execute',[C.c_void_p,C.c_void_p,C.c_void_p,C.c_uint64],C.c_uint32),
         ('aot_result',[C.c_void_p,C.POINTER(NativeResult)],None)]
        for name,args,result in signatures:
            fn=getattr(self.lib,name);fn.argtypes=args;fn.restype=result
        rows=proof['candidate_packet']['instructions'];base=proof['image_base']
        self.rows=(Instruction*len(rows))(*(Instruction(r['address']-base,r['length'],r['kind'],0,0) for r in rows))
        for name in ('switch8','switch8_variant'):
            fn=getattr(self.lib,name);fn.argtypes=[C.c_uint32,C.c_uint32];fn.restype=C.c_uint32

    def execute(self,registers,budget=100,corrupt=False,readable=True,binding_case=None,test_write=False):
        proof=self.proof;image=load_image(self.source);data=bytearray(image.data)
        table=proof['switch']['table_pc'];table_offset=table-image.base
        permissions=bytearray(image.permissions)
        if binding_case=='legal_member':
            struct.pack_into('<i',data,table_offset,proof['switch']['signed_offsets'][1])
        if binding_case=='writable':permissions[table_offset//4096]=3
        if binding_case=='executable':permissions[table_offset//4096]=5
        image_region=Region(image.base,data,permissions)
        if binding_case=='missing':image_region=Region(image.base,data[:table_offset],permissions[:table_offset//4096])
        stack=Region(0x70000000,bytearray(b'\x5a'*65536));struct.pack_into('<Q',stack.data,RSP-stack.base,EXIT_VA)
        original_stack=bytes(stack.data)
        state=self.lib.aot_state_create();require(state,'State allocation');ctx=None;backing=[]
        try:
            for index,value in enumerate(registers):self.lib.aot_set_register(state,index,value)
            initial_state=C.string_at(state,3504)
            ctx=self.lib.aot_context_create(image.base,self.rows,len(self.rows),budget,EXIT_VA,RSP);require(ctx,'context allocation')
            targets=list(proof['switch']['targets'])
            if binding_case=='target_signature':targets[0]=targets[1]
            array=(C.c_uint64*len(targets))(*targets)
            require(self.lib.aot_configure_switch(ctx,proof['switch']['jump_pc'],array,len(targets))==0,'switch configuration')
            for region in (image_region,stack):
                memory=(C.c_uint8*len(region.data)).from_buffer(region.data);rights=(C.c_uint8*len(region.permissions)).from_buffer(region.permissions)
                guest=GuestMemory(region.base,len(region.data),C.addressof(memory),C.addressof(rights),len(rights))
                require(region.base!=C.addressof(memory),'identity host pointer unexpectedly used')
                require(self.lib.aot_add_region(ctx,C.byref(guest))==0,'guest mapping');backing.append((memory,rights,guest))
            expected=bytes.fromhex(proof['switch']['table_bytes']);expected_array=(C.c_uint8*len(expected)).from_buffer_copy(expected)
            bound=None if binding_case=='unbound' else self.lib.aot_bind_switch(ctx,table,expected_array,len(expected))
            if not binding_case:require(bound==0,'original mapped table binding failed')
            # Explicit test-only mutation AFTER successful bind. A normal trusted
            # host must keep backing bytes/permissions stable for the entire run.
            if corrupt:struct.pack_into('<i',data,table_offset,0x123)
            if not readable:image_region.permissions[table_offset//4096]=0
            original_image=bytes(data)
            write_prefix=None
            if test_write:
                require(self.lib.aot_begin(state,proof['switch']['load_pc'],ctx)==0,'test transaction begin')
                write_prefix=C.string_at(state,3504).hex()
                getattr(self.lib,'__remill_write_memory_32')(ctx,table,0x12345678)
                require(self.lib.aot_commit(state,proof['switch']['add_pc'],ctx)==1,'read-only write accepted')
                result=NativeResult();self.lib.aot_result(ctx,C.byref(result));status=result.fault.status
            else:
                status=self.lib.aot_execute(C.cast(self.lib.aot_entry,C.c_void_p),state,ctx,image.base+proof['root_rva'])
            result=NativeResult();self.lib.aot_result(ctx,C.byref(result));full=C.string_at(state,3504)
            require(bytes(stack.data)==original_stack and bytes(data)==original_image,'unexpected memory modification')
            record=dict(status=status,steps=result.steps,depth=result.call_depth,returned=result.returned,
                        registers=[self.lib.aot_get_register(state,i) for i in range(17)],flags=self.lib.aot_get_flags(state),
                        state=full.hex(),memory_sha256=hashlib.sha256(data+stack.data).hexdigest(),
                        fault={key:getattr(result.fault,key) for key in ('status','access','pc','address','width')})
            if binding_case:
                record.update(binding_case=binding_case,binding_status=bound,initial_state=initial_state.hex())
                require(status==3 and result.steps==0 and full==initial_state and result.call_depth==0,
                        'binding failure entered guest or changed State')
            if test_write:record.update(test_operation='memory-helper transaction, not guest PE instruction',prefix_state=write_prefix)
            return record
        finally:
            if ctx:self.lib.aot_context_destroy(ctx)
            self.lib.aot_state_destroy(state)


def fixture_inputs(supported_pe=None,variant_pe=None):
    return [('supported',Path(supported_pe).resolve() if supported_pe is not None else
             REPO/'build/switch-supported-fixture-v1/pe-02/switch8.exe'),
            ('variant',Path(variant_pe).resolve() if variant_pe is not None else
             REPO/'build/switch-variant-fixture-v1/pe-01/switch8_variant.exe')]


def main(build,packets,out,supported_pe=None,variant_pe=None):
    build,packets,out=map(lambda x:Path(x).resolve(),(build,packets,out))
    receipt=json.loads(build.read_text());driver=Path(receipt['driver']);provider=Path(receipt['provider'])
    require(b.digest(driver)==receipt['driver_sha256'],'driver receipt mismatch')
    manifest,paths=b.paths_for(provider);out=b.fresh(out);run=b.Recorder(out,Path(receipt['prefix']))
    snapshot=b.source_snapshot(out,SOURCES);records=[]
    b.write_json(out/'started.json',dict(status='STARTED_NOT_PASSED',sources=snapshot,driver_sha256=b.digest(driver)))
    try:
        for label,pe in fixture_inputs(supported_pe,variant_pe):
            area=out/label;area.mkdir();source=pe.read_bytes();packet=json.loads((packets/(label+'.packet.json')).read_text())
            proof=prove_switch(source,packet,0x1000);validate_switch(proof,source,packet)
            (area/'input.exe').write_bytes(source)
            b.write_json(area/'proof.json',proof);(area/'data.bin').write_bytes(bytes.fromhex(proof['data_bytes']))
            argv=[driver,'--os=windows','--arch=amd64','--bytes='+proof['text_bytes'],
                  '--address='+str(proof['text_address']),'--entry_address='+str(proof['image_base']+proof['root_rva']),
                  '--aot_semantics='+str(paths['semantics']),'--aot_switch_profile=clang-rel32-v1',
                  '--aot_switch_data_path='+str(area/'data.bin'),'--aot_switch_data_va='+str(proof['data_address']),
                  '--aot_manifest='+str(area/'candidate.json')]
            # The same lift request without complete proof must reject before IR.
            run([*argv,'--ir_out='+str(area/'must-not-exist.ll')],label+'-no-proof',expected=1)
            require(not (area/'must-not-exist.ll').exists(),'unproved IR generated')
            validate_switch(proof,source,packet)
            run([*argv,'--aot_switch_proof_path='+str(area/'proof.json'),'--ir_out='+str(area/'lifted.ll'),
                 '--ir_pre_out='+str(area/'pre.ll')],label+'-lift')
            require(json.loads((area/'candidate.json').read_text())==packet,'fresh decoder packet changed')
            llvm=paths['llvm']/'bin'
            # Scoped recorder retains unique labels, no old evidence overwrite.
            def scoped(args,name):return run(args,label+'-'+name)
            ir=retarget(area/'lifted.ll',area,llvm,scoped)
            programs={}
            for mode in ('O0','O3'):
                obj=area/(mode+'.o');lib=area/(mode+'.dylib')
                scoped([llvm/'clang','-target','arm64-apple-macos11','-'+mode,'-c',ir,'-o',obj],mode+'-compile')
                scoped(['/usr/bin/clang','-arch','arm64','-isysroot',paths['sdk'],'-std=c11','-'+mode,
                        '-Wall','-Wextra','-Werror','-dynamiclib',HERE/'runtime.c',obj,
                        '-D__declspec(x)=__attribute__((x))',REPO/'switch_supported_fixture_v1/switch8.c',
                        REPO/'switch_variant_fixture_v1/switch8_variant.c','-o',lib],mode+'-link')
                require(struct.unpack_from('<II',lib.read_bytes())==(0xfeedfacf,0x100000c),'not thin ARM64 Mach-O')
                programs[mode]=Program(lib,proof,source)
            rng=random.Random(0x51a07);cases=[]
            for selector in list(range(10))+[0xffffffff,0x80000000]:
                for value in (0,1,0x7fffffff,0x80000000,0xffffffff,rng.getrandbits(32)):
                    regs=[rng.getrandbits(64)|0xa5a5000000000000 for _ in range(16)];regs[4]=RSP
                    values=(selector,value) if label=='supported' else (value,selector)
                    for index,x in zip((1,2),values):regs[index]=(regs[index]&~0xffffffff)|x
                    cases.append((selector,value,regs,values))
            normal=[]
            for selector,value,regs,values in cases:
                pair={mode:p.execute(regs) for mode,p in programs.items()}
                require(pair['O0']==pair['O3'],'full State/status/memory O0/O3 mismatch')
                expected=getattr(programs['O0'].lib,'switch8' if label=='supported' else 'switch8_variant')(*values)
                for mode,got in pair.items():
                    require(got['status']==0 and got['returned']==1 and got['depth']==0,'normal execution failure')
                    require(got['registers'][0]==expected,'compiled original C return mismatch')
                    require(got['registers'][4]==RSP+8 and got['registers'][16]==EXIT_VA,'RET/stack mismatch')
                    for index in (3,5,6,7,9,10,11,12,13,14,15):
                        require(got['registers'][index]==regs[index],'unmodified GPR changed')
                normal.append(dict(selector=selector,value=value,input_registers=regs,expected=expected,results=pair))
            # Injected host corruption tests the runtime membership gate; it is not an admitted PE.
            regs=list(cases[0][2]);candidate=proof['switch'];nodes=packet['instructions']
            jump_index=next(i for i,x in enumerate(nodes) if x['address']==candidate['jump_pc'])
            load_index=next(i for i,x in enumerate(nodes) if x['address']==candidate['load_pc'])
            boundaries=[]
            for mode,program in programs.items():
                prefix=program.execute(regs,budget=jump_index,corrupt=True)
                bad=program.execute(regs,corrupt=True)
                require(prefix['status']==4 and bad['status']==6 and bad['state']==prefix['state'],'JMP full-State rollback')
                require(bad['fault']['pc']==candidate['jump_pc'] and bad['depth']==0 and not bad['returned'],'JMP fault boundary')
                load_prefix=program.execute(regs,budget=load_index)
                denied=program.execute(regs,readable=False)
                require(load_prefix['status']==4 and denied['status']==2 and denied['state']==load_prefix['state'],'table read rollback')
                require(denied['fault']['pc']==candidate['load_pc'] and denied['fault']['width']==4,'table fault address')
                binding=[]
                for name,expected in [('legal_member',6),('target_signature',6),('writable',2),('executable',2),('missing',1),('unbound',None)]:
                    got=program.execute(regs,binding_case=name)
                    require(got['binding_status']==expected,'binding refusal classification')
                    binding.append(got)
                write=program.execute(regs,test_write=True)
                require(write['status']==2 and write['steps']==1 and write['depth']==0 and not write['returned'] and
                        write['state']==write['prefix_state'],'read-only helper write rollback')
                require(write['fault']==dict(status=2,access=2,pc=candidate['load_pc'],address=candidate['table_pc'],width=4),'write fault record')
                budgets=[]
                for phase,pc in [('guard',candidate['guard_pc']),('load',candidate['load_pc']),('add',candidate['add_pc']),
                                 ('jump',candidate['jump_pc']),('case_first',candidate['targets'][0])]:
                    count=next(i for i,x in enumerate(nodes) if x['address']==pc)
                    got=program.execute(regs,budget=count)
                    require(got['status']==4 and got['steps']==count and got['depth']==0 and not got['returned'] and
                            got['registers'][16]==pc and got['registers'][4]==RSP,'instruction budget boundary')
                    require(got['fault']==dict(status=4,access=0,pc=pc,address=pc,width=0),'budget fault record')
                    budgets.append(dict(phase=phase,budget=count,result=got))
                boundaries.append(dict(mode=mode,jump_prefix=prefix,bad_target=bad,load_prefix=load_prefix,unreadable_table=denied,
                                       binding_rejections=binding,read_only_write=write,budgets=budgets))
            for field in ('binding_rejections','read_only_write','budgets'):
                require(boundaries[0][field]==boundaries[1][field],'O0/O3 full-State boundary mismatch')
            b.write_json(area/'normal.json',normal);b.write_json(area/'boundaries.json',boundaries)
            require(b.digest(pe)==proof['pe_sha256'],'source PE changed during execution')
            records.append(dict(label=label,pe=str(pe),pe_sha256=proof['pe_sha256'],normal_cases=len(normal),arm_executions=len(normal)*2+18,binding_rejection_attempts=12,helper_transactions=2,
                                layout=programs['O0'].layout,proof_sha256=b.digest(area/'proof.json'),
                                artifacts={str(p.relative_to(area)):b.digest(p) for p in area.iterdir() if p.is_file()}))
        b.check_sources(snapshot)
        require(b.digest(driver)==receipt['driver_sha256'],'driver changed')
        b.write_json(out/'result.json',dict(schema=1,status='PASS_ARM64_O0_O3_AND_NATIVE_C_REFERENCE',records=records,
                    sources=snapshot,commands=run.commands,raw_x86_oracle=False,app_executions=0,gpu_executions=0,
                    scope='bounded two leaf fixtures; fullState O0/O3; native C checks return only; not arbitrary PE/App support'))
        print(json.dumps({'status':'PASS_ARM64_O0_O3_AND_NATIVE_C_REFERENCE','records':len(records)}))
    except BaseException as error:
        b.write_json(out/'failure.json',dict(status='FAILED',error=repr(error),traceback=traceback.format_exc(),completed=records,commands=run.commands));raise


def cli(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True);parser.add_argument('--packets',required=True);parser.add_argument('--out',required=True)
    parser.add_argument('--supported-pe',help='Explicit first fixture PE (default: historical local build output)')
    parser.add_argument('--variant-pe',help='Explicit second fixture PE (default: historical local build output)')
    return main(**vars(parser.parse_args(argv)))


if __name__=='__main__':
    cli()
