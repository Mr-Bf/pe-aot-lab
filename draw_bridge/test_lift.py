#!/usr/bin/env python3
"""Independent byte-shape/static gates. No lifted guest code is executed here."""
import argparse,copy,hashlib,json,subprocess,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from draw_bridge import lift
from draw_bridge.loader import load_image,ImageError
from draw_bridge.build_lifter import LIFTER,BUILD,OUT as TOOL_OUT,LLVM,PATCHES,digest
from fixtures import pe_image
OUT=ROOT/'build/draw-bridge/lift-tests/formal'
FIXTURES=ROOT/'build/draw-bridge/fixtures'

def require(value,message):
    if not value:raise RuntimeError(message)
def snapshot(paths):return {str(Path(p).resolve()):digest(p) for p in sorted(set(map(Path,paths)))}
def verify_evidence(out=OUT):
    out=Path(out).resolve();e=json.loads((out/'evidence.json').read_text())
    require(e['status']=='PASS_STATIC_NOT_GUEST_EXECUTED','static evidence not passing')
    require(e.get('schema')==1 and e.get('guest_execution_count')==0,'static-only scope changed')
    require(e['inputs_before']==e['inputs_after'],'static test inputs changed')
    require(snapshot(e['inputs_before'])==e['inputs_before'],'static evidence input hash stale')
    require(snapshot(e['artifacts_sha256'])==e['artifacts_sha256'],'static evidence artifact hash stale')
    actual_artifacts={str(p):digest(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=out/'evidence.json' and 'history' not in p.relative_to(out).parts}
    require(actual_artifacts==e['artifacts_sha256'],'static artifact closure incomplete')
    observed={'positive_byte_decodes':len(e['positive_decodes']),'negative_cases':len(e['negative_cases']),
              'metadata_rejections':len(e['metadata_rejections']),'module_builds':len(e['modules']),
              'original_cpp_virtual_calls':26}
    require(e['counts']==observed=={'positive_byte_decodes':250,'negative_cases':53,'metadata_rejections':13,
                                   'module_builds':5,'original_cpp_virtual_calls':26},'closed profile case counts differ')
    require({row['name'] for row in e['modules']}=={'normal','ret','RBP','R12','R15'},'module set differs')
    for row in e['modules']:
        manifest=json.loads(Path(row['manifest_path']).read_text())
        require(manifest['status']=='PASS' and manifest['validation_level']=='BUILD_STATIC_NOT_EXECUTED','module not static build PASS')
        require(manifest['inputs_before']==manifest['inputs_after'],'module build inputs changed')
        require(manifest['source_sha256']=={name:digest(ROOT/name) for name in lift.SOURCE_PATHS},'module producer closure differs')
        require(manifest['external_source_sha256']=={name:digest(ROOT/name) for name in lift.EXTERNAL_SOURCE_PATHS},'module parser closure differs')
        require(snapshot(manifest['inputs_before'])==manifest['inputs_before'],'module inputs stale')
        directory=Path(row['manifest_path']).parent
        require(set(manifest['artifact_sha256'])=={'text.bin','instructions-raw.json','lifted.ll','arm64.ll','arm64.o','arm64-o0.o'},'module artifact set differs')
        require({name:digest(directory/name) for name in manifest['artifact_sha256']}==manifest['artifact_sha256'],'module artifact changed')
        require(len(manifest['virtual_calls'])==row['virtual_calls'] and len(manifest['instructions'])==row['instructions'],'module count differs')
        for instruction in manifest['instructions']:
            if instruction['kind']==3:lift.validate_virtual_instruction(instruction)
    return e

def virtual_bytes(register,displacement):
    # Encode architectural register numbers directly; never use XED enum values.
    names=('RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI','R8','R9','R10','R11','R12','R13','R14','R15')
    reg=names.index(register);rm=reg&7
    mod=2 if displacement>127 else (1 if displacement or rm==5 else 0)
    code=bytearray(b'\x41' if reg>=8 else b'')
    code += bytes([0xff,(mod<<6)|(2<<3)|rm])
    if rm==4:code+=b'\x24' # SIB: no index, rsp/r12 base.
    if mod==1:code.append(displacement)
    elif mod==2:code+=int(displacement).to_bytes(4,'little',signed=True)
    return bytes(code)+b'\xc3'

def main(out=OUT):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    evidence=out/'evidence.json'
    if evidence.exists():
        history=out/'history';history.mkdir(exist_ok=True)
        (history/(digest(evidence)+'.json')).write_bytes(evidence.read_bytes())
    evidence.write_text('{"status":"RUNNING"}\n')
    deps=[Path(__file__),FIXTURES/'draw-readback.exe',FIXTURES/'manifest.json',
          LIFTER,BUILD/'lib/Arch/X86/Runtime/amd64.bc',TOOL_OUT/'build-manifest.json',
          *[ROOT/p for p in lift.SOURCE_PATHS+lift.EXTERNAL_SOURCE_PATHS]]
    before=snapshot(deps);positive=[];negative=[];modules=[];metadata_cases=[]
    def decode(name,raw,*,enabled=True,expect=True,register=None,slot=None,scalar=None):
        directory=out/'decode'/name;directory.mkdir(parents=True,exist_ok=True)
        path=directory/'instructions.json'
        if path.exists():path.unlink()
        (directory/'text.bin').write_bytes(raw)
        args=[str(LIFTER),'--os=windows','--arch=amd64','--address=5368713216',
              '--entry_address=5368713216','--bytes='+raw.hex(),
              '--aot_manifest='+str(path),'--aot_decode_only']
        if enabled:args.append('--aot_vtable_mem64')
        p=subprocess.run(args,text=True,capture_output=True)
        (directory/'command.log').write_text(json.dumps(args)+'\n'+p.stdout+p.stderr)
        item={'name':name,'bytes':raw.hex(),'returncode':p.returncode,'directory':str(directory)}
        if expect:
            require(p.returncode==0,'positive decode failed '+name+': '+p.stderr)
            instructions=json.loads(path.read_text());first=instructions[0]
            if scalar:
                selected=[i for i in instructions if i['iclass']==scalar]
                require(bool(selected),'new scalar instruction absent')
                for i in selected:
                    if scalar=='SETZ':require(i['function']=='SETZ_GPR8' and i['flags_read']==0x40 and i['flags_written']==0,'SETZ flag contract mismatch')
                    elif scalar=='CMOVNB':require(i['function']=='CMOVNB_GPRv_GPRv_32' and i['flags_read']==1 and i['flags_written']==0,'CMOVNB flag contract mismatch')
                    elif scalar=='INC':require(i['function']=='INC_MEMv_32' and not(i['flags_written']&1) and not(i['flags_undefined']&1),'INC must preserve CF definedness')
                lift.validate_flags(instructions,instructions[0]['address'])
                item['shape']=scalar
            else:
                require(len(instructions)==2 and first['kind']==3 and instructions[1]['kind']==2,'virtual/RET classification mismatch')
                require(first['base_reg']==register and first['slot']==slot and first['displacement']==slot*8 and 'method_signature' not in first,'decoded operand metadata mismatch')
                require(first['call_form']=='VTABLE_MEM64' and first['iat_slot_pc']==0 and first['target_pc']==0,'virtual call falsely became IAT/direct')
                item['shape']='VTABLE_MEM64'
            positive.append(item)
        else:
            require(p.returncode!=0 and 'REJECT' in p.stderr and not path.exists(),'negative not explicitly rejected '+name)
            item['rejection']=p.stderr.strip();negative.append(item)
    def module(name,pe=None,ret=False):
        directory=out/'modules'/name
        m=lift.build_ret_shim(directory) if ret else lift.lift_pe(pe,directory)
        modules.append({'name':name,'manifest_path':str(directory/'manifest.json'),
                        'manifest_sha256':digest(directory/'manifest.json'),
                        'instructions':len(m['instructions']),'virtual_calls':len(m['virtual_calls'])})
        return m
    try:
        for register in lift.REGISTER_IDS:
            for slot in sorted(lift.VIRTUAL_SLOTS):decode(register+'-'+str(slot),virtual_bytes(register,slot*8),register=register,slot=slot)
        # Same permitted address with a 32-bit displacement; no canonical-byte shortcut.
        decode('disp32',bytes.fromhex('ff9028000000c3'),register='RAX',slot=5)
        decode('setz-defined-true',bytes.fromhex('31c00f94c0c3'),scalar='SETZ')
        decode('setz-defined-false',bytes.fromhex('b80100000085c00f94c0c3'),scalar='SETZ')
        decode('setz-sil-defined-true',bytes.fromhex('31c0400f94c6c3'),scalar='SETZ')
        decode('setz-sil-defined-false',bytes.fromhex('b80100000085c0400f94c6c3'),scalar='SETZ')
        decode('setz-dil-defined-true',bytes.fromhex('31c0400f94c7c3'),scalar='SETZ')
        decode('setz-dil-defined-false',bytes.fromhex('b80100000085c0400f94c7c3'),scalar='SETZ')
        decode('cmovnb-defined-true',bytes.fromhex('31c00f43c1c3'),scalar='CMOVNB')
        decode('cmovnb-defined-false',bytes.fromhex('31c083f8010f43c1c3'),scalar='CMOVNB')
        decode('inc-rip-m32-defined-cf',bytes.fromhex('31c0ff05000000000f43c1c3'),scalar='INC')
        rejected={
            'call-register':'ffd0c3','jump-register':'ffe0','jump-memory':'ff20',
            'jump-rip':'ff2500000000','rsp-base':'ff1424c3','unregistered-rip':'ff1500000000c3',
            'indexed':'ff1408c3','absolute-sib':'ff142500000000c3',
            'negative-displacement':'ff50f8c3','unsupported-slot3':'ff5018c3','unsupported-queryinterface':'ff10c3','unsupported-addref':'ff5008c3','unsupported-slot51':'ff9098010000c3','unaligned-slot':'ff5001c3',
            'address32':'67ff10c3','segment-fs':'64ff10c3','segment-gs':'65ff10c3',
            'segment-cs':'2eff10c3','segment-ss':'36ff10c3','lock':'f0ff10c3',
            'repeat':'f3ff10c3','far-call':'ff18c3',
            'setz-cl':'0f94c1c3','setz-ah':'0f94c4c3','setz-r8b':'410f94c0c3',
            'setz-memory':'0f9400c3','setnz-al':'0f95c0c3','setz-bl':'0f94c3c3','cmovnb-reg64':'480f43c1c3','cmovnb-reg16':'660f43c1c3','cmovnb-memory':'0f4301c3','cmovb-reg32':'0f42c1c3','inc-rip-m64':'48ff0500000000c3','inc-rip-m16':'66ff0500000000c3','inc-rip-m8':'fe0500000000c3','inc-gpr-address-m32':'ff00c3','inc-indexed-m32':'ff0448c3','dec-rip-m32':'ff0d00000000c3','add-rip-m32':'83050000000001c3','lock-inc':'f0ff0500000000c3','inc-address32':'67ff0500000000c3','inc-segment':'64ff0500000000c3'}
        for name,raw in rejected.items():decode(name,bytes.fromhex(raw),expect=False)
        decode('profile-disabled',bytes.fromhex('ff5028c3'),enabled=False,expect=False)
        fixture=json.loads((FIXTURES/'manifest.json').read_text())['draw_readback']
        normal=module('normal',FIXTURES/'draw-readback.exe')
        expected=[(i['rva'],i['base_register'],i['slot']) for i in fixture['virtual_calls']]
        observed=[(i['call_rva'],i['base_reg'],i['slot']) for i in normal['virtual_calls']]
        require(expected==observed and len(observed)==26,'original C++ fixture callsites differ from decoded metadata')
        require(normal['input_sha256']==fixture['pe_sha256'],'fixture PE bytes changed')
        require({row['signature'] for row in normal['imports']}=={9,100},'method unexpectedly registered as IAT')
        module('ret',ret=True)
        for register,slot in [('RBP',12),('R12',44),('R15',13)]:
            pe=out/(register+'.exe');pe.write_bytes(pe_image(virtual_bytes(register,slot*8)))
            m=module(register,pe)
            require(len(m['virtual_calls'])==1,'synthetic module lacks real virtual call')
            text=(out/'modules'/register/'arm64.ll').read_text()
            for symbol in ('__remill_read_memory_64','__remill_write_memory_64','__remill_function_call','aot_commit','aot_should_exit'):
                require('@'+symbol+'(' in text,'actual lifted IR missing boundary '+symbol)
        # Defined flags before a call are not a post-call ABI promise.
        pe=out/'stale-flags.exe';pe.write_bytes(pe_image(bytes.fromhex('31c0ff50287500c3')))
        try:lift.lift_pe(pe,out/'stale-flags')
        except lift.TranslationError as error:
            require('undefined flags read' in str(error),'wrong flags rejection')
            negative.append({'name':'post-virtual-call-flags','rejection':str(error)})
        else:raise RuntimeError('post-call undefined flags incorrectly accepted')
        for name,raw in [('setz-entry-flags','0f94c0c3'),('setz-post-call-flags','31c0ff50280f94c0c3'),('setz-sil-entry-flags','400f94c6c3'),('setz-dil-entry-flags','400f94c7c3'),('setz-dil-post-call-flags','31c0ff5028400f94c7c3'),('cmovnb-entry-flags','0f43c1c3'),('cmovnb-post-call-flags','31c0ff50280f43c1c3'),('inc-preserves-undefined-cf','ff05000000000f43c1c3')]:
            pe=out/(name+'.exe');pe.write_bytes(pe_image(bytes.fromhex(raw)))
            try:lift.lift_pe(pe,out/name)
            except lift.TranslationError as error:
                require('undefined flags read' in str(error),'wrong SETZ rejection')
                negative.append({'name':name,'rejection':str(error)})
            else:raise RuntimeError('SETZ read of undefined ZF incorrectly accepted')
        # Mutate a real decoded instruction, independently of XED's emitter.
        base=next(i for i in normal['instructions'] if i['kind']==3)
        mutations=[('base_reg','RSP'),('base_reg','RIP'),('base_reg','EAX'),('base_reg',0),
                   ('displacement',24),('displacement',True),('slot',2),('method_signature',0),('signature',100),
                   ('target_rva',1),('iat_slot_rva',1),('kind',1),('function','CALL_NEAR_GPRv_64')]
        for key,value in mutations:
            row=copy.deepcopy(base);row[key]=value
            try:lift.validate_virtual_instruction(row)
            except lift.TranslationError as error:metadata_cases.append({'field':key,'value':value,'rejection':str(error)})
            else:raise RuntimeError('malformed virtual metadata accepted '+key)
        # Method names are not accepted as imported factory APIs.
        data=(FIXTURES/'draw-readback.exe').read_bytes();needle=b'D3D11CreateDevice\0'
        require(data.count(needle)==1,'D3D11 import name not unique')
        changed=data.replace(needle,b'CreateTexture2D\0'+bytes(len(needle)-len(b'CreateTexture2D\0')))
        try:load_image(changed)
        except ImageError as error:negative.append({'name':'method-as-IAT','rejection':str(error)})
        else:raise RuntimeError('method incorrectly allowed through IAT')
        after=snapshot(deps);require(before==after,'test input changed during verification')
        artifacts={str(p):digest(p) for p in sorted(out.rglob('*')) if p.is_file() and p!=evidence and 'history' not in p.relative_to(out).parts}
        result={'schema':1,'status':'PASS_STATIC_NOT_GUEST_EXECUTED','guest_execution_count':0,
            'notes':['State-layout probe executables run as part of lifting; no lifted guest or D3D11 runtime executes.',
                     'Build PASS and byte admission do not establish valid dynamic objects/vtables/targets or any GPU result.',
                     'Virtual method signatures must be resolved from registered interface_kind+slot+target, never inferred globally from slot.',
                     'Only SETZ DIL is a new scalar shape relative to the frozen D3D11 profile; actual true/false and preserved RDI upper bits need independent execution coverage. Inherited scalar rules are unchanged; no generic ISA claim.'],
            'inputs_before':before,'inputs_after':after,'artifacts_sha256':artifacts,
            'positive_decodes':positive,'negative_cases':negative,'metadata_rejections':metadata_cases,'modules':modules,
            'counts':{'positive_byte_decodes':len(positive),'negative_cases':len(negative),
                      'metadata_rejections':len(metadata_cases),'module_builds':len(modules),
                      'original_cpp_virtual_calls':len(normal['virtual_calls'])}}
        evidence.write_text(json.dumps(result,indent=2)+'\n')
        verify_evidence(out)
        print(json.dumps({'status':result['status'],'counts':result['counts'],'evidence_sha256':digest(evidence)}))
    except Exception as error:
        failure={'status':'FAIL','error':str(error),'traceback':traceback.format_exc(),'inputs_before':before,
                 'positive_decodes':positive,'negative_cases':negative,'modules':modules}
        first=out/'first-failure.json'
        if not first.exists():first.write_text(json.dumps(failure,indent=2)+'\n')
        evidence.write_text(json.dumps(failure,indent=2)+'\n');raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--verify-only',action='store_true')
    args=parser.parse_args()
    if args.verify_only:print(json.dumps({'status':verify_evidence(args.out)['status']}))
    else:main(args.out)
