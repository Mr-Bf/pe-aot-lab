#!/usr/bin/env python3
"""Actual SETZ DIL PE-byte differential: 128 raw x86 inputs, ARM O3 and O0.

Uses the frozen scalar host/oracle harness unchanged. Only the new Draw lifter
admits the added DIL byte shape. There is no D3D/GPU or Window execution here.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import platform
import random
import struct
import subprocess
import sys
import traceback
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from draw_bridge import lift
from draw_bridge.build_lifter import LIFTER,BUILD,OUT as TOOL_OUT
from d3d11_bridge import test_scalars as host
OUT=ROOT/'build/draw-bridge/dil'
require,sha,digest,snapshot=host.require,host.sha,host.digest,host.snapshot
MASK=0x8d5
BODY='cmpl %ecx,%edx\nsetz %dil\nretq\n'

def vectors():
    rng=random.Random(0xD11D1101);result=[]
    for index in range(128):
        regs=[rng.getrandbits(64) for _ in range(16)];regs[4]=host.RSP
        regs[7]|=0x9e37000000000000 # every input observes nonzero high bits
        left=rng.getrandbits(32)
        right=left if index%3==0 else (left+1)&0xffffffff if index%3==1 else (left-1)&0xffffffff
        regs[1]=(regs[1]&~0xffffffff)|left;regs[2]=(regs[2]&~0xffffffff)|right
        base=[host.BASE,0x180000000,0x220000000][index%3]+(index//3)*65536
        data=bytearray(rng.randbytes(8192));struct.pack_into('<Q',data,0,base+0x2000)
        result.append({'gpr':regs,'base':base,'data':bytes(data)})
    return result

def source_paths():
    paths={Path(__file__),Path(host.__file__),host.HERE/'scalar_runtime.c',host.HERE/'scalar_oracle.c',
      host.HERE/'scalar_oracle.S',ROOT/'fixtures.py',ROOT/'integration_stage3/bindings.py',
      ROOT/'integration_stage3/runtime.c',ROOT/'integration_stage3/runtime.h',ROOT/'memory_stage2/guest_memory.h',
      ROOT/'memory_stage2/image_loader.py',LIFTER,TOOL_OUT/'build-manifest.json',BUILD/'lib/Arch/X86/Runtime/amd64.bc',
      Path('/usr/bin/arch'),Path('/usr/bin/xcrun'),Path(sys.executable)}
    paths|={ROOT/p for p in lift.SOURCE_PATHS+lift.EXTERNAL_SOURCE_PATHS+host.SOURCE_PATHS+host.EXTERNAL_SOURCE_PATHS}
    return paths

def main(out=OUT):
    require(platform.machine() in ('arm64','aarch64'),'native ARM64 host required')
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json'
    require(not evidence.exists(),'preserve previous evidence; select a fresh --out')
    inputs=source_paths()
    compiler=Path(subprocess.check_output(['/usr/bin/xcrun','--find','clang'],text=True).strip())
    sdk=Path(subprocess.check_output(['/usr/bin/xcrun','--show-sdk-path'],text=True).strip())
    inputs|={compiler,Path(subprocess.check_output(['/usr/bin/xcrun','--find','ld'],text=True).strip())}
    initial=snapshot(inputs);normal=[]
    try:
        area=out/'setz_dil';area.mkdir(exist_ok=True)
        pe,code=host.make_pe(area,'setz_dil',BODY)
        require(code==bytes.fromhex('39ca400f94c7c3'),'unexpected real COFF byte encoding')
        module=area/'module';manifest=lift.lift_pe(pe,module)
        require(len(manifest['instructions'])==3 and any(i['function']=='SETZ_GPR8' for i in manifest['instructions']),
                'actual new lifter DIL semantic missing')
        corpus=vectors();raw=host.raw_oracle(pe,code,area/'oracle',corpus,compiler,sdk,inputs)
        programs={mode:host.ScalarProgram(pe,module,mode,compiler,sdk,inputs) for mode in ('O3','O0')}
        inputs|={p for p in out.rglob('*') if p.is_file() and p!=evidence}
        before=snapshot(inputs);require(all(before[p]==h for p,h in initial.items()),'producer changed during setup')
        states={mode:bytearray() for mode in programs};data_dumps={mode:bytearray() for mode in programs}
        coverage={'true':0,'false':0}
        for index,(case,want) in enumerate(zip(corpus,raw)):
            zero=bool(want['flags']&0x40);coverage['true' if zero else 'false']+=1
            expected=(case['gpr'][7]&~255)|int(zero)
            require(want['gpr'][7]==expected,'raw DIL does not preserve RDI upper56')
            pair={}
            for mode,program in programs.items():
                actual=program.run(case);pair[mode]=actual
                require(actual['status']==0 and actual['returned'] and actual['steps']==3 and actual['depth']==0,
                        'ARM leaf termination mismatch')
                require(actual['gpr']==want['gpr'] and actual['rip']==want['rip'] and
                        (actual['flags']&MASK)==(want['flags']&MASK) and actual['data']==want['data'],
                        'raw/ARM differential mismatch '+mode+' '+str(index))
                require(actual['gpr'][7]==expected,'ARM DIL upper56 mismatch')
                states[mode].extend(actual['state']);data_dumps[mode].extend(actual['data'])
                normal.append({'index':index,'mode':mode,'status':'PASS','steps':3,'condition':zero,
                               'state_sha256':digest(actual['state']),'data_sha256':digest(actual['data'])})
            require(pair['O3']['state']==pair['O0']['state'],'full 3504-byte State O3/O0 mismatch')
        require(coverage=={'true':43,'false':85},'both SETZ branches must be covered')
        after=snapshot(inputs);require(before==after,'actual source/module/binary changed during execution')
        for mode in programs:
            (out/('state-'+mode+'.bin')).write_bytes(states[mode]);(out/('data-'+mode+'.bin')).write_bytes(data_dumps[mode])
        (out/'results.json').write_text(json.dumps(normal,indent=2)+'\n')
        record={'schema':1,'status':'PASS_ACTUAL_SETZ_DIL_DIFFERENTIAL','raw_unique_cases':128,
                'arm_executions':256,'modes':['O3','O0'],'condition_coverage':coverage,'defined_flags_mask':MASK,
                'full_state_bytes_per_case':3504,'raw_code_hex':code.hex(),'inputs_before':before,'inputs_after':after,
                'initial_inputs':initial,'actual_libraries':{mode:str(p.library) for mode,p in programs.items()},
                'artifacts':snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence),
                'gpu_executions':0,'windows_executions':0,
                'scope':'original x86 PE .text bytes under Rosetta oracle vs actual new Draw Remill ARM64; frozen transactional memory harness; all GPR/defined flags/RSP/RIP/data plus full State O3/O0; not guest D3D/graphics/performance proof'}
        evidence.write_text(json.dumps(record,indent=2)+'\n')
        print(json.dumps(verify_evidence(out)))
    except Exception as error:
        failure={'status':'FAIL','error':str(error),'traceback':traceback.format_exc(),'initial_inputs':initial,
                 'completed_arm_executions':len(normal),'gpu_executions':0}
        (out/'first-failure.json').write_text(json.dumps(failure,indent=2)+'\n')
        evidence.write_text(json.dumps(failure,indent=2)+'\n');raise

def verify_evidence(out=OUT):
    out=Path(out).resolve();evidence=out/'evidence.json';e=json.loads(evidence.read_text())
    require(e.get('schema')==1 and e.get('status')=='PASS_ACTUAL_SETZ_DIL_DIFFERENTIAL','DIL evidence not PASS')
    require(e['raw_unique_cases']==128 and e['arm_executions']==256 and e['modes']==['O3','O0'], 'DIL count/mode mismatch')
    require(e['condition_coverage']=={'true':43,'false':85} and e['defined_flags_mask']==MASK and e['full_state_bytes_per_case']==3504,'DIL scope mismatch')
    require(e['gpu_executions']==e['windows_executions']==0 and e['raw_code_hex']=='39ca400f94c7c3','DIL code/scope mismatch')
    before=e['inputs_before'];require(before==e['inputs_after'] and snapshot(before)==before,'tested inputs changed')
    require({str(p.resolve()) for p in source_paths()}<=set(before),'required source closure omitted')
    actual_artifacts=snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence)
    require(e['artifacts']==actual_artifacts,'executed artifact closure changed')
    for mode,path in e['actual_libraries'].items():
        p=Path(path);require(mode in ('O3','O0') and p.name=='scalar-'+sha(p)+'.dylib','immutable loaded library mismatch')
    require(set(e['actual_libraries'])=={'O3','O0'},'loaded mode set mismatch')
    corpus=vectors();area=out/'setz_dil/oracle';request=(area/'request.bin').read_bytes();response=(area/'response.bin').read_bytes()
    encoded=b''.join(struct.pack('<8s17Q',b'SCAIN001',*c['gpr'],2)+c['data'] for c in corpus)
    require(request==encoded and len(response)==128*(152+8192),'raw stream corpus mismatch')
    run=json.loads((area/'run.json').read_text());meta=json.loads(run['stderr'])
    require(run['returncode']==0 and run['stdin_sha256']==digest(request) and run['stdout_sha256']==digest(response),'raw execution stream identity mismatch')
    require(meta=={'status':'RAW_X86_PASS','cases':128,'translated':1,'raw_pe_code_identity':True},'raw native oracle identity mismatch')
    identity=json.loads((area/'run-identity.json').read_text())
    require(identity['inputs_before']==identity['inputs_after'] and snapshot(identity['inputs_before'])==identity['inputs_before'],'raw identity stale')
    states={m:(out/('state-'+m+'.bin')).read_bytes() for m in ('O3','O0')}
    datas={m:(out/('data-'+m+'.bin')).read_bytes() for m in ('O3','O0')}
    require(states['O3']==states['O0'] and len(states['O3'])==128*3504,'full State identity mismatch')
    require(datas['O3']==datas['O0'] and len(datas['O3'])==128*8192,'full data identity mismatch')
    rows=json.loads((out/'results.json').read_text());require(len(rows)==256,'result row count')
    by={(r['mode'],r['index']):r for r in rows}
    require(set(by)=={(m,n) for m in ('O3','O0') for n in range(128)},'duplicate/missing result rows')
    offsets=[2216,2248,2264,2232,2312,2328,2280,2296,2344,2360,2376,2392,2408,2424,2440,2456,2472]
    flags=[(2065,0),(2067,2),(2069,4),(2071,6),(2073,7),(2077,11)];counts={'true':0,'false':0}
    for index,case in enumerate(corpus):
        raw=struct.unpack_from('<8s18Q',response,index*(152+8192));require(raw[0]==b'SCAOUT01','raw response magic')
        data=response[index*(152+8192)+152:(index+1)*(152+8192)]
        zero=bool(raw[17]&0x40);counts['true' if zero else 'false']+=1
        require(raw[8]==(case['gpr'][7]&~255)|int(zero),'raw RDI upper56 not preserved')
        for mode in ('O3','O0'):
            state=states[mode][index*3504:(index+1)*3504];actual_data=datas[mode][index*8192:(index+1)*8192]
            regs=[struct.unpack_from('<Q',state,offset)[0] for offset in offsets]
            flag=sum((state[offset]!=0)<<bit for offset,bit in flags)
            require(regs[:16]==list(raw[1:17]) and regs[16]==raw[18] and flag==(raw[17]&MASK) and actual_data==data,'offline actual State/raw/data mismatch')
            row=by[(mode,index)]
            require(row['status']=='PASS' and row['steps']==3 and row['condition'] is zero and row['state_sha256']==digest(state) and row['data_sha256']==digest(data),'summary/actual bytes mismatch')
    require(counts==e['condition_coverage'],'observed condition count mismatch')
    return {'status':'PASS_CURRENT','raw_unique_cases':128,'arm_executions':256,'gpu_executions':0,'evidence_sha256':sha(evidence)}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=OUT);p.add_argument('--verify-only',action='store_true');a=p.parse_args()
    if a.verify_only:print(json.dumps(verify_evidence(a.out)))
    else:main(a.out)
