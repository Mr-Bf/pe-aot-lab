#!/usr/bin/env python3
"""Raw PE x86 / actual Remill ARM64 leaf checks; no window API or GPU execution."""
import argparse
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import traceback
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from window_bridge import lift
from window_bridge.build_lifter import LIFTER,BUILD,OUT as TOOL_OUT
from d3d11_bridge import test_scalars as host
OUT=ROOT/'build/window-bridge/scalars'
require,sha,digest,snapshot=host.require,host.sha,host.digest,host.snapshot
NOPS=['6666666666662e0f1f840000000000','6666662e0f1f840000000000','662e0f1f840000000000']
SHAPES={
 'setnz_cl':('cmpl %r8d,%r9d\nsetne %cl\nretq\n','4539c10f95c1c3',0x8d5,3),
 'setnz_dl':('cmpl %r8d,%r9d\nsetne %dl\nretq\n','4539c10f95c2c3',0x8d5,3),
 'and_al_cl':('andb %cl,%al\nretq\n','20c8c3',0x8c5,2),
 'and_al_dl':('andb %dl,%al\nretq\n','20d0c3',0x8c5,2),
 'test_ax':('testw %ax,%ax\nretq\n','6685c0c3',0x8c5,2),
 'padding_nops':('cmpl %r8d,%r9d\n'+''.join('.byte '+','.join('0x'+b for b in [code[n:n+2] for n in range(0,len(code),2)])+'\n' for code in NOPS)+'retq\n','4539c1'+''.join(NOPS)+'c3',0x8d5,5),
}
COUNT=64

def vectors(name):
 rng=random.Random(0x57494e30+list(SHAPES).index(name));result=[]
 for index in range(COUNT):
  regs=[rng.getrandbits(64)|0x9e37000000000000 for _ in range(16)];regs[4]=host.RSP
  operand=rng.getrandbits(32);regs[8]=(regs[8]&~0xffffffff)|operand
  regs[9]=(regs[9]&~0xffffffff)|(operand if index%2==0 else operand^1)
  if name=='test_ax':regs[0]=(regs[0]&~65535)|(0 if index%2==0 else (rng.getrandbits(16)|1))
  if name.startswith('and_') and index<16:
   regs[0]=(regs[0]&~255)|[0,255,128,85][index%4]
   source=1 if name.endswith('cl') else 2
   regs[source]=(regs[source]&~255)|[255,0,127,170][index//4]
  base=[host.BASE,0x180000000,0x220000000][index%3]+(index//3)*65536
  data=bytearray(rng.randbytes(8192));struct.pack_into('<Q',data,0,base+0x2000)
  result.append({'gpr':regs,'base':base,'data':bytes(data)})
 return result

def source_paths():
 paths={Path(__file__),Path(host.__file__),host.HERE/'scalar_runtime.c',host.HERE/'scalar_oracle.c',host.HERE/'scalar_oracle.S',
  ROOT/'fixtures.py',ROOT/'integration_stage3/bindings.py',ROOT/'integration_stage3/runtime.c',ROOT/'integration_stage3/runtime.h',
  ROOT/'memory_stage2/guest_memory.h',ROOT/'memory_stage2/image_loader.py',LIFTER,TOOL_OUT/'build-manifest.json',
  BUILD/'lib/Arch/X86/Runtime/amd64.bc',Path('/usr/bin/arch'),Path('/usr/bin/xcrun'),Path(sys.executable)}
 paths|={ROOT/p for p in lift.SOURCE_PATHS+lift.EXTERNAL_SOURCE_PATHS+host.SOURCE_PATHS+host.EXTERNAL_SOURCE_PATHS}
 return paths

def expected_registers(name,case,want):
 before=case['gpr'];after=want['gpr'];changed=set()
 if name.startswith('setnz'):
  reg=1 if name.endswith('cl') else 2;changed.add(reg)
  require(after[reg]==((before[reg]&~255)|int(not bool(want['flags']&0x40))),'SETNZ upper56/result mismatch')
 elif name.startswith('and_'):
  reg=1 if name.endswith('cl') else 2;changed.add(0)
  require(after[0]==((before[0]&~255)|((before[0]&255)&(before[reg]&255))),'AND upper56/result mismatch')
 for reg in set(range(16))-{4}-changed:
  require(after[reg]==before[reg],'unexpected GPR mutation in '+name)

def main(out=OUT):
 out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json'
 require(not evidence.exists(),'preserve prior evidence; use a fresh --out')
 compiler=Path(subprocess.check_output(['/usr/bin/xcrun','--find','clang'],text=True).strip())
 sdk=Path(subprocess.check_output(['/usr/bin/xcrun','--show-sdk-path'],text=True).strip())
 inputs=source_paths()|{compiler,Path(subprocess.check_output(['/usr/bin/xcrun','--find','ld'],text=True).strip())}
 initial=snapshot(inputs);rows=[];records={}
 try:
  for name,(body,codehex,mask,steps) in SHAPES.items():
   area=out/name;area.mkdir(exist_ok=True);pe,code=host.make_pe(area,name,body)
   require(code.hex()==codehex,'unexpected original COFF encoding '+name)
   module=area/'module';manifest=lift.lift_pe(pe,module)
   require(len(manifest['instructions'])==steps,'instruction count differs '+name)
   corpus=vectors(name);raw=host.raw_oracle(pe,code,area/'oracle',corpus,compiler,sdk,inputs)
   programs={mode:host.ScalarProgram(pe,module,mode,compiler,sdk,inputs) for mode in ('O3','O0')}
   inputs|={p for p in area.rglob('*') if p.is_file()}
   setup=snapshot(inputs);require(all(setup[k]==v for k,v in initial.items()),'source changed during setup')
   state={m:bytearray() for m in programs};data={m:bytearray() for m in programs};coverage={'zf0':0,'zf1':0}
   for index,(case,want) in enumerate(zip(corpus,raw)):
    expected_registers(name,case,want);coverage['zf1' if want['flags']&0x40 else 'zf0']+=1;pair={}
    for mode,program in programs.items():
     got=program.run(case);pair[mode]=got
     require(got['status']==0 and got['returned'] and got['steps']==steps and got['depth']==0,'leaf termination differs')
     require(got['gpr']==want['gpr'] and got['rip']==want['rip'] and (got['flags']&mask)==(want['flags']&mask) and got['data']==want['data'],
             'raw/ARM differential '+name+' '+mode+' '+str(index))
     expected_registers(name,case,got);state[mode].extend(got['state']);data[mode].extend(got['data'])
     rows.append({'shape':name,'mode':mode,'index':index,'status':'PASS','steps':steps,
       'state_sha256':digest(got['state']),'data_sha256':digest(got['data'])})
    require(pair['O0']['state']==pair['O3']['state'],'full 3504-byte State differs O0/O3')
   executed_after=snapshot(inputs);require(setup==executed_after,'actual ARM execution input/objects changed')
   require(coverage['zf0']>0 and coverage['zf1']>0,'missing flag branch coverage')
   if name.startswith('setnz') or name in ('test_ax','padding_nops'):require(coverage=={'zf0':32,'zf1':32},'condition balance differs')
   for mode in programs:
    (area/('state-'+mode+'.bin')).write_bytes(state[mode]);(area/('data-'+mode+'.bin')).write_bytes(data[mode])
   records[name]={'raw_unique_cases':COUNT,'arm_executions':COUNT*2,'raw_code_hex':codehex,'flags_mask':mask,'steps':steps,
     'flag_coverage':coverage,'execution_inputs_before':setup,'execution_inputs_after':executed_after,'actual_libraries':{m:str(p.library) for m,p in programs.items()}}
  # Every generated object/IR, request/response, compiler/header identity and
  # actual immutable loaded library joins the before/after execution closure.
  inputs|={p for p in out.rglob('*') if p.is_file() and p!=evidence}
  before=snapshot(inputs);require(all(before[k]==v for k,v in initial.items()),'producer changed during execution')
  (out/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
  after=snapshot(inputs);require(before==after,'inputs/artifacts changed at final capture')
  record={'schema':1,'status':'PASS_ACTUAL_WINDOW_SCALAR_DIFFERENTIAL','initial_inputs':initial,
    'inputs_before':before,'inputs_after':after,'shapes':records,'raw_unique_cases':COUNT*len(SHAPES),
    'arm_executions':COUNT*len(SHAPES)*2,'full_state_bytes_per_case':3504,'modes':['O3','O0'],
    'artifacts':snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence),
    'gpu_executions':0,'guest_window_executions':0,'windows_executions':0,
    'scope':'leaf byte semantics only; original x86 PE bytes under Rosetta vs true Remill ARM64; no API/CALL-reg/window runtime claim'}
  evidence.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(verify_evidence(out)))
 except Exception as error:
  record={'status':'FAIL','error':str(error),'traceback':traceback.format_exc(),'initial_inputs':initial,
     'completed_arm_executions':len(rows),'guest_window_executions':0,'gpu_executions':0}
  (out/'first-failure.json').write_text(json.dumps(record,indent=2)+'\n');evidence.write_text(json.dumps(record,indent=2)+'\n');raise

def verify_evidence(out=OUT):
 out=Path(out).resolve();evidence=out/'evidence.json';e=json.loads(evidence.read_text())
 require(e['schema']==1 and e['status']=='PASS_ACTUAL_WINDOW_SCALAR_DIFFERENTIAL','not current PASS')
 require(e['raw_unique_cases']==COUNT*len(SHAPES) and e['arm_executions']==COUNT*len(SHAPES)*2,'case counts')
 require(e['gpu_executions']==e['guest_window_executions']==e['windows_executions']==0,'scope differs')
 require(e['inputs_before']==e['inputs_after'] and snapshot(e['inputs_before'])==e['inputs_before'],'input closure changed')
 require({str(p.resolve()) for p in source_paths()}<=set(e['inputs_before']),'required source missing')
 require(snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence)==e['artifacts'],'artifact closure changed')
 require(set(e['shapes'])==set(SHAPES) and e['modes']==['O3','O0'] and e['full_state_bytes_per_case']==3504,'shape/mode/state scope')
 rows=json.loads((out/'results.json').read_text());by={(r['shape'],r['mode'],r['index']):r for r in rows}
 require(len(rows)==len(by)==e['arm_executions'] and set(by)=={(n,m,i) for n in SHAPES for m in ('O3','O0') for i in range(COUNT)},'duplicate/missing rows')
 offsets=[2216,2248,2264,2232,2312,2328,2280,2296,2344,2360,2376,2392,2408,2424,2440,2456,2472]
 flag_fields=[(2065,0),(2067,2),(2069,4),(2071,6),(2073,7),(2077,11)]
 for name,(_,codehex,mask,steps) in SHAPES.items():
  area=out/name;r=e['shapes'][name];corpus=vectors(name)
  require(r['execution_inputs_before']==r['execution_inputs_after'] and snapshot(r['execution_inputs_before'])==r['execution_inputs_before'],'shape execution objects/source changed')
  require(r['raw_code_hex']==codehex and r['flags_mask']==mask and r['steps']==steps,'shape bytes/flags differ')
  request=(area/'oracle/request.bin').read_bytes();response=(area/'oracle/response.bin').read_bytes()
  require(request==b''.join(struct.pack('<8s17Q',b'SCAIN001',*c['gpr'],2)+c['data'] for c in corpus) and len(response)==COUNT*(152+8192),'oracle stream corpus mismatch')
  run=json.loads((area/'oracle/run.json').read_text());meta=json.loads(run['stderr'])
  require(run['returncode']==0 and run['stdin_sha256']==digest(request) and run['stdout_sha256']==digest(response),'raw execution stream identity')
  require(meta=={'status':'RAW_X86_PASS','cases':COUNT,'translated':1,'raw_pe_code_identity':True},'raw executable identity')
  identity=json.loads((area/'oracle/run-identity.json').read_text())
  require(identity['inputs_before']==identity['inputs_after'] and snapshot(identity['inputs_before'])==identity['inputs_before'],'raw source changed')
  states={m:(area/('state-'+m+'.bin')).read_bytes() for m in ('O3','O0')};datas={m:(area/('data-'+m+'.bin')).read_bytes() for m in states}
  require(states['O0']==states['O3'] and len(states['O3'])==COUNT*3504,'full State modes mismatch')
  require(datas['O0']==datas['O3'] and len(datas['O3'])==COUNT*8192,'full memory modes mismatch')
  require(set(r['actual_libraries'])=={'O3','O0'},'loaded mode set')
  for mode,path in r['actual_libraries'].items():require(Path(path).name=='scalar-'+sha(path)+'.dylib','immutable library identity')
  coverage={'zf0':0,'zf1':0}
  for i,case in enumerate(corpus):
   raw=struct.unpack_from('<8s18Q',response,i*(152+8192));require(raw[0]==b'SCAOUT01','raw response magic')
   data=response[i*(152+8192)+152:(i+1)*(152+8192)];want={'gpr':list(raw[1:17]),'flags':raw[17]}
   expected_registers(name,case,want);coverage['zf1' if raw[17]&0x40 else 'zf0']+=1
   for mode in states:
    state=states[mode][i*3504:(i+1)*3504];actual_data=datas[mode][i*8192:(i+1)*8192]
    regs=[struct.unpack_from('<Q',state,offset)[0] for offset in offsets];flags=sum((state[off]!=0)<<bit for off,bit in flag_fields)
    require(regs[:16]==want['gpr'] and regs[16]==raw[18] and flags&mask==raw[17]&mask and actual_data==data,'offline raw/State/data comparison')
    row=by[(name,mode,i)];require(row['status']=='PASS' and row['steps']==steps and row['state_sha256']==digest(state) and row['data_sha256']==digest(data),'summary differs from bytes')
  require(coverage==r['flag_coverage'],'branch coverage differs')
 return {'status':'PASS_CURRENT','raw_unique_cases':e['raw_unique_cases'],'arm_executions':e['arm_executions'],
  'guest_window_executions':0,'gpu_executions':0,'evidence_sha256':sha(evidence)}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=OUT);p.add_argument('--verify-only',action='store_true');a=p.parse_args()
 print(json.dumps(verify_evidence(a.out))) if a.verify_only else main(a.out)
