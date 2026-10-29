#!/usr/bin/env python3
"""Window-only decoder/metadata gates and actual multi-root static ARM build."""
import argparse,copy,json,struct,subprocess,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from window_bridge import lift,prepare
from window_bridge.build_lifter import LIFTER,BUILD,OUT as TOOL_OUT,digest,snapshot
OUT=ROOT/'build/window-bridge/lift-tests/current'
PE=ROOT/'build/window-bridge/prepared-v2/integer-tile.exe'
NOPS=['6666666666662e0f1f840000000000','6666662e0f1f840000000000','662e0f1f840000000000']

def require(v,m):
 if not v:raise RuntimeError(m)

def dependencies():
 return {Path(__file__),LIFTER,BUILD/'lib/Arch/X86/Runtime/amd64.bc',TOOL_OUT/'build-manifest.json',PE,
         ROOT/'build/window-bridge/prepared-v2/evidence.json',ROOT/'build/window-bridge/prepared-v2/manifest.json',
         *[ROOT/p for p in lift.SOURCE_PATHS+lift.EXTERNAL_SOURCE_PATHS]}

def decode(out,name,code,*,enabled=True,slots=True):
 p=out/'decode'/name;p.mkdir(parents=True,exist_ok=True);manifest=p/'instructions.json'
 require(not manifest.exists(),'do not reuse decoder output')
 args=[str(LIFTER),'--os=windows','--arch=amd64','--address=4096','--entry_address=4096','--bytes='+code.hex(),
       '--aot_decode_only','--aot_manifest='+str(manifest),'--aot_vtable_mem64']
 if enabled:args.append('--aot_import_reg64')
 if slots:args.append('--aot_iat_slots=12288')
 r=subprocess.run(args,capture_output=True,text=True)
 record={'name':name,'code':code.hex(),'command':args,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
 if r.returncode==0:
  require(manifest.exists(),'decoder success without manifest');record['instructions']=json.loads(manifest.read_text())
 else:require('REJECT' in r.stderr and not manifest.exists(),'tool failure is not a profile rejection')
 (p/'result.json').write_text(json.dumps(record,indent=2)+'\n');return record

def normalized(raw):
 rows=copy.deepcopy(raw)
 for i in rows:
  i['rva']=i['address']-4096;i['target_rva']=i['target_pc']-4096 if i['target_pc'] else 0
  i['iat_slot_rva']=i.get('iat_slot_pc',0)-4096 if i.get('iat_slot_pc') else 0
 return rows

def main(out=OUT):
 out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json'
 require(not evidence.exists(),'use fresh output to preserve evidence')
 before=snapshot(dependencies());positive=[];negative=[];metadata=[]
 try:
  prepare.verify()
  def yes(name,hexcode,**kw):
   r=decode(out,name,bytes.fromhex(hexcode),**kw);require(r['returncode']==0,'expected admission '+name+': '+r['stderr']);positive.append(r);return r
  def no(name,hexcode,**kw):
   r=decode(out,name,bytes.fromhex(hexcode),**kw);require(r['returncode']!=0,'expected rejection '+name);negative.append(r);return r
  for index,reg in enumerate(lift.REGISTER_NAMES):
   if reg=='RSP':continue
   code=('41' if index>=8 else '')+'ff'+format(0xd0+index%8,'02x')+'c3'
   r=yes('register-'+reg,code);i=normalized(r['instructions'])[0]
   require(lift.validate_register_instruction(i)=={'call_rva':0,'operand_reg':reg,'operand_register':index},'register/AOT mapping differs')
  for slot in sorted(lift.VIRTUAL_SLOTS):
   code='ff90'+struct.pack('<i',slot*8).hex()+'c3';r=yes('virtual-slot-'+str(slot),code)
   i=normalized(r['instructions'])[0];require(lift.validate_virtual_instruction(i)['slot']==slot,'actual slot mismatch')
  for n,code in enumerate(NOPS):
   r=yes('padding-'+str(n),code+'c3');require(r['instructions'][0]['length']==len(bytes.fromhex(code)) and r['instructions'][0]['iclass']=='NOP','padding decode changed')
  for name,code in {'setnz-cl':'4539c10f95c1c3','setnz-dl':'4539c10f95c2c3','and-al-cl':'20c8c3','and-al-dl':'20d0c3','test-ax':'6685c0c3'}.items():
   r=yes(name,code);lift.validate_flags(normalized(r['instructions']),4096)
  no('register-disabled','41ffd6c3',enabled=False)
  no('register-no-import-set','41ffd6c3',slots=False)
  for name,code in {'register-rsp':'ffd4c3','register-jmp':'41ffe6','memory-general':'ff10c3',
       'vtable-rsp':'ff542440c3','vtable-index':'ff544840c3','vtable-negative':'ff50f8c3','vtable-unaligned':'ff5041c3',
       'vtable-qi':'ff10c3','vtable-addref':'ff5008c3','unregistered-iat':'ff1500000000c3',
       'setnz-al':'0f95c0c3','setnz-sil':'400f95c6c3','setnz-dil':'400f95c7c3','setnz-r8b':'410f95c0c3',
       'setnz-memory':'0f9501c3','setnz-ah':'0f95c4c3','setl-cl':'0f9cc1c3',
       'and8-reversed-opcode':'22c1c3','and8-wrong-dest':'20c1c3','and8-immediate':'24ffc3','and8-memory':'2201c3',
       'test16-cx':'6685c9c3','test16-other-source':'6685c8c3','test16-memory':'668501c3',
       'fs-nop':'640f1f00c3','cs-memory':'2e488b01c3','cs-other-nop':'2e0f1f00c3',
       'lock-nop':'f090c3','rep-nop':'f390c3','call-address32':'6741ffd6c3'}.items():no(name,code)
  def reject(name,operation):
   try:operation()
   except lift.TranslationError as error:metadata.append({'name':name,'error':str(error)})
   else:raise RuntimeError('metadata/flags rejection missing '+name)
  for name,code in [('undefined-zf','0f95c1c3'),('zf-after-register-call','4539c141ffd60f95c1c3')]:
   r=yes('byte-only-'+name,code);reject(name,lambda r=r:lift.validate_flags(normalized(r['instructions']),4096))
  actual=normalized(positive[0]['instructions'])[0]
  for name,key,value in [('wrong-kind','kind',3),('wrong-form','call_form','VTABLE_MEM64'),('rsp','operand_reg','RSP'),
    ('xed-enum','operand_reg',14),('static-target','target_rva',4096),('fake-iat','iat_slot_rva',8192),
    ('global-signature','signature',216),('method-signature','method_signature',150),('vtable-base','base_reg','RAX'),
    ('vtable-slot','slot',8),('vtable-displacement','displacement',64),('wrong-semantic','function','CALL_NEAR_MEMv_64')]:
   bad=copy.deepcopy(actual);bad[key]=value;reject(name,lambda bad=bad:lift.validate_register_instruction(bad))
  roots=lift.lift_roots(PE,out/'modules',[0x1000]);ret=lift.build_ret_shim(out/'ret')
  require(roots['main']['rva']==0x1140 and len(roots['main']['manifest']['register_calls'])==5,'main root/call metadata differs')
  require(roots['roots'][0]['rva']==0x1000 and roots['roots'][0]['symbol']=='aot_window_proc_1000','callback symbol/root differs')
  require(len(roots['instructions'])==517,'actual unique static instruction count changed')
  require(len(ret['instructions'])==1 and ret['instructions'][0]['bytes']=='c3','RET shim changed')
  for name,rv in [('duplicate-roots',[0x1000,0x1000]),('entry-as-callback',[0x1140]),('bad-type',[True])]:
   reject(name,lambda rv=rv:lift.lift_roots(PE,out/'rejected-roots'/name,rv))
  after=snapshot(dependencies());require(before==after,'producer changed during static validation')
  record={'schema':1,'status':'PASS_STATIC_WINDOW_ROOTS_NOT_EXECUTED','inputs_before':before,'inputs_after':after,
    'positive_decodes':len(positive),'profile_rejections':len(negative),'metadata_rejections':len(metadata),
    'positive':positive,'negative':negative,'metadata':metadata,'modules':3,'object_modes':['O3','O0'],
    'main_instructions':len(roots['main']['manifest']['instructions']),'callback_instructions':len(roots['roots'][0]['manifest']['instructions']),
    'unique_instructions':517,'register_call_sites':5,'explicit_callback_roots':1,
    'artifacts':snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence),
    'guest_window_executions':0,'gpu_executions':0,'windows_executions':0,
    'scope':'real Remill/XED decode and ARM object lowering only; State-layout probes execute native helper code, never guest roots; targets require runtime validation'}
  evidence.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(verify_evidence(out)))
 except Exception as error:
  failure={'status':'FAIL','error':str(error),'traceback':traceback.format_exc(),'inputs_before':before,
   'positive_completed':len(positive),'negative_completed':len(negative),'guest_window_executions':0,'gpu_executions':0}
  (out/'first-failure.json').write_text(json.dumps(failure,indent=2)+'\n');evidence.write_text(json.dumps(failure,indent=2)+'\n');raise

def verify_evidence(out=OUT):
 out=Path(out).resolve();evidence=out/'evidence.json';e=json.loads(evidence.read_text())
 require(e['schema']==1 and e['status']=='PASS_STATIC_WINDOW_ROOTS_NOT_EXECUTED','static proof is not PASS')
 require(e['inputs_before']==e['inputs_after'] and snapshot(e['inputs_before'])==e['inputs_before'],'source/tool/input identity stale')
 require(set(e['inputs_before'])=={str(p.resolve()) for p in dependencies()},'source closure differs')
 require(e['artifacts']==snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence),'static artifact set changed')
 require(e['guest_window_executions']==e['gpu_executions']==e['windows_executions']==0,'execution scope differs')
 require(e['positive_decodes']==len(e['positive']) and e['profile_rejections']==len(e['negative']) and e['metadata_rejections']==len(e['metadata']),'gate counts differ')
 for r in e['positive']:require(r['returncode']==0 and r['instructions'],'positive byte gate not actual decoder success')
 for r in e['negative']:require(r['returncode']!=0 and 'REJECT' in r['stderr'],'negative is tool failure, not rejection')
 for name in ('modules/main','modules/window-proc-1000','ret'):
  path=out/name;m=json.loads((path/'manifest.json').read_text())
  require(m['status']=='PASS' and m['validation_level']=='BUILD_STATIC_NOT_EXECUTED','module scope differs')
  require(m['inputs_before']==m['inputs_after'] and snapshot(m['inputs_before'])==m['inputs_before'],'module input identity stale')
  require(set(m['source_sha256'])==set(lift.SOURCE_PATHS) and set(m['external_source_sha256'])==set(lift.EXTERNAL_SOURCE_PATHS),'module source set omitted')
  require(all(digest(path/k)==v for k,v in m['artifact_sha256'].items()),'module object/IR identity stale')
 roots=json.loads((out/'modules/roots.json').read_text())
 require(len(roots['instructions'])==e['unique_instructions']==517 and len(roots['main']['manifest']['register_calls'])==5,'multi-root metadata changed')
 return {k:e[k] for k in ('status','positive_decodes','profile_rejections','metadata_rejections','modules','unique_instructions','register_call_sites','guest_window_executions','gpu_executions')}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=OUT);p.add_argument('--verify-only',action='store_true');a=p.parse_args()
 print(json.dumps(verify_evidence(a.out))) if a.verify_only else main(a.out)
