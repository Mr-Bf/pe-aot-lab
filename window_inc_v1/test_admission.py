"""Static decoder and metadata rejection gates. No guest execution."""
import argparse,copy,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from window_inc_v1 import lift
from window_inc_v1.build_lifter import LIFTER,OUT as TOOL_OUT,digest
OUT=ROOT/'build/window-inc-v1/admission'
REGS={'RAX':'ff00','RCX':'ff01','RDX':'ff02','RBX':'ff03','RBP':'ff4500','RSI':'ff06','RDI':'ff07',
 'R8':'41ff00','R9':'41ff01','R10':'41ff02','R11':'41ff03','R12':'41ff0424','R13':'41ff4500','R14':'41ff06','R15':'41ff07'}
NEGATIVE={'rsp':'ff0424','index':'ff0408','scaled_index':'ff0488','disp8':'ff4001','disp32':'ff8000100000',
 'no_base':'ff042500100000','inc8':'fe00','inc16':'66ff00','inc64':'48ff00','dec32':'ff08','add_rmw':'830001',
 'lock':'f0ff00','rep':'f3ff00','gs':'65ff00','fs':'64ff00','addr32':'67ff00','setz_mem':'0f9400','setnz_al':'0f95c0','setnz_dil':'400f95c7'}
def require(v,m):
 if not v:raise RuntimeError(m)
def sources():return [Path(__file__),LIFTER,TOOL_OUT/'build-manifest.json',*[ROOT/p for p in lift.SOURCE_PATHS+lift.EXTERNAL_SOURCE_PATHS]]
def snapshot(paths):return {str(Path(p).resolve()):digest(p) for p in sorted(set(map(Path,paths)))}
def decode(out,name,code,enabled=True):
 record=out/(name+'.json');args=[str(LIFTER),'--os=windows','--arch=amd64','--address=5368713216','--bytes='+code+'c3','--aot_decode_only','--aot_manifest='+str(record)]
 if enabled:args+=['--aot_inc_base32']
 p=subprocess.run(args,text=True,capture_output=True)
 log={'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr};(out/(name+'-command.json')).write_text(json.dumps(log,indent=2)+'\n')
 if p.returncode:
  require('REJECT' in p.stderr,'non-profile tool failure');return None
 instructions=json.loads(record.read_text())
 for row in instructions:row['rva']=row['address']-0x140000000
 return instructions
def main(out=OUT):
 out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True);require(not (out/'evidence.json').exists(),'fresh output required')
 before=snapshot(sources());positive=[];negative=[];metadata=[]
 for reg,code in REGS.items():
  rows=decode(out,'inc-'+reg,code);require(rows is not None,'GPR rejected '+reg);lift.validate_inc_metadata(rows)
  i=rows[0];require(i['function']=='INC_MEMv_32' and i['rmw_base_reg']==reg and i['rmw_displacement']==0 and i['rmw_width']==4,'INC shape metadata')
  positive.append('inc-'+reg)
 for name,code in [('rip','ff0500000000'),('setnz-sil','39ca400f95c6')]:
  rows=decode(out,name,code);require(rows is not None,'existing/SIL rejected');lift.validate_inc_metadata(rows);positive.append(name)
 for name,code in NEGATIVE.items():
  require(decode(out,name,code) is None,'negative byte accepted '+name);negative.append(name)
 require(decode(out,'flag-disabled',REGS['RAX'],False) is None,'new profile accepted without switch');negative.append('flag-disabled')
 # Static definedness: INC preserves CF, it cannot define an unknown CF.
 rows=decode(out,'undefined-cf',REGS['RAX']+'7200');require(rows is not None,'CF probe decode failed')
 try:lift.validate_flags(rows,0x140001000)
 except lift.TranslationError:negative.append('undefined-cf')
 else:raise RuntimeError('INC incorrectly defined CF')
 rows=decode(out,'undefined-zf','400f95c6');require(rows is not None,'ZF probe decode failed')
 try:lift.validate_flags(rows,0x140001000)
 except lift.TranslationError:negative.append('undefined-zf')
 else:raise RuntimeError('SETNZ accepted undefined ZF')
 base=decode(out,'metadata-base',REGS['RAX'])
 for key,value in [('rmw_base_reg','RSP'),('rmw_base_reg','EAX'),('rmw_base_reg',''),('rmw_displacement',1),('rmw_displacement',False),('rmw_width',8),('rmw_width',True),('kind',1),('flags_written',1),('flags_undefined',1)]:
  row=copy.deepcopy(base);row[0][key]=value
  try:lift.validate_inc_metadata(row)
  except lift.TranslationError:metadata.append({'field':key,'value':value,'status':'REJECT'})
  else:raise RuntimeError('bad metadata accepted '+key)
 after=snapshot(sources());require(before==after,'source/tool changed')
 r={'status':'PASS_STATIC_ADMISSION','schema':1,'inputs_before':before,'inputs_after':after,'positive':positive,'negative':negative,'metadata':metadata,
    'artifacts':snapshot(p for p in out.iterdir() if p.is_file()),'guest_executions':0,'gpu_executions':0}
 (out/'evidence.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(verify(out)))
def verify(out=OUT):
 out=Path(out).resolve();e=json.loads((out/'evidence.json').read_text())
 require(e['status']=='PASS_STATIC_ADMISSION' and e['schema']==1,'not PASS')
 require(e['inputs_before']==e['inputs_after']==snapshot(sources()),'source closure mismatch')
 require(e['artifacts']==snapshot(p for p in out.iterdir() if p.is_file() and p.name!='evidence.json'),'artifact closure mismatch')
 require(e['positive']==['inc-'+r for r in REGS]+['rip','setnz-sil'] and e['negative']==list(NEGATIVE)+['flag-disabled','undefined-cf','undefined-zf'],'case set mismatch')
 require(len(e['metadata'])==10 and all(r['status']=='REJECT' for r in e['metadata']),'metadata gate count')
 require(e['guest_executions']==e['gpu_executions']==0,'static scope')
 return {'status':'PASS_CURRENT','positive':17,'negative':22,'metadata_rejections':10,'guest_executions':0,'gpu_executions':0}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=OUT);p.add_argument('--verify-only',action='store_true');a=p.parse_args()
 print(json.dumps(verify(a.out))) if a.verify_only else main(a.out)
