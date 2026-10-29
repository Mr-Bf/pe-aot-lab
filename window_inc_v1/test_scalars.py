"""Real PE-byte INC/SETNZ differential. No window, GPU, or save/load execution."""
import argparse,copy,json,platform,random,struct,subprocess,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from window_inc_v1 import lift
from window_inc_v1.build_lifter import LIFTER,BUILD,OUT as TOOL_OUT
from d3d11_bridge import test_scalars as host
from memory_stage2.image_loader import load_image
HERE=Path(__file__).resolve().parent;OUT=ROOT/'build/window-inc-v1/scalars-r3'
require,sha,digest,snapshot,command=host.require,host.sha,host.digest,host.snapshot,host.command
COUNT=64;MASK=0x8d5
PREFIX='.byte 0xc7,0x05\n.long 0x2010-(0x1000+(. - guest_entry)+8)\n.long 0xa5a55a5a\ncmpl %ecx,%edx\n'
SHAPES={
 'inc_rax':(0,PREFIX+'incl (%rax)\nretq\n','c705061000005a5aa5a539caff00c3',4),
 'inc_rbp':(5,PREFIX+'incl (%rbp)\nretq\n','c705061000005a5aa5a539caff4500c3',4),
 'inc_r12':(12,PREFIX+'incl (%r12)\nretq\n','c705061000005a5aa5a539ca41ff0424c3',4),
 'inc_r15':(15,PREFIX+'incl (%r15)\nretq\n','c705061000005a5aa5a539ca41ff07c3',4),
 'setnz_sil':(16,'cmpl %ecx,%edx\nsetne %sil\nretq\n','39ca400f95c6c3',3),
}

def source_paths():
 paths={Path(__file__),HERE/'scalar_oracle.c',Path(host.__file__),host.HERE/'scalar_runtime.c',host.HERE/'scalar_oracle.S',
  ROOT/'fixtures.py',ROOT/'integration_stage3/bindings.py',ROOT/'integration_stage3/runtime.c',ROOT/'integration_stage3/runtime.h',
  ROOT/'memory_stage2/guest_memory.h',ROOT/'memory_stage2/image_loader.py',LIFTER,TOOL_OUT/'build-manifest.json',
  BUILD/'lib/Arch/X86/Runtime/amd64.bc',Path('/usr/bin/arch'),Path('/usr/bin/xcrun'),Path(sys.executable)}
 paths|={ROOT/p for p in lift.SOURCE_PATHS+lift.EXTERNAL_SOURCE_PATHS+host.SOURCE_PATHS+host.EXTERNAL_SOURCE_PATHS}
 return paths

def vectors(name):
 rng=random.Random(0x1ac330+list(SHAPES).index(name));rows=[];reg=SHAPES[name][0]
 words=[0,1,0x7fffffff,0x80000000,0xffffffff,0xf,0x7f,0xfffffffe]
 for index in range(COUNT):
  regs=[rng.getrandbits(64)|0xa5a5000000000000 for _ in range(16)];regs[4]=host.RSP
  x=rng.randrange(1,0xffffffff);y=x if name=='setnz_sil' and index%2==0 else x-1 if index%2 else x+1
  regs[1]=(regs[1]&~0xffffffff)|x;regs[2]=(regs[2]&~0xffffffff)|y
  base=[host.BASE,0x180000000,0x220000000][index%3]+(index//3)*65536
  data=bytearray(rng.randbytes(8192));struct.pack_into('<Q',data,0,base+0x2000)
  struct.pack_into('<I',data,0xffe,words[index] if index<len(words) else rng.getrandbits(32))
  if reg<16:regs[reg]=base+0x2ffe
  rows.append({'base':base,'gpr':regs,'data':bytes(data)})
 return rows

def raw_oracle(pe,code,out,corpus,base_reg,compiler,sdk,inputs):
 out.mkdir();image=load_image(pe);header=out/'scalar_image.h'
 header.write_text('static const unsigned char kImage[] = {'+','.join(map(str,image.data))+'};\n'+
  'static const unsigned char kPermissions[] = {'+','.join(map(str,image.permissions))+'};\n'+
  f'static const unsigned kCodeSize={len(code)},kBaseRegister={base_reg};\n')
 flags=['-arch','x86_64','-isysroot',str(sdk),'-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(out)]
 inputs|=host.c_dependencies(compiler,flags,HERE/'scalar_oracle.c',out/'dependencies.log')
 exe=out/'raw-x86';command([compiler,*flags,HERE/'scalar_oracle.c',host.HERE/'scalar_oracle.S','-o',exe],out/'compile.log')
 require(struct.unpack_from('<II',exe.read_bytes())==(0xfeedfacf,0x1000007),'raw oracle is not x86-64')
 request=b''.join(struct.pack('<8s17Q',b'SCAIN001',*c['gpr'],2)+c['data'] for c in corpus);(out/'request.bin').write_bytes(request)
 before=snapshot(inputs|{pe,header,exe,out/'request.bin'});result=command(['/usr/bin/arch','-x86_64',exe],out/'run.json',request)
 after=snapshot(before);require(before==after,'raw input identity drift');(out/'response.bin').write_bytes(result.stdout)
 require(json.loads(result.stderr)=={'status':'RAW_X86_PASS','cases':len(corpus),'translated':1,'raw_pe_code_identity':True},'raw metadata')
 require(len(result.stdout)==len(corpus)*(152+8192),'raw record length')
 (out/'identity.json').write_text(json.dumps({'inputs_before':before,'inputs_after':after,'normalized_addresses':['RSP/RET',('base register '+str(base_reg)) if base_reg<16 else 'none'],'source_pe':sha(pe)},indent=2)+'\n')
 return decode_raw(result.stdout)

def decode_raw(data):
 rows=[]
 for offset in range(0,len(data),152+8192):
  v=struct.unpack_from('<8s18Q',data,offset);require(v[0]==b'SCAOUT01','raw response magic')
  rows.append({'gpr':list(v[1:17]),'flags':v[17],'rip':v[18],'data':data[offset+152:offset+152+8192]})
 return rows

def semantic_check(name,case,got):
 expected=list(case['gpr']);expected[4]+=8
 carry=int((case['gpr'][2]&0xffffffff)<(case['gpr'][1]&0xffffffff))
 if name=='setnz_sil':
  expected[6]=(expected[6]&~255)|int((case['gpr'][2]&0xffffffff)!=(case['gpr'][1]&0xffffffff))
  data=case['data']
 else:
  old=struct.unpack_from('<I',case['data'],0xffe)[0];new=(old+1)&0xffffffff
  data=bytearray(case['data']);struct.pack_into('<I',data,0x10,0xa5a55a5a);struct.pack_into('<I',data,0xffe,new);data=bytes(data)
  flags=carry|((bin(new&255).count('1')%2==0)<<2)|(((old^1^new)&16)!=0)<<4|((new==0)<<6)|((new>>31)<<7)|((old==0x7fffffff)<<11)
  require(got['flags']&MASK==flags,'INC defined flags/model mismatch')
 require(got['gpr']==expected and got['data']==data,'GPR or full memory semantic mismatch')
 require(got['flags']&1==carry,'CF must remain CMP result through INC/SETNZ')

def main(out=OUT):
 require(platform.machine() in ('arm64','aarch64'),'ARM host required')
 out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json'
 require(not evidence.exists(),'fresh output required; existing evidence preserved')
 compiler=Path(subprocess.check_output(['/usr/bin/xcrun','--find','clang'],text=True).strip());sdk=Path(subprocess.check_output(['/usr/bin/xcrun','--show-sdk-path'],text=True).strip())
 inputs=source_paths()|{compiler,Path(subprocess.check_output(['/usr/bin/xcrun','--find','ld'],text=True).strip())}
 initial=snapshot(inputs);normal=[];boundaries=[];shapes={}
 try:
  for name,(base_reg,body,codehex,steps) in SHAPES.items():
   area=out/name;area.mkdir();pe,code=host.make_pe(area,name,body);require(code.hex()==codehex,'COFF bytes unexpected')
   m=lift.lift_pe(pe,area/'module');require(len(m['instructions'])==steps,'instruction count')
   corpus=vectors(name);raw=raw_oracle(pe,code,area/'oracle',corpus,base_reg,compiler,sdk,inputs)
   programs={mode:host.ScalarProgram(pe,area/'module',mode,compiler,sdk,inputs) for mode in ('O3','O0')}
   inputs|={p for p in area.rglob('*') if p.is_file()};before=snapshot(inputs)
   require(all(before[p]==h for p,h in initial.items()),'source drift in setup')
   states={mode:bytearray() for mode in programs};datas={mode:bytearray() for mode in programs};cf=[0,0]
   for index,(case,want) in enumerate(zip(corpus,raw)):
    semantic_check(name,case,want);cf[want['flags']&1]+=1;pair={}
    for mode,program in programs.items():
     got=program.run(case);pair[mode]=got;semantic_check(name,case,got)
     require(got['status']==0 and got['returned'] and got['steps']==steps and got['depth']==0,'termination')
     require(all(got[k]==want[k] for k in ('gpr','rip','data')) and got['flags']&MASK==want['flags']&MASK,'raw/ARM differential')
     states[mode].extend(got['state']);datas[mode].extend(got['data'])
     normal.append({'name':name,'mode':mode,'index':index,'state_sha256':digest(got['state']),'data_sha256':digest(got['data']),'status':'PASS'})
    require(pair['O3']['state']==pair['O0']['state'],'complete State modes differ')
   require(cf==[32,32],'CF branch balance')
   if base_reg<16:
    case=corpus[4]
    for mode,program in programs.items():
     prefix=program.run(case,budget=2);require(prefix['status']==4 and prefix['steps']==2 and not prefix['returned'],'budget prefix')
     inc=next(i for i in m['instructions'] if i['function']=='INC_MEMv_32');require(prefix['rip']==case['base']+inc['rva'],'prefix PC')
     (area/f'prefix-{mode}.bin').write_bytes(prefix['state']);(area/f'prefix-data-{mode}.bin').write_bytes(prefix['data'])
     boundaries.append({'name':name,'mode':mode,'case':'prefix','status':4,'steps':2})
     for layout,status,access in [('split_readonly',2,2),('split_unreadable',2,1),('split_missing',1,1)]:
      got=program.run(case,layout)
      require(got['status']==status and got['steps']==3 and not got['returned'],'fault classification')
      require(got['state']==prefix['state'] and got['data']==prefix['data'],'fullState rollback/partial RMW/prior write')
      require(got['fault']=={'status':status,'access':access,'pc':prefix['rip'],'address':case['base']+0x2ffe,'width':4},'fault detail')
      require(struct.unpack_from('<I',got['data'],0x10)[0]==0xa5a55a5a,'prior committed write lost')
      (area/f'{layout}-{mode}.bin').write_bytes(got['state']);(area/f'{layout}-data-{mode}.bin').write_bytes(got['data'])
      boundaries.append({'name':name,'mode':mode,'case':layout,**{k:got[k] for k in ('status','steps','fault')}})
     got=program.run(case,'split_rw');want=raw[4]
     require(got['status']==0 and got['returned'] and all(got[k]==want[k] for k in ('gpr','rip','data')) and got['flags']&MASK==want['flags']&MASK,'split backing success')
     (area/f'split_rw-{mode}.bin').write_bytes(got['state']);(area/f'split_rw-data-{mode}.bin').write_bytes(got['data'])
     boundaries.append({'name':name,'mode':mode,'case':'split_rw','status':0,'steps':4})
   require(before==snapshot(before),'execution input drift')
   for mode in states:(area/f'state-{mode}.bin').write_bytes(states[mode]);(area/f'data-{mode}.bin').write_bytes(datas[mode])
   shapes[name]={'code':codehex,'raw_unique':COUNT,'arm_normal':2*COUNT,'cf_counts':cf,'inputs_before':before,'inputs_after':snapshot(before),'libraries':{mode:str(p.library) for mode,p in programs.items()}}
  (out/'normal.json').write_text(json.dumps(normal,indent=2)+'\n');(out/'boundaries.json').write_text(json.dumps(boundaries,indent=2)+'\n')
  inputs|={p for p in out.rglob('*') if p.is_file() and p!=evidence};final=snapshot(inputs)
  require(all(final[p]==h for p,h in initial.items()),'source drift')
  e={'status':'PASS_RAW_X86_ARM64_SCALARS','schema':1,'shapes':shapes,'inputs_before':final,'inputs_after':snapshot(inputs),
    'artifacts':snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence),'raw_unique_cases':COUNT*len(SHAPES),'arm_normal_executions':len(normal),'arm_boundary_executions':len(boundaries),
    'guest_window_executions':0,'gpu_executions':0,'save_load_executions':0,'scope':'native ARM scalar execution; Rosetta only executes original x86 oracle; no Windows fault oracle; full State equality O0/O3 and exact boundary rollback'}
  evidence.write_text(json.dumps(e,indent=2)+'\n');print(json.dumps(verify(out)))
 except Exception as error:
  (out/'first-failure.json').write_text(json.dumps({'status':'FAIL','error':str(error),'traceback':traceback.format_exc(),'completed_arm_normal':len(normal),'completed_arm_boundaries':len(boundaries),'inputs':initial},indent=2)+'\n');raise

def verify(out=OUT):
 out=Path(out).resolve();evidence=out/'evidence.json';e=json.loads(evidence.read_text())
 require(e['status']=='PASS_RAW_X86_ARM64_SCALARS' and e['schema']==1,'missing PASS')
 require(e['inputs_before']==e['inputs_after'] and snapshot(e['inputs_before'])==e['inputs_before'],'changed inputs')
 require(set(map(str,map(Path.resolve,source_paths())))<=set(e['inputs_before']),'missing source closure')
 require(snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence)==e['artifacts'],'artifact set or identity differs')
 require((e['raw_unique_cases'],e['arm_normal_executions'],e['arm_boundary_executions'])==(320,640,40),'counts')
 require(e['guest_window_executions']==e['gpu_executions']==e['save_load_executions']==0,'scope')
 require(set(e['shapes'])==set(SHAPES),'shape set')
 rows=json.loads((out/'normal.json').read_text());by={(i['name'],i['mode'],i['index']):i for i in rows}
 require(len(by)==len(rows)==640,'normal row uniqueness')
 boundary_rows=json.loads((out/'boundaries.json').read_text());boundary_by={(i['name'],i['mode'],i['case']):i for i in boundary_rows}
 boundary_keys={(n,m,c) for n in SHAPES if n!='setnz_sil' for m in ('O3','O0') for c in ('prefix','split_readonly','split_unreadable','split_missing','split_rw')}
 require(len(boundary_by)==len(boundary_rows)==40 and set(boundary_by)==boundary_keys,'boundary exact unique set')
 offsets=[2216,2248,2264,2232,2312,2328,2280,2296,2344,2360,2376,2392,2408,2424,2440,2456,2472]
 flags=[(2065,0),(2067,2),(2069,4),(2071,6),(2073,7),(2077,11)]
 for name in SHAPES:
  area=out/name;record=e['shapes'][name];corpus=vectors(name);raw=decode_raw((area/'oracle/response.bin').read_bytes())
  require(record['code']==SHAPES[name][2] and record['cf_counts']==[32,32],'shape identity')
  require(record['inputs_before']==record['inputs_after'] and snapshot(record['inputs_before'])==record['inputs_before'],'per-shape identity')
  request=b''.join(struct.pack('<8s17Q',b'SCAIN001',*c['gpr'],2)+c['data'] for c in corpus)
  require((area/'oracle/request.bin').read_bytes()==request,'raw inputs')
  run=json.loads((area/'oracle/run.json').read_text());require(run['returncode']==0 and run['stdin_sha256']==digest(request) and run['stdout_sha256']==sha(area/'oracle/response.bin'),'raw stream receipt')
  require(json.loads(run['stderr'])=={'status':'RAW_X86_PASS','cases':64,'translated':1,'raw_pe_code_identity':True},'raw architecture')
  require((area/'state-O3.bin').read_bytes()==(area/'state-O0.bin').read_bytes(),'full State mode equality')
  for mode in ('O3','O0'):
   states=(area/f'state-{mode}.bin').read_bytes();datas=(area/f'data-{mode}.bin').read_bytes()
   require(len(states)==64*3504 and len(datas)==64*8192,'raw dump sizes')
   for i,(case,want) in enumerate(zip(corpus,raw)):
    state=states[i*3504:(i+1)*3504];regs=[struct.unpack_from('<Q',state,off)[0] for off in offsets]
    got={'gpr':regs[:16],'rip':regs[16],'flags':sum((state[off]!=0)<<bit for off,bit in flags),'data':datas[i*8192:(i+1)*8192]}
    semantic_check(name,case,want);semantic_check(name,case,got)
    require(all(got[k]==want[k] for k in ('gpr','rip','data')) and got['flags']&MASK==want['flags']&MASK,'offline raw/ARM equality')
    row=by[(name,mode,i)];require(row['status']=='PASS' and row['state_sha256']==digest(state) and row['data_sha256']==digest(got['data']),'row/bytes equality')
   if name!='setnz_sil':
    prefix=(area/f'prefix-{mode}.bin').read_bytes();data=(area/f'prefix-data-{mode}.bin').read_bytes()
    case=corpus[4];module=json.loads((area/'module/manifest.json').read_text())
    inc=next(i for i in module['instructions'] if i['function']=='INC_MEMv_32');pc=case['base']+inc['rva']
    prefix_regs=[struct.unpack_from('<Q',prefix,off)[0] for off in offsets]
    require(prefix_regs==case['gpr']+[pc],'prefix complete GPR/PC')
    lhs=case['gpr'][2]&0xffffffff;rhs=case['gpr'][1]&0xffffffff;sub=(lhs-rhs)&0xffffffff
    cmp_flags=int(lhs<rhs)|((bin(sub&255).count('1')%2==0)<<2)|((((lhs^rhs^sub)&16)!=0)<<4)|((sub==0)<<6)|((sub>>31)<<7)|((((lhs^rhs)&(lhs^sub)&0x80000000)!=0)<<11)
    actual_flags=sum((prefix[off]!=0)<<bit for off,bit in flags)
    expected_data=bytearray(case['data']);struct.pack_into('<I',expected_data,0x10,0xa5a55a5a)
    require(actual_flags&MASK==cmp_flags and data==bytes(expected_data),'prefix CMP flags / prior committed store / untouched INC data')
    require(boundary_by[(name,mode,'prefix')]=={'name':name,'mode':mode,'case':'prefix','status':4,'steps':2},'prefix receipt')
    for layout,status,access in [('split_readonly',2,2),('split_unreadable',2,1),('split_missing',1,1)]:
     require((area/f'{layout}-{mode}.bin').read_bytes()==prefix and (area/f'{layout}-data-{mode}.bin').read_bytes()==data,'offline rollback')
     expected={'name':name,'mode':mode,'case':layout,'status':status,'steps':3,'fault':{'status':status,'access':access,'pc':pc,'address':case['base']+0x2ffe,'width':4}}
     require(boundary_by[(name,mode,layout)]==expected,'boundary exact fault receipt')
    split_state=(area/f'split_rw-{mode}.bin').read_bytes();split_data=(area/f'split_rw-data-{mode}.bin').read_bytes()
    require(len(split_state)==3504 and len(split_data)==8192,'split success dump length')
    split_regs=[struct.unpack_from('<Q',split_state,off)[0] for off in offsets]
    got={'gpr':split_regs[:16],'rip':split_regs[16],'flags':sum((split_state[off]!=0)<<bit for off,bit in flags),'data':split_data}
    semantic_check(name,case,got);want=raw[4]
    require(all(got[k]==want[k] for k in ('gpr','rip','data')) and got['flags']&MASK==want['flags']&MASK,'offline split success raw differential')
    require(boundary_by[(name,mode,'split_rw')]=={'name':name,'mode':mode,'case':'split_rw','status':0,'steps':4},'split success receipt')
 return {'status':'PASS_CURRENT','raw_unique':320,'arm_normal':640,'arm_boundaries':40,'gpu':0,'save_load':0,'evidence_sha256':sha(evidence)}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=OUT);p.add_argument('--verify-only',action='store_true');a=p.parse_args()
 print(json.dumps(verify(a.out))) if a.verify_only else main(a.out)
