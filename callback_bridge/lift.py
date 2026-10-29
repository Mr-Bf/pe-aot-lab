#!/usr/bin/env python3
"""Separate original-PE roots, with private traces, using the frozen IAT lifter."""
import argparse,dataclasses,json,pathlib,re,subprocess,sys
REPO=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO))
from native_bridge.build_lifter import SRC,BUILD,OUT as TOOL_OUT,LLVM,LIFTER,PATCHES,digest
from memory_stage2.image_loader import load_image as load_plain,EXEC,ImageError
from callback_bridge.loader import load_image
from fixtures import pe_image as plain_pe_image
SOURCE_PATHS=['callback_bridge/lift.py','native_bridge/build_lifter.py','integration_stage3/lifter_layout.cpp',*PATCHES]
EXTERNAL_SOURCE_PATHS=['memory_stage2/image_loader.py','callback_bridge/loader.py','callback_bridge/imports_v1.py','fixtures.py']
class TranslationError(ValueError):pass
Reject=TranslationError

def run(args,out,log='commands.log'):
 args=list(map(str,args));p=subprocess.run(args,text=True,capture_output=True)
 with (out/log).open('a') as f:f.write(json.dumps(args)+'\n'+p.stdout+p.stderr)
 if p.returncode:
  if 'REJECT' in p.stderr:raise TranslationError(p.stderr[-3000:])
  raise RuntimeError('tool failure: '+p.stderr[-3000:])
 return p.stdout

def validate_flags(instructions,entry):
 mask=0x8d5;by={i['address']:i for i in instructions};pred={p:[] for p in by};roots={entry}
 for pc,i in by.items():
  if i['kind']==2:succ=[]
  elif i['kind']==1:
   if i.get('iat_slot_rva'):succ=[i['next_pc']]
   else:succ=[i['next_pc'],i['target_pc']];roots.add(i['target_pc'])
  elif i['iclass']=='JMP':succ=[i['target_pc']]
  elif i['iclass'].startswith('J'):succ=[i['target_pc'],i['next_pc']]
  else:succ=[i['next_pc']]
  for target in succ:
   if target not in by:raise Reject('CFG target outside approved instructions')
   pred[target].append(pc)
 valid={p:mask for p in by}
 while True:
  changed=False
  for pc,i in by.items():
   incoming=0 if pc in roots else mask
   for parent in pred[pc]:
    prev=by[parent]
    after=0 if prev['kind']==1 else ((valid[parent]|prev['flags_written'])&~prev['flags_undefined'])&mask
    incoming&=after
   if incoming!=valid[pc]:valid[pc]=incoming;changed=True
  if not changed:break
 for pc,i in by.items():
  if i['flags_read']&mask&~valid[pc]:raise Reject('undefined flags read at RVA %#x'%i['rva'])

def validate_helper_effects(ir):
 # The import helper can synchronously call a guest callback using the exact
 # same live State/Context. Only a conservatively opaque memory contract is
 # valid; scoped memory or nocallback attributes could miscompile reentrancy.
 attrs={int(n):a for n,a in re.findall(r'^attributes #(\d+) = \{(.*)\}',ir,re.M)}
 for line in ir.splitlines():
  if not (line.startswith('declare ') or 'call ' in line):continue
  if not any(symbol in line for symbol in ('@aot_','@__remill_read_memory_','@__remill_write_memory_',
       '@__remill_function_call','@__remill_function_return')):continue
  groups=' '.join(attrs.get(int(n),'') for n in re.findall(r'#(\d+)',line))
  contract=line+' '+groups
  if '@__remill_function_call' in line:
   if re.search(r'\b(nocallback|argmemonly|inaccessiblememonly|inaccessiblemem_or_argmemonly|readnone|readonly|writeonly|speculatable)\b',contract):
    raise Reject('false callback helper effect contract')
   if any(memory.strip()!='readwrite' for memory in re.findall(r'\bmemory\(([^)]*)\)',contract)):
    raise Reject('scoped callback helper memory contract')
  elif re.search(r'\b(readnone|readonly|speculatable)\b|memory\((none|read)\)',contract):
   raise Reject('false helper effect contract')

def layout_gate(ir,out,layout_line,triple_line):
 expected=[3504,16]+list(range(2216,2473,16))+list(range(2065,2078,2))
 checks={}
 for target in ['x86_64-none-elf','aarch64-none-elf','x86_64-pc-windows-msvc','arm64-apple-macos11']:
  p=out/('layout-'+target+'.ll')
  run([LLVM/'clang++','-target',target,'-std=c++17','-nostdinc++','-ffreestanding',
       '-isystem',SRC/'include/remill/Arch/Runtime/sysroot','-I',SRC/'include',
       '-DADDRESS_SIZE_BITS=64','-DHAS_FEATURE_AVX=0','-DHAS_FEATURE_AVX512=0',
       '-S','-emit-llvm',REPO/'integration_stage3/lifter_layout.cpp','-o',p],out)
  line=next(x for x in p.read_text().splitlines() if '@offsets' in x)
  values=[int(v) for v in re.findall(r'i64 (\d+)',line)]
  if values!=expected:raise Reject('State source layout mismatch '+target)
  checks[target]=values
 # Also inspect the *actual retargeted LLVM State types*, not just independent C++ layouts.
 types='\n'.join(l for l in ir.splitlines() if re.match(r'^%.* = type ',l))
 exprs=['getelementptr (%struct.State, ptr null, i32 1)']
 exprs += [f'getelementptr (%struct.State, ptr null, i32 0, i32 0, i32 6, i32 {1+2*i}, i32 0, i32 0)' for i in range(17)]
 exprs += [f'getelementptr (%struct.State, ptr null, i32 0, i32 0, i32 2, i32 {1+2*i})' for i in range(7)]
 text=layout_line+'\n'+triple_line+'\n'+types+'\n'
 for i,expr in enumerate(exprs):text+=f'define i64 @layout_{i}() {{ ret i64 ptrtoint (ptr {expr} to i64) }}\n'
 p=out/'layout-retargeted.ll';p.write_text(text)
 harness='#include <stdio.h>\n'+''.join(f'unsigned long long layout_{i}(void);\n' for i in range(len(exprs)))
 harness+='int main(void){'+''.join(f'printf("%llu ",layout_{i}());' for i in range(len(exprs)))+'return 0;}\n'
 (out/'layout-retargeted.c').write_text(harness)
 run([LLVM/'clang','-target','arm64-apple-macos11','-O2','-c',p,'-o',out/'layout-retargeted.o'],out)
 run(['xcrun','clang','-arch','arm64',out/'layout-retargeted.c',out/'layout-retargeted.o','-o',out/'layout-retargeted'],out)
 actual=list(map(int,run([out/'layout-retargeted'],out).split()))
 if actual!=expected[:1]+expected[2:]:raise Reject('Actual LLVM State retarget layout mismatch')
 checks['actual_retargeted_llvm_size_and_offsets']=actual
 (out/'layout.json').write_text(json.dumps(checks,indent=2)+'\n')
 return checks

def _lift_image(pe_path,out_dir,image,entry_symbol,original_entry_rva):
 pe_path=pathlib.Path(pe_path);out=pathlib.Path(out_dir);out.mkdir(parents=True,exist_ok=True)
 (out/'manifest.json').write_text(json.dumps({'status':'RUNNING'})+'\n');(out/'commands.log').write_text('')
 dependencies=[pe_path,LIFTER,BUILD/'lib/Arch/X86/Runtime/amd64.bc',TOOL_OUT/'build-manifest.json']
 dependencies += [REPO/p for p in SOURCE_PATHS+EXTERNAL_SOURCE_PATHS]
 before={str(p.resolve()):digest(p) for p in dependencies}
 if image.source_sha256!=digest(pe_path):raise Reject('PE source changed after loading')
 build=json.loads((TOOL_OUT/'build-manifest.json').read_text())
 if build['status']!='PASS' or build['lifter_sha256']!=digest(LIFTER):raise RuntimeError('Lifter build evidence stale')
 if build['semantics_sha256']!=digest(BUILD/'lib/Arch/X86/Runtime/amd64.bc'):raise RuntimeError('Semantics build evidence stale')
 if build['patch_sha256']!={p:digest(REPO/p) for p in PATCHES}:raise RuntimeError('Lifter patch evidence stale')
 imports={item['iat_rva']:item for item in getattr(image,'imports',[])}
 executable=[s for s in image.sections if s['permissions']&EXEC]
 if len(executable)!=1:raise Reject('requires exactly one known executable text range')
 section=executable[0];start=section['rva'];length=min(section['virtual_size'],section['raw_size'])
 if not start<=image.entry_rva<start+length:raise Reject('entry outside file-backed executable range')
 if length>32768:raise Reject('MVP executable range too large for bounded CLI')
 if any(start<=r['rva']<start+length for r in image.relocations):raise Reject('text relocations not supported')
 code=bytes(image.data[start:start+length])
 (out/'text.bin').write_bytes(code)
 args=[LIFTER,'--os=windows','--arch=amd64','--address='+str(image.base+start),
       '--entry_address='+str(image.base+image.entry_rva),'--bytes='+code.hex(),
       '--aot_manifest='+str(out/'instructions-raw.json')]
 if imports:args.append('--aot_iat_slots='+','.join(str(image.base+slot) for slot in sorted(imports)))
 run(args+['--aot_decode_only'],out)
 instructions=json.loads((out/'instructions-raw.json').read_text())
 for i in instructions:
  i['rva']=i['address']-image.base
  i['bytes']=code[i['rva']-start:i['rva']-start+i['length']].hex()
  i['target_rva']=i['target_pc']-image.base if i['target_pc'] else 0
  i['iat_slot_rva']=i.get('iat_slot_pc',0)-image.base if i.get('iat_slot_pc') else 0
  if i['iat_slot_rva']:
   if i['iat_slot_rva'] not in imports or i['kind']!=1:raise Reject('decoded IAT call is not an authorized import')
   binding=imports[i['iat_slot_rva']]
   i['target_rva']=binding['target_rva'];i['signature']=binding['signature']
   i['import']={'dll':binding['dll'],'name':binding['name']}
  if i['immediate_width']==64 and image.base<=i['immediate']<image.base+len(image.data):
   raise Reject('absolute image-address immediate requires a supported code relocation')
 validate_flags(instructions,image.base+image.entry_rva)
 raw=out/'lifted.ll'
 run(args+['--ir_out='+str(raw),'--ir_pre_out='+str(out/'pre-optimization.ll')],out)
 ir=raw.read_text();entry='sub_%x'%(image.base+image.entry_rva)
 if 'x86_fp80' in ir or 'llvm.x86.' in ir:raise Reject('unsupported target-specific IR')
 if re.search(r'\binttoptr\b',ir):raise Reject('guest integer-to-host-pointer cast in lifted IR')
 if re.search(r'\b(?:fastcc|coldcc|cc \d+)\b',ir):raise Reject('unsupported calling convention')
 allowed={'aot_begin','aot_commit','aot_should_exit','__remill_function_return','__remill_function_call',
          '__remill_undefined_8','__remill_undefined_16','__remill_undefined_32','__remill_undefined_64'}
 allowed|={'__remill_read_memory_'+str(n) for n in (8,16,32,64)}
 allowed|={'__remill_write_memory_'+str(n) for n in (8,16,32,64)}
 allowed|={'__remill_flag_computation_'+n for n in ['zero','sign','carry','overflow']}
 allowed|={'__remill_compare_'+n for n in ['sle','slt','sge','sgt','ule','ult','uge','ugt','eq','neq']}
 for line in ir.splitlines():
  if line.startswith('declare '):
   symbol=re.search(r'@([^(]+)\(',line).group(1)
   if symbol not in allowed and not symbol.startswith(('llvm.ctpop.','llvm.fshl.','llvm.fshr.')):raise Reject('unknown helper '+symbol)
 if 'store ptr undef' in ir or re.search(r'noundef[^,()]*\bundef\b',ir):raise Reject('undefined Memory token')
 validate_helper_effects(ir)
 # Every root is compiled independently. Shared direct-call traces are private
 # to their root module; raw guest PCs and instruction metadata stay unchanged.
 sub_symbols=set(re.findall(r'^define\b[^\n]*@((?:sub_)[0-9a-f]+)\(',ir,re.M))
 if entry not in sub_symbols:raise Reject('selected root definition missing')
 rename={name:(entry_symbol if name==entry else f'cb_{image.entry_rva:x}_{name}') for name in sub_symbols}
 for old,new in rename.items():ir=re.sub('@'+re.escape(old)+r'\b','@'+new,ir)
 for private in set(rename.values())-{entry_symbol}:
  ir,count=re.subn(r'^(define )(?!internal )([^\n]*@'+re.escape(private)+r'\()',r'\1internal \2',ir,flags=re.M)
  if count!=1:raise Reject('cannot internalize private trace '+private)
 empty=out/'empty.c';empty.write_text('int empty;\n')
 run([LLVM/'clang','-target','arm64-apple-macos11','-S','-emit-llvm',empty,'-o',out/'empty.ll'],out)
 generated=(out/'empty.ll').read_text().splitlines()
 layout_line=next(l for l in generated if l.startswith('target datalayout'))
 triple_line=next(l for l in generated if l.startswith('target triple'))
 layouts=layout_gate(ir,out,layout_line,triple_line)
 arm=re.sub(r'^target datalayout.*$',layout_line,ir,flags=re.M)
 arm=re.sub(r'^target triple.*$',triple_line,arm,flags=re.M)
 arm=re.sub(r' "(?:target-cpu|target-features|tune-cpu)"="[^"]*"','',arm)
 (out/'arm64.ll').write_text(arm)
 run([LLVM/'opt','-passes=verify','-disable-output',out/'arm64.ll'],out)
 run([LLVM/'clang','-target','arm64-apple-macos11','-O3','-c',out/'arm64.ll','-o',out/'arm64.o'],out)
 run([LLVM/'clang','-target','arm64-apple-macos11','-O0','-c',out/'arm64.ll','-o',out/'arm64-o0.o'],out)
 exports={}
 for object_name in ('arm64.o','arm64-o0.o'):
  exported=run(['nm','-gU',out/object_name],out)
  names=[line.split()[-1] for line in exported.splitlines() if line.split()]
  if names!=['_'+entry_symbol]:raise Reject('unexpected externally defined object symbols: '+repr(names))
  exports[object_name]=names
 after={str(p.resolve()):digest(p) for p in dependencies}
 if before!=after:raise Reject('producer inputs changed during lifting')
 manifest={'status':'PASS','symbol':entry_symbol,'function_symbol':entry_symbol,'object':str((out/'arm64.o').resolve()),
           'scope':'selected root in original PE; no PE header rewrite' if imports else 'synthetic compatibility C3 RET shim, not Windows DLL code',
           'imports':list(imports.values()),'lifter_build_manifest_sha256':digest(TOOL_OUT/'build-manifest.json'),
           'entry_rva':image.entry_rva,'original_entry_rva':original_entry_rva,'root_rva':image.entry_rva,
           'private_trace_symbols':sorted(set(rename.values())-{entry_symbol}),'exports':exports,
           'preferred_base':image.base,'instructions':instructions,
           'inputs_before':before,'inputs_after':after,
           'input_sha256':digest(pe_path),'lifter_sha256':digest(LIFTER),'semantics_sha256':build['semantics_sha256'],'state_layout':layouts,
           'external_source_sha256':{p:digest(REPO/p) for p in EXTERNAL_SOURCE_PATHS},
           'source_sha256':{p:digest(REPO/p) for p in SOURCE_PATHS},
           'artifact_sha256':{p:digest(out/p) for p in ['text.bin','instructions-raw.json','lifted.ll','arm64.ll','arm64.o','arm64-o0.o']}}
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 return manifest
def lift_pe(pe_path,out_dir,entry_rva=None,entry_symbol='aot_entry'):
 try:image=load_image(pathlib.Path(pe_path))
 except ImageError as error:raise TranslationError(str(error)) from error
 original_entry=image.entry_rva
 if entry_rva is not None:
  if type(entry_rva) is not int or not 0<=entry_rva<len(image.data):raise Reject('invalid root RVA')
  image=dataclasses.replace(image,entry_rva=entry_rva)
 if entry_symbol not in ('aot_entry',f'aot_callback_{image.entry_rva:x}'):raise Reject('invalid root symbol')
 return _lift_image(pe_path,out_dir,image,entry_symbol,original_entry)

def lift_roots(pe_path,out_dir,callback_rvas):
 out=pathlib.Path(out_dir);out.mkdir(parents=True,exist_ok=True)
 roots=list(callback_rvas)
 if not roots or len(roots)>16 or any(type(r) is not int for r in roots) or len(set(roots))!=len(roots):
  raise Reject('requires one to sixteen distinct explicit callback root RVAs')
 image=load_image(pathlib.Path(pe_path))
 source_sha=digest(pe_path)
 if image.source_sha256!=source_sha:raise Reject('PE source changed before root lifting')
 if image.entry_rva in roots:raise Reject('main entry cannot also be callback root')
 main=lift_pe(pe_path,out/'main')
 records=[]
 for rva in roots:
  symbol=f'aot_callback_{rva:x}';directory=out/f'callback-{rva:x}'
  manifest=lift_pe(pe_path,directory,entry_rva=rva,entry_symbol=symbol)
  records.append({'rva':rva,'symbol':symbol,'signature':1,'directory':str(directory.resolve()),'manifest':manifest})
 if digest(pe_path)!=source_sha or any(m['input_sha256']!=source_sha for m in [main,*[r['manifest'] for r in records]]):
  raise Reject('PE identity differs between roots')
 result={'status':'PASS','input_sha256':source_sha,
         'main':{'rva':image.entry_rva,'symbol':'aot_entry','directory':str((out/'main').resolve()),'manifest':main},
         'roots':records,'scope':'independent selected roots; registration is explicit, no pointer discovery'}
 (out/'roots.json').write_text(json.dumps(result,indent=2)+'\n');return result

def build_ret_shim(out_dir):
 out=pathlib.Path(out_dir);out.mkdir(parents=True,exist_ok=True)
 pe=out/'synthetic-ret.exe';pe.write_bytes(plain_pe_image(b'\xc3'))
 image=load_plain(pe)
 result=_lift_image(pe,out,image,'aot_import_ret',image.entry_rva)
 if len(result['instructions'])!=1 or result['instructions'][0]['bytes']!='c3':raise Reject('RET shim is not exactly C3')
 return result

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('pe');parser.add_argument('out');args=parser.parse_args()
 print(json.dumps(lift_pe(args.pe,args.out),indent=2))
