#!/usr/bin/env python3
"""Restricted PE -> real instrumented Remill -> raw-State ARM64 object.
No identity host pointers or signature wrapper; guest runtime is linked separately.
"""
import argparse,json,pathlib,re,subprocess,sys
try:
 from .build_lifter import HERE,REPO,SRC,BUILD,OUT as TOOL_OUT,LLVM,LIFTER,PATCHES,digest
except ImportError:
 from build_lifter import HERE,REPO,SRC,BUILD,OUT as TOOL_OUT,LLVM,LIFTER,PATCHES,digest
sys.path.insert(0,str(REPO))
from memory_stage2.image_loader import load_image,EXEC,ImageError
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
  elif i['kind']==1:succ=[i['next_pc'],i['target_pc']];roots.add(i['target_pc'])
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

def layout_gate(ir,out,layout_line,triple_line):
 expected=[3504,16]+list(range(2216,2473,16))+list(range(2065,2078,2))
 checks={}
 for target in ['x86_64-none-elf','aarch64-none-elf','x86_64-pc-windows-msvc','arm64-apple-macos11']:
  p=out/('layout-'+target+'.ll')
  run([LLVM/'clang++','-target',target,'-std=c++17','-nostdinc++','-ffreestanding',
       '-isystem',SRC/'include/remill/Arch/Runtime/sysroot','-I',SRC/'include',
       '-DADDRESS_SIZE_BITS=64','-DHAS_FEATURE_AVX=0','-DHAS_FEATURE_AVX512=0',
       '-S','-emit-llvm',HERE/'lifter_layout.cpp','-o',p],out)
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

def lift_pe(pe_path,out_dir):
 pe_path=pathlib.Path(pe_path);out=pathlib.Path(out_dir);out.mkdir(parents=True,exist_ok=True)
 (out/'manifest.json').write_text(json.dumps({'status':'RUNNING'})+'\n');(out/'commands.log').write_text('')
 build=json.loads((TOOL_OUT/'build-manifest.json').read_text())
 if build['status']!='PASS' or build['lifter_sha256']!=digest(LIFTER):raise RuntimeError('Lifter build evidence stale')
 if build['semantics_sha256']!=digest(BUILD/'lib/Arch/X86/Runtime/amd64.bc'):raise RuntimeError('Semantics build evidence stale')
 if build['patch_sha256']!={p:digest(HERE/p) for p in PATCHES}:raise RuntimeError('Lifter patch evidence stale')
 try:image=load_image(pe_path)
 except ImageError as e:raise TranslationError(str(e)) from e
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
 run(args+['--aot_decode_only'],out)
 instructions=json.loads((out/'instructions-raw.json').read_text())
 for i in instructions:
  i['rva']=i['address']-image.base
  i['bytes']=code[i['rva']-start:i['rva']-start+i['length']].hex()
  i['target_rva']=i['target_pc']-image.base if i['target_pc'] else 0
  if i['immediate_width']==64 and image.base<=i['immediate']<image.base+len(image.data):
   raise Reject('absolute image-address immediate requires a supported code relocation')
 validate_flags(instructions,image.base+image.entry_rva)
 raw=out/'lifted.ll'
 run(args+['--ir_out='+str(raw),'--ir_pre_out='+str(out/'pre-optimization.ll')],out)
 ir=raw.read_text();entry='sub_%x'%(image.base+image.entry_rva)
 if 'x86_fp80' in ir or 'llvm.x86.' in ir:raise Reject('unsupported target-specific IR')
 if re.search(r'\binttoptr\b',ir):raise Reject('guest integer-to-host-pointer cast in lifted IR')
 if re.search(r'\b(?:fastcc|coldcc|cc \d+)\b',ir):raise Reject('unsupported calling convention')
 allowed={'aot_begin','aot_commit','aot_should_exit','__remill_function_return',
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
 # Memory helpers and transaction hooks must remain externally opaque with writes.
 attrs={int(n):a for n,a in re.findall(r'^attributes #(\d+) = \{(.*)\}',ir,re.M)}
 for line in ir.splitlines():
  if (line.startswith('declare ') or 'call ' in line) and ('@aot_' in line or '@__remill_read_memory_' in line or '@__remill_write_memory_' in line):
   m=re.search(r'#(\d+)',line);attr=attrs.get(int(m.group(1)),'') if m else ''
   if re.search(r'\b(readnone|readonly|speculatable)\b|memory\((none|read)\)',line+' '+attr):raise Reject('false helper effect contract')
 ir=re.sub('@'+re.escape(entry)+r'\b','@aot_entry',ir)
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
 manifest={'status':'PASS','symbol':'aot_entry','function_symbol':'aot_entry','object':str((out/'arm64.o').resolve()),
           'entry_rva':image.entry_rva,'preferred_base':image.base,'instructions':instructions,
           'input_sha256':digest(pe_path),'lifter_sha256':digest(LIFTER),'semantics_sha256':build['semantics_sha256'],'state_layout':layouts,
           'external_source_sha256':{'memory_stage2/image_loader.py':digest(REPO/'memory_stage2/image_loader.py')},
           'source_sha256':{p:digest(HERE/p) for p in ['lift.py','build_lifter.py','lifter_layout.cpp',*PATCHES]},
           'artifact_sha256':{p:digest(out/p) for p in ['text.bin','instructions-raw.json','lifted.ll','arm64.ll','arm64.o','arm64-o0.o']}}
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 return manifest
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('pe');parser.add_argument('out');args=parser.parse_args()
 print(json.dumps(lift_pe(args.pe,args.out),indent=2))
