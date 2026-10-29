#!/usr/bin/env python3
"""Actual PE main/registered root/RET tests, isolated synchronous callback component.

This is not User32, a window, or a graphics test. The C dispatcher is explicitly
test-owned; the translated guest instructions and shared transaction/callback
implementation are real. All modes preserve independent build/run identities.
"""
import argparse,json,re,shlex,shutil,subprocess,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from window_bridge import lift
from window_bridge.register_fixtures import LLVM,LINK,sha,command
from native_bridge.test_sanitizers import instrument,local_python_closure
OUT=ROOT/'build/window-bridge/callback-tests'
NAMES=('leaf','import','nested','exit','bad_nonvolatile','bad_return','read_fault','write_fault','register')
EXPECTED_BUDGETS=(17,13,35,5,0,0,0,0,20)
EXPECTED_HOOKS=(11,0,1,0,0,0,0,0,12)
def require(ok,message):
 if not ok:raise RuntimeError(message)
def snapshot(paths):return {str(Path(p).resolve()):sha(p) for p in sorted(set(map(Path,paths)))}
def verify_module(directory,manifest):
 directory=Path(directory)
 require(json.loads((directory/'manifest.json').read_text())==manifest,'module manifest replaced')
 require(manifest['status']=='PASS' and manifest['validation_level']=='BUILD_STATIC_NOT_EXECUTED','module build status')
 require(set(manifest['source_sha256'])==set(lift.SOURCE_PATHS) and set(manifest['external_source_sha256'])==set(lift.EXTERNAL_SOURCE_PATHS),'module source closure differs')
 for group in ('source_sha256','external_source_sha256'):
  require({p:sha(ROOT/p) for p in manifest[group]}==manifest[group],'module source identity changed')
 require(manifest['inputs_before']==manifest['inputs_after'] and snapshot(manifest['inputs_before'])==manifest['inputs_before'],'module input identity changed')
 require(set(manifest['artifact_sha256'])=={'text.bin','instructions-raw.json','lifted.ll','arm64.ll','arm64.o','arm64-o0.o'},'module artifacts incomplete')
 require({p:sha(directory/p) for p in manifest['artifact_sha256']}==manifest['artifact_sha256'],'module artifact identity changed')
 require(manifest['lifter_sha256']==sha(lift.LIFTER) and manifest['lifter_build_manifest_sha256']==sha(lift.TOOL_OUT/'build-manifest.json') and manifest['semantics_sha256']==sha(lift.BUILD/'lib/Arch/X86/Runtime/amd64.bc'),'module tool identity changed')
 return {Path(p) for p in manifest['inputs_before']}|{directory/'manifest.json',*[directory/p for p in manifest['artifact_sha256']]}
def run(args,path,**kwargs):
 args=list(map(str,args));p=subprocess.run(args,capture_output=True,text=True,**kwargs)
 path.write_text(json.dumps({'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr},indent=2)+'\n')
 require(not p.returncode,'command failed: '+str(path)+' '+p.stderr[-1500:]);return p.stdout
def fixtures(out):
 out.mkdir(parents=True,exist_ok=True);definition=out/'kernel32.def';definition.write_text('LIBRARY kernel32.dll\nEXPORTS\n GetLastError\n ExitProcess\n')
 run([LLVM/'llvm-dlltool','-m','i386:x86-64','-d',definition,'-l',out/'kernel32.lib'],out/'dlltool.json');rows={}
 weighted='movq %rcx,%rax\nleaq (%rdx,%rdx,2),%r10\naddq %r10,%rax\nleaq (%r8,%r8,4),%r10\naddq %r10,%rax\nleaq (%r9,%r9,2),%r10\nleaq (%r9,%r10,2),%r10\naddq %r10,%rax\naddq $17,%rax\nretq\n'
 for index,name in enumerate(NAMES):
  area=out/name;area.mkdir(exist_ok=True)
  if name=='register':prefix='pushq %r14\nsubq $32,%rsp\nmovq __imp_GetLastError(%rip),%r14\ncallq *%r14\n';suffix='addq $32,%rsp\npopq %r14\n'
  else:prefix='subq $40,%rsp\ncallq *__imp_GetLastError(%rip)\n';suffix='addq $40,%rsp\n'
  cb=weighted
  if name=='import':cb='subq $40,%rsp\ncallq *__imp_GetLastError(%rip)\naddq $17,%rax\naddq $40,%rsp\nretq\n'
  if name=='nested':cb='testl %edx,%edx\njz callback_base\nsubq $40,%rsp\ncallq *__imp_GetLastError(%rip)\naddq $17,%rax\naddq $40,%rsp\nretq\ncallback_base:\n'+weighted
  if name=='exit':cb='subq $40,%rsp\nmovl $0x87654321,%ecx\ncallq *__imp_ExitProcess(%rip)\nmovq $0x4321,after_exit(%rip)\naddq $40,%rsp\nretq\n'
  if name=='bad_nonvolatile':cb='movq %rcx,%rbx\nmovq %rcx,%rax\nretq\n'
  if name=='bad_return':cb='pushq %rcx\nretq\n'
  if name in ('read_fault','write_fault'):cb=('movq $0x1234,write_marker(%rip)\n' if name=='write_fault' else '')+'movq (%rcx),%rax\nretq\n'
  source=area/'input.s';source.write_text('.text\n.globl guest_entry\nguest_entry:\n'+prefix+'addq $7,%rax\nmovq %rax,after_main(%rip)\n'+suffix+'retq\n.p2align 4\n.globl guest_callback\nguest_callback:\n'+cb+'.data\n.globl after_main\nafter_main:.quad 0\n.globl after_exit\nafter_exit:.quad 0\n.globl write_marker\nwrite_marker:.quad 0\n.quad 0\n')
  obj=area/'input.obj';pe=area/'input.exe';mp=area/'input.map'
  run([LLVM/'clang','-target','x86_64-pc-windows-msvc','-c',source,'-o',obj],area/'compile.json')
  run([LINK,'/entry:guest_entry','/subsystem:console','/nodefaultlib','/machine:x64','/base:0x140000000','/dynamicbase','/nxcompat','/timestamp:0','/fixed:no','/out:'+str(pe),'/map:'+str(mp),obj,out/'kernel32.lib'],area/'link.json')
  symbols={m[1]:int(m[2],16)-0x140000000 for line in mp.read_text().splitlines() if (m:=re.match(r'^\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{16})\b',line))}
  run([LLVM/'llvm-objdump','--disassemble',pe],area/'disassembly.json')
  rows[name]={'variant':index,'pe':pe,'symbols':symbols,'module':area/'modules'}
 return rows
def header(row,path):
 from window_bridge.loader import load_image
 image=load_image(row['pe'].read_bytes());symbols=row['symbols'];modules=lift.lift_roots(row['pe'],row['module'],[symbols['guest_callback']])
 ins={i['rva']:i for i in modules['instructions']};imports=image.imports
 for i in imports:ins[i['target_rva']]={'rva':i['target_rva'],'length':1,'kind':2,'target_rva':0}
 regs=[r for root in [modules['main'],*modules['roots']] for r in root['manifest']['register_calls']]
 text='#define CALLBACK_SYMBOL aot_window_proc_%x\n'%symbols['guest_callback']
 values={'Base':image.preferred_base,'EntryRva':image.entry_rva,'CallbackRva':symbols['guest_callback'],
  'MarkerRva':symbols['after_main'],'AfterExitRva':symbols['after_exit'],'WriteMarkerRva':symbols['write_marker'],
  'FirstThunk':min(i['target_rva'] for i in imports),'LastThunk':max(i['target_rva'] for i in imports),
  'GetErrorThunk':next(i['target_rva'] for i in imports if i['signature']==8)}
 text+='enum {kVariant=%d};\n'%row['variant']
 for key,value in values.items():text+='static const uint64_t k%s=UINT64_C(%d);\n'%(key,value)
 text+='static const uint8_t kImage[]={'+','.join(map(str,image.data))+'};\n'
 text+='static const uint8_t kPermissions[]={'+','.join(map(str,image.permissions))+'};\n'
 text+='static const AotInstruction kInstructions[]={'+','.join('{%d,%d,%d,0,UINT64_C(%d)}'%(i['rva'],i['length'],i['kind'],i.get('target_rva',0)) for _,i in sorted(ins.items()))+'};\n'
 text+='typedef struct {uint32_t iat_rva,target_rva,signature;} TestImport;\nstatic const TestImport kImports[]={'+','.join('{%d,%d,%d}'%(i['iat_rva'],i['target_rva'],i['signature']) for i in imports)+'};\n'
 text+='static const size_t kImportCount=%d,kRegisterCount=%d;\n'%(len(imports),len(regs))
 text+='static const AotRegisterCall kRegisterCalls[]={'+(','.join('{%d,%d}'%(r['call_rva'],r['operand_register']) for r in regs) or '{0,0}')+'};\n'
 path.write_text(text);return modules
def required_sources():
 paths={Path(__file__),ROOT/'window_bridge/callback_test.c',ROOT/'window_bridge/callback_v1.inc',ROOT/'window_bridge/callback_v1.h',ROOT/'window_bridge/transaction_v1.c',ROOT/'window_bridge/runtime.h',ROOT/'memory_stage2/guest_memory.h',Path(sys.executable),LLVM/'clang',LLVM/'llvm-dlltool',LLVM/'llvm-objdump',LINK,lift.LIFTER}
 paths|={ROOT/p for p in lift.SOURCE_PATHS+lift.EXTERNAL_SOURCE_PATHS};paths|=set(local_python_closure(paths))
 paths|={lift.TOOL_OUT/'build-manifest.json',lift.BUILD/'lib/Arch/X86/Runtime/amd64.bc'}
 return paths
def main(out=OUT):
 out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json';require(not evidence.exists(),'preserve old evidence; choose a fresh output')
 initial=snapshot(required_sources());records={}
 try:
  sdk=Path(subprocess.check_output(['/usr/bin/xcrun','--show-sdk-path'],text=True).strip());clang=Path(subprocess.check_output(['/usr/bin/xcrun','--find','clang'],text=True).strip())
  inputs=set(map(Path,initial))|{clang,Path('/usr/bin/codesign'),Path('/usr/bin/install_name_tool'),Path('/usr/bin/nm'),Path('/usr/bin/otool')}
  # Compile real pinned C++ layout assertions, not a copied diagram.
  layout=out/'callback-layout.cpp';layout.write_text('#include "remill/Arch/X86/Runtime/State.h"\nstatic_assert(sizeof(State)==3504);\nstatic_assert(__builtin_offsetof(State,vec)==16);\nstatic_assert(sizeof(VectorReg)==64);\nstatic_assert(__builtin_offsetof(VectorReg,xmm)==0);\nstatic_assert(sizeof(((VectorReg*)0)->xmm)==16);\n')
  run([LLVM/'clang++','-std=c++17','-target','arm64-apple-macos11','-isysroot',sdk,'-I',lift.SRC/'include','-fsyntax-only',layout],out/'layout.json')
  dep=run([LLVM/'clang++','-std=c++17','-target','arm64-apple-macos11','-isysroot',sdk,'-I',lift.SRC/'include','-M',layout],out/'layout-dependencies.json')
  inputs|={Path(x) for x in shlex.split(dep.replace('\\\n',' ').split(':',1)[1])}
  rows=fixtures(out/'fixtures');ret_dir=out/'ret';ret_manifest=lift.build_ret_shim(ret_dir);inputs|=verify_module(ret_dir,ret_manifest)
  runtime=LLVM.parent/'lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib'
  runtime_copy=out/runtime.name;shutil.copy2(runtime,runtime_copy)
  run(['/usr/bin/install_name_tool','-id',runtime_copy,runtime_copy],out/'asan-id.json');run(['/usr/bin/codesign','--force','--sign','-',runtime_copy],out/'asan-sign.json');inputs|={runtime,runtime_copy}
  ret_ir=out/'ret-asan.ll';ret_o=out/'ret-asan.o';ret_functions=instrument(ret_dir/'arm64.ll',ret_ir)
  run([LLVM/'clang','-target','arm64-apple-macos11','-O1','-fsanitize=address','-c',ret_ir,'-o',ret_o],out/'ret-asan-build.json')
  for name,row in rows.items():
   area=row['module'].parent;modules=header(row,area/'callback_fixture.h');roots=[modules['main'],*modules['roots']]
   for root in roots:
    require(root['manifest']['input_sha256']==sha(row['pe']),'root PE identity differs')
    inputs|=verify_module(root['directory'],root['manifest'])
   objects={m:[] for m in ('O3','O0','sanitized')};counts={'aot_import_ret':ret_functions}
   for root in roots:
    directory=Path(root['directory']);objects['O3'].append(directory/'arm64.o');objects['O0'].append(directory/'arm64-o0.o')
    ir=area/(root['symbol']+'-asan.ll');obj=area/(root['symbol']+'-asan.o');counts[root['symbol']]=instrument(directory/'arm64.ll',ir)
    run([LLVM/'clang','-target','arm64-apple-macos11','-O1','-fsanitize=address','-c',ir,'-o',obj],area/(root['symbol']+'-asan-build.json'))
    require('__asan_report_' in run(['/usr/bin/nm',obj],area/(root['symbol']+'-asan-symbols.json')),'LLVM not actually instrumented');objects['sanitized'].append(obj)
   objects['O3'].append(ret_dir/'arm64.o');objects['O0'].append(ret_dir/'arm64-o0.o');objects['sanitized'].append(ret_o)
   reports={};executed={};mode_inputs={}
   for mode,objs in objects.items():
    compiler=LLVM/'clang' if mode=='sanitized' else clang
    flags=['-target','arm64-apple-macos11','-isysroot',sdk,'-std=c11','-O1' if mode=='sanitized' else '-'+mode,'-Wall','-Wextra','-Werror','-I',ROOT/'window_bridge','-I',area]
    if mode=='sanitized':flags+=['-fsanitize=address,undefined']
    dep=run([compiler,*flags,'-M',ROOT/'window_bridge/callback_test.c'],area/(mode+'-dependencies.json'))
    dependencies={Path(x) for x in shlex.split(dep.replace('\\\n',' ').split(':',1)[1])};inputs|=dependencies
    executable=area/('callback-'+mode)
    run([compiler,*flags,'-Wl,-syslibroot,'+str(sdk),ROOT/'window_bridge/callback_test.c',*objs,'-o',executable],area/(mode+'-compile.json'))
    if mode=='sanitized':
     linked=run(['/usr/bin/otool','-L',executable],area/'san-linked.json');old=[l.strip().split(' (',1)[0] for l in linked.splitlines()[1:] if runtime.name in l];require(len(old)==1,'ASan linkage missing')
     run(['/usr/bin/install_name_tool','-change',old[0],runtime_copy,executable],area/'san-install-name.json');run(['/usr/bin/codesign','--force','--sign','-',executable],area/'san-sign.json')
    current_inputs=inputs|set(objs)|{executable,row['pe'],area/'callback_fixture.h',ret_dir/'manifest.json'}
    for root in roots:
     directory=Path(root['directory']);current_inputs|={directory/'manifest.json',*[directory/p for p in root['manifest']['artifact_sha256']]}
    before=snapshot(current_inputs);require(all(before[p]==v for p,v in initial.items()),'initial source changed before execution')
    verify_module(ret_dir,ret_manifest)
    for root in roots:verify_module(root['directory'],root['manifest'])
    raw=run([executable,area/(mode+'-state.bin')],area/(mode+'-run.json'));report=json.loads(raw)
    require(report['status']=='PASS_COMPONENT_CALLBACK' and report['variant']==row['variant'],'missing actual execution PASS')
    after=snapshot(current_inputs);require(before==after,'actual executable/input changed during execution')
    verify_module(ret_dir,ret_manifest)
    for root in roots:verify_module(root['directory'],root['manifest'])
    reports[mode]=report;mode_inputs[mode]={'before':before,'after':after};executed[mode]={'executable':str(executable),'sha256':sha(executable),'log':str(area/(mode+'-run.json')),'state':str(area/(mode+'-state.bin')),'state_sha256':sha(area/(mode+'-state.bin'))}
   require(reports['O3']==reports['O0']==reports['sanitized'],'mode reports differ')
   # Context AccessPlan host addresses are intentionally absent from records.
   require(len({e['state_sha256'] for e in executed.values()})==1,'full State/frame/stack/image records differ between modes')
   records[name]={'reports':reports,'executions':executed,'execution_inputs':mode_inputs,'instrumented_functions':counts,'pe_sha256':sha(row['pe'])}
  inputs|={p for p in out.rglob('*') if p.is_file() and p!=evidence};final=snapshot(inputs)
  require(all(final[k]==v for k,v in initial.items()),'source changed before evidence')
  record={'schema':1,'status':'PASS_ACTUAL_CALLBACK_COMPONENT','initial_inputs':initial,'inputs_before':final,'inputs_after':snapshot(inputs),'fixtures':records,
   'modes':['O3','O0','sanitized'],'actual_executions':sum(r['reports']['O3']['actual_executions'] for r in records.values())*3,
   'case_executions_per_mode':sum(r['reports']['O3']['actual_executions'] for r in records.values()),'ordinary_vectors_per_mode':120,'budget_executions_per_mode':90,'host_injection_executions_per_mode':24,'baseline_measurements_per_mode':5,'registry_rejection_shapes':9,'registry_rejections_per_mode':81,'gpu_executions':0,'windows_executions':0,
   'scope':'real self-authored PE main, AOT callback and RET, exact window transaction/callback component, isolated test owner and IAT dispatcher; not User32, GUI, Windows, or full root runtime integration',
   'artifacts':snapshot(p for p in out.rglob('*') if p.is_file() and p!=evidence)}
  require(record['inputs_before']==record['inputs_after'],'final inputs changed');evidence.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(verify_evidence(out)))
 except Exception as error:
  failure={'status':'FAIL','error':str(error),'traceback':traceback.format_exc(),'initial_inputs':initial,'completed_fixtures':records}
  (out/'first-failure.json').write_text(json.dumps(failure,indent=2)+'\n');evidence.write_text(json.dumps(failure,indent=2)+'\n');raise
def verify_evidence(out=OUT):
 out=Path(out).resolve();e=json.loads((out/'evidence.json').read_text());require(e['schema']==1 and e['status']=='PASS_ACTUAL_CALLBACK_COMPONENT','not component PASS')
 require(e['inputs_before']==e['inputs_after'] and snapshot(e['inputs_before'])==e['inputs_before'],'input identity changed')
 require(set(map(str,map(Path.resolve,required_sources())))<=set(e['inputs_before']),'required source closure missing')
 require(snapshot(p for p in out.rglob('*') if p.is_file() and p!=out/'evidence.json')==e['artifacts'],'artifact closure changed')
 require(set(e['fixtures'])==set(NAMES) and e['modes']==['O3','O0','sanitized'],'fixture/mode set differs')
 total=0
 for name,r in e['fixtures'].items():
  require(r['reports']['O3']==r['reports']['O0']==r['reports']['sanitized'],'mode reports differ')
  n=NAMES.index(name);report=r['reports']['O3'];require(report['variant']==n and report['ordinary_cases']==(32 if n in (0,8) else 8) and report['budget_cases']==EXPECTED_BUDGETS[n] and report['host_injection_cases']==EXPECTED_HOOKS[n] and report['registry_rejections']==9,'case coverage differs')
  require(report['actual_executions']==report['ordinary_cases']+report['budget_cases']+report['host_injection_cases']+int(n<=3 or n==8),'case category sum differs')
  require(all(n>0 for n in r['instrumented_functions'].values()) and len(r['instrumented_functions'])==3,'actual root instrumentation missing')
  for mode,execution in r['executions'].items():
   x=r['execution_inputs'][mode];require(x['before']==x['after'] and snapshot(x['before'])==x['before'],'execution identity changed')
   log=json.loads(Path(execution['log']).read_text());require(log['returncode']==0 and not log['stderr'] and json.loads(log['stdout'])==r['reports'][mode],'actual stdout/sanitizer failure')
   require(sha(execution['executable'])==execution['sha256'] and sha(execution['state'])==execution['state_sha256'],'executed artifact changed')
  require(len({x['state_sha256'] for x in r['executions'].values()})==1,'full State records diverge');total+=r['reports']['O3']['actual_executions']
 require(e['actual_executions']==3*total and e['case_executions_per_mode']==total==239,'actual counts differ')
 require(e['ordinary_vectors_per_mode']==120 and e['budget_executions_per_mode']==90 and e['host_injection_executions_per_mode']==24 and e['baseline_measurements_per_mode']==5 and e['registry_rejection_shapes']==9 and e['registry_rejections_per_mode']==81,'coverage sum differs')
 for directory in [out/'ret',*[p.parent for p in (out/'fixtures').glob('*/modules/*/manifest.json')]]:
  verify_module(directory,json.loads((directory/'manifest.json').read_text()))
 require(e['gpu_executions']==e['windows_executions']==0,'scope differs')
 return {'status':e['status'],'fixtures':len(NAMES),'actual_executions':e['actual_executions'],'case_executions_per_mode':total,'gpu_executions':0,'windows_executions':0,'evidence_sha256':sha(out/'evidence.json')}
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
 if args.verify:print(json.dumps(verify_evidence(args.out)))
 else:main(args.out)
