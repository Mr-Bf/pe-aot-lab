#!/usr/bin/env python3
"""Self-authored real COFF/PE register-CALL probes; compilation only."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];WORK=ROOT.parents[1]/'work'
LLVM=WORK/'remill-stage2/llvm@17/17.0.6/bin';LINK=WORK/'file-bridge/tools/lld-link'
OUT=ROOT/'build/window-bridge/register-fixtures'
VARIANTS={'good':'','bad-offset':'addq $1,%r14\n','bad-guest':'leaq guest_entry(%rip),%r14\n',
          'bad-method':'movabsq $0xf0096000,%r14\n'} # reserved Present signature150; not an import

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def command(args,path):
 args=list(map(str,args));p=subprocess.run(args,capture_output=True,text=True)
 path.write_text(json.dumps({'command':args,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr},indent=2)+'\n')
 if p.returncode:raise RuntimeError('build failed: '+str(path))
 return p.stdout

def build(out=OUT):
 out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
 if (out/'manifest.json').exists():raise RuntimeError('preserve previous preparation')
 source_sha=sha(__file__);definitions=out/'kernel32.def';definitions.write_text('LIBRARY kernel32.dll\nEXPORTS\n GetLastError\n ExitProcess\n')
 command([LLVM/'llvm-dlltool','-m','i386:x86-64','-d',definitions,'-l',out/'kernel32.lib'],out/'imports.json')
 rows={}
 for name,change in VARIANTS.items():
  source=out/(name+'.s');source.write_text('''.text
.globl guest_entry
guest_entry:
 pushq %r14
 subq $32,%rsp
 movq __imp_GetLastError(%rip),%r14
'''+change+''' .globl register_call
register_call:
 callq *%r14
 .globl after_register_call
after_register_call:
 movl %eax,%ecx
 callq *__imp_ExitProcess(%rip)
 movl $0xdeadbeef,after_exit(%rip)
 addq $32,%rsp
 popq %r14
 retq
.data
.globl after_exit
after_exit: .long 0
''')
  obj=out/(name+'.obj');pe=out/(name+'.exe');mapping=out/(name+'.map')
  command([LLVM/'clang','-target','x86_64-pc-windows-msvc','-c',source,'-o',obj],out/(name+'-compile.json'))
  command([LINK,'/entry:guest_entry','/subsystem:console','/nodefaultlib','/machine:x64','/base:0x140000000','/dynamicbase','/nxcompat','/timestamp:0','/fixed:no','/out:'+str(pe),'/map:'+str(mapping),obj,out/'kernel32.lib'],out/(name+'-link.json'))
  text=command([LLVM/'llvm-objdump','--disassemble',pe],out/(name+'-disassembly.json'))
  symbols={}
  import re
  for line in mapping.read_text().splitlines():
   m=re.match(r'^\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{16})\b',line)
   if m:symbols[m[1]]=int(m[2],16)-0x140000000
  rows[name]={'pe':str(pe),'sha256':sha(pe),'symbols':symbols,'expected':('ExitProcess(0), after_exit stays zero' if name=='good' else 'reject register target before CALL commit; no GetLastError/ExitProcess side effect'),
     'last_error_contract':'test session initializes LastError=0; this is expected contract, not Windows execution/oracle evidence'}
 if sha(__file__)!=source_sha:raise RuntimeError('fixture source changed')
 record={'status':'REGISTER_CALL_PE_PREPARED_NOT_EXECUTED','source_sha256':source_sha,'fixtures':rows,
   'tools':{str(p):sha(p) for p in [LLVM/'clang',LLVM/'llvm-dlltool',LLVM/'llvm-objdump',LINK]},
   'artifacts':{p.name:sha(p) for p in out.iterdir() if p.is_file()},'guest_executions':0,'gpu_executions':0}
 (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n');return record

if __name__=='__main__':print(json.dumps(build(),indent=2))
