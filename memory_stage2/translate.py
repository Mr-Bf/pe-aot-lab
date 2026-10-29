#!/usr/bin/env python3
"""PE byte-driven memory-loop AOT experiment with checked and verified-span modes.
The profile verifier is intentionally restrictive. Not a general x86 lifter.
"""
import sys,pathlib,struct,json,hashlib,argparse
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pe_aot import PE,Unsupported,unpack

def decode(pe,pc):
 def b(n):return pe.read(pc,n,execute=True)
 op=b(1)[0]
 if op==0xc3:return (1,'ret',())
 if op in (0x74,0x75):return (2,'jz' if op==0x74 else 'jnz',(pc+2+unpack('<b',b(2),1)[0],))
 t=b(2)
 if t==b'\x31\xc0':return (2,'zero',())
 if t==b'\x85\xd2':return (2,'test_count',())
 if t==b'\x03\x01':return (2,'add_load',())
 if t==b'\x33\x01':return (2,'xor_load',())
 if t==b'\x89\x01':return (2,'store',())
 if t==b'\x89\xd0':return (2,'seed_count',())
 if b(3)==b'\xc1\xc0\x05':return (3,'rol5',())
 if b(3)==b'\x83\xc0\x11':return (3,'add17',())
 if b(3)==b'\x83\xea\x01':return (3,'dec_count',())
 if b(4)==b'\x48\x83\xc1\x04':return (4,'advance',())
 raise Unsupported('unsupported memory-profile opcode at 0x%x'%pc)

def recover(pe):
 if any(r or n for r,n in pe.dirs):raise Unsupported('memory profile accepts no PE directories')
 ins=[];pc=pe.entry
 for i in range(32):
  size,op,args=decode(pe,pc);ins.append((pc,size,op,args));pc+=size
  if op=='ret':break
 else:raise Unsupported('memory profile instruction budget')
 # Prove that the only accesses are [entry RCX + 4*i], 0 <= i < entry EDX.
 # No source program name or source code is used by the recognizer.
 ops=[i[2] for i in ins]
 prefix=ops[:3];suffix=ops[-4:];body=ops[3:-4]
 if prefix not in (['zero','test_count','jz'],['seed_count','test_count','jz']):raise Unsupported('unproven loop entry')
 if suffix!=['advance','dec_count','jnz','ret']:raise Unsupported('unproven loop latch')
 if body not in (['add_load'],['xor_load','rol5','add17'],['xor_load','rol5','store']):raise Unsupported('unproven memory body')
 if ins[2][3]!=(ins[-1][0],) or ins[-2][3]!=(ins[3][0],):raise Unsupported('unproven branch target')
 return ins

def emit(pe,ins,mode):
 fn='guest_'+mode
 lines=['#include "guest_memory.h"',
 'GuestResult guest_checked(GuestMemory *,uint64_t,uint32_t);',
 '__attribute__((noinline)) GuestResult %s(GuestMemory *memory,uint64_t address,uint32_t count) {'%fn,
 'GuestResult out={0,0,0,0}; uint32_t eax=0, edx=count, word=0, error=0; uint64_t rcx=address; int zf=0;']
 if mode=='fast':
  access='GM_READ|GM_WRITE' if any(x[2]=='store' for x in ins) else 'GM_READ'
  lines+=['uint8_t *span=NULL;',
   'if(count) { span=gm_range(memory,address,(size_t)count*4,%s,&error);'%access,
   'if(!span) return guest_checked(memory,address,count); }',
   '/* A successful proof holds only while mappings and bytes are stable to other threads. */']
 lines+=['goto L%x;'%pe.entry]
 for pc,size,op,args in ins:
  lines+=['L%x: ; /* guest RVA 0x%x: %s */'%(pc,pc,op)]
  if op=='zero':lines+=['eax=0; zf=1;']
  elif op=='seed_count':lines+=['eax=edx;']
  elif op=='test_count':lines+=['zf=(edx==0);']
  elif op in ('jz','jnz'):lines+=['if(%szf) goto L%x;'%('!' if op=='jnz' else '',args[0])]
  elif op in ('add_load','xor_load'):
   if mode=='checked':
    lines+=['if(!gm_load32(memory,rcx,&word,&error)) { out.result=eax;out.status=error;out.access_address=rcx;out.guest_pc=UINT64_C(%d);return out; }'%(pe.base+pc)]
   else:lines+=['memcpy(&word,span+(size_t)(rcx-address),4);']
   lines+=['eax %s=word; zf=(eax==0);'%('+' if op=='add_load' else '^')]
  elif op=='store':
   if mode=='checked':
    lines+=['if(!gm_store32(memory,rcx,eax,&error)) { out.result=eax;out.status=error;out.access_address=rcx;out.guest_pc=UINT64_C(%d);return out; }'%(pe.base+pc)]
   else:lines+=['memcpy(span+(size_t)(rcx-address),&eax,4);']
  elif op=='rol5':lines+=['eax=(eax<<5)|(eax>>27); /* rotate does not write ZF */']
  elif op=='add17':lines+=['eax+=17;zf=(eax==0);']
  elif op=='advance':lines+=['rcx+=4;zf=(rcx==0);']
  elif op=='dec_count':lines+=['edx-=1;zf=(edx==0);']
  elif op=='ret':lines+=['out.result=eax;return out;'];continue
  else:raise AssertionError(op)
  lines+=['goto L%x;'%(pc+size)]
 lines+=['}'];return '\n'.join(lines)+'\n'

def translate(source,dest):
 pe=PE(source.read_bytes());ins=recover(pe);dest.mkdir(parents=True,exist_ok=True)
 for mode in ('checked','fast'):(dest/(mode+'.c')).write_text(emit(pe,ins,mode))
 result={'input_sha256':hashlib.sha256(pe.data).hexdigest(),'instructions':len(ins),
 'cfg':[{ 'rva':pc,'op':op,'arguments':args} for pc,size,op,args in ins],
 'proof':{'access':'base + 4*i, i in [0,count)','permissions':'immutable during call','threading':'single-threaded backing memory only','fallback':'checked path on any failed span proof','effects':'32-bit modular arithmetic and explicit guest fault output; not SEH'},
 'runtime':'ARM64 native; no CPU interpreter/JIT/Rosetta'}
 (dest/'translation.json').write_text(json.dumps(result,indent=2));return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('input',type=pathlib.Path);p.add_argument('output',type=pathlib.Path);a=p.parse_args()
 try:print(json.dumps(translate(a.input,a.output),indent=2))
 except Unsupported as e:p.exit(2,'REJECT: '+str(e)+'\n')
