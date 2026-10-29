#!/usr/bin/env python3
import pathlib,subprocess,json,statistics,hashlib
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parent;OUT=ROOT/'build/memory-stage2'
def run(args):
 p=subprocess.run([str(a) for a in args],capture_output=True,text=True)
 if p.returncode:raise RuntimeError('%s\n%s'%(args,p.stderr))
 return p.stdout

def main():
 if not (OUT/'evidence.json').exists():raise SystemExit('Run test_memory.py first')
 rosetta=subprocess.run(['arch','-x86_64','/usr/bin/true'],capture_output=True).returncode==0
 results={}
 for name in ('sum','mix','mutate'):
  dest=OUT/name;native=dest/'native.c'
  body={'sum':'a+=word;','mix':'a^=word;a=(a<<5)|(a>>27);a+=17;','mutate':'a^=word;a=(a<<5)|(a>>27);memcpy(p,&a,4);'}[name]
  native.write_text('#include <stdint.h>\n#include <string.h>\n__attribute__((noinline)) uint32_t native_kernel(uint8_t *p,uint32_t count) { uint32_t a=0;while(count--){uint32_t word;memcpy(&word,p,4);'+body+'p+=4;}return a;}\n')
  variants=['checked','fast','native']+(['rosetta'] if rosetta else [])
  for mode,variant in enumerate(variants):
   sources=[dest/'checked.c',dest/'fast.c'] if mode<2 else [native] if mode==2 else [OUT/'fixtures'/(name+'-oracle.s')]
   run(['xcrun','clang','-arch','x86_64' if mode==3 else 'arm64','-O3','-I',HERE,'-DBENCH_MODE=%d'%mode,HERE/'bench.c']+sources+['-o',dest/('bench-'+variant)])
  samples={v:[] for v in variants}
  # Rotate ordering to reduce systematic order bias. Timings include full native
  # guest/host function boundary costs; every mode begins with the same memory.
  for round_ in range(7):
   order=variants[round_%len(variants):]+variants[:round_%len(variants)]
   for variant in order:
    exe=dest/('bench-'+variant);args=([ 'arch','-x86_64'] if variant=='rosetta' else [])+[exe,4096,3000]
    sample=json.loads(run(args));sample['ns_per_element']=sample['elapsed_ns']/sample['elements'];samples[variant].append(sample)
  checks={(s['checksum'],s['buffer_hash']) for v in samples.values() for s in v};assert len(checks)==1,(name,checks)
  results[name]={v:{'median_ns_per_element':statistics.median(s['ns_per_element'] for s in ss),'samples':ss} for v,ss in samples.items()}
  (dest/'bench-fast.asm').write_text(run(['xcrun','llvm-objdump','--disassemble',dest/'bench-fast']))
 evidence={'status':'PASS','method':'4096 unaligned uint32 elements, 3000 calls/round, 7 rotating rounds; exact guest x86 bytes vs ARM checked/hoisted/native; checksum and mutated memory identical',
 'limits':['Warm small arrays; not a game benchmark','Single-threaded immutable mapping and exclusive backing memory','Source-native does not pay guest address validation','No Wine, DirectX, Windows loader or threads','Fast mode is allowed only for statically proven stream-loop profiles'], 'results':results}
 (OUT/'benchmark.json').write_text(json.dumps(evidence,indent=2));print(json.dumps({k:{v:round(x['median_ns_per_element'],5) for v,x in m.items()} for k,m in results.items()},indent=2))
if __name__=='__main__':main()
