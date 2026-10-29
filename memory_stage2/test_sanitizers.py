#!/usr/bin/env python3
import pathlib,json,subprocess
HERE=pathlib.Path(__file__).resolve().parent;OUT=HERE.parent/'build/memory-stage2'
def main():
 results=[]
 for name in ('sum','mix','mutate','sum_seed'):
  d=OUT/name;exe=d/'sanitize'
  cmd=['xcrun','clang','-arch','arm64','-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I',str(HERE),str(HERE/'sanitize.c'),str(d/'checked.c'),str(d/'fast.c'),'-o',str(exe)]
  subprocess.run(cmd,check=True,capture_output=True,text=True)
  p=subprocess.run([str(exe)],capture_output=True,text=True)
  if p.returncode:raise RuntimeError(name+'\n'+p.stderr)
  record=json.loads(p.stdout);record['name']=name;record['stderr']=p.stderr;results.append(record)
 evidence={'status':'PASS','sanitizers':['AddressSanitizer','UndefinedBehaviorSanitizer'],'mode':'ARM64 native randomized differential of checked vs fast, including failing accesses and prior writes','tests':results,'cases':sum(x['cases'] for x in results)}
 (OUT/'sanitizers.json').write_text(json.dumps(evidence,indent=2));print(json.dumps(evidence,indent=2))
if __name__=='__main__':main()
