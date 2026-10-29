#!/usr/bin/env python3
"""Strict profile rejection checks; no guest program is executed."""
import hashlib,json,pathlib,sys
try:
 from .lift import lift_pe,TranslationError,HERE,REPO
except ImportError:
 from lift import lift_pe,TranslationError,HERE,REPO
sys.path.insert(0,str(REPO));from fixtures import pe_image
CASES={
 'ud2':'0f0bc3','syscall':'0f05c3','lock':'f00101c3','rep':'f3a4c3',
 'gs':'65488b01c3','fs':'64488b01c3','segment_ds':'3e488b01c3',
 'mov_to_segment':'8ed8c3','mov_from_segment':'8cd8c3','ret_imm':'c21000',
 'control_register':'0f20c0c3','simd':'660fefc0c3','x87':'d9e8c3',
 'indirect_call':'ffd0c3','indirect_jump':'ffe0','call_next':'e80000000058c3',
 'memory_rmw':'830101c3','rotate_cl':'d3c0c3','entry_undefined_flags':'7500c3',
 'rotate_undefined_of':'89c8c1c00d7000c3',
 'absolute_memory':'488b042500200040c3',
 'absolute_image_immediate':'48b80011004001000000c3',
}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def identity():
 manifest=REPO/'build/integration-stage3/lifter/build-manifest.json'
 build=json.loads(manifest.read_text())
 return {'build_manifest_sha256':sha(manifest),'lifter_sha256':build['lifter_sha256'],
         'semantics_sha256':build['semantics_sha256'],
         'source_sha256':{name:sha(REPO/name) for name in (
             'integration_stage3/lifter_checks.py','integration_stage3/lift.py',
             'integration_stage3/build_lifter.py','integration_stage3/lifter_layout.cpp',
             'fixtures.py','pe_aot.py','memory_stage2/image_loader.py')}}
def main():
 out=REPO/'build/integration-stage3/lifter-checks';out.mkdir(parents=True,exist_ok=True)
 (out/'results.json').write_text(json.dumps({'status':'RUNNING'})+'\n')
 before=identity();results=[]
 for name,raw in CASES.items():
  pe=out/(name+'.exe');pe.write_bytes(pe_image(bytes.fromhex(raw)))
  try:lift_pe(pe,out/name)
  except TranslationError as e:results.append({'name':name,'rejected':True,'reason':str(e)})
  else:raise AssertionError('Unapproved input accepted: '+name)
 if identity()!=before:raise RuntimeError('Lifter rejection dependencies changed during execution')
 (out/'results.json').write_text(json.dumps({'status':'PASS','count':len(results),'cases':results,**before},indent=2)+'\n')
 print('PASS:',len(results),'unsupported profiles rejected before execution')
if __name__=='__main__':main()
