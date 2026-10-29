#!/usr/bin/env python3
import pathlib,sys,subprocess,ctypes,random,struct,json,hashlib
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(HERE))
from make_fixtures import BODIES,build
from translate import translate
sys.path.insert(0,str(ROOT))
from pe_aot import PE,Unsupported
from translate import recover
OUT=ROOT/'build/memory-stage2'
class Memory(ctypes.Structure):
 _fields_=[('base',ctypes.c_uint64),('size',ctypes.c_size_t),('bytes',ctypes.POINTER(ctypes.c_uint8)),('permissions',ctypes.POINTER(ctypes.c_uint8)),('page_count',ctypes.c_size_t)]
class Result(ctypes.Structure):
 _fields_=[('result',ctypes.c_uint32),('status',ctypes.c_uint32),('access_address',ctypes.c_uint64),('guest_pc',ctypes.c_uint64)]
def run(args,input=None):
 p=subprocess.run([str(a) for a in args],input=input,capture_output=True,text=True)
 if p.returncode:raise RuntimeError('%s\n%s'%(args,p.stderr))
 return p.stdout

def memory(raw,base=0x170000000,permissions=None):
 data=(ctypes.c_uint8*len(raw)).from_buffer_copy(raw)
 n=(len(raw)+4095)//4096
 perms=(ctypes.c_uint8*n)(*([3]*n if permissions is None else permissions))
 m=Memory(base,len(raw),data,perms,n);m.owner=(data,perms);return m

def result_tuple(result):return tuple(getattr(result,n) for n,_ in Result._fields_)
def main():
 fixtures=build(OUT/'fixtures');OUT.mkdir(exist_ok=True)
 has_rosetta=subprocess.run(['arch','-x86_64','/usr/bin/true'],capture_output=True).returncode==0
 rng=random.Random(20261027);cases=[]
 for i in range(1000):
  count=[0,1,2,1023,1024,1025,2047][i] if i<7 else rng.randrange(2048)
  offset=rng.randrange(8);values=[rng.getrandbits(32) for _ in range(count)]
  cases.append((count,offset,values,((0x140000000+rng.randrange(1<<18)*4096))))
 inputs=''.join('%d %d '%(n,o)+' '.join('%08x'%v for v in values)+'\n' for n,o,values,_ in cases)
 evidence=[];libraries={}
 for name in BODIES:
  dest=OUT/name;translate(fixtures/(name+'.exe'),dest)
  if name=='sum_seed':
   pe=PE((fixtures/(name+'.exe')).read_bytes())
   assert pe.read(pe.entry,2)==b'\x89\xd0', 'seed fixture must execute MOV EAX, EDX'
  lib=dest/'aot.dylib'
  run(['xcrun','clang','-arch','arm64','-O3','-dynamiclib','-I',HERE,dest/'checked.c',dest/'fast.c',HERE/'probe.c','-o',lib])
  dylib=ctypes.CDLL(str(lib));libraries[name]=dylib
  for mode in ('checked','fast'):
   f=getattr(dylib,'guest_'+mode);f.argtypes=[ctypes.POINTER(Memory),ctypes.c_uint64,ctypes.c_uint32];f.restype=Result
  answers=None
  if has_rosetta:
   oracle=dest/'oracle-x86'
   run(['xcrun','clang','-arch','x86_64','-O3',HERE/'oracle.c',fixtures/(name+'-oracle.s'),'-o',oracle])
   answers=run(['arch','-x86_64',oracle],inputs).splitlines();assert len(answers)==len(cases)
  output_hash=hashlib.sha256()
  for i,(count,offset,values,base) in enumerate(cases):
   raw=b'\xa5'*offset+b''.join(struct.pack('<I',v) for v in values)+b'\xa5'*16
   outputs=[]
   for mode in ('checked','fast'):
    m=memory(raw,base);r=getattr(dylib,'guest_'+mode)(ctypes.byref(m),base+offset,count)
    assert r.status==0,(name,mode,i,result_tuple(r))
    if name=='sum_seed':assert r.result==(count+sum(values))&0xffffffff,(name,mode,i,'seed arithmetic')
    all_bytes=bytes(m.owner[0]);assert all_bytes[:offset]==raw[:offset] and all_bytes[offset+count*4:]==raw[offset+count*4:]
    words=struct.unpack('<%dI'%count,all_bytes[offset:offset+count*4]) if count else ()
    outputs.append((r.result,words));assert outputs[0]==outputs[-1]
   actual='%08x'%outputs[0][0]+''.join(' %08x'%v for v in outputs[0][1])
   if answers is not None:assert actual==answers[i],(name,i,actual[:80],answers[i][:80])
   output_hash.update((actual+'\n').encode())
  evidence.append({'name':name,'cases':len(cases),'accumulator_init':'entry_EDX' if name=='sum_seed' else 'zero','modes':['checked','verified_span_with_checked_fallback'],'status':'PASS','oracle':'original COFF text in Rosetta ms_abi harness' if has_rosetta else 'SKIP original-byte oracle; only modes compared','output_sha256':output_hash.hexdigest(),'identity':run(['file',fixtures/(name+'.exe'),lib]).strip()})
  for mode in ('checked','fast'):
   run(['xcrun','clang','-arch','arm64','-O3','-I',HERE,'-S','-emit-llvm',dest/(mode+'.c'),'-o',dest/(mode+'.ll')])
  (dest/'arm64.asm').write_text(run(['xcrun','llvm-objdump','--disassemble',lib]))
 # Memory boundary checks, including access spanning two guest pages.
 dylib=libraries['sum'];dylib.memory_load.argtypes=[ctypes.POINTER(Memory),ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32)];dylib.memory_load.restype=ctypes.c_int
 dylib.memory_store.argtypes=[ctypes.POINTER(Memory),ctypes.c_uint64,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32)];dylib.memory_store.restype=ctypes.c_int
 boundary=[];base=0x170000000
 for label,address,perms,want in [
  ('unaligned',base+1,[3,3],0),('cross_page_read',base+4094,[1,1],0),
  ('cross_page_denied',base+4094,[1,0],2),('below_base',base-1,[3,3],1),
  ('end_overflow',base+8190,[3,3],1),('uint64_max',2**64-2,[3,3],1)]:
  m=memory(bytes(range(256))*32,base,perms);out=ctypes.c_uint32(0xdeadbeef);error=ctypes.c_uint32()
  ok=dylib.memory_load(ctypes.byref(m),address,ctypes.byref(out),ctypes.byref(error))
  assert error.value==want and bool(ok)==(want==0),(label,error.value)
  if want:assert out.value==0xdeadbeef
  boundary.append({'test':label,'status':'PASS','error':error.value})
 for label,address,perms,want in [('write_readonly',base+4,[1,3],2),('cross_page_write_denied',base+4094,[3,1],2),('cross_page_write',base+4094,[3,3],0)]:
  raw=b'\xa5'*8192;m=memory(raw,base,perms);error=ctypes.c_uint32()
  ok=dylib.memory_store(ctypes.byref(m),address,0x12345678,ctypes.byref(error))
  assert error.value==want and bool(ok)==(want==0)
  if want:assert bytes(m.owner[0])==raw
  else:assert bytes(m.owner[0])[address-base:address-base+4]==b'\x78\x56\x34\x12'
  boundary.append({'test':label,'status':'PASS','error':error.value})
 # Failed proof must fall back: preserve the checked path's prior writes and exact guest fault PC.
 for name in BODIES:
  raw=bytes(range(256))*32;outcomes=[]
  for mode in ('checked','fast'):
   m=memory(raw,base,[3,0]);r=getattr(libraries[name],'guest_'+mode)(ctypes.byref(m),base,1025)
   outcomes.append((result_tuple(r),bytes(m.owner[0])))
  assert outcomes[0]==outcomes[1] and outcomes[0][0][1]==2
  if name=='mutate':assert outcomes[0][1][:4096]!=raw[:4096]
  if name=='sum_seed':
   want=(1025+sum(struct.unpack('<1024I',raw[:4096])))&0xffffffff
   assert outcomes[0][0][0]==want and outcomes[0][1]==raw
  boundary.append({'test':name+'_failed_proof_preserves_partial_effects','status':'PASS','guest_fault_pc':hex(outcomes[0][0][3])})
 # A first-access failure must retain EDX's full unsigned seed; count zero
 # performs no memory access, even when the host descriptor is NULL.
 pe=PE((fixtures/'sum_seed.exe').read_bytes());load_pc=pe.base+pe.entry+6
 seed_counts=[1,2,0x80000000,0xffffffff]
 for mode in ('checked','fast'):
  for count in seed_counts:
   m=memory(b'\xa5'*4,base,[0]);r=getattr(libraries['sum_seed'],'guest_'+mode)(ctypes.byref(m),base,count)
   assert result_tuple(r)==(count,2,base,load_pc),(mode,count,result_tuple(r))
   assert bytes(m.owner[0])==b'\xa5'*4
  r=getattr(libraries['sum_seed'],'guest_'+mode)(None,2**64-1,0)
  assert result_tuple(r)==(0,0,0,0),(mode,result_tuple(r))
 boundary.append({'test':'seed_count_first_fault_preserves_unsigned_seed','status':'PASS','counts':seed_counts,'modes':2})
 boundary.append({'test':'seed_count_zero_count_without_memory','status':'PASS','modes':2})
 rejected=[]
 raw=bytearray((fixtures/'sum.exe').read_bytes());raw[raw.index(b'\x48\x83\xc1\x04')+3]=8
 try:recover(PE(bytes(raw)))
 except Unsupported as e:rejected.append({'test':'unproven_stride','status':'REJECT','reason':str(e)})
 else:raise AssertionError('stride 8 must reject')
 functional_cases=sum(x['cases'] for x in evidence)
 results={'status':'PASS','functional_cases':functional_cases,'original_byte_oracle':has_rosetta,'boundary_checks':boundary,'rejection_checks':rejected,'fixtures':evidence,'limits':['Single-threaded stable memory only','No general PE image loading, relocation, syscall, TLS, SEH, or TSO','Only recognized stream-loop profiles','Host backing allocations are trusted, guest addresses never native pointers']}
 (OUT/'evidence.json').write_text(json.dumps(results,indent=2));print(json.dumps({'status':results['status'],'functional_cases':functional_cases,'original_byte_oracle':has_rosetta,'boundary_checks':len(boundary),'rejections':len(rejected)},indent=2))
if __name__=='__main__':main()
