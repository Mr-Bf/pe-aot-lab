#!/usr/bin/env python3
"""Independent original-byte oracle for Remill + mapped guest load/store + RET."""
import ctypes
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from integration_stage3.bindings import Program,Region,EXIT_VA
from memory_stage2.make_fixtures import build,BODIES
OUT=ROOT/'build/integration-stage3/memory'

def run(args,input=None):
    p=subprocess.run(list(map(str,args)),input=input,text=True,capture_output=True)
    if p.returncode:raise RuntimeError(str(args)+'\n'+p.stderr)
    return p.stdout

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    evidence=OUT/'evidence.json';evidence.write_text('{"status":"RUNNING"}\n')
    if subprocess.run(['arch','-x86_64','/usr/bin/true'],capture_output=True).returncode:
        evidence.write_text('{"status":"SKIP","reason":"original-byte Rosetta oracle unavailable"}\n');return
    fixtures=build(OUT/'fixtures')
    rng=random.Random(20261028);cases=[]
    for i in range(300):
        n=[0,1,2,1023,1024,1025,2047][i] if i<7 else rng.randrange(257)
        offset=rng.randrange(8);words=[rng.getrandbits(32) for _ in range(n)]
        cases.append((n,offset,words,0x500000000+rng.randrange(1<<16)*4096))
    inputs=''.join(f'{n} {offset} '+' '.join(f'{w:08x}' for w in words)+'\n' for n,offset,words,_ in cases)
    records=[];boundaries=[];programs={}
    for name in BODIES:
        program=Program(fixtures/(name+'.exe'),OUT/name);programs[name]=program
        oracle=OUT/name/'oracle-x86'
        run(['xcrun','clang','-arch','x86_64','-O3',ROOT/'memory_stage2/oracle.c',
             fixtures/(name+'-oracle.s'),'-o',oracle])
        expected=run(['arch','-x86_64',oracle],inputs).splitlines()
        assert len(expected)==len(cases)
        output=hashlib.sha256()
        for i,(n,offset,words,base) in enumerate(cases):
            initial=bytearray(b'\xa5'*offset+b''.join(struct.pack('<I',w) for w in words)+b'\xa5'*16)
            data=Region(base,bytearray(initial))
            assert data.base!=ctypes.addressof(ctypes.c_uint8.from_buffer(data.data))
            result=program.run(gpr={'RCX':base+offset,'RDX':n},regions=[data])
            assert result.status==0 and result.returned and result.call_depth==0,(name,i,result)
            assert result.registers['RIP']==EXIT_VA
            assert result.registers['RSP']==result.stack.base+len(result.stack.data)-0x100
            assert data.data[:offset]==initial[:offset] and data.data[offset+n*4:]==initial[offset+n*4:]
            words_after=struct.unpack('<%dI'%n,data.data[offset:offset+n*4]) if n else ()
            actual=f'{result.registers["RAX"]:08x}'+''.join(f' {w:08x}' for w in words_after)
            assert actual==expected[i],(name,i,actual,expected[i])
            output.update((actual+'\n').encode())
        records.append({'name':name,'cases':len(cases),'status':'PASS','output_sha256':output.hexdigest(),
                        'oracle':'original Windows COFF .text under Rosetta/ms_abi',
                        'input_sha256':sha(fixtures/(name+'.exe')),
                        'arm64_object_sha256':sha(OUT/name/'arm64.o'),
                        'dylib_sha256':sha(OUT/name/'program.dylib')})
    # Precise architectural state at a faulting ADD, after 1,024 successful iterations.
    base=0x520000000;initial=bytearray(bytes(range(256))*32)
    for name in ('sum','sum_seed'):
        p=programs[name];data=Region(base,bytearray(initial),bytearray([3,0]))
        r=p.run(gpr={'RCX':base,'RDX':1025},regions=[data])
        want=(sum(struct.unpack('<1024I',initial[:4096]))+(1025 if name=='sum_seed' else 0))&0xffffffff
        pc=p.image.base+next(i['rva'] for i in p.manifest['instructions'] if i['bytes']=='0301')
        assert r.status==2 and not r.returned and data.data==initial
        assert r.registers['RAX']==want and r.registers['RCX']==base+4096 and r.registers['RDX']==1
        assert r.registers['RIP']==pc and r.fault=={'status':2,'access':1,'pc':pc,'address':base+4096,'width':4}
        boundaries.append({'test':name+'_faulting_add_rolls_back_registers','status':'PASS'})
    # A store after a successful read/rotate fails as one instruction; earlier instructions stay visible.
    p=programs['mutate'];data=Region(base,bytearray(initial),bytearray([3,1]))
    expected=bytearray(initial);acc=0
    for i in range(1025):
        acc^=struct.unpack_from('<I',expected,i*4)[0];acc=((acc<<5)|(acc>>27))&0xffffffff
        if i<1024:struct.pack_into('<I',expected,i*4,acc)
    r=p.run(gpr={'RCX':base,'RDX':1025},regions=[data])
    pc=p.image.base+next(i['rva'] for i in p.manifest['instructions'] if i['bytes']=='8901')
    assert r.status==2 and data.data==expected and r.registers['RAX']==acc and r.registers['RIP']==pc
    assert r.fault['address']==base+4096 and r.fault['access']==2
    boundaries.append({'test':'prior_writes_preserved_on_store_fault','status':'PASS'})
    # One unaligned load/store can span separate adjacent guest mappings safely.
    p=programs['mutate'];a=Region(base,bytearray(b'\x11'*4096));b=Region(base+4096,bytearray(b'\x22'*4096))
    r=p.run(gpr={'RCX':base+4094,'RDX':1},regions=[a,b])
    word=0x22221111;want=((word<<5)|(word>>27))&0xffffffff
    assert r.status==0 and a.data[-2:]+b.data[:2]==struct.pack('<I',want)
    boundaries.append({'test':'unaligned_access_across_distinct_backing_allocations','status':'PASS'})
    a=Region(base,bytearray(b'\x11'*4096));b=Region(base+4096,bytearray(b'\x22'*4096),bytearray([1]))
    r=p.run(gpr={'RCX':base+4094,'RDX':1},regions=[a,b])
    assert r.status==2 and a.data==b'\x11'*4096 and b.data==b'\x22'*4096
    boundaries.append({'test':'cross_mapping_store_fault_has_no_partial_write','status':'PASS'})
    # Zero count must never touch its invalid data pointer; it still executes a real RET stack read.
    for name in BODIES:
        r=programs[name].run(gpr={'RCX':2**64-1,'RDX':0})
        assert r.status==0 and r.registers['RAX']==0
    boundaries.append({'test':'zero_count_invalid_data_pointer','status':'PASS','programs':4})
    r=programs['sum'].run(gpr={'RCX':2**64-2,'RDX':1})
    assert r.status==1 and r.fault['address']==2**64-2 and r.fault['width']==4
    boundaries.append({'test':'uint64_access_wrap_rejected','status':'PASS'})
    data=Region(base,bytearray(4096),bytearray([0]))
    r=programs['sum'].run(gpr={'RCX':base+4094,'RDX':1},regions=[data])
    assert r.status==1 and r.fault['width']==4 and r.fault['address']==base+4094
    boundaries.append({'test':'full_range_bounds_precede_permission_check','status':'PASS'})
    sources=['integration_stage3/runtime.c','integration_stage3/runtime.h','integration_stage3/bindings.py',
             'integration_stage3/test_memory.py','integration_stage3/lift.py','memory_stage2/make_fixtures.py',
             'memory_stage2/oracle.c','memory_stage2/image_loader.py']
    report={'status':'PASS','functional_cases':sum(r['cases'] for r in records),'samples':records,
            'boundaries':boundaries,'source_sha256':{p:sha(ROOT/p) for p in sources},
            'scope':'real Remill with mapped guest addresses, transactional scalar reads/writes and real RET; single threaded trusted mappings; no Windows startup, API, SIMD or SEH'}
    evidence.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'status':'PASS','cases':report['functional_cases'],'boundaries':len(boundaries)}))

if __name__=='__main__':main()
