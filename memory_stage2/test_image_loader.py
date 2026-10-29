#!/usr/bin/env python3
import pathlib,struct,sys,random,json
HERE=pathlib.Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(HERE));from image_loader import load_image,ImageError
sys.path.insert(0,str(ROOT));from fixtures import pe_image
OUT=ROOT/'build/memory-stage2/loader'

def fixture():
 # .text RX; .data RW with a pointer and BSS; .reloc R.
 data=bytearray(pe_image(b'\x31\xc0\xc3')[:512]);pe=0x80;opt=pe+24;table=opt+240
 struct.pack_into('<H',data,pe+6,3);struct.pack_into('<H',data,pe+22,0x22)
 struct.pack_into('<I',data,opt+8,1024);struct.pack_into('<I',data,opt+56,0x4000)
 struct.pack_into('<II',data,opt+112+5*8,0x3000,12)
 def section(name,vs,rva,raw,flags):return struct.pack('<8sIIIIIIHHI',name,vs,rva,512,raw,0,0,0,0,flags)
 data[table:table+120]=section(b'.text',3,0x1000,512,0x60000020)+section(b'.data',0x900,0x2000,1024,0xc0000040)+section(b'.reloc',12,0x3000,1536,0x40000040)
 text=b'\x31\xc0\xc3'.ljust(512,b'\0');payload=bytearray(512)
 struct.pack_into('<Q',payload,0,0x140002100);payload[0x100:0x108]=b'payload!'
 relocs=struct.pack('<IIHH',0x2000,12,0xa000,0).ljust(512,b'\0')
 return bytes(data)+text+payload+relocs

def main():
 OUT.mkdir(parents=True,exist_ok=True);source=fixture();(OUT/'reloc-bss.exe').write_bytes(source)
 rng=random.Random(20261027);bases=[0x140000000,0x180000000,0x100000000]+[rng.randrange(0x10000,0x100000)*65536 for _ in range(1000)]
 for base in bases:
  loaded=load_image(source,base)
  pointer=struct.unpack('<Q',loaded.read(base+0x2000,8))[0]
  assert pointer==base+0x2100 and loaded.read(pointer,8)==b'payload!'
  assert loaded.read(base+0x2200,0x700)==b'\0'*0x700
  loaded.write(base+0x2800,b'BSS!');assert loaded.read(base+0x2800,4)==b'BSS!'
  try:loaded.write(base+0x1000,b'X')
  except ImageError:pass
  else:raise AssertionError('RX must reject write')
 last=load_image(source,0x180000000);(OUT/'manifest.json').write_text(json.dumps(last.manifest(),indent=2))
 # Adjacent DIR64 slots are valid in either directory order and must not
 # alter each other's values. Both old values come from the original image.
 for entries in ((0xa000,0xa008),(0xa008,0xa000)):
  adjacent=bytearray(source)
  struct.pack_into('<HH',adjacent,1536+8,*entries)
  struct.pack_into('<Q',adjacent,1024+8,0x140002200)
  moved=load_image(adjacent,0x180000000)
  assert struct.unpack('<QQ',moved.read(0x180002000,16))==(0x180002100,0x180002200)
  assert len(moved.relocations)==2
 errors=[]
 def reject(name,mutator,base=0x180000000):
  d=bytearray(source);mutator(d)
  try:load_image(d,base)
  except ImageError as e:errors.append({'case':name,'status':'REJECT','reason':str(e)})
  else:raise AssertionError(name)
 reject('relocations_stripped',lambda d:struct.pack_into('<H',d,0x80+22,0x23))
 reject('wrong_relocation_type',lambda d:struct.pack_into('<H',d,1536+8,0x3000))
 reject('odd_block_size',lambda d:struct.pack_into('<I',d,1536+4,11))
 reject('target_outside_image',lambda d:struct.pack_into('<I',d,1536,0x5000))
 reject('unsupported_tls',lambda d:struct.pack_into('<II',d,152+112+9*8,0x2000,40))
 reject('bad_image_base',lambda d:None,0x180000001)
 reject('image_overflow',lambda d:None,0xffffffffffff0000+65536)
 reject('overlapping_section',lambda d:struct.pack_into('<I',d,392+40+12,0x1000))
 reject('writable_code',lambda d:struct.pack_into('<I',d,392+36,0xe0000020))
 reject('header_truncated',lambda d:d.__delitem__(slice(500,None)))
 reject('not_executable_image',lambda d:struct.pack_into('<H',d,0x80+22,0x20))
 for shift in (1,4,7):
  reject('overlapping_dir64_%d_forward'%shift,lambda d,shift=shift:struct.pack_into('<HH',d,1536+8,0xa000,0xa000+shift))
  reject('overlapping_dir64_%d_reverse'%shift,lambda d,shift=shift:struct.pack_into('<HH',d,1536+8,0xa000+shift,0xa000))
 reject('duplicate_dir64',lambda d:struct.pack_into('<HH',d,1536+8,0xa000,0xa000))
 reject('relocation_directory_self_patch',lambda d:struct.pack_into('<I',d,1536,0x3000))
 reject('relocation_crosses_directory_start',lambda d:struct.pack_into('<H',d,1536+8,0xaffc))
 reject('exclusive_end_overflow',lambda d:struct.pack_into('<I',d,152+56,0x10000),0xffffffffffff0000)
 def bad_preferred(d):
  struct.pack_into('<I',d,152+56,0x10000);struct.pack_into('<Q',d,152+24,0xffffffffffff0000)
 reject('preferred_exclusive_end_overflow',bad_preferred)
 result={'status':'PASS','rebase_bss_permission_cases':len(bases),'adjacent_relocation_order_cases':2,'rejections':errors,'scope':'Restricted PE32+ in-memory data image, DIR64 and BSS; not process execution, host mapping, imports, TLS or SEH'}
 (OUT/'evidence.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
if __name__=='__main__':main()
