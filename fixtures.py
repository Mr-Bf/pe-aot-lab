"""Build self-authored AMD64 COFF with Clang; wrap .text in minimal PE32+.
This small fixture linker accepts zero COFF relocations. No game inputs.
"""
import pathlib,struct,subprocess
from pe_aot import unpack
SOURCES={
 'add': 'movl %ecx, %eax\naddl %edx, %eax\nretq',
 'loop': 'xorl %eax, %eax\ntestl %ecx, %ecx\njz 2f\n1: addl %ecx, %eax\nsubl $1, %ecx\njnz 1b\n2: retq',
 'pid': 'subq $40, %rsp\n.byte 0xff,0x15\n.long 0x2040 - (0x1000 + (. - guest_entry) + 4)\naddq $40, %rsp\nretq',
 'flags_add': 'movl %ecx, %eax\naddl %edx, %eax\npushfq\npopq %rax\nandl $0x8d5, %eax\nretq',
 'flags_sub': 'movl %ecx, %eax\nsubl %edx, %eax\npushfq\npopq %rax\nandl $0x8d5, %eax\nretq',
 'unsupported': 'ud2\nretq',
 'indirect': 'jmpq *%rax',
 'undefined_flags':'jnz 1f\n1: retq',
 'undefined_af':'xorl %eax, %eax\npushfq\npopq %rax\nandl $0x8d5, %eax\nretq',
 'stack_flags':'subq $40, %rsp\njz 1f\n1: addq $40, %rsp\nxorl %eax, %eax\nretq',
 'uninit_eax':'retq',
 'import_volatile':'subq $40, %rsp\n.byte 0xff,0x15\n.long 0x2040 - (0x1000 + (. - guest_entry) + 4)\naddq $40, %rsp\nmovl %ecx, %eax\nretq',
 'import_bad_shadow':'subq $8, %rsp\n.byte 0xff,0x15\n.long 0x2040 - (0x1000 + (. - guest_entry) + 4)\naddq $8, %rsp\nretq',
}
C_SOURCES={
 'compiled_add':'unsigned guest_entry(unsigned a,unsigned b) { return a+b; }\n',
 'compiled_checksum':'unsigned guest_entry(unsigned a,unsigned b) { return (a^b)+17; }\n',
}
def text_from_coff(data):
 machine,nsec,_,_,_,opt,_=unpack('<HHIIIHH',data,0)
 assert machine==0x8664
 for i in range(nsec):
  s=20+opt+40*i
  name,_,_,size,raw,_,_,nrel,_,_=unpack('<8sIIIIIIHHI',data,s)
  if name.rstrip(b'\0')==b'.text':
   assert nrel==0,'fixture linker does not implement COFF relocations'
   return data[raw:raw+size]
 raise ValueError('no text')
def pe_image(text,imports=False):
 n=2 if imports else 1
 dos=bytearray(0x80);dos[:2]=b'MZ';struct.pack_into('<I',dos,0x3c,0x80)
 coff=struct.pack('<HHIIIHH',0x8664,n,0,0,0,240,0x23)
 opt=bytearray(240)
 struct.pack_into('<H',opt,0,0x20b)
 struct.pack_into('<III',opt,4,512,512 if imports else 0,0)
 struct.pack_into('<IIQ',opt,16,0x1000,0x1000,0x140000000)
 struct.pack_into('<II',opt,32,0x1000,0x200)
 struct.pack_into('<HH',opt,40,6,0);struct.pack_into('<HH',opt,48,6,0)
 struct.pack_into('<II',opt,56,0x3000 if imports else 0x2000,0x200)
 struct.pack_into('<HH',opt,68,3,0x100) # console; NX_COMPAT
 struct.pack_into('<QQQQII',opt,72,0x100000,0x1000,0x100000,0x1000,0,16)
 def section(name,vs,va,raw,flags):return struct.pack('<8sIIIIIIHHI',name,vs,va,512,raw,0,0,0,0,flags)
 headers=dos+b'PE\0\0'+coff+opt+section(b'.text',len(text),0x1000,512,0x60000020)
 idata=bytearray(512)
 if imports:
  struct.pack_into('<II',opt,112+8,0x2000,40)
  struct.pack_into('<II',opt,112+12*8,0x2040,16)
  headers=dos+b'PE\0\0'+coff+opt+section(b'.text',len(text),0x1000,512,0x60000020)+section(b'.idata',0xb0,0x2000,1024,0xc0000040)
  struct.pack_into('<IIIII',idata,0,0x2030,0,0,0x2060,0x2040)
  struct.pack_into('<QQ',idata,0x30,0x2080,0);struct.pack_into('<QQ',idata,0x40,0x2080,0)
  idata[0x60:0x60+13]=b'kernel32.dll\0'
  symbol=b'\0\0GetCurrentProcessId\0';idata[0x80:0x80+len(symbol)]=symbol
 assert len(text)<=512 and len(headers)<=512
 return headers.ljust(512,b'\0')+text.ljust(512,b'\0')+(idata if imports else b'')
def build(directory):
 directory.mkdir(parents=True,exist_ok=True)
 for name,source in SOURCES.items():
  asm=directory/(name+'.s');obj=directory/(name+'.obj')
  asm.write_text('.text\n.globl guest_entry\nguest_entry:\n'+source+'\n')
  subprocess.run(['xcrun','clang','-target','x86_64-pc-windows-msvc','-c',str(asm),'-o',str(obj)],check=True)
  (directory/(name+'.exe')).write_bytes(pe_image(text_from_coff(obj.read_bytes()),name=='pid' or name.startswith('import_')))
 for name,source in C_SOURCES.items():
  c=directory/(name+'.c');obj=directory/(name+'.obj');c.write_text(source)
  subprocess.run(['xcrun','clang','-target','x86_64-pc-windows-msvc','-O2','-fno-asynchronous-unwind-tables','-c',str(c),'-o',str(obj)],check=True)
  (directory/(name+'.exe')).write_bytes(pe_image(text_from_coff(obj.read_bytes())))
 return directory
if __name__=='__main__':build(pathlib.Path(__file__).parent/'build'/'fixtures')
