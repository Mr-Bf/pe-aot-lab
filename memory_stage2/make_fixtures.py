import pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from fixtures import text_from_coff,pe_image
BODIES={'sum':'addl (%rcx), %eax',
        'mix':'xorl (%rcx), %eax\nroll $5, %eax\naddl $17, %eax',
        'mutate':'xorl (%rcx), %eax\nroll $5, %eax\nmovl %eax, (%rcx)',
        'sum_seed':'addl (%rcx), %eax'}
def build(dest):
 dest.mkdir(parents=True,exist_ok=True)
 for name,body in BODIES.items():
  init='movl %edx, %eax' if name=='sum_seed' else 'xorl %eax, %eax'
  code=init+'\ntestl %edx, %edx\njz 2f\n1:\n'+body+'\naddq $4, %rcx\nsubl $1, %edx\njnz 1b\n2: retq\n'
  asm=dest/(name+'.s');obj=dest/(name+'.obj');asm.write_text('.text\n.globl guest_entry\nguest_entry:\n'+code)
  subprocess.run(['xcrun','clang','-target','x86_64-pc-windows-msvc','-c',str(asm),'-o',str(obj)],check=True)
  raw=text_from_coff(obj.read_bytes());(dest/(name+'.exe')).write_bytes(pe_image(raw))
  (dest/(name+'-oracle.s')).write_text('.text\n.globl _guest_entry\n_guest_entry:\n.byte '+','.join('0x%02x'%b for b in raw)+'\n')
 return dest
