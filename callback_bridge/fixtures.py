#!/usr/bin/env python3
"""Self-authored original PE IAT -> native -> six-argument guest callback callers."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from integration_stage3.call_fixtures import parse_coff

IMAGE_BASE=0x140000000
TEXT_RVA=0x1000
IDATA_RVA=0x2000
MASK64=(1<<64)-1
NAMES=('leaf','import','direct','nested')


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def coff_labels(data,wanted):
    _,_,_,table,count,_,_=struct.unpack_from('<HHIIIHH',data)
    strings=table+count*18;labels={};index=0
    while index<count:
        raw,value,section,_,_,aux=struct.unpack_from('<8sIhHBB',data,table+index*18)
        if raw[:4]==b'\0'*4:
            offset=struct.unpack_from('<I',raw,4)[0];start=strings+offset
            name=data[start:data.index(b'\0',start)].decode('ascii')
        else:name=raw.rstrip(b'\0').decode('ascii')
        if section>0 and name in wanted:labels[name]=value
        index+=1+aux
    return labels


def make_idata(imports):
    count=len(imports);data=bytearray(512)
    ilt_start=((count+1)*20+7)&~7
    iat_start=ilt_start+count*16
    cursor=iat_start+count*16
    slots={}
    for index,(dll,name,signature) in enumerate(imports):
        ilt=ilt_start+index*16;iat=iat_start+index*16
        encoded=dll.encode('ascii')+b'\0';dll_offset=cursor
        data[cursor:cursor+len(encoded)]=encoded;cursor+=len(encoded)
        cursor=(cursor+1)&~1
        encoded=b'\0\0'+name.encode('ascii')+b'\0';name_offset=cursor
        data[cursor:cursor+len(encoded)]=encoded;cursor+=len(encoded)
        struct.pack_into('<IIIII',data,index*20,IDATA_RVA+ilt,0,0,IDATA_RVA+dll_offset,IDATA_RVA+iat)
        struct.pack_into('<QQ',data,ilt,IDATA_RVA+name_offset,0)
        struct.pack_into('<QQ',data,iat,IDATA_RVA+name_offset,0)
        slots[name]={'dll':dll,'name':name,'signature':signature,'iat_rva':IDATA_RVA+iat}
    if cursor>512:raise ValueError('bounded import fixture exceeded')
    return data,slots,cursor,(count+1)*20,IDATA_RVA+iat_start,count*16


def pe_image(text,imports):
    if not 0<len(text)<=512:raise ValueError('bounded fixture text required')
    idata,slots,extent,dsize,iat,isize=make_idata(imports)
    dos=bytearray(0x80);dos[:2]=b'MZ';struct.pack_into('<I',dos,0x3c,0x80)
    coff=struct.pack('<HHIIIHH',0x8664,3,0,0,0,240,0x22)
    opt=bytearray(240);struct.pack_into('<H',opt,0,0x20b)
    struct.pack_into('<III',opt,4,512,1024,0)
    struct.pack_into('<IIQ',opt,16,TEXT_RVA,TEXT_RVA,IMAGE_BASE)
    struct.pack_into('<II',opt,32,4096,512)
    struct.pack_into('<HH',opt,40,6,0);struct.pack_into('<HH',opt,48,6,0)
    struct.pack_into('<II',opt,56,0x4000,512)
    struct.pack_into('<HH',opt,68,3,0x140)
    struct.pack_into('<QQQQII',opt,72,0x100000,0x1000,0x100000,0x1000,0,16)
    struct.pack_into('<II',opt,112+8,IDATA_RVA,dsize)
    struct.pack_into('<II',opt,112+12*8,iat,isize)
    struct.pack_into('<II',opt,112+5*8,0x3000,12)
    def section(name,size,rva,raw,flags):
        return struct.pack('<8sIIIIIIHHI',name,size,rva,512,raw,0,0,0,0,flags)
    headers=dos+b'PE\0\0'+coff+opt
    headers+=section(b'.text',len(text),TEXT_RVA,512,0x60000020)
    headers+=section(b'.idata',extent,IDATA_RVA,1024,0xc0000040)
    headers+=section(b'.reloc',12,0x3000,1536,0x42000040)
    if len(headers)!=512:raise ValueError('unexpected header extent')
    return bytes(headers)+text.ljust(512,b'\0')+bytes(idata)+struct.pack('<IIHH',0,12,0,0).ljust(512,b'\0')


def iat_call(slot):
    return '.byte 0xff,0x15\n.long %d - (%d + (. - guest_entry) + 4)\n'%(slot,TEXT_RVA)


WEIGHTED=('movq %rcx,%rax\nleaq (%rdx,%rdx,2),%r10\naddq %r10,%rax\n'
          'leaq (%r8,%r8,4),%r10\naddq %r10,%rax\n'
          'leaq (%r9,%r9,2),%r10\nleaq (%r9,%r10,2),%r10\naddq %r10,%rax\n'
          'movq 40(%rsp),%r10\nleaq (%r10,%r10,4),%r11\nleaq (%r10,%r11,2),%r11\naddq %r11,%rax\n'
          'movq 48(%rsp),%r10\nleaq (%r10,%r10,2),%r11\nleaq (%r10,%r11,4),%r11\naddq %r11,%rax\n')


def body(name,slots):
    # Entry accepts six values. The real import takes callback pointer + six
    # values, so arg4/5/6 become three correctly placed Win64 stack arguments.
    main=('guest_entry:\nmovq 40(%rsp),%r10\nmovq 48(%rsp),%r11\nsubq $56,%rsp\n'
          'movq %r9,32(%rsp)\nmovq %r10,40(%rsp)\nmovq %r11,48(%rsp)\n'
          'movq %r8,%r9\nmovq %rdx,%r8\nmovq %rcx,%rdx\n'
          '.byte 0x48,0x8d,0x0d\n.long guest_callback - (. + 4)\n'
          'main_call:\n'+iat_call(slots['NativeInvokeCallback']['iat_rva'])+
          'main_after_call:\naddq $7,%rax\naddq $56,%rsp\nmain_ret:\nretq\n'
          '.p2align 4,0x90\nguest_callback:\n')
    if name=='leaf':callback=WEIGHTED+'addq $17,%rax\ncallback_ret:\nretq\n'
    elif name in ('import','direct'):
        callback=('movq 40(%rsp),%r10\nmovq 48(%rsp),%r11\nsubq $56,%rsp\n'
                  'movq %r10,32(%rsp)\nmovq %r11,40(%rsp)\ncallback_call:\n')
        callback+=(iat_call(slots['NativeSix']['iat_rva']) if name=='import' else
                   '.byte 0xe8\n.long guest_helper - (. + 4)\n')
        callback+='callback_after_call:\naddq $17,%rax\naddq $56,%rsp\ncallback_ret:\nretq\n'
        if name=='direct':callback+='.p2align 4,0x90\nguest_helper:\n'+WEIGHTED+'helper_ret:\nretq\n'
    elif name=='nested':
        callback=('testq %rcx,%rcx\n.byte 0x0f,0x84\n.long callback_base - (. + 4)\n'
                  'movq 40(%rsp),%r10\nmovq 48(%rsp),%r11\nsubq $56,%rsp\n'
                  'movq %r9,32(%rsp)\nmovq %r10,40(%rsp)\nmovq %r11,48(%rsp)\n'
                  'movq %r8,%r9\nmovq %rdx,%r8\nmovq %rcx,%rdx\nsubq $1,%rdx\n'
                  '.byte 0x48,0x8d,0x0d\n.long guest_callback - (. + 4)\ncallback_call:\n'+
                  iat_call(slots['NativeInvokeCallback']['iat_rva'])+
                  'callback_after_call:\naddq $17,%rax\naddq $56,%rsp\ncallback_ret:\nretq\n'
                  'callback_base:\n'+WEIGHTED+'addq $17,%rax\ncallback_base_ret:\nretq\n')
    else:raise ValueError('unknown callback fixture')
    labels=['guest_entry','main_call','main_after_call','main_ret','guest_callback','callback_ret']
    if name!='leaf':labels+=['callback_call','callback_after_call']
    if name=='direct':labels+=['guest_helper','helper_ret']
    if name=='nested':labels+=['callback_base','callback_base_ret']
    return '.text\n'+''.join('.globl '+x+'\n' for x in labels)+main+callback,labels


def expected(arguments,name='leaf'):
    if len(arguments)!=6:raise ValueError('six uint64 arguments required')
    if name=='nested':return (sum(a*w for a,w in zip(arguments[1:],(3,5,7,11,13)))+(arguments[0]+1)*40+7)&MASK64
    return (sum(a*w for a,w in zip(arguments,(1,3,5,7,11,13)))+17+23+7)&MASK64


def build(directory=ROOT/'build/callback-bridge/fixtures'):
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=True);records={}
    for name in NAMES:
        imports=[('aotdemo.dll','NativeInvokeCallback',3)]
        if name=='import':imports+=[('aotdemo.dll','NativeSix',2)]
        _,slots,*_=make_idata(imports);source,labels=body(name,slots)
        asm=directory/(name+'.s');obj=directory/(name+'.obj');pe=directory/(name+'.exe');asm.write_text(source)
        command=['xcrun','clang','-target','x86_64-pc-windows-msvc','-c',str(asm),'-o',str(obj)]
        result=subprocess.run(command,capture_output=True,text=True)
        (directory/(name+'-compile.log')).write_text(json.dumps(command)+'\n'+result.stdout+result.stderr)
        if result.returncode:raise RuntimeError('callback fixture assembly failed: '+result.stderr)
        text,_=parse_coff(obj.read_bytes());offsets=coff_labels(obj.read_bytes(),set(labels))
        if set(offsets)!=set(labels) or offsets['guest_entry']!=0:raise ValueError('fixture labels missing')
        pe.write_bytes(pe_image(text,imports));rvas={k:TEXT_RVA+v for k,v in offsets.items()}
        records[name]={'name':name,'pe_path':str(pe),'pe_sha256':digest(pe),'text_hex':text.hex(),
            'text_sha256':hashlib.sha256(text).hexdigest(),'coff_relocations':0,'image_base':IMAGE_BASE,
            'entry_rva':TEXT_RVA,'callback_rva':rvas['guest_callback'],'callback_rvas':[rvas['guest_callback']],
            'callback_signature':1,'labels':rvas,'imports':list(slots.values()),
            'entry_parameters':['RCX','RDX','R8','R9','entry_RSP+40','entry_RSP+48'],
            'import_parameters':['RCX=callbackVA','RDX=a','R8=b','R9=c','callee_RSP+40=d','callee_RSP+48=e','callee_RSP+56=f'],
            'callback_parameters':['RCX=a','RDX=b','R8=c','R9=d','callback_RSP+40=e','callback_RSP+48=f'],
            'result':('u64(3*b+5*c+7*d+11*e+13*f+(a+1)*40+7)' if name=='nested' else 'u64(a+3*b+5*c+7*d+11*e+13*f+17+23+7)'),
            'api_calls':'a+1' if name=='nested' else (2 if name=='import' else 1),
            'callback_calls':'a+1' if name=='nested' else 1,'max_callback_depth':'a+1' if name=='nested' else 1,
            'source_sha256':{'callback_bridge/fixtures.py':digest(__file__),
                             'integration_stage3/call_fixtures.py':digest(ROOT/'integration_stage3/call_fixtures.py')}}
    (directory/'manifest.json').write_text(json.dumps(records,indent=2)+'\n');return records


if __name__=='__main__':print(json.dumps(build(),indent=2))
