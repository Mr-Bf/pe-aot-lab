#!/usr/bin/env python3
"""Narrow, fail-closed research PE32+ -> C CFG -> ARM64 Mach-O translator.
Not a general x86 lifter or a Windows loader. No guest instruction dispatch loop.
"""
import argparse, json, pathlib, struct, subprocess, plistlib, hashlib

class Unsupported(ValueError):
    pass

def unpack(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise Unsupported('truncated binary')
    return struct.unpack_from(fmt, data, offset)

class PE:
    def __init__(self, data):
        self.data = data
        if data[:2] != b'MZ': raise Unsupported('missing DOS magic')
        pe, = unpack('<I', data, 0x3c)
        if data[pe:pe+4] != b'PE\0\0': raise Unsupported('missing PE magic')
        machine,nsec,_,_,_,optsize,flags = unpack('<HHIIIHH', data, pe+4)
        if machine != 0x8664 or nsec not in range(1,97): raise Unsupported('requires AMD64 PE')
        opt = pe+24
        if optsize != 240 or unpack('<H',data,opt)[0] != 0x20b:
            raise Unsupported('requires 240-byte PE32+ optional header')
        self.entry, = unpack('<I',data,opt+16)
        self.base, = unpack('<Q',data,opt+24)
        ndir, = unpack('<I',data,opt+108)
        if ndir != 16: raise Unsupported('requires 16 data directories')
        self.dirs = [unpack('<II',data,opt+112+i*8) for i in range(16)]
        # This prototype handles only an import directory and IAT.
        for i,(rva,size) in enumerate(self.dirs):
            if (rva or size) and i not in (1,12):
                raise Unsupported('unsupported PE data directory %d (TLS/SEH/reloc/etc.)' % i)
        self.sections=[]
        for i in range(nsec):
            s=opt+optsize+i*40
            name,vs,va,rs,rp,_,_,_,_,ch=unpack('<8sIIIIIIHHI',data,s)
            if rp+rs>len(data): raise Unsupported('section exceeds file')
            if ch & 0x20000000 and ch & 0x80000000: raise Unsupported('writable executable section')
            if any(max(va,t['rva'])<min(va+max(vs,rs),t['rva']+max(t['size'],t['rawsize'])) for t in self.sections):
                raise Unsupported('overlapping sections')
            self.sections.append(dict(name=name.rstrip(b'\0').decode('ascii'),rva=va,size=vs,rawsize=rs,raw=rp,flags=ch))
        self.imports={}
        rva,size=self.dirs[1]
        if rva:
            if size<40 or size>4096: raise Unsupported('invalid import directory size')
            terminated=False
            for d in range(0,size-19,20):
                ilt,stamp,chain,name,iat=unpack('<IIIII',self.read(rva+d,20),0)
                if not any((ilt,stamp,chain,name,iat)):
                    terminated=True; break
                if not ilt or not iat: raise Unsupported('missing import thunks')
                if stamp or chain: raise Unsupported('bound/chained imports unsupported')
                dll=self.cstring(name).lower()
                for j in range(1024):
                    target,=unpack('<Q',self.read(ilt+j*8,8),0)
                    slot=iat+j*8
                    iat_rva,iat_size=self.dirs[12]
                    if not (iat_rva<=slot and slot+8<=iat_rva+iat_size):
                        raise Unsupported('IAT slot outside declared IAT directory')
                    slot_value,=unpack('<Q',self.read(slot,8),0)
                    if slot_value!=target: raise Unsupported('requires unbound IAT matching ILT')
                    if not target: break
                    if target & (1<<63): raise Unsupported('ordinal import')
                    symbol=self.cstring(target+2)
                    if (dll,symbol)!=('kernel32.dll','GetCurrentProcessId'):
                        raise Unsupported('unsupported import '+dll+'!'+symbol)
                    self.imports[iat+j*8]=(dll,symbol)
                else: raise Unsupported('unterminated ILT')
            if not terminated: raise Unsupported('unterminated import directory')
        self.read(self.entry,1,execute=True)

    def read(self,rva,size,execute=False):
        for s in self.sections:
            offset=rva-s['rva']
            if offset>=0 and offset+size<=min(s['size'],s['rawsize']):
                if execute and not s['flags'] & 0x20000000: raise Unsupported('control flow outside executable section')
                return self.data[s['raw']+offset:s['raw']+offset+size]
        raise Unsupported('unmapped/file-unbacked RVA 0x%x size %d'%(rva,size))

    def cstring(self,rva):
        out=bytearray()
        for i in range(256):
            c=self.read(rva+i,1)[0]
            if c==0: return out.decode('ascii')
            out.append(c)
        raise Unsupported('unterminated string')

def decode(pe, pc):
    def b(n): return pe.read(pc,n,execute=True)
    op=b(1)[0]
    if op in (0xb8,0xb9,0xba):
        return (5,'movimm',(('eax','ecx','edx')[op-0xb8],unpack('<I',b(5),1)[0]))
    if b(1)==b'\xc3': return (1,'ret',())
    if op==0x0f: raise Unsupported('unsupported opcode 0f at RVA 0x%x'%pc)
    if op in (0x74,0x75,0xeb):
        rel,=unpack('<b',b(2),1)
        return (2,{0x74:'jz',0x75:'jnz',0xeb:'jmp'}[op],(pc+2+rel,))
    if op==0xe9: return (5,'jmp',(pc+5+unpack('<i',b(5),1)[0],))
    two=b(2)
    if b(1)==b'\x8d':
        three=b(3)
        if three==b'\x8d\x04\x11': return (3,'leasum',('eax','ecx','edx'))
        if three[:2]==b'\x8d\x41': return (3,'leaoffset',('eax','ecx',unpack('<b',three,2)[0]))
    if two==b'\x89\xc8': return (2,'copy',('eax','ecx'))
    if two==b'\x31\xd1': return (2,'xorreg',('ecx','edx'))
    if two==b'\x01\xd0': return (2,'addreg',('eax','edx'))
    if two==b'\x01\xc8': return (2,'addreg',('eax','ecx'))
    if two==b'\x29\xd0': return (2,'subreg',('eax','edx'))
    if two==b'\x9c\x58':
        if b(7)[2:]!=b'\x25\xd5\x08\x00\x00':
            raise Unsupported('PUSHFQ/POP only allowed with arithmetic flags mask')
        return (2,'flags',())
    if op==0x25: return (5,'andimm',('eax',unpack('<I',b(5),1)[0]))
    if two==b'\x31\xc0': return (2,'zero',('eax',))
    if two==b'\x85\xc9': return (2,'test',('ecx',))
    if two in (b'\x83\xe9',b'\x83\xc0'):
        imm,=unpack('<b',b(3),2)
        return (3,'subimm' if two[1]==0xe9 else 'addimm',('ecx' if two[1]==0xe9 else 'eax',imm))
    if two==b'\xff\x15':
        iat=pc+6+unpack('<i',b(6),2)[0]
        if iat not in pe.imports: raise Unsupported('indirect call outside supported IAT at RVA 0x%x'%pc)
        return (6,'import',(iat,))
    if op==0x48:
        four=b(4)
        if four[:3] in (b'\x48\x83\xec',b'\x48\x83\xc4'):
            imm,=unpack('<b',four,3)
            return (4,'stacksub' if four[2]==0xec else 'stackadd',(imm,))
    raise Unsupported('unsupported opcode %s at RVA 0x%x'%(two.hex(),pc))

def recover(pe):
    pending=[pe.entry]; ins={}; occupied={}
    while pending:
        pc=pending.pop()
        if pc in ins: continue
        if pc in occupied: raise Unsupported('branch into instruction at 0x%x'%pc)
        if len(ins)>10000: raise Unsupported('instruction budget exceeded')
        length,op,args=decode(pe,pc)
        for i in range(pc,pc+length):
            if i in occupied: raise Unsupported('overlapping instruction at 0x%x'%pc)
            occupied[i]=pc
        nexts=[] if op=='ret' else ([args[0]] if op=='jmp' else [pc+length])
        if op in ('jz','jnz'): nexts.append(args[0])
        ins[pc]=(length,op,args,nexts)
        pending.extend(nexts)
    # Definite flag initialization over the reachable CFG; imports kill flags.
    pred={pc:[] for pc in ins}
    for pc,(_,_,_,succ) in ins.items():
        for n in succ: pred[n].append(pc)
    valid={pc:True for pc in ins}; valid[pe.entry]=False
    changed=True
    writers={'addreg','subreg','andimm','xorreg','zero','test','subimm','addimm'}
    while changed:
        changed=False
        for pc,(_,op,_,_) in ins.items():
            incoming=False if pc==pe.entry else all(valid[p] for p in pred[pc])
            v=True if op in writers else False if op in ('import','stacksub','stackadd') else incoming
            if valid[pc]!=v: valid[pc]=v; changed=True
    for pc,(_,op,_,_) in ins.items():
        if op in ('jz','jnz') and (pc==pe.entry or not all(valid[p] for p in pred[pc])):
            raise Unsupported('branch consumes undefined ZF at 0x%x'%pc)
    # Full arithmetic-flag reads require all six flags to be modeled and defined.
    all_flags=0x8d5
    defined={pc:all_flags for pc in ins}
    changed=True
    while changed:
        changed=False
        for pc,(_,op,_,_) in ins.items():
            incoming=0 if pc==pe.entry else all_flags
            if pc!=pe.entry:
                for p in pred[pc]: incoming &= defined[p]
            if op in ('addreg','subreg','addimm','subimm'): mask=all_flags
            elif op in ('test','zero','andimm','xorreg'): mask=all_flags & ~0x10
            elif op in ('stacksub','stackadd'): mask=0
            elif op=='import': mask=0
            else: mask=incoming
            if mask!=defined[pc]: defined[pc]=mask; changed=True
    for pc,(_,op,_,_) in ins.items():
        if op=='flags':
            incoming=0 if pc==pe.entry else all_flags
            for p in pred[pc]: incoming &= defined[p]
            if incoming!=all_flags:
                raise Unsupported('PUSHFQ reads undefined/unmodeled flags at 0x%x'%pc)
    # Only ECX/EDX are input registers. Imported calls clobber both.
    bits={'eax':1,'ecx':2,'edx':4}
    regs={pc:7 for pc in ins}
    def reg_input(pc):
        mask=6 if pc==pe.entry else 7
        for p in pred[pc]: mask &= regs[p]
        return mask
    changed=True
    while changed:
        changed=False
        for pc,(_,op,args,_) in ins.items():
            mask=reg_input(pc)
            if op=='import': mask=1
            elif op=='flags': mask |= 1
            elif op in ('movimm','copy','zero','leasum','leaoffset','addreg','subreg','xorreg','andimm','subimm','addimm'):
                mask |= bits[args[0]]
            if mask!=regs[pc]:regs[pc]=mask;changed=True
    for pc,(_,op,args,_) in ins.items():
        reads=[]
        if op in ('copy','leaoffset'):reads=[args[1]]
        elif op=='leasum':reads=list(args[1:])
        elif op in ('addreg','subreg','xorreg'):reads=list(args)
        elif op in ('andimm','subimm','addimm','test'):reads=[args[0]]
        elif op=='ret':reads=['eax']
        for reg in reads:
            if not reg_input(pc)&bits[reg]:
                raise Unsupported('read of undefined/clobbered %s at 0x%x'%(reg,pc))
    # Abstract stack delta only: no guest stack memory exists in this prototype.
    pending=[(pe.entry,0)]; states=set()
    while pending:
        pc,delta=pending.pop()
        if (pc,delta) in states:continue
        states.add((pc,delta))
        if len(states)>10000:raise Unsupported('unbounded stack analysis')
        _,op,args,succ=ins[pc]
        if op=='stacksub':delta-=args[0]
        elif op=='stackadd':delta+=args[0]
        if not -65536<=delta<=0:raise Unsupported('stack delta outside supported range')
        if op=='import' and (delta>-40 or (8+delta)%16):
            raise Unsupported('Win64 call requires aligned stack and 32-byte shadow space')
        if op=='ret' and delta:raise Unsupported('stack not restored at return')
        pending.extend((n,delta) for n in succ)
    return ins

def lift(pe, ins):
    lines=['#include <stdint.h>','#include <stdlib.h>','#include <unistd.h>',
           '''static inline uint32_t arith_flags(uint32_t a,uint32_t b,int sub) {
 uint32_t r=sub?a-b:a+b;
 uint32_t cf=sub?(a<b):((uint64_t)a+(uint64_t)b>UINT32_MAX);
 uint32_t of=((sub?(a^b):~(a^b)) & (a^r))>>31;
 return cf | ((!__builtin_parity((unsigned char)r))<<2) | ((a^b^r)&16)
   | ((r==0)<<6) | ((r>>31)<<7) | (of<<11) | 2;
}''',
           '__attribute__((noinline)) uint32_t guest_entry(uint32_t a, uint32_t b) {',
           'uint32_t eax=0, ecx=a, edx=b; uint64_t rsp=0x100008; uint32_t rflags=0; int zf=0;',
           'goto L%x;'%pe.entry]
    for pc,(length,op,args,succ) in sorted(ins.items()):
        lines.append('L%x: ; /* guest RVA 0x%x %s */'%(pc,pc,op))
        if op=='movimm': lines.append('%s = UINT32_C(%d);'%args)
        elif op=='copy': lines.append('%s = %s;'%args)
        elif op=='leasum': lines.append('%s = %s + %s;'%args)
        elif op=='leaoffset': lines.append('%s = %s + (uint32_t)(int32_t)(%d);'%args)
        elif op=='xorreg': lines.append('%s ^= %s; zf=(%s==0);'%(args[0],args[1],args[0]))
        elif op=='zero': lines.append('%s=0; zf=1;'%args)
        elif op=='test': lines.append('zf=(%s==0);'%args)
        elif op in ('addreg','subreg'):
            lines.append('rflags=arith_flags(%s,%s,%d); %s %s= %s; zf=(%s==0);'%(args[0],args[1],int(op=='subreg'),args[0],'-' if op=='subreg' else '+',args[1],args[0]))
        elif op=='flags': lines.append('eax=rflags; /* restricted PUSHFQ; POP RAX, arithmetic flags only */')
        elif op=='andimm': lines.append('%s &= UINT32_C(%d); zf=(%s==0);'%(args[0],args[1],args[0]))
        elif op in ('subimm','addimm'):
            lines.append('rflags=arith_flags(%s,(uint32_t)(int32_t)(%d),%d);'%(args[0],args[1],int(op=='subimm')))
            lines.append('%s %s= (uint32_t)(int32_t)(%d); zf=(%s==0);'%(args[0],'-' if op=='subimm' else '+',args[1],args[0]))
        elif op in ('stacksub','stackadd'):
            lines.append('rsp %s= (uint64_t)(int64_t)(%d); zf=(rsp==0);'%('-' if op=='stacksub' else '+',args[0]))
        elif op=='import': lines.append('if ((rsp & 15)!=0) abort(); eax=(uint32_t)getpid(); /* no guest ABI call escapes */')
        elif op=='ret': lines.append('if (rsp!=0x100008) abort(); return eax;'); continue
        elif op in ('jz','jnz'):
            lines.append('if (%szf) goto L%x;'%('!' if op=='jnz' else '',args[0]))
        elif op=='jmp': lines.append('goto L%x;'%args[0]); continue
        else: raise AssertionError(op)
        lines.append('goto L%x;'%(pc+length))
    lines.append('}')
    return '\n'.join(lines)+'\n'

def translate(src,out):
    pe=PE(src.read_bytes()); ins=recover(pe); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(lift(pe,ins))
    manifest={'input_sha256':hashlib.sha256(pe.data).hexdigest(),'entry_rva':pe.entry,
              'image_base':pe.base,'instructions':sum(2 if v[1]=='flags' else 1 for v in ins.values()),'decoded_ops':len(ins),'imports':pe.imports,
              'coverage':'reachable subset only; not whole-image proof','runtime':'native C labels; no x86 interpreter/JIT/Rosetta',
              'cfg':{hex(pc):{'op':v[1],'successors':[hex(s) for s in v[3]]} for pc,v in sorted(ins.items())}}
    out.with_suffix('.json').write_text(json.dumps(manifest,indent=2))
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('input',type=pathlib.Path);p.add_argument('output',type=pathlib.Path)
    a=p.parse_args()
    try: print(json.dumps(translate(a.input,a.output),indent=2))
    except (Unsupported,UnicodeError,struct.error) as e: p.exit(2,'REJECT: '+str(e)+'\n')
