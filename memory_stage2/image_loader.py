#!/usr/bin/env python3
"""Restricted PE32+ data-image loader: sections/BSS, 4KiB permissions, DIR64.
No Windows process startup, imports, TLS, SEH, or host executable mappings.
"""
import pathlib,struct,hashlib,json,dataclasses
PAGE=4096;READ=1;WRITE=2;EXEC=4;MAX_U64=0xffffffffffffffff
class ImageError(ValueError):pass

def read_struct(fmt,data,offset):
 size=struct.calcsize(fmt)
 if offset<0 or offset+size>len(data):raise ImageError('truncated field')
 return struct.unpack_from(fmt,data,offset)

@dataclasses.dataclass
class LoadedImage:
 base:int
 preferred_base:int
 entry_rva:int
 data:bytearray
 permissions:list
 sections:list
 relocations:list
 source_sha256:str

 def offset(self,address,size,access=READ):
  if address<0 or address>MAX_U64 or size<0 or size>MAX_U64-address:raise ImageError('invalid address or size')
  offset=address-self.base
  if offset<0 or offset>len(self.data) or size>len(self.data)-offset:raise ImageError('address outside image')
  if size:
   for page in range(offset//PAGE,(offset+size-1)//PAGE+1):
    if self.permissions[page]&access != access:raise ImageError('guest page permission denied')
  return offset
 def read(self,address,size):
  offset=self.offset(address,size);return bytes(self.data[offset:offset+size])
 def write(self,address,value):
  offset=self.offset(address,len(value),WRITE);self.data[offset:offset+len(value)]=value
 def manifest(self):
  return {'base':self.base,'preferred_base':self.preferred_base,'entry_rva':self.entry_rva,'size':len(self.data),'source_sha256':self.source_sha256,'sections':self.sections,'relocations':self.relocations,'permissions':self.permissions,'scope':'data image only; no Windows initialization or native executable mapping'}

def load_image(source,load_base=None):
 data=source.read_bytes() if isinstance(source,pathlib.Path) else bytes(source)
 if data[:2]!=b'MZ':raise ImageError('missing DOS header')
 pe,=read_struct('<I',data,0x3c)
 if data[pe:pe+4]!=b'PE\0\0':raise ImageError('missing PE signature')
 machine,nsec,_,_,_,optsize,characteristics=read_struct('<HHIIIHH',data,pe+4)
 if machine!=0x8664 or not 1<=nsec<=96 or not characteristics&0x2 or characteristics&0x2000:raise ImageError('requires AMD64 executable profile')
 opt=pe+24
 if optsize!=240 or read_struct('<H',data,opt)[0]!=0x20b:raise ImageError('requires PE32+ optional header')
 entry,=read_struct('<I',data,opt+16);preferred,=read_struct('<Q',data,opt+24)
 section_alignment,file_alignment=read_struct('<II',data,opt+32)
 image_size,headers_size=read_struct('<II',data,opt+56)
 if section_alignment!=PAGE or file_alignment!=512:raise ImageError('requires 4096/512 section/file alignment')
 if not 0<image_size<=64*1024*1024 or image_size%PAGE:raise ImageError('unsupported image size')
 section_table_end=opt+optsize+nsec*40
 if not section_table_end<=headers_size<=min(image_size,len(data)) or headers_size%512:raise ImageError('invalid headers size')
 if read_struct('<I',data,opt+108)[0]!=16:raise ImageError('requires 16 directories')
 dirs=[read_struct('<II',data,opt+112+i*8) for i in range(16)]
 for i,(rva,size) in enumerate(dirs):
  if bool(rva)!=bool(size):raise ImageError('incomplete directory')
  if (rva or size) and i!=5:raise ImageError('unsupported directory %d'%i)
 base=preferred if load_base is None else load_base
 # Store exclusive ends as uint64 values too; do not admit an end at 2**64.
 if base<0 or base&0xffff or preferred&0xffff or base>MAX_U64-image_size or preferred>MAX_U64-image_size:raise ImageError('invalid image base')
 image=bytearray(image_size);image[:headers_size]=data[:headers_size]
 perms=[0]*(image_size//PAGE);sections=[];ranges=[(0,(headers_size+PAGE-1)//PAGE*PAGE)]
 for p in range((headers_size+PAGE-1)//PAGE):perms[p]=READ
 for i in range(nsec):
  name,virtual_size,rva,raw_size,raw_offset,_,_,_,_,flags=read_struct('<8sIIIIIIHHI',data,opt+optsize+40*i)
  span=max(virtual_size,raw_size)
  if rva%PAGE or rva<ranges[0][1] or span==0 or rva+span>image_size:raise ImageError('invalid section extent')
  if raw_size and (raw_offset%512 or raw_size%512 or raw_offset<headers_size or raw_offset+raw_size>len(data)):raise ImageError('invalid raw section')
  if any(max(rva,start)<min(rva+span,end) for start,end in ranges):raise ImageError('overlapping sections')
  ranges.append((rva,rva+span));image[rva:rva+raw_size]=data[raw_offset:raw_offset+raw_size]
  access=(READ if flags&0x40000000 else 0)|(WRITE if flags&0x80000000 else 0)|(EXEC if flags&0x20000000 else 0)
  if access&WRITE and access&EXEC:raise ImageError('writable executable section unsupported')
  for page in range(rva//PAGE,(rva+span-1)//PAGE+1):perms[page]=access
  try:section_name=name.rstrip(b'\0').decode('ascii')
  except UnicodeError:raise ImageError('non-ASCII section name')
  sections.append({'name':section_name,'rva':rva,'virtual_size':virtual_size,'raw_size':raw_size,'permissions':access})
 if entry>=image_size or not perms[entry//PAGE]&EXEC:raise ImageError('entry is not executable')
 loaded=LoadedImage(base,preferred,entry,image,perms,sections,[],hashlib.sha256(data).hexdigest())
 reloc_rva,reloc_size=dirs[5]
 if base!=preferred and (not reloc_size or characteristics&1):raise ImageError('image cannot be rebased without relocations')
 if reloc_size:
  # Directory must be wholly readable; no host code is modified.
  directory=loaded.read(base+reloc_rva,reloc_size)
  pos=0;end=reloc_size;seen=set();fixups=[]
  while pos<end:
   if end-pos<8:raise ImageError('truncated relocation block')
   page,block_size=read_struct('<II',directory,pos)
   if page%PAGE or block_size<8 or block_size%4 or block_size>end-pos:raise ImageError('invalid relocation block')
   for off in range(pos+8,pos+block_size,2):
    encoded,=read_struct('<H',directory,off);kind=encoded>>12;target=page+(encoded&4095)
    if kind==0:continue
    if kind!=10:raise ImageError('unsupported base relocation type %d'%kind)
    if target in seen:raise ImageError('duplicate relocation target')
    seen.add(target);loaded.read(base+target,8)
    if max(target,reloc_rva)<min(target+8,reloc_rva+reloc_size):raise ImageError('relocation modifies relocation directory')
    old,=read_struct('<Q',image,target);new=(old+base-preferred)&MAX_U64
    fixups.append({'rva':target,'old':old,'new':new})
   pos+=block_size
  # Validate all byte intervals before mutating the image. Distinct starting
  # addresses do not make overlapping eight-byte DIR64 patches independent.
  ordered=sorted(fixups,key=lambda item:item['rva'])
  for left,right in zip(ordered,ordered[1:]):
   if left['rva']+8>right['rva']:raise ImageError('overlapping relocation targets')
  for fixup in fixups:
   struct.pack_into('<Q',image,fixup['rva'],fixup['new'])
  loaded.relocations=fixups
 return loaded
