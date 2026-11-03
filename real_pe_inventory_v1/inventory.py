"""Bounded, independent PE32+ metadata inventory using only the standard library."""
import hashlib
import os
from pathlib import Path
import stat
import struct

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_FILES = 1024
MAX_ENTRIES = 262144
MAX_STRING_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_TOTAL_ENTRIES = 1048576
MAX_TOTAL_STRING_BYTES = 32 * 1024 * 1024
NAMES = ('exports','imports','resources','exception','security','relocations','debug',
         'architecture','global_pointer','tls','load_config','bound_imports','iat','delay_imports','clr','reserved')
OS_NAMES = set('kernel32.dll kernelbase.dll ntdll.dll user32.dll gdi32.dll advapi32.dll shell32.dll ole32.dll oleaut32.dll comdlg32.dll comctl32.dll ws2_32.dll winmm.dll imm32.dll version.dll shlwapi.dll setupapi.dll crypt32.dll bcrypt.dll secur32.dll rpcrt4.dll d3d11.dll dxgi.dll d3d12.dll opengl32.dll glu32.dll dwmapi.dll winhttp.dll wininet.dll iphlpapi.dll'.split())
SCOPE = ('Static file metadata only. No PE execution, instruction discovery, Windows loader emulation, '
         'signature trust verification, dependency availability proof or AOT compatibility admission. '
         'A directory not declared in the file does not prove the corresponding runtime mechanism is absent.')


class InventoryError(ValueError):
    pass


def need(ok, message):
    if not ok:raise InventoryError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


class PE:
    def __init__(self,data,entry_limit=None,string_limit=None):
        need(type(data) is bytes and len(data)<=MAX_FILE,'input exceeds bounded byte inspection')
        self.data=data;self.entries=0;self.string_bytes=0;self.payload_bytes=0
        self.entry_limit=MAX_ENTRIES if entry_limit is None else min(MAX_ENTRIES,entry_limit)
        self.string_limit=MAX_STRING_BYTES if string_limit is None else min(MAX_STRING_BYTES,string_limit)
        need(data[:2]==b'MZ','missing DOS signature')
        pe=self.field('<I',0x3c)[0]
        need(pe>=64 and self.take(pe,4)==b'PE\0\0','missing/overlapping PE signature')
        machine,count,timestamp,symbols,symbol_count,optional_size,characteristics=self.field('<HHIIIHH',pe+4)
        need(machine==0x8664,'only AMD64 machine 0x8664 is inventoried')
        need(1<=count<=96,'section count outside 1..96')
        optional=pe+24;self.take(optional,optional_size)
        need(optional_size>=112 and self.field('<H',optional)[0]==0x20b,'requires complete PE32+ optional header')
        entry=self.field('<I',optional+16)[0];self.base=self.field('<Q',optional+24)[0]
        section_alignment,file_alignment=self.field('<II',optional+32)
        self.image_size,self.header_size=self.field('<II',optional+56)
        subsystem,dll_flags=self.field('<HH',optional+68)
        directory_count=self.field('<I',optional+108)[0]
        need(directory_count<=128 and 112+directory_count*8<=optional_size,'directory array exceeds optional header/bound')
        end=optional+optional_size+count*40
        need(end<=self.header_size<=len(data) and self.header_size<=self.image_size,'section table/header/image size inconsistent')
        need(self.base+self.image_size<=1<<64,'image virtual address overflow')
        self.headers=dict(machine=machine,format='PE32+',pe_offset=pe,section_count=count,
            timestamp=timestamp,coff_symbol_table_offset=symbols,coff_symbol_count=symbol_count,
            optional_header_size=optional_size,characteristics=characteristics,is_dll=bool(characteristics&0x2000),
            entry_rva=entry,image_base=self.base,image_size=self.image_size,headers_size=self.header_size,
            section_alignment=section_alignment,file_alignment=file_alignment,subsystem=subsystem,
            dll_characteristics=dll_flags,directory_count=directory_count)
        self.sections=[]
        for i in range(count):
            name,virtual_size,rva,raw_size,raw_offset,_,_,_,_,flags=self.field('<8sIIIIIIHHI',optional+optional_size+i*40)
            span=max(virtual_size,raw_size)
            need(rva+span<=self.image_size and (not span or rva>=self.header_size),'section virtual range outside image/overlaps headers')
            need(not raw_size or self.header_size<=raw_offset<=len(data)-raw_size,'section raw range outside file/overlaps headers')
            for other in self.sections:
                need(not span or not other['mapped_span'] or rva+span<=other['rva'] or other['rva']+other['mapped_span']<=rva,
                     'ambiguous overlapping virtual sections')
                need(not raw_size or not other['raw_size'] or raw_offset+raw_size<=other['raw_offset'] or other['raw_offset']+other['raw_size']<=raw_offset,
                     'ambiguous overlapping raw sections')
            self.sections.append(dict(name=name.rstrip(b'\0').decode('ascii','backslashreplace'),rva=rva,
                virtual_size=virtual_size,raw_size=raw_size,raw_offset=raw_offset,mapped_span=span,
                characteristics=flags,readable=bool(flags&0x40000000),writable=bool(flags&0x80000000),executable=bool(flags&0x20000000)))
        if entry:self.mapped(entry,1)
        self.directories=[]
        for i in range(max(16,directory_count)):
            address,size=self.field('<II',optional+112+8*i) if i<directory_count else (0,0)
            self.directories.append(dict(index=i,name=NAMES[i] if i<16 else 'unknown_'+str(i),
                declared=i<directory_count,address=address,size=size,address_kind='file_offset' if i==4 else 'rva',
                presence='declared_nonzero' if address or size else 'not_declared',
                parse_status='pending' if address or size else 'not_declared'))

    def file_range(self,offset,size):
        need(type(offset) is int and type(size) is int and offset>=0 and size>=0 and offset<=len(self.data)-size,'truncated/out-of-file byte range')

    def take(self,offset,size):
        self.file_range(offset,size);return self.data[offset:offset+size]

    def field(self,fmt,offset):return struct.unpack(fmt,self.take(offset,struct.calcsize(fmt)))

    def mapped(self,rva,size):
        need(0<=rva<=0xffffffff and size>=0 and rva+size<=self.image_size,'RVA range outside image')
        if rva<self.header_size and rva+size<=self.header_size:return None
        candidates=[s for s in self.sections if s['rva']<=rva and rva+size<=s['rva']+s['mapped_span']]
        need(len(candidates)==1,'RVA is not uniquely mapped')
        return candidates[0]

    def offset(self,rva,size):
        section=self.mapped(rva,size)
        if section is None:return rva
        delta=rva-section['rva'];need(delta+size<=section['raw_size'],'metadata RVA is virtual-only, not file-backed')
        return section['raw_offset']+delta

    def read(self,rva,size):return self.take(self.offset(rva,size),size)
    def rfield(self,fmt,rva):return struct.unpack(fmt,self.read(rva,struct.calcsize(fmt)))

    def va_rva(self,value):
        need(self.base<=value<self.base+self.image_size,'VA does not point into this image')
        return value-self.base

    def string(self,rva,limit=4096):
        need(rva!=0,'null string RVA')
        out=bytearray()
        for i in range(limit):
            value=self.read(rva+i,1)[0]
            if value==0:
                need(bool(out),'empty metadata string');self.charge_string(len(out))
                try:return out.decode('ascii')
                except UnicodeError:raise InventoryError('non-ASCII metadata name')
            need(32<=value<=126,'control/non-ASCII byte in metadata name')
            need(self.string_bytes+len(out)+1<=self.string_limit,'cumulative metadata string byte bound exceeded')
            out.append(value)
        raise InventoryError('metadata string exceeds inspection bound or lacks terminator')

    def count(self,n=1):
        need(0<=n<=self.entry_limit-self.entries,'metadata entry inspection bound exceeded');self.entries+=n

    def charge_string(self,n):
        need(0<=n<=self.string_limit-self.string_bytes,'cumulative metadata string byte bound exceeded');self.string_bytes+=n

    def payload(self,offset,size):
        need(0<=size<=MAX_PAYLOAD_BYTES-self.payload_bytes,'opaque metadata payload byte bound exceeded')
        self.payload_bytes+=size;return self.take(offset,size)

    def thunks(self,lookup,iat,bound_without_lookup=False):
        need(iat!=0,'null IAT RVA');self.mapped(iat,8)
        if bound_without_lookup:return dict(status='unparsed',reason='bound IAT has no original lookup table',symbols=[])
        symbols=[]
        for i in range(MAX_ENTRIES):
            self.count();value=self.rfield('<Q',lookup+8*i)[0];self.mapped(iat+8*i,8)
            if not value:return dict(status='parsed',symbols=symbols)
            if value>>63:
                need(value&0x7fffffffffff0000==0,'invalid ordinal thunk bits')
                symbols.append(dict(name=None,ordinal=value&0xffff,hint=None,iat_rva=iat+8*i))
            else:
                need(value<=0xffffffff,'named import thunk is not an RVA')
                hint=self.rfield('<H',value)[0]
                symbols.append(dict(name=self.string(value+2),ordinal=None,hint=hint,iat_rva=iat+8*i))
        raise InventoryError('import thunk terminator not found within bound')

    def imports(self,d,delay=False):
        width=32 if delay else 20;need(d['size']>=width,'truncated import descriptor array')
        descriptors=[];partial=False
        for i in range(d['size']//width):
            self.count();values=self.rfield('<8I' if delay else '<5I',d['address']+i*width)
            if not any(values):return dict(descriptors=descriptors),('partial' if partial else 'parsed')
            if delay:
                attributes,name,module,iat,lookup,bound,unload,timestamp=values
                if attributes&~1:
                    descriptors.append(dict(attributes=attributes,raw_fields=list(values),status='unparsed',reason='unknown delay-import attributes'))
                    partial=True;continue
                if not attributes&1:
                    def convert(v):return self.va_rva(v) if v else 0
                    name,module,iat,lookup,bound,unload=map(convert,(name,module,iat,lookup,bound,unload))
                extra=dict(attributes=attributes,address_encoding='rva' if attributes&1 else 'legacy_va',
                    module_handle_rva=module,bound_iat_rva=bound,unload_iat_rva=unload)
            else:
                lookup,timestamp,forwarder,name,iat=values;extra=dict(forwarder_chain=forwarder)
            if delay:
                if module:self.mapped(module,8)
                for pointer in (bound,unload):
                    if pointer:self.mapped(pointer,8)
            table=(dict(status='unparsed',reason='legacy VA delay thunk encoding not decoded',symbols=[])
                   if delay and not attributes&1 else self.thunks(lookup or iat,iat,not lookup and bool(timestamp)))
            if delay and (bound or unload):
                length=8*(len(table['symbols'])+1)
                for pointer in (bound,unload):
                    if pointer:self.mapped(pointer,length)
                table.update(status='partial',unparsed_tables=[name for name,pointer in [('bound_iat',bound),('unload_iat',unload)] if pointer])
            partial|=table['status']!='parsed'
            descriptors.append(dict(dll=self.string(name),kind='delay' if delay else 'normal',
                descriptor_rva=d['address']+i*width,lookup_rva=lookup,iat_rva=iat,timestamp=timestamp,**extra,**table))
        raise InventoryError('import descriptor terminator missing inside declared directory')

    def relocations(self,d):
        offset=0;blocks=[];types={};partial=False
        while offset<d['size']:
            need(d['size']-offset>=8,'truncated relocation block header')
            page,size=self.rfield('<II',d['address']+offset)
            need(size>=8 and size%2==0 and size<=d['size']-offset,'invalid relocation block size')
            need(page%4096==0,'unaligned relocation page RVA')
            self.count();word_count=(size-8)//2;self.count(word_count);entries=[]
            i=0
            while i<word_count:
                word=self.rfield('<H',d['address']+offset+8+2*i)[0];kind=word>>12;target=page+(word&0xfff)
                entry=dict(type=kind,rva=target);types[str(kind)]=types.get(str(kind),0)+1
                if kind==10:self.mapped(target,8)
                elif kind!=0:
                    partial=True;entry['semantics']='unparsed_for_amd64'
                    if kind==4:
                        need(i+1<word_count,'HIGHADJ relocation lacks paired word')
                        i+=1;entry['paired_word']=self.rfield('<H',d['address']+offset+8+2*i)[0]
                entries.append(entry);i+=1
            blocks.append(dict(page_rva=page,size=size,entries=entries));offset+=size
        return dict(blocks=blocks,type_counts=types),('partial' if partial else 'parsed')

    def exceptions(self,d):
        need(d['size']%12==0,'runtime-function directory size is not a multiple of 12')
        functions=[];unwind={};previous_end=0;notes=set()
        for offset in range(0,d['size'],12):
            self.count();begin,end,info=self.rfield('<III',d['address']+offset)
            need(begin<=end,'reversed runtime-function range')
            self.mapped(begin,max(1,end-begin))
            item=dict(begin_rva=begin,end_rva=end,unwind_rva=info)
            if begin==end:
                item['range_status']='empty_range_unparsed';notes.add('empty_runtime_function_range_not_interpreted')
            if begin<previous_end:notes.add('overlapping_or_unsorted_runtime_function_ranges')
            previous_end=end;functions.append(item)
            if str(info) in unwind:continue
            if not info or info&3:
                unwind[str(info)]=dict(status='unparsed',reason='null or encoded/unaligned unwind address');notes.add('encoded_unwind');continue
            version_flags,prolog,count,frame=self.rfield('<4B',info);self.count(count)
            version=version_flags&7;flags=version_flags>>3
            raw=self.read(info+4,count*2);tail=info+4+((count+1)&~1)*2
            value=dict(version=version,flags=flags,prolog_size=prolog,code_slots=count,
                frame_register=frame&15,frame_offset=(frame>>4)*16,raw_codes_hex=raw.hex(),
                status='header_and_code_bytes_only',operations_status='unparsed')
            if version!=1 or flags&~7:
                value['tail_status']='unparsed_unknown_version_or_flags';notes.add('unknown_unwind_version_or_flags')
            elif flags&4:
                if flags&3:value['tail_status']='unparsed_conflicting_handler_chain_flags'
                else:value['chained_runtime_function']=list(self.rfield('<III',tail));value['tail_status']='chain_semantics_unparsed'
                notes.add('chained_unwind_semantics')
            elif flags&3:
                value['handler_rva']=self.rfield('<I',tail)[0]
                value['handler_data_rva']=tail+4;value['tail_status']='language_specific_handler_data_unparsed'
                notes.add('language_specific_handler_data')
            else:value['tail_status']='no_handler_or_chain_declared'
            unwind[str(info)]=value
        notes.add('unwind_operation_semantics_not_decoded')
        return dict(runtime_functions=functions,unwind_records=unwind,unparsed=sorted(notes)),'partial'

    def tls(self,d):
        need(d['size']>=40,'truncated PE32+ TLS directory')
        start,end,index,callbacks,zero,flags=self.rfield('<4Q2I',d['address'])
        need(end>=start and bool(start)==bool(end),'inconsistent TLS template VA range')
        value=dict(raw_start_va=start,raw_end_va=end,index_va=index,callbacks_va=callbacks,
                   zero_fill=zero,characteristics=flags,callbacks=[])
        if start:
            rva=self.va_rva(start);self.mapped(rva,end-start)
            value['raw_template_rva']=rva;value['raw_template_size']=end-start
        if index:self.mapped(self.va_rva(index),4)
        partial=False
        if callbacks:
            rva=self.va_rva(callbacks)
            for i in range(4096):
                self.count();address=self.rfield('<Q',rva+i*8)[0]
                if not address:break
                item=dict(va=address)
                if self.base<=address<self.base+self.image_size:
                    item['rva']=self.va_rva(address);self.mapped(item['rva'],1)
                else:item['address_status']='outside_this_image_unparsed';partial=True
                value['callbacks'].append(item)
            else:raise InventoryError('TLS callback table lacks terminator within bound')
        value['semantic_scope']='Declared static TLS metadata only; TEB, initialization order and dynamic TLS APIs not analyzed'
        return value,('partial' if partial else 'parsed')

    def load_config(self,d):
        need(d['size']>=4,'truncated load-config Size')
        declared=self.rfield('<I',d['address'])[0];need(declared>=4,'invalid load-config Size')
        available=min(declared,d['size']);fields={}
        specs=[('timestamp',4,'I'),('major_version',8,'H'),('minor_version',10,'H'),
            ('global_flags_clear',12,'I'),('global_flags_set',16,'I'),('security_cookie_va',88,'Q'),
            ('seh_table_va',96,'Q'),('seh_count',104,'Q'),('guard_cf_check_va',112,'Q'),
            ('guard_cf_dispatch_va',120,'Q'),('guard_cf_table_va',128,'Q'),('guard_cf_count',136,'Q'),
            ('guard_flags',144,'I'),('dynamic_value_reloc_table_va',192,'Q'),('chpe_metadata_va',200,'Q'),
            ('guard_eh_continuation_table_va',264,'Q'),('guard_eh_continuation_count',272,'Q')]
        for name,offset,fmt in specs:
            if offset+struct.calcsize(fmt)<=available:fields[name]=self.rfield('<'+fmt,d['address']+offset)[0]
        notes=['load_config_tables_and_version_specific_semantics_not_parsed']
        if declared>d['size']:notes.append('structure_size_exceeds_directory_size')
        if declared>320:notes.append('unknown_extended_load_config_tail')
        return dict(structure_size=declared,directory_size=d['size'],known_prefix_fields=fields,unparsed=notes),'partial'

    def security(self,d):
        need(d['address']%8==0,'certificate file offset is not 8-byte aligned')
        self.file_range(d['address'],d['size']);start=d['address'];end=start+d['size']
        need(start>=self.header_size,'certificate table overlaps headers')
        need(all(not s['raw_size'] or end<=s['raw_offset'] or s['raw_offset']+s['raw_size']<=start for s in self.sections),
             'certificate file range overlaps mapped section data')
        records=[];offset=0
        while offset<d['size']:
            self.count();need(d['size']-offset>=8,'truncated WIN_CERTIFICATE header')
            length,revision,kind=self.field('<IHH',start+offset)
            need(8<=length<=d['size']-offset,'WIN_CERTIFICATE length exceeds directory')
            records.append(dict(file_offset=start+offset,length=length,revision=revision,type=kind,
                payload_sha256=sha(self.payload(start+offset+8,length-8))))
            aligned=(length+7)&~7;need(aligned<=d['size']-offset,'truncated certificate alignment padding');offset+=aligned
        return dict(certificates=records,signature_validation='not_performed'),'parsed'

    def debug(self,d):
        need(d['size']%28==0,'debug directory size is not a multiple of 28')
        records=[];partial=False
        for offset in range(0,d['size'],28):
            self.count();flags,timestamp,major,minor,kind,size,rva,pointer=self.rfield('<IIHHIIII',d['address']+offset)
            value=dict(characteristics=flags,timestamp=timestamp,major=major,minor=minor,type=kind,
                size=size,data_rva=rva,data_file_offset=pointer)
            raw=self.payload(pointer,size) if size else b''
            if rva and size:need(self.offset(rva,size)==pointer,'debug RVA/file offset disagreement')
            value['data_sha256']=sha(raw)
            if kind==2 and raw[:4]==b'RSDS':
                need(len(raw)>=25 and b'\0' in raw[24:],'truncated RSDS CodeView record')
                pdb=raw[24:].split(b'\0',1)[0];self.charge_string(len(pdb))
                value['codeview']=dict(format='RSDS',guid_hex=raw[4:20].hex(),age=struct.unpack('<I',raw[20:24])[0],
                    pdb_path=pdb.decode('utf-8','backslashreplace'),pdb_followed=False)
            else:value['payload_status']='unparsed_debug_type_or_format';partial=True
            records.append(value)
        return dict(records=records),('partial' if partial else 'parsed')

    def analyze(self):
        findings=[];imports=[]
        parsers={1:lambda d:self.imports(d),3:self.exceptions,4:self.security,5:self.relocations,
                 6:self.debug,9:self.tls,10:self.load_config,13:lambda d:self.imports(d,True)}
        for d in self.directories:
            if d['parse_status']=='not_declared':continue
            try:
                need(d['address']!=0,'nonzero directory size with zero address')
                if d['index']==4:self.file_range(d['address'],d['size'])
                elif d['size']:self.offset(d['address'],d['size'])
                else:self.mapped(d['address'],1)
                if d['index'] in parsers:d['detail'],d['parse_status']=parsers[d['index']](d)
                else:d['parse_status']='unparsed';d['reason']='presence and bounded storage only; payload parser not implemented'
            except InventoryError as error:
                d['parse_status']='invalid';d['error']=str(error)
            if d['parse_status'] in ('invalid','partial','unparsed'):
                findings.append(dict(code='DIRECTORY_'+d['parse_status'].upper(),severity='error' if d['parse_status']=='invalid' else 'analysis_gap',
                    directory=d['name'],message=d.get('error',d.get('reason','some metadata semantics remain unparsed'))))
            if d['index'] in (1,13):imports.extend(d.get('detail',{}).get('descriptors',[]))
        for s in self.sections:
            if s['writable'] and s['executable']:findings.append(dict(code='WRITABLE_EXECUTABLE_SECTION',severity='observed_requirement',section=s['name'],message='W+X declaration observed; no dynamic-code behavior inferred'))
        return dict(headers=self.headers,sections=self.sections,directories=self.directories,imports=imports,findings=findings,
            metadata_complete=not any(d['parse_status'] in ('invalid','partial','unparsed') for d in self.directories),
            inspection_usage=dict(metadata_entries=self.entries,string_bytes=self.string_bytes,opaque_payload_bytes=self.payload_bytes),
            dynamic_behavior='not_analyzed',migration_admission='not_performed',guest_executions=0)


def analyze_bytes(data,name='input.exe',entry_limit=None,string_limit=None):
    result=dict(path=name,sha256=sha(data),bytes=len(data),status='REJECTED',findings=[],metadata_complete=False)
    try:
        result.update(PE(data,entry_limit,string_limit).analyze());result['status']='INVENTORIED' if result['metadata_complete'] else 'INCOMPLETE'
    except InventoryError as error:result['findings']=[dict(code='PE_REJECTED',severity='error',message=str(error))]
    return result


def read_input(path):
    path=Path(path).absolute();need(path==path.resolve(),'symlink/noncanonical input path rejected')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|getattr(os,'O_NOFOLLOW',0))
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode),'input must be a regular file')
        need(before.st_size<=MAX_FILE,'input exceeds 256 MiB inspection bound')
        stream=os.fdopen(fd,'rb');fd=None
        with stream:
            data=stream.read(MAX_FILE+1);after=os.fstat(stream.fileno())
    finally:
        if fd is not None:os.close(fd)
    current=path.stat(follow_symlinks=False)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)
    need(identity(before)==identity(after)==identity(current) and len(data)==before.st_size,'input changed while reading')
    return data


def inventory_path(path):
    path=Path(path).absolute();need(path==path.resolve(),'canonical input path required')
    paths=[];root=path.parent if path.is_file() else path
    if path.is_file():paths=[path]
    else:
        need(path.is_dir(),'input is not a file or directory')
        def walk_error(error):raise InventoryError(str(error))
        for directory,dirs,files in os.walk(path,followlinks=False,onerror=walk_error):
            dirs.sort();files.sort()
            for name in list(dirs):
                if (Path(directory)/name).is_symlink():raise InventoryError('symlink directory in inventory tree')
            paths.extend(Path(directory)/n for n in files if Path(n).suffix.lower() in ('.exe','.dll'))
            need(len(paths)<=MAX_FILES,'more than 1024 PE candidates')
    paths.sort(key=lambda p:p.relative_to(root).as_posix());need(paths,'no .exe/.dll candidates found')
    reports=[];total=0;total_entries=0;total_strings=0
    for p in paths:
        name=p.relative_to(root).as_posix()
        try:
            need(total+p.lstat().st_size<=MAX_TOTAL,'total inspection bytes exceed 1 GiB')
            data=read_input(p);total+=len(data)
            record=analyze_bytes(data,name,MAX_TOTAL_ENTRIES-total_entries,MAX_TOTAL_STRING_BYTES-total_strings)
            usage=record.get('inspection_usage',{});total_entries+=usage.get('metadata_entries',0);total_strings+=usage.get('string_bytes',0)
            reports.append(record)
        except (InventoryError,OSError) as error:
            reports.append(dict(path=name,status='REJECTED',sha256=None,bytes=None,metadata_complete=False,
                findings=[dict(code='INPUT_REJECTED',severity='error',message=str(error))]))
    candidates={}
    for item in reports:candidates.setdefault(Path(item['path']).name.casefold(),[]).append(item['path'])
    edges=[]
    for item in reports:
        for imp in item.get('imports',[]):
            if 'dll' not in imp:continue
            name=imp['dll'].replace('\\','/').split('/')[-1].casefold();matches=candidates.get(name,[])
            hint='api_set_contract_name' if name.startswith(('api-ms-win-','ext-ms-win-')) else 'windows_os_dll_name' if name in OS_NAMES else 'unclassified'
            edges.append(dict(source=item['path'],dll=imp['dll'],import_kind=imp['kind'],name_classification_hint=hint,
                candidates=matches,match_status='unique_basename_candidate' if len(matches)==1 else 'ambiguous_basename_candidates' if matches else 'not_in_inventory',
                loader_resolution='not_performed',missing_dependency_claim=False))
    edges.sort(key=lambda e:(e['source'],e['import_kind'],e['dll']))
    return dict(schema=1,tool='real-pe-inventory-v1',status='INVENTORIED' if all(x['metadata_complete'] for x in reports) else 'INCOMPLETE',
        scope=SCOPE,input_kind='file' if path.is_file() else 'directory',files=reports,dependency_edges=edges,
        summary=dict(files=len(reports),bytes_read=total,rejected=sum(x['status']=='REJECTED' for x in reports),
                     incomplete=sum(x['status']=='INCOMPLETE' for x in reports)),guest_executions=0)


def markdown(report):
    lines=['# Windows x64 PE 静态库存','',f"状态：`{report['status']}`。文件数：{report['summary']['files']}。未执行 PE，未进行迁移准入。",'',
        '未声明目录不证明相关运行机制不存在；目录局部损坏或未解析会保留为 INCOMPLETE。DLL 名称匹配不是 Windows loader 解析，未在库存发现不等于缺失系统 DLL。','',
        '| 文件 | SHA256 | 状态 | 静态导入符号数 |','|---|---|---|---|']
    def safe(s):return str(s).replace('|','\\|').replace('\n',' ')
    for item in report['files']:
        count=sum(len(i.get('symbols',[])) for i in item.get('imports',[]))
        lines.append(f"| {safe(item['path'])} | {item['sha256'] or '读取失败'} | {item['status']} | {count} |")
    lines+=['','## 待解决／未解析清单','']
    for item in report['files']:
        for finding in item['findings']:lines.append('- '+safe(item['path'])+': `'+finding['code']+'` '+safe(finding.get('directory',''))+' '+safe(finding['message']))
    lines+=['','这些记录是元数据事实或分析缺口，不是已证实的运行故障、完整指令覆盖率或性能判断。','']
    return '\n'.join(lines)
