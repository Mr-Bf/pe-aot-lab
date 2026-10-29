#!/usr/bin/env python3
"""Ordinary LLVM C/COFF/LLD no-argument Windows process fixtures, not host frames."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;WORK=ROOT.parent.parent/'work'
LLVM=WORK/'remill-stage2/llvm@17/17.0.6';LINKER=WORK/'file-bridge/tools/lld-link'
sys.path.insert(0,str(ROOT))
from callback_bridge.imports_v1 import load_imported_image
from callback_bridge.lift import validate_flags,SOURCE_PATHS,EXTERNAL_SOURCE_PATHS
from memory_stage2.image_loader import load_image as load_plain
from native_bridge.build_lifter import LIFTER,BUILD,OUT as TOOL_OUT

BASE=0x140000000
API_NAMES=('CreateFileA','WriteFile','ReadFile','CloseHandle','GetLastError','ExitProcess')
PROFILE={('kernel32.dll',name):4+index for index,name in enumerate(API_NAMES)}
VARIANTS=('normal','open_exit','after_exit','return_only')
DATA_SIZES={'process_filename':17,'process_source':67,'process_after_source':13,'process_source_size':4,
    'process_destination':67,'process_result':16,'process_marker':4,'process_caller_marker':4,
    'process_written':4,'process_after_written':4,'process_handle':8,'process_return_code':8,'process_image_anchor':8}
FLAGS=['-target','x86_64-pc-windows-msvc','-O2','-std=c11','-Wall','-Wextra','-Werror',
    '-ffreestanding','-nostdinc','-fno-builtin','-fno-stack-protector','-mno-stack-arg-probe',
    '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-vectorize','-fno-slp-vectorize',
    '-mno-sse','-mno-sse2','-mno-mmx','-fno-optimize-sibling-calls']

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise ValueError(message)

def run(command,log,check=True):
    command=list(map(str,command));result=subprocess.run(command,capture_output=True,text=True)
    Path(log).write_text(json.dumps(command)+'\n'+result.stdout+result.stderr)
    if check and result.returncode:raise RuntimeError('tool failed: '+str(command[0])+': '+result.stderr[-2000:])
    return result

def imports_present(path):
    data=Path(path).read_bytes();pe=struct.unpack_from('<I',data,0x3c)[0]
    return bool(struct.unpack_from('<I',data,pe+24+112+8)[0])

def load_fixture(path,load_base=None):
    return load_imported_image(Path(path),load_base,signatures=PROFILE) if imports_present(path) else load_plain(Path(path),load_base)

def parse_map(path):
    symbols={}
    for line in Path(path).read_text().splitlines():
        match=re.match(r'^\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{16})\b',line)
        if match:symbols[match[1]]=int(match[2],16)-BASE
    return symbols

def decode(path,directory,prefix,allow_reject=False):
    image=load_fixture(path);section=next(s for s in image.sections if s['permissions']&4)
    code=bytes(image.data[section['rva']:section['rva']+section['virtual_size']])
    manifest=directory/(prefix+'-decoded.json')
    if manifest.exists():manifest.unlink()
    command=[LIFTER,'--os=windows','--arch=amd64','--address='+str(image.base+section['rva']),
        '--entry_address='+str(image.base+image.entry_rva),'--bytes='+code.hex(),
        '--aot_manifest='+str(manifest),'--aot_decode_only']
    imports=getattr(image,'imports',[])
    if imports:command+=['--aot_iat_slots='+','.join(str(image.base+i['iat_rva']) for i in imports)]
    result=run(command,directory/(prefix+'-decode.log'),check=not allow_reject)
    if result.returncode:
        require(allow_reject and 'REJECT' in result.stderr and not manifest.exists(),'unexpected decoder failure')
        return image,[],{'status':'REJECT','reason':result.stderr.strip(),'returncode':result.returncode}
    instructions=json.loads(manifest.read_text())
    for item in instructions:
        item['rva']=item['address']-image.base
        item['iat_slot_rva']=item.get('iat_slot_pc',0)-image.base if item.get('iat_slot_pc') else 0
    validate_flags(instructions,image.base+image.entry_rva)
    return image,instructions,{'status':'STATIC_DECODE_PASS','instructions':len(instructions)}

def build(directory=ROOT/'build/process-bridge/fixtures'):
    out=Path(directory).resolve();out.mkdir(parents=True,exist_ok=True)
    evidence=out/'evidence.json';evidence.write_text('{"status":"RUNNING"}\n')
    require(LINKER.is_file(),'requires prepared read-only local LLD from file fixture milestone')
    sources={Path(__file__),HERE/'process_fixture.c',HERE/'kernel32.def',ROOT/'file_bridge/file_roundtrip.c'}
    sources|={ROOT/p for p in SOURCE_PATHS+EXTERNAL_SOURCE_PATHS}
    tools={LLVM/'bin'/p for p in ('clang','llvm-dlltool','llvm-readobj','llvm-objdump')}
    tools|={LINKER,LIFTER,LLVM/'lib/libLLVM.dylib',LLVM/'lib/libclang-cpp.dylib',Path('/opt/homebrew/opt/zstd/lib/libzstd.1.dylib')}
    inputs=sources|tools|{TOOL_OUT/'build-manifest.json',BUILD/'lib/Arch/X86/Runtime/amd64.bc'}
    before={str(p.resolve()):sha(p) for p in sorted(inputs)};records={}
    try:
        library=out/'kernel32.lib'
        run([LLVM/'bin/llvm-dlltool','-m','i386:x86-64','-d',HERE/'kernel32.def','-l',library],out/'import-library.log')
        helper=out/'file_roundtrip.obj'
        run([LLVM/'bin/clang',*FLAGS,'-c',ROOT/'file_bridge/file_roundtrip.c','-o',helper],out/'file-compile.log')
        def make(name,index,flags=FLAGS):
            obj=out/(name+'.obj');pe=out/(name+'.exe');map_file=out/(name+'.map')
            run([LLVM/'bin/clang',*flags,'-DPROCESS_VARIANT='+str(index),'-c',HERE/'process_fixture.c','-o',obj],out/(name+'-compile.log'))
            objects=[obj]+([helper] if index==1 else [])
            command=[LINKER,'/entry:process_entry','/subsystem:console','/nodefaultlib','/machine:x64',
                '/base:'+hex(BASE),'/dynamicbase','/nxcompat','/fixed:no','/timestamp:0',
                *['/include:'+s for s in DATA_SIZES],'/out:'+str(pe),'/map:'+str(map_file),*objects,library]
            run(command,out/(name+'-link.log'))
            run([LLVM/'bin/llvm-objdump','--disassemble',pe],out/(name+'-disassembly.txt'))
            run([LLVM/'bin/llvm-readobj','--file-headers','--sections','--coff-imports','--coff-basereloc',pe],out/(name+'-headers.txt'))
            return pe,map_file
        for index,name in enumerate(VARIANTS,1):
            pe,map_file=make(name,index);symbols=parse_map(map_file)
            require(set(DATA_SIZES).issubset(symbols) and 'process_entry' in symbols,'map omitted observable data/entry')
            image,instructions,check=decode(pe,out,name)
            require(image.entry_rva==symbols['process_entry'],'entry/map mismatch')
            payload=image.read(image.base+symbols['process_source'],67)
            require(image.read(image.base+symbols['process_filename'],17)==b'process-save.bin\0','unexpected static filename')
            require(struct.unpack('<I',image.read(image.base+symbols['process_source_size'],4))[0]==67,'source length mismatch')
            for key in ('process_destination','process_result','process_marker','process_caller_marker','process_written','process_after_written','process_return_code'):
                require(image.read(image.base+symbols[key],DATA_SIZES[key])==bytes(DATA_SIZES[key]),'PE BSS/data not initially zero: '+key)
            moved=load_fixture(pe,0x180000000)
            require(struct.unpack('<Q',moved.read(moved.base+symbols['process_image_anchor'],8))[0]==moved.base+symbols['process_filename'],'static anchor did not rebase')
            imports=[{k:i[k] for k in ('dll','name','signature','iat_rva')} for i in getattr(image,'imports',[])]
            if name=='return_only':require(not imports and len(instructions)==1 and instructions[0]['iclass']=='RET_NEAR','return-only must be a real import-free RET')
            else:require(any(i['name']=='ExitProcess' for i in imports),'ExitProcess import absent')
            # Observe symbols through LLD's map, without adding an export directory.
            observations={s:{'rva':symbols[s],'size':size} for s,size in DATA_SIZES.items() if s!='process_handle'}
            observations['process_image_anchor'].update(kind='image_pointer',target_rva=symbols['process_filename'])
            markers=[]
            if name=='after_exit':
                require('process_exit_helper' in symbols,'after_exit noinline helper missing')
                for item in instructions:
                    raw=bytes(image.data[item['rva']:item['rva']+item['length']])
                    if len(raw)==10 and raw[:2]==b'\xc7\x05':
                        target=item['rva']+10+struct.unpack_from('<i',raw,2)[0];value=struct.unpack_from('<I',raw,6)[0]
                        if (target,value) in [(symbols['process_marker'],0xa5a55a5a),(symbols['process_caller_marker'],0xc0dec0de)]:
                            markers.append({'instruction_rva':item['rva'],'target_rva':target,'value':value})
                require(len(markers)==2,'compiled post-exit markers were optimized away')
                write_slot=next(i['iat_rva'] for i in imports if i['name']=='WriteFile')
                require(sum(i['iat_slot_rva']==write_slot for i in instructions)==2,'second post-exit WriteFile was not retained')
                require(any(i['kind']==1 and i['target_pc']==BASE+symbols['process_exit_helper'] for i in instructions),'main no longer directly calls exit helper')
            expected_exit={'normal':0,'open_exit':0x12345678,'after_exit':0x87654321,'return_only':None}[name]
            expected_counts=dict.fromkeys(API_NAMES,0)
            if name=='normal':expected_counts.update(CreateFileA=2,WriteFile=1,ReadFile=1,CloseHandle=2,ExitProcess=1)
            elif name!='return_only':expected_counts.update(CreateFileA=1,WriteFile=1,ExitProcess=1)
            records[name]={'name':name,'pe_path':str(pe),'pe_sha256':sha(pe),'entry_rva':image.entry_rva,'entry_symbol':'process_entry',
                'entry_contract':'void process_entry(void); all filename/payload/buffers/results are static PE data/BSS, no host business arguments',
                'symbols':symbols,'labels':symbols,'observations':observations,'imports':imports,'source_length':67,
                'source_rva':symbols['process_source'],'destination_rva':symbols['process_destination'],
                'filename':'process-save.bin','filename_rva':symbols['process_filename'],'filename_size':17,
                'result_rva':symbols['process_result'],'marker_rva':symbols['process_marker'],'caller_marker_rva':symbols['process_caller_marker'],
                'expected_exit_code':expected_exit,'expected_outcome':'FUNCTION_RETURN' if expected_exit is None else 'PROCESS_EXIT',
                'expected_file_hex':None if name=='return_only' else payload.hex(),'payload_hex':payload.hex(),
                'expected_destination_hex':(payload if name=='normal' else bytes(67)).hex(),
                'expected_file_result':[8,0,67,67] if name=='normal' else [0,0,0,0] if name=='return_only' else [3,0,67,0],
                'expected_api_calls':expected_counts,'expected_cleanup_closes':1 if name in ('open_exit','after_exit') else 0,
                'minimum_active_guest_call_depth':2 if name=='after_exit' else 0 if name=='return_only' else 1,
                'post_exit_markers':markers,'sections':image.sections,'relocations':image.relocations,
                'rebase_check':{'base':moved.base,'status':'PASS'},'decode':check,
                'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sorted(sources)},
                'windows_execution':False,'runtime_execution':False}
        # Actual compiler option experiment: do not edit bytes to avoid a tail
        # jump. Preserve the default optimizer candidate and its real rejection.
        candidate,_=make('normal-default-tail',1,[f for f in FLAGS if f!='-fno-optimize-sibling-calls'])
        _,_,tail_check=decode(candidate,out,'normal-default-tail',allow_reject=True)
        (out/'manifest.json').write_text(json.dumps(records,indent=2)+'\n')
        after={str(p.resolve()):sha(p) for p in sorted(inputs)};require(before==after,'fixture source/frozen tools changed')
        result={'status':'BUILD_AND_DECODE_PASS_NOT_EXECUTED','variants':list(records),'cases':{n:r['decode'] for n,r in records.items()},
                'default_tailcall_experiment':tail_check,'inputs_before':before,'inputs_after':after,
                'artifact_sha256':{str(p.relative_to(out)):sha(p) for p in out.iterdir() if p.is_file() and p!=evidence},
                'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sorted(sources)},
                'scope':'actual C/COFF/LLD no-argument PE preparation and static decode; no process execution yet'}
        evidence.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({'status':result['status'],'variants':{n:r['decode']['instructions'] for n,r in records.items()},'default_tailcall':tail_check}));return records
    except Exception as error:
        evidence.write_text(json.dumps({'status':'FAIL','error':str(error)},indent=2)+'\n');raise


if __name__=='__main__':build()
