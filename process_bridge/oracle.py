#!/usr/bin/env python3
"""No-argument original PE + actual Win64 IAT calls + test-only process exit.
Runs under x86/Rosetta/POSIX; never claims Windows/Wine process startup.
"""
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(ROOT))
from file_bridge.oracle import Oracle as FileOracle
from callback_bridge.imports_v1 import load_imported_image
from memory_stage2.image_loader import load_image as load_plain
API_ORDER=('CreateFileA','WriteFile','ReadFile','CloseHandle','GetLastError','ExitProcess')
PROFILE={('kernel32.dll',name):4+i for i,name in enumerate(API_ORDER)}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise ValueError(message)

class Oracle(FileOracle):
    def __init__(self,pe_path,out_dir=None,metadata=None):
        self.pe_path=Path(pe_path).resolve(strict=True)
        self.out_dir=Path(out_dir or ROOT/'build/process-bridge/oracle'/self.pe_path.stem).resolve();self.out_dir.mkdir(parents=True,exist_ok=True)
        producer_path=ROOT/'build/process-bridge/fixtures/manifest.json'
        producer=json.loads(producer_path.read_text())
        matching=[value for value in producer.values() if value['pe_sha256']==sha(self.pe_path)]
        require(len(matching)==1,'only a current self-authored process fixture is executable by this oracle')
        self.metadata=matching[0]
        require(metadata is None or metadata==self.metadata,'supplied fixture metadata differs from producer')
        producer_evidence=ROOT/'build/process-bridge/fixtures/evidence.json'
        evidence=json.loads(producer_evidence.read_text())
        require(evidence['status']=='BUILD_AND_DECODE_PASS_NOT_EXECUTED','producer evidence missing')
        require(evidence['artifact_sha256']['manifest.json']==sha(producer_path),'producer manifest identity mismatch')
        require(evidence['artifact_sha256'][self.metadata['name']+'.exe']==sha(self.pe_path),'producer PE identity mismatch')
        self.sources=[Path(__file__),HERE/'oracle_x86.c',HERE/'oracle_file_stubs.h',ROOT/'file_bridge/oracle.py',
            ROOT/'callback_bridge/imports_v1.py',ROOT/'memory_stage2/image_loader.py',self.pe_path,producer_path,producer_evidence]
        self.source_sha256={str(p):sha(p) for p in self.sources}
        data=self.pe_path.read_bytes();pe=struct.unpack_from('<I',data,0x3c)[0]
        has_imports=bool(struct.unpack_from('<I',data,pe+24+112+8)[0])
        image=load_imported_image(self.pe_path,signatures=PROFILE) if has_imports else load_plain(self.pe_path)
        imports=getattr(image,'imports',[]);require(all((x['dll'],x['name']) in PROFILE for x in imports),'unknown import')
        executable=[s for s in image.sections if s['permissions']&4];require(len(executable)==1,'one text range required')
        section=executable[0];self.image_size=len(image.data)
        text=bytes(image.data[section['rva']:section['rva']+section['virtual_size']]);by_name={b['name']:b for b in imports}
        header='static const unsigned char kImage[]={'+','.join(map(str,image.data))+'};\n'
        header+='static const uint64_t kPreferredBase=UINT64_C(%d);\n'%image.preferred_base
        header+='static const uint32_t kRelocations[]={'+','.join(str(r['rva']) for r in image.relocations)+'};\n'
        header+='static const uint32_t kIatRvas[]={'+','.join(str(by_name[name]['iat_rva']) if name in by_name else '0' for name in API_ORDER)+'};\n'
        header+='static const unsigned char kPagePermissions[]={'+','.join(map(str,image.permissions))+'};\n'
        header+='enum {kEntryRva=%d,kTextRva=%d,kTextSize=%d,kRelocationCount=%d,kPageCount=%d};\n'%(image.entry_rva,section['rva'],len(text),len(image.relocations),len(image.permissions))
        include=self.out_dir/'oracle_image.h';include.write_text(header);self.executable=self.out_dir/'oracle-x86'
        common=['xcrun','clang','-arch','x86_64','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',str(self.out_dir)]
        command=[*common,str(HERE/'oracle_x86.c'),'-o',str(self.executable)]
        probe=subprocess.run([*command,'-###'],capture_output=True,text=True);require(probe.returncode==0,'cannot inspect compiler command')
        (self.out_dir/'driver-commands.log').write_text(json.dumps([*command,'-###'])+'\n'+probe.stdout+probe.stderr)
        tool_paths={Path(shutil.which(n)).resolve() for n in ('xcrun','arch')};tool_paths.add(Path(sys.executable).resolve())
        for name in ('clang','ld'):
            found=subprocess.run(['xcrun','--find',name],capture_output=True,text=True);require(found.returncode==0,'cannot find '+name);tool_paths.add(Path(found.stdout.strip()))
        for line in probe.stderr.splitlines():
            if line.lstrip().startswith('"'):
                parts=shlex.split(line)
                if parts and Path(parts[0]).is_file():tool_paths.add(Path(parts[0]))
        dependency_command=[*common,'-M','-MT','oracle',str(HERE/'oracle_x86.c')]
        deps=subprocess.run(dependency_command,capture_output=True,text=True);require(deps.returncode==0,'C dependency capture failed: '+deps.stderr)
        (self.out_dir/'dependencies.log').write_text(json.dumps(dependency_command)+'\n'+deps.stdout+deps.stderr)
        joined=deps.stdout.replace('\\\n',' ');require(joined.startswith('oracle:'),'unexpected dependency output')
        dependency_paths={Path(p) for p in shlex.split(joined[len('oracle:'):])}
        require(HERE/'oracle_file_stubs.h' in dependency_paths and include in dependency_paths,'missing actual C dependencies')
        self.tool_sha256={str(p):sha(p) for p in sorted(tool_paths)};self.dependency_sha256={str(p):sha(p) for p in sorted(dependency_paths)}
        self.inputs_before={str(p):{'realpath':str(p.resolve()),'sha256':sha(p)} for p in sorted(set(self.sources)|tool_paths|dependency_paths)}
        result=subprocess.run(command,capture_output=True,text=True)
        (self.out_dir/'compile.log').write_text(json.dumps(command)+'\n'+result.stdout+result.stderr)
        require(result.returncode==0,'process oracle compilation failed: '+result.stderr)
        self.artifact_sha256={str(p):sha(p) for p in (include,self.executable,self.out_dir/'driver-commands.log',self.out_dir/'dependencies.log')};self._validate_identity()
        self.manifest={'status':'BUILT_NOT_TESTED','fixture':self.metadata['name'],'pe_sha256':sha(self.pe_path),
            'text_sha256':hashlib.sha256(text).hexdigest(),'page_permissions':image.permissions,
            'source_sha256':self.source_sha256,'tool_sha256':self.tool_sha256,'dependency_sha256':self.dependency_sha256,
            'inputs_before':self.inputs_before,'inputs_after':self._input_identity(),'artifact_sha256':self.artifact_sha256,'command':command,
            'scope':'original no-argument PE entry under x86/Rosetta, real typed Win64 IAT calls to restricted POSIX stubs; ExitProcess uses test-only setjmp/longjmp; not Windows/Wine',
            'memory':'exact 4KiB PE page permissions only if host page granularity divides 4KiB; .text RX, .data/BSS RW; all host pointers exist only in this raw x86 oracle',
            'dependency_scope':'actual C/header dependencies and explicit compiler/linker/driver binaries; not full SDK/dyld signature',
            'windows_execution':False,'wine_execution':False,'arm64_comparison_performed':False}
        (self.out_dir/'manifest.json').write_text(json.dumps(self.manifest,indent=2)+'\n');self.last_run=None

    def run(self,base_hint=None):
        hint=0 if base_hint is None else base_hint
        require(type(hint) is int and 0<=hint<(1<<64)-self.image_size and hint%4096==0,'invalid non-fixed mapping hint')
        self._validate_identity();inputs_before=self._input_identity();artifacts_before={p:sha(p) for p in self.artifact_sha256}
        runs=self.out_dir/'runs';runs.mkdir(exist_ok=True);directory=Path(tempfile.mkdtemp(prefix='run-',dir=runs))
        command=['arch','-x86_64',str(self.executable),str(directory),hex(hint)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=30)
        (directory/'run.log').write_text(json.dumps(command)+'\n'+result.stdout+result.stderr)
        require(result.returncode==0 and not result.stderr,'original process PE oracle failed: '+result.stderr)
        raw=json.loads(result.stdout);metadata=self.metadata
        require(raw['outcome']==metadata['expected_outcome'],'ExitProcess and RET outcome differ')
        require(raw['exit_code']==(metadata['expected_exit_code'] or 0),'full DWORD exit code differs')
        require(raw['exit_calls']==(metadata['expected_exit_code'] is not None),'ExitProcess count differs')
        require(raw['original_text_unchanged']==1,'original PE code modified')
        counts=dict(zip(API_ORDER,raw['api_calls']));require(counts==metadata['expected_api_calls'],'post-exit API executed or normal API path differed')
        require(raw['open_handles_before_cleanup']==raw['cleanup_closes']==metadata['expected_cleanup_closes'],'abrupt exit residual handle cleanup differed')
        require(raw['cleanup_errors']==0 and raw['open_handles_after_cleanup']==0,'process test leaked handles')
        dump=directory/'image-after.bin';memory=dump.read_bytes();require(len(memory)==self.image_size,'image observation truncated')
        observations={name:memory[item['rva']:item['rva']+item['size']].hex() for name,item in metadata['observations'].items()}
        normalized=dict(observations)
        for name,item in metadata['observations'].items():
            if item.get('kind')=='image_pointer':
                pointer=int.from_bytes(bytes.fromhex(observations[name]),'little')
                require(pointer==raw['mapped_base']+item['target_rva'],'image anchor not genuinely rebased')
                normalized[name]=item['target_rva'].to_bytes(item['size'],'little').hex()
        file_result=list(struct.unpack('<4I',bytes.fromhex(observations['process_result'])))
        require(file_result==metadata['expected_file_result'],'static PE FileResult differs')
        for marker in ('process_marker','process_caller_marker','process_after_written'):
            require(observations[marker]=='00000000','post-ExitProcess code executed: '+marker)
        require(observations['process_destination']==metadata['expected_destination_hex'],'static destination differs')
        require(observations['process_source']==metadata['payload_hex'],'static source modified')
        require(bytes.fromhex(observations['process_filename'])==b'process-save.bin\0','static filename modified')
        disk_path=directory/metadata['filename'];disk=None
        if metadata['expected_file_hex'] is None:require(not disk_path.exists(),'return-only performed file I/O')
        else:
            info=disk_path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'disk output not regular owned file')
            disk=disk_path.read_bytes();require(disk.hex()==metadata['expected_file_hex'],'actual disk differs; post-exit WriteFile may have run')
        self._validate_identity()
        answer={**raw,'exit_code':metadata['expected_exit_code'],'call_counts':counts,'api_calls':sum(counts.values()),
            'observations':observations,'normalized_observations':normalized,'file_result':file_result,
            'disk_data':disk,'disk_path':str(disk_path) if disk is not None else None,'directory':str(directory)}
        self.last_run={'status':'PASS','fixture':metadata['name'],'command':command,
            'result':{k:v for k,v in answer.items() if k!='disk_data'},'disk_sha256':hashlib.sha256(disk).hexdigest() if disk is not None else None,
            'image_after_sha256':sha(dump),'source_sha256':self.source_sha256,'tool_sha256':self.tool_sha256,
            'dependency_sha256':self.dependency_sha256,'inputs_before':inputs_before,'inputs_after':self._input_identity(),
            'artifacts_before':artifacts_before,'artifacts_after':{p:sha(p) for p in self.artifact_sha256},
            'scope':self.manifest['scope'],'windows_execution':False,'arm64_comparison_performed':False}
        (directory/'evidence.json').write_text(json.dumps(self.last_run,indent=2)+'\n')
        (self.out_dir/'last-run.json').write_text(json.dumps(self.last_run,indent=2)+'\n');return answer
