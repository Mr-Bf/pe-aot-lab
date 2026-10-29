#!/usr/bin/env python3
"""Exact self-authored PE -> native ms_abi API -> PE callback x86 oracle."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(ROOT))
from callback_bridge.loader import load_image

KNOWN_TEXT={
    'df16975a4e4fd44f3a84787214850f80b4342c9af5434ea96a076bd99e057955':('leaf',129,0x2038,0),
    '4703ed27ab0efebd588c35f108c7873e3856be14873e4cd8013a05f0a8513e56':('import',103,0x2060,0x2070),
    'c510ae410cb243714f18ed2097eb88472ff9db28e4dc137007ee27c807b83a55':('direct',173,0x2038,0),
    'b862ea04c0c199e43d8d379e0dbacf9f9e543869d335cabbb26ac14932aaa76f':('nested',202,0x2038,0)}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise ValueError(message)


class Oracle:
    def __init__(self,pe_path,out_dir=None):
        self.pe_path=Path(pe_path).resolve(strict=True)
        self.out_dir=Path(out_dir or ROOT/'build/callback-bridge/oracle'/self.pe_path.stem).resolve()
        self.out_dir.mkdir(parents=True,exist_ok=True)
        self.sources=[Path(__file__),HERE/'oracle_x86.c',HERE/'loader.py',HERE/'imports_v1.py',
                      ROOT/'memory_stage2/image_loader.py',self.pe_path]
        self.source_sha256={str(p):sha(p) for p in self.sources}
        image=load_image(self.pe_path)
        executable=[s for s in image.sections if s['permissions']&4]
        require(len(executable)==1 and executable[0]['rva']==image.entry_rva==0x1000,'unexpected executable shape')
        text=image.read(image.base+image.entry_rva,executable[0]['virtual_size'])
        text_sha=hashlib.sha256(text).hexdigest();require(text_sha in KNOWN_TEXT,'unknown original callback fixture bytes')
        self.name,size,invoke_iat,six_iat=KNOWN_TEXT[text_sha]
        require(len(text)==size,'incorrect known text size')
        expected=[('aotdemo.dll','NativeInvokeCallback',3,invoke_iat)]
        if six_iat:expected.append(('aotdemo.dll','NativeSix',2,six_iat))
        require([(b['dll'],b['name'],b['signature'],b['iat_rva']) for b in image.imports]==expected,'unexpected import bindings')
        header='static const unsigned char kOracleImage[]={'+','.join(map(str,image.data))+'};\n'
        header+='enum {kOracleEntryRva=4096,kOracleCallbackRva=4160,kOracleInvokeIat=%d,kOracleSixIat=%d,kOracleTextSize=%d};\n'%(invoke_iat,six_iat,size)
        include=self.out_dir/'oracle_image.h';include.write_text(header)
        self.executable=self.out_dir/'oracle-x86'
        command=['xcrun','clang','-arch','x86_64','-std=c11','-O2','-Wall','-Wextra','-Werror',
                 '-I',str(self.out_dir),str(HERE/'oracle_x86.c'),'-o',str(self.executable)]
        compiled=subprocess.run(command,capture_output=True,text=True)
        (self.out_dir/'compile.log').write_text(json.dumps(command)+'\n'+compiled.stdout+compiled.stderr)
        require(compiled.returncode==0,'oracle compilation failed: '+compiled.stderr)
        self.artifact_sha256={str(p):sha(p) for p in (include,self.executable)};self._validate_identity()
        self.manifest={'status':'BUILT_NOT_TESTED','fixture':self.name,'pe_sha256':sha(self.pe_path),
            'text_hex':text.hex(),'text_sha256':text_sha,'callback_rva':0x1040,'callback_signature':1,
            'source_sha256':self.source_sha256,'artifact_sha256':self.artifact_sha256,'command':command,
            'scope':'unchanged original PE .text on x86/Rosetta; actual seven-argument ms_abi import calls actual six-argument PE callback via typed pointer; no Windows DLL',
            'memory':'oracle maps validated image RW, binds IAT then makes entire image RX; not Windows page permissions'}
        (self.out_dir/'manifest.json').write_text(json.dumps(self.manifest,indent=2)+'\n');self.last_run=None

    def _validate_identity(self):
        for path,digest in {**self.source_sha256,**getattr(self,'artifact_sha256',{})}.items():
            require(sha(path)==digest,'oracle input or artifact changed: '+path)

    def run_many(self,vectors):
        vectors=[tuple(vector) for vector in vectors]
        require(bool(vectors),'oracle requires nonempty input')
        for vector in vectors:
            require(len(vector)==6 and all(type(x) is int and 0<=x<(1<<64) for x in vector),'six uint64 arguments required')
            if self.name=='nested':require(vector[0]<=8,'nested oracle accepts only bounded normal depths a<=8')
        self._validate_identity();payload=''.join(' '.join('%016x'%x for x in vector)+'\n' for vector in vectors)
        command=['arch','-x86_64',str(self.executable)]
        executed=subprocess.run(command,input=payload,capture_output=True,text=True)
        (self.out_dir/'run.log').write_text(json.dumps(command)+'\n'+executed.stdout+executed.stderr)
        require(executed.returncode==0 and not executed.stderr,'original PE callback oracle failed: '+executed.stderr)
        lines=executed.stdout.splitlines();require(len(lines)==len(vectors),'oracle response count mismatch');answers=[]
        for index,line in enumerate(lines):
            fields=[int(word,16) for word in line.split()];require(len(fields)==18,'oracle response layout mismatch')
            result,calls,cb_calls,depth,cb_result,cb_rva,*arguments=fields
            expected_depth=vectors[index][0]+1 if self.name=='nested' else 1
            expected_calls=2 if self.name=='import' else expected_depth
            require(calls==expected_calls and cb_calls==expected_depth and depth==expected_depth and cb_rva==0x1040,'wrong native/callback call path')
            require(tuple(arguments[:6])==vectors[index],'native API received wrong Win64 seven-argument layout')
            if self.name=='import':require(tuple(arguments[6:])==vectors[index],'callback nested API received wrong six-argument layout')
            else:require(not any(arguments[6:]),'unexpected nested API observations')
            require(result==(cb_result+23+7)&((1<<64)-1),'callback/native/caller continuations did not return expected increments')
            answers.append({'result':result,'api_calls':calls,'callback_calls':cb_calls,'max_callback_depth':depth,
                            'callback_result':cb_result,'callback_rva':cb_rva,'native_arguments':arguments[:6],
                            'nested_native_arguments':arguments[6:]})
        self._validate_identity()
        self.last_run={'status':'PASS','cases':len(vectors),'command':command,
            'input_sha256':hashlib.sha256(payload.encode()).hexdigest(),
            'output_sha256':hashlib.sha256(executed.stdout.encode()).hexdigest(),'stderr':''}
        (self.out_dir/'last-run.json').write_text(json.dumps(self.last_run,indent=2)+'\n');return answers
