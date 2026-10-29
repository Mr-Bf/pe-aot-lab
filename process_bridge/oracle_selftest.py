#!/usr/bin/env python3
"""Small actual process-oracle lifecycle/rebase test, separate from ARM tests."""
import copy
import hashlib
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(ROOT))
from process_bridge.oracle import Oracle
OUT=ROOT/'build/process-bridge/oracle-tests'

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise RuntimeError(message)

def main():
    OUT.mkdir(parents=True,exist_ok=True);evidence=OUT/'evidence.json';evidence.write_text('{"status":"RUNNING"}\n')
    sources=[Path(__file__),HERE/'oracle.py',HERE/'oracle_x86.c',HERE/'oracle_file_stubs.h']
    before={str(p):sha(p) for p in sources};runs=[];rejections=[];all_inputs={};artifacts={}
    try:
        fixtures=json.loads((ROOT/'build/process-bridge/fixtures/manifest.json').read_text())
        for name,metadata in fixtures.items():
            oracle=Oracle(metadata['pe_path'],OUT/name,metadata=metadata);mapped=[]
            for hint in (None,0x180000000):
                result=oracle.run(base_hint=hint);mapped.append(result['mapped_base'])
                record=copy.deepcopy(oracle.last_run);record['evidence_path']=str(Path(result['directory'])/'evidence.json')
                record['evidence_sha256']=sha(record['evidence_path']);runs.append(record)
                require(record['inputs_before']==record['inputs_after'] and record['artifacts_before']==record['artifacts_after'],'run identity changed')
                for path,value in record['inputs_before'].items():
                    require(path not in all_inputs or all_inputs[path]==value,'inconsistent shared input identity')
                    all_inputs[path]=value
                artifacts.update(record['artifacts_after'])
                directory=Path(result['directory'])
                artifacts.update({str(p):sha(p) for p in directory.iterdir() if p.is_file()})
            require(len(set(mapped))==2,'two mapping requests did not exercise distinct actual x86 image bases')
            artifacts[str(oracle.out_dir/'manifest.json')]=sha(oracle.out_dir/'manifest.json')
        def rejected(name,call):
            try:call()
            except ValueError as error:rejections.append({'case':name,'status':'REJECT','reason':str(error)})
            else:raise RuntimeError('expected wrapper rejection: '+name)
        rejected('unaligned_hint',lambda:oracle.run(base_hint=1))
        mutated=copy.deepcopy(fixtures['normal']);mutated['expected_exit_code']=123
        rejected('metadata_mismatch',lambda:Oracle(mutated['pe_path'],OUT/'bad-metadata',metadata=mutated))
        unknown=OUT/'unknown.exe';data=bytearray(Path(fixtures['normal']['pe_path']).read_bytes());data[1024]^=1;unknown.write_bytes(data)
        rejected('unknown_original_pe',lambda:Oracle(unknown,OUT/'bad-pe'))
        include=oracle.out_dir/'oracle_image.h';saved=include.read_bytes()
        try:
            include.write_bytes(saved+b'\n')
            rejected('artifact_identity',lambda:oracle.run())
        finally:include.write_bytes(saved)
        oracle._validate_identity()
        require(before=={str(p):sha(p) for p in sources},'selftest sources changed')
        for path,value in all_inputs.items():
            require(str(Path(path).resolve())==value['realpath'] and sha(path)==value['sha256'],'shared input stale at end')
        require(all(sha(path)==value for path,value in artifacts.items()),'executed/observed artifacts changed')
        require(len(runs)==8 and len(rejections)==4,'selftest count mismatch')
        result={'status':'PASS','raw_no_argument_pe_invocations':8,'variants':list(fixtures),'replays_per_variant':2,
            'process_exit_cases':6,'function_return_cases':2,'wrapper_rejections':4,'rejected':rejections,
            'source_before':before,'source_after':{str(p):sha(p) for p in sources},
            'inputs_before':all_inputs,'inputs_after':{p:{'realpath':str(Path(p).resolve()),'sha256':sha(p)} for p in all_inputs},
            'artifact_sha256':artifacts,'runs':runs,
            'scope':'original no-argument PE x86/Rosetta/POSIX oracle only; actual ExitProcess test longjmp vs true RET, static data/BSS, I/O and residual descriptor cleanup',
            'windows_execution':False,'wine_execution':False,'arm64_comparison_performed':False}
        evidence.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps({'status':'PASS','raw_no_argument_pe_invocations':8,'process_exit':6,'function_return':2,'wrapper_rejections':4}))
    except Exception as error:
        evidence.write_text(json.dumps({'status':'FAIL','error':str(error)},indent=2)+'\n');raise


if __name__=='__main__':main()
