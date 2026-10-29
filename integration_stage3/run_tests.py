#!/usr/bin/env python3
"""Run the stage3 acceptance suites, or verify their current recorded evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];HERE=ROOT/'integration_stage3'
OUT=ROOT/'build/integration-stage3'
PARTS={'lifter':'lifter-checks/results.json','memory':'memory/evidence.json',
       'image':'image-integration/evidence.json','calls':'calls/evidence.json',
       'sanitizers':'sanitizers/evidence.json'}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def require(value,message):
    if not value:raise RuntimeError(message)
def valid_digest(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value) is not None
def check_hash(path,digest):
    require(valid_digest(digest),'invalid SHA-256 for '+str(path))
    require(path.exists() and sha(path)==digest,'stale/missing evidence dependency: '+str(path))
def read_json(path):
    def unique_keys(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'duplicate JSON key in '+str(path)+': '+key)
            result[key]=value
        return result
    value=json.loads(path.read_text(),object_pairs_hook=unique_keys)
    require(isinstance(value,dict),'expected evidence object: '+str(path))
    return value
def positive(value,label):
    require(type(value) is int and value>0,'invalid positive count: '+label)
    return value
def rows(doc,key,identity,status='PASS'):
    values=doc.get(key)
    require(isinstance(values,list) and values,'empty/missing evidence list: '+key)
    seen=set()
    for item in values:
        require(isinstance(item,dict),'invalid record in '+key)
        name=item.get(identity)
        require(isinstance(name,str) and bool(name.strip()),'missing record identity in '+key)
        # CALL boundary tests deliberately exercise one test with two targets.
        unique=(name,item.get('target')) if key=='boundary_checks' else name
        require(unique not in seen,'duplicate record in '+key+': '+name);seen.add(unique)
        if status is not None:require(item.get('status')==status,'nested record did not '+status+': '+name)
    return values
def hash_map(doc,key,label,required=()):
    values=doc.get(key)
    require(isinstance(values,dict) and bool(values),'empty/missing '+key+': '+label)
    require(set(required)<=set(values),'incomplete '+key+': '+label)
    for name,digest in values.items():
        require(isinstance(name,str) and name and valid_digest(digest),'invalid hash entry: '+label)
    return values
def validate_records(documents):
    lifter=documents['lifter'];rejected=rows(lifter,'cases','name',None)
    for item in rejected:
        require(item.get('rejected') is True,'lifter case was not rejected: '+item['name'])
        require(isinstance(item.get('reason'),str) and bool(item['reason'].strip()),'missing lifter rejection reason')
    require(positive(lifter.get('count'),'lifter count')==len(rejected),'lifter rejection count mismatch')
    memory=documents['memory'];samples=rows(memory,'samples','name')
    require(positive(memory.get('functional_cases'),'memory total')==sum(positive(s.get('cases'),s['name']) for s in samples),'memory functional count mismatch')
    rows(memory,'boundaries','test')
    calls=documents['calls'];functional=rows(calls,'functional','fixture')
    require(calls.get('original_byte_oracle') is True,'CALL evidence is not original-byte differential')
    require(positive(calls.get('functional_cases'),'CALL total')==sum(positive(s.get('cases'),s['fixture']) for s in functional),'CALL functional count mismatch')
    rows(calls,'boundary_checks','test')
    for item in rows(calls,'rejections','fixture','REJECT'):
        require(isinstance(item.get('reason'),str) and bool(item['reason'].strip()),'missing CALL rejection reason')
    native=calls.get('native_artifacts')
    require(isinstance(native,dict) and native,'missing CALL native artifacts')
    require({s['fixture'] for s in functional}<=set(native),'CALL functional fixture has no native artifact')
    image=documents['image'];image_rows=rows(image,'records','case')
    require(any(r['case']=='rebase_rip_relative_dir64_bss_ret' and positive(r.get('cases'),'image rebase count') for r in image_rows),'missing image rebase acceptance record')
    for item in image_rows:
        if 'cases' in item:positive(item['cases'],item['case'])
        if 'expected_execution' not in item:continue
        mode=item['expected_execution'];require(mode in ('FAULT','REJECT'),'unknown image outcome')
        if mode=='REJECT':require(isinstance(item.get('reason'),str) and bool(item['reason'].strip()),'missing image rejection reason')
        else:
            fault=item.get('fault');require(isinstance(fault,dict),'missing image fault')
            positive(fault.get('status'),'image fault status')
            for name in ('pc','address','width','access'):
                require(type(fault.get(name)) is int and fault[name]>=0,'invalid image fault '+name)
    san=documents['sanitizers'];count=positive(san.get('cases'),'sanitizer cases');outcomes=san.get('outcomes')
    require(isinstance(outcomes,dict) and outcomes,'missing sanitizer outcomes')
    required={'returned','bounds','protection','bad_return'}
    require(required<=set(outcomes),'missing sanitizer outcome category')
    for name,value in outcomes.items():
        require(type(value) is int and value>=0,'invalid sanitizer outcome count: '+name)
        if name in required:positive(value,'sanitizer '+name)
    require(sum(outcomes.values())==count,'sanitizer outcome count mismatch')
    positive(san.get('lifted_functions_instrumented'),'instrumented lifted functions')

REQUIRED_SOURCES={
 'lifter':{'integration_stage3/lifter_checks.py','integration_stage3/lift.py','integration_stage3/build_lifter.py','integration_stage3/lifter_layout.cpp','fixtures.py','pe_aot.py','memory_stage2/image_loader.py'},
 'memory':{'integration_stage3/runtime.c','integration_stage3/runtime.h','integration_stage3/bindings.py','integration_stage3/test_memory.py','integration_stage3/lift.py','memory_stage2/image_loader.py'},
 'image':{'integration_stage3/runtime.c','integration_stage3/runtime.h','integration_stage3/bindings.py','integration_stage3/make_image.py','integration_stage3/test_image_integration.py','integration_stage3/lift.py','memory_stage2/image_loader.py'},
 'calls':{'integration_stage3/runtime.c','integration_stage3/runtime.h','integration_stage3/bindings.py','integration_stage3/test_calls.py','integration_stage3/call_fixtures.py','integration_stage3/lift.py'},
 'sanitizers':{'integration_stage3/runtime.c','integration_stage3/runtime.h','integration_stage3/sanitize.c','integration_stage3/test_sanitizers.py'}}

def verify():
    documents={}
    for name,relative in PARTS.items():
        path=OUT/relative;doc=read_json(path);require(doc.get('status')=='PASS',name+' did not pass')
        if name in REQUIRED_SOURCES:hash_map(doc,'source_sha256',name,REQUIRED_SOURCES[name])
        for source,digest in doc.get('source_sha256',{}).items():
            require(not Path(source).is_absolute() and '..' not in Path(source).parts,'source key must be repo-relative')
            check_hash(ROOT/source,digest)
        documents[name]=doc
    validate_records(documents)
    # Tie the instruction approval, emitted objects and actual loaded native images
    # to the current patched lifter. A PASS string alone is insufficient.
    build=read_json(OUT/'lifter/build-manifest.json')
    require(build['status']=='PASS','lifter build did not pass');check_hash(Path(build['lifter']),build['lifter_sha256'])
    rejected=documents['lifter']
    check_hash(OUT/'lifter/build-manifest.json',rejected['build_manifest_sha256'])
    require(rejected['lifter_sha256']==build['lifter_sha256'],'profile rejection evidence used a different lifter')
    require(rejected['semantics_sha256']==build['semantics_sha256'],'profile rejection evidence used different semantics')
    for name,digest in hash_map(build,'patch_sha256','lifter build',('xed-only.patch','transactions.patch','aot-profile.patch')).items():check_hash(HERE/name,digest)
    semantics=Path(build['lifter']).parents[2]/'lib/Arch/X86/Runtime/amd64.bc'
    check_hash(semantics,build['semantics_sha256'])
    artifact_count=0
    dirs=[OUT/'memory'/s['name'] for s in documents['memory']['samples']]
    dirs += [OUT/'calls'/name for name in documents['calls']['native_artifacts']]
    dirs += [OUT/'image-integration/compiled']
    for directory in dirs:
        manifest=read_json(directory/'manifest.json')
        require(manifest['status']=='PASS' and manifest['lifter_sha256']==build['lifter_sha256'],'stale lifted module')
        require(manifest['semantics_sha256']==build['semantics_sha256'],'stale lifted semantics')
        require(isinstance(manifest.get('instructions'),list) and bool(manifest['instructions']),'missing approved instructions')
        for source,digest in hash_map(manifest,'source_sha256','lifted module').items():check_hash(HERE/source,digest)
        for source,digest in hash_map(manifest,'external_source_sha256','lifted module',('memory_stage2/image_loader.py',)).items():check_hash(ROOT/source,digest)
        for name,digest in hash_map(manifest,'artifact_sha256','lifted module',('text.bin','instructions-raw.json','lifted.ll','arm64.ll','arm64.o','arm64-o0.o')).items():check_hash(directory/name,digest);artifact_count+=1
        native=read_json(directory/'native-artifact.json')
        require(native['input_sha256']==manifest['input_sha256'],'native input/module mismatch')
        check_hash(Path(native['library_path']),native['library_sha256'])
        check_hash(directory/'arm64.o',native['object_sha256'])
    for sample in documents['memory']['samples']:
        directory=OUT/'memory'/sample['name'];native=read_json(directory/'native-artifact.json')
        require(native['library_sha256']==sample['dylib_sha256'],'memory ran a different dylib')
        check_hash(directory/'arm64.o',sample['arm64_object_sha256'])
    for name,native in documents['calls']['native_artifacts'].items():
        check_hash(Path(native['library_path']),native['library_sha256'])
        check_hash(OUT/'calls'/name/'manifest.json',native['manifest_sha256'])
    for name,digest in hash_map(documents['image'],'tested_artifact_sha256','image suite').items():
        path=Path(name);check_hash(path if path.is_absolute() else ROOT/path,digest)
    for record in documents['image']['records']:
        if 'library_sha256' in record:
            require(isinstance(record['library_sha256'],list) and record['library_sha256'],'missing shared-directory native images')
            for digest in record['library_sha256']:check_hash(OUT/'image-integration/shared-output'/('program-'+digest+'.dylib'),digest)
    san=documents['sanitizers'];check_hash(OUT/PARTS['memory'],san['correctness_evidence_sha256'])
    check_hash(OUT/'memory/mutate/manifest.json',san['module_manifest_sha256'])
    check_hash(OUT/'sanitizers/sanitized',san['executable_sha256'])
    check_hash(OUT/'sanitizers/instrumented.ll',san['instrumented_ir_sha256'])
    compiler_rt=san.get('compiler_rt');require(isinstance(compiler_rt,dict),'missing sanitizer runtime dependency')
    require(compiler_rt.get('scope')=='workspace-only test tool dependency','unexpected sanitizer runtime scope')
    check_hash(Path(compiler_rt['path']),compiler_rt['relocated_sha256'])
    return {'status':'PASS','scope':'Restricted scalar Remill + guest memory + rebase + direct CALL/RET acceptance; not native API bridge, Windows startup, graphics or game support',
        'dependency_scope':'explicit_recorded_sources_and_artifacts',
        'integrity_scope':'staleness and evidence-consistency checks; not signatures or protection against hostile forgery',
        'sanitizer_runtime_scope':'workspace-only test dependency; not a product redistribution dependency declaration',
        'original_byte_differential_cases':documents['memory']['functional_cases']+documents['calls']['functional_cases'],
        'image_records':documents['image']['records'],'sanitizer_cases':san['cases'],
        'lifter_rejections':documents['lifter']['count'],'checked_emitted_artifacts':artifact_count,
        'aggregator_source_sha256':sha(Path(__file__).resolve()),
        'evidence_sha256':{name:sha(OUT/path) for name,path in PARTS.items()},
        'lifter_build_manifest_sha256':sha(OUT/'lifter/build-manifest.json')}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--verify-only',action='store_true');args=parser.parse_args()
    OUT.mkdir(parents=True,exist_ok=True);target=OUT/'evidence.json';target.write_text('{"status":"RUNNING"}\n')
    try:
        if not args.verify_only:
            for script in ['lifter_checks.py','test_memory.py','test_image_integration.py','test_calls.py','test_sanitizers.py','test_evidence_gate.py']:
                run=subprocess.run([sys.executable,str(HERE/script)],cwd=ROOT,capture_output=True,text=True)
                (OUT/(script+'.log')).write_text(run.stdout+run.stderr)
                require(run.returncode==0,script+' failed; see log')
        report=verify();report['verification_mode']='existing_evidence_and_hashes' if args.verify_only else 'suite_replay_and_hashes'
        target.write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:report[k] for k in ['status','verification_mode','original_byte_differential_cases','sanitizer_cases','lifter_rejections']}))
    except Exception as error:
        target.write_text(json.dumps({'status':'FAIL','error':str(error)},indent=2)+'\n');raise

if __name__=='__main__':main()
