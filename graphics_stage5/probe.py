#!/usr/bin/env python3
"""Compile/run/read-only verify a native Metal preflight, never DirectX or guest code."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent;OUT=ROOT/'build/graphics-stage5/probe'
SCOPE='native Metal clear/readback only; not DXMT, shader, guest graphics or window acceptance'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise RuntimeError(message)
def hashes(paths):return {str(Path(p).resolve()):sha(p) for p in sorted(set(map(Path,paths)))}
def same(values):
    require(isinstance(values,dict) and bool(values),'empty probe identity set')
    require(hashes(values)==values,'probe source/dependency/artifact changed')
def validate_result(result,exit_code):
    fields={'status','device','pixel_count','pixel_rgba','mismatched_channels','rosetta_query',
        'rosetta_query_errno','command_status','directx_executed','guest_executed','scope'}
    require(type(exit_code) is int and exit_code==0,'native Metal probe did not exit successfully')
    require(isinstance(result,dict) and set(result)==fields,'Metal result fields missing or unknown')
    require(result['status']=='PASS' and isinstance(result['device'],str) and bool(result['device']),'Metal device/pass absent')
    for field,value in [('pixel_count',1024),('mismatched_channels',0),('rosetta_query',0),('command_status',4)]:
        require(type(result[field]) is int and result[field]==value,'Metal result mismatch: '+field)
    require(type(result['rosetta_query_errno']) is int and result['rosetta_query_errno'] in (0,2),'translation query failed')
    require(result['directx_executed'] is False and result['guest_executed'] is False,'unexpected claimed graphics scope')
    rgba=result['pixel_rgba'];expected=[64,128,191,255]
    require(isinstance(rgba,list) and len(rgba)==4 and all(type(v) is int and 0<=v<=255 and abs(v-e)<=1 for v,e in zip(rgba,expected)),
            'unexpected readback pixel')
    require(result['scope']=='native Metal clear and texture readback; not DXMT, shaders, triangle or GUI','unexpected Metal result scope')
def command(args,log):
    args=list(map(str,args));p=subprocess.run(args,text=True,capture_output=True)
    log.write_text(json.dumps(args)+'\n'+p.stdout+p.stderr)
    require(p.returncode==0,'probe command failed: '+str(log));return p.stdout

def build():
    OUT.mkdir(parents=True,exist_ok=True)
    clang=Path(subprocess.check_output(['xcrun','--find','clang'],text=True).strip())
    linker=Path(subprocess.check_output(['xcrun','--find','ld'],text=True).strip())
    sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip())
    flags=['-arch','arm64','-isysroot',sdk,'-fobjc-arc','-O2','-Wall','-Wextra','-Werror']
    deps=command([clang,*flags,'-M','-MT','probe',HERE/'metal_probe.m'],OUT/'dependencies.log')
    (OUT/'probe.d').write_text(deps)
    paths=[Path(p) for p in shlex.split(deps.replace('\\\n',' ').split(':',1)[1])]
    before=hashes([*paths,Path(__file__),clang,linker,Path('/usr/bin/xcrun'),Path(sys.executable),OUT/'probe.d'])
    command([clang,*flags,HERE/'metal_probe.m','-framework','Foundation','-framework','Metal','-o',OUT/'metal-probe'],OUT/'compile.log')
    identity=command(['file',OUT/'metal-probe'],OUT/'file.log');require('arm64' in identity,'probe is not ARM64')
    command(['otool','-L',OUT/'metal-probe'],OUT/'libraries.log');same(before)
    result={'schema':1,'status':'BUILT_NOT_RENDER_VERIFIED','inputs_before':before,'inputs_after':hashes(before),
        'executable':str(OUT/'metal-probe'),'executable_sha256':sha(OUT/'metal-probe'),
        'compiler':str(clang.resolve()),'linker':str(linker.resolve()),'python':str(Path(sys.executable).resolve()),
        'dependency_file':str(OUT/'probe.d'),
        'dependency_scope':'explicit compiler/header/tool inputs; system dyld cache not fully hashed'}
    (OUT/'build.json').write_text(json.dumps(result,indent=2)+'\n');return result

def verify_build():
    b=json.loads((OUT/'build.json').read_text());require(b.get('schema')==1 and b['status']=='BUILT_NOT_RENDER_VERIFIED','unexpected build record')
    require(Path(b['dependency_file']).resolve()==(OUT/'probe.d').resolve(),'unexpected C dependency record path')
    deps=Path(b['dependency_file']).read_text()
    paths=[Path(p) for p in shlex.split(deps.replace('\\\n',' ').split(':',1)[1])]
    required={str(p.resolve()) for p in [*paths,Path(__file__),Path(b['compiler']),Path(b['linker']),
        Path('/usr/bin/xcrun'),Path(b['python']),OUT/'probe.d']}
    require(str((HERE/'metal_probe.m').resolve()) in required,'Metal source absent from build closure')
    require(set(b['inputs_after'])==required,'probe build input closure incomplete or unknown')
    require(Path(b['executable']).resolve()==(OUT/'metal-probe').resolve(),'unexpected Metal executable path')
    require(b['inputs_before']==b['inputs_after'],'build identity mismatch');same(b['inputs_after'])
    require(sha(b['executable'])==b['executable_sha256'],'probe executable changed');return b

def execute(label):
    require(label in ('host','restricted'),'unknown execution label');b=verify_build()
    before=hashes([b['executable'],OUT/'build.json',Path(__file__)])
    p=subprocess.run([b['executable']],text=True,capture_output=True)
    log=OUT/(label+'.log');log.write_text(p.stdout+p.stderr)
    stdout=OUT/(label+'.stdout.json');stderr=OUT/(label+'.stderr.log')
    stdout.write_text(p.stdout);stderr.write_text(p.stderr)
    data=json.loads(p.stdout)
    same(before)
    accepted=True;validation_error=None
    try:validate_result(data,p.returncode)
    except RuntimeError as error:accepted=False;validation_error=str(error)
    record={'status':'PASS' if accepted else 'FAIL','label':label,'exit_code':p.returncode,'result':data,
        'inputs_before':before,'inputs_after':hashes(before),'log':str(log),'log_sha256':sha(log),
        'stdout':str(stdout),'stdout_sha256':sha(stdout),'stderr':str(stderr),'stderr_sha256':sha(stderr),
        'validation_error':validation_error,
        'scope':SCOPE}
    (OUT/(label+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2));return 0 if accepted else 2

def verify():
    b=verify_build();record=json.loads((OUT/'host.json').read_text())
    require(record['label']=='host' and record['scope']==SCOPE,'unexpected GPU record label or scope')
    require(record['status']=='PASS' and record['inputs_before']==record['inputs_after'],'host GPU record not successful')
    expected=hashes([b['executable'],OUT/'build.json',Path(__file__)])
    require(record['inputs_after']==expected,'GPU execution input closure incomplete or changed')
    same(record['inputs_after']);require(sha(record['log'])==record['log_sha256'],'GPU run log changed')
    require(Path(record['log']).resolve()==(OUT/'host.log').resolve() and
            Path(record['stdout']).resolve()==(OUT/'host.stdout.json').resolve() and
            Path(record['stderr']).resolve()==(OUT/'host.stderr.log').resolve(),'unexpected GPU log paths')
    for field in ('stdout','stderr'):require(sha(record[field])==record[field+'_sha256'],'GPU stream changed: '+field)
    stdout=Path(record['stdout']).read_text();stderr=Path(record['stderr']).read_text()
    require(json.loads(stdout)==record['result'] and Path(record['log']).read_text()==stdout+stderr,'GPU summary differs from actual output')
    require(record['validation_error'] is None,'GPU result has a validation error')
    validate_result(record['result'],record['exit_code'])
    return {'status':'PASS_CURRENT','scope':record['scope'],'evidence_sha256':sha(OUT/'host.json')}
if __name__=='__main__':
    p=argparse.ArgumentParser();group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--build',action='store_true');group.add_argument('--run',action='store_true');group.add_argument('--verify',action='store_true')
    p.add_argument('--label',choices=['host','restricted'],default='host');a=p.parse_args()
    if a.build:print(json.dumps({'status':build()['status']}))
    elif a.run:raise SystemExit(execute(a.label))
    else:print(json.dumps(verify()))
