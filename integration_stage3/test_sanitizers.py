#!/usr/bin/env python3
"""Instrument the actual lifted LLVM functions, not only the host runtime."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from memory_stage2.image_loader import load_image
from integration_stage3.build_lifter import LLVM
HERE=ROOT/'integration_stage3';OUT=ROOT/'build/integration-stage3/sanitizers'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args,env=None):
    p=subprocess.run(list(map(str,args)),text=True,capture_output=True,env=env)
    commands.append({'command':list(map(str,args)),'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    (OUT/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    if p.returncode:raise RuntimeError(p.stderr or p.stdout)
    return p.stdout
commands=[]

def main():
    OUT.mkdir(parents=True,exist_ok=True);(OUT/'evidence.json').write_text('{"status":"RUNNING"}\n')
    evidence=ROOT/'build/integration-stage3/memory/evidence.json';correct=json.loads(evidence.read_text())
    assert correct['status']=='PASS'
    for name,digest in correct['source_sha256'].items():assert sha(ROOT/name)==digest,('stale correctness',name)
    module=ROOT/'build/integration-stage3/memory/mutate'
    manifest=json.loads((module/'manifest.json').read_text())
    for name,digest in manifest['artifact_sha256'].items():assert sha(module/name)==digest,('stale artifact',name)
    image=load_image(ROOT/'build/integration-stage3/memory/fixtures/mutate.exe')
    pc=lambda raw: image.base+next(i['rva'] for i in manifest['instructions'] if i['bytes']==raw)
    header='#define IMAGE_BASE UINT64_C(%d)\n#define ENTRY_RVA %d\n#define EXIT_PC UINT64_C(0x7fff00000000)\n'%(image.base,image.entry_rva)
    header+='#define LOAD_PC UINT64_C(%d)\n#define STORE_PC UINT64_C(%d)\n#define RET_PC UINT64_C(%d)\n'%(pc('3301'),pc('8901'),pc('c3'))
    header+='static uint8_t image_bytes[]={'+','.join(map(str,image.data))+'};\n'
    header+='static const uint8_t image_permissions[]={'+','.join(map(str,image.permissions))+'};\n'
    header+='static const AotInstruction instructions[]={\n'
    for i in manifest['instructions']:
        header+='{%d,%d,%d,0,%d},\n'%(i['rva'],i['length'],i['kind'],i['target_rva'])
    header+='};\n';(OUT/'sanitizer-fixture.h').write_text(header)
    original=(module/'arm64.ll').read_text();lines=[];functions=0
    for line in original.splitlines():
        if line.startswith('define '):
            assert line.endswith('{');line=line[:-1]+'sanitize_address {';functions+=1
        lines.append(line)
    assert functions>0
    instrumented=OUT/'instrumented.ll';instrumented.write_text('\n'.join(lines)+'\n')
    obj=OUT/'instrumented.o'
    run([LLVM/'clang','-target','arm64-apple-macos11','-O2','-fsanitize=address','-fno-omit-frame-pointer',
         '-c',instrumented,'-o',obj])
    symbols=run(['xcrun','nm','-u',obj]);assert '___asan_report_' in symbols,'Lifted code was not instrumented'
    exe=OUT/'sanitized'
    sdk=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip()
    # Instrumented LLVM 17 objects must use the matching compiler-rt ABI, not
    # Apple's differently-versioned ASan runtime. The actual installed SDK is explicit.
    run([LLVM/'clang','-target','arm64-apple-macos11','-isysroot',sdk,'--ld-path=/usr/bin/ld',
         '-Wl,-syslibroot,'+sdk,
         '-std=c11','-O2','-g','-fno-omit-frame-pointer',
         '-fsanitize=address,undefined','-fno-sanitize-recover=all','-Wall','-Wextra','-Werror',
         '-I',OUT,HERE/'runtime.c',HERE/'sanitize.c',obj,'-o',exe])
    # The downloaded bottle keeps a placeholder install-name in compiler-rt.
    # Relocate a workspace-only copy; never mutate the stage2 toolchain.
    compiler_rt=LLVM.parent/'lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib'
    relocated=ROOT.parent.parent/'work/integration-stage3/sanitizer-runtime/libclang_rt.asan_osx_dynamic.dylib'
    relocated.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(compiler_rt,relocated)
    run(['install_name_tool','-id',relocated,relocated])
    run(['codesign','--force','--sign','-',relocated])
    old='@@HOMEBREW_PREFIX@@/opt/llvm@17/lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib'
    run(['install_name_tool','-change',old,relocated,exe])
    run(['codesign','--force','--sign','-',exe])
    env=os.environ.copy();env['ASAN_OPTIONS']='halt_on_error=1';env['UBSAN_OPTIONS']='halt_on_error=1'
    actual=json.loads(run([exe],env));assert actual['status']=='PASS'
    result={**actual,'scope':'ASan on actual lifted State accesses; ASan/UBSan on host runtime/harness; 2,000 random mapped load/store/fault/RET cases against C reference',
            'lifted_functions_instrumented':functions,'asan_undefined_symbols':symbols.splitlines(),
            'correctness_evidence_sha256':sha(evidence),'module_manifest_sha256':sha(module/'manifest.json'),
            'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in [HERE/'runtime.c',HERE/'runtime.h',HERE/'sanitize.c',HERE/'test_sanitizers.py']},
            'instrumented_ir_sha256':sha(instrumented),'executable_sha256':sha(exe)}
    result['compiler_rt']={'source_sha256':sha(compiler_rt),'relocated_sha256':sha(relocated),
                           'path':str(relocated),'scope':'workspace-only test tool dependency'}
    (OUT/'evidence.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(actual))

if __name__=='__main__':
    try:main()
    except Exception as error:
        OUT.mkdir(parents=True,exist_ok=True)
        (OUT/'evidence.json').write_text(json.dumps({'status':'FAIL','error':str(error)},indent=2)+'\n')
        raise
