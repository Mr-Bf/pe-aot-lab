#!/usr/bin/env python3
"""Real main/callback/RET LLVM ASan and C ASan/UBSan, plus actual PE mutants.

Uses the frozen native-bridge test helpers for dependency identity/instrumentation,
not its guest runtime. Own artifacts are confined to build/callback-bridge.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent;WORKSPACE=ROOT.parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from native_bridge.test_sanitizers import (require,sha,identity,unchanged,local_python_closure,run,instrument,LLVM)
from callback_bridge.bindings import Program
OUT=ROOT/'build/callback-bridge/sanitizers'
NAMES=('leaf','import','direct','nested','bad_nonvolatile','bad_return')


def fixture_header(program,fixture,name,path):
    image=program.image;labels=fixture['labels'];ins=program.manifest['instructions']
    main=[i for i in ins if image.entry_rva<=i['rva']<=labels['main_ret']]
    callback=[i for i in ins if labels['guest_callback']<=i['rva']<=labels['callback_ret']]
    main_step=next(i+1 for i,row in enumerate(main) if row['rva']==labels['main_call'])
    nested_step=main_step+next((i+1 for i,row in enumerate(callback) if row['rva']==labels.get('callback_call')),0)
    imports=image.imports
    prefix_steps=next((i+1 for i,row in enumerate(callback) if row['rva']==labels.get('callback_call')),0)
    iteration_steps=prefix_steps+sum(labels.get('callback_after_call',0)<=row['rva']<=labels['callback_ret'] for row in callback)+1 if name=='nested' else 0
    success_steps=(len(main)+1+2+sum(labels['callback_base']<=row['rva']<=labels['callback_base_ret'] for row in ins)) if name=='nested' else len(program.instructions)
    require(len(imports)<=2 and len(program.callbacks)==1,'sanitizer fixture profile expanded')
    values={'PreferredBase':image.preferred_base,'EntryRva':image.entry_rva,'CallbackRva':labels['guest_callback'],
            'MainAfterCallRva':labels['main_after_call'],'CallbackRetRva':labels['callback_ret'],
            'CallbackAfterCallRva':labels.get('callback_after_call',0),
            'InvokeThunkRva':next(row['target_rva'] for row in imports if row['signature']==3)}
    text='/* Identity-bound actual loaded PE/decoded roots; independent scalar oracle in C. */\n'
    for key,value in values.items():text+='static const uint64_t k%s=UINT64_C(%d);\n'%(key,value)
    text+='enum {kFixture=%d,kMutant=%d,kThunkCount=%d,kMainCallStep=%d,kNestedCallStep=%d,kSuccessSteps=%d,kNestedPrefixSteps=%d,kNestedIterationSteps=%d};\n'%(
        {'leaf':0,'import':1,'direct':2,'nested':3}.get(name,0),{'bad_nonvolatile':1,'bad_return':2}.get(name,0),
        len(imports),main_step,nested_step,success_steps,prefix_steps,iteration_steps)
    for label,values in [('IatRvas',[row['iat_rva'] for row in imports]),('ThunkRvas',[row['target_rva'] for row in imports])]:
        text+='static const uint64_t k%s[]={%s};\n'%(label,','.join('UINT64_C(%d)'%v for v in values))
    text+='static const uint8_t kImage[]={'+','.join(map(str,image.data))+'};\n'
    text+='static const uint8_t kImagePermissions[]={'+','.join(map(str,image.permissions))+'};\n'
    text+='static const AotInstruction kInstructions[]={'+','.join(
        '{%d,%d,%d,0,UINT64_C(%d)}'%(row.rva,row.length,row.kind,row.target_rva) for row in program.instructions)+'};\n'
    path.write_text(text)


def validate_report(report,name):
    require(report.get('status')=='PASS' and report.get('random_cases')==128,'missing callback runtime cases')
    mutant={'bad_nonvolatile':1,'bad_return':2}.get(name,0)
    require(report.get('mutant')==mutant,'wrong mutant identity')
    require(report.get('actual_lifted_roots') and report.get('whole_stack_image_check'),'missing actual roots/memory checks')
    require(report.get('preparation_faults')==(0 if mutant else 3),'preparation coverage')
    require(report.get('budget_cuts',0)>0 if not mutant else report.get('budget_cuts')==0,'budget coverage')
    require(report.get('depth_boundaries')==(2 if name=='nested' else 0),'depth boundary coverage')
    require(report.get('public_reentry_rejections')==128+report['preparation_faults']+report['budget_cuts']+report['depth_boundaries']+report.get('callback_boundary_full_state_checks',0),'public reentry coverage')
    require(report.get('callback_boundary_full_state_checks')==(0 if mutant else 1),'callback boundary full State missing')
    require(report.get('all_GPR_flags_on_success')==(not mutant),'register/flag coverage')


def verify_evidence(out=OUT):
    out=Path(out).resolve();evidence=json.loads((out/'evidence.json').read_text())
    require(evidence.get('schema')==1 and evidence.get('status')=='PASS','callback sanitizer evidence is not PASS')
    require(set(evidence['fixtures'])==set(NAMES),'sanitizer fixture set incomplete')
    require(evidence['inputs_before']==evidence['inputs_after'],'input identities changed')
    require(str(Path(__file__).resolve()) in evidence['inputs_before'],'producer identity absent')
    unchanged(evidence['inputs_before'])
    require(evidence['unique_normal_calls']==512 and evidence['unique_mutant_rejections']==256,'case totals changed')
    for name,record in evidence['fixtures'].items():
        require(record['inputs_before']==record['inputs_after'],'fixture input changed');unchanged(record['inputs_before'])
        require(record['reports']['plain']==record['reports']['sanitized'],'sanitizer replay differs')
        require(set(record['instrumented_lifted_functions'])=={'aot_entry','aot_callback_1040','aot_import_ret'},'actual LLVM root instrumentation incomplete')
        require(all(x>0 for x in record['instrumented_lifted_functions'].values()),'uninstumented root')
        for mode in ('plain','sanitized'):
            validate_report(record['reports'][mode],name)
            execution=record['executions'][mode]
            require(execution['inputs_before']==execution['inputs_after'],'executable changed');unchanged(execution['inputs_before'])
            require(sha(execution['log'])==execution['log_sha256'],'execution log changed')
    require(bool(evidence['artifacts_sha256']),'empty artifact closure')
    for relative,digest in evidence['artifacts_sha256'].items():require(sha(ROOT/relative)==digest,'artifact changed: '+relative)
    return evidence


def main(out=OUT):
    out=Path(out).resolve()
    require(out.is_relative_to(ROOT/'build/callback-bridge'),'must use isolated callback build directory')
    out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json'
    if evidence.exists():
        history=out/'history';history.mkdir(exist_ok=True);(history/(sha(evidence)+'.json')).write_bytes(evidence.read_bytes())
    evidence.write_text('{"status":"RUNNING"}\n')
    initial=[HERE/name for name in ('test_sanitizers.py','review_runtime.c','runtime.c','runtime.h','bindings.py',
                                  'loader.py','imports_v1.py','fixtures.py','lift.py')]
    initial += list(local_python_closure(initial))
    initial += [ROOT/'integration_stage3/runtime.c',ROOT/'integration_stage3/runtime.h',ROOT/'memory_stage2/guest_memory.h',
                ROOT/'build/callback-bridge/fixtures/manifest.json',*[ROOT/'build/callback-bridge/fixtures'/(n+'.exe') for n in NAMES[:4]],
                Path(sys.executable),LLVM/'clang',LLVM/'opt',LLVM/'llvm-symbolizer',
                *[Path(shutil.which(n)) for n in ['xcrun','nm','otool','codesign','install_name_tool']]]
    before=identity(initial)
    try:
        fixtures=json.loads((ROOT/'build/callback-bridge/fixtures/manifest.json').read_text())
        sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip())
        asan_source=LLVM.parent/'lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib'
        support=WORKSPACE/'work/callback-bridge/sanitizers-runtime';support.mkdir(parents=True,exist_ok=True)
        asan_copy=support/asan_source.name;asan_copy.write_bytes(asan_source.read_bytes())
        run(['install_name_tool','-id',asan_copy,asan_copy],out/'asan-runtime-id.log')
        run(['codesign','--force','--sign','-',asan_copy],out/'asan-runtime-sign.log')
        all_inputs=dict(before);records={};artifacts=[]
        for name in NAMES:
            folder=out/name;folder.mkdir(exist_ok=True)
            source_name=name if name in NAMES[:4] else 'leaf';fixture=fixtures[source_name]
            original=ROOT/'build/callback-bridge/fixtures'/(source_name+'.exe');require(sha(original)==fixture['pe_sha256'],'stale fixture')
            raw=original.read_bytes();pe=folder/'input.exe';mutation=None
            if name not in NAMES[:4]:
                offset=512+fixture['callback_rva']-0x1000
                require(raw[offset:offset+3]==bytes.fromhex('4889c8'),'unexpected callback initial MOV')
                replacement=bytes.fromhex('4889cb' if name=='bad_nonvolatile' else '519090')
                mutation={'file_offset':offset,'old_hex':'4889c8','new_hex':replacement.hex(),'original_pe_sha256':sha(original)}
                raw=raw[:offset]+replacement+raw[offset+3:]
            pe.write_bytes(raw)
            callback={'rva':fixture['callback_rva'],'symbol':'aot_callback_'+format(fixture['callback_rva'],'x'),'signature':1}
            program=Program(pe,folder/'program',optimization='O3',callbacks=[callback]);program._verify_lifts()
            header=folder/'sanitizer_fixture.h';fixture_header(program,fixture,name,header)
            common=[LLVM/'clang','-target','arm64-apple-macos11','-isysroot',sdk,'-Wl,-syslibroot,'+str(sdk),
                    '-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-I',HERE,'-I',folder,'-I',program.out]
            command=[LLVM/'clang','-target','arm64-apple-macos11','-isysroot',sdk,'-std=c11','-O1',
                     '-fsanitize=address,undefined','-I',HERE,'-I',folder,'-I',program.out,'-M','-MT','callback-driver',HERE/'review_runtime.c']
            dep_text=run(command,folder/'dependencies.log');(folder/'runtime.d').write_text(dep_text)
            dependencies=[Path(p) for p in shlex.split(dep_text.replace('\\\n',' ').split(':',1)[1])]
            dependencies += [pe,asan_source,asan_copy,program.library_path,program.out/'program-build.json',header]
            for file,digest in program.build_manifest['native_inputs'].items():require(sha(file)==digest,'native input changed');dependencies.append(Path(file))
            roots=[(r['symbol'],r['directory'],r['manifest']) for r in program.roots]
            roots.append(('aot_import_ret',program.out/'ret-shim',program.ret_manifest))
            for symbol,directory,manifest in roots:
                dependencies.append(directory/'manifest.json')
                for relative,digest in manifest['artifact_sha256'].items():
                    p=directory/relative;require(sha(p)==digest,'lift artifact changed');dependencies.append(p)
                for group in ('source_sha256','external_source_sha256'):
                    for relative,digest in manifest[group].items():
                        p=ROOT/relative;require(sha(p)==digest,'lift source changed');dependencies.append(p)
            inputs=identity([*initial,*dependencies]);all_inputs.update(inputs)
            objects=[];plain_objects=[];instrumented={}
            for symbol,directory,_ in roots:
                ir=folder/(symbol+'-asan.ll');obj=folder/(symbol+'-asan.o')
                instrumented[symbol]=instrument(directory/'arm64.ll',ir)
                run([LLVM/'clang','-target','arm64-apple-macos11','-O1','-fsanitize=address','-c',ir,'-o',obj],folder/(symbol+'-build.log'))
                symbols=run(['nm',obj],folder/(symbol+'-symbols.log'));require('__asan_report_' in symbols,'actual LLVM has no ASan checks: '+symbol)
                objects.append(obj);plain_objects.append(directory/'arm64.o');artifacts += [ir,obj]
            plain=folder/'callback-plain';sanitized=folder/'callback-sanitized'
            run(common+[HERE/'review_runtime.c',*plain_objects,'-o',plain],folder/'compile-plain.log')
            run(common+['-fsanitize=address,undefined',HERE/'review_runtime.c',*objects,'-o',sanitized],folder/'compile-sanitized.log')
            linked=run(['otool','-L',sanitized],folder/'linked.log')
            names=[line.strip().split(' (',1)[0] for line in linked.splitlines()[1:] if asan_source.name in line]
            require(len(names)==1,'ASan runtime linkage ambiguous')
            run(['install_name_tool','-change',names[0],asan_copy,sanitized],folder/'asan-link.log')
            run(['codesign','--force','--sign','-',sanitized],folder/'asan-sign.log')
            env={**os.environ,'ASAN_OPTIONS':'halt_on_error=1:detect_leaks=0','UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1',
                 'ASAN_SYMBOLIZER_PATH':str(LLVM/'llvm-symbolizer')}
            reports={};executions={}
            for mode,exe,environment in [('plain',plain,None),('sanitized',sanitized,env)]:
                stable=identity([exe,asan_copy,*objects] if mode=='sanitized' else [exe]);log=folder/(mode+'-run.log')
                report=json.loads(run([exe],log,environment));validate_report(report,name);unchanged(stable)
                reports[mode]=report;executions[mode]={'inputs_before':stable,'inputs_after':identity(stable),'log':str(log),'log_sha256':sha(log)}
            require(reports['plain']==reports['sanitized'],'sanitized replay differs')
            require(run(command,folder/'dependencies-recheck.log')==dep_text,'dependency closure changed')
            program._verify_lifts();unchanged(inputs)
            records[name]={'status':'PASS','input_pe_sha256':sha(pe),'mutation':mutation,'reports':reports,'executions':executions,
                           'instrumented_lifted_functions':instrumented,'inputs_before':inputs,'inputs_after':identity(inputs)}
            artifacts += [plain,sanitized,header,pe,*folder.glob('*.log'),folder/'runtime.d']
        unchanged(before);unchanged(all_inputs)
        report={'schema':1,'status':'PASS','fixtures':records,'unique_normal_calls':512,'unique_mutant_rejections':256,
                'unique_preparation_faults':12,'budget_cuts':sum(r['reports']['plain']['budget_cuts'] for r in records.values()),
                'inputs_before':all_inputs,'inputs_after':identity(all_inputs),
                'artifacts_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sorted(set(artifacts))},
                'scope':'Actual original PE main/callback and compatibility RET LLVM ASan; actual C runtime ASan/UBSan. Trusted host metadata and stable allocations.',
                'limits':['not a proof of LLVM noalias/provenance validity','LeakSanitizer disabled; no leak-free claim',
                          'not Windows exceptions, asynchronous callbacks, arbitrary callback signatures, or DLL execution'],
                'sanitizer_environment':{k:env[k] for k in ('ASAN_OPTIONS','UBSAN_OPTIONS','ASAN_SYMBOLIZER_PATH')}}
        evidence.write_text(json.dumps(report,indent=2)+'\n');verify_evidence(out)
        print(json.dumps({'status':'PASS','normal_calls':512,'mutant_rejections':256,'preparation_faults':12,'budget_cuts':report['budget_cuts']}))
    except Exception as error:
        evidence.write_text(json.dumps({'status':'FAIL','error':str(error)},indent=2)+'\n');raise


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    if args.verify:verify_evidence(args.out);print('{"status":"PASS_CURRENT"}')
    else:main(args.out)
