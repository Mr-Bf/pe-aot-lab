#!/usr/bin/env python3
"""Read-only process/App acceptance: existing evidence, hashes and dependency discovery.

No PE or native application is executed. Optional --record only saves this
aggregate result; it never rewrites producer/test or historical failure evidence.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from process_bridge.test_program import verify_evidence as verify_program
from process_bridge.test_sanitizers import verify_evidence as verify_sanitizers

BASE=ROOT/'build/process-bridge'
NAMES={'normal','open_exit','after_exit','return_only'}
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise ValueError(message)
def read(path):return json.loads(Path(path).read_text())
def checked_hashes(values,base=None):
    require(bool(values),'empty input/artifact hash collection')
    for name,item in values.items():
        path=(base/name) if base else Path(name)
        if isinstance(item,dict):
            realpath=item.get('realpath',item.get('resolved'))
            require(realpath is not None and str(path.resolve())==realpath,'dependency target changed: '+name)
            digest=item['sha256']
        else:digest=item
        require(sha(path)==digest,'input/artifact changed: '+str(path))

def verify():
    fixture_path=BASE/'fixtures/evidence.json';fixture=read(fixture_path)
    require(fixture['status']=='BUILD_AND_DECODE_PASS_NOT_EXECUTED','fixture preparation status changed')
    require(set(fixture['variants'])==NAMES and set(fixture['cases'])==NAMES,'fixture closure incomplete')
    require(fixture['inputs_before']==fixture['inputs_after'],'fixture inputs changed during build')
    checked_hashes(fixture['inputs_after']);checked_hashes(fixture['source_sha256'],ROOT)
    checked_hashes(fixture['artifact_sha256'],BASE/'fixtures')
    tail=fixture['default_tailcall_experiment']
    require(tail['status']=='REJECT' and tail['returncode']!=0,'recorded unsupported tailcall experiment missing')

    oracle_path=BASE/'oracle-tests/evidence.json';oracle=read(oracle_path)
    require(oracle['status']=='PASS' and set(oracle['variants'])==NAMES and
            oracle['raw_no_argument_pe_invocations']==8 and oracle['replays_per_variant']==2 and
            oracle['process_exit_cases']==6 and oracle['function_return_cases']==2 and
            oracle['wrapper_rejections']==4,'oracle self-test coverage incomplete')
    require(len(oracle['runs'])==8 and len(oracle['rejected'])==4 and
            all(row['status']=='REJECT' for row in oracle['rejected']),'oracle recorded counts differ')
    for prefix in ('source','inputs'):
        require(oracle[prefix+'_before']==oracle[prefix+'_after'],'oracle '+prefix+' changed during test')
        checked_hashes(oracle[prefix+'_after'])
    checked_hashes(oracle['artifact_sha256'])
    for run in oracle['runs']:
        require(run['status']=='PASS' and run['inputs_before']==run['inputs_after'] and
                run['artifacts_before']==run['artifacts_after'],'individual oracle run identity changed')
        require(sha(run['evidence_path'])==run['evidence_sha256'],'oracle run record changed')
        checked_hashes(run['tool_sha256']);checked_hashes(run['dependency_sha256'])
    require(not oracle['windows_execution'] and not oracle['wine_execution'],'oracle execution scope changed')

    program_path=BASE/'program-tests/evidence.json';program=verify_program(BASE/'program-tests')
    counts=Counter(row['kind'] for row in program['records'])
    require(counts==Counter({'launch':24,'budget':18,'relocated_app_no_path':1,'host_cli_rejection':3}),
            'standalone launch coverage differs')
    require(program['native_launches']==sum(counts.values())==46 and program['raw_x86_executions']==8,
            'native/raw replay counts differ')
    for mode in ('O3','O0'):
        for name in NAMES:
            rows=[row for row in program['records'] if row['kind']=='launch' and row['mode']==mode and row['variant']==name]
            require(len(rows)==3 and {row['launch'] for row in rows}=={0,1,2},'missing repeat/rebase launches')
            require({row['result']['image_base'] for row in rows}=={0x140000000,0x180000000},'native rebase coverage missing')
            for row in rows:
                result=row['result'];exited=name!='return_only'
                require(result['outcome']==('PROCESS_EXITED' if exited else 'FUNCTION_RETURN') and
                        result['host_returncode']==(0 if exited else 2) and result['returned']==int(not exited),
                        'process exit/function return distinction absent')

    native_path=BASE/'native/build.json';native=read(native_path)
    require(native['status']=='BUILT_NATIVE_AND_APP_NOT_EXECUTED' and set(native['programs'])==NAMES,
            'native producer closure changed')
    checked_hashes(native['sources'])
    for row in native['programs'].values():
        require(sha(row['program_build'])==row['program_build_sha256'] and
                sha(row['executable'])==row['executable_sha256'],'standalone producer artifact changed')
        built=read(row['program_build'])
        require(built['status']=='BUILT_NATIVE_NOT_EXECUTED' and
                built['native_inputs']==built['native_inputs_after'],'native build identity changed')
        require(built['runtime_dependencies']==['/usr/lib/libSystem.B.dylib'],'unexpected native runtime dependency')
        checked_hashes(built['native_inputs'])
    app_path=BASE/'native/app/app-build.json';app=read(app_path)
    require(app==native['app'] and app['status']=='BUILT_APP_NOT_EXECUTED','App producer record changed')
    require(app['inputs_before']==app['inputs_after'],'App signing inputs changed')
    checked_hashes(app['inputs_after']);checked_hashes(app['artifacts_sha256'])
    app_root=Path(app['app'])
    require(str(app_root)==program['app'] and sha(app['executable'])==app['app_executable_sha256'],'tested App identity mismatch')
    entries=list(app_root.rglob('*'))
    require(not any(p.is_symlink() for p in entries),'generated standalone App acquired a symlink')
    require({str(p) for p in entries if p.is_file()}==set(app['artifacts_sha256']),'App file closure incomplete or changed')

    sanitizer_path=BASE/'sanitizers/evidence.json';sanitizer=verify_sanitizers(BASE/'sanitizers')
    reports={name:record['reports']['plain'] for name,record in sanitizer['fixtures'].items()}
    # audited_entry performs exactly one public reentry check per real lifted
    # execution. The three private boundary tests use four executions (before/
    # after State comparison is two), so adding case labels would undercount.
    actual_executions=sum(report['public_reentry_checks'] for report in reports.values())
    budget_cuts=sum(report['budget_cuts'] for report in reports.values())
    terminal_checks=sum(report['terminal_no_mutation_checks'] for report in reports.values())
    require(actual_executions==669 and budget_cuts==576 and terminal_checks==651,'sanitizer execution coverage changed')

    # The prior failed consumer misread a metadata record as a string key. Its
    # source hashes are historical, intentionally not required to match today.
    failed_path=BASE/'program-tests/first-failure.json';failed=read(failed_path);failed_sha=sha(failed_path)
    require(failed['status']=='FAIL' and 'unhashable type' in failed['error'] and
            'TypeError' in failed['traceback'],'recorded first consumer failure missing')
    history=BASE/'program-tests/history'/(failed_sha+'.json')
    require(sha(history)==failed_sha,'historical failure copy changed')
    evidence_paths=[fixture_path,BASE/'fixtures/manifest.json',oracle_path,program_path,native_path,app_path,sanitizer_path]
    return {'schema':1,'status':'ACCEPTANCE_CURRENT','mode':'existing_evidence_hashes_and_C_dependency_discovery_only',
        'python_optimized':not __debug__,'unique_original_pe_variants':4,
        'program_raw_x86_executions':program['raw_x86_executions'],'native_launches':program['native_launches'],
        'native_launch_breakdown':dict(counts),'oracle_selftest_raw_executions':oracle['raw_no_argument_pe_invocations'],
        'oracle_selftest_wrapper_rejections':oracle['wrapper_rejections'],'native_modes':program['native_modes'],
        'sanitizer_pe_profiles':len(reports),'sanitizer_actual_lifted_executions_per_mode':actual_executions,
        'sanitizer_budget_cuts_per_mode':budget_cuts,'sanitizer_terminal_state_checks_per_mode':terminal_checks,
        'sanitizer_modes':['plain','actual lifted LLVM ASan + C ASan/UBSan'],
        'app':str(app_root),'app_executable_sha256':app['app_executable_sha256'],
        'historical_failure':{'path':str(failed_path.relative_to(ROOT)),'sha256':failed_sha,
            'status':'RETAINED_NOT_CURRENT_FAILURE','resolution':'consumer maps post-exit target_rva to its unique DWORD observation'},
        'evidence_sha256':{str(path.relative_to(ROOT)):sha(path) for path in evidence_paths},
        'verifier_sha256':sha(__file__),
        'scope':'restricted no-argument PE, file APIs and ExitProcess in an ARM64 CLI App; no GUI, notarization, full Windows startup, or performance claim'}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--record',type=Path);args=parser.parse_args()
    output=json.dumps(verify(),indent=2)+'\n'
    if args.record:args.record.write_text(output)
    print(output,end='')
