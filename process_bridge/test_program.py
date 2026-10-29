#!/usr/bin/env python3
"""Independent ARM64 executables/App, actual PE exit semantics and x86 oracle."""
import argparse,hashlib,json,os,shutil,struct,subprocess,sys,tempfile,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from process_bridge.bindings import Program,sha,snapshot,unchanged,python_closure
from process_bridge.build_app import build,FIXTURES,OUT as NATIVE_OUT
from process_bridge.oracle import Oracle
OUT=ROOT/'build/process-bridge/program-tests'
NAMES=('normal','open_exit','after_exit','return_only')
API_NAMES={4:'CreateFileA',5:'WriteFile',6:'ReadFile',7:'CloseHandle',8:'GetLastError',9:'ExitProcess'}
def require(value,message):
    if not value:raise RuntimeError(message)
def sources():
    paths=python_closure([Path(__file__),HERE/'fixtures.py',HERE/'oracle.py'])
    paths.update([HERE/'native_host.c',HERE/'runtime.c',HERE/'runtime.h',HERE/'process_fixture.c',HERE/'kernel32.def',
        HERE/'oracle_x86.c',HERE/'oracle_file_stubs.h',FIXTURES,ROOT/'file_bridge/file_roundtrip.c',
        ROOT/'integration_stage3/runtime.c',ROOT/'integration_stage3/runtime.h',ROOT/'memory_stage2/guest_memory.h'])
    fixtures=json.loads(FIXTURES.read_text())
    for record in fixtures.values():
        paths.add(Path(record['pe_path']))
        for name,digest in record['source_sha256'].items():
            path=ROOT/name;require(sha(path)==digest,'fixture source stale: '+name);paths.add(path)
    return paths
def normalize(result,metadata):
    normalized=dict(result['observations'])
    require(set(normalized)==set(metadata['observations']),'observation closure mismatch')
    for name,item in metadata['observations'].items():
        raw=bytes.fromhex(normalized[name]);require(len(raw)==item['size'],'observation size')
        if item.get('kind')=='image_pointer':
            require(int.from_bytes(raw,'little')==result['image_base']+item['target_rva'],'native image pointer was not rebased')
            normalized[name]=item['target_rva'].to_bytes(item['size'],'little').hex()
    return normalized
def check_normal(result,metadata,reference,directory):
    exited=metadata['expected_exit_code'] is not None
    require(result['outcome']==('PROCESS_EXITED' if exited else 'FUNCTION_RETURN'),'ExitProcess confused with function return')
    require(result['aot_status']==(11 if exited else 0) and result['host_returncode']==(0 if exited else 2),'host/process status mismatch')
    require(result['exit_requested']==int(exited) and result['returned']==int(not exited) and not result['fault']['status'],
            'exit synthesized a RET or an AotFault')
    require(result['entry_arguments']==0 and result['entry_rva']==metadata['entry_rva'],'not the original no-argument PE entry')
    require(result['exit_code']==(metadata['expected_exit_code'] or 0),'full 32-bit exit code was truncated')
    if exited:
        require(result['exit_pc']==result['rip'] and result['exit_rsp']==result['rsp'] and
                result['exit_depth']==result['call_depth']>=metadata['minimum_active_guest_call_depth'],
                'ExitProcess did not retain its actual CALL boundary')
    else:require(result['api_calls']==0 and result['call_depth']==0 and result['steps']==1,'return-only registered or executed an API')
    counts={API_NAMES[int(key)]:value for key,value in result['call_counts'].items()}
    require(counts==metadata['expected_api_calls']==reference['call_counts'],'original x86 API path differs')
    require(result['api_calls']==sum(counts.values())==reference['api_calls'],'API total differs')
    require(result['open_before_cleanup']==result['cleanup_closes']==metadata['expected_cleanup_closes']==reference['cleanup_closes'],
            'abrupt exit handle ownership/cleanup differs')
    require(result['open_after_cleanup']==result['cleanup_errors']==0,'native executable leaked owned file handles')
    require(normalize(result,metadata)==reference['normalized_observations'],'original x86 static image observations differ')
    require(list(struct.unpack('<4I',bytes.fromhex(result['observations']['process_result'])))==metadata['expected_file_result'],
            'static guest FileResult differs')
    for marker in metadata['post_exit_markers']:
        names=[name for name,item in metadata['observations'].items() if item['rva']==marker['target_rva'] and item['size']==4]
        require(len(names)==1,'post-exit marker has no unique DWORD observation')
        require(result['observations'][names[0]]=='00000000','instruction after ExitProcess executed: '+names[0])
    target=Path(directory)/metadata['filename'];disk=target.read_bytes() if target.exists() else None
    require(disk==reference['disk_data'],'actual native disk differs from original x86 execution')
    return disk
def verify_evidence(out=OUT):
    out=Path(out).resolve();e=json.loads((out/'evidence.json').read_text())
    require(e.get('schema')==1 and e.get('status')=='PASS','standalone process evidence not PASS')
    require(e['inputs_before']==e['inputs_after'],'process test input changed during execution')
    require(set(map(str,sources()))<=set(e['inputs_before']),'process source closure incomplete')
    unchanged(e['inputs_before'])
    require(e['unique_pe_variants']==4 and e['raw_x86_executions']==8 and e['native_modes']==['O3','O0'],'process coverage missing')
    for path,digest in e['artifacts_sha256'].items():require(sha(path)==digest,'process artifact changed: '+path)
    return e

def run(out,native_out):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json'
    if evidence.exists():
        (out/'history').mkdir(exist_ok=True);(out/'history'/(sha(evidence)+'.json')).write_bytes(evidence.read_bytes())
    evidence.write_text('{"status":"RUNNING"}\n')
    before=snapshot(sources());inputs=dict(before);artifacts=[];records=[]
    try:
        metadata=json.loads(FIXTURES.read_text());references={}
        for name in NAMES:
            oracle=Oracle(metadata[name]['pe_path'],out/'oracle'/name,metadata=metadata[name])
            references[name]=oracle.run()
            rebased=oracle.run(base_hint=0x180000000)
            require(rebased['normalized_observations']==references[name]['normalized_observations'],'raw-x86 rebase changed state')
            require(oracle.last_run['inputs_before']==oracle.last_run['inputs_after'] and
                    oracle.last_run['artifacts_before']==oracle.last_run['artifacts_after'],'oracle identity changed')
            inputs.update({p:r['sha256'] for p,r in oracle.last_run['inputs_before'].items()})
            inputs.update(oracle.last_run['artifacts_before']);artifacts.extend((out/'oracle'/name).rglob('*'))
        programs,build_result=build(native_out)
        artifacts.extend(Path(native_out).rglob('*'))
        for mode in ('O3','O0'):
            for name in NAMES:
                record=metadata[name]
                program=programs[name] if mode=='O3' else Program(record['pe_path'],out/'O0'/name,'O0',record,[FIXTURES])
                inputs.update(program.build_manifest['native_inputs']);inputs[str(program.executable)]=program.executable_sha256
                artifacts.extend(program.out.rglob('*'))
                directory=out/'io'/mode/name;directory.mkdir(parents=True,exist_ok=True)
                target=directory/record['filename']
                if target.exists():target.unlink()
                successful=None
                # Each launch is a separate native process. Repeats test fresh BSS/session state.
                for index,base in enumerate((None,None,0x180000000)):
                    log=directory/('launch-%d.log'%index)
                    result=program.run(directory,base=base,log_path=log)
                    disk=check_normal(result,record,references[name],directory)
                    if name!='return_only':require(result['last_error']==(0 if index==0 else 183),'repeat launch LastError semantics')
                    records.append({'kind':'launch','mode':mode,'variant':name,'launch':index,'result':result,
                        'disk_sha256':hashlib.sha256(disk).hexdigest() if disk is not None else None})
                    successful=result;artifacts.append(log)
                if target.exists():artifacts.append(target)
                if name!='return_only':
                    # Exit's committed CALL may consume the last budget step;
                    # no synthetic RET step is required after ExitProcess.
                    for budget in sorted({1,successful['steps']-1,successful['steps']}):
                        limited=out/'budget'/mode/name/str(budget);limited.mkdir(parents=True,exist_ok=True)
                        file=limited/record['filename']
                        if file.exists():file.unlink()
                        log=limited/'launch.log';result=program.run(limited,budget=budget,log_path=log)
                        if budget==successful['steps']:check_normal(result,record,references[name],limited)
                        else:
                            require(result['outcome']=='FAULT' and result['aot_status']==4 and result['fault']['status']==4 and
                                    result['steps']==budget and result['host_returncode']==3 and not result['exit_requested'],
                                    'process boundary budget did not stop before ExitProcess')
                            require(result['open_after_cleanup']==result['cleanup_errors']==0 and
                                    result['cleanup_closes']==result['open_before_cleanup'],'budget fault leaked handle')
                        records.append({'kind':'budget','mode':mode,'variant':name,'budget':budget,'result':result})
                        artifacts.append(log)
                        if file.exists():artifacts.append(file)
        # Move the signed App away from the build tree and launch its binary
        # with no usable PATH. It must not find Python or the original PE file.
        source_app=Path(build_result['app']['app']);copy_root=Path(tempfile.mkdtemp(prefix='relocated-app-',dir=out))
        relocated=copy_root/source_app.name;shutil.copytree(source_app,relocated)
        app_exe=relocated/'Contents/MacOS/process-demo'
        require(sha(app_exe)==build_result['app']['app_executable_sha256'],'App copy executable identity')
        directory=copy_root/'data';directory.mkdir();stable=snapshot([app_exe])
        command=[str(app_exe),'--data-dir',str(directory)]
        execution=subprocess.run(command,cwd=copy_root,env={'PATH':'/nonexistent'},capture_output=True,text=True)
        unchanged(stable)
        (copy_root/'launch.log').write_text(json.dumps(command)+'\n'+execution.stdout+execution.stderr)
        require(not execution.stderr,'relocated native App wrote unexpected stderr')
        result=json.loads(execution.stdout);result['host_returncode']=execution.returncode
        check_normal(result,metadata['normal'],references['normal'],directory)
        verified=subprocess.run(['codesign','--verify','--deep','--strict',str(relocated)],capture_output=True,text=True)
        require(verified.returncode==0,'relocated App signature invalid: '+verified.stderr)
        records.append({'kind':'relocated_app_no_path','result':result,'executable_sha256':sha(app_exe),'cwd':str(copy_root)})
        inputs.update(stable);artifacts.extend(copy_root.rglob('*'))
        # CLI configuration errors are host errors, never invented guest exits.
        for arguments in ([],['--data-dir',str(directory),'--budget','0'],['--data-dir',str(directory),'--base','1']):
            execution=subprocess.run([str(app_exe),*arguments],env={'PATH':'/nonexistent'},capture_output=True,text=True)
            result=json.loads(execution.stdout)
            require(execution.returncode==64 and result['outcome']=='HOST_ERROR' and not execution.stderr,'invalid host CLI accepted')
            records.append({'kind':'host_cli_rejection','arguments':arguments,'result':result})
        unchanged(before);unchanged(inputs)
        result={'schema':1,'status':'PASS','unique_pe_variants':4,'raw_x86_executions':8,'native_modes':['O3','O0'],
            'native_launches':sum(r['kind'] in ('launch','budget','relocated_app_no_path','host_cli_rejection') for r in records),
            'python_optimized':not __debug__,'records':records,'inputs_before':inputs,'inputs_after':snapshot(inputs),
            'artifacts_sha256':{str(p.resolve()):sha(p) for p in sorted(set(artifacts)) if p.is_file() and p.name!='.program-build.lock'},
            'app':build_result['app']['app'],'limits':['restricted no-argument PE entry, not complete Windows startup/CRT/TLS/SEH',
                'original x86 oracle runs on Rosetta, not Windows','ad-hoc signed CLI App foundation, no GUI/notarization/default data-directory creation',
                'only explicit file APIs and ExitProcess; trusted host metadata and allocations']}
        evidence.write_text(json.dumps(result,indent=2)+'\n');verify_evidence(out)
        print(json.dumps({'status':'PASS','unique_pe_variants':4,'native_launches':result['native_launches'],'app':result['app']}))
    except Exception as error:
        failure={'status':'FAIL','error':str(error),'traceback':traceback.format_exc(),'inputs_before':before,'records':records,
                 'build_logs':{str(p):p.read_text() for p in Path(native_out).rglob('native-build.log')}}
        evidence.write_text(json.dumps(failure,indent=2)+'\n')
        if not (out/'first-failure.json').exists():(out/'first-failure.json').write_bytes(evidence.read_bytes())
        raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT)
    parser.add_argument('--native-out',type=Path,default=NATIVE_OUT);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    if args.verify:print(json.dumps({'status':'PASS_CURRENT','native_launches':verify_evidence(args.out)['native_launches']}))
    else:run(args.out,args.native_out)
