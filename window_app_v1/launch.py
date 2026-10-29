"""Supervise one no-argument App process; external CUA supplies OS input.

No synthetic queue, guest state injection, file rewriting, or implicit retry.
Raw stdout/stderr and before/after data snapshots are retained even on failure.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

from window_app_v1 import package
from window_app_v1.noarg import require,write
from graphics_stage5 import d3d11_probe as g


def files(directory):
    if not directory.exists():return {}
    result={}
    for p in directory.rglob('*'):
        require(not p.is_symlink(),'unexpected data symlink')
        if p.is_file():result[str(p.relative_to(directory))]=dict(sha256=g.sha(p),size=p.stat().st_size)
        else:require(p.is_dir(),'unexpected data file kind')
    return result


def main(build,out,relocated=False,timeout=180):
    build=package.output(build);out=Path(out).resolve()
    require(out.parent==package.ROOT/'build/window-app-v1','separate execution output required')
    require(type(timeout)is int and 30<=timeout<=300,'supervision must be 30..300 seconds')
    require(not out.exists(),'fresh execution output required');out.mkdir(parents=True)
    (out/'cache/dxmt').mkdir(parents=True)
    package_record=package.verify(build)
    app=Path(package_record['relocated' if relocated else 'app']);exe=app/'Contents/MacOS/pe-aot-window'
    identifier=package_record['spec']['identifier'];support=Path.home()/'Library/Application Support'/identifier
    data=support/'Data';runs=support/'Runs'
    existing_runs={p.name for p in runs.iterdir()} if runs.exists() else set()
    before=files(data)
    if data.exists():shutil.copytree(data,out/'data-before')
    record=dict(schema=1,status='STARTED_NOT_ACCEPTED',build=str(build),package_receipt_sha256=g.sha(build/'evidence.json'),
                app=str(app),executable_sha256=g.sha(exe),command=[str(exe)],argv_count=1,
                identifier=identifier,expected_support=str(support),data_before=before,
                existing_run_directories=sorted(existing_runs),relocated=relocated,timeout_seconds=timeout,
                launch_kind='direct bundled executable with no extra arguments; not Finder or LaunchServices',
                input_kind='external CUA OS events; not TEST_QUEUE or a physical-keyboard claim',
                started_unix_ns=time.time_ns())
    write(out/'started.json',record)
    stdout=out/'stdout';stderr=out/'stderr';child=None
    try:
        with stdout.open('xb') as o,stderr.open('xb') as e:
            child=subprocess.Popen([str(exe)],stdout=o,stderr=e,env=g.environment(out,images=True))
            record['pid']=child.pid
            write(out/'launched.json',dict(pid=child.pid,command=[str(exe)],started_unix_ns=record['started_unix_ns']))
            print(json.dumps(dict(status='LIVE_NATIVE_APP_PROCESS',pid=child.pid,app=str(app),identifier=identifier)),flush=True)
            timed_out=False
            try:code=child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out=True;child.terminate()
                try:code=child.wait(timeout=3)
                except subprocess.TimeoutExpired:child.kill();code=child.wait(timeout=3)
        record.update(returncode=code,external_timeout=timed_out,ended_unix_ns=time.time_ns(),
                      stdout_sha256=g.sha(stdout),stderr_sha256=g.sha(stderr),data_after=files(data))
        if data.exists():shutil.copytree(data,out/'data-after')
        new_runs=sorted({p.name for p in runs.iterdir()}-existing_runs) if runs.exists() else []
        record['new_run_directories']=new_runs
        for name in new_runs:shutil.copytree(runs/name,out/'wrapper-runs'/name)
        require(not timed_out,'supervision expired; termination is not normal guest exit')
        require(code==0,'actual App process failed')
        result=g.strict_json(stdout.read_text());record['result']=result
        require(result['outcome']=='PROCESS_EXITED' and result['exit_code']==0 and result['proc_translated']==0,'guest/ISA result differs')
        require(result['test_queue']['requested']==0 and result['test_queue']['posted']==0,'unexpected test queue')
        require(len(new_runs)==1,'exactly one App wrapper run expected')
        start=g.read_json(runs/new_runs[0]/'entry-started.json');finish=g.read_json(runs/new_runs[0]/'entry-finished.json')
        require(start['pid']==finish['pid']==child.pid and start['argument_count']==1,'wrapper process identity differs')
        require(start['bundle_identifier']==identifier and Path(start['bundle_path']).resolve()==app,'actual bundle identity differs')
        require(start['data_directory']==str(data) and start['instance_lock_held'] and finish['instance_lock_held_until_host_return'],'data/lock contract differs')
        require(finish['host_returncode']==0,'wrapper reported failure')
        record['loaded_images']=g.loaded_images(stderr.read_text(),exe,
            [p for p in package_record['relocated_graph' if relocated else 'graph']['nodes'] if p!=str(exe)])
        require(package.verify(build)==package_record,'App changed during execution')
        record['status']='ACTUAL_CONFIGURED_APP_EXECUTION_OBSERVED_NOT_ACCEPTED'
    except Exception as error:
        record.update(status='FAIL_NOT_ACCEPTED',error_type=type(error).__name__,error=str(error))
        write(out/'evidence.json',record);raise
    write(out/'evidence.json',record)
    print(json.dumps(dict(status=record['status'],pid=child.pid,returncode=record['returncode'],
                         steps=record['result']['steps'],saved_file=record['result']['saved_file']),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--relocated',action='store_true');p.add_argument('--timeout',type=int,default=180)
    args=p.parse_args();main(args.build,args.out,args.relocated,args.timeout)
