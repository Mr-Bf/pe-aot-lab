"""Same-UID grandchild tests. Pipes synchronize registration and target exit.

The still-alive helper is the real parent and supplies actual waitpid status.
All cleanup acts only on a process created by this script; no GUI/GPU calls.
"""
from __future__ import annotations
import argparse,errno,hashlib,json,os,platform,re,select,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from window_bridge import kqueue_exit_v1 as observer
TIMEOUT=8


def require(x,m):
    if not x:raise ValueError(m)


def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()


def write(path,value):
    with Path(path).open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')


def read_line(fd):
    ready,_,_=select.select([fd],[],[],TIMEOUT)
    if not ready:raise TimeoutError('synchronized pipe deadline')
    data=os.read(fd,4096)
    require(data.endswith(b'\n') and data.count(b'\n')==1,'atomic protocol line required')
    return data[:-1]


def emit(fd,value):
    data=(json.dumps(value,sort_keys=True)+'\n').encode();require(len(data)<4096,'bounded protocol')
    require(os.write(fd,data)==len(data),'short pipe write')


def helper(kind):
    ready_r,ready_w=os.pipe();gate_r,gate_w=os.pipe();target=os.fork()
    if target==0:
        os.close(ready_r);os.close(gate_w)
        try:
            signal.signal(signal.SIGTERM,signal.SIG_DFL)
            emit(ready_w,{'target_pid':os.getpid(),'target_ppid':os.getppid(),'uid':os.getuid(),'euid':os.geteuid()});os.close(ready_w)
            token=read_line(gate_r);os.close(gate_r)
            if token!=b'GO':os._exit(125)
            if kind=='signal15':os.kill(os.getpid(),signal.SIGTERM);os._exit(126)
            os._exit(int(kind.removeprefix('exit')))
        except BaseException:os._exit(124)
    os.close(ready_w);os.close(gate_r);reaped=False
    try:
        actual=json.loads(read_line(ready_r));os.close(ready_r)
        emit(1,{'stage':'TARGET_BLOCKED','helper_pid':os.getpid(),'supervisor_pid':os.getppid(),'actual_target':actual})
        command=read_line(0)
        os.write(gate_w,b'GO\n' if command==b'GO' else b'ABORT\n');os.close(gate_w);gate_w=-1
        waited,status=os.waitpid(target,0);reaped=True
        emit(1,{'stage':'TARGET_REAPED_PARENT_STILL_ALIVE','helper_pid':os.getpid(),'waited_pid':waited,'raw_wait_status':status,'decoded':observer.decode_wait_status(status)})
        require(read_line(0)==b'ACK','supervisor acknowledgement missing')
        return 0
    finally:
        if gate_w>=0:os.close(gate_w)
        if not reaped:
            waited,_=os.waitpid(target,os.WNOHANG)
            if not waited:
                os.kill(target,signal.SIGKILL);os.waitpid(target,0)


def current_inputs():
    sdk=Path(subprocess.check_output(['/usr/bin/xcrun','--show-sdk-path'],text=True).strip())
    event=sdk/'usr/include/sys/event.h';manual=sdk/'usr/share/man/man2/kqueue.2';content=event.read_text()
    expected={'NOTE_EXITSTATUS':observer.NOTE_EXITSTATUS,'EV_RECEIPT':observer.EV_RECEIPT}
    for name,value in expected.items():
        m=re.search(r'^#define\s+'+name+r'\s+(0x[0-9a-fA-F]+)',content,re.M);require(m and int(m[1],16)==value,'installed SDK constant mismatch '+name)
    paths=[Path(__file__).resolve(),Path(observer.__file__).resolve(),Path(sys.executable).resolve(),Path(select.__file__).resolve(),Path(subprocess.__file__).resolve(),event,manual,Path('/usr/bin/xcrun')]
    return {str(p):sha(p) for p in paths}


def case(kind,out):
    p=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--helper',kind],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    record={'kind':kind,'helper_command':p.args,'helper_pid':p.pid,'supervisor_pid':os.getpid(),'supervisor_uid':os.getuid(),'supervisor_euid':os.geteuid(),'status':'STARTED'}
    try:
        ready=json.loads(read_line(p.stdout.fileno()));record['ready']=ready;actual=ready['actual_target'];target=actual['target_pid']
        require(ready['helper_pid']==p.pid and ready['supervisor_pid']==os.getpid() and actual['target_ppid']==p.pid and actual['uid']==os.getuid() and actual['euid']==os.geteuid(),'actual target parent/UID differs')
        try:os.waitpid(target,os.WNOHANG)
        except ChildProcessError as error:record['nonparent_wait_errno']=error.errno
        else:raise ValueError('supervisor unexpectedly owns target')
        require(record['nonparent_wait_errno']==errno.ECHILD,'nonparent relation not independently observed')
        require(p.poll() is None,'true parent exited before registration')
        with observer.ExitWatch(target) as watch:
            record['registration']=watch.registration;record['registered_at_monotonic_ns']=time.monotonic_ns()
            # No delay or PID polling controls the target. It cannot leave the
            # gate until the registration receipt has actually succeeded.
            require(os.write(p.stdin.fileno(),b'GO\n')==3,'GO pipe write');record['target_released_at_monotonic_ns']=time.monotonic_ns()
            event=watch.wait(TIMEOUT);record['observed_at_monotonic_ns']=time.monotonic_ns();record['observation']=event
            record['parent_alive_when_observed']=p.poll() is None
            require(record['parent_alive_when_observed'],'actual parent must stay alive through observation')
            parent=json.loads(read_line(p.stdout.fileno()));record['parent_wait']=parent
            require(parent['helper_pid']==p.pid and parent['waited_pid']==target and parent['raw_wait_status']==event['event']['data'] and parent['decoded']==event['termination'],'kqueue did not equal actual parent wait status')
            expected={'exit0':0,'exit23':23,'signal15':-15}[kind]
            require(event['termination']['python_returncode']==expected,'terminal outcome differs')
        require(os.write(p.stdin.fileno(),b'ACK\n')==4,'ACK pipe write');p.stdin.close();p.stdin=None
        tail,stderr=p.communicate(timeout=TIMEOUT)
        record.update(helper_returncode=p.returncode,helper_tail=tail.decode(),helper_stderr=stderr.decode())
        require(p.returncode==0 and tail==stderr==b'','helper cleanup/extra output differs');record['status']='PASS_NONPARENT_STATUS_EQUALS_PARENT_WAIT'
        write(out/(kind+'.json'),record);return record
    except BaseException as error:
        record.update(status='FAIL_PRESERVED',error=repr(error))
        try:
            if p.poll() is None and p.stdin is not None:os.write(p.stdin.fileno(),b'ABORT\nACK\n')
        except (BrokenPipeError,OSError):pass
        try:p.wait(timeout=TIMEOUT+2)
        except subprocess.TimeoutExpired:p.terminate();p.wait(timeout=3)
        record['cleanup_helper_returncode']=p.returncode
        if p.stderr is not None:record['helper_stderr']=p.stderr.read().decode()
        write(out/(kind+'-failure.json'),record);raise


def run(out):
    out=out.resolve();out.mkdir(parents=True,exist_ok=False)
    before=current_inputs();write(out/'started.json',{'status':'COMPONENT_TEST_STARTED','inputs_before':before,'sys_platform':sys.platform,'mac_ver':platform.mac_ver(),'uname':list(platform.uname()),'scope':{'new_gui':0,'new_gpu':0,'new_PE':0}})
    try:
        cases=[case(kind,out) for kind in ('exit0','exit23','signal15')]
        after=current_inputs();require(before==after,'test inputs changed')
        result={'status':'PASS_THREE_SAME_UID_NONPARENT_EXIT_CASES','cases':[{'kind':r['kind'],'pid':r['ready']['actual_target']['target_pid'],'raw_wait_status':r['parent_wait']['raw_wait_status'],'python_returncode':r['parent_wait']['decoded']['python_returncode'],'evidence_sha256':sha(out/(r['kind']+'.json'))} for r in cases],
                'inputs_before':before,'inputs_after':after,'artifacts':{str(p):sha(p) for p in [out/'started.json',*[out/(kind+'.json') for kind in ('exit0','exit23','signal15')]]},
                'scope':{'actual_test_targets':3,'actual_helpers':3,'new_gui':0,'new_gpu':0,'new_PE':0,'launchservices_app_verified':False},
                'limitations':['same UID and signal permission only','target is blocked before acknowledged registration','arbitrary/other-UID targets not tested','App identity/start-time binding and LaunchServices exit race require separate integration']}
        write(out/'evidence.json',result);verify(out);return result
    except BaseException as error:write(out/'first-failure.json',{'status':'FAIL_PRESERVED','error':repr(error),'inputs_before':before});raise


def verify(out):
    result=json.loads((out/'evidence.json').read_text());require(result['status']=='PASS_THREE_SAME_UID_NONPARENT_EXIT_CASES','not accepted')
    require(result['inputs_before']==result['inputs_after']==current_inputs(),'source/tool/SDK differs')
    names=('exit0','exit23','signal15')
    expected_paths=[out/'started.json',*[out/(name+'.json') for name in names]]
    require(result['artifacts']=={str(p):sha(p) for p in expected_paths},'required artifacts changed/omitted')
    start=json.loads((out/'started.json').read_text());require(start['status']=='COMPONENT_TEST_STARTED' and start['inputs_before']==result['inputs_before'],'test start differs')
    require(result['scope']=={'actual_test_targets':3,'actual_helpers':3,'new_gui':0,'new_gpu':0,'new_PE':0,'launchservices_app_verified':False},'scope differs')
    require(type(result['cases']) is list and [r['kind'] for r in result['cases']]==list(names),'exact three cases required')
    targets=set();helpers=set()
    for row in result['cases']:
        rec=json.loads((out/(row['kind']+'.json')).read_text());require(sha(out/(row['kind']+'.json'))==row['evidence_sha256'],'case changed')
        require(rec['status']=='PASS_NONPARENT_STATUS_EQUALS_PARENT_WAIT' and rec['nonparent_wait_errno']==errno.ECHILD,'case lacks nonparent witness')
        require(rec['helper_command']==[sys.executable,str(Path(__file__).resolve()),'--helper',row['kind']],'actual helper command differs')
        ready=rec['ready'];target=ready['actual_target'];pid=target['target_pid'];helper=rec['helper_pid'];targets.add(pid);helpers.add(helper)
        require(type(pid) is int and pid>1 and pid==row['pid'] and ready['helper_pid']==helper and target['target_ppid']==helper and ready['supervisor_pid']==rec['supervisor_pid'] and pid!=helper!=rec['supervisor_pid'],'actual parent PID relation differs')
        require(target['uid']==rec['supervisor_uid'] and target['euid']==rec['supervisor_euid'],'actual UID differs')
        require(rec['parent_alive_when_observed'] is True and rec['helper_returncode']==0 and rec['helper_tail']==rec['helper_stderr']=='','helper lifecycle differs')
        require(rec['registered_at_monotonic_ns']<=rec['target_released_at_monotonic_ns']<=rec['observed_at_monotonic_ns'],'registration/release/event order differs')
        ack=rec['registration'];event=rec['observation']['event']
        require(ack['ident']==event['ident']==pid and ack['filter']==event['filter']==select.KQ_FILTER_PROC and ack['flags']&select.KQ_EV_ERROR and ack['data']==0,'acknowledged registration differs')
        require(not(event['flags']&select.KQ_EV_ERROR) and event['fflags']&select.KQ_NOTE_EXIT and event['fflags']&observer.NOTE_EXITSTATUS,'terminal status flags absent')
        require(rec['observation']['registration']==ack and rec['observation']['pid']==pid,'watch observation identity differs')
        parent=rec['parent_wait'];require(parent['stage']=='TARGET_REAPED_PARENT_STILL_ALIVE' and parent['helper_pid']==helper and parent['waited_pid']==pid and parent['raw_wait_status']==event['data']==row['raw_wait_status'],'actual parent wait differs')
        require(rec['observation']['termination']==parent['decoded']==observer.decode_wait_status(row['raw_wait_status']),'wait decoding mismatch')
        require(row['python_returncode']==parent['decoded']['python_returncode']=={'exit0':0,'exit23':23,'signal15':-15}[row['kind']],'expected termination mismatch')
    require(len(targets)==len(helpers)==3 and not(targets&helpers),'distinct actual test processes required')
    return result

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--helper',choices=('exit0','exit23','signal15'));a.add_argument('--out',type=Path);a.add_argument('--run',action='store_true');args=a.parse_args()
    if args.helper:sys.exit(helper(args.helper))
    require(args.out is not None,'explicit output directory required');r=run(args.out) if args.run else verify(args.out.resolve())
    print(json.dumps({'status':r['status'],'cases':r['cases'],'scope':r['scope']}))
