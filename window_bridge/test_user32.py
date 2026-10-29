#!/usr/bin/env python3
"""No GUI/GPU: real User32 C + checked memory, mock callback/Cocoa contract tests."""
import argparse, hashlib, json, os, shlex, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'build/window-bridge/user32-tests/final'
SOURCE=ROOT/'window_bridge/user32_test.c'
MODES={'O0':['-O0'],'O3':['-O3'],'sanitized':['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all']}
CHECKS=460
SCOPE='real_User32_and_memory_mock_host_and_callback'
def require(ok,message):
    if not ok:raise RuntimeError(message)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def snapshot(paths):return {str(Path(p).resolve()):sha(p) for p in sorted(set(map(Path,paths)))}
def output(args):return subprocess.check_output(list(map(str,args)),text=True).strip()
def tools():
    clang=Path(output(['/usr/bin/xcrun','--find','clang']));ld=Path(output(['/usr/bin/xcrun','--find','ld']))
    sdk=Path(output(['/usr/bin/xcrun','--show-sdk-path']))
    asan=Path(output([clang,'-print-file-name=libclang_rt.asan_osx_dynamic.dylib']))
    return clang,ld,sdk,asan
def base_flags(sdk):return ['-std=c11','-arch','arm64','-isysroot',str(sdk),'-Wall','-Wextra','-Werror','-I',str(ROOT/'window_bridge')]
def dependencies(clang,ld,sdk,asan):
    dep=output([clang,*base_flags(sdk),'-M',SOURCE])
    paths={Path(p) for p in shlex.split(dep.replace('\\\n',' ').split(':',1)[1])}
    paths|={Path(__file__),clang,ld,asan,Path(sys.executable),Path('/usr/bin/xcrun')}
    return paths,dep

def validate_run(row):
    require(row['returncode']==0,'test subprocess failed')
    data=json.loads(row['stdout'])
    require(data=={'status':'PASS','checks':CHECKS,'scope':SCOPE,'guest_executions':0,'gui_executions':0,'gpu_executions':0},'unexpected test result/count/scope')
    require(row['stderr']=='','unexpected sanitizer/runtime diagnostics')
    return data

def run(out=OUT):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=True)
    require(not (out/'evidence.json').exists(),'preserve old evidence, choose fresh --out')
    clang,ld,sdk,asan=tools();paths,dep=dependencies(clang,ld,sdk,asan);before=snapshot(paths)
    (out/'dependencies.txt').write_text(dep+'\n');rows={}
    for mode,flags in MODES.items():
        binary=out/('user32-'+mode);command=list(map(str,[clang,*base_flags(sdk),*flags,SOURCE,'-o',binary]))
        p=subprocess.run(command,capture_output=True,text=True)
        compile_row={'command':command,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
        (out/(mode+'-compile.json')).write_text(json.dumps(compile_row,indent=2)+'\n')
        require(p.returncode==0,'compile failed: '+mode)
        env=os.environ.copy();env['ASAN_OPTIONS']='detect_leaks=0:halt_on_error=1';env['UBSAN_OPTIONS']='halt_on_error=1:print_stacktrace=1'
        p=subprocess.run([str(binary)],capture_output=True,text=True,env=env,timeout=30)
        row={'command':[str(binary)],'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr,
             'environment':{'ASAN_OPTIONS':env['ASAN_OPTIONS'],'UBSAN_OPTIONS':env['UBSAN_OPTIONS']}}
        (out/(mode+'-run.json')).write_text(json.dumps(row,indent=2)+'\n');rows[mode]=validate_run(row)
    paths_after,dep_after=dependencies(clang,ld,sdk,asan)
    require(paths_after==paths and dep_after==dep,'dependency closure changed')
    after=snapshot(paths);require(before==after,'input identity changed')
    artifacts=['dependencies.txt',*[mode+suffix for mode in MODES for suffix in ('-compile.json','-run.json')],*['user32-'+mode for mode in MODES]]
    evidence={'status':'PASS','scope':SCOPE,'checks_per_mode':CHECKS,'modes':rows,
        'guest_executions':0,'gui_executions':0,'gpu_executions':0,'leak_detection':False,
        'inputs_before':before,'inputs_after':after,'tools':{'clang':str(clang),'ld':str(ld),'sdk':str(sdk),'asan':str(asan)},
        'artifacts_sha256':{p:sha(out/p) for p in artifacts},
        'limits':['Mock callback body is not translated x86 and does not validate Remill callback behavior.',
                  'Mock Cocoa does not establish OS focus, actual message scheduling, GUI or GPU operation.',
                  'ASan/UBSan instrument this C test, not LLVM-lifted guest functions. Leak detection disabled.']}
    (out/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n');return verify_evidence(out)

def verify_evidence(out=OUT):
    out=Path(out).resolve();e=json.loads((out/'evidence.json').read_text())
    require(e['status']=='PASS' and e['scope']==SCOPE and e['checks_per_mode']==CHECKS,'status/scope/count differs')
    require(e['guest_executions']==e['gui_executions']==e['gpu_executions']==0 and e['leak_detection'] is False,'invalid execution/sanitizer scope')
    clang,ld,sdk,asan=tools();paths,dep=dependencies(clang,ld,sdk,asan)
    require(e['tools']=={'clang':str(clang),'ld':str(ld),'sdk':str(sdk),'asan':str(asan)},'tools changed')
    require(e['inputs_before']==e['inputs_after']==snapshot(paths),'source/tool/header dependency identity differs')
    expected={'dependencies.txt',*[mode+suffix for mode in MODES for suffix in ('-compile.json','-run.json')],*['user32-'+mode for mode in MODES]}
    require(set(e['artifacts_sha256'])==expected,'artifact set differs')
    require({p:sha(out/p) for p in expected}==e['artifacts_sha256'],'artifact identity differs')
    require((out/'dependencies.txt').read_text()==dep+'\n','dependency log differs')
    require(set(e['modes'])==set(MODES),'modes differ')
    for mode,flags in MODES.items():
        r=json.loads((out/(mode+'-run.json')).read_text());require(validate_run(r)==e['modes'][mode],'nested result differs')
        require(r['command']==[str(out/('user32-'+mode))],'executed binary identity differs')
        require(r['environment']=={'ASAN_OPTIONS':'detect_leaks=0:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1'},'sanitizer options differ')
        c=json.loads((out/(mode+'-compile.json')).read_text())
        require(c['returncode']==0 and c['command']==list(map(str,[clang,*base_flags(sdk),*flags,SOURCE,'-o',out/('user32-'+mode)])),'compiler result/command differs')
    return {'status':'PASS_CURRENT','checks_per_mode':CHECKS,'modes':list(MODES),'guest_executions':0,'gui_executions':0,'gpu_executions':0,'evidence_sha256':sha(out/'evidence.json')}
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,default=OUT);ap.add_argument('--verify-only',action='store_true');a=ap.parse_args()
    print(json.dumps(verify_evidence(a.out) if a.verify_only else run(a.out),indent=2))
