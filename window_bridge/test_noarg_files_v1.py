"""Real private-directory/lock component tests, without AppKit/PE/GPU."""
import argparse,json,subprocess,tempfile
from pathlib import Path
from window_bridge import noarg_build_v1 as producer
from graphics_stage5 import d3d11_probe as g
ROOT=producer.ROOT;OUT=ROOT/'build/window-bridge/noarg-preflight-v1/r6'

def require(x,m):
    if not x:raise ValueError(m)
def paths(text):return g.dependency_paths(text)
def command(cmd,out,name):
    r=subprocess.run(list(map(str,cmd)),text=True,capture_output=True,timeout=30)
    producer.write(out/(name+'.json'),{'command':list(map(str,cmd)),'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
    require(r.returncode==0,name+' failed: '+r.stderr);return r.stdout

def run(out=OUT):
    out=Path(out).resolve();require(not out.exists(),'preserve prior attempt');out.mkdir(parents=True)
    source=ROOT/'window_bridge/noarg_files_test_v1.c'
    tools=g.read_json(producer.SOURCE/'program-build.json')['tools']
    flags=['-arch','arm64','-isysroot',tools['sdk'],'-std=c11','-Wall','-Wextra','-Werror']
    dep=command([tools['clang'],*flags,'-M','-MT','probe',source],out,'deps')
    inputs=g.hashes([__file__,producer.__file__,g.__file__,source,*paths(dep),tools['clang'],tools['ld']])
    work=Path(tempfile.mkdtemp(prefix='pe-aot-noarg-components-',dir='/private/tmp'))
    results={}
    for opt in ('O0','O3'):
        exe=out/('files-'+opt)
        command([tools['clang'],*flags,'-'+opt,source,'-o',exe],out,'compile-'+opt)
        result=g.strict_json(command([exe,work],out,'run-'+opt))
        require(result=={'status':'PASS_FILES_COMPONENT_ONLY','checks':49,'guest_executions':0,'gui_executions':0,'gpu_executions':0},'component outcome differs')
        results[opt]=result
    g.same(inputs)
    artifacts=g.hashes([p for p in out.iterdir() if p.is_file()])
    r={'status':'PASS_FILES_COMPONENT_ONLY','inputs_before':inputs,'inputs_after':g.hashes(inputs),'results':results,'artifacts':artifacts,'guest_executions':0,'gui_executions':0,'gpu_executions':0,'scope':'49 checks per compiler mode, same finite POSIX filesystem/lock set; no default ApplicationSupport writes or App launch'}
    producer.write(out/'evidence.json',r);return verify(out)

def verify(out=OUT):
    out=Path(out).resolve();r=g.read_json(out/'evidence.json')
    require(r['status']=='PASS_FILES_COMPONENT_ONLY' and r['inputs_before']==r['inputs_after'],'component receipt differs')
    g.same(r['inputs_before']);g.same(r['artifacts'])
    for opt in ('O0','O3'):
        raw=g.read_json(out/('run-'+opt+'.json'))
        require(raw['returncode']==0 and g.strict_json(raw['stdout'])==r['results'][opt] and r['results'][opt]['checks']==49,'raw component log differs')
    require(all(r[k]==0 for k in ('guest_executions','gui_executions','gpu_executions')),'scope differs')
    return {'status':r['status'],'checks_per_mode':49,'modes':['O0','O3'],'evidence_sha256':g.sha(out/'evidence.json'),'new_guest_executions':0}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,default=OUT);p.add_argument('--run',action='store_true');a=p.parse_args()
    print(json.dumps(run(a.out) if a.run else verify(a.out),indent=2))
