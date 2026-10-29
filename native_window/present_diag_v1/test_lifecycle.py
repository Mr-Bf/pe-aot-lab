"""Actual provider component only. Default reads; --run compiles/runs 10 cases.

No DXMT queue/device/render code is linked or executed. Each case is a fresh
process, so no testing-only reset is added to the production registry.
"""
import argparse,hashlib,json,os,shlex,subprocess,sys,traceback
from pathlib import Path
from native_window.present_diag_v1 import prepare as p

ROOT=p.ROOT
OUT=ROOT/'build/native-present-diag-v1/lifecycle-02'
CASES=('arguments','normal','owner','overflow','clock','unfinished_join','unfinished_work','close_owner','multi','late')
MODES={'O0':['-O0'],'O3':['-O3'],'asan-ubsan':['-O1','-fsanitize=address,undefined','-fno-omit-frame-pointer']}
SOURCE=Path(__file__).with_name('lifecycle.cpp')
PROVIDER=p.DEST/'src/nativemetal/present_diagnostics_v1.cpp'
def need(ok,message):
    if not ok:raise ValueError(message)
def sha(b):return hashlib.sha256(b).hexdigest()
def write(path,obj):
    with path.open('x') as f:json.dump(obj,f,indent=2,sort_keys=True);f.write('\n')
def hashes(paths):return {str(x.resolve()):sha(x.read_bytes()) for x in sorted(set(paths))}
def initial_paths():return [Path(__file__),SOURCE,*p.sources(),p.OUT/'evidence.json',Path(sys.executable).resolve(),Path('/usr/bin/otool')]
def environment():
    env={k:v for k,v in os.environ.items() if not k.startswith(('DYLD_','ASAN_','UBSAN_')) and k not in ('CPATH','CPLUS_INCLUDE_PATH','C_INCLUDE_PATH','LIBRARY_PATH','SDKROOT')}
    env.update(ASAN_OPTIONS='detect_leaks=0:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    return env
def command(argv,name,records,timeout=60):
    argv=list(map(str,argv));result=subprocess.run(argv,cwd=ROOT,env=environment(),capture_output=True,timeout=timeout)
    (OUT/(name+'.stdout')).write_bytes(result.stdout);(OUT/(name+'.stderr')).write_bytes(result.stderr)
    record={'argv':argv,'returncode':result.returncode,'stdout':name+'.stdout','stderr':name+'.stderr'}
    records.append(record)
    need(result.returncode==0,'command failed '+name)
    return result.stdout
def dependencies(raw):
    text=raw.decode().replace('\\\n',' ')
    need(text.startswith('deps: '),'actual compiler dependency target')
    return {Path(x).resolve() for x in shlex.split(text[len('deps: '):])}
def compile_flags(sdk):return ['--driver-mode=g++','-arch','arm64','-std=c++20','-isysroot',sdk,'-Wall','-Wextra','-Werror','-pthread','-I'+str(p.DEST/'include')]
def libraries(raw,binary):
    lines=raw.decode().splitlines();need(lines and lines[0]==str(binary)+':','actual otool binary')
    libs=[]
    for line in lines[1:]:
        need(line.startswith('\t') and ' (compatibility version ' in line,'otool library syntax')
        libs.append(line.strip().split(' (compatibility version ',1)[0])
    need(len(libs)==len(set(libs)),'duplicate linked library');return set(libs)
def run():
    need(not OUT.exists(),'fresh lifecycle evidence required; preserve previous attempt')
    OUT.mkdir(parents=True);records=[]
    inputs_start=hashes(initial_paths())
    write(OUT/'started.json',{'status':'COMPONENT_STARTED','inputs':inputs_start,'cases':CASES,'modes':list(MODES),'gui_gpu_guest':0})
    try:
        source_check=p.verify()
        compiler=Path(command(['/usr/bin/xcrun','--find','clang++'],'compiler-path',records).decode().strip()).resolve()
        linker=Path(command(['/usr/bin/xcrun','--find','ld'],'linker-path',records).decode().strip()).resolve()
        sdk=command(['/usr/bin/xcrun','--show-sdk-path'],'sdk-path',records).decode().strip()
        resource=Path(command([compiler,'-print-resource-dir'],'resource-path',records).decode().strip())
        runtime=resource/'lib/darwin/libclang_rt.asan_osx_dynamic.dylib'
        deps=set(map(Path,inputs_start))|{compiler,linker,Path('/usr/bin/xcrun'),runtime,PROVIDER}
        flags=compile_flags(sdk)
        for mode,opts in MODES.items():
            for name,source in [('harness',SOURCE),('provider',PROVIDER)]:
                raw=command([compiler,*flags,*opts,'-M','-MT','deps',source],mode+'-'+name+'-deps',records)
                deps|=dependencies(raw)
        inputs_before=hashes(deps)
        need(all(inputs_before[k]==v for k,v in inputs_start.items()),'producer changed before build')
        binaries={}
        for mode,opts in MODES.items():
            binary=OUT/('provider-'+mode)
            command([compiler,*flags,*opts,'-v',SOURCE,PROVIDER,'-o',binary],mode+'-compile',records)
            binaries[mode]=binary
            command(['/usr/bin/otool','-L',binary],mode+'-libraries',records)
        rows=[]
        for mode,binary in binaries.items():
            for case in CASES:
                name=mode+'-'+case
                raw=command([binary,case],name,records,timeout=10)
                value=json.loads(raw)
                need(value['status']=='PASS_PROVIDER_COMPONENT' and value['case']==case and value['gpu_calls']==0,'component case did not pass')
                rows.append({'mode':mode,'case':case,'stdout':name+'.stdout','result':value})
        need(hashes(deps)==inputs_before and p.verify()==source_check,'inputs changed during component tests')
        receipt={'schema':1,'status':'PASS_ACTUAL_PROVIDER_COMPONENT_NOT_DXMT_EXECUTION','cases':list(CASES),'modes':list(MODES),
            'source_preparation':source_check,'inputs_before':inputs_before,'inputs_after':inputs_before,'commands':records,'rows':rows,
            'artifacts':{x.name:sha(x.read_bytes()) for x in sorted(OUT.iterdir()) if x.is_file()},
            'scope':{'component_processes':30,'dxmt_device_guest_gui_gpu_executions':0,'leak_sanitizer_enabled':False,'performance_claim':False}}
        write(OUT/'evidence.json',receipt)
        return verify()
    except BaseException as error:
        write(OUT/'failure.json',{'status':'FAIL_COMPONENT_PRESERVED','error':repr(error),'traceback':traceback.format_exc(),'commands':records})
        raise
def verify():
    path=OUT/'evidence.json';raw=path.read_bytes();r=json.loads(raw)
    need(r['schema']==1 and r['status']=='PASS_ACTUAL_PROVIDER_COMPONENT_NOT_DXMT_EXECUTION','component status')
    need(r['cases']==list(CASES) and r['modes']==list(MODES),'exact finite case set')
    need(r['inputs_before']==r['inputs_after']==hashes(map(Path,r['inputs_before'])),'bound source/tool/dependency bytes')
    need(p.verify()==r['source_preparation'],'current prepared source')
    need({x.name for x in OUT.iterdir()}==set(r['artifacts'])|{'evidence.json'},'exact component output set')
    blobs={name:(OUT/name).read_bytes() for name in r['artifacts']}
    need({name:sha(data) for name,data in blobs.items()}==r['artifacts'],'actual artifact bytes')
    names={'compiler-path','linker-path','sdk-path','resource-path'}
    names|={m+'-'+n+'-deps' for m in MODES for n in ('harness','provider')}
    names|={m+'-'+n for m in MODES for n in ('compile','libraries',*CASES)}
    need(len(r['commands'])==len(names) and {c['stdout'] for c in r['commands']}=={n+'.stdout' for n in names},'complete actual command set')
    expected_artifacts={'started.json',*('provider-'+m for m in MODES),*(n+s for n in names for s in ('.stdout','.stderr'))}
    need(set(blobs)==expected_artifacts,'required component artifact closure')
    compiler=Path(blobs['compiler-path.stdout'].decode().strip()).resolve()
    linker=Path(blobs['linker-path.stdout'].decode().strip()).resolve()
    resource=Path(blobs['resource-path.stdout'].decode().strip())
    sdk=blobs['sdk-path.stdout'].decode().strip();flags=compile_flags(sdk)
    planned={'compiler-path':['/usr/bin/xcrun','--find','clang++'],'linker-path':['/usr/bin/xcrun','--find','ld'],
        'sdk-path':['/usr/bin/xcrun','--show-sdk-path'],'resource-path':[str(compiler),'-print-resource-dir']}
    for mode,opts in MODES.items():
        binary=OUT/('provider-'+mode)
        for name,source in [('harness',SOURCE),('provider',PROVIDER)]:planned[mode+'-'+name+'-deps']=list(map(str,[compiler,*flags,*opts,'-M','-MT','deps',source]))
        planned[mode+'-compile']=list(map(str,[compiler,*flags,*opts,'-v',SOURCE,PROVIDER,'-o',binary]))
        planned[mode+'-libraries']=['/usr/bin/otool','-L',str(binary)]
        for case in CASES:planned[mode+'-'+case]=[str(binary),case]
        expected_libs={'/usr/lib/libc++.1.dylib','/usr/lib/libSystem.B.dylib'}
        if mode=='asan-ubsan':expected_libs.add('@rpath/libclang_rt.asan_osx_dynamic.dylib')
        need(libraries(blobs[mode+'-libraries.stdout'],binary)==expected_libs,'actual linked runtime set')
        if mode=='asan-ubsan':
            link_lines=[shlex.split(s) for s in blobs[mode+'-compile.stderr'].decode().splitlines() if s.lstrip().startswith('"'+str(linker)+'"')]
            need(len(link_lines)==1,'actual sanitizer linker command')
            args=link_lines[0];rpaths=[args[i+1] for i,x in enumerate(args[:-1]) if x=='-rpath']
            need(str(resource/'lib/darwin') in rpaths,'sanitizer runtime rpath bound to compiler resource')
    need(all(c['argv']==planned[c['stdout'][:-7]] and c['stderr']==c['stdout'][:-7]+'.stderr' for c in r['commands']),'exact compiler/mode/dependency/tool command arguments')
    deps=set(initial_paths())|{PROVIDER,compiler,linker,Path('/usr/bin/xcrun'),resource/'lib/darwin/libclang_rt.asan_osx_dynamic.dylib'}
    for mode in MODES:
        for name in ('harness','provider'):deps|=dependencies(blobs[mode+'-'+name+'-deps.stdout'])
    need(set(r['inputs_before'])=={str(x.resolve()) for x in deps},'actual -M exact dependency set')
    need(json.loads(blobs['started.json'])=={'status':'COMPONENT_STARTED','inputs':hashes(initial_paths()),'cases':list(CASES),'modes':list(MODES),'gui_gpu_guest':0},'start input closure')
    need(len(r['rows'])==30 and {(v['mode'],v['case']) for v in r['rows']}=={(m,c) for m in MODES for c in CASES},'exact case executions')
    results={}
    for row in r['rows']:
        expected_name=row['mode']+'-'+row['case']
        need(row['stdout']==expected_name+'.stdout','actual stdout path')
        value=json.loads(blobs[row['stdout']]);need(value==row['result'],'parse authenticated bytes')
        need(set(value)=={'status','case','checks','dummy_business_calls','gpu_calls'} and value['status']=='PASS_PROVIDER_COMPONENT' and value['case']==row['case'] and value['gpu_calls']==0,'exact component result')
        need(type(value['checks']) is int and value['checks']>0,'actual assertions')
        need(value['dummy_business_calls']=={'owner':1,'clock':2}.get(row['case'],0),'diagnostic failure business pass through')
        calls=[c for c in r['commands'] if c['stdout']==row['stdout']]
        need(len(calls)==1 and calls[0]['argv']==[str(OUT/('provider-'+row['mode'])),row['case']] and calls[0]['returncode']==0,'actual component invocation')
        need(blobs[calls[0]['stderr']]==b'','no sanitizer or component stderr')
        if row['case'] in results:need(results[row['case']]==value,'three modes same assertions/results')
        else:results[row['case']]=value
    need(all(c['returncode']==0 and c['stdout'] in blobs and c['stderr'] in blobs for c in r['commands']),'all actual tool results passed')
    need(r['scope']=={'component_processes':30,'dxmt_device_guest_gui_gpu_executions':0,'leak_sanitizer_enabled':False,'performance_claim':False},'component-only scope')
    need(hashes(map(Path,r['inputs_before']))==r['inputs_before'] and all((OUT/n).read_bytes()==b for n,b in blobs.items()) and path.read_bytes()==raw,'final inputs/record/artifacts unchanged')
    return {'status':'PROVIDER_COMPONENT_CURRENT','checks_per_mode':sum(v['checks'] for v in results.values()),'cases_per_mode':10,
        'component_processes':30,'new_dxmt_device_guest_gui_gpu_executions':0,'evidence_sha256':sha(raw)}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--run',action='store_true');args=parser.parse_args()
    print(json.dumps(run() if args.run else verify(),sort_keys=True))
