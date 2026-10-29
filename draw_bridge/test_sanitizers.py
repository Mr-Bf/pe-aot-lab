#!/usr/bin/env python3
"""Actual lifted PE + C/C++ bridge ASan/UBSan; external DXMT remains uninstrumented."""
import argparse,json,os,re,shlex,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent;WORK=ROOT.parents[1]/'work'
sys.path.insert(0,str(ROOT))
from draw_bridge.bindings_v2 import Program,python_closure,snapshot,unchanged,sha
from graphics_stage5 import d3d11_probe as graphics
from native_bridge.test_sanitizers import instrument,LLVM
OUT=ROOT/'build/draw-bridge/sanitizers-v2'

def require(value,message):
    if not value:raise RuntimeError(message)
def command(args,log,env=None):
    args=list(map(str,args));r=subprocess.run(args,capture_output=True,text=True,env=env)
    log.write_text(json.dumps(args)+'\n'+r.stdout+r.stderr)
    require(r.returncode==0,'command failed '+str(log)+': '+r.stderr[-3000:]);return r.stdout

def points(program):
    rows=program.manifest['instructions'];values={}
    for label,slot in [('Map',14),('VS',12),('Draw',13)]:
        matches=[r for r in rows if r.get('kind')==3 and r.get('slot')==slot]
        require(len(matches)==1,'review requires unique actual '+label+' call')
        row=matches[0];previous=[r for r in rows if r['rva']<row['rva']]
        values[label]=(row['rva'],len(previous)+sum(r['kind'] in (1,3) for r in previous)+1)
    return ''.join('static const uint32_t k%sCallRva=%du;static const uint64_t k%sCallStep=%du;\n'%(name,rva,name,step) for name,(rva,step) in values.items())

def tools(program):
    return [LLVM/'clang',LLVM/'clang++',LLVM/'llvm-symbolizer',Path(program.tools['ld']),Path('/usr/bin/install_name_tool'),Path('/usr/bin/codesign'),Path('/usr/bin/nm'),Path('/usr/bin/otool'),Path('/usr/bin/lipo'),Path(sys.executable)]
def flags(program,out,cpp=False):
    c=['-target','arm64-apple-macos11','-isysroot',program.tools['sdk'],'-O1','-g','-fno-lto','-Wall','-Wextra','-Werror','-I',str(out),'-I',str(HERE)]
    if cpp:c+=['-std=c++17','-Wno-extern-c-compat','-fno-rtti','-fno-exceptions','-nostdinc++','-isystem',program.tools['sdk']+'/usr/include/c++/v1','-I'+program.config['dxmt_source']+'/include/native/windows','-I'+program.config['dxmt_source']+'/include/native/directx']
    else:c+=['-std=c11']
    return c

def deps(program,out):
    records={};paths=set()
    for name,compiler,cpp in [('sanitizer_driver.c',LLVM/'clang',False),('native_backend.cpp',LLVM/'clang++',True)]:
        text=command([compiler,*flags(program,out,cpp),'-fsanitize=address,undefined','-M','-MT','probe',HERE/name],out/(name+'.deps.log'))
        records[name]=text;paths.update(graphics.dependency_paths(text))
    return records,paths

def initial(program,out):
    own=[HERE/'test_sanitizers.py',HERE/'sanitizer_driver.c']
    lift_inputs={directory/name for directory in (program.out/'compiler',program.out/'ret-shim') for name in json.loads((directory/'manifest.json').read_text())['artifact_sha256']}
    return lift_inputs|set(map(Path,program.build_manifest['native_inputs']))|set(map(Path,program.build_manifest['artifacts']))|set(own)|set(python_closure([own[0]]))|set(tools(program))|{program.out/'program-build.json',out/'native_imports.h',out/'native_image.h',out/'review_points.h'}

def validate(report):
    require(report.get('status')=='PASS' and report.get('architecture')=='arm64' and report.get('actual_dxmt') is True,'driver outcome')
    require(report.get('actual_pe_cases')==4 and report.get('trusted_hook_cases')==19 and report.get('actual_guest_entry_executions')==23 and report.get('checks',0)>2000,'case coverage')

def validate_cases(out,mode):
    names=['normal-preferred','normal-rebased','map-call-budget','map-active-budget']+[f'map-hook-{i}' for i in range(4)]+['bad-call-target','active-map-release']+[f'shader-hook-{i}' for i in range(5)]+[f'pipeline-hook-{i}' for i in range(6)]+['bound-apprefs-release-draw','early-release-all-no-map']
    statuses=[11,11,4,4,1,9,17,3,13,16,9,9,1,9,9,9,9,9,12,9,9,0,0]
    rows=[graphics.strict_json(x) for x in (out/(mode+'.canonical.cases')).read_text().splitlines()]
    expected=[]
    for i,(name,status) in enumerate(zip(names,statuses),1):expected.extend([{'event':'start','id':i,'name':name},{'event':'end','id':i,'status':status}])
    require(rows==expected,'actual per-case completion/status trace mismatch')
    return rows

def loaded_images(stderr,executable,expected,asan_copy=None):
    # ASan intentionally interposes libc. This dyld diagnostic describes delay
    # policy, not a newly loaded image; require a same-PID UUID/path announcement.
    filtered=[];interposition=[]
    for line in stderr.splitlines():
        match=re.fullmatch(r'dyld\[(\d+)\]: has interposing tuples so cannot be delayed: libclang_rt.asan_osx_dynamic.dylib',line)
        if match:
            require(asan_copy is not None,'ASan interposition in plain process')
            announcement=r'dyld\['+match.group(1)+r'\]: <[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}> '+re.escape(str(Path(asan_copy).resolve()))
            require(any(re.fullmatch(announcement,x) for x in stderr.splitlines()),'interposer has no same-process actual image')
            interposition.append(line)
        else:filtered.append(line)
    require(len(interposition)<=1,'duplicate ASan interposition diagnostic')
    require(not re.search(r'ERROR: AddressSanitizer|runtime error:|SUMMARY:.*Sanitizer',stderr),'sanitizer diagnostic found')
    return graphics.loaded_images('\n'.join(filtered),executable,expected),interposition

def required_artifacts(out):
    names={'native_imports.h','native_image.h','review_points.h','asan-id.log','asan-thin.log','asan-sign.log','asan-linked.log','asan-relink.log','ubsan-symbols.log'}
    for name in ('main','ret'):
        names.update({name+'-asan.ll',name+'-asan-symbols.log'})
        for mode in ('plain','sanitized'):names.update({name+'-'+mode+'.o',name+'-'+mode+'.compile.log'})
    for name in ('sanitizer_driver.c','native_backend.cpp'):
        names.add(name+'.deps.log');names.add(name+'-san-symbols.log')
        for mode in ('plain','sanitized'):names.update({name+'-'+mode+'.o',name+'-'+mode+'.compile.log'})
    for mode in ('plain','sanitized'):names.update({'review-'+mode,mode+'-link.log',mode+'-sign.log',mode+'.stdout',mode+'.stderr',mode+'.canonical',mode+'.canonical.cases'})
    return {out/name for name in names}

def verify_evidence(out=OUT):
    out=Path(out).resolve();e=graphics.read_json(out/'evidence.json');require(e.get('schema')==1 and e.get('status')=='PASS','not accepted')
    p=Program.from_build(e['program_out']);require((out/'review_points.h').read_text()==points(p),'test call points differ from actual manifest');require(e['asan_source']==str(LLVM.parent/'lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib') and e['asan_copy']==str(WORK/'draw-bridge/sanitizers-v2-runtime/libclang_rt.asan_osx_dynamic.dylib'),'unknown sanitizer source or local runtime');require(e['inputs_before']==e['inputs_after'],'input changed');unchanged(e['inputs_before']);unchanged(e['artifacts'])
    expected=initial(p,out)|{Path(e['asan_source']),Path(e['asan_copy'])}
    for name,cpp in [('sanitizer_driver.c',False),('native_backend.cpp',True)]:
        text=subprocess.check_output(list(map(str,[LLVM/('clang++' if cpp else 'clang'),*flags(p,out,cpp),'-fsanitize=address,undefined','-M','-MT','probe',HERE/name])),text=True)
        require(text==e['dependencies'][name],'C/C++ dependency graph changed');expected.update(graphics.dependency_paths(text))
    require(set(e['inputs_before'])==set(map(lambda x:str(Path(x).resolve()),expected)),'input closure omitted or changed')
    for name,directory in [('main',p.out/'compiler'),('ret',p.out/'ret-shim')]:
        text=(directory/'arm64.ll').read_text();expected_ir=re.sub(r'^define [^\n]+\{',lambda m:m.group(0).rsplit('{',1)[0]+' sanitize_address {',text,flags=re.M)
        require((out/(name+'-asan.ll')).read_text()==expected_ir,'ASan IR differs from exact instrumentation-only transform')
    require(set(e['instrumented_functions'])=={'main','ret'} and all(e['instrumented_functions'].values()),'real IR not instrumented')
    for mode in ('plain','sanitized'):
        r=e['runs'][mode];validate(r['report']);validate_cases(out,mode);
        require(r['executable']==str(out/('review-'+mode)) and r['command']==[str(out/('review-'+mode)),str(out/(mode+'.canonical'))],'executed command identity')
        require(r['stdout']==str(out/(mode+'.stdout')) and r['stderr']==str(out/(mode+'.stderr')) and r['streams']==snapshot([out/(mode+'.stdout'),out/(mode+'.stderr')]),'stream closure mismatch')
        expected_images=set(p.build_manifest['library_graph']['nodes'])|({e['asan_copy']} if mode=='sanitized' else set())
        require(set(r['expected_images'])==expected_images and set(r['graph']['nodes'])==expected_images|{r['executable']},'expected library closure differs from bound DXMT')
        expected_env={'ASAN_OPTIONS':'halt_on_error=1:detect_leaks=0','UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1','ASAN_SYMBOLIZER_PATH':str(LLVM/'llvm-symbolizer')} if mode=='sanitized' else {}
        require(r['sanitizer_environment']==expected_env,'instrumentation options differ')
        require(r['inputs_before']=={**e['inputs_before'],**snapshot([r['executable'],*r['graph']['nodes']])},'execution closure omitted');require(r['inputs_before']==r['inputs_after'],'execution drift');unchanged(r['inputs_before']);unchanged(r['streams'])
        require(graphics.strict_json(Path(r['stdout']).read_text())==r['report'],'stdout summary mismatch')
        loaded,diagnostics=loaded_images(Path(r['stderr']).read_text(),Path(r['executable']),r['expected_images'],e['asan_copy'] if mode=='sanitized' else None)
        require(loaded==r['loaded_images'] and diagnostics==r['asan_interposition_lines'],'loaded graph differs')
        require(graphics.library_graph(Path(r['executable']),Path(r['executable']))==r['graph'],'library graph changed')
        require(r['returncode']==0,'nonzero execution')
    require(e['runs']['plain']['report']==e['runs']['sanitized']['report'],'report mismatch')
    require(sha(out/'plain.canonical')==sha(out/'sanitized.canonical')==e['canonical_sha256'],'full state/guest bytes mismatch')
    expected_artifacts={str(p.resolve()) for p in required_artifacts(out)}
    require(set(e['artifacts'])==expected_artifacts,'artifact closure omitted or unknown')
    return e

def main(out=OUT,program_out=None):
    out=Path(out).resolve();require(out.is_relative_to(ROOT/'build/draw-bridge'),'private output required');out.mkdir(parents=True,exist_ok=True)
    evidence=out/'evidence.json'
    if evidence.exists():
        history=out/'history';history.mkdir(exist_ok=True);(history/(sha(evidence)+'.json')).write_bytes(evidence.read_bytes())
    graphics.save(evidence,{'status':'RUNNING'})
    try:
        p=Program.from_build(program_out or ROOT/'build/draw-bridge/program-revised-v2')
        for name in ('native_imports.h','native_image.h'):shutil.copy2(p.out/name,out/name)
        (out/'review_points.h').write_text(points(p))
        dependencies,paths=deps(p,out)
        source=LLVM.parent/'lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib';support=WORK/'draw-bridge/sanitizers-v2-runtime';support.mkdir(parents=True,exist_ok=True);copy=support/source.name
        copy.unlink(missing_ok=True);command(['lipo',source,'-thin','arm64','-output',copy],out/'asan-thin.log');copy.chmod(0o755);command(['install_name_tool','-id',copy,'-delete_rpath','@loader_path',copy],out/'asan-id.log');command(['codesign','--force','--sign','-',copy],out/'asan-sign.log')
        inputs=snapshot(initial(p,out)|paths|{source,copy});instrumented={};roots=[]
        for name,directory in [('main',p.out/'compiler'),('ret',p.out/'ret-shim')]:
            original=directory/'arm64.ll';san=out/(name+'-asan.ll');instrumented[name]=instrument(original,san)
            objects={}
            for mode,ir in [('plain',original),('sanitized',san)]:
                obj=out/(name+'-'+mode+'.o');command([LLVM/'clang','-target','arm64-apple-macos11','-O1',*(['-fsanitize=address'] if mode=='sanitized' else []),'-c',ir,'-o',obj],out/(name+'-'+mode+'.compile.log'));objects[mode]=obj
            require('__asan_report_' in command(['nm',objects['sanitized']],out/(name+'-asan-symbols.log')),'lifted ASan absent');roots.append(objects)
        runs={}
        for mode in ('plain','sanitized'):
            sanitized=mode=='sanitized';sanflags=['-fsanitize=address,undefined'] if sanitized else [];objects=[]
            for name,cpp in [('sanitizer_driver.c',False),('native_backend.cpp',True)]:
                obj=out/(name+'-'+mode+'.o');compiler=LLVM/('clang++' if cpp else 'clang')
                command([compiler,*flags(p,out,cpp),*sanflags,'-c',HERE/name,'-o',obj],out/(name+'-'+mode+'.compile.log'));objects.append(obj)
                if sanitized:
                    symbols=command(['nm',obj],out/(name+'-san-symbols.log'));require('__asan_' in symbols and '__ubsan_handle_' in symbols,'C/C++ unit missing actual sanitizer instrumentation')
            exe=out/('review-'+mode);library=Path(p.build_manifest['library'])
            command([LLVM/'clang++','-target','arm64-apple-macos11','-isysroot',p.tools['sdk'],'-Wl,-syslibroot,'+p.tools['sdk'],'--ld-path='+p.tools['ld'],*sanflags,*objects,*[r[mode] for r in roots],library,'-Wl,-rpath,'+str(library.parent),'-o',exe],out/(mode+'-link.log'))
            if sanitized:
                require('__ubsan_handle_' in command(['nm',exe],out/'ubsan-symbols.log'),'C/C++ UBSan absent')
                linked=command(['otool','-L',exe],out/'asan-linked.log');names=[line.strip().split(' (',1)[0] for line in linked.splitlines()[1:] if source.name in line];require(len(names)==1,'ASan runtime missing')
                command(['install_name_tool','-change',names[0],copy,'-delete_rpath','@executable_path','-delete_rpath',source.parent,exe],out/'asan-relink.log')
            command(['codesign','--force','--sign','-',exe],out/(mode+'-sign.log'))
            graph=graphics.library_graph(exe,exe);expected=set(p.build_manifest['library_graph']['nodes'])|({str(copy.resolve())} if sanitized else set())
            require(set(graph['nodes'])==expected|{str(exe.resolve())},'unexpected linked library graph')
            env=graphics.environment(out,images=True)
            if sanitized:env.update(ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1',ASAN_SYMBOLIZER_PATH=str(LLVM/'llvm-symbolizer'))
            stable={**inputs,**snapshot([exe,*graph['nodes']])};stdout=out/(mode+'.stdout');stderr=out/(mode+'.stderr');cmd=[str(exe),str(out/(mode+'.canonical'))]
            completed=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=120);stdout.write_text(completed.stdout);stderr.write_text(completed.stderr)
            require(completed.returncode==0,'actual driver failed returncode='+str(completed.returncode)+': '+str(stderr));report=graphics.strict_json(completed.stdout);validate(report);validate_cases(out,mode)
            loaded,diagnostics=loaded_images(completed.stderr,exe,expected,copy if sanitized else None);unchanged(stable)
            runs[mode]={'command':cmd,'returncode':completed.returncode,'executable':str(exe),'stdout':str(stdout),'stderr':str(stderr),'report':report,'streams':snapshot([stdout,stderr]),'inputs_before':stable,'inputs_after':snapshot(stable),'expected_images':sorted(expected),'loaded_images':loaded,'asan_interposition_lines':diagnostics,'graph':graph,'sanitizer_environment':{k:env[k] for k in ('ASAN_OPTIONS','UBSAN_OPTIONS','ASAN_SYMBOLIZER_PATH') if k in env}}
        unchanged(inputs);p.verify_build();require(runs['plain']['report']==runs['sanitized']['report'],'reports differ');require(sha(out/'plain.canonical')==sha(out/'sanitized.canonical'),'canonical mismatch')
        artifacts=snapshot(required_artifacts(out))
        result={'schema':1,'status':'PASS','program_out':str(p.out),'input_pe_sha256':p.source_sha256,'dependencies':dependencies,'inputs_before':inputs,'inputs_after':snapshot(inputs),'artifacts':artifacts,'instrumented_functions':instrumented,'asan_source':str(source),'asan_copy':str(copy),'runs':runs,'canonical_sha256':sha(out/'plain.canonical'),'canonical_bytes':(out/'plain.canonical').stat().st_size,'limits':['DXMT, DXGI, WineMetal and Metal drivers are not sanitizer-instrumented','UBSan applies to C/C++ bridge; lifted LLVM uses ASan only','LeakSanitizer disabled','Nineteen trusted host-hook cases are not guest-only fault inputs','Map oversized RowPitch is injected after actual native Map success, and actual Unmap must clean up','Only the two bound shaders and fixed pipeline are covered; no general shader/window/Steam/game or performance claim']}
        graphics.save(evidence,result);verify_evidence(out);print(json.dumps({'status':'PASS','actual_pe_cases_per_mode':4,'trusted_hook_cases_per_mode':19,'canonical_bytes':result['canonical_bytes']}))
    except Exception as error:
        result={'status':'FAIL','error':str(error)};graphics.save(evidence,result)
        history=out/'history'/sha(evidence);history.mkdir(parents=True,exist_ok=True)
        for path in [HERE/'test_sanitizers.py',HERE/'sanitizer_driver.c',*[x for x in out.iterdir() if x.is_file()]]:
            saved=history/(sha(path)+'-'+path.name)
            if not saved.exists():shutil.copy2(path,saved)
        first=out/'first-failure.json'
        if not first.exists():graphics.save(first,result)
        raise
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--program-out',type=Path);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    if args.verify:verify_evidence(args.out);print('{"status":"PASS_CURRENT"}')
    else:main(args.out,args.program_out)
