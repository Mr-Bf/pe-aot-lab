#!/usr/bin/env python3
"""Build isolated Remill for the versioned non-LOCK INC m32 [GPR64+0] profile.

The first six patches are frozen window producer inputs. Only the seventh
patch adds zero-displacement non-stack GPR-base INC admission and metadata. Building this tool is not guest execution acceptance.
"""
import argparse,hashlib,json,os,re,subprocess,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent;REPO=HERE.parent
BASE=REPO.parents[1]/'work/remill-stage2';WORK=REPO.parents[1]/'work/window-inc-v1'
SHA='56918a8c2554088e93389e97d292f4035286506c'
SRC=WORK/('remill-'+SHA);OUT=REPO/'build/window-inc-v1/lifter';BUILD=OUT/'build'
LLVM=BASE/'llvm@17/17.0.6/bin';LIFTER=BUILD/'bin/lift/remill-lift-17'
PATCH_PATHS=[REPO/'window_bridge'/name for name in ('xed-only-v1.patch','transactions-v1.patch',
    'aot-profile-v1.patch','import-calls-v1.patch','vtable-calls-v1.patch','window-calls-v1.patch')] + [HERE/'inc-base32-v1.patch']
PATCHES=[str(p.relative_to(REPO)) for p in PATCH_PATHS]

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise RuntimeError(message)
def snapshot(paths):return {str(p.resolve()):digest(p) for p in sorted(set(map(Path,paths)))}
def source_tree():return {str(p.relative_to(SRC)):digest(p) for p in sorted(SRC.rglob('*')) if p.is_file()}
def run(args,log,**kwargs):
    args=list(map(str,args))
    with (OUT/log).open('w') as stream:
        stream.write(json.dumps(args)+'\n');stream.flush()
        subprocess.run(args,stdout=stream,stderr=subprocess.STDOUT,check=True,**kwargs)

def build(jobs=2):
    require(sys.version_info>=(3,9),'Requires Python >=3.9; tested 3.13')
    require(type(jobs) is int and 1<=jobs<=2,'jobs must be in 1..2')
    OUT.mkdir(parents=True,exist_ok=True);WORK.mkdir(parents=True,exist_ok=True)
    manifest_path=OUT/'build-manifest.json'
    if manifest_path.exists():
        history=OUT/'history'/digest(manifest_path);history.mkdir(parents=True,exist_ok=True)
        for retained in [manifest_path,*OUT.glob('*.log'),Path(__file__),*PATCH_PATHS]:
            (history/(digest(retained)+'-'+retained.name)).write_bytes(retained.read_bytes())
    manifest_path.write_text('{"status":"RUNNING"}\n')
    archive=BASE/'remill.tar.gz';cmake=BASE/'cmake/4.4.4/bin/cmake';ninja=BASE/'ninja/1.13.2/bin/ninja'
    compiler=Path(subprocess.check_output(['/usr/bin/xcrun','--find','clang++'],text=True).strip())
    inputs=[archive,Path(__file__),HERE/'BASELINE.json',*PATCH_PATHS,cmake,ninja,compiler,Path('/usr/bin/clang'),
        Path('/usr/bin/clang++'),Path('/usr/bin/xcrun'),Path('/usr/bin/patch'),Path('/usr/bin/tar'),
        *[LLVM/name for name in ('clang','clang++','llvm-link','opt')],
        LLVM.parent/'lib/libLLVM.dylib',LLVM.parent/'lib/libclang-cpp.dylib',
        *sorted((BASE/'deps-install-apple/lib').glob('*.a')),
        REPO/'build/native-bridge/lifter/build-manifest.json',
        REPO/'build/native-bridge/lifter/build/bin/lift/remill-lift-17',
        REPO/'build/native-bridge/lifter/build/lib/Arch/X86/Runtime/amd64.bc']
    before=snapshot(inputs)
    try:
        require(digest(archive)=='4ba4218566367fad162ed0427ee32221a55134eca2eee5efc2436be67b46885f','pinned Remill archive mismatch')
        preparation=WORK/'source-prepared.json';patch_hashes={p:digest(REPO/p) for p in PATCHES}
        previous=json.loads(preparation.read_text()) if preparation.exists() else None
        if previous and previous.get('patch_sha256')==patch_hashes:
            require(previous['source_tree_sha256']==source_tree(),'prepared source changed outside versioned patches')
        else:
            if SRC.exists():
                history=WORK/'source-history';history.mkdir(exist_ok=True)
                key=hashlib.sha256(json.dumps(source_tree(),sort_keys=True).encode()).hexdigest()
                preserved=history/(SRC.name+'-'+key)
                require(not preserved.exists(),'source history collision; inspect retained tree')
                SRC.rename(preserved)
            run(['/usr/bin/tar','-xzf',archive,'-C',WORK],'extract.log')
            for patch in PATCH_PATHS:run(['/usr/bin/patch','--batch','--forward','-F','0','-p1','-i',patch],'patch-'+patch.name+'.log',cwd=SRC)
            preparation.write_text(json.dumps({'patch_sha256':patch_hashes,'source_tree_sha256':source_tree()},indent=2)+'\n')
        sources_before=source_tree()
        env={**os.environ,'PATH':str(cmake.parent)+':'+str(ninja.parent)+':'+str(LLVM)+':'+os.environ['PATH']}
        run([cmake,'-G','Ninja','-S',SRC,'-B',BUILD,'-DCMAKE_BUILD_TYPE=Release',
             '-DCMAKE_C_COMPILER=/usr/bin/clang','-DCMAKE_CXX_COMPILER=/usr/bin/clang++',
             '-DCMAKE_PREFIX_PATH='+str(BASE/'deps-install-apple')+';'+str(LLVM.parent),
             '-DCMAKE_INSTALL_PREFIX='+str(WORK/'install'),'-DREMILL_ENABLE_TESTING=OFF',
             '-DREMILL_ENABLE_INSTALL_TARGET=OFF','-DGIT_FAIL_IF_NONZERO_EXIT=OFF'],'configure.log',env=env)
        run([cmake,'--build',BUILD,'--target','remill-lift-17','amd64','--parallel',str(jobs)],'build.log',env=env)
        after=snapshot(inputs);require(before==after,'build inputs or frozen native artifacts changed')
        require(sources_before==source_tree(),'upstream source tree changed during build')
        result={'status':'PASS','validation_level':'BUILD_STATIC_NOT_EXECUTED',
            'scope':'isolated pinned decoder/lifter build; no guest execution, D3D11 runtime or GPU claim',
            'remill_sha':SHA,'archive_sha256':digest(archive),'patch_sha256':patch_hashes,
            'lifter':str(LIFTER),'lifter_sha256':digest(LIFTER),
            'semantics_sha256':digest(BUILD/'lib/Arch/X86/Runtime/amd64.bc'),
            'inputs_before':before,'inputs_after':after,'source_tree_sha256':sources_before,
            'modified_upstream_source_sha256':{name:digest(SRC/name) for name in
                ('bin/lift/Lift.cpp','lib/BC/TraceLifter.cpp')},
            'logs_sha256':{p.name:digest(p) for p in sorted(OUT.glob('*.log'))}}
        manifest_path.write_text(json.dumps(result,indent=2)+'\n');print(LIFTER);return result
    except Exception as error:
        failure={'status':'FAIL','error':str(error),'inputs_before':before,
                 'logs_sha256':{p.name:digest(p) for p in sorted(OUT.glob('*.log'))}}
        manifest_path.write_text(json.dumps(failure,indent=2)+'\n')
        if not (OUT/'first-failure.json').exists():(OUT/'first-failure.json').write_bytes(manifest_path.read_bytes())
        raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--jobs',type=int,default=2)
    build(parser.parse_args().jobs)
