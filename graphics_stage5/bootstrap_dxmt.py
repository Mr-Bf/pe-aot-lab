#!/usr/bin/env python3
"""Workspace-only pinned DXMT/LLVM15 preparation. Never install system packages."""
import argparse
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1];WORK=ROOT.parents[1]/'work/graphics-stage5'
sys.path.insert(0,str(ROOT))
OUT=ROOT/'build/graphics-stage5/bootstrap'
DXMT='d162ea44a31fbf9089ea09977337f0beb30bd082'
LLVM='8dfdcc7b7bf66834a761bd8de445840ef68e4d1a' # llvmorg-15.0.7, GitHub API verified
HEADERS='9df86f2341616ef1888ae59919feaa6d4fad693d' # DXMT's exact gitlink
CMAKE=ROOT.parents[1]/'work/remill-stage2/cmake/4.4.4/bin/cmake'
NINJA=ROOT.parents[1]/'work/remill-stage2/ninja/1.13.2/bin/ninja'
SOURCES=[('dxmt','3Shain/dxmt',DXMT),('llvm-project','llvm/llvm-project',LLVM),
         ('mingw-directx-headers','misyltoad/mingw-directx-headers',HEADERS)]
CACHE_PATCH=ROOT/'graphics_stage5/metal-module-cache.patch'
MESON_BEFORE='285cfd8a34e592d63b2ec7404d8e9108642775a14b7dc39260c7bd64661e888c'
MESON_AFTER='81ceffb0d5fb540cc03945d5cf32d80020b35d55ffaab85868e274dc22c12205'

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
    return h.hexdigest()
def require(value,message):
    if not value:raise RuntimeError(message)
class CommandFailure(RuntimeError):
    def __init__(self,record):
        self.record=record
        super().__init__('command failed; immutable log '+record['log'])
def run(command,name,env=None):
    command=list(map(str,command));log=OUT/(name+'.log')
    with log.open('w') as f:
        f.write(json.dumps(command)+'\n');f.flush()
        try:
            result=subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,env=env)
            returncode=result.returncode;launch_error=None
        except OSError as error:
            returncode=None;launch_error=str(error);f.write('\nlaunch error: '+str(error)+'\n')
    digest=sha(log);history=OUT/'command-logs';history.mkdir(exist_ok=True)
    saved=history/(name+'-'+digest+'.log')
    if saved.exists():require(sha(saved)==digest,'immutable command log changed')
    else:shutil.copyfile(log,saved)
    record={'command':command,'returncode':returncode,'log':str(saved),'log_sha256':digest}
    if launch_error is not None:record['launch_error']=launch_error
    if returncode!=0:raise CommandFailure(record)
    return record
def source_paths_confined(source):
    require(source.is_dir() and not source.is_symlink(),'source root must be a real directory')
    root=source.resolve()
    for path in source.rglob('*'):
        require(path.resolve().is_relative_to(root),'source link escapes extraction root: '+str(path))
def tree_identity(source):
    source_paths_confined(source)
    identity={}
    for path in sorted(source.rglob('*')):
        relative=str(path.relative_to(source))
        if path.is_symlink():identity[relative]=['symlink',os.readlink(path)]
        elif path.is_dir():identity[relative]=['directory']
        elif path.is_file():identity[relative]=['file',sha(path)]
        else:raise RuntimeError('special source path rejected: '+str(path))
    return identity
def bound_tree(source):
    return {'root':str(source.resolve()),'tree_identity':tree_identity(source)}
def apply_cache_patch(source):
    # Local build adaptation, not an upstream contribution. A fixed pre/post
    # identity prevents fuzzy patching or silently accepting another source.
    target=source/'meson.build'
    require(sha(CACHE_PATCH)=='e96a6bd671fae2b7aabd91c47b3f6716fe8dccfcac3d6679b9262298f6eb7df4',
            'Metal cache patch identity differs')
    if sha(target)==MESON_AFTER:return
    require(sha(target)==MESON_BEFORE,'unexpected DXMT meson.build before patch')
    result=subprocess.run(['/usr/bin/patch','--batch','-p1','-i',str(CACHE_PATCH)],cwd=source,
                          text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    require(result.returncode==0 and sha(target)==MESON_AFTER,'exact Metal cache patch failed: '+result.stdout)
def verify_archive_tree(entry,transform=None):
    """Compare cached source with a fresh extraction of the bound archive."""
    source=Path(entry['source']);archive=Path(entry['archive'])
    require(sha(archive)==entry['sha256'],'source archive identity changed')
    with tempfile.TemporaryDirectory(prefix='.verify-source-',dir=WORK/'sources') as temporary:
        reference=Path(temporary)/source.name
        extract_source_archive(archive,reference)
        (reference/'.pe-aot-source.json').write_text(json.dumps(
            {'archive_sha256':entry['sha256'],'commit':entry['commit']},indent=2)+'\n')
        if transform:transform(reference)
        require(tree_identity(source)==tree_identity(reference),'cached source differs from pinned archive: '+entry['name'])
def llvm_source():
    source=WORK/'sources'/('llvm-core-verified-'+LLVM)
    if source.exists():
        from graphics_stage5 import recover_llvm_source
        proof=recover_llvm_source.verify_recovered(source)
        return {'name':'llvm-project','repo':'llvm/llvm-project','commit':LLVM,'source':str(source),
                'kind':'verified-complete-git-subtrees-from-partial-archive','proof':proof,
                'recovery_script_sha256':sha(recover_llvm_source.__file__)}
    release=WORK/'downloads/llvm-15.0.7.src.tar.xz'
    if release.exists():
        from graphics_stage5 import llvm_release_source
        return llvm_release_source.materialize_and_verify()
    # Never restart the repeatedly truncated monorepo download implicitly.
    archive=WORK/'downloads'/('llvm-project-'+LLVM+'.tar.gz')
    require(archive.exists(),'LLVM source not ready: verify subtree recovery or fetch official release; no automatic whole-monorepo retry')
    return fetch(*SOURCES[1])
def prepare_headers(dxmt,header_source):
    # A copy keeps both pinned source roots self-contained across repeated
    # preparation. Never exempt a cross-root symlink from archive validation.
    destination=dxmt/'include/native/directx'
    expected=tree_identity(header_source)
    require(not destination.is_symlink(),'DXMT header destination must not be a symlink')
    if destination.is_dir() and not any(destination.iterdir()):destination.rmdir()
    if not destination.exists():shutil.copytree(header_source,destination,symlinks=True)
    require(tree_identity(destination)==expected,'DXMT directx header copy differs from pinned source')
    return destination
def validate_members(members,prefix):
    require(bool(members),'empty source archive')
    for m in members:
        path=PurePosixPath(m.name);parts=path.parts
        require(not path.is_absolute() and bool(parts) and parts[0]==prefix and '..' not in parts,
                'source archive member escapes expected prefix: '+m.name)
        require(m.isdir() or m.isfile() or m.issym() or m.islnk(),'special source archive member rejected')
        require(len(parts)>1 or m.isdir(),'source archive root must be a directory')
        if m.issym() or m.islnk():
            target=PurePosixPath(m.linkname)
            require(not target.is_absolute(),'absolute source archive link rejected')
            stack=list(parts[:-1]) if m.issym() else []
            for part in target.parts:
                if part=='.':continue
                if part=='..':
                    require(len(stack)>1,'source archive link escapes expected prefix')
                    stack.pop()
                else:stack.append(part)
            require(bool(stack) and stack[0]==prefix,'source archive link outside expected prefix')
def extract_source_archive(archive,source):
    archive=Path(archive);source=Path(source)
    require(not source.exists() and not source.is_symlink(),'source destination already exists')
    source.parent.mkdir(parents=True,exist_ok=True)
    # tarfile's data filter is relative to the destination, so give each archive
    # a private container. Never let it write directly into the shared sources
    # parent. Reject lexical escapes before extraction and resolved link-chain
    # escapes afterward, before publishing any source directory.
    with tarfile.open(archive) as t:
        validate_members(t.getmembers(),source.name)
        with tempfile.TemporaryDirectory(prefix='.extract-',dir=source.parent) as temporary:
            t.extractall(temporary,filter='data')
            extracted=Path(temporary)/source.name
            source_paths_confined(extracted)
            extracted.rename(source)
def fetch(name,repo,commit):
    url=f'https://codeload.github.com/{repo}/tar.gz/{commit}'
    archive=WORK/'downloads'/(name+'-'+commit+'.tar.gz');metadata=archive.with_suffix('.json')
    archive.parent.mkdir(parents=True,exist_ok=True)
    if archive.exists():
        require(metadata.exists(),'archive without identity metadata: '+str(archive))
        expected=json.loads(metadata.read_text());require(sha(archive)==expected['sha256'] and expected['url']==url,'cached archive changed')
    else:
        temporary=archive.with_suffix('.partial')
        request=urllib.request.Request(url,headers={'User-Agent':'pe-aot-lab-workspace-bootstrap'})
        with urllib.request.urlopen(request,timeout=120) as response,temporary.open('wb') as f:
            shutil.copyfileobj(response,f,1024*1024)
        digest=sha(temporary);temporary.replace(archive)
        metadata.write_text(json.dumps({'url':url,'commit':commit,'sha256':digest},indent=2)+'\n')
    source=WORK/'sources'/(name+'-'+commit);stamp=source/'.pe-aot-source.json'
    if not source.exists():
        extract_source_archive(archive,source)
        stamp.write_text(json.dumps({'archive_sha256':sha(archive),'commit':commit},indent=2)+'\n')
    source_paths_confined(source)
    require(stamp.exists() and json.loads(stamp.read_text())['archive_sha256']==sha(archive),'source extraction identity mismatch')
    return {'name':name,'repo':repo,'commit':commit,'url':url,'archive':str(archive),'sha256':sha(archive),'source':str(source)}
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--fetch-only',action='store_true');parser.add_argument('--llvm',action='store_true')
    parser.add_argument('--dxmt',action='store_true');parser.add_argument('--jobs',type=int,default=4);args=parser.parse_args()
    require(sys.version_info>=(3,12),'Python 3.12+ required for safe tar extraction')
    require(1<=args.jobs<=8,'bounded build concurrency 1..8 required')
    OUT.mkdir(parents=True,exist_ok=True);WORK.mkdir(parents=True,exist_ok=True)
    evidence=OUT/'evidence.json'
    if evidence.exists():
        history=OUT/'history';history.mkdir(exist_ok=True);shutil.copyfile(evidence,history/(sha(evidence)+'.json'))
    record={'status':'RUNNING','script_sha256':sha(__file__),'sources':[],'commands':[],
            'scope':'dependency preparation only; no DXMT rendering or guest execution proof',
            'source_identity_limit':'fetch-only stamps are bookkeeping; builds compare original archives plus explicit patch/header copy, exact Git subtrees, or official release assets; release source is not claimed to reproduce the Git tree; hashes are not signatures'}
    evidence.write_text(json.dumps(record,indent=2)+'\n')
    try:
        for entry in SOURCES:
            record['sources'].append(llvm_source() if entry[0]=='llvm-project' else fetch(*entry))
            evidence.write_text(json.dumps(record,indent=2)+'\n')
        paths={s['name']:Path(s['source']) for s in record['sources']}
        scripts=[Path(__file__).resolve()]
        if record['sources'][1].get('kind')=='official-llvm-15.0.7-release-assets':
            scripts.extend([ROOT/'graphics_stage5/llvm_release_source.py',ROOT/'graphics_stage5/fetch_llvm_release.py'])
        elif record['sources'][1].get('kind')=='verified-complete-git-subtrees-from-partial-archive':
            scripts.append(ROOT/'graphics_stage5/recover_llvm_source.py')
        record['source_scripts']={str(path):sha(path) for path in scripts}
        def require_scripts_current():
            require(sha(__file__)==record['script_sha256'] and
                    {str(path):sha(path) for path in scripts}==record['source_scripts'],
                    'bootstrap/source preparation changed while executing')
        dxmt=paths['dxmt'];prepare_headers(dxmt,paths['mingw-directx-headers'])
        install=WORK/'llvm15-install';llvm_build=WORK/'llvm15-build'
        receipt=OUT/'llvm-build-receipt.json'
        if args.llvm or args.dxmt:
            verify_archive_tree(record['sources'][2])
            apply_cache_patch(dxmt)
            def transform(reference):
                prepare_headers(reference,paths['mingw-directx-headers']);apply_cache_patch(reference)
            verify_archive_tree(record['sources'][0],transform)
            if record['sources'][1].get('kind') is None:verify_archive_tree(record['sources'][1])
            record['source_validation']='BOUND_ARCHIVES_OR_RELEASE_ASSETS_OR_VERIFIED_GIT_SUBTREES_PLUS_EXACT_PATCH_AND_HEADER_COPY'
        if args.llvm:
            llvm_before=bound_tree(paths['llvm-project'])
            configure=[CMAKE,'-S',paths['llvm-project']/'llvm','-B',llvm_build,'-G','Ninja',
                '-DCMAKE_MAKE_PROGRAM='+str(NINJA),'-DCMAKE_C_COMPILER=/usr/bin/clang','-DCMAKE_CXX_COMPILER=/usr/bin/clang++',
                '-DCMAKE_INSTALL_PREFIX='+str(install),'-DCMAKE_OSX_ARCHITECTURES=arm64',
                '-DLLVM_HOST_TRIPLE=arm64-apple-darwin','-DLLVM_ENABLE_ASSERTIONS=ON','-DLLVM_ENABLE_ZSTD=OFF',
                '-DLLVM_TARGETS_TO_BUILD=','-DLLVM_BUILD_TOOLS=OFF','-DLLVM_INCLUDE_TESTS=OFF',
                '-DLLVM_INCLUDE_BENCHMARKS=OFF','-DLLVM_INCLUDE_EXAMPLES=OFF','-DCMAKE_BUILD_TYPE=Release',
                '-DCMAKE_POLICY_VERSION_MINIMUM=3.5','-DBUG_REPORT_URL=https://github.com/3Shain/dxmt','-DPACKAGE_VENDOR=DXMT',
                '-DLLVM_VERSION_PRINTER_SHOW_HOST_TARGET_INFO=OFF']
            record['commands'].append(run(configure,'llvm-configure'))
            record['commands'].append(run([CMAKE,'--build',llvm_build,'--parallel',args.jobs],'llvm-build'))
            record['commands'].append(run([CMAKE,'--install',llvm_build],'llvm-install'))
            require((install/'lib/libLLVMCore.a').is_file(),'LLVM static library absent')
            require(bound_tree(paths['llvm-project'])==llvm_before,'LLVM source changed during build')
            require_scripts_current()
            llvm_record={'schema':1,'status':'LLVM_BUILT','commit':LLVM,'script_sha256':record['script_sha256'],
                         'source':llvm_before,'install':bound_tree(install),'commands':record['commands'],
                         'scope':'native static LLVM dependency build; no DXMT or guest execution'}
            receipt.write_text(json.dumps(llvm_record,indent=2)+'\n')
            record['llvm_install']=str(install)
        if args.dxmt:
            require((install/'lib/libLLVMCore.a').is_file(),'run --llvm first')
            require(receipt.is_file(),'LLVM build receipt missing')
            llvm_record=json.loads(receipt.read_text())
            require(llvm_record.get('status')=='LLVM_BUILT' and llvm_record.get('commit')==LLVM and
                    llvm_record.get('script_sha256')==record['script_sha256'],'LLVM build receipt identity differs')
            require(llvm_record['source']==bound_tree(paths['llvm-project']) and
                    llvm_record['install']==bound_tree(install),'LLVM source/install changed since build')
            record['llvm_receipt']={'path':str(receipt),'sha256':sha(receipt)}
            def dxmt_inputs():
                return {'source':bound_tree(dxmt),'headers':bound_tree(paths['mingw-directx-headers']),
                        'llvm_install':bound_tree(install),'patches':{str(CACHE_PATCH.resolve()):sha(CACHE_PATCH)}}
            dxmt_before=dxmt_inputs()
            packages=WORK/'python';env={**os.environ,'PYTHONPATH':str(packages),'PATH':str(NINJA.parent)+':'+os.environ.get('PATH','')}
            if not (packages/'mesonbuild').is_dir():
                record['commands'].append(run([sys.executable,'-m','pip','install','--disable-pip-version-check','--no-deps','--no-compile',
                    '--target',packages,'meson==1.10.0'],'meson-install'))
            build=WORK/'dxmt-build'
            configure=[sys.executable,'-m','mesonbuild.mesonmain','setup',build,dxmt,'--buildtype=release',
                       '-Dnative_llvm_path='+str(install),'-Denable_nvapi=false','-Denable_nvngx=false','-Denable_d3d12=false']
            if (build/'meson-private/coredata.dat').exists():configure.append('--reconfigure')
            record['commands'].append(run(configure,'dxmt-configure',env))
            record['commands'].append(run([sys.executable,'-m','mesonbuild.mesonmain','compile','-C',build,'-j',args.jobs],'dxmt-build',env))
            after=dxmt_inputs();require(after==dxmt_before,'DXMT build inputs changed during build')
            outputs={str(path.resolve()):{'realpath':str(path.resolve()),'sha256':sha(path)}
                     for path in sorted(build.rglob('*.dylib')) if path.is_file()}
            require(str((build/'src/d3d11/d3d11.dylib').resolve()) in outputs,'native d3d11 output missing')
            record['dxmt_provenance']={'schema':1,'profile':'native-dxmt-build-v1',
                                       'inputs_before':dxmt_before,'inputs_after':after,'outputs':outputs}
            record['dxmt_build']=str(build)
        require_scripts_current()
        record['status']='DEPENDENCIES_BUILT' if args.llvm or args.dxmt else 'SOURCES_FETCHED_NOT_BUILT'
        evidence.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps({'status':record['status'],'evidence':str(evidence)}))
    except Exception as error:
        if isinstance(error,CommandFailure):record['commands'].append(error.record)
        record.update(status='FAIL',error=str(error));evidence.write_text(json.dumps(record,indent=2)+'\n')
        failure=OUT/'first-failure.json'
        if not failure.exists():shutil.copyfile(evidence,failure)
        raise
if __name__=='__main__':main()
