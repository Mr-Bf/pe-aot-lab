"""Build the native backend with the public v2 cache and frozen compile pipeline.

The build body retains v1 compilation, flags, patching and provider contracts.
Only cache selection, disjoint paths and early failure evidence are different.
"""
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import traceback

from portable_graphics_v1 import build as frozen, tooling, llvm
from portable_lifter_v1 import build as common, tools as binary
from graphics_stage5 import d3d11_probe as macho_graph
from . import cache

REPO = frozen.REPO
PROFILE, STATUS, MINIMUM, NAMES = frozen.PROFILE, frozen.STATUS, frozen.MINIMUM, frozen.NAMES
PATCHES, ADAPTERS = frozen.PATCHES, frozen.ADAPTERS
require, digest, write = frozen.require, frozen.digest, frozen.write
tree, minimum, native_file = frozen.tree, frozen.minimum, frozen.native_file
notices, runtime_command, paths_for = frozen.notices, frozen.runtime_command, frozen.paths_for
SOURCES = [*frozen.SOURCES, *(Path(__file__).parent/name for name in
           ('__init__.py', '__main__.py', 'build.py', 'cache.py', 'cache-lock.json'))]

def build(prefix, cache_path, out, jobs=2):
    require(sys.version_info>=(3,13),'Python >= 3.13 required; current tested external interpreter is 3.13')
    require(platform.system()=='Darwin' and platform.machine()=='arm64','native Apple Silicon required')
    require(type(jobs) is int and 1<=jobs<=2,'jobs must be 1..2')
    prefix,cache_path,out=map(binary.real_path,(prefix,cache_path,out))
    require(not prefix.exists(),'fresh graphics prefix required')
    require(not prefix.is_relative_to(common.OLD_WORK),'provider must be outside historical work')
    for left,right in ((prefix,cache_path),(prefix,out),(cache_path,out)):
        require(not left.is_relative_to(right) and not right.is_relative_to(left),
                'graphics cache, provider and evidence must be disjoint')
    out=common.fresh(out);run=common.Recorder(out,prefix)
    snapshot=common.source_snapshot(out,SOURCES)
    write(out/'started.json',dict(prefix=str(prefix),cache=str(cache_path),started_at=common.now(),sources=snapshot))
    try:
        cache_before=cache.check_cache(cache_path)
        prefix.mkdir(parents=True)
        developer=Path(run(['/usr/bin/xcode-select','-p'],'apple-developer')['stdout'].strip()).resolve(strict=True)
        run.env['DEVELOPER_DIR']=str(developer)
        sdk=Path(run(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-path'],'apple-sdk')['stdout'].strip()).resolve(strict=True)
        require(sdk.is_relative_to(developer),'SDK must belong to selected Apple developer directory')
        sdk_version=run(['/usr/bin/xcrun','--sdk','macosx','--show-sdk-version'],'apple-sdk-version')['stdout'].strip()
        external={'developer':str(developer),'sdk':str(sdk),'sdk_version':sdk_version,
                  'python':str(Path(sys.executable).resolve()),'python_sha256':digest(Path(sys.executable).resolve()),
                  'sdk_settings':{p.name:digest(p) for p in (sdk/'SDKSettings.json',sdk/'SDKSettings.plist') if p.is_file()},
                  'tools':{}}
        require(external['sdk_settings'],'SDK identity unavailable')
        for name in ('clang','clang++','ar','ld','metal','metallib'):
            path=Path(run(['/usr/bin/xcrun','--sdk','macosx','--find',name],'apple-'+name.replace('+','p'))['stdout'].strip()).resolve(strict=True)
            external['tools'][name]={'path':str(path),'sha256':digest(path)}
        for name in ('touch','xxd','patch','git','install_name_tool','codesign'):
            path=Path('/usr/bin')/name;require(path.is_file(),'missing system build command: '+name)
            external['tools'][name]={'path':str(path),'sha256':digest(path)}
        write(out/'external-prerequisites.json',external)
        run.env.update(SDKROOT=str(sdk),MACOSX_DEPLOYMENT_TARGET=MINIMUM,PYTHONNOUSERSITE='1')
        installed=tooling.install(prefix/'tools',cache_path,sdk,Path(sys.executable).resolve(),run)
        tool_receipt=prefix/'tools/tooling.json'
        tool_receipt_sha=digest(tool_receipt);tool_record=json.loads(tool_receipt.read_text())
        run.env['PATH']=':'.join(map(str,(installed['cmake'].parent,installed['ninja'].parent)))+':/usr/bin:/bin:/usr/sbin:/sbin'
        inputs=cache.extract_sources(cache_path,prefix/'sources')
        llvm_source,source,headers=(Path(inputs[name]) for name in ('llvm','dxmt','headers'))
        built_llvm=llvm.build(llvm_source,prefix/'llvm-build',prefix/'llvm-install',installed,sdk,
                              Path(sys.executable).resolve(),run,jobs=jobs)
        write(out/'llvm.json',built_llvm)
        original=tree(source);header_identity=tree(headers)
        destination=source/'include/native/directx'
        require(not destination.is_symlink(),'DirectX header destination is a symlink')
        if destination.exists():
            require(destination.is_dir() and not any(destination.iterdir()),'DirectX header destination not empty')
            destination.rmdir()
        shutil.copytree(headers,destination,symlinks=True)
        require(tree(destination)==header_identity,'copied header source differs')
        for index,patch in enumerate(PATCHES):
            record=run(['/usr/bin/patch','--batch','--forward','-F','0','-p1','-i',patch],f'dxmt-patch-{index+1}',cwd=source)
            require(not re.search(r'\b(?:offset|fuzz|FAILED|Reversed|previously applied)\b',record['stdout']+record['stderr'],re.I),'inexact DXMT patch')
        for path,relative in ADAPTERS.items():
            destination=source/relative;require(not destination.exists(),'adapter would overwrite upstream file')
            shutil.copy2(path,destination)
        source_before=tree(source)
        write(out/'prepared-source.json',dict(original=original,headers=header_identity,prepared=source_before,
                    patches={str(p.relative_to(REPO)):digest(p) for p in PATCHES},
                    adapters={str(p.relative_to(REPO)):dict(destination=d,sha256=digest(p)) for p,d in ADAPTERS.items()}))
        configuration=prefix/'native.ini';native_file(configuration,sdk)
        shutil.copy2(configuration,out/'native.ini')
        env=tooling.meson_env(installed,Path(sys.executable).resolve(),sdk)
        env.update(DEVELOPER_DIR=str(developer),MACOSX_DEPLOYMENT_TARGET=MINIMUM,
                   GIT_CEILING_DIRECTORIES=str(prefix.parent),GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null')
        meson=[Path(sys.executable).resolve(),'-S','-m','mesonbuild.mesonmain']
        target=prefix/'dxmt-build'
        run([*meson,'setup',target,source,'--native-file',configuration,'--buildtype=release','--wrap-mode=nodownload',
             '-Dnative_llvm_path='+str(prefix/'llvm-install'),'-Denable_nvapi=false','-Denable_nvngx=false',
             '-Denable_d3d12=false','-Denable_tests=false'],'dxmt-configure',env=env)
        run([*meson,'compile','-C',target,'-j',str(jobs)],'dxmt-build',env=env)
        require(tree(source)==source_before and tree(headers)==header_identity,'backend source changed during build')
        outputs=sorted(target.rglob('*.dylib'))
        require({p.name for p in outputs}=={*NAMES,'d3d10core.dylib'} and len(outputs)==4,'unexpected backend dylib outputs')
        source_map={p.name:p for p in outputs}
        raw={str(p):dict(sha256=digest(p),macho=binary.macho(p),deployment=minimum(p)) for p in outputs}
        require(all(item['deployment']['minimum']==[15,2,0] for item in raw.values()),'native backend deployment target differs')
        original_graph=macho_graph.library_graph(source_map['d3d11.dylib'],target/'not-executed',[source_map['d3d11.dylib'].parent])
        require(set(original_graph['nodes'])=={str(source_map[n]) for n in NAMES},'raw backend dependency escaped current build')
        write(out/'raw-outputs.json',dict(outputs=raw,graph=original_graph,observed_before_runtime_packaging=True))
        runtime=prefix/'runtime';runtime.mkdir()
        for name in NAMES:
            original_path=source_map[name];path=runtime/name;shutil.copy2(original_path,path)
            info=binary.macho(path);command=runtime_command(path,info)
            run(command,'runtime-paths-'+name)
            run(['/usr/bin/codesign','--force','--sign','-',path],'runtime-sign-'+name)
            run(['/usr/bin/codesign','--verify','--strict',path],'runtime-signature-'+name)
            require(minimum(path)==raw[str(original_path)]['deployment'],'path repair changed deployment target')
        graph=binary.selected_closure(prefix,[runtime/'d3d11.dylib'])
        require(set(graph['nodes'])=={str(runtime/n) for n in NAMES},'runtime closure differs')
        licenses=notices(prefix,source,llvm_source,headers)
        for name in ('build.ninja','compile_commands.json','meson-info/intro-compilers.json','version.h'):
            path=target/name;require(path.is_file(),'generated backend metadata absent: '+name)
            data=path.read_bytes();require(str(common.OLD_WORK).encode() not in data,'old work path in backend metadata')
            # sys.executable is the declared external Python prerequisite.
            stripped=data.replace(str(Path(sys.executable).resolve()).encode(),b'EXTERNAL_PYTHON')
            require(b'/opt/homebrew/' not in stripped,'uncontrolled Homebrew backend dependency')
            destination=out/'metadata'/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,destination)
        require(cache.check_cache(cache_path)==cache_before,'offline cache changed')
        require(llvm.tree(prefix/'llvm-install')==built_llvm['installed_files'],'LLVM installation changed during backend build')
        require(digest(tool_receipt)==tool_receipt_sha and tooling.inventory(installed['meson'])==tool_record['meson_files'],
                'Meson/tool installation changed during backend build')
        for path,info in tool_record['selected_graph']['nodes'].items():
            require(digest(path)==info['sha256'],'build tool image changed')
        for info in external['tools'].values():
            require(digest(info['path'])==info['sha256'],'external Apple/system tool changed during build')
        require(digest(external['python'])==external['python_sha256'],'external Python changed during build')
        for name,value in external['sdk_settings'].items():
            require(digest(sdk/name)==value,'SDK settings changed during build')
        common.check_sources(snapshot)
        runtime_files={str((runtime/name).relative_to(prefix)):{'sha256':digest(runtime/name),'mode':stat.S_IMODE((runtime/name).stat().st_mode)} for name in NAMES}
        provider=dict(schema=1,status=STATUS,profile=PROFILE,minimum_macos=MINIMUM,
             layout={'source':str(source.relative_to(prefix)),**{name[:-6]:str((runtime/name).relative_to(prefix)) for name in NAMES}},
             runtime_files=runtime_files,source_tree=source_before,licenses=licenses,external_prerequisites=external,
             implementation=snapshot,cache=cache_before,guest_executions=0,gpu_executions=0,backend_loads=0,
             limitation='Fresh full native-window/lifetime backend build. Not loaded, not integrated into a new App, not a clean-machine test.')
        write(prefix/'provider.json',provider)
        write(out/'result.json',dict(status=STATUS,provider_sha256=digest(prefix/'provider.json'),prefix=str(prefix),
                   commands=run.commands,raw_outputs=raw,raw_graph=original_graph,runtime_graph=graph,finished_at=common.now()))
        return provider
    except Exception as error:
        write(out/'failure.json',dict(status='FAIL',error=str(error),traceback=traceback.format_exc(),
                                     commands=run.commands,finished_at=common.now()))
        raise
