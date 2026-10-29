"""Build the actual window/lifetime DXMT backend from fixed offline sources.

No historical backend, LLVM installation, build tree or success receipt is an
input. Python, the selected Apple developer directory and SDK are external.
"""
import json
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import struct
import sys
import traceback

from portable_lifter_v1 import build as common, tools as binary
from graphics_stage5 import d3d11_probe as macho_graph
from . import cache, tooling, llvm

REPO=Path(__file__).resolve().parents[1]
PROFILE='native-window-wsi-v1-plus-lifetime-v2-r2'
STATUS='GRAPHICS_PROVIDER_BUILT_NOT_EXECUTED'
MINIMUM='15.2'
NAMES=('d3d11.dylib','dxgi.dylib','winemetal.dylib')
PATCHES=[REPO/'graphics_stage5/metal-module-cache.patch',REPO/'native_window/native-wsi-v1.patch',
         REPO/'graphics_stage5/lifetime_v2/dxmt-lifetime-v2.patch']
ADAPTERS={REPO/'native_window/native_wsi.h':'include/native_wsi.h',
          REPO/'native_window/native_wsi.c':'src/nativemetal/native_wsi.c'}
SOURCES=[REPO/'portable_graphics_v1'/name for name in
         ('__init__.py','__main__.py','build.py','cache.py','cache-lock.json','tooling.py','llvm.py')]
SOURCES += [REPO/'portable_lifter_v1'/name for name in ('__init__.py','build.py','tools.py','deps.py')]
SOURCES += [REPO/'graphics_stage5/d3d11_probe.py',REPO/'graphics_stage5/bootstrap_dxmt.py',*PATCHES,*ADAPTERS]
SOURCES += [REPO/'portable_graphics_v1/licenses/DXBCParser-MIT.txt']
require=common.require
digest=common.digest
write=common.write_json


def tree(root):
    root=Path(root)
    require(root.is_dir() and not root.is_symlink(),'real source directory required')
    result={}
    for path in sorted(root.rglob('*')):
        relative=str(path.relative_to(root))
        if path.is_symlink():
            require(path.resolve().is_relative_to(root.resolve()),'tree link escapes root')
            result[relative]={'symlink':os.readlink(path)}
        elif path.is_file():
            require(path.stat().st_nlink==1,'hardlinked provider file rejected')
            result[relative]={'sha256':digest(path),'mode':stat.S_IMODE(path.stat().st_mode)}
        else:
            require(path.is_dir(),'special provider member rejected')
    return result


def minimum(path):
    binary.macho(path)
    with Path(path).open('rb') as stream:
        header=stream.read(32)
        _,_,_,_,count,size,_,_=struct.unpack('<8I',header)
        commands=stream.read(size)
    offset=0;versions=[]
    for _ in range(count):
        kind,length=struct.unpack_from('<II',commands,offset)
        if kind==0x32:
            require(length>=24,'short build version command')
            target,value,sdk,_=struct.unpack_from('<4I',commands,offset+8)
            require(target==1,'non-macOS deployment target')
            versions.append((value,sdk))
        elif kind==0x24:
            require(length>=16,'short minimum version command')
            versions.append(struct.unpack_from('<II',commands,offset+8))
        offset+=length
    require(len(versions)==1,'one macOS deployment target required')
    def decode(value):return [value>>16,(value>>8)&255,value&255]
    return {'minimum':decode(versions[0][0]),'sdk':decode(versions[0][1])}


def native_file(path,sdk):
    compile_flags=['-arch','arm64','-isysroot',str(sdk),'-mmacosx-version-min='+MINIMUM]
    link_flags=[*compile_flags,'-Wl,-syslibroot,'+str(sdk),'--ld-path=/usr/bin/ld']
    lines=['[binaries]',"c = '/usr/bin/clang'","cpp = '/usr/bin/clang++'",
           "ar = '/usr/bin/ar'","strip = '/usr/bin/strip'",'[built-in options]']
    for name,value in [('c_args',compile_flags),('cpp_args',compile_flags),('c_link_args',link_flags),('cpp_link_args',link_flags)]:
        # Meson machine files use its expression syntax, not JSON arrays.
        require(all(not any(c in item for c in "'\\\r\n") for item in value),
                'unsupported character in Meson machine argument')
        require(all(not any(token in item for token in ('@DIRNAME@','@GLOBAL_SOURCE_ROOT@')) for item in value),
                'Meson substitution token in machine argument')
        lines.append(name+" = ["+', '.join("'"+item+"'" for item in value)+']')
    with path.open('x') as stream:stream.write('\n'.join(lines)+'\n')


def notices(prefix,source,llvm_source,headers):
    target=prefix/'licenses';target.mkdir()
    selected={'DXMT-LICENSE':source/'LICENSE','DXMT-COPYING.LIB':source/'COPYING.LIB',
              'LLVM15-LICENSE.TXT':llvm_source/'llvm/LICENSE.TXT',
              'DirectX-Headers-COPYING.MinGW-w64.txt':headers/'COPYING.MinGW-w64.txt',
              'DirectX-Headers-README.md':headers/'README.md'}
    selected['DXBCParser-MIT.txt']=REPO/'portable_graphics_v1/licenses/DXBCParser-MIT.txt'
    for name,path in selected.items():
        require(path.is_file(),'required upstream notice absent: '+str(path))
        shutil.copy2(path,target/name)
    # Preserve the original source notices verbatim with their surrounding
    # files; no guessed copyright holders or rewritten license paragraphs.
    for directory,label in [(source/'libs/DXBCParser','DXBCParser'),
                            (source/'include/native/windows','Windows-Headers')]:
        for path in sorted(directory.rglob('*')):
            if path.is_file():
                destination=target/label/path.relative_to(directory)
                destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,destination)
    for path in PATCHES:
        destination=target/'BackendChanges'/path.name
        destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,destination)
    for path in ADAPTERS:
        shutil.copy2(path,target/'BackendChanges'/path.name)
    return tree(target)


def runtime_command(path,info):
    path=Path(path)
    require(path.name in NAMES,'unknown runtime library role')
    require(len(info['rpaths'])==len(set(info['rpaths'])),'duplicate runtime rpath')
    command=['/usr/bin/install_name_tool','-id','@rpath/'+path.name]
    for dependency in info['dependencies']:
        if binary.system_image(dependency):continue
        basename=Path(dependency).name
        require(basename in NAMES,'unrecognized non-system dependency')
        command.extend(['-change',dependency,'@rpath/'+basename])
    for rpath in info['rpaths']:
        if rpath!='@loader_path/':command.extend(['-delete_rpath',rpath])
    if '@loader_path/' not in info['rpaths']:
        command.extend(['-add_rpath','@loader_path/'])
    return [*command,path]


def build(prefix, cache_path, out, jobs=2):
    require(sys.version_info>=(3,13),'Python >= 3.13 required; current tested external interpreter is 3.13')
    require(platform.system()=='Darwin' and platform.machine()=='arm64','native Apple Silicon required')
    require(type(jobs) is int and 1<=jobs<=2,'jobs must be 1..2')
    prefix,cache_path,out=map(binary.real_path,(prefix,cache_path,out))
    require(not prefix.exists(),'fresh graphics prefix required')
    require(not prefix.is_relative_to(common.OLD_WORK),'provider must be outside historical work')
    require(not out.is_relative_to(prefix) and not prefix.is_relative_to(out),'separate evidence/prefix required')
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


def paths_for(prefix):
    prefix=binary.real_path(prefix);manifest=prefix/'provider.json'
    require(manifest.is_file() and not manifest.is_symlink(),'regular graphics provider manifest required')
    raw=manifest.read_bytes();manifest_sha=hashlib.sha256(raw).hexdigest();record=json.loads(raw)
    require(record.get('schema')==1 and record.get('status')==STATUS and record.get('profile')==PROFILE,'unsupported graphics provider')
    require(record.get('minimum_macos')==MINIMUM,'graphics deployment target differs')
    require(set(record.get('layout',{}))=={'source','d3d11','dxgi','winemetal'},'graphics roles differ')
    require(all(record['layout'][name[:-6]]=='runtime/'+name for name in NAMES),'canonical distinct graphics library roles required')
    def local(relative):
        require(type(relative) is str and bool(relative) and not Path(relative).is_absolute() and '..' not in Path(relative).parts,'relative provider path required')
        path=prefix/relative;require(path.resolve().is_relative_to(prefix),'graphics provider path escaped');return path
    paths={key:local(value) for key,value in record['layout'].items()}
    require(type(record.get('source_tree')) is dict and bool(record['source_tree']),'graphics source inventory required')
    require(tree(paths['source'])==record['source_tree'],'graphics source/header identity changed')
    for relative in ('include/native/directx/d3d11.h','include/native/directx/dxgi.h',
                     'include/native/windows/windows.h','include/native_wsi.h','src/nativemetal/native_wsi.c'):
        require((paths['source']/relative).is_file(),'required graphics source/header absent: '+relative)
    require(set(record['runtime_files'])=={record['layout'][name[:-6]] for name in NAMES},'graphics runtime file coverage differs')
    for relative,identity in record['runtime_files'].items():
        path=local(relative)
        require(path.is_file() and not path.is_symlink() and digest(path)==identity['sha256'] and stat.S_IMODE(path.stat().st_mode)==identity['mode'],'graphics runtime identity changed')
        info=binary.macho(path)
        require(info['filetype']==6 and info['identity']=='@rpath/'+path.name and
                info['rpaths']==['@loader_path/'] and path.stat().st_mode&0o111,'graphics dylib identity/search paths differ')
        require(minimum(path)['minimum']==[15,2,0],'graphics minimum OS changed')
    graph=binary.selected_closure(prefix,[paths['d3d11']])
    require(set(graph['nodes'])=={str(paths[name[:-6]]) for name in NAMES},'graphics runtime dependency closure changed')
    required_licenses={'DXMT-LICENSE','DXMT-COPYING.LIB','LLVM15-LICENSE.TXT',
                       'DirectX-Headers-COPYING.MinGW-w64.txt','DirectX-Headers-README.md','DXBCParser-MIT.txt',
                       *('BackendChanges/'+p.name for p in [*PATCHES,*ADAPTERS])}
    require(type(record.get('licenses')) is dict and required_licenses<=set(record['licenses']),'graphics license inventory incomplete')
    license_root=prefix/'licenses';require(tree(license_root)==record['licenses'],'graphics notices changed')
    for name in required_licenses:
        path=license_root/name
        require(path.is_file() and not path.is_symlink() and 'sha256' in record['licenses'][name],
                'required graphics notice must be a regular file: '+name)
    sdk=Path(record['external_prerequisites']['sdk']);require(sdk.is_absolute() and sdk.is_dir(),'graphics SDK absent')
    settings=record['external_prerequisites'].get('sdk_settings')
    require(type(settings) is dict and bool(settings),'graphics SDK identity required')
    for name,value in settings.items():
        require(name in ('SDKSettings.json','SDKSettings.plist') and digest(sdk/name)==value,'graphics SDK identity changed')
    require(digest(manifest)==manifest_sha,'graphics provider manifest changed during verification')
    return dict(**paths,sdk=sdk,minimum_macos=MINIMUM,provider_manifest=manifest,provider_sha256=manifest_sha,
                licenses={name:license_root/name for name in record['licenses'] if 'sha256' in record['licenses'][name]})
