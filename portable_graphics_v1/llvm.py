"""Build native LLVM15 static dependencies from an already verified new source root."""
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import traceback

from . import tooling

require, sha, real, write = tooling.require, tooling.sha, tooling.real, tooling.write
LIBRARIES = tuple('LLVM' + name for name in (
    'Passes', 'Target', 'ObjCARCOpts', 'Coroutines', 'ipo', 'Instrumentation', 'Vectorize', 'Linker', 'IRReader',
    'AsmParser', 'FrontendOpenMP', 'ScalarOpts', 'InstCombine', 'AggressiveInstCombine', 'TransformUtils',
    'BitWriter', 'Analysis', 'ProfileData', 'Symbolize', 'DebugInfoPDB', 'DebugInfoMSF', 'DebugInfoDWARF',
    'Object', 'TextAPI', 'MCParser', 'MC', 'DebugInfoCodeView', 'BitReader', 'Core', 'Remarks',
    'BitstreamReader', 'BinaryFormat', 'Support', 'Demangle'))
OLD_WORK = Path(__file__).resolve().parents[3] / 'work'


def tree(root):
    result = {}
    for path in sorted(root.rglob('*')):
        name = str(path.relative_to(root)); mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            require(path.resolve().is_relative_to(root) and path.resolve().exists(), 'tree alias escaped/broken')
            result[name] = dict(type='symlink', target=os.readlink(path), mode=mode)
        elif path.is_file():
            require(path.stat().st_nlink == 1, 'tree hardlink unsupported')
            result[name] = dict(type='file', sha256=sha(path), mode=mode)
        else:
            require(path.is_dir(), 'special file unsupported')
            result[name] = dict(type='directory', mode=mode)
    return result


def arm_archive(path):
    """Read every ar member header to reject foreign objects without running lipo."""
    objects = 0; total = path.stat().st_size
    with path.open('rb') as stream:
        require(stream.read(8) == b'!<arch>\n', 'static archive required: ' + str(path))
        while True:
            header = stream.read(60)
            if not header:
                break
            require(len(header) == 60 and header[58:] == b'`\n', 'invalid ar header')
            size = int(header[48:58]); name = header[:16].decode().strip(); payload = stream.tell()
            require(size >= 0 and payload + size <= total, 'truncated ar member')
            name_size = 0
            if name.startswith('#1/'):
                name_size = int(name[3:]); require(0 <= name_size <= size, 'invalid BSD ar name')
                name = stream.read(name_size).rstrip(b'\0').decode()
            name = name.rstrip('/')
            if not name.startswith('__.SYMDEF') and name not in ('', '/'):
                h = stream.read(32)
                require(len(h) == 32 and size - name_size >= 32, 'short object header')
                magic, cpu, subtype, kind, commands, command_size, flags, reserved = struct.unpack('<8I', h)
                require((magic, cpu, kind) == (0xfeedfacf, 0x100000c, 1), 'non ARM64 object: ' + name)
                require(command_size <= size - name_size - 32 and commands <= command_size // 8,
                        'object load commands exceed member')
                objects += 1
            stream.seek(payload + size)
            if size & 1:
                require(stream.read(1) == b'\n', 'invalid ar alignment')
    require(objects > 0, 'archive has no objects')
    return dict(sha256=sha(path), objects=objects)


def plan(source, build_dir, install, tools, sdk, python, jobs):
    cmake, ninja = tools['cmake'], tools['ninja']
    options = [
        '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_SHARED_LIBS=OFF', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON',
        '-DCMAKE_C_COMPILER=/usr/bin/clang', '-DCMAKE_CXX_COMPILER=/usr/bin/clang++',
        '-DCMAKE_ASM_COMPILER=/usr/bin/clang', '-DCMAKE_AR=/usr/bin/ar', '-DCMAKE_RANLIB=/usr/bin/ranlib',
        '-DCMAKE_OSX_ARCHITECTURES=arm64', '-DCMAKE_OSX_DEPLOYMENT_TARGET=15.2', '-DCMAKE_OSX_SYSROOT=' + str(sdk),
        '-DCMAKE_INSTALL_PREFIX=' + str(install), '-DCMAKE_MAKE_PROGRAM=' + str(ninja), '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
        '-DCMAKE_POLICY_VERSION_MINIMUM=3.5', '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF',
        '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF',
        '-DCMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH=OFF', '-DCMAKE_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local',
        '-DCMAKE_SYSTEM_IGNORE_PREFIX_PATH=/opt/homebrew;/usr/local', '-DCMAKE_PREFIX_PATH=',
        '-DPython3_EXECUTABLE=' + str(python), '-DPYTHON_EXECUTABLE=' + str(python),
        '-DPython3_FIND_VIRTUALENV=STANDARD', '-DPython3_FIND_REGISTRY=NEVER',
        '-DGO_EXECUTABLE=GO_EXECUTABLE-NOTFOUND', '-DGIT_EXECUTABLE=/usr/bin/git',
        '-DLLVM_HOST_TRIPLE=arm64-apple-darwin', '-DLLVM_ENABLE_ASSERTIONS=ON',
        '-DLLVM_ENABLE_RTTI=OFF', '-DLLVM_ENABLE_EH=OFF', '-DLLVM_ENABLE_LTO=OFF',
        '-DLLVM_ENABLE_ZSTD=OFF', '-DLLVM_ENABLE_FFI=OFF', '-DLLVM_ENABLE_CURL=OFF', '-DLLVM_ENABLE_HTTPLIB=OFF',
        '-DLLVM_ENABLE_LIBPFM=OFF', '-DLLVM_ENABLE_Z3_SOLVER=OFF', '-DLLVM_ENABLE_BINDINGS=OFF',
        '-DLLVM_TARGETS_TO_BUILD=', '-DLLVM_BUILD_TOOLS=OFF', '-DLLVM_INCLUDE_TOOLS=OFF',
        '-DLLVM_BUILD_UTILS=OFF', '-DLLVM_INSTALL_UTILS=OFF', '-DLLVM_INCLUDE_TESTS=OFF',
        '-DLLVM_INCLUDE_BENCHMARKS=OFF', '-DLLVM_INCLUDE_EXAMPLES=OFF', '-DLLVM_BUILD_LLVM_DYLIB=OFF',
        '-DLLVM_LINK_LLVM_DYLIB=OFF', '-DLLVM_ENABLE_ZLIB=FORCE_ON', '-DLLVM_ENABLE_LIBXML2=FORCE_ON',
        '-DLLVM_ENABLE_TERMINFO=FORCE_ON', '-DZLIB_INCLUDE_DIR=' + str(sdk / 'usr/include'),
        '-DZLIB_LIBRARY_RELEASE=' + str(sdk / 'usr/lib/libz.tbd'), '-DLIBXML2_INCLUDE_DIR=' + str(sdk / 'usr/include/libxml2'),
        '-DLIBXML2_LIBRARY=' + str(sdk / 'usr/lib/libxml2.tbd'), '-DTerminfo_LIBRARIES=' + str(sdk / 'usr/lib/libcurses.tbd'),
        '-DBUG_REPORT_URL=https://github.com/3Shain/dxmt', '-DPACKAGE_VENDOR=DXMT',
        '-DLLVM_VERSION_PRINTER_SHOW_HOST_TARGET_INFO=OFF']
    return [([cmake, '-S', source / 'llvm', '-B', build_dir, '-G', 'Ninja', *options], 'graphics-llvm-configure'),
            ([cmake, '--build', build_dir, '--parallel', str(jobs)], 'graphics-llvm-build'),
            ([cmake, '--install', build_dir], 'graphics-llvm-install')]


def check_metadata(build_dir, python):
    """Reject executable/search-path dependencies on old work or non-Python Homebrew."""
    identities = {}; allowed_python = {}
    for name in ('CMakeCache.txt', 'build.ninja', 'compile_commands.json'):
        path = build_dir / name; text = path.read_text()
        require(str(OLD_WORK) not in text, 'old workspace dependency in LLVM metadata')
        for line in text.splitlines():
            if name == 'CMakeCache.txt' and re.match(r'(?:_?Python3|PYTHON)[A-Za-z0-9_]*:', line):
                allowed_python[line.split(':', 1)[0]] = line; continue
            # Ignore explicit denylist settings: they are not selected dependencies.
            if name == 'CMakeCache.txt' and line.startswith(('CMAKE_IGNORE_PREFIX_PATH:', 'CMAKE_SYSTEM_IGNORE_PREFIX_PATH:')):
                continue
            if name == 'build.ninja' and ('-DCMAKE_IGNORE_PREFIX_PATH=' in line or '-DCMAKE_SYSTEM_IGNORE_PREFIX_PATH=' in line):
                line = line.replace('/opt/homebrew;/usr/local', '')
            require('/opt/homebrew/' not in line.replace(str(python), '') and '/usr/local/' not in line,
                    'uncontrolled external dependency in ' + name)
        identities[name] = sha(path)
    return dict(files=identities, declared_external_python_metadata=allowed_python)


def build(source, build_dir, install, tools, sdk, python, run, jobs=2):
    source, build_dir, install = map(real, (source, build_dir, install))
    sdk, python = Path(sdk).absolute(), Path(python).resolve(strict=True)
    require(type(jobs) is int and 1 <= jobs <= 2, 'jobs must be 1..2')
    require(source.is_dir() and (source / 'llvm/CMakeLists.txt').is_file() and (source / 'cmake').is_dir(), 'verified llvm+cmake source root required')
    require(not build_dir.exists() and not install.exists(), 'new LLVM build/install directories required')
    require(all(not a.is_relative_to(b) and not b.is_relative_to(a) for a,b in
                ((source,build_dir),(source,install),(build_dir,install))), 'source/build/install directories must be disjoint')
    require(not any(path.is_relative_to(OLD_WORK) for path in (source, build_dir, install)), 'old work paths are not build inputs')
    require(sdk.is_dir() and python.is_file(), 'explicit external SDK/Python required')
    sdk_inputs = ('usr/lib/libz.tbd', 'usr/lib/libxml2.tbd', 'usr/lib/libcurses.tbd', 'usr/include/zlib.h', 'usr/include/libxml2/libxml/parser.h')
    for relative in sdk_inputs:
        require((sdk / relative).is_file(), 'required Apple SDK dependency missing: ' + relative)
    for name in ('cmake', 'ninja'):
        require(Path(tools[name]).is_file() and os.access(tools[name], os.X_OK), 'explicit build tool missing')
    sources = tree(source); implementations = {str(Path(p).resolve()):sha(p) for p in (__file__, tooling.__file__, tooling.shared.__file__)}
    inputs = {str(Path(p)):sha(p) for p in (tools['cmake'], tools['ninja'], python, '/usr/bin/clang', '/usr/bin/clang++', '/usr/bin/ar', '/usr/bin/ranlib')}
    inputs.update({str(p):sha(p) for p in (sdk/'SDKSettings.json',sdk/'SDKSettings.plist') if p.is_file()})
    inputs.update({str(sdk/relative):sha(sdk/relative) for relative in sdk_inputs})
    require(any(Path(p).name.startswith('SDKSettings.') for p in inputs), 'SDK identity metadata absent')
    env = tooling.meson_env(tools, python, sdk); env['GIT_CEILING_DIRECTORIES'] = str(source.parent)
    commands = []; build_dir.mkdir(parents=True)
    write(build_dir / 'provider-started.json', dict(schema=1, source=str(source), install=str(install), inputs=inputs, source_tree=sources, implementations=implementations))
    try:
        for argv, label in plan(source, build_dir, install, tools, sdk, python, jobs):
            commands.append(tooling.call(run, argv, label, env, build_dir))
            if label == 'graphics-llvm-configure':
                check_metadata(build_dir, python)
        for name in ('llvm/IR/Module.h', 'llvm/Config/llvm-config.h', 'llvm/Config/abi-breaking.h'):
            require((install / 'include' / name).is_file(), 'installed LLVM header absent: ' + name)
        libraries = {('lib/lib' + name + '.a'): arm_archive(install / 'lib' / ('lib' + name + '.a')) for name in LIBRARIES}
        require(not list(install.rglob('*.dylib')), 'LLVM static-only installation required')
        license_path = install / 'share/licenses/llvm/LICENSE.TXT'; license_path.parent.mkdir(parents=True, exist_ok=True)
        with (source / 'llvm/LICENSE.TXT').open('rb') as src, license_path.open('xb') as dst:
            shutil.copyfileobj(src, dst)
        require(tree(source) == sources, 'LLVM source changed during build')
        require(all(sha(p) == value for p,value in {**inputs, **implementations}.items()), 'LLVM build inputs changed')
        result = dict(schema=1, status='LLVM15_STATIC_BUILT_NOT_DXMT_VERIFIED', source=str(source), build=str(build_dir), install=str(install),
                      libraries=libraries, installed_files=tree(install), source_tree=sources, inputs=inputs, implementations=implementations,
                      metadata=check_metadata(build_dir, python), commands=commands, licenses={str(license_path.relative_to(install)):sha(license_path)},
                      external=dict(python=str(python), sdk=str(sdk), deployment_target='15.2'), guest_executions=0, gpu_executions=0,
                      profile='LLVM15 Release static, assertions ON; no ISA backends/tools/tests/examples/benchmarks/bindings; SDK zlib/xml2/terminfo only; no ZSTD/FFI/CURL/HTTPLIB/libpfm/Z3',
                      scope='Native LLVM static dependency only. No DXMT build, App, guest, GPU or moved-build acceptance.')
        write(build_dir / 'provider-result.json', result)
        return result
    except Exception as error:
        write(build_dir / 'provider-failure.json', dict(status='FAIL', error=str(error), traceback=traceback.format_exc(), commands=commands))
        raise
