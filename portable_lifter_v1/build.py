"""Fresh-prefix CPU provider. Recorded build attempts are never overwritten.

The installed provider is an explicitly bounded Remill/XED lifter, not the full
PE-to-App pipeline. Apple SDK/compiler and Python remain external prerequisites.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import traceback

from . import deps, tools

REPO = Path(__file__).resolve().parents[1]
OLD_WORK = REPO.parents[1] / 'work'
REMILL_SHA = '56918a8c2554088e93389e97d292f4035286506c'
REMILL_ARCHIVE_SHA = '4ba4218566367fad162ed0427ee32221a55134eca2eee5efc2436be67b46885f'
PATCHES = [REPO / 'window_bridge' / name for name in (
    'xed-only-v1.patch', 'transactions-v1.patch', 'aot-profile-v1.patch',
    'import-calls-v1.patch', 'vtable-calls-v1.patch', 'window-calls-v1.patch')]
PATCHES += [REPO / 'window_inc_v1/inc-base32-v1.patch',
            REPO / 'portable_lifter_v1/explicit-semantics.patch']
SOURCES = [REPO / 'portable_lifter_v1' / name for name in (
    '__init__.py', '__main__.py', 'build.py', 'tools.py', 'deps.py', 'cache-lock.json')]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def fresh(path):
    path = tools.real_path(path)
    require(not path.exists(), 'fresh absent directory required: ' + str(path))
    path.mkdir(parents=True)
    return path


def source_snapshot(out, paths):
    result = {}
    for path in sorted(set(paths)):
        require(not path.is_symlink() and path.is_file(), 'regular source required: ' + str(path))
        relative = path.relative_to(REPO)
        target = out / 'sources' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        require(digest(path) == digest(target), 'source changed during copy')
        result[str(relative)] = digest(target)
    return result


def check_sources(snapshot):
    require(all(digest(REPO / path) == value for path, value in snapshot.items()),
            'implementation inputs changed during operation')


class Recorder:
    def __init__(self, out, prefix):
        self.directory = out / 'commands'
        self.directory.mkdir()
        self.commands = []
        self.env = {k: os.environ[k] for k in ('HOME', 'TMPDIR') if k in os.environ}
        self.env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C',
                        PYTHONDONTWRITEBYTECODE='1', GIT_CONFIG_NOSYSTEM='1',
                        GIT_CONFIG_GLOBAL='/dev/null', GIT_CEILING_DIRECTORIES=str(prefix.parent))

    def __call__(self, argv, label, cwd=None, env=None, expected=0):
        argv = list(map(str, argv))
        require(re.fullmatch('[A-Za-z0-9_.-]+', label), 'unsafe command label')
        cwd = str(Path(cwd).resolve()) if cwd is not None else str(self.directory.parent)
        effective = dict(self.env)
        if env:
            effective.update(env)
        # Provenance may name the cache origin; executable dependencies may not.
        require(str(OLD_WORK) not in json.dumps([argv, cwd, effective]), 'old work dependency in command')
        stem = self.directory / (f'{len(self.commands)+1:03d}-' + label)
        started = dict(argv=argv, label=label, cwd=cwd, env=effective,
                       expected=expected, started_at=now())
        write_json(stem.with_suffix('.started.json'), started)
        print('RUN ' + label, flush=True)
        launch_error = None
        returncode = None
        with stem.with_suffix('.stdout').open('xb') as stdout, stem.with_suffix('.stderr').open('xb') as stderr:
            try:
                returncode = subprocess.run(argv, cwd=cwd, env=effective, stdout=stdout, stderr=stderr).returncode
            except OSError as error:
                launch_error = repr(error)
                stderr.write((launch_error+'\n').encode())
        record = dict(**started, returncode=returncode, launch_error=launch_error, finished_at=now(),
                      stdout_path=str(stem.with_suffix('.stdout')), stderr_path=str(stem.with_suffix('.stderr')),
                      stdout_sha256=digest(stem.with_suffix('.stdout')), stderr_sha256=digest(stem.with_suffix('.stderr')))
        write_json(stem.with_suffix('.result.json'), record)
        self.commands.append(record)
        require(returncode == expected and launch_error is None,
                f'{label}: exit {returncode}, expected {expected}; launch error={launch_error}; logs: {stem}')
        return dict(**record, stdout=stem.with_suffix('.stdout').read_text(errors='replace'),
                    stderr=stem.with_suffix('.stderr').read_text(errors='replace'))


def paths_for(prefix):
    prefix = tools.real_path(prefix)
    manifest_path = prefix / 'provider.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink(), 'regular provider manifest required')
    manifest = json.loads(manifest_path.read_text())
    require(manifest.get('schema') == 1 and manifest.get('status') == 'CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED', 'provider not successful')
    require(type(manifest.get('runtime_files')) is dict and bool(manifest['runtime_files']), 'provider file inventory required')
    require(type(manifest.get('source_tree')) is dict and bool(manifest['source_tree']), 'provider source inventory required')
    require(set(manifest.get('layout', {})) == {'lifter','llvm','semantics','source'}, 'invalid provider roles')
    def local_path(relative):
        require(type(relative) is str and bool(relative) and not Path(relative).is_absolute() and
                '..' not in Path(relative).parts, 'relative provider path required')
        path = prefix / relative
        require(path.resolve().is_relative_to(prefix), 'provider path escaped')
        return path
    for relative, identity in manifest['runtime_files'].items():
        path = local_path(relative)
        require(path.is_file(), 'provider file absent')
        require(digest(path) == identity['sha256'] and path.stat().st_mode & 0o777 == identity['mode'],
                'provider file identity changed: ' + relative)
    result = {key: local_path(value) for key, value in manifest['layout'].items()}
    require(result['source'].is_dir() and result['llvm'].is_dir(), 'provider directories absent')
    for path in (result['lifter'],result['semantics'],*[result['llvm']/'bin'/name for name in ('clang','opt','llvm-link')]):
        require(str(path.resolve().relative_to(prefix)) in manifest['runtime_files'], 'provider role not in runtime inventory')
    result['sdk'] = Path(manifest['external_prerequisites']['sdk'])
    require(result['sdk'].is_absolute() and result['sdk'].is_dir(),'external SDK absent')
    require(bool(manifest['external_prerequisites']['sdk_settings']),'SDK identity required')
    for name,value in manifest['external_prerequisites']['sdk_settings'].items():
        require(name in ('SDKSettings.json','SDKSettings.plist') and digest(result['sdk']/name)==value,'SDK identity changed')
    return manifest, result


def build(prefix, cache, out, jobs=2):
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'native Apple Silicon required')
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required')
    require(type(jobs) is int and 1 <= jobs <= 2, 'jobs must be 1..2')
    prefix, cache, out = map(tools.real_path, (prefix, cache, out))
    require(not prefix.exists(), 'provider prefix must be absent')
    require(not prefix.is_relative_to(OLD_WORK), 'fresh provider must be outside old work tree')
    require(not out.is_relative_to(prefix) and not prefix.is_relative_to(out), 'evidence/prefix must be disjoint')
    out = fresh(out)
    run = Recorder(out, prefix)
    snapshot = source_snapshot(out, [*SOURCES, *PATCHES])
    write_json(out / 'started.json', dict(prefix=str(prefix),cache=str(cache),started_at=now(),sources=snapshot))
    try:
        tools.check_cache(cache)
        deps.sources(cache)
        archive = cache / 'remill.tar.gz'
        require(not archive.is_symlink() and digest(archive) == REMILL_ARCHIVE_SHA, 'Remill source archive mismatch')
        prefix.mkdir(parents=True)
        sdk = Path(run(['/usr/bin/xcrun','--show-sdk-path'], 'sdk')['stdout'].strip()).resolve(strict=True)
        compiler = Path(run(['/usr/bin/xcrun','--find','clang++'], 'compiler-path')['stdout'].strip()).resolve(strict=True)
        compiler_version = run([compiler,'--version'], 'compiler-version')['stdout']
        external = dict(sdk=str(sdk),compiler=str(compiler),compiler_sha256=digest(compiler),
                        compiler_version=compiler_version,python=str(Path(sys.executable).resolve()),
                        python_version=sys.version,python_sha256=digest(Path(sys.executable).resolve()),
                        sdk_settings={p.name:digest(p) for p in (sdk/'SDKSettings.json',sdk/'SDKSettings.plist') if p.is_file()})
        installed = tools.install(prefix / 'tools', cache, run, jobs=jobs)
        write_json(out / 'tools.json', installed)
        locations = installed['paths']
        cmake, ninja, llvm, zstd = (Path(locations[k]) for k in ('cmake','ninja','llvm','zstd'))
        run.env['PATH'] = ':'.join(map(str,(cmake.parent,ninja.parent,llvm/'bin'))) + ':/usr/bin:/bin:/usr/sbin:/sbin'
        built_deps = deps.build(prefix / 'deps',cache,installed,sdk,Path(sys.executable).resolve(),run,jobs=jobs)
        write_json(out / 'deps.json', built_deps)
        for name in built_deps['libraries']:
            arch = run(['/usr/bin/lipo','-archs',prefix/'deps/lib'/name], 'archive-arch-'+name)['stdout'].strip()
            require(arch == 'arm64','non-native dependency archive: '+name)
        source_parent = prefix / 'source'; source_parent.mkdir()
        tools.extract_archive(archive,source_parent,'remill-'+REMILL_SHA)
        source = source_parent / ('remill-'+REMILL_SHA)
        for index, patch in enumerate(PATCHES):
            result = run(['/usr/bin/patch','--batch','--forward','-F','0','-p1','-i',patch],
                         f'remill-patch-{index+1}',cwd=source)
            require(not re.search(r'\b(?:offset|fuzz|FAILED)\b',result['stdout']+result['stderr']), 'inexact patch application')
        source_before = deps.tree(source)
        target = prefix / 'lifter-build'
        config = [cmake,'-G','Ninja','-S',source,'-B',target,
                  '-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=/usr/bin/clang',
                  '-DCMAKE_CXX_COMPILER=/usr/bin/clang++','-DCMAKE_OSX_ARCHITECTURES=arm64',
                  '-DCMAKE_OSX_SYSROOT='+str(sdk),'-DCMAKE_MAKE_PROGRAM='+str(ninja),
                  '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
                  '-DCMAKE_PREFIX_PATH='+';'.join(map(str,(prefix/'deps',llvm,zstd))),
                  '-DCMAKE_INSTALL_PREFIX='+str(prefix/'install'),
                  '-DLLVM_DIR='+str(llvm/'lib/cmake/llvm'),
                  '-DXED_DIR='+str(prefix/'deps/lib/cmake/XED'),
                  '-Dgflags_DIR='+str(prefix/'deps/lib/cmake/gflags'),
                  '-Dglog_DIR='+str(prefix/'deps/lib/cmake/glog'),
                  '-DUnwind_INCLUDE_DIR='+str(llvm/'include'),
                  '-DUnwind_LIBRARY='+str(llvm/'lib/libunwind.dylib'),
                  '-Dzstd_DIR='+str(zstd/'lib/cmake/zstd'),
                  '-Dzstd_INCLUDE_DIR='+str(zstd/'include'),
                  '-Dzstd_LIBRARY='+str(zstd/'lib/libzstd.dylib'),
                  '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF','-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
                  '-DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF',
                  '-DREMILL_ENABLE_TESTING=OFF','-DREMILL_ENABLE_INSTALL_TARGET=OFF',
                  '-DGIT_FAIL_IF_NONZERO_EXIT=OFF']
        run(config,'remill-configure')
        run([cmake,'--build',target,'--target','remill-lift-17','amd64','--parallel',str(jobs)],'remill-build')
        require(deps.tree(source) == source_before,'Remill source changed during build')
        require(digest(archive) == REMILL_ARCHIVE_SHA,'Remill archive changed')
        lifter = target/'bin/lift/remill-lift-17'
        semantics = target/'lib/Arch/X86/Runtime/amd64.bc'
        require(lifter.is_file() and semantics.is_file(),'provider artifacts missing')
        info = tools.macho(lifter)
        require(info['rpaths'] and all(v.startswith(str(prefix)+'/') for v in info['rpaths']), 'unexpected linker search paths')
        args = ['/usr/bin/install_name_tool']
        for value in info['rpaths']:
            args.extend(['-delete_rpath',value])
        args.extend(['-add_rpath','@loader_path/../../../tools/llvm@17/17.0.6/lib',str(lifter)])
        run(args,'lifter-relative-rpath')
        run(['/usr/bin/codesign','--force','--sign','-',lifter],'lifter-sign')
        graph = tools.selected_closure(prefix,[lifter,llvm/'bin/clang',llvm/'bin/opt',llvm/'bin/llvm-link'])
        run([llvm/'bin/opt','-passes=verify','-disable-output',semantics],'semantics-verify')
        # Keep generated metadata as evidence. It is not a relocation recipe.
        for name in ('CMakeCache.txt','compile_commands.json','build.ninja'):
            path = target/name
            data = path.read_bytes()
            require(str(OLD_WORK).encode() not in data,'old build path in generated '+name)
            require(b'/opt/homebrew/' not in data,'uncontrolled Homebrew dependency in generated '+name)
            shutil.copy2(path,out/name)
        versions = [p for p in target.rglob('*') if p.is_file() and p.name in ('Version.cpp','git-state.txt','git-state.json','git-state-hash')]
        for index,path in enumerate(versions):
            shutil.copy2(path,out/(f'generated-version-{index}-'+path.name))
        identities = {}
        for path in [semantics,*map(Path,graph['nodes'])]:
            identities[str(path.relative_to(prefix))] = dict(sha256=digest(path),mode=path.stat().st_mode & 0o777)
        layout = dict(lifter=str(lifter.relative_to(prefix)),semantics=str(semantics.relative_to(prefix)),
                      llvm=str(llvm.relative_to(prefix)),source=str(source.relative_to(prefix)))
        provider = dict(schema=1,status='CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED',layout=layout,
                        runtime_files=identities,source_tree=source_before,external_prerequisites=external,
                        implementation=snapshot,patches={str(p.relative_to(REPO)):digest(p) for p in PATCHES},
                        archive_sha256=REMILL_ARCHIVE_SHA,guest_executions=0,gpu_executions=0,
                        limitation='Selected CPU lifter only. Full App pipeline, relocated execution and clean machine not verified.')
        check_sources(snapshot)
        write_json(prefix/'provider.json',provider)
        write_json(out/'result.json',dict(status=provider['status'],prefix=str(prefix),provider_sha256=digest(prefix/'provider.json'),
                                        selected_graph=graph,commands=run.commands,finished_at=now()))
        return provider
    except Exception as error:
        write_json(out/'failure.json',dict(status='FAIL',error=str(error),traceback=traceback.format_exc(),
                                         commands=run.commands,finished_at=now(),sources=snapshot))
        raise


def probe(prefix, pe, out):
    from .probe import run_probe, SOURCE_FILES
    prefix = tools.real_path(prefix)
    provider, paths = paths_for(prefix)
    provider_sha = digest(prefix/'provider.json')
    out = fresh(out)
    run = Recorder(out,prefix)
    snapshot = source_snapshot(out,[*SOURCES,*[REPO/p for p in SOURCE_FILES]])
    write_json(out/'started.json',dict(started_at=now(),prefix=str(prefix),provider_sha256=provider_sha,sources=snapshot))
    try:
        require(deps.tree(paths['source']) == provider['source_tree'],'installed source changed')
        graph = tools.selected_closure(prefix,[paths['lifter'],paths['llvm']/'bin/clang',paths['llvm']/'bin/opt'])
        result = run_probe(paths,pe,out/'artifacts',run)
        check_sources(snapshot)
        paths_for(prefix)
        require(digest(prefix/'provider.json') == provider_sha,'provider manifest changed during probe')
        write_json(out/'result.json',dict(status=result['validation_level'],probe_sha256=digest(out/'artifacts/probe.json'),
                                        provider_sha256=provider_sha,selected_graph=graph,
                                        commands=run.commands,finished_at=now()))
        return result
    except Exception as error:
        write_json(out/'failure.json',dict(status='FAIL',error=str(error),traceback=traceback.format_exc(),
                                         commands=run.commands,finished_at=now()))
        raise
