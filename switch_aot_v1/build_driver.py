"""Rebuild experimental Remill/driver using an immutable accepted CPU provider.

No LLVM/dependency rebuild, download, guest execution or production mutation.
The new driver depends explicitly on the supplied provider; it is not a new
standalone/relocatable provider. Every attempt requires absent prefix and out.
"""
import argparse
import json
import platform
from pathlib import Path
import shutil
import sys
import traceback

from portable_lifter_v1 import build as base, deps

REPO = Path(__file__).resolve().parents[1]
SOURCES = [REPO / 'switch_aot_v1' / n for n in
           ('build_driver.py', 'driver.patch', 'SwitchProfile.h')]


def build(provider, prefix, out, jobs=2):
    require = base.require
    provider, prefix, out = (Path(p).resolve() for p in (provider, prefix, out))
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'native macOS ARM64 required')
    require(type(jobs) is int and 1 <= jobs <= 2, 'jobs must be 1..2')
    require(not prefix.exists() and not out.exists(), 'new absent prefix/out required')
    for a, b in ((prefix, out), (prefix, provider), (out, provider)):
        require(not a.is_relative_to(b) and not b.is_relative_to(a), 'provider/prefix/out must be disjoint')
    require(shutil.disk_usage(prefix.parent if prefix.parent.exists() else REPO).free >= 512 * 1024**2,
            'at least 512MiB free required for limited driver build')
    manifest, paths = base.paths_for(provider)
    source_before = deps.tree(paths['source'])
    require(source_before == manifest['source_tree'], 'accepted prepared source changed')
    provider_sha = base.digest(provider / 'provider.json')
    cmake = provider / 'tools/cmake/4.4.4/bin/cmake'
    ninja = provider / 'tools/ninja/1.13.2/bin/ninja'
    zstd = provider / 'tools/zstd'
    llvm, sdk = paths['llvm'], paths['sdk']
    require(cmake.is_file() and ninja.is_file() and zstd.is_dir(), 'accepted build tools absent')
    dependencies_before = deps.tree(provider / 'deps')
    tools_before = {str(p): base.digest(p) for p in (cmake, ninja)}
    out = base.fresh(out)
    recorder = base.Recorder(out, prefix)
    snapshot = base.source_snapshot(out, SOURCES)
    base.write_json(out / 'started.json', dict(schema=1, status='STARTED', provider=str(provider),
                    provider_sha256=provider_sha, prefix=str(prefix), jobs=jobs, sources=snapshot,
                    started_at=base.now(), scope='driver only; explicit external provider dependency'))
    try:
        prefix.mkdir(parents=True)
        source = prefix / 'source'
        shutil.copytree(paths['source'], source)
        require(deps.tree(source) == source_before, 'source copy changed')
        patch = REPO / 'switch_aot_v1/driver.patch'
        result = recorder(['/usr/bin/patch', '--batch', '--forward', '-F', '0', '-p1', '-i', patch],
                          'switch-patch', cwd=source)
        require(not any(word in result['stdout'] + result['stderr'] for word in ('offset', 'fuzz', 'FAILED')),
                'inexact switch patch')
        shutil.copy2(REPO / 'switch_aot_v1/SwitchProfile.h', source / 'bin/lift/SwitchProfile.h')
        prepared = deps.tree(source)
        recorder.env['PATH'] = ':'.join(map(str, (cmake.parent, ninja.parent, llvm / 'bin'))) + ':/usr/bin:/bin:/usr/sbin:/sbin'
        target = prefix / 'lifter-build'
        config = [cmake, '-G', 'Ninja', '-S', source, '-B', target,
                  '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=/usr/bin/clang',
                  '-DCMAKE_CXX_COMPILER=/usr/bin/clang++', '-DCMAKE_OSX_ARCHITECTURES=arm64',
                  '-DCMAKE_OSX_SYSROOT=' + str(sdk), '-DCMAKE_MAKE_PROGRAM=' + str(ninja),
                  '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
                  '-DCMAKE_PREFIX_PATH=' + ';'.join(map(str, (provider / 'deps', llvm, zstd))),
                  '-DCMAKE_INSTALL_PREFIX=' + str(prefix / 'install'),
                  '-DLLVM_DIR=' + str(llvm / 'lib/cmake/llvm'),
                  '-DXED_DIR=' + str(provider / 'deps/lib/cmake/XED'),
                  '-Dgflags_DIR=' + str(provider / 'deps/lib/cmake/gflags'),
                  '-Dglog_DIR=' + str(provider / 'deps/lib/cmake/glog'),
                  '-DUnwind_INCLUDE_DIR=' + str(llvm / 'include'),
                  '-DUnwind_LIBRARY=' + str(llvm / 'lib/libunwind.dylib'),
                  '-Dzstd_DIR=' + str(zstd / 'lib/cmake/zstd'),
                  '-Dzstd_INCLUDE_DIR=' + str(zstd / 'include'),
                  '-Dzstd_LIBRARY=' + str(zstd / 'lib/libzstd.dylib'),
                  '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
                  '-DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF', '-DREMILL_ENABLE_TESTING=OFF',
                  '-DREMILL_ENABLE_INSTALL_TARGET=OFF', '-DGIT_FAIL_IF_NONZERO_EXIT=OFF']
        recorder(config, 'configure')
        recorder([cmake, '--build', target, '--target', 'remill-lift-17', '--parallel', str(jobs)], 'build-driver')
        driver = target / 'bin/lift/remill-lift-17'
        require(driver.is_file(), 'driver absent after build')
        architecture = recorder(['/usr/bin/lipo', '-archs', driver], 'driver-architecture')['stdout'].strip()
        require(architecture == 'arm64', 'driver not native ARM64')
        require(deps.tree(source) == prepared and deps.tree(paths['source']) == source_before,
                'source changed during build')
        require(deps.tree(provider / 'deps') == dependencies_before, 'external dependencies changed')
        require(base.digest(provider / 'provider.json') == provider_sha, 'provider receipt changed')
        require(all(base.digest(Path(p)) == sha for p, sha in tools_before.items()), 'build tools changed')
        base.paths_for(provider)
        base.check_sources(snapshot)
        result = dict(schema=1, status='EXPERIMENTAL_SWITCH_DRIVER_BUILT_NOT_ADMITTED_NOT_GUEST_EXECUTED',
                      provider=str(provider), provider_sha256=provider_sha, prefix=str(prefix),
                      driver=str(driver), driver_sha256=base.digest(driver), semantics=str(paths['semantics']),
                      semantics_sha256=base.digest(paths['semantics']), sources=snapshot,
                      prepared_source=prepared, commands=recorder.commands, finished_at=base.now(),
                      llvm_rebuilt=False, dependencies_rebuilt=False, guest_executions=0, gpu_executions=0)
        base.write_json(out / 'result.json', result)
        return result
    except BaseException as error:
        base.write_json(out / 'failure.json', dict(schema=1, status='FAILED_OR_CANCELLED_CHILD_STATE_UNKNOWN',
                        error=repr(error), traceback=traceback.format_exc(), commands=recorder.commands,
                        finished_at=base.now()))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', required=True)
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--jobs', type=int, default=2)
    arguments = parser.parse_args()
    result = build(**vars(arguments))
    print(json.dumps({key: result[key] for key in ('status', 'driver', 'driver_sha256')}))


if __name__ == '__main__':
    main()
