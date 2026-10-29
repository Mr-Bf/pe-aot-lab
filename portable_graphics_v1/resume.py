"""Finalize the pinned graphics build-03 in a new prefix, without recompiling.

The failed attempt and its partially processed runtime are never modified or
used as code inputs. Raw-library and additional Apple-tool hashes were not
sealed before the original failure: they are first recorded by this reader.
This is a bounded recovery recipe, not a general build-cache importer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import traceback

from . import build, cache, llvm, tooling
from portable_app_v1 import lift
from window_bridge import app_v3 as sections

need, sha, write = build.require, build.digest, build.write
PINS = {
    'started.json': '6f8fc80492a940cb72979591a9e8986270880e36a1aa7f994821c720c16ac8a8',
    'failure.json': '99bb096fec74f3f249e89857f0b1ab0877188adaed60917f38bb971a8f09b333',
    'prepared-source.json': '1ef3d6e6b02e1f760a87f80620dde8a5f33cb4253af6936d8956791881cc950a',
    'llvm.json': 'ba44e00b027dcf7884ccaeb162d774a9720e0b04dc589d748024edccef882040',
    'native.ini': 'cedd5f46c765511b46a2c802525fe3a7cc72942714f7fc9914b01fc44082dd11',
}
SCOPE = ('Fresh packaging of the native LLVM15/DXMT outputs compiled in pinned graphics build-03. '
         'No C++ compilation in this attempt. Raw-library hashes and Apple-tool hashes not present in the '
         'original LLVM receipt, plus the Meson inventory, are observed during finalization; unsealed identities are '
         'not retroactively claimed at compile completion. '
         'No backend loading, App, guest, GPU, performance or clean-machine acceptance.')


def bound_json(path, expected=None):
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    need(expected is None or digest == expected, 'receipt identity differs: ' + str(path))
    value = build.macho_graph.strict_json(raw.decode())
    need(sha(path) == digest, 'receipt changed while reading')
    return value


def command_records(origin, failure):
    records = failure['commands']
    need(failure['status'] == 'FAIL' and type(records) is list and len(records) == 27, 'exact 27-command failed attempt required')
    expected_files, result = set(), []
    for index, record in enumerate(records, 1):
        need(type(record) is dict and re.fullmatch(r'[A-Za-z0-9_.-]+', record['label']), 'invalid command label')
        stem = origin / 'commands' / (f'{index:03d}-' + record['label'])
        paths = {suffix: stem.with_suffix('.' + suffix) for suffix in ('started.json', 'result.json', 'stdout', 'stderr')}
        expected_files.update(path.name for path in paths.values())
        need(bound_json(paths['result.json']) == record, 'recorded command differs from failure ledger')
        started = bound_json(paths['started.json'])
        need(set(started) == {'argv', 'label', 'cwd', 'env', 'expected', 'started_at'} and
             all(record[key] == value for key, value in started.items()), 'command start/result identity differs')
        need(type(record['expected']) is int and record['expected'] == 0 and record['launch_error'] is None and
             type(record['returncode']) is int and record['returncode'] == (1 if index == 27 else 0),
             'unexpected origin command exit')
        for stream in ('stdout', 'stderr'):
            need(record[stream + '_path'] == str(paths[stream]) and sha(paths[stream]) == record[stream + '_sha256'],
                 'origin command raw output identity differs')
        need(str(build.common.OLD_WORK) not in json.dumps([record['argv'], record['cwd'], record['env']]),
             'historical work dependency in origin command')
        need(record['started_at'] <= record['finished_at'] and
             (not result or result[-1]['finished_at'] <= record['started_at']), 'origin command chronology differs')
        result.append(record)
    need({p.name for p in (origin / 'commands').iterdir()} == expected_files, 'origin command file closure differs')
    need(result[19]['label'] == 'dxmt-build' and result[26]['label'] == 'runtime-paths-winemetal.dylib',
         'origin stopped at a different stage')
    last = result[-1]
    argv = last['argv']
    need(argv[:3] == ['/usr/bin/install_name_tool', '-id', '@rpath/winemetal.dylib'] and
         argv[3:-1] == ['-delete_rpath', '@loader_path/', '-delete_rpath', '@loader_path/../../', '-add_rpath', '@loader_path/'],
         'failure is not the known duplicate-rpath operation')
    need('can\'t specify both "-delete_rpath @loader_path/" and "-add_rpath @loader_path/"' in
         Path(last['stderr_path']).read_text(), 'origin diagnostic differs from known failure')
    return result


def isolated(prefix, out, *inputs):
    need(not prefix.exists() and not out.exists(), 'fresh finalization prefix/evidence required')
    for a, b in [(prefix, out), *[(value, item) for value in (prefix, out) for item in inputs]]:
        need(not a.is_relative_to(b) and not b.is_relative_to(a), 'finalization paths overlap inputs or each other')
    need(not prefix.is_relative_to(build.common.OLD_WORK), 'historical work prefix rejected')


def retire_failed_provider(prefix):
    """A failed fresh attempt must not leave a consumable success entry point."""
    manifest = prefix / 'provider.json'
    if manifest.exists():
        failed = prefix / 'failed-provider.json'
        need(not failed.exists(), 'refuse to overwrite failed provider evidence')
        manifest.rename(failed)


def review_origin(origin):
    """Read/hash only. No native tools, extraction, writes or old runtime reads."""
    origin = build.binary.real_path(origin)
    for name, digest in PINS.items():
        need(sha(origin / name) == digest, 'only pinned graphics build-03 is supported: ' + name)
    started, failure, prepared, lr = [bound_json(origin / name, PINS[name]) for name in
                                    ('started.json', 'failure.json', 'prepared-source.json', 'llvm.json')]
    original = build.binary.real_path(started['prefix'])
    need(original.name == 'graphics-03' and not original.is_relative_to(build.common.OLD_WORK), 'unexpected original prefix')
    records = command_records(origin, failure)
    need(records[-1]['argv'][-1] == str(original / 'runtime/winemetal.dylib'), 'origin failed output path differs')
    snapshots = build.tree(origin / 'sources')
    need(set(snapshots) == set(started['sources']) and all(snapshots[name]['sha256'] == value for name, value in started['sources'].items()),
         'origin implementation snapshot differs')
    for name, value in started['sources'].items():
        # build.py's post-build fix is intentionally a new implementation;
        # the original implementation remains frozen in origin/sources.
        if name != 'portable_graphics_v1/build.py':
            need(sha(build.REPO / name) == value, 'unchanged origin implementation differs: ' + name)
    cache_path = build.binary.real_path(started['cache'])
    cache_record = cache.check_cache(cache_path)
    need(sha(origin / 'native.ini') == sha(original / 'native.ini'), 'original machine file changed')
    source = original / 'sources' / ('dxmt-' + cache.DXMT_COMMIT)
    headers = original / 'sources' / ('mingw-directx-headers-' + cache.HEADERS_COMMIT)
    llvm_source = original / 'sources/llvm15-subtrees'
    need(build.tree(source) == prepared['prepared'] and build.tree(headers) == prepared['headers'] and
         build.tree(source / 'include/native/directx') == prepared['headers'], 'prepared DXMT/header tree changed')
    need(prepared['patches'] == {str(p.relative_to(build.REPO)): sha(p) for p in build.PATCHES}, 'patch identity differs')
    need(prepared['adapters'] == {str(p.relative_to(build.REPO)): dict(destination=d, sha256=sha(p)) for p, d in build.ADAPTERS.items()},
         'adapter identity differs')
    for path, destination in build.ADAPTERS.items():
        need(sha(source / destination) == sha(path), 'prepared adapter bytes differ')
    need(lr['schema'] == 1 and lr['status'] == 'LLVM15_STATIC_BUILT_NOT_DXMT_VERIFIED' and
         lr['source'] == str(llvm_source) and lr['build'] == str(original / 'llvm-build') and
         lr['install'] == str(original / 'llvm-install'), 'LLVM stage paths/status differ')
    need(bound_json(original / 'llvm-build/provider-result.json', PINS['llvm.json']) == lr, 'LLVM receipt copies differ')
    need(llvm.tree(llvm_source) == lr['source_tree'] and llvm.tree(original / 'llvm-install') == lr['installed_files'],
         'LLVM source/install changed')
    need(set(lr['libraries']) == {'lib/lib' + name + '.a' for name in llvm.LIBRARIES} and
         all(llvm.arm_archive(original / 'llvm-install' / name) == value for name, value in lr['libraries'].items()) and
         not list((original / 'llvm-install').rglob('*.dylib')), 'LLVM static ARM64 closure differs')
    need(all(sha(Path(path)) == value for path, value in {**lr['inputs'], **lr['implementations']}.items()), 'LLVM recorded inputs changed')
    need(llvm.check_metadata(original / 'llvm-build', Path(lr['external']['python'])) == lr['metadata'], 'LLVM metadata changed')
    need(len(lr['commands']) == 3 and all({k: v for k, v in command.items() if k not in ('stdout', 'stderr')} == recorded
         for command, recorded in zip(lr['commands'], records[12:15])), 'LLVM actual command records differ')
    tooling_receipt = bound_json(original / 'tools/tooling.json')
    tool_paths = {name: original / 'tools' / relative for name, relative in tooling_receipt['paths'].items()}
    need(tooling.inventory(tool_paths['meson']) == tooling_receipt['meson_files'] and
         all(sha(Path(path)) == node['sha256'] for path, node in tooling_receipt['selected_graph']['nodes'].items()),
         'original tooling identity changed')
    target = original / 'dxmt-build'
    python = Path(lr['external']['python'])
    need(records[18]['argv'] == [str(python), '-S', '-m', 'mesonbuild.mesonmain', 'setup', str(target), str(source),
         '--native-file', str(original / 'native.ini'), '--buildtype=release', '--wrap-mode=nodownload',
         '-Dnative_llvm_path=' + str(original / 'llvm-install'), '-Denable_nvapi=false', '-Denable_nvngx=false',
         '-Denable_d3d12=false', '-Denable_tests=false'] and records[19]['argv'] ==
         [str(python), '-S', '-m', 'mesonbuild.mesonmain', 'compile', '-C', str(target), '-j', '2'],
         'successful DXMT commands selected different inputs')
    metadata = {}
    for name in ('build.ninja', 'compile_commands.json', 'meson-info/intro-compilers.json', 'version.h', '.ninja_log'):
        path = target / name
        raw = path.read_bytes()
        need(str(build.common.OLD_WORK).encode() not in raw and b'/opt/homebrew/' not in raw.replace(str(python).encode(), b'EXTERNAL_PYTHON'),
             'uncontrolled path in DXMT metadata')
        metadata[name] = sha(path)
    outputs = sorted(target.rglob('*.dylib'))
    need(len(outputs) == 4 and {p.name for p in outputs} == {*build.NAMES, 'd3d10core.dylib'}, 'exact four original raw libraries required')
    raw_outputs = {}
    log_rows = [line.split('\t') for line in (target / '.ninja_log').read_text().splitlines() if not line.startswith('#')]
    for path in outputs:
        need(not path.is_symlink() and path.stat().st_nlink == 1, 'raw library alias rejected')
        need(build.binary.macho(path)['filetype'] == 6 and build.minimum(path)['minimum'] == [15, 2, 0], 'raw ARM64/macOS library differs')
        need(any(len(row) == 5 and row[3] == str(path.relative_to(target)) for row in log_rows), 'raw output absent from successful Ninja log')
        raw_outputs[str(path)] = dict(sha256=sha(path), macho=build.binary.macho(path), deployment=build.minimum(path),
                                      sections=sections.section_identity(path))
    mapping = {p.name: p for p in outputs}
    graph = build.macho_graph.library_graph(mapping['d3d11.dylib'], target / 'not-executed', [mapping['d3d11.dylib'].parent])
    need(set(graph['nodes']) == {str(mapping[name]) for name in build.NAMES}, 'raw three-library graph escaped original build')
    # Query results bind original paths; only LLVM's inputs carry historical
    # binary hashes. Other hashes below describe finalization-time identities.
    sdk = Path(lr['external']['sdk'])
    developer = str(Path(Path(records[0]['stdout_path']).read_text().strip()).resolve(strict=True))
    external = dict(sdk=str(sdk), developer=developer, sdk_version=Path(records[2]['stdout_path']).read_text().strip(),
                    python=str(python), python_sha256=sha(python),
                    sdk_settings={p.name: sha(p) for p in (sdk / 'SDKSettings.json', sdk / 'SDKSettings.plist') if p.is_file()}, tools={},
                    hash_observation_scope='finalization-time; historical LLVM identities separately retained in origin llvm.json')
    queried_sdk = Path(Path(records[1]['stdout_path']).read_text().strip()).resolve(strict=True)
    need(queried_sdk == sdk.resolve(strict=True) and sdk.is_dir() and external['sdk_settings'], 'SDK query/receipt differs')
    for row, name in zip(records[3:9], ('clang', 'clang++', 'ar', 'ld', 'metal', 'metallib')):
        path = Path(Path(row['stdout_path']).read_text().strip()).resolve(strict=True)
        external['tools'][name] = dict(path=str(path), sha256=sha(path))
    for name in ('touch', 'xxd', 'patch', 'git', 'install_name_tool', 'codesign'):
        path = Path('/usr/bin') / name
        external['tools'][name] = dict(path=str(path), sha256=sha(path))
    return dict(origin=str(origin), original_prefix=str(original), source=str(source), headers=str(headers), llvm_source=str(llvm_source),
                cache_path=str(cache_path), cache=cache_record, origin_files=build.tree(origin), source_tree=prepared['prepared'],
                raw_outputs=raw_outputs, raw_graph=graph, metadata=metadata, external=external,
                llvm_receipt_sha256=PINS['llvm.json'], tooling_receipt_sha256=sha(original / 'tools/tooling.json'), scope=SCOPE)


def finalize(origin, prefix, out):
    origin, prefix, out = map(build.binary.real_path, (origin, prefix, out))
    before = review_origin(origin)
    isolated(prefix, out, origin, Path(before['original_prefix']), Path(before['cache_path']))
    out.mkdir(parents=True)
    implementation_paths = [*build.SOURCES, *lift.source_closure([Path(__file__)])]
    implementation = build.common.source_snapshot(out, implementation_paths)
    write(out / 'origin-review.json', before)
    write(out / 'started.json', dict(status='STARTED_FINALIZATION_NOT_EXECUTED', prefix=str(prefix), origin=str(origin),
                                   origin_review_sha256=sha(out / 'origin-review.json'), implementation=implementation, scope=SCOPE))
    run = build.common.Recorder(out, prefix)
    run.env.update(DEVELOPER_DIR=before['external']['developer'], SDKROOT=before['external']['sdk'])
    try:
        prefix.mkdir(parents=True)
        source = prefix / 'source'
        shutil.copytree(before['source'], source, symlinks=True)
        need(build.tree(source) == before['source_tree'], 'copied prepared source differs')
        runtime = prefix / 'runtime'
        runtime.mkdir()
        copied = {}
        by_name = {Path(path).name: (Path(path), info) for path, info in before['raw_outputs'].items()}
        for name in build.NAMES:
            original, info = by_name[name]
            path = runtime / name
            shutil.copy2(original, path)
            need(sha(path) == info['sha256'], 'raw library copy differs')
            run(build.runtime_command(path, build.binary.macho(path)), 'runtime-paths-' + name)
            run(['/usr/bin/codesign', '--force', '--sign', '-', path], 'runtime-sign-' + name)
            run(['/usr/bin/codesign', '--verify', '--strict', path], 'runtime-signature-' + name)
            need(sections.section_identity(path) == info['sections'] and build.minimum(path) == info['deployment'],
                 'path/signature processing changed code/data or deployment target')
            copied[name] = dict(original=str(original), raw_sha256=info['sha256'], finalized_sha256=sha(path))
        graph = build.binary.selected_closure(prefix, [runtime / 'd3d11.dylib'])
        need(set(graph['nodes']) == {str(runtime / name) for name in build.NAMES}, 'finalized runtime closure differs')
        licenses = build.notices(prefix, source, Path(before['llvm_source']), Path(before['headers']))
        need(review_origin(origin) == before, 'original inputs changed during finalization')
        build.common.check_sources(implementation)
        need(build.tree(source) == before['source_tree'], 'finalized source changed')
        provider = dict(schema=1, status=build.STATUS, profile=build.PROFILE, minimum_macos=build.MINIMUM,
                        layout={'source': 'source', **{name[:-6]: 'runtime/' + name for name in build.NAMES}},
                        runtime_files={'runtime/' + name: dict(sha256=sha(runtime / name), mode=stat.S_IMODE((runtime / name).stat().st_mode)) for name in build.NAMES},
                        source_tree=before['source_tree'], licenses=licenses, external_prerequisites=before['external'],
                        implementation=implementation, cache=before['cache'], guest_executions=0, gpu_executions=0, backend_loads=0,
                        native_compile_commands_this_attempt=0, inherited_native_build_origin=str(origin),
                        inherited_receipt_hashes=PINS, origin_review_sha256=sha(out / 'origin-review.json'), limitation=SCOPE)
        write(prefix / 'provider.json', provider)
        build.paths_for(prefix)
        write(out / 'result.json', dict(status=build.STATUS, prefix=str(prefix), provider_sha256=sha(prefix / 'provider.json'),
                                       origin=str(origin), origin_review_sha256=sha(out / 'origin-review.json'), copied=copied,
                                       runtime_graph=graph, commands=run.commands, native_compile_commands_this_attempt=0, scope=SCOPE))
        return provider
    except Exception as error:
        retire_failed_provider(prefix)
        write(out / 'failure.json', dict(status='FINALIZATION_FAILED_NOT_EXECUTED', error=str(error), traceback=traceback.format_exc(),
                                        commands=run.commands, scope=SCOPE))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Finalize pinned graphics build-03 in a fresh prefix; never compile')
    for name in ('origin', 'prefix', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    print(finalize(**vars(parser.parse_args()))['status'])
