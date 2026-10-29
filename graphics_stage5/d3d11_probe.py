#!/usr/bin/env python3
"""Pinned native DXMT clear/readback build, execution and read-only verification.

Build does not load DXMT or execute a GPU operation. Run first executes a native
dlopen/dlsym check (library initializers may run), then the unchanged C++ probe. System dyld-cache images are
reported, not hashed; this is a local experiment, not hostile-host attestation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
WORK = ROOT.parents[1] / 'work/graphics-stage5'
OUT = ROOT / 'build/graphics-stage5/d3d11'
DXMT = 'd162ea44a31fbf9089ea09977337f0beb30bd082'
HEADERS = '9df86f2341616ef1888ae59919feaa6d4fad693d'
LLVM = '8dfdcc7b7bf66834a761bd8de445840ef68e4d1a'
SOURCE = HERE / 'd3d11_probe.cpp'
SOURCE_SHA = 'a2fb6fffdf76455b1cf8121f6ce75ed5114148e65948fb0d54013b99318a2eca'
SCOPE = 'native DXMT D3D11 clear/copy/readback only; no shader, triangle, window, PE or guest ABI'
BUILD_STATUS = 'BUILT_NOT_LOADED_NOT_RENDER_VERIFIED'
LOAD_SOURCE = r'''#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc != 2) return 64;
  void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!lib) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
  void *symbol = dlsym(lib, "D3D11CreateDevice");
  Dl_info info = {}; char expected[PATH_MAX], actual[PATH_MAX];
  int match = symbol && dladdr(symbol, &info) && info.dli_fname &&
              realpath(argv[1], expected) && realpath(info.dli_fname, actual) &&
              strcmp(expected, actual) == 0;
  if (!match) { fprintf(stderr, "D3D11CreateDevice image identity mismatch\n"); return 2; }
  puts("{\"status\":\"LOADABLE\",\"symbol_in_expected_image\":true}");
  /* Keep loaded until exit. No D3D11 call here; initializers may already have run. */
  return 0;
}
'''


class IntegrityError(RuntimeError):
    pass


class DependencyNotReady(IntegrityError):
    pass


def require(value, message):
    if not value:
        raise IntegrityError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def hashes(paths):
    return {str(p): sha(p) for p in sorted({Path(p).resolve() for p in paths})}


def same(identity):
    require(isinstance(identity, dict) and bool(identity), 'empty identity closure')
    require(hashes(identity) == identity, 'source, tool, header, library or artifact changed')


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON field: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise IntegrityError('non-finite JSON value: ' + value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def read_json(path):
    return strict_json(Path(path).read_text())


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        history = path.parent / 'history'
        history.mkdir(exist_ok=True)
        (history / (path.name + '.' + sha(path) + '.json')).write_bytes(path.read_bytes())
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def output(path):
    path = Path(path).resolve()
    require(path.is_relative_to(OUT.resolve()), 'output must stay within build/graphics-stage5/d3d11')
    return path


def environment(out, *, images=False):
    # A small allowlist also excludes DXMT configuration overrides, SDKROOT,
    # compiler search variables and all inherited DYLD_* variables.
    result = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C',
              'HOME': os.environ['HOME'], 'TMPDIR': os.environ.get('TMPDIR', '/tmp'),
              'XDG_CACHE_HOME': str(out / 'cache'), 'DXMT_LOG_PATH': 'none',
              'DXMT_SHADER_CACHE_PATH': str(out / 'cache/dxmt')}
    if images:
        result['DYLD_PRINT_LIBRARIES'] = '1'
    return result


def invoke(args, env, log=None):
    args = list(map(str, args))
    process = subprocess.run(args, env=env, text=True, capture_output=True)
    if log is not None:
        Path(log).write_text(json.dumps({'command': args, 'returncode': process.returncode,
                                        'stdout': process.stdout, 'stderr': process.stderr}, indent=2) + '\n')
    require(process.returncode == 0, 'command failed: ' + str(log or args))
    return process.stdout


def tools(out):
    env = environment(out)
    found = {name: str(Path(invoke(['/usr/bin/xcrun', '--find', name], env).strip()))
             for name in ('clang++', 'ld')}
    found['sdk'] = invoke(['/usr/bin/xcrun', '--show-sdk-path'], env).strip()
    found['xcrun'] = '/usr/bin/xcrun'
    found['python'] = str(Path(sys.executable).resolve())
    return found


def uint(value, limit=0xffffffff):
    return type(value) is int and 0 <= value <= limit


def validate_result(result, exit_code):
    fields = {'schema', 'probe', 'status', 'failure_stage', 'scope', 'compile_arch', 'native_arm64',
              'translation', 'feature_level', 'feature_level_hex', 'hresult', 'clear_called',
              'copy_called', 'unmap_called', 'format', 'width', 'height', 'row_pitch', 'depth_pitch',
              'expected_rgba8', 'tolerance_per_channel', 'pixels_checked', 'channels_checked',
              'mismatched_pixels', 'mismatched_channels', 'max_absolute_error', 'first_mismatch',
              'released_application_objects', 'all_application_references_released'}
    require(type(exit_code) is int and exit_code == 0, 'D3D11 probe did not exit successfully')
    require(isinstance(result, dict) and set(result) == fields, 'D3D11 result fields missing or unknown')
    require(result['status'] == 'PASS' and result['failure_stage'] is None, 'D3D11 result is not PASS')
    require(result['probe'] == 'native_dxmt_d3d11_offscreen', 'unexpected D3D11 probe identity')
    require(result['scope'] == dict.fromkeys(('shader', 'triangle', 'window', 'guest'), False)
            and all(v is False for v in result['scope'].values()), 'unexpected claimed graphics scope')
    require(result['compile_arch'] == 'arm64' and result['native_arm64'] is True, 'native ARM64 absent')
    for field, value in {'schema': 1, 'feature_level': 0xb000, 'width': 32, 'height': 32,
                         'tolerance_per_channel': 1, 'pixels_checked': 1024, 'channels_checked': 4096,
                         'mismatched_pixels': 0, 'mismatched_channels': 0,
                         'released_application_objects': 5}.items():
        require(type(result[field]) is int and result[field] == value, 'D3D11 result mismatch: ' + field)
    require(result['feature_level_hex'] == '0xb000', 'feature level representation mismatch')
    require(result['format'] == 'R8G8B8A8_UNORM', 'unexpected texture format')
    require(result['expected_rgba8'] == [17, 85, 170, 238]
            and all(type(x) is int for x in result['expected_rgba8']), 'unexpected clear color')
    for field in ('clear_called', 'copy_called', 'unmap_called', 'all_application_references_released'):
        require(result[field] is True, 'D3D11 operation/cleanup missing: ' + field)
    require(uint(result['row_pitch']) and result['row_pitch'] >= 128 and uint(result['depth_pitch']),
            'invalid mapping pitch')
    require(uint(result['max_absolute_error'], 1) and result['first_mismatch'] is None,
            'pixel error exceeds tolerance')
    translation = result['translation']
    require(isinstance(translation, dict) and set(translation) ==
            {'sysctl_return', 'errno', 'raw_value', 'known', 'rosetta'}, 'translation fields mismatch')
    require(translation['known'] is True and translation['rosetta'] is False, 'native query unverified')
    require(all(type(translation[k]) is int for k in ('sysctl_return', 'errno', 'raw_value')),
            'invalid native query types')
    require(tuple(translation[k] for k in ('sysctl_return', 'errno', 'raw_value')) in
            ((0, 0, 0), (-1, 2, -1)), 'unexpected native sysctl result')
    results = result['hresult']
    require(isinstance(results, dict) and set(results) == {'D3D11CreateDevice', 'CreateTexture2D_render_target',
            'CreateRenderTargetView', 'CreateTexture2D_staging', 'Map', 'GetDeviceRemovedReason'},
            'HRESULT operation set mismatch')
    for name, hr in results.items():
        require(isinstance(hr, dict) and set(hr) == {'signed', 'hex', 'succeeded'} and
                type(hr['signed']) is int and hr['signed'] == 0 and hr['hex'] == '0x00000000'
                and hr['succeeded'] is True, 'HRESULT not S_OK: ' + name)


def macho(path):
    """Read thin little-endian ARM64 Mach-O load commands, never run the image."""
    data = Path(path).read_bytes()
    require(len(data) >= 32, 'truncated Mach-O: ' + str(path))
    magic, cpu, subtype, filetype, count, size, flags, reserved = struct.unpack_from('<8I', data)
    require(magic == 0xfeedfacf and cpu == 0x100000c, 'thin ARM64 Mach-O required: ' + str(path))
    require(filetype in (2, 6), 'expected Mach-O executable or dylib: ' + str(path))
    require(size <= len(data) - 32 and count <= size // 8, 'invalid Mach-O load command bounds')
    offset = 32
    result = {'filetype': filetype, 'cpu_subtype': subtype, 'id': None, 'rpaths': [], 'dependencies': []}
    def string(start, length, minimum):
        index = struct.unpack_from('<I', data, start + 8)[0]
        require(minimum <= index < length, 'invalid Mach-O path offset')
        end = data.find(b'\0', start + index, start + length)
        require(end != -1, 'unterminated Mach-O path')
        value = data[start + index:end].decode('utf-8')
        require(value and '\n' not in value, 'invalid Mach-O path')
        return value
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, offset)
        require(length >= 8 and length % 8 == 0 and offset + length <= 32 + size,
                'invalid Mach-O command length')
        if command in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0xd):
            require(length >= 24, 'truncated dylib command')
            name = string(offset, length, 24)
            if command == 0xd:
                require(result['id'] is None, 'duplicate dylib install ID')
                result['id'] = name
            else:
                result['dependencies'].append({'command': command, 'name': name})
        elif command == 0x8000001c:
            require(length >= 16, 'truncated rpath command')
            result['rpaths'].append(string(offset, length, 12))
        elif command in (0x27, 0x20, 0x10):
            raise IntegrityError('embedded dyld environment/lazy/prebound dylib is unsupported')
        offset += length
    require(offset == 32 + size, 'Mach-O command size mismatch')
    require(filetype != 6 or result['id'] is not None, 'dylib install ID absent')
    return result


def system_image(name):
    path = Path(name)
    return path.is_absolute() and '..' not in path.parts and (
        name.startswith('/usr/lib/') or name.startswith('/System/Library/'))


def unaliased_file(path):
    path = Path(os.path.abspath(path))
    # @loader_path semantics through a symlink spelling are deliberately not
    # inferred. Build-tree dylibs must be actual files, with unaliased parents.
    require(path == path.resolve(), 'symlinked non-system library path is unsupported: ' + str(path))
    require(path.is_file(), 'non-system dylib missing: ' + str(path))
    return path


def expand_path(name, owner, executable):
    if name.startswith('@loader_path/'):
        return Path(os.path.abspath(owner.parent / name[len('@loader_path/'):]))
    if name.startswith('@executable_path/'):
        return Path(os.path.abspath(executable.parent / name[len('@executable_path/'):]))
    require(name.startswith('/'), 'unsupported relative load/rpath: ' + name)
    return Path(os.path.abspath(name))


def library_graph(start, executable, inherited=()):
    """Resolve every non-system edge or reject; no fallback search assumptions.

    Reject multiple existing @rpath candidates even if dyld would select the
    first. Revisit shared nodes through different ancestor chains, and reject a
    load name that resolves differently. Missing weak dependencies also reject.
    """
    start = unaliased_file(start)
    executable = Path(executable).resolve()
    nodes, edges, visited, bindings = {}, set(), set(), {}
    pending = [(start, tuple(map(str, inherited)), ())]
    while pending:
        owner, ancestor_paths, ancestors = pending.pop()
        require(owner.is_file(), 'non-system dylib missing: ' + str(owner))
        info = macho(owner)
        nodes[str(owner)] = info
        own_paths = [str(expand_path(x, owner, executable)) for x in info['rpaths']]
        search = tuple(dict.fromkeys(own_paths + list(ancestor_paths)))
        key = (str(owner), search)
        if key in visited:
            continue
        visited.add(key)
        require(len(visited) <= 512, 'dependency graph exceeds bounded resolver')
        for item in info['dependencies']:
            name = item['name']
            if system_image(name):
                target = name
            elif name.startswith('@rpath/'):
                candidates = {str(unaliased_file(Path(p) / name[len('@rpath/'):])) for p in search
                              if (Path(p) / name[len('@rpath/'):]).is_file()}
                require(len(candidates) == 1, 'unresolved or ambiguous @rpath dependency: ' + name)
                target = candidates.pop()
            else:
                target = str(unaliased_file(expand_path(name, owner, executable)))
            previous = bindings.setdefault((str(owner), name), target)
            require(previous == target, 'dependency resolution varies by ancestor chain')
            edges.add((str(owner), name, target, item['command']))
            if not system_image(target) and target not in ancestors:
                pending.append((Path(target), search, ancestors + (str(owner),)))
    return {'nodes': nodes, 'edges': [list(x) for x in sorted(edges)],
            'system_images': sorted({x[2] for x in edges if system_image(x[2])}),
            'scope': 'thin ARM64 load-command closure; system shared cache not hashed; no dlopen inference'}


def loaded_images(stderr, executable, expected):
    found = set()
    process_id = None
    transitions = []
    for line in stderr.splitlines():
        if not line.startswith('dyld['):
            continue
        prefix = re.fullmatch(r'dyld\[(\d+)\]: (.+)', line)
        require(prefix is not None, 'unrecognized dyld prefix')
        pid, body = prefix.groups()
        if process_id is None:
            process_id = pid
        require(process_id == pid, 'mixed dyld process identities')
        match = re.fullmatch(r'<[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}> (/[^\n]+)', body)
        if match is None:
            transition = re.fullmatch(r'move (?:loaded to delayed|delayed to loaded): ([^/\s]+)', body)
            require(transition is not None, 'unrecognized dyld diagnostic; actual image identity unverified')
            transitions.append(transition.group(1))
            continue
        name = match.group(1)
        found.add(name if system_image(name) else str(Path(name).resolve()))
    require(found, 'dyld image log absent')
    # macOS may announce lazy-initialization state transitions by basename.
    # These lines never create image evidence; an actual UUID/path announcement
    # from this same process must account for every transition basename.
    require(set(transitions).issubset({Path(name).name for name in found}),
            'dyld transition has no corresponding image announcement')
    non_system = {x for x in found if not system_image(x)}
    require(non_system == {str(Path(executable).resolve()), *map(str, expected)},
            'actual loaded non-system images differ from static closure')
    return sorted(found)


def validate_load_result(result, exit_code):
    require(type(exit_code) is int and exit_code == 0 and isinstance(result, dict)
            and set(result) == {'status', 'symbol_in_expected_image'} and result['status'] == 'LOADABLE'
            and result['symbol_in_expected_image'] is True, 'native DXMT library failed load check')


def dependency_paths(text):
    require(text.startswith('probe:'), 'unexpected compiler dependency target')
    paths = shlex.split(text.replace('\\\n', ' ').split(':', 1)[1])
    require(bool(paths), 'empty compiler dependency set')
    return [Path(p).resolve() for p in paths]


def flags(config, discovered):
    source = Path(config['dxmt_source'])
    return ['-arch', 'arm64', '-isysroot', discovered['sdk'], '-std=c++20', '-O2',
            '-Wall', '-Wextra', '-Werror', '-Wno-extern-c-compat',
            '-I' + str(source / 'include/native/windows'), '-I' + str(source / 'include/native/directx')]


def tree_identity(source):
    """Independent reader for the bootstrap's complete tree receipt format."""
    source = Path(source)
    require(source.is_absolute() and source.is_dir() and not source.is_symlink(), 'invalid provenance tree root')
    require(source == source.resolve(), 'provenance tree root is not canonical')
    identity = {}
    for path in sorted(source.rglob('*')):
        require(path.resolve().is_relative_to(source), 'provenance tree link escapes root')
        relative = str(path.relative_to(source))
        if path.is_symlink():
            identity[relative] = ['symlink', os.readlink(path)]
        elif path.is_dir():
            identity[relative] = ['directory']
        elif path.is_file():
            identity[relative] = ['file', sha(path)]
        else:
            raise IntegrityError('special path in provenance tree')
    require(bool(identity), 'empty provenance tree')
    return identity


def validate_dxmt_provenance(record, config):
    provenance = record.get('dxmt_provenance')
    require(isinstance(provenance, dict) and set(provenance) ==
            {'schema', 'profile', 'inputs_before', 'inputs_after', 'outputs'},
            'DXMT build provenance absent or schema incomplete')
    require(type(provenance['schema']) is int and provenance['schema'] == 1 and
            provenance['profile'] == 'native-dxmt-build-v1', 'unsupported DXMT provenance profile')
    before = provenance['inputs_before']
    require(isinstance(before, dict) and set(before) == {'source', 'headers', 'llvm_install', 'patches'}
            and before == provenance['inputs_after'], 'DXMT provenance input set incomplete or changed during build')
    entries = {entry['name']: entry for entry in record['sources']}
    expected_roots = {'source': Path(config['dxmt_source']).resolve(),
                      'headers': Path(entries['mingw-directx-headers']['source']).resolve(),
                      'llvm_install': (WORK / 'llvm15-install').resolve()}
    trees = {}
    for key, root in expected_roots.items():
        item = before[key]
        require(isinstance(item, dict) and set(item) == {'root', 'tree_identity'}
                and item['root'] == str(root), 'DXMT provenance root/fields mismatch: ' + key)
        trees[key] = tree_identity(root)
        require(item['tree_identity'] == trees[key], 'DXMT provenance tree changed or omitted entries: ' + key)
    require(tree_identity(expected_roots['source'] / 'include/native/directx') == trees['headers'],
            'compiled native DirectX headers differ from pinned header source receipt')
    expected_patches = hashes([HERE / 'metal-module-cache.patch'])
    require(before['patches'] == expected_patches, 'DXMT applied patch receipt incomplete or changed')
    outputs = provenance['outputs']
    require(isinstance(outputs, dict) and bool(outputs), 'DXMT output receipt absent')
    build_dir = Path(config['dxmt_build']).resolve()
    expected_paths = {str(path.resolve()) for path in build_dir.rglob('*.dylib') if path.is_file()}
    require(set(outputs) == expected_paths, 'DXMT output receipt path set incomplete or changed')
    primary = str(build_dir / 'src/d3d11/d3d11.dylib')
    require(primary in outputs, 'D3D11 primary library absent from build receipt')
    bound = {}
    for path, item in outputs.items():
        require(isinstance(item, dict) and set(item) == {'realpath', 'sha256'}, 'malformed DXMT output receipt')
        actual = Path(path).resolve()
        require(actual.is_relative_to(build_dir) and item['realpath'] == str(actual), 'DXMT output path/realpath changed')
        require(item['sha256'] == sha(actual), 'DXMT output no longer matches bootstrap artifact: ' + path)
        previous = bound.setdefault(str(actual), item['sha256'])
        require(previous == item['sha256'], 'conflicting DXMT output aliases')
    receipt = record.get('llvm_receipt')
    require(isinstance(receipt, dict) and set(receipt) == {'path', 'sha256'}, 'LLVM install build receipt missing')
    receipt_path = Path(receipt['path'])
    require(receipt_path.is_absolute() and receipt_path == receipt_path.resolve()
            and receipt['sha256'] == sha(receipt_path), 'LLVM install receipt changed')
    llvm_record = read_json(receipt_path)
    require(type(llvm_record.get('schema')) is int and llvm_record['schema'] == 1 and
            llvm_record.get('status') == 'LLVM_BUILT' and llvm_record.get('commit') == LLVM and
            llvm_record.get('install') == before['llvm_install'], 'LLVM receipt does not bind the actual install tree')
    return bound, [receipt_path, *expected_patches]


def require_graph_provenance(graph, bound):
    require(bool(graph['nodes']) and set(graph['nodes']).issubset(bound),
            'actual non-system dylib dependency absent from DXMT build receipt')
    require(all(sha(path) == bound[path] for path in graph['nodes']),
            'actual linked library differs from DXMT build receipt')


def provenance(config):
    source, build_dir = Path(config['dxmt_source']), Path(config['dxmt_build'])
    library = build_dir / 'src/d3d11/d3d11.dylib'
    needed = [source / 'include/native/windows/windows.h', source / 'include/native/directx/d3d11.h', library]
    missing = [str(p) for p in needed if not p.is_file()]
    if missing:
        raise DependencyNotReady('DXMT native dependency not ready: ' + ', '.join(missing))
    record_path = ROOT / 'build/graphics-stage5/bootstrap/evidence.json'
    if not record_path.is_file():
        raise DependencyNotReady('DXMT bootstrap provenance absent')
    record = read_json(record_path)
    require(record.get('status') == 'DEPENDENCIES_BUILT' and
            Path(record.get('dxmt_build', '')).resolve() == build_dir, 'DXMT build provenance not complete')
    require(record.get('script_sha256') == sha(HERE / 'bootstrap_dxmt.py'), 'bootstrap producer changed after DXMT build')
    require(record.get('source_validation') == 'BOUND_ARCHIVES_OR_RELEASE_ASSETS_OR_VERIFIED_GIT_SUBTREES_PLUS_EXACT_PATCH_AND_HEADER_COPY',
            'bootstrap did not verify source archives and approved transformations')
    entries = {entry['name']: entry for entry in record['sources']}
    require(entries['dxmt']['commit'] == DXMT and Path(entries['dxmt']['source']).resolve() == source
            and entries['mingw-directx-headers']['commit'] == HEADERS, 'DXMT/header pinned provenance mismatch')
    require(sha(SOURCE) == SOURCE_SHA, 'native C++ probe changed from reviewed source')
    bound, receipt_paths = validate_dxmt_provenance(record, config)
    records = [record_path, HERE / 'bootstrap_dxmt.py', source / 'meson.build',
               source / 'src/d3d11/meson.build', source / 'src/nativemetal/meson.build',
               source / 'include/native/directx/d3d11.h', source / 'src/dxmt/dxmt_shader_cache.cpp',
               source / 'src/util/log/log.cpp', *receipt_paths]
    patch = HERE / 'metal-module-cache.patch'
    if patch.is_file():
        records.append(patch)
    return unaliased_file(library), records, bound


def discover_inputs(config, out, discovered, *, write=False):
    library, records, bound = provenance(config)
    cpp = flags(config, discovered)
    env = environment(out)
    dependencies = {}
    for stem, source in [('probe', SOURCE), ('loadcheck', out / 'loadcheck.cpp')]:
        text = invoke([discovered['clang++'], *cpp, '-M', '-MT', 'probe', source], env,
                      out / (stem + '-dependencies.log') if write else None)
        dependencies[stem] = text
        path = out / (stem + '.d')
        if write:
            path.write_text(text)
        else:
            require(path.read_text() == text, 'compiler dependency discovery changed: ' + stem)
    graph = library_graph(library, out / 'd3d11-probe', [library.parent])
    require_graph_provenance(graph, bound)
    input_paths = [Path(__file__), SOURCE, out / 'loadcheck.cpp', out / 'probe.d', out / 'loadcheck.d',
                   *records, *(discovered[x] for x in ('clang++', 'ld', 'xcrun', 'python')),
                   *graph['nodes']]
    for text in dependencies.values():
        input_paths.extend(dependency_paths(text))
    require(SOURCE.resolve() in dependency_paths(dependencies['probe']), 'C++ source absent from dependencies')
    return hashes(input_paths), graph, library


def build(out=OUT, dxmt_source=None, dxmt_build=None):
    out = output(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'cache').mkdir(exist_ok=True)
    (out / 'cache/dxmt').mkdir(exist_ok=True)
    config = {'dxmt_source': str(Path(dxmt_source or WORK / ('sources/dxmt-' + DXMT)).resolve()),
              'dxmt_build': str(Path(dxmt_build or WORK / 'dxmt-build').resolve())}
    initial = {'schema': 1, 'status': 'BUILD_STARTED_NOT_EXECUTED', 'config': config,
               'scope': SCOPE, 'wrapper_sha256': sha(__file__), 'source_sha256': sha(SOURCE)}
    save(out / 'build-attempt.json', initial)
    try:
        provenance(config)  # Fail before invoking clang when DXMT is still absent.
        (out / 'loadcheck.cpp').write_text(LOAD_SOURCE)
        discovered = tools(out)
        before, graph, library = discover_inputs(config, out, discovered, write=True)
        cpp = flags(config, discovered)
        common = [discovered['clang++'], *cpp, '--ld-path=' + discovered['ld'],
                  '-Wl,-rpath,' + str(library.parent)]
        env = environment(out)
        invoke([*common, SOURCE, library, '-o', out / 'd3d11-probe'], env, out / 'compile.log')
        invoke([*common, out / 'loadcheck.cpp', '-o', out / 'loadcheck'], env, out / 'loadcheck-compile.log')
        executable_graph = library_graph(out / 'd3d11-probe', out / 'd3d11-probe')
        require(set(executable_graph['nodes']) - {str(out / 'd3d11-probe')} == set(graph['nodes']),
                'actual link graph differs from pre-build library identity')
        require(macho(out / 'loadcheck')['filetype'] == 2, 'load checker is not ARM64 executable')
        after, graph_after, library_after = discover_inputs(config, out, discovered)
        require(before == after and graph == graph_after and library == library_after, 'build inputs changed')
        artifact_paths = [out / x for x in ('d3d11-probe', 'loadcheck', 'compile.log', 'loadcheck-compile.log',
                                           'probe-dependencies.log', 'loadcheck-dependencies.log')]
        result = {**initial, 'status': BUILD_STATUS, 'tools': discovered, 'inputs_before': before,
                  'inputs_after': after, 'library': str(library), 'library_graph': graph,
                  'executable_graph': executable_graph, 'artifacts': hashes(artifact_paths),
                  'identity_scope': 'actual compiler -M inputs/tools and linked non-system dylibs; system dyld cache not hashed',
                  'load_verified': False, 'render_verified': False}
        save(out / 'build.json', result)
        save(out / 'build-attempt.json', {**initial, 'status': BUILD_STATUS, 'build_sha256': sha(out / 'build.json')})
        return result
    except Exception as error:
        failure = {**initial, 'status': 'DEPENDENCY_NOT_READY' if isinstance(error, DependencyNotReady) else 'FAIL',
                   'exception': type(error).__name__, 'error': str(error), 'load_verified': False, 'render_verified': False}
        save(out / 'build-attempt.json', failure)
        if not (out / 'first-failure.json').exists():
            save(out / 'first-failure.json', failure)
        raise


def verify_build(out=OUT):
    out = output(out)
    record = read_json(out / 'build.json')
    require(record['schema'] == 1 and record['status'] == BUILD_STATUS and record['scope'] == SCOPE,
            'unexpected D3D11 build record')
    require(record['load_verified'] is False and record['render_verified'] is False, 'build claims runtime acceptance')
    require(record['wrapper_sha256'] == sha(__file__) and record['source_sha256'] == SOURCE_SHA,
            'build wrapper/source identity changed')
    require((out / 'loadcheck.cpp').read_text() == LOAD_SOURCE, 'native load check source changed')
    require(record['tools'] == tools(out), 'actual compiler/linker/python selection changed')
    expected, graph, library = discover_inputs(record['config'], out, record['tools'])
    require(record['inputs_before'] == record['inputs_after'] == expected, 'build input closure incomplete or changed')
    require(record['library_graph'] == graph and record['library'] == str(library), 'library resolution changed')
    require(record['executable_graph'] == library_graph(out / 'd3d11-probe', out / 'd3d11-probe'),
            'linked executable dependency graph changed')
    paths = [out / x for x in ('d3d11-probe', 'loadcheck', 'compile.log', 'loadcheck-compile.log',
                               'probe-dependencies.log', 'loadcheck-dependencies.log')]
    require(record['artifacts'] == hashes(paths), 'mandatory build artifact closure changed')
    return record


def execution_inputs(out, build_record):
    return hashes([*build_record['inputs_after'], *build_record['artifacts'], out / 'build.json'])


def run_child(command, env, stdout_path, stderr_path):
    try:
        process = subprocess.run(list(map(str, command)), env=env, text=True, capture_output=True, timeout=120)
    except subprocess.TimeoutExpired as error:
        for path, value in ((stdout_path, error.stdout), (stderr_path, error.stderr)):
            Path(path).write_bytes(value.encode() if isinstance(value, str) else value or b'')
        raise IntegrityError('native child exceeded 120 seconds; partial streams retained') from error
    Path(stdout_path).write_text(process.stdout)
    Path(stderr_path).write_text(process.stderr)
    return process


def execute(out=OUT, label='host'):
    out = output(out)
    require(label in ('host', 'restricted'), 'unknown run label')
    b = verify_build(out)
    before = execution_inputs(out, b)
    env = environment(out, images=True)
    record = {'schema': 1, 'status': 'FAIL', 'scope': SCOPE, 'label': label, 'environment': env,
              'inputs_before': before, 'load_result': None, 'result': None,
              'load_exit_code': None, 'exit_code': None, 'validation_error': None,
              'load_images': [], 'probe_images': [], 'gpu_probe_started': False}
    stream_names = [label + suffix for suffix in ('.load.stdout', '.load.stderr', '.stdout.json', '.stderr.log')]
    for name in stream_names:
        (out / name).write_text('')
    try:
        load = run_child([out / 'loadcheck', b['library']], env, out / stream_names[0], out / stream_names[1])
        record['load_exit_code'] = load.returncode
        record['load_result'] = strict_json(load.stdout)
        validate_load_result(record['load_result'], load.returncode)
        record['load_images'] = loaded_images(load.stderr, out / 'loadcheck', b['library_graph']['nodes'])
        same(before)
        record['gpu_probe_started'] = True
        probe = run_child([out / 'd3d11-probe'], env, out / stream_names[2], out / stream_names[3])
        record['exit_code'] = probe.returncode
        record['result'] = strict_json(probe.stdout)
        record['probe_images'] = loaded_images(probe.stderr, out / 'd3d11-probe', b['library_graph']['nodes'])
        validate_result(record['result'], probe.returncode)
        same(before)
        verify_build(out)
        record['status'] = 'PASS'
    except Exception as error:
        record['validation_error'] = type(error).__name__ + ': ' + str(error)
    try:
        record['inputs_after'] = hashes(before)
    except OSError as error:
        record['inputs_after'] = None
        record['identity_error'] = str(error)
    if record['inputs_after'] != before:
        record['status'] = 'FAIL'
        record['validation_error'] = 'execution inputs changed'
    record['artifacts'] = hashes(out / name for name in stream_names)
    save(out / (label + '.json'), record)
    return record


def verify(out=OUT, label='host'):
    out = output(out)
    require(label in ('host', 'restricted'), 'unknown run label')
    b = verify_build(out)
    r = read_json(out / (label + '.json'))
    require(r['schema'] == 1 and r['status'] == 'PASS' and r['label'] == label and r['scope'] == SCOPE,
            'D3D11 run is not accepted')
    require(r['environment'] == environment(out, images=True), 'run environment changed')
    require(r['gpu_probe_started'] is True and r['validation_error'] is None, 'run has a validation error')
    require(r['inputs_before'] == r['inputs_after'] == execution_inputs(out, b), 'execution closure incomplete or changed')
    names = [label + suffix for suffix in ('.load.stdout', '.load.stderr', '.stdout.json', '.stderr.log')]
    require(r['artifacts'] == hashes(out / name for name in names), 'run streams changed or missing')
    load_result = strict_json((out / names[0]).read_text())
    require(load_result == r['load_result'], 'load summary differs from actual output')
    validate_load_result(load_result, r['load_exit_code'])
    require(r['load_images'] == loaded_images((out / names[1]).read_text(), out / 'loadcheck', b['library_graph']['nodes']),
            'loaded-library summary differs from actual output')
    require(r['probe_images'] == loaded_images((out / names[3]).read_text(), out / 'd3d11-probe', b['library_graph']['nodes']),
            'probe library summary differs from actual output')
    result = strict_json((out / names[2]).read_text())
    require(result == r['result'], 'D3D11 summary differs from actual stdout')
    validate_result(result, r['exit_code'])
    return {'status': 'PASS_CURRENT', 'scope': SCOPE, 'evidence_sha256': sha(out / (label + '.json'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    for mode in ('build', 'verify-build', 'run', 'verify'):
        group.add_argument('--' + mode, action='store_true')
    parser.add_argument('--out', type=Path, default=OUT)
    parser.add_argument('--dxmt-source', type=Path)
    parser.add_argument('--dxmt-build', type=Path)
    parser.add_argument('--label', choices=('host', 'restricted'), default='host')
    args = parser.parse_args()
    try:
        if args.build:
            result = build(args.out, args.dxmt_source, args.dxmt_build)
        elif args.verify_build:
            result = verify_build(args.out)
        elif args.run:
            result = execute(args.out, args.label)
        else:
            result = verify(args.out, args.label)
        print(json.dumps({k: result[k] for k in ('status', 'scope') if k in result}))
        return 0 if result['status'] != 'FAIL' else 2
    except Exception as error:
        print(json.dumps({'status': 'DEPENDENCY_NOT_READY' if isinstance(error, DependencyNotReady) else 'REJECT',
                          'exception': type(error).__name__, 'error': str(error), 'scope': SCOPE}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
