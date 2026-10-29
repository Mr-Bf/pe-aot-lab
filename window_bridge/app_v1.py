#!/usr/bin/env python3
"""Package the frozen original-PE O3 program; never launch its native code.

This is a local, ad-hoc signed development App requiring explicit CLI arguments.
Its static relocation check does not establish LaunchServices/Finder readiness.
"""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from graphics_stage5 import d3d11_probe as base
from window_bridge import window_bindings as binding
from native_window import build_v2 as backend

SOURCE_BUILD = ROOT / 'build/window-bridge/program-build-03'
SOURCE_RECEIPT_SHA = '052159cb1f173102a07786fd22367941fa385f9b4a3b121d1787f1e59adbca03'
SOURCE_EXE_SHA = '2ea542a520900ee985001f2eb0b363c65651f06a2eb908641808eb92be691e21'
PE_SHA = 'a9997a6e542efee64c19d8a2ac343d28e294341a187ab954b9d8e0a6a9824da1'
OUT = ROOT / 'build/window-bridge/app-v1-01'
STATUS = 'APP_STATICALLY_VERIFIED_NOT_EXECUTED'
SCOPE = dict.fromkeys(('packaged_executable_launches', 'library_loads', 'window_executions',
                       'gpu_executions', 'guest_executions'), 0)
NAMES = frozenset(('d3d11.dylib', 'dxgi.dylib', 'winemetal.dylib'))
PLIST = {'CFBundleIdentifier': 'org.peaotlab.IntegerTileV1',
         'CFBundleName': 'PE AOT Integer Tile V1', 'CFBundleDisplayName': 'PE AOT Integer Tile V1',
         'CFBundleExecutable': 'pe-aot-window', 'CFBundlePackageType': 'APPL',
         'CFBundleVersion': '1', 'CFBundleShortVersionString': '0.1',
         'NSHighResolutionCapable': True}
README = '''# PE AOT Integer Tile V1 — local development package

This App contains the unchanged original Windows PE lifted to ARM64, the frozen
native host/runtime, and three dynamically linked DXMT libraries. Packaging only
changes Mach-O dependency paths and ad-hoc signatures; it does not rebuild the
PE, rewrite guest game rules, or run the executable.

Explicit arguments are required. Finder double-click/no-argument startup is not
implemented. From a terminal, use a newly created absolute data directory and
an independently supervised run, for example (replace paths with your own):

  "./PE AOT Integer Tile V1.app/Contents/MacOS/pe-aot-window" \\
    --data-dir "/absolute/fresh data directory" --budget 1000000 \\
    --timeout-ms 45000 \\
    --test-sequence right,right-repeat,right-up,right,right-up,left,left-up,escape

TEST_QUEUE is controlled message injection, not evidence of physical keyboard
input. The original PE currently saves state only; loading an existing save is
not implemented. The host emits JSON to stdout. A zero exit code alone does not
prove the workload passed: inspect actual guest/API/save/cleanup observations.
An external 60-second supervisor remains required. No runtime relocation,
LaunchServices, Finder, pixel-readback or performance claim is made by the static
packaging receipt. No Python or Rosetta is used by this ARM64 executable.

Signatures are ad-hoc for local testing, not Developer ID/notarization. The DXMT
license notices, LGPL text and local patches/adapters are included under Licenses
and BackendChanges. Full corresponding backend build sources and provenance are
retained in the development workspace; this is not a release distribution.
'''


def require(value, message):
    if not value:
        raise ValueError(message)


def dump_exclusive(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def output(path):
    path = Path(path).absolute()
    root = ROOT / 'build/window-bridge'
    require(path == path.resolve() and path.parent == root and path.name.startswith('app-v1-'),
            'new app-v1-* directory directly under build/window-bridge required')
    return path


def app_path(out):
    return Path(out) / 'PE AOT Integer Tile V1.app'


def relocation_path(out):
    return Path(out) / 'relocation with spaces/Relocated Integer Tile.app'


def executable(app):
    return Path(app) / 'Contents/MacOS/pe-aot-window'


def tools():
    found = {name: str(Path(shutil.which(name) or '/usr/bin/' + name).absolute())
             for name in ('install_name_tool', 'codesign')}
    found['python'] = str(Path(sys.executable).resolve())
    require(all(Path(p).is_file() for p in found.values()), 'packaging tool absent')
    return found


def resource_sources():
    return {'Licenses/DXMT-LICENSE': backend.SOURCE / 'LICENSE',
            'Licenses/DXMT-COPYING.LIB': backend.SOURCE / 'COPYING.LIB',
            'Licenses/Remill-LICENSE': ROOT / 'integration_stage3/LICENSE.remill',
            'BackendChanges/metal-module-cache.patch': ROOT / 'graphics_stage5/metal-module-cache.patch',
            'BackendChanges/native-wsi-v1.patch': backend.WSI,
            'BackendChanges/dxmt-lifetime-v2.patch': backend.LIFETIME,
            'BackendChanges/native_wsi.h': backend.HERE / 'native_wsi.h',
            'BackendChanges/native_wsi.c': backend.HERE / 'native_wsi.c'}


def source_program():
    require(base.sha(SOURCE_BUILD / 'program-build.json') == SOURCE_RECEIPT_SHA,
            'frozen O3 source receipt differs')
    program = binding.Program.from_build(SOURCE_BUILD)
    require(program.optimization == 'O3' and program.executable_sha256 == SOURCE_EXE_SHA and
            program.source_sha256 == PE_SHA, 'fixed original PE/executable identity differs')
    return program


def discover(t):
    program = source_program()
    record = program.build_manifest
    paths = {*record['native_inputs'], *record['artifacts'], str(SOURCE_BUILD / 'program-build.json'),
             *map(str, binding.python_closure([Path(__file__)])), *t.values(),
             *map(str, resource_sources().values())}
    return base.hashes(paths), program


def tree(app):
    app = Path(app)
    require(app.is_dir() and not app.is_symlink(), 'real App directory required')
    result = {}
    for path in sorted(app.rglob('*')):
        require(not path.is_symlink(), 'bundle symlink rejected')
        if path.is_file():
            result[str(path.relative_to(app))] = {'sha256': base.sha(path), 'mode': path.stat().st_mode & 0o777}
        else:
            require(path.is_dir(), 'special bundle file rejected')
    require(result, 'empty bundle')
    return result


def section_identity(path):
    """Compare every Mach-O section payload/VA, excluding mutable load commands.

    This complements, rather than replaces, the trusted install_name_tool command
    chain: link-edit tables/signatures have no sections and are not this check's
    scope. All code, constants, embedded PE and file-backed data sections count.
    """
    data = Path(path).read_bytes()
    base.macho(path)
    count, command_bytes = struct.unpack_from('<II', data, 16)
    at = 32
    result = {}
    for _ in range(count):
        command, size = struct.unpack_from('<II', data, at)
        if command == 0x19:
            require(size >= 72, 'short segment command')
            nsections = struct.unpack_from('<I', data, at + 64)[0]
            require(size == 72 + nsections * 80, 'segment section table differs')
            for i in range(nsections):
                pos = at + 72 + i * 80
                sect = data[pos:pos+16].split(b'\0')[0].decode('ascii')
                seg = data[pos+16:pos+32].split(b'\0')[0].decode('ascii')
                address, length, offset, align, reloff, nreloc, flags, r1, r2, r3 = struct.unpack_from('<QQ8I', data, pos+32)
                key = seg + '/' + sect
                require(key not in result, 'duplicate Mach-O section')
                zero = (flags & 0xff) in (1, 0xc, 0x12)
                require(zero or (offset <= len(data) and length <= len(data)-offset), 'section outside file')
                result[key] = {'address': address, 'size': length, 'alignment': align, 'flags': flags,
                               'reserved': [r1, r2, r3], 'relocation_count': nreloc,
                               'sha256': None if zero else hashlib.sha256(data[offset:offset+length]).hexdigest()}
        at += size
    require(at == 32 + command_bytes and result, 'invalid or empty section identity')
    return result


def package_graph(app):
    app = Path(app).absolute()
    require(app == app.resolve(), 'bundle aliased path rejected')
    exe = executable(app)
    libs = app / 'Contents/Frameworks'
    require(set(p.name for p in libs.iterdir()) == NAMES, 'bundled library set differs')
    require(plistlib.loads((app / 'Contents/Info.plist').read_bytes()) == PLIST, 'App plist differs')
    graph = base.library_graph(exe, exe)
    require(set(graph['nodes']) == {str(exe), *(str(libs / n) for n in NAMES)},
            'non-system dependency escaped bundle or a library is unreachable')
    for name, node in graph['nodes'].items():
        is_exe = name == str(exe)
        require(node['filetype'] == (2 if is_exe else 6), 'unexpected Mach-O file type')
        require(node['rpaths'] == (['@executable_path/../Frameworks'] if is_exe else ['@loader_path/']),
                'residual or missing search path')
        require(Path(name).stat().st_mode & 0o111, 'non-executable code file')
        if not is_exe:
            require(node['id'] == '@rpath/' + Path(name).name, 'dylib ID not bundle-relative')
        for dependency in node['dependencies']:
            require(base.system_image(dependency['name']) or dependency['name'] in {'@rpath/' + n for n in NAMES},
                    'external dependency load name')
    require(all(base.system_image(target) or Path(target).is_relative_to(app)
                for _, _, target, _ in graph['edges']), 'external dependency target')
    return graph


def normalized_graph(graph, app):
    app = Path(app).resolve()
    def local(path):
        path = Path(path)
        return str(path.relative_to(app)) if path.is_relative_to(app) else str(path)
    return {'nodes': {local(p): v for p, v in graph['nodes'].items()},
            'edges': [[local(owner), name, local(target), kind] for owner, name, target, kind in graph['edges']],
            'system_images': graph['system_images'], 'scope': graph['scope']}


def mapping_for(program, app):
    graph = program.build_manifest['executable_graph']
    libraries = set(graph['nodes']) - {str(program.executable)}
    require(len(libraries) == 3 and {Path(p).name for p in libraries} == NAMES, 'source graph is not the fixed three-library closure')
    return {str(program.executable): executable(app),
            **{p: app / 'Contents/Frameworks' / Path(p).name for p in sorted(libraries)}}


def plans(program, app, relocated, t):
    graph = program.build_manifest['executable_graph']
    mapping = mapping_for(program, app)
    result = []
    for original, destination in mapping.items():
        node = graph['nodes'][original]
        is_exe = original == str(program.executable)
        wanted_rpath = '@executable_path/../Frameworks' if is_exe else '@loader_path/'
        args = [t['install_name_tool']]
        if not is_exe:
            args += ['-id', '@rpath/' + destination.name]
        for old in node['rpaths']:
            if old != wanted_rpath:
                args += ['-delete_rpath', old]
        if wanted_rpath not in node['rpaths']:
            args += ['-add_rpath', wanted_rpath]
        for owner, name, target, kind in graph['edges']:
            if owner == original and target in mapping:
                args += ['-change', name, '@rpath/' + mapping[target].name]
        result.append(('transform-' + destination.name, [*args, str(destination)]))
    for name in sorted(NAMES):
        result.append(('sign-' + name, [t['codesign'], '--force', '--sign', '-', '--timestamp=none', str(app / 'Contents/Frameworks' / name)]))
    result += [('sign-app', [t['codesign'], '--force', '--sign', '-', '--timestamp=none', str(app)]),
               ('verify-app', [t['codesign'], '--verify', '--deep', '--strict', '--verbose=2', str(app)]),
               ('verify-relocated', [t['codesign'], '--verify', '--deep', '--strict', '--verbose=2', str(relocated)])]
    return result


def resources(program):
    provenance = {'schema': 1, 'original_pe_sha256': PE_SHA, 'original_program_sha256': SOURCE_EXE_SHA,
                  'original_build_receipt_sha256': SOURCE_RECEIPT_SHA,
                  'backend_profile': backend.PROFILE, 'build_optimization': 'O3',
                  'runtime_requires_python': False, 'runtime_requires_rosetta': False,
                  'requires_explicit_arguments': True, 'finder_no_arguments_ready': False,
                  'package_acceptance': 'STATIC_ONLY; see external evidence for actual execution',
                  'licenses_and_backend_changes': {k: base.sha(v) for k, v in resource_sources().items()}}
    result = {k: p.read_bytes() for k, p in resource_sources().items()}
    result['README.txt'] = README.encode()
    result['provenance.json'] = (json.dumps(provenance, indent=2, sort_keys=True) + '\n').encode()
    return result


def command(out, name, args, commands):
    path = out / 'commands' / (name + '.json')
    path.parent.mkdir(exist_ok=True)
    require(not path.exists(), 'command log already exists')
    completed = subprocess.run(args, env=base.environment(out), capture_output=True, text=True)
    detail = {'command': args, 'returncode': completed.returncode, 'stdout': completed.stdout, 'stderr': completed.stderr}
    dump_exclusive(path, detail)
    commands.append({'name': name, 'path': str(path), 'sha256': base.sha(path), 'returncode': completed.returncode})
    require(completed.returncode == 0, 'packaging command failed: ' + str(path))


def build(out=OUT):
    out = output(out)
    require(not out.exists(), 'attempt directory exists; keep it and use a fresh app-v1-* name')
    out.mkdir(parents=True)
    t = tools()
    initial = {'schema': 1, 'status': 'PACKAGING_STARTED_NOT_EXECUTED', 'scope': SCOPE,
               'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'source_build': str(SOURCE_BUILD), 'source_build_sha256': SOURCE_RECEIPT_SHA,
               'packager_sha256': base.sha(__file__), 'tools': t}
    dump_exclusive(out / 'started.json', initial)
    commands = []
    try:
        before, program = discover(t)
        app = app_path(out)
        relocated = relocation_path(out)
        mapping = mapping_for(program, app)
        for original, destination in mapping.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, destination)
            require(base.sha(destination) == base.sha(original), 'source copy mismatch')
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(PLIST, sort_keys=True))
        for name, data in resources(program).items():
            destination = app / 'Contents/Resources' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        plan = plans(program, app, relocated, t)
        for name, args in plan[:-1]:
            command(out, name, args, commands)
        copied = {}
        for original, destination in mapping.items():
            identity = section_identity(original)
            require(section_identity(destination) == identity, 'packaging changed code/PE/data section payload or virtual layout')
            copied[str(destination.relative_to(app))] = {'source': original, 'original_sha256': base.sha(original),
                'packaged_sha256': base.sha(destination), 'section_identity': identity}
        graph = package_graph(app)
        relocated.parent.mkdir(parents=True)
        shutil.copytree(app, relocated)
        moved_graph = package_graph(relocated)
        require(tree(app) == tree(relocated) and normalized_graph(graph, app) == normalized_graph(moved_graph, relocated),
                'static relocation changed bytes/modes or load graph')
        name, args = plan[-1]
        command(out, name, args, commands)
        after, again = discover(t)
        require(before == after and program.build_manifest == again.build_manifest, 'packaging inputs changed')
        receipt = {'schema': 1, 'status': STATUS, 'scope': SCOPE, 'source_build': str(SOURCE_BUILD),
            'source_build_sha256': SOURCE_RECEIPT_SHA, 'source_executable_sha256': SOURCE_EXE_SHA,
            'original_pe_sha256': PE_SHA, 'tools': t, 'inputs_before': before, 'inputs_after': after,
            'app': str(app), 'relocation': str(relocated), 'app_tree': tree(app), 'relocation_tree': tree(relocated),
            'graph': graph, 'relocation_graph': moved_graph, 'normalized_graph': normalized_graph(graph, app),
            'copied_code': copied, 'commands': commands,
            'artifacts': base.hashes([out / 'started.json', *[Path(c['path']) for c in commands]]),
            'signature': 'ad-hoc; no Developer ID/notarization', 'runtime_relocation_verified': False,
            'finder_no_arguments_ready': False, 'requires_explicit_arguments': True,
            'identity_scope': 'verified source build + exact copied code/data sections + transformed Mach-O/load graph + signatures; no package execution'}
        dump_exclusive(out / 'evidence.json', receipt)
        return verify(out)
    except Exception as error:
        dump_exclusive(out / 'first-failure.json', {'schema': 1, 'status': 'FAIL_NOT_EXECUTION_ACCEPTANCE',
                       'error': repr(error), 'scope': SCOPE, 'commands': commands,
                       'started_sha256': base.sha(out / 'started.json')})
        raise


def verify(out=OUT):
    out = output(out)
    r = base.read_json(out / 'evidence.json')
    require(type(r.get('schema')) is int and r['schema'] == 1 and r.get('status') == STATUS and
            r.get('scope') == SCOPE and all(type(v) is int for v in r['scope'].values()), 'invalid static scope/status')
    t = tools()
    require(r['tools'] == t, 'packaging tools changed')
    current, program = discover(t)
    require(current == r['inputs_before'] == r['inputs_after'], 'source dependency set changed/omitted')
    require((r['source_build'], r['source_build_sha256'], r['source_executable_sha256'], r['original_pe_sha256']) ==
            (str(SOURCE_BUILD), SOURCE_RECEIPT_SHA, SOURCE_EXE_SHA, PE_SHA), 'source identity differs')
    started = base.read_json(out / 'started.json')
    expected_start = {'schema': 1, 'status': 'PACKAGING_STARTED_NOT_EXECUTED', 'scope': SCOPE,
                     'source_build': str(SOURCE_BUILD), 'source_build_sha256': SOURCE_RECEIPT_SHA,
                     'packager_sha256': base.sha(__file__), 'tools': t}
    require({k: v for k, v in started.items() if k != 'started_utc'} == expected_start and
            isinstance(started.get('started_utc'), str), 'immutable start identity changed')
    app = app_path(out)
    moved = relocation_path(out)
    require(r['app'] == str(app) and r['relocation'] == str(moved), 'bundle path differs')
    require(tree(app) == r['app_tree'] == r['relocation_tree'] == tree(moved), 'bundle bytes/modes differ')
    expected_resources = resources(program)
    actual_resources = {str(p.relative_to(app / 'Contents/Resources')): p.read_bytes()
                        for p in (app / 'Contents/Resources').rglob('*') if p.is_file()}
    require(actual_resources == expected_resources, 'resource provenance/licenses differ')
    require(set(r['app_tree']) == {'Contents/Info.plist', 'Contents/MacOS/pe-aot-window',
            *(f'Contents/Frameworks/{n}' for n in NAMES), *(f'Contents/Resources/{n}' for n in expected_resources),
            'Contents/_CodeSignature/CodeResources'}, 'unexpected bundle file set')
    graph = package_graph(app)
    moved_graph = package_graph(moved)
    require(graph == r['graph'] and moved_graph == r['relocation_graph'] and
            normalized_graph(graph, app) == r['normalized_graph'] == normalized_graph(moved_graph, moved), 'bundle dependency graph differs')
    copied = {}
    for original, destination in mapping_for(program, app).items():
        identity = section_identity(original)
        require(identity == section_identity(destination), 'original code/PE/data sections differ')
        copied[str(destination.relative_to(app))] = {'source': original, 'original_sha256': base.sha(original),
                'packaged_sha256': base.sha(destination), 'section_identity': identity}
    require(copied == r['copied_code'], 'transformation/source linkage differs')
    plan = plans(program, app, moved, t)
    require(len(r['commands']) == len(plan), 'command count differs')
    for recorded, (name, args) in zip(r['commands'], plan, strict=True):
        path = out / 'commands' / (name + '.json')
        detail = base.read_json(path)
        require(recorded == {'name': name, 'path': str(path), 'sha256': base.sha(path), 'returncode': 0} and
                detail.get('command') == args and type(detail.get('returncode')) is int and detail['returncode'] == 0 and
                set(detail) == {'command', 'returncode', 'stdout', 'stderr'}, 'static command evidence differs')
    require(r['artifacts'] == base.hashes([out / 'started.json', *[out / 'commands' / (n + '.json') for n, _ in plan]]),
            'command/start artifact closure differs')
    for path in (app, moved):
        base.invoke([t['codesign'], '--verify', '--deep', '--strict', str(path)], base.environment(out))
    require(r['runtime_relocation_verified'] is False and r['finder_no_arguments_ready'] is False and
            r['requires_explicit_arguments'] is True, 'unexecuted startup claim')
    return {'status': STATUS, 'evidence_sha256': base.sha(out / 'evidence.json'), 'app': str(app),
            'executable': str(executable(app)), 'packaged_executable_sha256': base.sha(executable(app)),
            'reachable_libraries': 3, 'static_relocation_verified': True, 'signature_verified': True,
            'runtime_relocation_verified': False, 'finder_no_arguments_ready': False, 'scope': SCOPE}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=OUT)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    print(json.dumps(verify(args.out) if args.verify_only else build(args.out), indent=2))
