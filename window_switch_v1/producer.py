"""Build a complete no-argument native window executable from caller PE bytes.

Packaging is the caller's next stage. Every root, RET shim, runtime, bridge,
Cocoa host and entry object is produced in this fresh attempt. No old Program
instance, old native object or historical build receipt is consumed.
"""
import json
from pathlib import Path
import re
import struct
from types import SimpleNamespace

from graphics_stage5 import d3d11_probe as graphics
from window_switch_v1 import lift
from portable_graphics_v1 import build as graphics_provider
from window_app_v1.noarg import expected_exports, header, spec
from window_switch_v1.headers import generate_headers
from window_switch_v1.profile import read_input, validate

ROOT = lift.ROOT
HOST = ROOT / 'window_bridge'
STATUS = 'PORTABLE_NO_ARGUMENT_NATIVE_BUILT_NOT_EXECUTED'
LIBRARIES = ('d3d11', 'dxgi', 'winemetal')


def version(value):
    lift.require(type(value) is str and re.fullmatch(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?', value), 'numeric macOS version required')
    values = tuple(map(int, value.split('.')))
    lift.require(all(0 <= n < 65536 for n in values), 'macOS version component outside bounds')
    return values + (0,) * (3 - len(values))


def minimum_version(filename):
    """Read deployment commands from an already validated thin ARM64 image."""
    graphics.macho(filename)
    data = Path(filename).read_bytes()
    count, size = struct.unpack_from('<II', data, 16)
    position, found = 32, []
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, position)
        if command == 0x32:  # LC_BUILD_VERSION
            lift.require(length >= 24, 'short build-version command')
            platform, packed = struct.unpack_from('<II', data, position + 8)
            lift.require(platform == 1, 'non-macOS backend/executable platform')
            found.append((packed >> 16, (packed >> 8) & 255, packed & 255))
        elif command == 0x24:  # LC_VERSION_MIN_MACOSX
            lift.require(length >= 16, 'short deployment-version command')
            packed, = struct.unpack_from('<I', data, position + 8)
            found.append((packed >> 16, (packed >> 8) & 255, packed & 255))
        position += length
    lift.require(position == 32 + size and len(found) == 1, 'unique macOS deployment version required')
    return found[0]


def backend_identity(provider, future_executable):
    required = {'source', 'd3d11', 'dxgi', 'winemetal', 'sdk', 'minimum_macos',
                'provider_manifest', 'provider_sha256', 'licenses'}
    lift.require(type(provider) is dict and required <= set(provider), 'complete explicit backend provider required')
    source = lift.path(provider['source'])
    sdk = Path(provider['sdk']).resolve(strict=True)
    lift.require(sdk.is_dir() and not sdk.is_relative_to(lift.OLD_WORK), 'external SDK directory required')
    receipt = lift.path(provider['provider_manifest'])
    lift.require(type(provider['provider_sha256']) is str and re.fullmatch('[0-9a-f]{64}', provider['provider_sha256']) and
                 lift.sha(receipt) == provider['provider_sha256'], 'backend provider receipt differs')
    # A caller-provided hash cannot establish that an arbitrary file is a
    # successful provider receipt. Reopen and validate the complete installation
    # using its public loader before accepting any of the caller's roles.
    verified = graphics_provider.paths_for(receipt.parent)

    def descriptor(value):
        lift.require(type(value.get('licenses')) is dict and bool(value['licenses']), 'backend licenses required')
        return dict(**{key: str(Path(value[key]).resolve(strict=True))
                       for key in ('source', 'sdk', 'provider_manifest', *LIBRARIES)},
                    minimum_macos=value['minimum_macos'], provider_sha256=value['provider_sha256'],
                    licenses={key: str(Path(item).resolve(strict=True)) for key, item in value['licenses'].items()})

    lift.require(descriptor(provider) == descriptor(verified), 'backend descriptor differs from verified provider roles')
    minimum = version(provider['minimum_macos'])
    lift.require(minimum >= (15, 2, 0), 'backend minimum macOS must be at least 15.2')
    files = [receipt]
    libraries = {}
    for name in LIBRARIES:
        item = lift.path(provider[name])
        lift.require(item.name == name + '.dylib' and graphics.macho(item)['filetype'] == 6,
                     'incorrect backend library role: ' + name)
        lift.require(minimum_version(item) <= minimum, 'backend library requires a newer macOS than provider declares')
        libraries[name] = item
        files.append(item)
    for suffix, filename in (('windows', 'windows.h'), ('directx', 'd3d11.h')):
        directory = source / 'include/native' / suffix
        lift.require((directory / filename).is_file(), 'new backend API headers absent')
        for item in directory.rglob('*'):
            lift.require(item.resolve().is_relative_to(source), 'backend include link escaped new source')
            if item.is_file():
                files.append(item)
    licenses = provider['licenses']
    lift.require(type(licenses) is dict and bool(licenses), 'backend licenses required')
    for relative, item in licenses.items():
        lift.require(type(relative) is str and relative and not Path(relative).is_absolute() and
                     '..' not in Path(relative).parts, 'relative license resource name required')
        files.append(lift.path(item))
    settings = [sdk / name for name in ('SDKSettings.json', 'SDKSettings.plist') if (sdk / name).is_file()]
    lift.require(bool(settings), 'backend SDK identity absent')
    files.extend(settings)
    graph = graphics.library_graph(libraries['d3d11'], future_executable,
                                   sorted({str(item.parent) for item in libraries.values()}))
    lift.require(set(graph['nodes']) == {str(item) for item in libraries.values()},
                 'backend non-system graph is not the selected three libraries')
    normalized = dict(source=str(source), sdk=str(sdk), minimum_macos=provider['minimum_macos'],
                      provider_manifest=str(receipt), provider_sha256=provider['provider_sha256'],
                      licenses={key: str(Path(value).resolve()) for key, value in licenses.items()},
                      **{name: str(item) for name, item in libraries.items()})
    return normalized, lift.snapshot(files), graph


def disjoint_output(out, cpu_prefix, graphics_prefix):
    for role, installation in (('CPU', cpu_prefix), ('graphics', graphics_prefix)):
        lift.require(not out.is_relative_to(installation) and not installation.is_relative_to(out),
                     'producer output and ' + role + ' installation must be disjoint')


def compilation_units(out, backend, tools):
    common = ['-arch', 'arm64', '-isysroot', tools['sdk'],
              '-mmacosx-version-min=' + backend['minimum_macos'], '-O3', '-fno-lto',
              '-I', str(out), '-Wall', '-Wextra', '-Werror',
              '-DAOT_WINDOW_SWITCH_V1', '-include', str(ROOT / 'window_switch_v1/runtime.h')]
    cpp = [*common, '-std=c++17', '-Wno-extern-c-compat', '-fno-rtti', '-fno-exceptions',
           '-I' + backend['source'] + '/include/native/windows',
           '-I' + backend['source'] + '/include/native/directx']
    objc = [*common, '-std=c++20', '-Wno-deprecated-declarations']
    return [
        ('host', HOST / 'window_host.c', tools['clang'], [*common, '-std=c11', '-Dmain=aot_window_main']),
        ('runtime', HOST / 'window_runtime/runtime.c', tools['clang'], [*common, '-std=c11']),
        ('native-backend', HOST / 'native_backend.cpp', tools['clang++'], cpp),
        ('window-backend', HOST / 'native_backend_window.cpp', tools['clang++'], cpp),
        ('cocoa', HOST / 'cocoa_host.mm', tools['clang++'], objc),
        ('entry', ROOT / 'window_app_v1/entry.mm', tools['clang++'],
         [*objc, '-I', str(HOST), '-fno-objc-arc']),
    ]


def generated_dependencies(name, text, out):
    paths = graphics.dependency_paths(text)
    wanted = {'host': 'native_image.h', 'runtime': 'native_imports.h', 'entry': 'app_config.h'}.get(name)
    if wanted:
        lift.require([item.resolve() for item in paths if item.name == wanted] == [out / wanted],
                     'compiler selected a different generated header: ' + wanted)
    if name == 'entry':
        lift.require(HOST / 'noarg_files_v1.h' in paths, 'no-argument filesystem helper missing')
    lift.snapshot(paths)  # Existence and old-work guard apply before compilation.
    return paths


def discover_tools(run, sdk, env):
    result = {}
    for name in ('clang', 'clang++', 'ld'):
        value = run(['/usr/bin/xcrun', '--find', name], 'tool-' + name.replace('+', 'p'), env=env)['stdout'].strip()
        lift.require(value.startswith('/') and '\n' not in value, 'invalid explicit Apple tool path')
        item = Path(value).absolute()
        lift.require(item.is_file() and not item.resolve().is_relative_to(lift.OLD_WORK), 'Apple tool absent or points into old work')
        # clang++ must retain its invoked basename even when it is a symlink.
        result[name] = str(item)
    result.update(sdk=sdk, codesign='/usr/bin/codesign', nm='/usr/bin/nm', xcrun='/usr/bin/xcrun')
    return result


def build(cpu_prefix, backend_provider, pe, profile, identifier, out, run):
    value = spec(dict(identifier=identifier, name='PE AOT Portable Window'))
    data = read_input(pe)
    profile, image, _ = validate(data, profile)
    out = lift.path(out, exists=False)
    lift.require(not out.exists(), 'fresh native production directory required')
    cpu_prefix = lift.path(cpu_prefix)
    backend, backend_before, library_graph = backend_identity(backend_provider, out / 'native-executable')
    disjoint_output(out, cpu_prefix, Path(backend['provider_manifest']).parent)
    lift.cpu_identity(cpu_prefix)
    out.mkdir(parents=True)
    commands = lift.Commands(out, run, 'native')
    env = graphics.environment(out)
    (out / 'cache/dxmt').mkdir(parents=True)
    frozen = out / 'input.exe'
    frozen.write_bytes(data)
    lift.write(out / 'profile.json', profile)
    (out / 'app_config.h').write_text(header(value))
    lift.write(out / 'started.json', dict(status='STARTED_NOT_EXECUTED', input_sha256=lift.sha(frozen),
                                        cpu_prefix=str(cpu_prefix), backend=backend, identifier=identifier))
    try:
        source_files = lift.source_closure([Path(__file__), ROOT / 'portable_app_v1/lift.py'])
        producer_sources = lift.snapshot(source_files)
        session = lift.Session(cpu_prefix, out / 'compiler', run)
        roots = session.roots(frozen, profile['callback_rvas'], profile['switch_leaf_rva'])
        ret = session.ret_shim(out / 'ret-shim')
        root_rows = [roots['main'], *roots['roots']]
        generated = SimpleNamespace(image=image, source_bytes=data, source_sha256=lift.sha(frozen),
                                    out=out, roots=root_rows, root_manifest=roots)
        calls, instructions, observations = generate_headers(generated, profile)
        tools = discover_tools(commands, backend['sdk'], env)
        units = compilation_units(out, backend, tools)
        dependency_graphs, dependency_files = {}, []
        for name, source, compiler, flags in units:
            text = commands([compiler, *flags, '-M', '-MT', 'probe', source], 'deps-' + name, env=env)['stdout']
            dependency_graphs[name] = text
            (out / (name + '.d')).write_text(text)
            dependency_files.extend(generated_dependencies(name, text, out))
            dependency_files.append(out / (name + '.d'))
        root_inputs = [Path(row['directory']) / 'manifest.json' for row in root_rows]
        root_objects = [Path(row['manifest']['objects']['O3']['path']) for row in root_rows]
        ret_directory = out / 'ret-shim/lift'
        ret_object = Path(ret['objects']['O3']['path'])
        compile_before = lift.snapshot([
            *producer_sources, *session.inputs, *backend_before, *dependency_files,
            *[item for name, item in tools.items() if name != 'sdk'], frozen, out / 'profile.json',
            out / 'app_config.h', out / 'native_image.h', out / 'native_imports.h',
            out / 'compiler/roots.json', *root_inputs, *root_objects,
            ret_directory / 'manifest.json', ret_object,
        ])
        native_objects = []
        native_object_info = {}
        for name, source, compiler, flags in units:
            obj = out / (name + '.o')
            commands([compiler, *flags, '-c', source, '-o', obj], 'compile-' + name, env=env)
            info = lift.macho(obj, 1)
            exported = commands([tools['nm'], '-gU', obj], 'exports-' + name, env=env)['stdout']
            symbols = [line.split()[-1] for line in exported.splitlines() if line.split()]
            if name in ('host', 'entry'):
                lift.require(set(symbols) == expected_exports(name), 'host/entry object exports differ')
            native_objects.append(obj)
            native_object_info[name] = dict(path=str(obj), sha256=lift.sha(obj), macho=info, exports=symbols,
                                           source=str(source), compiler=compiler, flags=flags)
        lift.unchanged(compile_before)
        for row in root_rows:
            lift.verify_root(row['directory'], row['manifest'])
        lift.verify_root(ret_directory, ret)
        link_inputs = {**compile_before, **lift.snapshot(native_objects)}
        executable = out / 'native-executable'
        argv = [tools['clang++'], '-arch', 'arm64', '-isysroot', tools['sdk'],
                '-mmacosx-version-min=' + backend['minimum_macos'], '--ld-path=' + tools['ld'],
                '-Wl,-syslibroot,' + tools['sdk'], *native_objects, *root_objects, ret_object,
                backend['d3d11'], backend['winemetal'], '-framework', 'Cocoa', '-framework', 'Metal', '-framework', 'QuartzCore',
                *['-Wl,-rpath,' + item for item in sorted({str(Path(backend[name]).parent) for name in LIBRARIES})],
                '-o', executable]
        commands(argv, 'link', env=env)
        commands([tools['codesign'], '--force', '--sign', '-', '--timestamp=none', '--identifier', identifier, executable], 'sign', env=env)
        commands([tools['codesign'], '--verify', '--strict', executable], 'signature', env=env)
        lift.require(graphics.macho(executable)['filetype'] == 2 and
                     minimum_version(executable) == version(backend['minimum_macos']), 'native executable architecture/deployment differs')
        actual_graph = graphics.library_graph(executable, executable)
        lift.require(set(actual_graph['nodes']) == {str(executable), *library_graph['nodes']},
                     'linked executable consumed an unexpected non-system library')
        for node in actual_graph['nodes']:
            lift.require(not Path(node).resolve().is_relative_to(lift.OLD_WORK), 'linked old-work image')
        for name, source, compiler, flags in units:
            text = commands([compiler, *flags, '-M', '-MT', 'probe', source], 'deps-after-' + name, env=env)['stdout']
            lift.require(text == dependency_graphs[name], 'native dependency graph changed while compiling')
        backend_after, current_inputs, current_graph = backend_identity(backend_provider, executable)
        lift.require((backend_after, current_inputs, current_graph) == (backend, backend_before, library_graph),
                     'backend headers/libraries/provider changed during production')
        session.verify()
        for row in root_rows:
            lift.verify_root(row['directory'], row['manifest'])
        lift.verify_root(ret_directory, ret)
        lift.unchanged(link_inputs)
        lift.unchanged(producer_sources)
        # Re-derive headers without writing. Host state cannot replace PE bytes.
        expected_headers = dict(generated.generated_headers)
        generate_headers(generated, profile, write=False)
        lift.require(generated.generated_headers == expected_headers and
                     all((out / name).read_text() == text for name, text in expected_headers.items()),
                     'generated PE/import headers changed')
        record = dict(schema=1, status=STATUS, input_sha256=lift.sha(frozen), source_sha256=lift.sha(frozen),
                      profile=profile, identifier=identifier, minimum_macos=backend['minimum_macos'],
                      cpu_prefix=str(cpu_prefix), cpu_provider_sha256=session.provider_sha256, backend=backend, tools=tools,
                      native_executable=str(executable), native_sha256=lift.sha(executable),
                      library=backend['d3d11'], library_graph=actual_graph, backend_library_graph=library_graph,
                      native_objects=native_object_info,
                      objects=[str(item) for item in [*native_objects, *root_objects, ret_object]],
                      roots=root_rows, root_manifest=roots, ret_manifest=ret,
                      generated_headers={name: dict(path=str(out / name), sha256=lift.sha(out / name)) for name in expected_headers},
                      instruction_count=len(roots['instructions']), callback_count=len(roots['roots']),
                      calls=calls, imports=image.imports, virtual_calls=generated.virtual_calls,
                      register_calls=generated.register_calls, observations=observations,
                      dependency_graphs=dependency_graphs, compile_inputs_before=compile_before,
                      compile_inputs_after=lift.snapshot(compile_before), inputs_before=link_inputs, inputs_after=lift.snapshot(link_inputs),
                      producer_sources=producer_sources, command_count=len(commands.records),
                      generated_layout_harness_executions=0, guest_executions=0, gpu_executions=0,
                      artifacts=lift.artifacts(out), manifest_path=str(out / 'producer.json'),
                      scope='all caller PE roots and C3 shim lifted with selected CPU provider; six fresh host units; no-argument ARM64 executable linked to selected real backend; not packaged or executed')
        lift.write(out / 'producer.json', record)
        return record
    except Exception as error:
        lift.write(out / 'failure.json', dict(status='BUILD_FAILED_NOT_EXECUTED', error=repr(error),
                   input_sha256=lift.sha(frozen), command_count=len(commands.records),
                   generated_layout_harness_executions=0, guest_executions=0, gpu_executions=0))
        raise
