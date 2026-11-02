"""Fresh native production with a versioned, immutable inline lookup overlay."""
from pathlib import Path
from types import SimpleNamespace

from window_switch_v1 import lift
from window_switch_v1.producer import (ROOT, HOST, STATUS, LIBRARIES,
    backend_identity, disjoint_output, discover_tools, generated_dependencies,
    minimum_version, version, graphics, compilation_units as original_units)
from window_switch_v1.headers import generate_headers
from window_switch_v1.profile import read_input, validate
from window_app_v1.noarg import expected_exports, header, spec
from . import runtime


def compilation_units(out, backend, tools):
    units = original_units(out, backend, tools)
    return [(name, out / 'runtime-source' / runtime.RUNTIME if name == 'runtime' else source,
             compiler, [*flags, '-iquote', str(HOST / 'window_runtime')] if name == 'runtime' else flags)
            for name, source, compiler, flags in units]


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
        source_files = [*lift.source_closure([Path(__file__), ROOT / 'portable_app_v1/lift.py']), *runtime.template_paths()]
        producer_sources = lift.snapshot(source_files)
        session = lift.Session(cpu_prefix, out / 'compiler', run)
        roots = session.roots(frozen, profile['callback_rvas'], profile['switch_leaf_rva'])
        ret = session.ret_shim(out / 'ret-shim')
        root_rows = [roots['main'], *roots['roots']]
        generated = SimpleNamespace(image=image, source_bytes=data, source_sha256=lift.sha(frozen),
                                    out=out, roots=root_rows, root_manifest=roots)
        calls, instructions, observations = generate_headers(generated, profile)
        tools = discover_tools(commands, backend['sdk'], env)
        lookup = runtime.prepare(out / 'runtime-source')
        units = compilation_units(out, backend, tools)
        dependency_graphs, dependency_files = {}, []
        for name, source, compiler, flags in units:
            text = commands([compiler, *flags, '-M', '-MT', 'probe', source], 'deps-' + name, env=env)['stdout']
            dependency_graphs[name] = text
            (out / (name + '.d')).write_text(text)
            dependency_files.extend(generated_dependencies(name, text, out))
            if name == 'runtime': runtime.validate_dependencies(text, lookup)
            dependency_files.append(out / (name + '.d'))
        root_inputs = [Path(row['directory']) / 'manifest.json' for row in root_rows]
        root_objects = [Path(row['manifest']['objects']['O3']['path']) for row in root_rows]
        ret_directory = out / 'ret-shim/lift'
        ret_object = Path(ret['objects']['O3']['path'])
        compile_before = lift.snapshot([
            *producer_sources, *session.inputs, *backend_before, *dependency_files,
            *[item for name, item in tools.items() if name != 'sdk'], frozen, out / 'profile.json',
            out / 'app_config.h', out / 'native_image.h', out / 'native_imports.h',
            out / 'compiler/roots.json', Path(lookup['manifest_path']), *root_inputs, *root_objects,
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
        runtime.verify(lookup)
        record = dict(schema=1, runtime_lookup=lookup, status=STATUS, input_sha256=lift.sha(frozen), source_sha256=lift.sha(frozen),
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
                      scope='all caller PE roots and C3 shim lifted with selected CPU provider; six fresh host units with inline instruction search; no-argument ARM64 executable linked to selected real backend; not packaged or executed')
        lift.write(out / 'producer.json', record)
        return record
    except Exception as error:
        lift.write(out / 'failure.json', dict(status='BUILD_FAILED_NOT_EXECUTED', error=repr(error),
                   input_sha256=lift.sha(frozen), command_count=len(commands.records),
                   generated_layout_harness_executions=0, guest_executions=0, gpu_executions=0))
        raise
