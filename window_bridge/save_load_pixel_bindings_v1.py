"""Independent pixel-observer link over the frozen save/load original PE.

Build/verify only. Reuse six objects from the NEW save/load Program and compile
three observation units against its exact copied headers. No old PE object or
runtime is used. Successful build is not a pixel/GUI/GPU execution result.
"""
import argparse
import json
from pathlib import Path
import shutil

from window_bridge import save_load_bindings_v1 as baseline
from window_bridge import pixel_bindings_v1 as pixel
from graphics_stage5 import d3d11_probe as g

ROOT, HERE = baseline.ROOT, baseline.HERE
SOURCE = ROOT / 'build/window-bridge/save-load-program-v1-01'
SOURCE_SHA = '7384ae558ceb05fb6761219a629f04c14138bdade45ad7a83deb02f42d0f4391'
PE_SHA = '0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976'
EXE_SHA = '9a404deef5f0ae807d12ded1d28915f6eea5c31f4935b808dff1da1f743b2609'
PIXEL_PRODUCER_SHA = 'a9936593408df7e1c189b800421f104aa3f9c4b2fcedbb29de8bfe5379e01a3c'
BASELINE_SHA = '8004785cf525d72de8f31463d5addb420ea2a005c47b741293246edbe4416aca'
OUT = ROOT / 'build/window-bridge/save-load-pixel-program-v1-02'
STATUS = 'BUILT_SAVE_LOAD_PIXEL_OBSERVER_NOT_EXECUTED'
SCOPE = dict.fromkeys(('guest_executions', 'window_executions', 'gpu_executions', 'library_loads', 'pixel_frames'), 0)
require, write, command = pixel.require, pixel.write, pixel.command


def output(path):
    p = Path(path).absolute()
    require(p == p.resolve() and p.parent == ROOT / 'build/window-bridge' and
            p.name.startswith('save-load-pixel-program-v1-'), 'new save-load-pixel-program-v1-* directory required')
    return p


def source_program():
    require(g.sha(SOURCE / 'program-build.json') == SOURCE_SHA and
            g.sha(baseline.__file__) == BASELINE_SHA and g.sha(pixel.__file__) == PIXEL_PRODUCER_SHA,
            'frozen normal/observer producer changed')
    p = baseline.Program.from_build(SOURCE)
    require(p.source_sha256 == PE_SHA and p.executable_sha256 == EXE_SHA and p.optimization == 'O3',
            'only frozen new save/load O3 Program is admitted')
    require(len(p.roots) == 2 and p.roots[0]['symbol'] == 'aot_entry' and
            p.roots[1]['symbol'] == 'aot_window_proc_1000', 'new guest roots differ')
    require(any(i['name'] == 'ReadFile' and i['signature'] == 6 and i['iat_rva'] == 0x2728
                for i in p.build_manifest['imports']), 'new ReadFile import absent')
    return p


def reused_objects(p):
    return {'runtime.o': p.out / 'window_runtime__runtime.c.o',
            'native-backend.o': p.out / 'native_backend.cpp.o', 'cocoa.o': p.out / 'cocoa_host.mm.o',
            'main.o': Path(p.roots[0]['directory']) / 'arm64.o',
            'wndproc.o': Path(p.roots[1]['directory']) / 'arm64.o', 'ret.o': p.out / 'ret-shim/arm64.o'}


def units(out, p):
    flags = {n: (compiler, list(f)) for n, compiler, f in p.compilation_units()}
    c, cf = flags['window_host.c']
    cpp, cppf = flags['native_backend_window.cpp']
    for f in (cf, cppf):
        require(f.count(str(p.out)) == 1, 'source include-directory recipe differs')
        f[f.index(str(p.out))] = str(out)
    return [('host', HERE / 'window_host_pixel_v1.c', c, cf),
            ('window', HERE / 'native_backend_window.cpp', cpp, [*cppf, pixel.observer.MACRO]),
            ('observer', HERE / 'pixel_observer_v1.cpp', cpp, cppf)]


def discover(out, p, writing=False):
    require(g.sha(baseline.__file__) == BASELINE_SHA and g.sha(pixel.__file__) == PIXEL_PRODUCER_SHA,
            'frozen reused Python helper differs')
    require((HERE / 'window_host_pixel_v1.c').read_text() == pixel.expected_host(), 'observer host delta differs')
    require(g.sha(pixel.observer.OUT / 'evidence.json') == pixel.OBSERVER_SHA, 'frozen observer receipt differs')
    obs = pixel.observer.verify()
    for n in ('native_image.h', 'native_imports.h'):
        require((out / n).read_bytes() == (p.out / n).read_bytes(), 'new save/load generated header substituted: ' + n)
    dependencies, graphs = [], {}
    for n, source, compiler, flags in units(out, p):
        args = [compiler, *flags, '-M', '-MT', 'probe', source]
        text = command(out, 'deps-' + n, args) if writing else g.invoke(args, g.environment(out))
        actual = g.dependency_paths(text)
        generated = [Path(x).resolve() for x in actual if Path(x).name in ('native_image.h', 'native_imports.h')]
        require(generated == ([out / 'native_image.h'] if n == 'host' else []),
                'actual observation compiler consumed wrong generated headers')
        path = out / (n + '.d')
        if writing:
            path.write_text(text)
        else:
            require(path.read_text() == text, 'actual compile dependencies changed')
        dependencies += [*actual, path]
        graphs[n] = text
    # The reused new runtime object was compiled with SOURCE/native_imports.h.
    # Program.verify_build regenerates it and checks that exact -M dependency,
    # and both its object and header are bound here to the fixed new PE receipt.
    paths = [*p.build_manifest['native_inputs'], *p.build_manifest['artifacts'], SOURCE / 'program-build.json',
             *obs['inputs_before'], *obs['artifacts'], pixel.observer.OUT / 'evidence.json',
             *baseline.python_closure([Path(__file__)]), *dependencies,
             out / 'native_image.h', out / 'native_imports.h']
    return g.hashes(paths), graphs


def link_plan(out, p):
    nodes = p.build_manifest['library_graph']['nodes']
    return list(map(str, [p.tools['clang++'], '-arch', 'arm64', '-isysroot', p.tools['sdk'],
        '--ld-path=' + p.tools['ld'], *[out / 'reused' / n for n in reused_objects(p)],
        *[out / (n + '.o') for n, _, _, _ in units(out, p)], p.build_manifest['library'],
        next(n for n in nodes if Path(n).name == 'winemetal.dylib'),
        '-framework', 'Cocoa', '-framework', 'Metal', '-framework', 'QuartzCore',
        *['-Wl,-rpath,' + n for n in sorted({str(Path(x).parent) for x in nodes})], '-o', out / 'linked-native']))


def plans(out, p):
    result = [('deps-' + n, list(map(str, [compiler, *flags, '-M', '-MT', 'probe', src])))
              for n, src, compiler, flags in units(out, p)]
    for n, src, compiler, flags in units(out, p):
        result += [('compile-' + n, list(map(str, [compiler, *flags, '-c', src, '-o', out / (n + '.o')]))),
                   ('exports-' + n, [p.tools['nm'], '-gU', str(out / (n + '.o'))])]
    return result + [('link', link_plan(out, p)),
        ('sign', [p.tools['codesign'], '--force', '--sign', '-', '--identifier', 'org.peaotlab.window.saveloadpixelv1', str(out / 'linked-native')]),
        ('signature', [p.tools['codesign'], '--verify', '--strict', str(out / 'linked-native')])]


def artifact_paths(out, p, exe):
    return [out / 'started.json', out / 'native_image.h', out / 'native_imports.h', out / 'linked-native', exe,
        *[out / 'reused' / n for n in reused_objects(p)],
        *[out / (n + '.o') for n, _, _, _ in units(out, p)],
        *[out / (n + '.d') for n, _, _, _ in units(out, p)],
        *[out / 'commands' / (n + '.json') for n, _ in plans(out, p)]]


def start_record():
    return {'schema': 1, 'status': 'BUILD_STARTED_NOT_EXECUTED', 'scope': SCOPE,
        'producer_sha256': g.sha(__file__), 'source_program': str(SOURCE), 'source_program_sha256': SOURCE_SHA,
        'pe_sha256': PE_SHA, 'observer_producer_sha256': PIXEL_PRODUCER_SHA,
        'observer_receipt_sha256': pixel.OBSERVER_SHA}


class Program:
    validate_execution = pixel.Program.validate_execution
    validate_capture = pixel.Program.validate_capture

    def __init__(self, out_dir=OUT):
        self.out = output(out_dir)
        require(not self.out.exists(), 'preserve previous build; choose fresh directory')
        self.out.mkdir(parents=True)
        write(self.out / 'started.json', start_record())
        try:
            self.original = p = source_program()
            for n in ('native_image.h', 'native_imports.h'):
                shutil.copy2(p.out / n, self.out / n)
            before, graphs = discover(self.out, p, True)
            (self.out / 'reused').mkdir()
            for n, source in reused_objects(p).items():
                shutil.copy2(source, self.out / 'reused' / n)
                require(g.sha(source) == g.sha(self.out / 'reused' / n), 'reused new object copy differs')
            for n, src, compiler, flags in units(self.out, p):
                command(self.out, 'compile-' + n, [compiler, *flags, '-c', src, '-o', self.out / (n + '.o')])
                pixel.observer.arm_object(self.out / (n + '.o'))
                exports = command(self.out, 'exports-' + n, [p.tools['nm'], '-gU', self.out / (n + '.o')])
                require(pixel.observer.symbols(exports) == pixel.expected_exports(n), 'observation exports differ')
            link_inputs = g.hashes([*[self.out / 'reused' / n for n in reused_objects(p)],
                                   *[self.out / (n + '.o') for n, _, _, _ in units(self.out, p)]])
            for n, args in plans(self.out, p)[-3:]:
                command(self.out, n, args)
            self.executable_sha256 = g.sha(self.out / 'linked-native')
            self.executable = self.out / ('save-load-pixel-' + self.executable_sha256)
            shutil.copy2(self.out / 'linked-native', self.executable)
            graph = g.library_graph(self.executable, self.executable)
            require(set(graph['nodes']) == {str(self.executable), *p.build_manifest['library_graph']['nodes']}, 'native library graph differs')
            after, after_graphs = discover(self.out, p)
            p.verify_build()
            g.same(link_inputs)
            require(before == after and graphs == after_graphs, 'build input changed')
            self.build_manifest = {'schema': 1, 'status': STATUS, 'scope': SCOPE,
                'source_program': str(SOURCE), 'source_program_sha256': SOURCE_SHA, 'input_sha256': PE_SHA,
                'native_executable': str(self.executable), 'native_sha256': self.executable_sha256,
                'tools': p.tools, 'inputs_before': before, 'inputs_after': after, 'dependency_graphs': graphs,
                'reused_objects': {n: {'source': str(src), 'sha256': g.sha(src)} for n, src in reused_objects(p).items()},
                'link_inputs': link_inputs, 'library_graph': graph,
                'commands': [{'name': n, 'path': str(self.out / 'commands' / (n + '.json')),
                              'sha256': g.sha(self.out / 'commands' / (n + '.json'))} for n, _ in plans(self.out, p)],
                'artifacts': g.hashes(artifact_paths(self.out, p, self.executable)),
                'observer_profile': 'save-load-pixel-observer-v1; readback before original Present, unchanged guest rules/data',
                'pixels_verified': False, 'performance_sample': False}
            write(self.out / 'program-build.json', self.build_manifest)
            self.verify_build()
        except Exception as error:
            write(self.out / 'first-build-failure.json', {'status': 'FAIL_BUILD_NOT_EXECUTED', 'error': repr(error), 'scope': SCOPE})
            raise

    @classmethod
    def from_build(cls, out_dir=OUT):
        self = cls.__new__(cls)
        self.out = output(out_dir)
        self.original = source_program()
        self.build_manifest = g.read_json(self.out / 'program-build.json')
        self.executable = Path(self.build_manifest['native_executable'])
        self.executable_sha256 = self.build_manifest['native_sha256']
        self.verify_build()
        return self

    def verify_build(self):
        p, r = self.original, g.read_json(self.out / 'program-build.json')
        require(set(r) == {'schema', 'status', 'scope', 'source_program', 'source_program_sha256', 'input_sha256',
                'native_executable', 'native_sha256', 'tools', 'inputs_before', 'inputs_after', 'dependency_graphs',
                'reused_objects', 'link_inputs', 'library_graph', 'commands', 'artifacts', 'observer_profile',
                'pixels_verified', 'performance_sample'}, 'manifest field closure differs')
        require(r['observer_profile'] == 'save-load-pixel-observer-v1; readback before original Present, unchanged guest rules/data',
                'observer profile claim differs')
        require(r == self.build_manifest and type(r['schema']) is int and r['schema'] == 1 and
                r['status'] == STATUS and r['scope'] == SCOPE and all(type(v) is int for v in r['scope'].values()), 'build status/scope differs')
        require(g.read_json(self.out / 'started.json') == start_record(), 'immutable build start differs')
        require(r['source_program'] == str(SOURCE) and r['source_program_sha256'] == SOURCE_SHA and r['input_sha256'] == PE_SHA,
                'new source PE binding differs')
        p.verify_build()
        current, graphs = discover(self.out, p)
        require(r['inputs_before'] == r['inputs_after'] == current and r['dependency_graphs'] == graphs and r['tools'] == p.tools,
                'source/header/tool closure differs')
        expected = {n: {'source': str(src), 'sha256': g.sha(src)} for n, src in reused_objects(p).items()}
        require(r['reused_objects'] == expected and all(g.sha(self.out / 'reused' / n) == v['sha256'] for n, v in expected.items()),
                'new runtime/guest/native object source changed or omitted')
        require(r['link_inputs'] == g.hashes([*[self.out / 'reused' / n for n in reused_objects(p)],
                *[self.out / (n + '.o') for n, _, _, _ in units(self.out, p)]]), 'link input closure differs')
        require(self.executable == self.out / ('save-load-pixel-' + self.executable_sha256) and
                g.sha(self.executable) == self.executable_sha256 == g.sha(self.out / 'linked-native'), 'immutable executable differs')
        require(r['artifacts'] == g.hashes(artifact_paths(self.out, p, self.executable)), 'artifact set omitted/changed')
        commands = []
        for n, args in plans(self.out, p):
            path = self.out / 'commands' / (n + '.json')
            detail = g.read_json(path)
            require(set(detail) == {'command', 'returncode', 'stdout', 'stderr'} and detail['command'] == args and
                    type(detail['returncode']) is int and detail['returncode'] == 0, 'actual command differs')
            commands.append({'name': n, 'path': str(path), 'sha256': g.sha(path)})
        require(r['commands'] == commands, 'command closure differs')
        for n, _, _, _ in units(self.out, p):
            pixel.observer.arm_object(self.out / (n + '.o'))
            actual = g.invoke([p.tools['nm'], '-gU', self.out / (n + '.o')], g.environment(self.out))
            require(pixel.observer.symbols(actual) == pixel.expected_exports(n), 'object exports differ')
        graph = g.library_graph(self.executable, self.executable)
        require(graph == r['library_graph'] and set(graph['nodes']) == {str(self.executable), *p.build_manifest['library_graph']['nodes']},
                'actual native image graph differs')
        g.invoke([p.tools['codesign'], '--verify', '--strict', self.executable], g.environment(self.out))
        require(r['pixels_verified'] is False and r['performance_sample'] is False,
                'build receipt must not claim pixel/performance acceptance')
        return r


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=OUT)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    program = Program.from_build(args.out) if args.verify else Program(args.out)
    print(json.dumps({'status': program.build_manifest['status'], 'program': str(program.out),
        'executable': str(program.executable), 'executable_sha256': program.executable_sha256,
        'scope': SCOPE}, indent=2))
