"""Build an untimed same-address replay observer from an independently checked v7 product.

Only the diagnostic runtime and argument-taking host are compiled here. The
three backend objects and lifted main/WndProc/RET objects are explicit reused
inputs, never reported as newly lifted or as a new production App.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

from graphics_stage5.d3d11_probe import dependency_paths, environment
from window_lookup_v1 import review as baseline
from . import generate

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'build/window-outer-replay-v1'
STATUS = 'OUTER_REPLAY_DIAGNOSTICS_BUILT_NOT_EXECUTED_NOT_MEASURED'
HOST_SHA256 = '9b79aa34c0cfc6302f34d354b39d6bae9678b6b7efe6fe805ddbd7d072e04919'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write('\n')


def fresh(path):
    p = Path(path).absolute()
    need(p == p.resolve() and p.parent == BASE and not p.exists(),
         'fresh direct child of build/window-outer-replay-v1 required')
    BASE.mkdir(parents=True, exist_ok=True)
    return p


def identities(paths):
    return {str(Path(p).absolute()): sha(p) for p in sorted(set(map(str, paths)))}


def unchanged(values):
    need(identities(values) == values, 'immutable input changed')


def merge_inputs(inputs, addition):
    need(all(name not in inputs or inputs[name] == value for name, value in addition.items()),
         'previously observed input changed before compilation')
    inputs.update(addition)


def validate_host_storage(producer, verified):
    source = Path(producer['native_objects']['host']['source'])
    need(source == ROOT / 'window_bridge/window_host.c' and source.is_file() and
         not source.is_symlink() and sha(source) == HOST_SHA256 and
         verified['files'].get(str(source)) == HOST_SHA256,
         'fixed host-owned writable backing allocation source required for replay')


def command(out, records, argv, label, env):
    argv = list(map(str, argv))
    stem = out / 'commands' / ('%03d-' % (len(records) + 1) + label)
    proc = subprocess.run(argv, cwd=out, env=env, capture_output=True)
    stdout, stderr = Path(str(stem) + '.stdout'), Path(str(stem) + '.stderr')
    stdout.write_bytes(proc.stdout); stderr.write_bytes(proc.stderr)
    row = dict(argv=argv, cwd=str(out), env=env, returncode=proc.returncode,
               stdout=str(stdout), stderr=str(stderr),
               stdout_sha256=sha(stdout), stderr_sha256=sha(stderr), label=label)
    record = Path(str(stem) + '.json'); write(record, row)
    records.append(dict(path=str(record), sha256=sha(record)))
    need(proc.returncode == 0, 'command failed; see ' + str(record))
    return proc.stdout.decode()


def build(product, out):
    product = Path(product).resolve(strict=True)
    out = fresh(out)
    verified = baseline.review(product, sha(product / 'result.json'))
    need(verified['status'] == 'PASS_LOOKUP_V7_PRODUCT_INDEPENDENTLY_REVIEWED', 'baseline review failed')
    native = product / 'native'
    producer = json.loads((native / 'producer.json').read_bytes())
    validate_host_storage(producer, verified)
    need(producer['input_sha256'] == '39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8',
         'only the frozen switch window PE is admitted')
    out.mkdir(); (out / 'commands').mkdir(); (out / 'cache/dxmt').mkdir(parents=True)
    write(out / 'baseline-review.json', verified)
    records, inputs = [], dict(verified['files'])
    implementation = identities([Path(__file__), Path(generate.__file__),
                                 ROOT / 'window_outer_replay_v1/instrumentation.inc'])
    merge_inputs(inputs, implementation)
    env = environment(out)
    write(out / 'started.json', dict(status='STARTED_NOT_EXECUTED', product=str(product), implementation=implementation))
    try:
        tools, units = producer['tools'], producer['native_objects']
        command(out, records, [tools['clang'], '--version'], 'compiler-version', env)
        # Root source is unchanged; the production App's no-argument entry shim is omitted.
        host_flags = [x for x in units['host']['flags'] if x != '-Dmain=aot_window_main']
        host_source = Path(units['host']['source'])
        depfiles, generated, objects, runtime_ir = {}, {}, {}, {}

        def compile_unit(name, source, flags):
            text = command(out, records, [tools['clang'], *flags, '-M', '-MT', 'probe', source], name + '-deps', env)
            dep = out / (name + '.d'); dep.write_text(text)
            deps = dependency_paths(text)
            need(Path(source) in deps, 'compiler omitted actual source')
            merge_inputs(inputs, identities(deps)); inputs[str(dep)] = sha(dep)
            obj = out / (name + '.o')
            command(out, records, [tools['clang'], *flags, '-c', source, '-o', obj], name + '-compile', env)
            merge_inputs(inputs, identities([obj]))
            depfiles[name] = dict(path=str(dep), sha256=sha(dep), paths=list(map(str, deps)),
                                  source=str(source), flags=flags, object=str(obj), object_sha256=sha(obj))
            return obj

        host = compile_unit('host', host_source, host_flags)
        reused = [Path(units[n]['path']) for n in ('native-backend', 'window-backend', 'cocoa')]
        configurations = {}
        for strategy in ('reference', 'inline'):
            overlay = generate.prepare(out / ('source-' + strategy), strategy)
            generated[strategy] = overlay
            merge_inputs(inputs, identities([p for p in Path(overlay['source_root']).rglob('*') if p.is_file()]))
            source = Path(overlay['compile_source'])
            flags = [*units['runtime']['flags'], '-iquote', str(ROOT / 'window_bridge')]
            runtime = compile_unit('runtime-' + strategy, source, flags)
            ir = out / ('runtime-' + strategy + '.ll')
            command(out, records, [tools['clang'], *flags, '-S', '-emit-llvm', source, '-o', ir], strategy + '-runtime-ir', env)
            runtime_ir[strategy] = dict(path=str(ir), sha256=sha(ir))
            merge_inputs(inputs, identities([ir]))
            for optimization in ('O0', 'O3'):
                name = strategy + '-' + optimization
                lifted = [Path(r['manifest']['objects'][optimization]['path']) for r in producer['roots']]
                ret = Path(producer['ret_manifest']['objects'][optimization]['path'])
                linked_objects = [host, runtime, *reused, *lifted, ret]
                merge_inputs(inputs, identities([*reused, *lifted, ret]))
                executable = out / ('outer-' + name)
                backend = producer['backend']
                argv = [tools['clang++'], '-arch', 'arm64', '-isysroot', tools['sdk'],
                        '-mmacosx-version-min=' + producer['minimum_macos'], '--ld-path=' + tools['ld'],
                        '-Wl,-syslibroot,' + tools['sdk'], *linked_objects, backend['d3d11'], backend['winemetal'],
                        '-framework', 'Cocoa', '-framework', 'Metal', '-framework', 'QuartzCore',
                        *['-Wl,-rpath,' + d for d in sorted({str(Path(backend[k]).parent) for k in ('d3d11', 'dxgi', 'winemetal')})],
                        '-o', executable]
                command(out, records, argv, name + '-link', env)
                command(out, records, [tools['codesign'], '--force', '--sign', '-', '--timestamp=none', executable], name + '-sign', env)
                command(out, records, [tools['codesign'], '--verify', '--strict', executable], name + '-signature', env)
                merge_inputs(inputs, identities([executable]))
                configurations[name] = dict(strategy=strategy, guest_optimization=optimization,
                    runtime_optimization='O3', executable=str(executable), executable_sha256=sha(executable),
                    linked_objects=identities(linked_objects), root_objects=list(map(str, lifted)), ret_object=str(ret))
        for name, dep in depfiles.items():
            text = command(out, records, [tools['clang'], *dep['flags'], '-M', '-MT', 'probe', dep['source']], name + '-deps-after', env)
            need(text == Path(dep['path']).read_text(), 'dependency graph changed')
        unchanged(inputs)
        artifacts = identities([p for p in out.rglob('*') if p.is_file() and 'cache' not in p.relative_to(out).parts])
        result = dict(schema=1, status=STATUS, product=str(product), product_receipt_sha256=sha(product / 'result.json'),
            producer=str(native / 'producer.json'), producer_sha256=sha(native / 'producer.json'),
            baseline_review=str(out / 'baseline-review.json'), baseline_review_sha256=sha(out / 'baseline-review.json'),
            implementation=implementation, inputs=inputs, artifacts=artifacts, commands=records, tools=tools,
            generated=generated, dependencies=depfiles, runtime_ir=runtime_ir, configurations=configurations,
            native_executions=0, timing_enabled=False, replay_enabled=True, diagnostic_rounds=2, continuation_rounds=1,
            scope='Fresh observer runtime/argument-taking host; reused lifted roots/RET and three backend objects from independently reviewed product. Two diagnostic rounds then original-boundary continuation are compiled, not yet executed. No App packaging or performance claim.')
        write(out / 'build.json', result)
        return result
    except BaseException as e:
        write(out / 'failure.json', dict(status='FAILED_NOT_ACCEPTED', error=repr(e), commands=records))
        raise
