"""Supervise two starts of one relocated save/load App; default is read-only.

Only --run launches native code. The coordinator never rewrites the shared
save or installs restored state in guest memory. Immutable per-phase records
retain historical bytes after the second guest replaces the live file.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from window_bridge import app_v2 as package
from window_bridge import save_load_bindings_v1 as binding
from window_bridge import save_load_acceptance_v1 as acceptance

SEQUENCE = ['right', 'right-repeat', 'right-up', 'right', 'right-up', 'left', 'left-up', 'escape']
BUDGET = 1000000
TIMEOUT_MS = 45000
STATUS = 'PASS_RELOCATED_APP_TWO_PROCESS_SAVE_RESTORE'
OBSERVED = 'TWO_APP_STARTS_OBSERVED_NOT_ACCEPTED'
SCOPE = ('two direct starts of the same relocated App and original save/load PE; '
         'shared original disk save, TEST_QUEUE, no host restoration; '
         'no Finder/LaunchServices/physical-key/pixel/performance claim')


def require(value, reason):
    if not value:
        raise ValueError(reason)


def write(path, record):
    with Path(path).open('x') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')


def write_bytes(path, data):
    with Path(path).open('xb') as stream:
        stream.write(data)


def regular(path, maximum=64 * 1024 * 1024):
    """Trusted-local observation; reject FIFO/symlink without a blocking read."""
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum,
                'bounded regular artifact required: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(maximum + 1)
        require(len(data) == info.st_size and len(data) <= maximum, 'artifact changed during read')
        return data
    finally:
        os.close(fd)


def read(path):
    return binding.graphics.strict_json(regular(path).decode())


def output(path):
    path = Path(path).absolute()
    require(path == path.resolve() and path.parent == binding.ROOT / 'build/window-bridge'
            and path.name.startswith('window-run-app-v2-'),
            'new window-run-app-v2-* output directory required')
    return path


def environment(out):
    env = binding.graphics.environment(out, images=True)
    env['PATH'] = '/nonexistent'
    return env


def command(app, data):
    return [str(package.executable(app)), '--data-dir', str(data), '--budget', str(BUDGET),
            '--timeout-ms', str(TIMEOUT_MS), '--test-sequence', ','.join(SEQUENCE)]


def input_identity(package_directory, receipt, app):
    paths = [*receipt['inputs_before'], *receipt['artifacts'],
             package_directory / 'evidence.json',
             *binding.python_closure([Path(__file__)]),
             *(Path(receipt['app']) / p for p in receipt['app_tree']),
             *(app / p for p in receipt['app_tree'])]
    return binding.snapshot(paths)


def check_app(receipt, app, program):
    require(app == app.resolve() and app.is_relative_to('/private/tmp')
            and app.name == 'PE AOT Integer Tile V2.app'
            and app.parent.name == 'relocation with spaces'
            and app.parent.parent.name.startswith('pe-aot-save-load-v2-'),
            'expected real /private/tmp spaced App copy required')
    require(package.tree(app) == receipt['app_tree'], 'whole App bytes/modes changed')
    graph = package.package_graph(app)
    require(package.normalized_graph(graph, app) == receipt['normalized_graph'],
            'copied App dependency graph differs')
    copied = {}
    for source, destination in package.mapping_for(program, app).items():
        original = package.section_identity(source)
        require(original == package.section_identity(destination), 'original code/data sections changed')
        copied[str(destination.relative_to(app))] = original
    require(copied == {p: v['section_identity'] for p, v in receipt['copied_code'].items()},
            'section identity differs from package receipt')
    # These subprocesses inspect signatures; they do not load the App code.
    binding.graphics.invoke([package.tools()['codesign'], '--verify', '--deep', '--strict', str(app)],
                            environment(app.parent))
    return graph


def before_description(value):
    return {'name': 'integer-tile.bin', 'exists': value is not None,
            'sha256': None if value is None else hashlib.sha256(value).hexdigest(),
            'data_hex': None if value is None else value.hex(),
            'size': None if value is None else len(value)}


def data_bytes(data, expected_present):
    require(data.is_dir() and not data.is_symlink(), 'real shared data directory required')
    require({p.name for p in data.iterdir()} == ({'integer-tile.bin'} if expected_present else set()),
            'shared data file set differs')
    return regular(data / 'integer-tile.bin', 4096) if expected_present else None


def phase_start(index, out, start, before):
    phase = out / f'phase-{index}'
    return {'schema': 1, 'status': 'STARTED_NOT_ACCEPTED', 'phase': index,
            'coordinator_started_sha256': binding.sha(out / 'started.json'),
            'command': command(Path(start['relocated_app']), out / 'data'),
            'environment': environment(out), 'inputs_before': start['inputs_before'],
            'before_sha256': before_description(before)['sha256'],
            'before_record_sha256': binding.sha(phase / 'before.json'),
            'test_sequence': SEQUENCE, 'budget': BUDGET, 'timeout_ms': TIMEOUT_MS,
            'external_timeout_seconds': 60, 'stdout_path': str(phase / 'run.stdout'),
            'stderr_path': str(phase / 'run.stderr')}


def phase_artifacts(phase, before):
    paths = [phase / n for n in ('before.json', 'run.started.json', 'run.stdout', 'run.stderr', 'saved-after.bin')]
    if before is not None:
        paths.append(phase / 'input-before.bin')
    return paths


def validate_phase(index, out, start, record, before, after, program, graph):
    phase = out / f'phase-{index}'
    expected_start = phase_start(index, out, start, before)
    require(read(phase / 'run.started.json') == expected_start, 'phase immutable start differs')
    require(set(record) == {'schema', 'status', 'phase', 'started_sha256', 'pid', 'returncode',
            'external_timeout', 'result', 'loaded_images', 'semantic', 'inputs_after', 'artifacts',
            'app_tree_after'}, 'phase record field closure differs')
    require(type(record['schema']) is int and record['schema'] == 1
            and record['status'] == 'APP_PHASE_OBSERVED_NOT_ACCEPTED'
            and type(record['phase']) is int
            and record['phase'] == index and record['started_sha256'] == binding.sha(phase / 'run.started.json'),
            'phase record identity differs')
    require(type(record['pid']) is int and record['pid'] > 0 and
            type(record['returncode']) is int and record['returncode'] == 0 and
            record['external_timeout'] is False, 'App child did not exit cleanly')
    require(read(phase / 'before.json') == before_description(before)
            and type(read(phase / 'before.json')['exists']) is bool, 'before metadata differs')
    require((phase / 'input-before.bin').exists() == (before is not None), 'before artifact existence differs')
    if before is not None:
        require(regular(phase / 'input-before.bin', 4096) == before, 'historical before bytes differ')
    require(regular(phase / 'saved-after.bin', 4096) == after, 'historical after bytes differ')
    streams = {name: regular(phase / name).decode() for name in ('run.stdout', 'run.stderr')}
    result = binding.graphics.strict_json(streams['run.stdout'])
    require(result == record['result'], 'phase result differs from actual stdout')
    program.validate_execution(result, record['returncode'], None, BUDGET)
    loaded = binding.graphics.loaded_images(streams['run.stderr'], package.executable(Path(start['relocated_app'])), graph['nodes'])
    require(loaded == record['loaded_images'], 'actual cumulative dyld image identities differ')
    require(set(map(int, re.findall(r'^dyld\[(\d+)\]:', streams['run.stderr'], re.M))) == {record['pid']},
            'dyld image announcements do not belong to actual child PID')
    semantic = acceptance.semantic_acceptance({'result': result, 'test_sequence': SEQUENCE,
        'returncode': record['returncode'], 'external_timeout': record['external_timeout']}, before, after)
    require(semantic == record['semantic'], 'phase semantic summary differs')
    require(record['inputs_after'] == start['inputs_before'], 'phase input identity changed')
    require(record['artifacts'] == binding.snapshot(phase_artifacts(phase, before)),
            'phase immutable artifact closure differs')
    require(record['app_tree_after'] == start['app_tree'], 'App changed across child execution')
    return {'phase': index, 'pid': record['pid'], 'before_sha256': before_description(before)['sha256'],
            'after_sha256': hashlib.sha256(after).hexdigest(), 'semantic': semantic,
            'run_sha256': binding.sha(phase / 'run.json') if (phase / 'run.json').exists() else None}


def setup_context(out, start):
    package_directory = Path(start['package_directory'])
    require(package_directory == package_directory.resolve(), 'aliased package directory')
    package.verify(package_directory)
    receipt = read(package_directory / 'evidence.json')
    require(binding.sha(package_directory / 'evidence.json') == start['package_sha256'], 'package receipt changed')
    program = package.source_program()
    app = Path(start['relocated_app'])
    graph = check_app(receipt, app, program)
    identities = input_identity(package_directory, receipt, app)
    expected = {'schema': 1, 'status': 'STARTED_NOT_ACCEPTED', 'driver_sha256': binding.sha(__file__),
        'acceptance_sha256': binding.sha(acceptance.__file__), 'package_directory': str(package_directory),
        'package_sha256': binding.sha(package_directory / 'evidence.json'), 'program': str(package.SOURCE_BUILD),
        'program_build_sha256': package.SOURCE_RECEIPT_SHA, 'original_pe_sha256': package.PE_SHA,
        'relocated_app': str(app), 'app_tree': receipt['app_tree'], 'data_directory': str(out / 'data'),
        'initial_data_files': [], 'command': command(app, out / 'data'), 'environment': environment(out),
        'sequence': SEQUENCE, 'budget': BUDGET, 'timeout_ms': TIMEOUT_MS, 'external_timeout_seconds': 60,
        'inputs_before': identities, 'scope': SCOPE}
    require(start == expected, 'coordinator source/setup/complete input identity differs')
    return receipt, program, app, graph


def verify(out, candidate=None):
    """Read actual records only; never calls run/Popen or changes the disk save."""
    out = output(out)
    record = read(out / 'evidence.json') if candidate is None else candidate
    require(record['status'] == (STATUS if candidate is None else OBSERVED), 'two-process run is not ready')
    require(set(record) == {'schema', 'status', 'started_sha256', 'phases', 'guest_executions',
            'artifacts', 'inputs_after', 'app_tree_after'}, 'final record field closure differs')
    require(type(record['schema']) is int and record['schema'] == 1
            and record['started_sha256'] == binding.sha(out / 'started.json'),
            'coordinator identity differs')
    require(read(out / 'observed.json') == {**record, 'status': OBSERVED},
            'immutable pre-acceptance observation differs')
    start = read(out / 'started.json')
    require(read(out / 'attempt.json') == {'status': 'PREFLIGHT_NOT_EXECUTED', 'driver_sha256': binding.sha(__file__)},
            'attempt identity differs')
    receipt, program, app, graph = setup_context(out, start)
    binding.unchanged(start['inputs_before'])
    required = [out / 'attempt.json', out / 'started.json', out / 'data/integer-tile.bin']
    summaries = []
    previous = None
    for index in (1, 2):
        phase = out / f'phase-{index}'
        require(phase.is_dir() and not phase.is_symlink(), 'real phase directory required')
        before = None if index == 1 else regular(phase / 'input-before.bin', 4096)
        require(before == previous, 'phase 2 did not receive phase 1 original save bytes')
        after = regular(phase / 'saved-after.bin', 4096)
        paths = [*phase_artifacts(phase, before), phase / 'run.json']
        require({p.name for p in phase.iterdir()} == {p.name for p in paths}, 'phase artifact set differs')
        item = validate_phase(index, out, start, read(phase / 'run.json'), before, after, program, graph)
        summaries.append(item)
        required += paths
        previous = after
    require(len({p['pid'] for p in summaries}) == 2, 'two distinct actual child processes required')
    require(data_bytes(out / 'data', True) == previous, 'final shared disk is not phase 2 actual save')
    require([(s['semantic']['position'], s['semantic']['moves']) for s in summaries] == [(4, 3), (5, 6)],
            'fixed two-process progression differs')
    require(record['phases'] == summaries and record['guest_executions'] == 2
            and type(record['guest_executions']) is int, 'phase count/summary differs')
    require(record['artifacts'] == binding.snapshot(required), 'complete execution artifact closure differs')
    require(record['inputs_after'] == start['inputs_before'], 'final input identities changed')
    require(record['app_tree_after'] == start['app_tree'] == package.tree(app), 'final whole App tree changed')
    check_app(receipt, app, program)
    binding.unchanged(record['artifacts'])
    binding.unchanged(start['inputs_before'])
    return {'status': STATUS, 'original_pe_sha256': package.PE_SHA, 'phases': summaries,
            'existing_guest_executions': 2, 'new_guest_executions': 0, 'new_gpu_executions': 0,
            'runtime_requires_python': False, 'runtime_requires_rosetta': False,
            'launchservices_tested': False, 'finder_no_arguments_ready': False, 'scope': SCOPE}


def child_run(args, env, phase):
    """Bounded own-child supervision; preserve raw streams even on failure."""
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    timeout = False
    try:
        stdout, stderr = child.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        timeout = True
        child.terminate()
        try:
            stdout, stderr = child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate(timeout=3)
    write_bytes(phase / 'run.stdout', stdout)
    write_bytes(phase / 'run.stderr', stderr)
    return {'pid': child.pid, 'returncode': child.returncode, 'external_timeout': timeout}


def run(package_directory, out):
    out = output(out)
    out.mkdir(parents=True, exist_ok=False)
    write(out / 'attempt.json', {'status': 'PREFLIGHT_NOT_EXECUTED', 'driver_sha256': binding.sha(__file__)})
    completed = []
    active = None
    try:
        package_directory = Path(package_directory).resolve()
        package.verify(package_directory)
        receipt = read(package_directory / 'evidence.json')
        program = package.source_program()
        temporary = Path(tempfile.mkdtemp(prefix='pe-aot-save-load-v2-', dir='/private/tmp'))
        app = temporary / 'relocation with spaces/PE AOT Integer Tile V2.app'
        app.parent.mkdir()
        shutil.copytree(receipt['app'], app)
        graph = check_app(receipt, app, program)
        data = out / 'data'
        data.mkdir()
        data_bytes(data, False)
        start = {'schema': 1, 'status': 'STARTED_NOT_ACCEPTED', 'driver_sha256': binding.sha(__file__),
            'acceptance_sha256': binding.sha(acceptance.__file__), 'package_directory': str(package_directory),
            'package_sha256': binding.sha(package_directory / 'evidence.json'), 'program': str(package.SOURCE_BUILD),
            'program_build_sha256': package.SOURCE_RECEIPT_SHA, 'original_pe_sha256': package.PE_SHA,
            'relocated_app': str(app), 'app_tree': receipt['app_tree'], 'data_directory': str(data),
            'initial_data_files': [], 'command': command(app, data), 'environment': environment(out),
            'sequence': SEQUENCE, 'budget': BUDGET, 'timeout_ms': TIMEOUT_MS, 'external_timeout_seconds': 60,
            'inputs_before': input_identity(package_directory, receipt, app), 'scope': SCOPE}
        write(out / 'started.json', start)
        previous = None
        for index in (1, 2):
            phase = out / f'phase-{index}'
            phase.mkdir()
            active = {'phase': index, 'status': 'PREFLIGHT_NOT_EXECUTED'}
            before = data_bytes(data, index == 2)
            require(before == previous, 'shared file changed between original-PE starts')
            if before is not None:
                write_bytes(phase / 'input-before.bin', before)
            write(phase / 'before.json', before_description(before))
            check_app(receipt, app, program)
            binding.unchanged(start['inputs_before'])
            write(phase / 'run.started.json', phase_start(index, out, start, before))
            active = {'schema': 1, 'status': 'APP_PHASE_STARTED_NOT_ACCEPTED', 'phase': index,
                      'started_sha256': binding.sha(phase / 'run.started.json')}
            active.update(child_run(start['command'], start['environment'], phase))
            require(active['external_timeout'] is False, 'external 60-second supervision expired')
            after = data_bytes(data, True)
            write_bytes(phase / 'saved-after.bin', after)
            result = binding.graphics.strict_json(regular(phase / 'run.stdout').decode())
            program.validate_execution(result, active['returncode'], None, BUDGET)
            stderr = regular(phase / 'run.stderr').decode()
            loaded = binding.graphics.loaded_images(stderr, package.executable(app), graph['nodes'])
            semantic = acceptance.semantic_acceptance({'result': result, 'test_sequence': SEQUENCE,
                'returncode': active['returncode'], 'external_timeout': active['external_timeout']}, before, after)
            check_app(receipt, app, program)
            binding.unchanged(start['inputs_before'])
            active.update(status='APP_PHASE_OBSERVED_NOT_ACCEPTED', result=result, loaded_images=loaded,
                          semantic=semantic, inputs_after=binding.snapshot(start['inputs_before']),
                          artifacts=binding.snapshot(phase_artifacts(phase, before)), app_tree_after=package.tree(app))
            # Validate full raw/identity/semantic evidence before the next start.
            validate_phase(index, out, start, active, before, after, program, graph)
            write(phase / 'run.json', active)
            summary = validate_phase(index, out, start, active, before, after, program, graph)
            completed.append(summary)
            previous = after
            print(json.dumps(summary, ensure_ascii=False), flush=True)
        artifacts = [out / 'attempt.json', out / 'started.json', data / 'integer-tile.bin']
        for index in (1, 2):
            artifacts += list((out / f'phase-{index}').iterdir())
        record = {'schema': 1, 'status': OBSERVED, 'started_sha256': binding.sha(out / 'started.json'),
                  'phases': completed, 'guest_executions': 2, 'artifacts': binding.snapshot(artifacts),
                  'inputs_after': binding.snapshot(start['inputs_before']), 'app_tree_after': package.tree(app)}
        write(out / 'observed.json', record)
        validated = verify(out, record)
        record['status'] = STATUS
        write(out / 'evidence.json', record)
        print(json.dumps(validated, ensure_ascii=False), flush=True)
        return validated
    except Exception as error:
        preserved = [p for p in out.rglob('*')
                     if p.is_file() and not p.is_symlink() and 'cache' not in p.relative_to(out).parts]
        write(out / 'failure.json', {'status': 'FAIL_PRESERVED', 'error': repr(error),
              'completed_phases': completed, 'active_phase': active,
              'preserved_artifacts': binding.snapshot(preserved)})
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, default=package.OUT)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if args.run:
        run(args.package, args.out)
    else:
        print(json.dumps(verify(args.out), ensure_ascii=False))
