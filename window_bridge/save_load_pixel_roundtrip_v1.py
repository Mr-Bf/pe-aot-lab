"""Two-process save/load + actual backbuffer observation; default is read-only.

Only --run launches. Both starts use one original PE and shared disk save, with
separate capture directories. No host rendering, state restoration or save-file
rewrite occurs. Synchronous observer captures are not performance samples.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import traceback

from window_bridge import save_load_pixel_bindings_v1 as producer
from window_bridge import save_load_bindings_v1 as binding
from window_bridge import save_load_acceptance_v1 as semantic
from window_bridge import save_load_pixels_v1 as pixels

SEQUENCE = semantic.SEQUENCE
BUDGET, TIMEOUT_MS = 1000000, 45000
STATUS = 'PASS_SAME_PE_TWO_PROCESS_SAVE_RESTORE_AND_PIXELS'
OBSERVED = 'TWO_PIXEL_SAVE_LOAD_PHASES_OBSERVED_NOT_ACCEPTED'
DEFAULT_OUT = binding.ROOT / 'build/window-bridge/save-load-pixel-run-v1-01'


def require(value, message):
    if not value:
        raise ValueError(message)


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular evidence file required: ' + str(path))
    return path.read_bytes()


def read(path):
    return binding.graphics.strict_json(regular(path).decode())


def bytes_write(path, value):
    with Path(path).open('xb') as stream:
        stream.write(value)


def output(path):
    path = Path(path).absolute()
    require(path == path.resolve() and path.parent == binding.ROOT / 'build/window-bridge'
            and path.name.startswith('save-load-pixel-run-v1-'), 'fresh direct save-load-pixel-run-v1-* directory required')
    return path


def identities(program):
    return {**program.build_manifest['inputs_before'], **program.build_manifest['artifacts'],
            **binding.snapshot([program.out / 'program-build.json', *binding.python_closure([Path(__file__)])])}


def command(program, out, index):
    return [str(program.executable), '--data-dir', str(out / 'data'), '--pixel-dir', str(out / f'phase-{index}/pixels'),
            '--budget', str(BUDGET), '--timeout-ms', str(TIMEOUT_MS), '--test-sequence', ','.join(SEQUENCE)]


def before_description(value):
    return {'name': 'integer-tile.bin', 'exists': value is not None,
            'sha256': None if value is None else hashlib.sha256(value).hexdigest(),
            'data_hex': None if value is None else value.hex(), 'size': None if value is None else len(value)}


def live_data(out, exists):
    data = out / 'data'
    require(data.is_dir() and not data.is_symlink() and
            {p.name for p in data.iterdir()} == ({'integer-tile.bin'} if exists else set()), 'shared save set differs')
    return regular(data / 'integer-tile.bin') if exists else None


def start_record(out, program):
    return {'schema': 1, 'status': 'STARTED_NOT_ACCEPTED', 'program': str(program.out),
            'program_build_sha256': binding.sha(program.out / 'program-build.json'),
            'pe_sha256': producer.PE_SHA, 'driver_sha256': binding.sha(__file__),
            'inputs_before': identities(program), 'data_directory': str(out / 'data'),
            'initial_data_files': [], 'sequence': SEQUENCE, 'budget': BUDGET, 'timeout_ms': TIMEOUT_MS,
            'environment': binding.graphics.environment(out, images=True),
            'scope': 'same original save/load PE; two real processes, shared original file, separate native backbuffer captures; TEST_QUEUE not OS input; no performance claim'}


def phase_start(out, program, index, before):
    return {'schema': 1, 'status': 'PHASE_STARTED_NOT_ACCEPTED', 'phase': index,
            'coordinator_started_sha256': binding.sha(out / 'started.json'),
            'command': command(program, out, index), 'environment': binding.graphics.environment(out, images=True),
            'inputs_before': identities(program), 'initial_pixel_files': [],
            'before_record_sha256': binding.sha(out / f'phase-{index}/before.json'),
            'before_sha256': before_description(before)['sha256'], 'external_timeout_seconds': 60}


def phase_files(out, index, before, capture):
    phase = out / f'phase-{index}'
    paths = [phase / n for n in ('run.started.json', 'before.json', 'saved-after.bin', 'run.stdout', 'run.stderr')]
    if before is not None:
        paths.append(phase / 'input-before.bin')
    return {**binding.snapshot(paths), **capture['artifacts']}


def actual_phase(out, program, index, record, before, after):
    """Authenticate raw process/capture then apply independent semantic/pixel predicates."""
    phase = out / f'phase-{index}'
    require(read(phase / 'run.started.json') == phase_start(out, program, index, before), 'immutable phase inputs differ')
    before_meta = read(phase / 'before.json')
    require(type(before_meta.get('exists')) is bool and before_meta == before_description(before), 'historical before metadata differs')
    require((phase / 'input-before.bin').exists() == (before is not None), 'before file presence differs')
    if before is not None:
        require(regular(phase / 'input-before.bin') == before, 'historical before data differs')
    require(regular(phase / 'saved-after.bin') == after, 'historical after data differs')
    require(type(record['pid']) is int and record['pid'] > 0 and type(record['returncode']) is int
            and record['returncode'] == 0 and record['external_timeout'] is False, 'actual child did not exit normally')
    stdout, stderr = regular(phase / 'run.stdout').decode(), regular(phase / 'run.stderr').decode()
    result = binding.graphics.strict_json(stdout)
    normal = program.validate_execution(result, record['returncode'], None, BUDGET)
    require(normal is not None, 'host setup failure')
    gameplay = semantic.semantic_acceptance({'result': normal, 'returncode': record['returncode'],
        'external_timeout': False, 'test_sequence': SEQUENCE}, before, after)
    capture = program.validate_capture(result, phase / 'pixels')
    loaded = binding.graphics.loaded_images(stderr, program.executable, program.build_manifest['library_graph']['nodes'])
    require(set(map(int, re.findall(r'^dyld\[(\d+)\]:', stderr, re.M))) == {record['pid']}, 'actual dyld PID differs')
    picture = pixels.inspect_frames(phase / 'pixels', capture['frames'], SEQUENCE, before)
    return {'result': result, 'gameplay': gameplay, 'capture': capture, 'pixels': picture, 'loaded_images': loaded,
            'artifacts': phase_files(out, index, before, capture)}


def summary(index, record, before, after):
    picture = record['pixels']
    return {'phase': index, 'pid': record['pid'], 'run_sha256': record['_run_sha256'],
            'before_sha256': before_description(before)['sha256'], 'after_sha256': hashlib.sha256(after).hexdigest(),
            'initial_position': record['gameplay']['initial_position'], 'position': record['gameplay']['position'],
            'moves': record['gameplay']['moves'], 'persisted_draws': record['gameplay']['persisted_draws'],
            'frames': record['capture']['frames'], 'position_transitions': picture['observed_position_transitions'],
            'checked_pixels': picture['checked_pixels'], 'checked_channels': picture['checked_channels'],
            'max_channel_error': max(f['max_channel_error'] for f in picture['frames'])}


def verify(out, candidate=None):
    out = output(out)
    receipt = read(out / 'evidence.json') if candidate is None else candidate
    expected_status = STATUS if candidate is None else OBSERVED
    require(set(receipt) == {'schema', 'status', 'started_sha256', 'phases', 'inputs_after', 'artifacts', 'guest_executions'}
            and type(receipt['schema']) is int and receipt['schema'] == 1 and receipt['status'] == expected_status,
            'batch status/schema differs')
    require(read(out / 'observed.json') == {**receipt, 'status': OBSERVED}, 'immutable batch observation differs')
    start = read(out / 'started.json')
    program = producer.Program.from_build(start['program'])
    inputs = identities(program)
    require(start == start_record(out, program), 'batch input contract differs')
    require(read(out / 'attempt.json') == {'status': 'PREFLIGHT_NOT_EXECUTED', 'driver_sha256': binding.sha(__file__)}, 'attempt source differs')
    require(receipt['started_sha256'] == binding.sha(out / 'started.json'), 'batch start identity differs')
    binding.unchanged(inputs)
    all_artifacts = binding.snapshot([out / 'attempt.json', out / 'started.json', out / 'data/integer-tile.bin'])
    previous, summaries = None, []
    for index in (1, 2):
        phase = out / f'phase-{index}'
        require(phase.is_dir() and not phase.is_symlink(), 'real phase directory required')
        before = None if index == 1 else regular(phase / 'input-before.bin')
        require(before == previous, 'phase 2 input is not phase 1 original saved bytes')
        after = regular(phase / 'saved-after.bin')
        record = read(phase / 'run.json')
        require(set(record) == {'schema', 'status', 'phase', 'started_sha256', 'pid', 'returncode', 'external_timeout',
                'result', 'gameplay', 'capture', 'pixels', 'loaded_images', 'artifacts', 'inputs_after'} and
                type(record['schema']) is int and record['schema'] == 1 and record['status'] == 'PIXEL_PHASE_OBSERVED_NOT_ACCEPTED'
                and type(record['phase']) is int and record['phase'] == index
                and record['started_sha256'] == binding.sha(phase / 'run.started.json'), 'phase receipt differs')
        actual = actual_phase(out, program, index, record, before, after)
        require(all(record[k] == v for k, v in actual.items()) and record['inputs_after'] == inputs,
                'record differs from actual raw/capture/input closure')
        require(actual['pixels']['status'] == 'PASS_FULL_RGBA_RESTORED_SCENE', 'full restored scene mismatch')
        allowed = {'run.started.json', 'run.json', 'before.json', 'saved-after.bin', 'run.stdout', 'run.stderr', 'pixels'}
        if before is not None:
            allowed.add('input-before.bin')
        require({p.name for p in phase.iterdir()} == allowed, 'phase artifact set differs')
        all_artifacts.update(actual['artifacts'])
        all_artifacts.update(binding.snapshot([phase / 'run.json']))
        summaries.append(summary(index, {**record, '_run_sha256': binding.sha(phase / 'run.json')}, before, after))
        previous = after
    require(len({x['pid'] for x in summaries}) == 2, 'two actual child identities required')
    require([(x['initial_position'], x['position'], x['moves']) for x in summaries] == [(3, 4, 3), (4, 5, 6)],
            'two-process movement/restoration differs')
    require(live_data(out, True) == previous, 'final shared file differs from second original PE save')
    require(type(receipt['guest_executions']) is int and receipt['guest_executions'] == 2
            and receipt['phases'] == summaries and receipt['inputs_after'] == inputs and receipt['artifacts'] == all_artifacts,
            'batch exact summary/artifact/input closure differs')
    required_top = {'attempt.json', 'started.json', 'observed.json', 'data', 'phase-1', 'phase-2'}
    if candidate is None:
        required_top.add('evidence.json')
    if (out / 'cache').exists():
        require((out / 'cache').is_dir() and not (out / 'cache').is_symlink(), 'native cache must be a real directory')
        required_top.add('cache')  # Explicit non-semantic native cache; never used as pixel/save evidence.
    require({p.name for p in out.iterdir()} == required_top, 'batch artifact namespace differs')
    program.verify_build()
    binding.unchanged(all_artifacts)
    binding.unchanged(inputs)
    return {'status': STATUS, 'original_pe_sha256': producer.PE_SHA, 'phases': summaries,
            'existing_guest_executions': 2, 'new_guest_executions': 0, 'new_gui_executions': 0, 'new_gpu_executions': 0,
            'performance_sample': False, 'scope': 'two actual new-PE processes with full native backbuffer RGBA, original save restoration; not old seven-frame evidence, compositor or physical keyboard'}


def run(out, program_directory):
    out = output(out)
    out.mkdir(parents=True, exist_ok=False)
    write(out / 'attempt.json', {'status': 'PREFLIGHT_NOT_EXECUTED', 'driver_sha256': binding.sha(__file__)})
    completed, active = [], None
    try:
        program = producer.Program.from_build(program_directory)
        data = out / 'data'
        data.mkdir()
        require(live_data(out, False) is None, 'initial save must not exist')
        write(out / 'started.json', start_record(out, program))
        inputs = identities(program)
        previous = None
        for index in (1, 2):
            phase = out / f'phase-{index}'
            phase.mkdir()
            (phase / 'pixels').mkdir()
            before = live_data(out, index == 2)
            require(before == previous, 'shared file changed between processes')
            write(phase / 'before.json', before_description(before))
            if before is not None:
                bytes_write(phase / 'input-before.bin', before)
            program.verify_build()
            binding.unchanged(inputs)
            write(phase / 'run.started.json', phase_start(out, program, index, before))
            active = {'schema': 1, 'status': 'PHASE_STARTED_NOT_ACCEPTED', 'phase': index,
                      'started_sha256': binding.sha(phase / 'run.started.json')}
            child = subprocess.Popen(command(program, out, index), env=binding.graphics.environment(out, images=True),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            active['pid'] = child.pid
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
            bytes_write(phase / 'run.stdout', stdout)
            bytes_write(phase / 'run.stderr', stderr)
            active.update(returncode=child.returncode, external_timeout=timeout)
            require(not timeout, 'external supervision is not successful guest exit')
            after = live_data(out, True)
            bytes_write(phase / 'saved-after.bin', after)
            actual = actual_phase(out, program, index, active, before, after)
            active.update(actual)
            active.update(status='PIXEL_PHASE_OBSERVED_NOT_ACCEPTED', inputs_after=identities(program))
            require(active['inputs_after'] == inputs, 'run source/tool/object identities changed')
            write(phase / 'run.json', active)
            require(actual['pixels']['status'] == 'PASS_FULL_RGBA_RESTORED_SCENE', 'full RGBA mismatch; raw frames preserved')
            binding.unchanged(inputs)
            completed.append(summary(index, {**active, '_run_sha256': binding.sha(phase / 'run.json')}, before, after))
            previous = after
            print(json.dumps(completed[-1]), flush=True)
        artifacts = binding.snapshot([out / 'attempt.json', out / 'started.json', out / 'data/integer-tile.bin'])
        for index in (1, 2):
            rec = read(out / f'phase-{index}/run.json')
            artifacts.update(rec['artifacts'])
            artifacts.update(binding.snapshot([out / f'phase-{index}/run.json']))
        observed = {'schema': 1, 'status': OBSERVED, 'started_sha256': binding.sha(out / 'started.json'),
                    'phases': completed, 'inputs_after': identities(program), 'artifacts': artifacts, 'guest_executions': 2}
        write(out / 'observed.json', observed)
        accepted = verify(out, observed)
        write(out / 'evidence.json', {**observed, 'status': STATUS})
        return accepted
    except Exception as error:
        paths = [p for p in out.rglob('*') if p.is_file() and not p.is_symlink() and 'cache' not in p.relative_to(out).parts]
        write(out / 'failure.json', {'status': 'FAIL_PRESERVED', 'error': repr(error), 'traceback': traceback.format_exc(),
              'completed_phases': completed, 'active_phase': active, 'preserved_artifacts': binding.snapshot(paths)})
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--program', type=Path, default=producer.OUT)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    print(json.dumps(run(args.out, args.program) if args.run else verify(args.out), indent=2, ensure_ascii=False))
