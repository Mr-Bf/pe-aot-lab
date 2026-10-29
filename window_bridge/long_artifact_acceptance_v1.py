"""Additional read-only authentication for completed long/smoke observations.

No launch code. Consume exact receipt and artifact bytes, then rerun the frozen
source/build/launch checks and pure timing/game semantics. A running process is
NOT_READY, never PASS. This is not hostile-host attestation or a new execution.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import sys

from window_bridge import long_run_v1 as original
from window_bridge import long_run_bindings_v1 as producer
from window_bridge import long_validation_v1 as validation


class NotReady(ValueError):
    pass


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded_bytes(path, limit=64 * 1024 * 1024):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'bounded regular artifact required: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        require(len(raw) == info.st_size and len(raw) <= limit, 'artifact size changed during read: ' + str(path))
        return raw
    finally:
        os.close(fd)


def parse(raw):
    return original.g.strict_json(raw.decode())


def authenticate_artifacts(mapping):
    """The bytes hashed here are exactly the bytes returned to the parsers."""
    require(type(mapping) is dict and mapping, 'nonempty receipt artifacts required')
    captured = {}
    for name, expected in mapping.items():
        require(type(name) is str and type(expected) is str and len(expected) == 64, 'artifact identity type')
        path = Path(name)
        require(path.is_absolute() and path == path.resolve(), 'canonical artifact path required')
        raw = bounded_bytes(path, 4 * 1024 * 1024)
        require(digest(raw) == expected, 'captured bytes differ from receipt: ' + name)
        captured[name] = raw
    return captured


def accept(directory):
    directory = Path(directory).absolute()
    require(directory == directory.resolve() and directory.is_dir(), 'real run directory required')
    receipt_path = directory / 'evidence.json'
    if not receipt_path.exists():
        raise NotReady('final evidence.json absent; started/launched or live process is not completion')
    receipt_bytes = bounded_bytes(receipt_path)
    record = parse(receipt_bytes)
    require(record.get('status') in (original.SMOKE_STATUS, original.FORMAL_STATUS), 'final exact mode is not accepted')
    capture = authenticate_artifacts(record['artifacts'])
    required = {str(directory / n) for n in ('started.json', 'attempt.json', 'launched.json', 'run.stdout',
                                              'run.stderr', 'data/integer-tile.bin')}
    start_path = str(directory / 'started.json')
    require(start_path in capture, 'receipt omits immutable start')
    start = parse(capture[start_path])
    before = None if start['before_hex'] is None else bytes.fromhex(start['before_hex'])
    if before is not None:
        required.add(str(directory / 'initial-save.bin'))
    require(set(capture) == required, 'exact completed run artifact set differs')
    if before is not None:
        require(capture[str(directory / 'initial-save.bin')] == before and len(before) == 20,
                'initial bytes differ from immutable start')
    else:
        require(not (directory / 'initial-save.bin').exists(), 'unexpected historical initial save')
    raw_result = parse(capture[str(directory / 'run.stdout')])
    require(raw_result == record['result'], 'receipt result differs from exact authenticated stdout bytes')
    require(digest(capture[start_path]) == record['started_sha256'], 'start digest differs')
    require(record['inputs_after'] == start['inputs_before'], 'producer inputs changed')
    source_paths = [Path(__file__).resolve(), Path(original.__file__).resolve(), Path(producer.__file__).resolve(),
                    Path(validation.__file__).resolve(), Path(sys.executable).resolve()]
    review_sources = original.g.hashes(source_paths)
    # This also checks actual command, launched PID, source/object/library
    # identities, dyld PID and complete trace. It never launches the guest.
    old = original.verify(directory)
    require(bounded_bytes(receipt_path) == receipt_bytes, 'receipt changed during original verification')
    program = producer.Program.from_build(start['program'])
    require(start == original.expected_start(directory, program, start['duration_ms'], start['smoke'], before),
            'captured immutable command/environment/source contract differs')
    require(parse(capture[str(directory / 'attempt.json')]) == {'status': 'PREFLIGHT_NOT_EXECUTED',
        'driver_sha256': original.g.sha(original.__file__), 'program': str(program.out),
        'smoke': start['smoke'], 'duration_ms': start['duration_ms']}, 'captured attempt differs')
    stderr = capture[str(directory / 'run.stderr')].decode()
    loaded = original.g.loaded_images(stderr, program.executable, program.build_manifest['library_graph']['nodes'])
    require(loaded == record['loaded_images'] and
            set(map(int, re.findall(r'^dyld\[(\d+)\]:', stderr, re.M))) == {record['pid']},
            'captured actual library/PID announcements differ')
    clock = raw_result['long_run']
    require(type(record['supervisor_begin_ns']) is int and type(record['supervisor_end_ns']) is int and
            0 < record['supervisor_begin_ns'] <= clock['start_ns'] <= clock['finish_ns'] <= record['supervisor_end_ns']
            and record['supervisor_end_ns'] - record['supervisor_begin_ns'] <= start['external_timeout_seconds'] * 1000000000,
            'captured same-clock native/supervisor interval differs')
    timing = program.validate_execution(raw_result, record['returncode'], None, start['budget'])
    sequence = [event['name'] for event in raw_result['test_queue']['events']]
    gameplay = validation.semantic_acceptance_long(
        {'result': raw_result, 'returncode': record['returncode'], 'test_sequence': sequence, 'external_timeout': False},
        before, capture[str(directory / 'data/integer-tile.bin')])
    require(timing == record['timing'] == old['timing'] and gameplay == record['gameplay'] == old['gameplay'],
            'authenticated in-memory timing/gameplay differs from original accepted record')
    smoke = start['smoke']
    require(type(smoke) is bool, 'explicit smoke mode required')
    expected = original.SMOKE_STATUS if smoke else original.FORMAL_STATUS
    require(record['status'] == old['status'] == expected, 'smoke/formal mode cannot be relabeled')
    launched = parse(capture[str(directory / 'launched.json')])
    require(launched == {'status': 'PROCESS_LAUNCHED_NOT_ACCEPTED', 'pid': record['pid'],
        'supervisor_begin_ns': record['supervisor_begin_ns'], 'started_sha256': record['started_sha256'],
        'external_timeout_seconds': start['external_timeout_seconds']}, 'captured launched identity differs')
    require(type(record['pid']) is int and record['pid'] > 0 and record['external_timeout'] is False,
            'actual process identity/timeout differs')
    # Bind the otherwise informational pre-acceptance observation as well.
    observation_path = directory / 'observed.json'
    observation_bytes = bounded_bytes(observation_path)
    require(parse(observation_bytes) == {**record, 'status': 'OBSERVED_NOT_ACCEPTED'},
            'immutable observation differs from final accepted record')
    for name, raw in capture.items():
        require(bounded_bytes(name, 4 * 1024 * 1024) == raw and digest(raw) == record['artifacts'][name],
                'authenticated artifact changed during review: ' + name)
    require(bounded_bytes(receipt_path) == receipt_bytes and bounded_bytes(observation_path) == observation_bytes,
            'receipt/observation changed during review')
    original.g.same(start['inputs_before'])
    require(original.g.hashes(source_paths) == review_sources, 'reviewer or validators changed during review')
    input_map = json.dumps(start['inputs_before'], sort_keys=True, separators=(',', ':')).encode()
    return {'status': 'PASS_READONLY_AUTHENTICATED_SMOKE_BYTES' if smoke else 'PASS_READONLY_AUTHENTICATED_FORMAL_BYTES',
            'existing_status': expected, 'run_directory': str(directory), 'pid': record['pid'],
            'receipt_sha256': digest(receipt_bytes), 'observation_sha256': digest(observation_bytes),
            'artifacts': {name: digest(raw) for name, raw in capture.items()},
            'producer_inputs_count': len(start['inputs_before']), 'producer_input_map_sha256': digest(input_map),
            'review_sources': review_sources, 'timing': timing, 'gameplay': gameplay,
            'existing_guest_executions': 1, 'new_guest_executions': 0, 'new_gui_executions': 0, 'new_gpu_executions': 0,
            'scope': 'same completed native process; exact in-memory raw bytes bound to frozen receipt before pure validation and after; trusted local host, no new execution/performance/pixel/physical-input claim'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-directory', type=Path, required=True)
    parser.add_argument('--out', type=Path, help='exclusive new review JSON; never changes the actual run directory')
    args = parser.parse_args()
    try:
        verdict = accept(args.run_directory)
    except NotReady as error:
        print(json.dumps({'status': 'NOT_READY', 'reason': str(error), 'new_guest_executions': 0}))
        raise SystemExit(2)
    if args.out is not None:
        out = args.out.absolute()
        run = args.run_directory.resolve()
        require(out == out.resolve() and not out.is_relative_to(run), 'review output must be outside the frozen run')
        with out.open('x') as stream:
            json.dump(verdict, stream, indent=2, sort_keys=True)
            stream.write('\n')
    print(json.dumps({k: verdict[k] for k in ('status', 'pid', 'receipt_sha256', 'existing_guest_executions', 'new_guest_executions')}))
