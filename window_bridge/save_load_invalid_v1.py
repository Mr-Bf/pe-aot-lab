"""Six malformed files: read-only acceptance by default; --run explicitly starts PE.

Each file is seeded once in its own new directory. No guest memory is installed,
no shared roundtrip save is touched, and an expected guest ExitProcess(32) is a
business rejection, not successful gameplay. GUI/GPU creation must remain zero.
"""
import argparse
import hashlib
import json
import re
import stat
import struct
import sys
import traceback
from pathlib import Path

from window_bridge import save_load_bindings_v1 as binding

PROGRAM = binding.ROOT / 'build/window-bridge/save-load-program-v1-01'
DEFAULT_OUT = binding.ROOT / 'build/window-bridge/save-load-run-invalid-v1-01'
PE_SHA = '0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976'
BUDGET, TIMEOUT_MS = 1000000, 45000
MAGIC = 0x31574F43
INITIAL = struct.pack('<5I', MAGIC, 1, 3, 0, 0)
CASES = (
    ('empty', b'', 1),
    ('prefix19', INITIAL[:19], 1),
    ('extra21', INITIAL + b'\0', 2),
    ('bad-magic', struct.pack('<5I', MAGIC ^ 1, 1, 3, 0, 0), 3),
    ('bad-version', struct.pack('<5I', MAGIC, 2, 3, 0, 0), 4),
    ('position8', struct.pack('<5I', MAGIC, 1, 8, 0, 0), 5),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular artifact required: ' + str(path))
    return path.read_bytes()


def load(path):
    return binding.graphics.strict_json(read(path).decode())


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def file_identity(path):
    value = read(path)
    info = Path(path).stat()
    require(stat.S_ISREG(info.st_mode), 'not a regular file')
    return {'sha256': digest(value), 'size': len(value), 'data_hex': value.hex(),
            'device': info.st_dev, 'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns,
            'mode': stat.S_IMODE(info.st_mode)}


def source_inputs():
    return binding.snapshot([Path(__file__).resolve(), Path(binding.__file__).resolve(),
                             Path(sys.executable).resolve()])


def check_profile(program_dir):
    """Called only after the frozen producer has checked the complete build."""
    build = load(program_dir / 'program-build.json')
    main = load(program_dir / 'compiler/main/manifest.json')
    require(build['input_sha256'] == PE_SHA and
            build['status'] == 'BUILT_NATIVE_SAVE_LOAD_WINDOW_PE_NOT_EXECUTED', 'wrong PE/producer')
    reads = [i for i in build['imports'] if i['dll'] == 'kernel32.dll' and i['name'] == 'ReadFile']
    require(len(reads) == 1 and reads[0]['signature'] == 6 and reads[0]['iat_rva'] == 0x2728,
            'new ReadFile binding differs')
    require(main['profile'] == {
        'virtual_slots': sorted(binding.lifter.VIRTUAL_SLOTS),
        'new_scalar_shapes': ['CMOVNB reg32,reg32 with defined CF',
            'SETZ AL/SIL/DIL with defined ZF',
            'non-LOCK INC m32 [RIP+disp32] or [GPR64+0] excluding RSP/index; preserving CF definedness',
            'SETNZ CL/DL/SIL with defined ZF', 'AND8 AL,CL/DL opcode20 only',
            'TEST16 AX,AX only', 'exact observed 15/12/10-byte CS-prefixed NOP padding only']},
        'new finite save/load profile differs')


def semantic_acceptance(record, before, after, case_name):
    """Pure record semantics; authentication is performed separately by verify()."""
    matches = [(raw, reason) for name, raw, reason in CASES if name == case_name]
    require(len(matches) == 1, 'unknown case')
    expected, reason = matches[0]
    require(type(before) is bytes and before == expected and after == before, 'file bytes changed/wrong fixture')
    r = record['result']
    require(r['pe_sha256'] == PE_SHA and r['proc_translated'] == 0 and r['entry_arguments'] == 0,
            'original native translated PE identity differs')
    require(record['returncode'] == 0 and record['external_timeout'] is False and
            r['outcome'] == 'PROCESS_EXITED' and r['exit_requested'] == 1 and r['exit_code'] == 32 and
            r['fault']['status'] == 0 and not r['timed_out'] and 0 < r['steps'] < BUDGET,
            'expected clean guest business rejection ExitProcess(32) absent')
    require(record['test_sequence'] is None, 'invalid files must not use an input sequence')
    q = r['test_queue']
    require(q == {'events': [], 'injection_error': 0, 'observed_hwnd': 0, 'posted': 0, 'requested': 0},
            'unexpected injected input/window')
    obs = r['observations']
    require(bytes.fromhex(obs['window_state']) == INITIAL, 'failed candidate committed into game state')
    expected_result = [0] * 15
    expected_result[0], expected_result[1], expected_result[11] = 1, 32, 13
    require(bytes.fromhex(obs['window_result']) == struct.pack('<15I', *expected_result),
            'guest result/error/stage or side effects differ')
    count, extra = min(len(before), 20), max(0, len(before) - 20)
    load_expected = [1, 0, 0, 1, count, extra, 13, reason, 0]
    require(bytes.fromhex(obs['window_load_result']) == struct.pack('<9I', *load_expected),
            'load validation order/count/errors/close differs')
    require(bytes.fromhex(obs['window_load_candidate']) == before[:20].ljust(20, b'\0'),
            'candidate differs from actual bytes read')
    require(bytes.fromhex(obs['window_load_count']) == struct.pack('<I', count) and
            bytes.fromhex(obs['window_load_extra_count']) == struct.pack('<I', extra) and
            bytes.fromhex(obs['window_load_extra']) == b'\0', 'read/EOF outputs differ')
    for name, size in (('window_handle', 8), ('window_instance', 8), ('window_feature', 4),
                       ('window_client', 16), ('window_message', 48)):
        require(bytes.fromhex(obs[name]) == bytes(size), 'pre-window output changed: ' + name)
    saved = r['saved_file']
    require(saved['name'] == 'integer-tile.bin' and saved['errno'] == 0 and saved['truncated'] is False
            and saved['data_hex'] == before.hex(), 'host disk observation differs from unchanged input')
    files = r['files']
    expected_calls = [1, 0, 1 if len(before) < 20 else 2, 1, 0, 0]
    require(files['api_calls_4_to_9'] == expected_calls and files['bytes_read'] == len(before)
            and files['bytes_written'] == 0, 'actual file calls/transfer sizes differ')
    require(all(files[k] == 0 for k in ('open_before_cleanup', 'open_after_cleanup',
            'cleanup_closes', 'cleanup_errors')), 'file leak/cleanup masked guest Close')
    # The PE writes validation error 13 into its own observation; it never calls
    # SetLastError. This fixed OPEN_EXISTING + successful Read/Close profile keeps 0.
    require(files['last_error'] == 0, 'file LastError was confused with guest validation error')
    d = r['d3d_before_cleanup']
    require(d['exit_calls'] == 1 and all(v == 0 for k, v in d.items() if k != 'exit_calls'),
            'graphics object/API/cleanup occurred before rejected load')
    require(d == r['d3d_after_cleanup'] and r['d3d_cleanup_result'] == 0,
            'graphics cleanup changed empty session')
    for host in (r['host_before_finish'], r['host_after_finish']):
        for key in ('windows_created', 'windows_destroyed', 'views_created', 'views_released',
                    'active_views', 'forced_cleanup_windows', 'test_queue_events', 'cocoa_key_events',
                    'close_requests', 'resize_events', 'queue_overflows', 'quit_messages'):
            require(host[key] == 0, 'unexpected host window/input/cleanup: ' + key)
    u = r['user32_stats']
    require(all(v == 0 for k, v in u.items() if k != 'api_calls') and
            u['api_calls'] == [0] * 14, 'User32 activity before validation rejection')
    require(all(v == 0 for v in r['callback_stats'].values()), 'guest callback activity before rejection')
    return {'case': case_name, 'input_size': len(before), 'validation_error': reason,
            'load_observations': load_expected, 'file_api_calls': expected_calls,
            'bytes_read': len(before), 'bytes_written': 0, 'file_last_error': 0,
            'guest_observation_error': 13, 'guest_exit_code': 32, 'host_returncode': 0,
            'steps': r['steps'], 'window_creations': 0, 'graphics_creations': 0,
            'unchanged_file_sha256': digest(before)}


def case_artifacts(directory):
    paths = [directory / n for n in ('input-before.bin', 'saved-after.bin', 'before.json', 'after.json',
             'run.json', 'run.started.json', 'run.stdout', 'run.stderr')]
    history = directory / 'history'
    require(history.is_dir() and not history.is_symlink(), 'missing producer initial receipt history')
    historical = list(history.iterdir())
    require(len(historical) == 1, 'exact initial producer history required')
    old = load(historical[0])
    initial = load(directory / 'run.started.json')
    require(old == {**initial, 'started_path': str(directory / 'run.started.json'),
                    'started_sha256': binding.sha(directory / 'run.started.json')}, 'initial producer history differs')
    require(historical[0].name == 'run.json.' + binding.sha(historical[0]) + '.json', 'history content filename differs')
    return paths + historical + [directory / 'data/integer-tile.bin']


def start_record(directory, program, inputs):
    return {'schema': 1, 'status': 'STARTED_NOT_ACCEPTED', 'program': str(program),
            'program_build_sha256': binding.sha(program / 'program-build.json'),
            'pe_sha256': PE_SHA, 'inputs_before': inputs, 'budget': BUDGET, 'timeout_ms': TIMEOUT_MS,
            'test_sequence': None, 'cases': [{'name': n, 'input_hex': v.hex(), 'validation_error': e}
                                          for n, v, e in CASES],
            'output_directory': str(directory), 'scope': 'six private seeded malformed files; original PE alone reads them; no GUI/GPU acceptance'}


def verify(directory):
    """Read-only validation of already completed six cases and exact identities."""
    directory = Path(directory).resolve()
    start = load(directory / 'started.json')
    observed = load(directory / 'observed.json')
    inputs = source_inputs()
    program = Path(start['program'])
    require(program == PROGRAM, 'closed Program directory differs')
    require(start == start_record(directory, program, inputs), 'immutable driver inputs/contract differ')
    require(load(directory / 'attempt.json') == {'status': 'PREFLIGHT_NOT_EXECUTED', 'inputs_before': inputs},
            'attempt differs')
    required = [directory / 'started.json', directory / 'attempt.json', directory / 'observed.json']
    for name, _, _ in CASES:
        required += case_artifacts(directory / name) + [directory / name / 'observed.json']
        required += [Path(p) for p in load(directory / name / 'run.json')['inputs_before']]
    before_identity = binding.snapshot(required)
    summaries, pids = [], []
    for name, expected, _ in CASES:
        case = directory / name
        require(case.is_dir() and not case.is_symlink(), 'real case directory required')
        require({p.name for p in case.iterdir()} == {'input-before.bin', 'saved-after.bin', 'before.json',
                'after.json', 'observed.json', 'run.json', 'run.started.json', 'run.stdout', 'run.stderr', 'history', 'data'},
                'case artifact set differs')
        require((case / 'data').is_dir() and not (case / 'data').is_symlink() and
                {p.name for p in (case / 'data').iterdir()} == {'integer-tile.bin'}, 'private data set differs')
        before, after = read(case / 'input-before.bin'), read(case / 'saved-after.bin')
        require(before == expected, 'case seed differs')
        identity = file_identity(case / 'data/integer-tile.bin')
        require(load(case / 'before.json') == load(case / 'after.json') == identity,
                'file changed since original private seed')
        require(identity['data_hex'] == before.hex(), 'before metadata bytes differ')
        record = binding.verify_run(case / 'run.json')
        check_profile(Path(record['program_out']))
        require(record['program_out'] == str(PROGRAM) and record['data_directory'] == str(case / 'data')
                and record['requested_base'] is None and record['requested_budget'] == BUDGET
                and record['timeout_ms'] == TIMEOUT_MS and record['test_sequence'] is None,
                'actual program/parameters differ')
        require(record['stdout_path'] == str(case / 'run.stdout') and record['stderr_path'] == str(case / 'run.stderr'),
                'actual stream location differs')
        require(type(record['pid']) is int and record['pid'] > 0, 'invalid actual PID')
        require(set(map(int, re.findall(r'^dyld\[(\d+)\]:', read(case / 'run.stderr').decode(), re.M))) == {record['pid']},
                'actual child/dyld identity differs')
        summary = semantic_acceptance(record, before, after, name)
        receipt = {'summary': summary, 'pid': record['pid'], 'artifacts': binding.snapshot(case_artifacts(case))}
        require(load(case / 'observed.json') == receipt, 'case receipt/artifact closure differs')
        summaries.append(receipt)
        pids.append(record['pid'])
    require(len(set(pids)) == 6, 'six distinct actual children required')
    require({p.name for p in directory.iterdir()} == {'attempt.json', 'started.json', 'observed.json'} |
            {n for n, _, _ in CASES}, 'batch artifact set differs')
    require(observed == {'status': 'SIX_INVALID_FILES_OBSERVED_NOT_FINAL_ACCEPTANCE',
        'started_sha256': binding.sha(directory / 'started.json'), 'inputs_after': inputs,
        'cases': summaries, 'new_guest_executions': 6}, 'batch summary differs')
    require(binding.snapshot(required) == before_identity and source_inputs() == inputs, 'verification input changed')
    return {'status': 'PASS_SIX_MALFORMED_SAVE_REJECTIONS', 'cases': [x['summary'] for x in summaries],
            'pids': pids, 'existing_guest_executions': 6, 'new_guest_executions': 0,
            'new_gui_executions': 0, 'new_gpu_executions': 0, 'inputs': inputs, 'artifacts': before_identity,
            'scope': 'original PE rejects malformed disk input before creating any window/graphics objects; host exit0 is not gameplay success'}


def run(directory):
    """Explicit runner: six sequential native processes, no input injection."""
    directory = Path(directory).resolve()
    binding.output_directory(directory)
    directory.mkdir(parents=True, exist_ok=False)
    inputs, completed = source_inputs(), []
    write(directory / 'attempt.json', {'status': 'PREFLIGHT_NOT_EXECUTED', 'inputs_before': inputs})
    try:
        program = binding.Program.from_build(PROGRAM)
        check_profile(PROGRAM)
        write(directory / 'started.json', start_record(directory, PROGRAM, inputs))
        for name, raw, _ in CASES:
            require(source_inputs() == inputs, 'driver changed before launch')
            case = directory / name
            case.mkdir()
            data = case / 'data'
            data.mkdir()
            save = data / 'integer-tile.bin'
            for path in (save, case / 'input-before.bin'):
                with path.open('xb') as stream:
                    stream.write(raw)
            before = file_identity(save)
            write(case / 'before.json', before)
            program.run(io_directory=data, budget=BUDGET, timeout_ms=TIMEOUT_MS,
                        test_sequence=None, log_path=case / 'run.json')
            # Preserve actual after bytes even if the semantic test rejects them.
            after = read(save)
            with (case / 'saved-after.bin').open('xb') as stream:
                stream.write(after)
            write(case / 'after.json', file_identity(save))
            record = binding.verify_run(case / 'run.json')
            summary = semantic_acceptance(record, raw, after, name)
            require(file_identity(save) == before, 'original file modified despite rejection')
            require(source_inputs() == inputs, 'driver changed during launch')
            receipt = {'summary': summary, 'pid': record['pid'], 'artifacts': binding.snapshot(case_artifacts(case))}
            write(case / 'observed.json', receipt)
            completed.append(receipt)
            print(json.dumps(summary), flush=True)
        write(directory / 'observed.json', {'status': 'SIX_INVALID_FILES_OBSERVED_NOT_FINAL_ACCEPTANCE',
              'started_sha256': binding.sha(directory / 'started.json'), 'inputs_after': source_inputs(),
              'cases': completed, 'new_guest_executions': 6})
        return verify(directory)
    except Exception as error:
        write(directory / 'failure.json', {'status': 'FAIL_PRESERVED', 'error': str(error),
              'traceback': traceback.format_exc(), 'completed_cases': completed,
              'inputs_after': source_inputs(), 'scope': 'failed attempt is not accepted execution evidence'})
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    parser.add_argument('--run', action='store_true', help='explicitly start six original-PE native processes')
    args = parser.parse_args()
    print(json.dumps(run(args.out) if args.run else verify(args.out), indent=2, sort_keys=True))
