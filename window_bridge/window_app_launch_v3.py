"""Observe one no-argument LaunchServices start. Only --run launches the App.

No keyboard injection, TCC request, save mutation or gameplay acceptance. A
durable launched.json means a live exact-path/start-time target is registered
with kqueue and its entry UUID is authenticated. External control may then act.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from window_bridge import app_v3 as package
from window_bridge import save_load_bindings_v1 as binding
from window_bridge import kqueue_exit_v1 as exit_observer

ROOT = binding.ROOT
OUT = ROOT / 'build/window-bridge/window-run-app-v3-ls-01'
APP_ID = 'org.peaotlab.IntegerTileV3'
PACKAGE_SHA = '40ae38f932b3b27115a396338fdf5c1bc716604874c7b86883897926de9e2ec8'
WATCH_SHA = '79334be51f819811ffbef56657f56fdf2278c778eeb98fe81051784a8f3246b9'
OBSERVED = 'LAUNCHSERVICES_OBSERVED_NOT_ACCEPTED'
MAX_STREAM = 4 * 1024 * 1024
BUDGET = 100000000
SCOPE = ('one no-argument LaunchServices observation of the fixed save/load PE; '
         'no injected events, TCC requests, default-save mutation or semantic acceptance')


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    return binding.sha(path)


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def bytes_exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def metadata(info):
    return {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode),
            'uid': info.st_uid, 'gid': info.st_gid, 'links': info.st_nlink,
            'size': info.st_size, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def regular(path, cap=MAX_STREAM):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= cap, 'bounded regular file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and len(raw) <= cap and
                metadata(before) == metadata(after), 'file changed during bounded observation')
        return raw
    finally:
        os.close(fd)


def read(path):
    return binding.graphics.strict_json(regular(path).decode())


def growing_stream(path):
    """Read a bounded prefix while dyld may append; final evidence uses regular()."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_STREAM, 'bounded growing stream required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_STREAM + 1)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino) and
                len(raw) <= MAX_STREAM and after.st_size <= MAX_STREAM, 'growing stream replaced/oversized')
        return raw
    finally:
        os.close(fd)


def output(path):
    path = Path(path).absolute()
    require(path == path.resolve() and path.parent == ROOT / 'build/window-bridge' and
            path.name.startswith('window-run-app-v3-ls-'), 'new window-run-app-v3-ls-* directory required')
    return path


def environment(out):
    return binding.graphics.environment(out)


def open_command(app, out):
    return ['/usr/bin/open', '--arch', 'arm64', '-n', '-W', '--stdout', str(out / 'app.stdout'),
            '--stderr', str(out / 'app.stderr'), '--env', 'PATH=/nonexistent',
            '--env', 'DYLD_PRINT_LIBRARIES=1', str(app)]


def query(helper, args, log=None):
    cmd = [str(helper), *map(str, args)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    record = {'command': cmd, 'returncode': result.returncode, 'stdout': result.stdout,
              'stderr': result.stderr, 'at_monotonic_ns': time.monotonic_ns()}
    if log is not None:
        with Path(log).open('a') as stream:
            stream.write(json.dumps(record, sort_keys=True) + '\n')
            stream.flush()
    require(result.returncode == 0 and not result.stderr, 'read-only identity/location query failed')
    return binding.graphics.strict_json(result.stdout)


def helper_plans(out):
    source = ROOT / 'window_bridge/noarg_launch_probe_v1.mm'
    tools = read(package.SOURCE_BUILD / 'program-build.json')['tools']
    flags = ['-arch', 'arm64', '-isysroot', tools['sdk'], '-std=c++17', '-O2',
             '-fno-objc-arc', '-Wall', '-Wextra', '-Werror']
    helper = out / 'location-process-probe'
    commands = [('dependencies', [tools['clang'], *flags, '-M', '-MT', 'probe', str(source)]),
                ('compile', [tools['clang'], *flags, str(source), '-framework', 'Foundation', '-lc++', '-o', str(helper)])]
    return source, tools, helper, commands


def helper_build(out):
    source, tools, helper, commands = helper_plans(out)
    records = {}
    before = None
    for name, command in commands:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=60)
        records[name] = {'command': command, 'returncode': proc.returncode,
                         'stdout': proc.stdout, 'stderr': proc.stderr}
        write(out / ('helper-' + name + '.json'), records[name])
        require(proc.returncode == 0, 'query helper compilation failed')
        if name == 'dependencies':
            deps = binding.graphics.dependency_paths(proc.stdout)
            before = binding.snapshot([source, *deps, tools['clang'], tools['ld'], '/usr/bin/xcrun'])
    deps = binding.graphics.dependency_paths(records['dependencies']['stdout'])
    paths = [source, *deps, tools['clang'], tools['ld'], '/usr/bin/xcrun']
    require(before == binding.snapshot(paths), 'query helper source/header changed during compile')
    receipt = {'status': 'READ_ONLY_QUERY_HELPER_BUILT', 'inputs': before,
               'commands': records, 'executable': str(helper), 'sha256': sha(helper),
               'scope': 'Foundation path and same-UID libproc only; no AppKit/GUI/guest'}
    write(out / 'helper-build.json', receipt)
    return helper, receipt


def verify_helper(out):
    source, tools, helper, commands = helper_plans(out)
    receipt = read(out / 'helper-build.json'); records = {}
    for name, command in commands:
        row = read(out / ('helper-' + name + '.json'))
        require(set(row) == {'command', 'returncode', 'stdout', 'stderr'} and
                row['command'] == command and type(row['returncode']) is int and row['returncode'] == 0,
                'actual query helper compile command differs')
        records[name] = row
    deps = binding.graphics.dependency_paths(records['dependencies']['stdout'])
    require(receipt['commands'] == records and receipt['inputs'] ==
            binding.snapshot([source, *deps, tools['clang'], tools['ld'], '/usr/bin/xcrun']) and
            receipt['executable'] == str(helper) and receipt['sha256'] == sha(helper),
            'query helper exact inputs/artifact differ')
    return receipt


def snapshot_data(support, out, label):
    """Observe existing user data; never mkdir/chmod/truncate inside it."""
    support = Path(support)
    require(support.is_absolute() and support == support.resolve(), 'non-aliased Foundation support path required')
    root = support / APP_ID
    entries = {}
    for name, path in [('application', root), ('data', root / 'Data'), ('runs', root / 'Runs'),
                       ('lock', root / 'instance.lock')]:
        try:
            st = path.lstat()
        except FileNotFoundError:
            entries[name] = {'exists': False}
            continue
        require(not stat.S_ISLNK(st.st_mode), 'symlink in user App paths')
        require(stat.S_ISREG(st.st_mode) if name == 'lock' else stat.S_ISDIR(st.st_mode),
                'unexpected user App path type')
        entries[name] = {'exists': True, 'metadata': metadata(st)}
    data = root / 'Data'
    names = sorted(p.name for p in data.iterdir()) if entries['data']['exists'] else []
    runs = sorted(p.name for p in (root / 'Runs').iterdir()) if entries['runs']['exists'] else []
    save = data / 'integer-tile.bin'
    try:
        info = save.lstat()
    except FileNotFoundError:
        saved = {'exists': False, 'metadata': None, 'sha256': None, 'size': None, 'snapshot': None}
    else:
        require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'save must be a regular file')
        raw = regular(save, 1024 * 1024)
        require(metadata(info) == metadata(save.lstat()), 'save changed while observing')
        destination = out / (label + '-save.bin')
        bytes_exclusive(destination, raw)
        saved = {'exists': True, 'metadata': metadata(info), 'sha256': hashlib.sha256(raw).hexdigest(),
                 'size': len(raw), 'snapshot': str(destination)}
    value = {'support_directory': str(support), 'data_directory': str(data), 'paths': entries,
             'data_entries': names, 'run_entries': runs, 'save': saved,
             'scope': 'actual filesystem snapshot; no save or user-directory writes by supervisor'}
    write(out / (label + '.json'), value)
    return value


def validate_snapshot(value, out, label, pinned=None):
    def raw(path): return pinned[str(path)] if pinned is not None else regular(path, 1024 * 1024)
    require(binding.graphics.strict_json(raw(out / (label + '.json')).decode()) == value, 'snapshot metadata changed')
    saved = value['save']; target = out / (label + '-save.bin')
    require(type(saved['exists']) is bool and target.exists() == saved['exists'], 'snapshot existence mismatch')
    if saved['exists']:
        data = raw(target)
        require(saved['snapshot'] == str(target) and saved['size'] == len(data) and
                saved['metadata']['size'] == len(data) and saved['sha256'] == hashlib.sha256(data).hexdigest(),
                'historical save snapshot mismatch')
    else:
        require(all(saved[k] is None for k in ('metadata', 'sha256', 'size', 'snapshot')), 'absent snapshot metadata')


def check_app(receipt, app, program):
    require(app == app.resolve() and app.is_relative_to('/private/tmp') and
            app.name == 'PE AOT Integer Tile V3.app' and app.parent.name == 'relocation with spaces' and
            app.parent.parent.name.startswith('pe-aot-noarg-ls-v3-'), 'expected unique moved App path')
    require(package.tree(app) == receipt['app_tree'], 'App tree/modes changed')
    graph = package.package_graph(app)
    require(package.normalized_graph(graph, app) == receipt['normalized_graph'], 'App load graph differs')
    actual = {}
    for source, destination in package.mapping_for(program, app).items():
        identity = package.section_identity(source)
        require(identity == package.section_identity(destination), 'code/data section identity changed')
        actual[str(destination.relative_to(app))] = identity
    require(actual == {p: r['section_identity'] for p, r in receipt['copied_code'].items()}, 'section receipt differs')
    binding.graphics.invoke([package.tools()['codesign'], '--verify', '--deep', '--strict', str(app)], environment(app.parent))
    return graph


def input_identity(out, receipt, app, helper_receipt):
    paths = [*receipt['inputs_before'], *receipt['artifacts'], package.OUT / 'evidence.json',
             *binding.python_closure([Path(__file__)]), *helper_receipt['inputs'],
             out / 'helper-build.json', out / 'location-process-probe', '/usr/bin/open',
             Path(select.__file__), Path(sys.executable).resolve(),
             *(Path(receipt['app']) / p for p in receipt['app_tree']),
             *(app / p for p in receipt['app_tree'])]
    return binding.snapshot(paths)


def identity_ok(value, executable, since):
    require(set(value) == {'pid', 'uid', 'ppid', 'path', 'start_seconds', 'start_microseconds'}, 'process identity schema')
    require(all(type(value[k]) is int for k in ('pid', 'uid', 'ppid', 'start_seconds', 'start_microseconds')),
            'process identity integer types')
    require(value['pid'] > 1 and value['pid'] != os.getpid() and value['uid'] == os.geteuid() and
            value['path'] == str(executable) and value['start_seconds'] >= since and
            0 <= value['start_microseconds'] < 1000000, 'live target identity differs')
    return value


def same_process(a, b):
    return all(a.get(k) == b.get(k) for k in ('pid', 'uid', 'path', 'start_seconds', 'start_microseconds'))


def marker(stderr):
    # Ignore only a final unfinished line while the real stream is still growing.
    lines = stderr.splitlines(keepends=True)
    matches = [line[len('PE_AOT_NOARG_RUN '):].rstrip('\r\n') for line in lines
               if line.endswith('\n') and line.startswith('PE_AOT_NOARG_RUN ')]
    require(len(matches) <= 1, 'multiple no-argument run markers')
    return Path(matches[0]) if matches else None


def authenticate_entry(record, run, app, support, identity, previous_runs):
    require(run.parent == Path(support) / APP_ID / 'Runs' and run == run.resolve(), 'run marker path differs')
    require(str(uuid.UUID(run.name)).upper() == run.name and run.name not in previous_runs, 'run UUID was not freshly created')
    require(record['schema'] == 1 and record['status'] == 'ENTRY_STARTED_NOT_ACCEPTED' and
            record['pid'] == identity['pid'] and record['uid'] == identity['uid'] and
            record['run_id'] == run.name and record['bundle_identifier'] == APP_ID and
            record['bundle_path'] == str(app) and record['argument_count'] == 1 and
            record['run_directory'] == str(run) and record['data_directory'] == str(Path(support) / APP_ID / 'Data') and
            record['instance_lock_held'] is True and record['test_queue_requested'] is False and
            record['host_arguments'] == ['--data-dir', record['data_directory'], '--budget', str(BUDGET)],
            'entry-start identity/configuration differs')


def prepare(out, timeout):
    require(type(timeout) is int and 180 <= timeout <= 240, 'external timeout must be 180..240 seconds')
    require(sha(exit_observer.__file__) == WATCH_SHA, 'frozen kqueue observer differs')
    out = output(out); require(not out.exists(), 'preserve prior launch attempt'); out.mkdir(parents=True)
    write(out / 'attempt.json', {'status': 'PREPARING_NO_TARGET_STARTED', 'driver_sha256': sha(__file__), 'scope': SCOPE})
    package.verify(package.OUT)
    require(sha(package.OUT / 'evidence.json') == PACKAGE_SHA, 'fixed v3 package receipt differs')
    receipt = read(package.OUT / 'evidence.json'); program = package.source_program()
    parent = Path(tempfile.mkdtemp(prefix='pe-aot-noarg-ls-v3-', dir='/private/tmp'))
    app = parent / 'relocation with spaces/PE AOT Integer Tile V3.app'
    app.parent.mkdir(); shutil.copytree(Path(receipt['app']), app, copy_function=shutil.copy2)
    graph = check_app(receipt, app, program)
    helper, helper_receipt = helper_build(out)
    location = query(helper, ['location']); write(out / 'location.json', location)
    require(location['uid'] == os.geteuid(), 'Foundation query user differs')
    before = snapshot_data(location['support_directory'], out, 'before')
    for name in ('app.stdout', 'app.stderr', 'open.stdout', 'open.stderr'):
        bytes_exclusive(out / name, b'')
    identities = input_identity(out, receipt, app, helper_receipt)
    start = {'schema': 1, 'status': 'PREPARED_NOT_STARTED', 'driver_sha256': sha(__file__),
             'package_sha256': PACKAGE_SHA, 'watch_sha256': WATCH_SHA, 'app': str(app),
             'executable': str(package.executable(app)), 'executable_sha256': sha(package.executable(app)),
             'source_program_sha256': package.SOURCE_RECEIPT_SHA, 'original_pe_sha256': package.PE_SHA,
             'support_directory': location['support_directory'], 'location_sha256': sha(out / 'location.json'),
             'before_sha256': sha(out / 'before.json'), 'before': before, 'app_tree': receipt['app_tree'],
             'command': open_command(app, out), 'environment': environment(out), 'timeout_seconds': timeout,
             'inputs_before': identities, 'helper': str(helper), 'helper_sha256': sha(helper), 'scope': SCOPE}
    write(out / 'started.json', start)
    return start, receipt, program, graph


def stream_caps(out):
    for name in ('app.stdout', 'app.stderr', 'open.stdout', 'open.stderr'):
        require((out / name).stat().st_size <= MAX_STREAM, 'live stream limit exceeded: ' + name)


def terminate_owned(helper, identity, log):
    """Signal only a newly re-authenticated live instance; never PID-retry."""
    actions = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            current = query(helper, ['pid', identity['pid']], log)
        except (ValueError, OSError, subprocess.TimeoutExpired):
            actions.append({'action': 'not_signaled', 'reason': 'original live identity unavailable'})
            break
        if not same_process(current, identity):
            actions.append({'action': 'not_signaled', 'reason': 'PID identity changed'})
            break
        try:
            os.kill(identity['pid'], sig)
        except ProcessLookupError:
            actions.append({'action': 'not_signaled', 'reason': 'original process already exited'})
            break
        except OSError as problem:
            actions.append({'action': 'signal_failed', 'pid': identity['pid'], 'signal': int(sig), 'reason': repr(problem)})
            break
        actions.append({'action': 'signal', 'pid': identity['pid'], 'signal': int(sig), 'identity': current})
        if sig == signal.SIGTERM:
            time.sleep(0.5)
    return actions


def stop_open_child(child):
    """Popen owns this direct child; poll/wait prevent signaling a reaped PID."""
    actions = []
    if child.poll() is None:
        child.terminate(); actions.append({'action': 'terminate_owned_open_child', 'pid': child.pid})
        try: child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill(); actions.append({'action': 'kill_owned_open_child', 'pid': child.pid})
            child.wait(timeout=2)
    return actions


def run(out, timeout=210):
    out = output(out); start, receipt, program, graph = prepare(out, timeout)
    helper = Path(start['helper']); app = Path(start['app']); exe = Path(start['executable'])
    state = {'status': 'LAUNCH_STARTED_NOT_ACCEPTED', 'started_sha256': sha(out / 'started.json'),
             'launch_wall_ns': time.time_ns(), 'launch_monotonic_ns': time.monotonic_ns()}
    write(out / 'launch-requested.json', state)
    since = state['launch_wall_ns'] // 1000000000
    deadline = time.monotonic() + timeout
    child = None; watch = None; target = None; child_identity = None; run_path = None
    observation = None; launched = None; error = None; cleanup = []
    try:
        with (out / 'open.stdout').open('ab') as stdout, (out / 'open.stderr').open('ab') as stderr:
            child = subprocess.Popen(start['command'], stdout=stdout, stderr=stderr, env=start['environment'])
        # This child is only the launcher; its return code never supplies App status.
        write(out / 'open-started.json', {'pid': child.pid, 'command': start['command'],
            'monotonic_ns': time.monotonic_ns(), 'scope': 'LaunchServices tool child only'})
        try:
            child_identity = query(helper, ['pid', child.pid], out / 'queries.jsonl')
            require(child_identity['path'] == '/System/Applications/Utilities/Terminal.app/Contents/MacOS/open' or
                    child_identity['path'] == '/usr/bin/open', 'unexpected open executable path')
        except (ValueError, OSError, subprocess.TimeoutExpired):
            # Short-lived open failures can be reaped without assuming an App PID.
            child_identity = None
        while observation is None:
            stream_caps(out)
            if time.monotonic() >= deadline:
                raise TimeoutError('bounded LaunchServices App observation expired')
            if target is None:
                matches = query(helper, ['find', exe, since], out / 'queries.jsonl')['matches']
                require(type(matches) is list and len(matches) <= 1, 'ambiguous exact-path App instances')
                if matches:
                    target = identity_ok(matches[0], exe, since)
                    # Never poll another PID after this registration attempt.
                    watch = exit_observer.ExitWatch(target['pid'])
                    confirmed = query(helper, ['pid', target['pid']], out / 'queries.jsonl')
                    require(same_process(confirmed, target), 'identity changed across kqueue registration')
                    registered = {'identity': target, 'registration': watch.registration,
                                  'registered_at_monotonic_ns': time.monotonic_ns(),
                                  'post_registration_identity': confirmed,
                                  'executable_sha256': start['executable_sha256']}
                    write(out / 'process-registered.json', registered)
                elif child.poll() is not None:
                    raise ValueError('open completed without an authenticated live App; no exit-code inference')
            if target is not None and launched is None:
                mark = marker(growing_stream(out / 'app.stderr').decode())
                if mark is not None:
                    raw = regular(mark / 'entry-started.json')
                    entry = binding.graphics.strict_json(raw.decode())
                    authenticate_entry(entry, mark, app, start['support_directory'], target, start['before']['run_entries'])
                    bytes_exclusive(out / 'entry-started.json', raw); run_path = mark
                    launched = {'status': 'APP_REGISTERED_READY_FOR_EXTERNAL_CONTROL_NOT_ACCEPTED',
                        'started_sha256': sha(out / 'started.json'), 'requested_sha256': sha(out / 'launch-requested.json'),
                        'registered_sha256': sha(out / 'process-registered.json'), 'entry_started_sha256': sha(out / 'entry-started.json'),
                        'pid': target['pid'], 'run_id': mark.name, 'run_directory': str(mark),
                        'app': str(app), 'identity': target, 'ready_at_monotonic_ns': time.monotonic_ns(),
                        'input_policy': 'external operator only; runner sends no events or permission requests'}
                    write(out / 'launched.json', launched)
                    print(json.dumps({'control_ready': str(out / 'launched.json'), 'pid': target['pid'],
                                      'run_id': mark.name}), flush=True)
            if watch is not None:
                try:
                    observation = watch.wait(min(0.25, max(0.001, deadline - time.monotonic())))
                except TimeoutError:
                    pass
            else:
                time.sleep(0.1)
        write(out / 'app-exit.json', observation)
        require(launched is not None, 'App exited before entry authentication/control-ready; preserved exit is not success')
        require(run_path is not None, 'missing authenticated run path')
        finish_raw = regular(run_path / 'entry-finished.json')
        bytes_exclusive(out / 'entry-finished.json', finish_raw)
        child.wait(timeout=5)
    except BaseException as problem:
        error = {'type': type(problem).__name__, 'message': str(problem),
                 'timeout': isinstance(problem, (TimeoutError, subprocess.TimeoutExpired))}
    finally:
        if error is not None and child is not None and target is None:
            # Failure persisting the very first launcher record can precede
            # normal discovery. Killing open alone does not kill an LS App.
            try:
                remaining = query(helper, ['find', exe, since], out / 'queries.jsonl')['matches']
                require(type(remaining) is list and len(remaining) <= 1, 'ambiguous cleanup candidates')
                if remaining:
                    target = identity_ok(remaining[0], exe, since)
                    cleanup.append({'action': 'late_exact_identity_found_for_cleanup', 'identity': target})
                else:
                    cleanup.append({'action': 'unresolved_residual', 'reason': 'no live exact-path target found; no proof LS did not start later'})
            except (ValueError, OSError, subprocess.TimeoutExpired) as problem:
                cleanup.append({'action': 'unresolved_residual', 'reason': repr(problem)})
        # Even persistence errors after Popen reach cleanup. A registered exit
        # event proves the target is already terminal and must not be signaled.
        if error is not None and target is not None and observation is None:
            try: cleanup += terminate_owned(helper, target, out / 'queries.jsonl')
            except BaseException as problem:
                cleanup.append({'action': 'target_cleanup_failed', 'reason': repr(problem)})
            if watch is not None:
                try:
                    observation = watch.wait(3)
                    if not (out / 'app-exit.json').exists(): write(out / 'app-exit.json', observation)
                except (TimeoutError, ValueError, OSError) as problem:
                    cleanup.append({'action': 'exit_status_unavailable', 'reason': repr(problem)})
        if child is not None and child.poll() is None:
            try:
                if child_identity is not None:
                    cleanup += terminate_owned(helper, child_identity, out / 'queries.jsonl')
            except BaseException as problem:
                cleanup.append({'action': 'open_identity_cleanup_failed', 'reason': repr(problem)})
            try:
                # Popen still owns its direct child's waitpid even if the
                # first persistence/libproc operation failed.
                cleanup += stop_open_child(child)
            except BaseException as problem:
                cleanup.append({'action': 'open_cleanup_failed', 'reason': repr(problem)})
        if watch is not None:
            try: watch.close()
            except BaseException as problem:
                cleanup.append({'action': 'watch_close_failed', 'reason': repr(problem)})
    capture = {'status': OBSERVED if error is None else 'FAILED_OBSERVATION_PRESERVED',
               'started_sha256': sha(out / 'started.json'), 'requested_sha256': sha(out / 'launch-requested.json'),
               'identity': target, 'app_exit': observation, 'open_pid': None if child is None else child.pid,
               'open_returncode': None if child is None else child.returncode, 'error': error,
               'cleanup_actions': cleanup, 'external_input_log': 'none supplied to this runner; no input source inferred',
               'scope': SCOPE}
    try:
        capture['after'] = snapshot_data(start['support_directory'], out, 'after')
        capture['app_tree_after'] = package.tree(app)
        capture['inputs_after'] = input_identity(out, receipt, app, read(out / 'helper-build.json'))
        capture['loaded_images'] = binding.graphics.loaded_images(regular(out / 'app.stderr').decode(), exe, graph['nodes'])
        capture['result'] = binding.graphics.strict_json(regular(out / 'app.stdout').decode())
    except BaseException as problem:
        capture['capture_error'] = repr(problem);capture['status'] = 'FAILED_OBSERVATION_PRESERVED'
    capture['artifacts'] = observation_artifacts(out)
    write(out / 'observed.json', capture)
    if capture['status'] != OBSERVED:
        raise ValueError('failed observation retained: ' + str(out / 'observed.json'))
    return verify(out)


def observation_artifacts(out):
    names = ['attempt.json', 'started.json', 'helper-build.json', 'helper-dependencies.json', 'helper-compile.json',
             'location.json', 'location-process-probe', 'before.json', 'before-save.bin', 'after.json', 'after-save.bin',
             'launch-requested.json', 'open-started.json', 'process-registered.json', 'launched.json',
             'entry-started.json', 'entry-finished.json', 'app-exit.json', 'queries.jsonl',
             'app.stdout', 'app.stderr', 'open.stdout', 'open.stderr']
    return binding.snapshot([out / name for name in names if (out / name).is_file()])


def verify(out):
    """Read saved bytes/identities; never starts helper, open, App or input."""
    out = output(out)
    record_raw = regular(out / 'observed.json')
    record = binding.graphics.strict_json(record_raw.decode())
    require(set(record) == {'status', 'started_sha256', 'requested_sha256', 'identity', 'app_exit', 'open_pid',
            'open_returncode', 'error', 'cleanup_actions', 'external_input_log', 'scope', 'after', 'app_tree_after',
            'inputs_after', 'loaded_images', 'result', 'artifacts'}, 'observation record field closure differs')
    require(record['artifacts'] == observation_artifacts(out), 'actual artifact set or bytes differ')
    pinned = {p: regular(p) for p in record['artifacts']}
    require({p: hashlib.sha256(data).hexdigest() for p, data in pinned.items()} == record['artifacts'],
            'pinned observation bytes differ')
    def blob(name): return pinned[str(out / name)]
    def load(name): return binding.graphics.strict_json(blob(name).decode())
    start = load('started.json')
    require(record['status'] == OBSERVED and record['error'] is None and record['cleanup_actions'] == [],
            'no complete non-timeout observation; failures are retained separately')
    require(record['scope'] == start['scope'] == SCOPE, 'observation scope differs')
    require(sha(exit_observer.__file__) == WATCH_SHA and sha(package.OUT / 'evidence.json') == PACKAGE_SHA and
            start['driver_sha256'] == sha(__file__) and start['watch_sha256'] == WATCH_SHA and
            start['package_sha256'] == PACKAGE_SHA and start['source_program_sha256'] == package.SOURCE_RECEIPT_SHA and
            start['original_pe_sha256'] == package.PE_SHA and start['status'] == 'PREPARED_NOT_STARTED', 'fixed source/profile differs')
    package.verify(package.OUT); receipt = read(package.OUT / 'evidence.json'); program = package.source_program()
    app = Path(start['app']); graph = check_app(receipt, app, program)
    require(start['executable'] == str(package.executable(app)) and sha(start['executable']) == start['executable_sha256'], 'actual App executable differs')
    helper = verify_helper(out)
    current = input_identity(out, receipt, app, helper)
    require(current == start['inputs_before'] == record['inputs_after'], 'whole source/helper/App closure changed')
    require(start['command'] == open_command(app, out) and start['environment'] == environment(out) and
            type(start['timeout_seconds']) is int and 180 <= start['timeout_seconds'] <= 240, 'launch command/environment/deadline differs')
    require(start['helper'] == str(out / 'location-process-probe') and start['helper_sha256'] == sha(start['helper']) and
            helper['sha256'] == start['helper_sha256'], 'query helper identity differs')
    require(start['location_sha256'] == sha(out / 'location.json') and
            read(out / 'location.json')['support_directory'] == start['support_directory'], 'Foundation location receipt differs')
    require(start['before_sha256'] == sha(out / 'before.json') and record['started_sha256'] == sha(out / 'started.json'), 'start/snapshot identity differs')
    validate_snapshot(start['before'], out, 'before', pinned); validate_snapshot(record['after'], out, 'after', pinned)
    require(start['before']['support_directory'] == record['after']['support_directory'] == start['support_directory'], 'shared real data path differs')
    require(record['artifacts'] == observation_artifacts(out) and record['app_tree_after'] == start['app_tree'] == receipt['app_tree'], 'required artifact/App closure differs')
    for name in ('process-registered.json', 'launched.json', 'entry-started.json', 'entry-finished.json', 'app-exit.json'):
        require(str(out / name) in record['artifacts'], 'mandatory observation omitted: ' + name)
    requested = load('launch-requested.json'); launched = load('launched.json'); registered = load('process-registered.json')
    require(launched['status'] == 'APP_REGISTERED_READY_FOR_EXTERNAL_CONTROL_NOT_ACCEPTED', 'control-ready status differs')
    require(record['requested_sha256'] == sha(out / 'launch-requested.json') and requested['started_sha256'] == sha(out / 'started.json'), 'launch request identity differs')
    identity = identity_ok(record['identity'], package.executable(app), requested['launch_wall_ns'] // 1000000000)
    require(registered['identity'] == launched['identity'] == identity and
            same_process(registered['post_registration_identity'], identity) and
            registered['executable_sha256'] == start['executable_sha256'] and launched['pid'] == identity['pid'] and
            launched['registered_sha256'] == sha(out / 'process-registered.json') and
            launched['requested_sha256'] == sha(out / 'launch-requested.json') and
            launched['entry_started_sha256'] == sha(out / 'entry-started.json') and
            launched['started_sha256'] == sha(out / 'started.json'), 'control-ready identity chain differs')
    require(requested['launch_monotonic_ns'] <= registered['registered_at_monotonic_ns'] <= launched['ready_at_monotonic_ns'], 'registration/control ordering differs')
    entry = load('entry-started.json'); finish = load('entry-finished.json')
    run_path = Path(launched['run_directory']); authenticate_entry(entry, run_path, app, start['support_directory'], identity, start['before']['run_entries'])
    require(launched['run_id'] == run_path.name and launched['app'] == str(app) and
            marker(blob('app.stderr').decode()) == run_path, 'actual stderr marker differs')
    require(regular(run_path / 'entry-started.json') == blob('entry-started.json') and
            regular(run_path / 'entry-finished.json') == blob('entry-finished.json'), 'original entry diagnostics changed')
    event = load('app-exit.json'); ack = event['registration']; terminal = event['event']
    require(record['app_exit'] == event and event['pid'] == identity['pid'] and
            registered['registration'] == ack and ack['ident'] == terminal['ident'] == identity['pid'] and
            ack['filter'] == terminal['filter'] == select.KQ_FILTER_PROC and ack['flags'] & select.KQ_EV_ERROR and ack['data'] == 0 and
            not terminal['flags'] & select.KQ_EV_ERROR and terminal['fflags'] & select.KQ_NOTE_EXIT and
            terminal['fflags'] & exit_observer.NOTE_EXITSTATUS, 'acknowledged actual App exit missing')
    decoded = exit_observer.decode_wait_status(terminal['data'])
    require(event['termination'] == decoded, 'actual exit status decode differs')
    require(finish['schema'] == 1 and finish['status'] == 'HOST_RETURNED_NOT_ACCEPTED' and finish['pid'] == identity['pid'] and
            finish['run_id'] == run_path.name and finish['host_returncode'] == decoded['python_returncode'] and
            decoded['exited'] is True and finish['test_queue_requested'] is False and
            finish['instance_lock_held_until_host_return'] is True, 'entry completion differs from actual App status')
    result = binding.graphics.strict_json(blob('app.stdout').decode())
    require(record['result'] == result, 'raw stdout differs')
    # Schema only: no exact keyboard sequence or successful-save predicate.
    program.original.validate_execution(result, decoded['python_returncode'], None, BUDGET)
    require(result['test_queue']['requested'] == result['test_queue']['posted'] == 0, 'unexpected test injection')
    stderr = blob('app.stderr').decode()
    require(set(map(int, re.findall(r'^dyld\[(\d+)\]:', stderr, re.M))) == {identity['pid']}, 'mixed dyld process IDs')
    require(record['loaded_images'] == binding.graphics.loaded_images(stderr, package.executable(app), graph['nodes']), 'dynamic image identities differ')
    tool = load('open-started.json')
    require(tool['pid'] == record['open_pid'] and tool['command'] == start['command'] and type(record['open_returncode']) is int,
            'open child identity/return observation differs')
    queries = [binding.graphics.strict_json(line) for line in blob('queries.jsonl').decode().splitlines()]
    successful = [q for q in queries if q['returncode'] == 0 and q['stderr'] == '']
    require(any(q['command'] == [start['helper'], 'find', start['executable'], str(requested['launch_wall_ns'] // 1000000000)] and
                identity in binding.graphics.strict_json(q['stdout']).get('matches', []) for q in successful),
            'actual exact-path discovery query missing')
    require(any(q['command'] == [start['helper'], 'pid', str(identity['pid'])] and
                binding.graphics.strict_json(q['stdout']) == registered['post_registration_identity'] for q in successful),
            'actual post-registration identity query missing')
    require(regular(out / 'observed.json') == record_raw and observation_artifacts(out) == record['artifacts'] and
            input_identity(out, receipt, app, helper) == current, 'evidence/input changed during read-only verification')
    return {'status': OBSERVED, 'pid': identity['pid'], 'app_returncode': decoded['python_returncode'],
            'open_returncode': record['open_returncode'], 'run_id': run_path.name,
            'observed_sha256': sha(out / 'observed.json'), 'scope': SCOPE,
            'semantic_acceptance': False, 'new_target_executions_during_verify': 0}


def preflight(out, timeout):
    start, _, _, _ = prepare(out, timeout)
    result = {'status': 'STATIC_LAUNCH_PREFLIGHT_ONLY', 'started_sha256': sha(Path(out) / 'started.json'),
              'app': start['app'], 'command': start['command'], 'default_data_observation': start['before'],
              'scope': {'target_launches': 0, 'GUI': 0, 'GPU': 0, 'event_posts': 0, 'permission_requests': 0}}
    write(Path(out) / 'preflight.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=OUT)
    modes = parser.add_mutually_exclusive_group(); modes.add_argument('--run', action='store_true'); modes.add_argument('--preflight', action='store_true')
    parser.add_argument('--timeout', type=int, default=210)
    args = parser.parse_args()
    value = run(args.out, args.timeout) if args.run else preflight(args.out, args.timeout) if args.preflight else verify(args.out)
    print(json.dumps(value, indent=2, sort_keys=True))
