"""Controlled interruption of this probe's own fresh App build group.

This is an explicit integration experiment, not an automatic installer retry.
It creates a new installation, preserves the failed attempt and all raw logs,
and never sends a signal before checking the owned worker PID/PGID/parent/job.
Resume is a separate user/driver command after inspecting the failed result.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def read(path):
    return json.loads(Path(path).read_bytes())


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write('\n')


def group_members(pgid):
    env = dict(os.environ, LC_ALL='C', LANG='C')
    run = subprocess.run(['/bin/ps', '-ww', '-axo', 'pid=,ppid=,pgid=,command='],
                         capture_output=True, text=True, env=env, timeout=15, check=True)
    records = []
    for line in run.stdout.splitlines():
        fields = line.strip().split(None, 3)
        if len(fields) != 4:
            continue
        try:
            pid, parent, group = map(int, fields[:3])
        except ValueError:
            continue
        if group == pgid:
            records.append(dict(pid=pid, parent_pid=parent, pgid=group, command=fields[3]))
    need(records, 'owned process group not present in process inventory')
    # Keep only the second, PID-scoped raw query. Do not retain unrelated user
    # process command lines from the discovery inventory.
    command = ['/bin/ps', '-ww', '-p', ','.join(str(r['pid']) for r in records),
               '-o', 'pid=,ppid=,pgid=,command=']
    exact = subprocess.run(command, capture_output=True, text=True, env=env, timeout=15, check=True)
    scoped = parse_members(exact.stdout, pgid)
    # A short-lived compiler may have exited between queries. Do not signal
    # from a partial observation; the supervisor can safely sample again.
    complete = {r['pid'] for r in scoped} == {r['pid'] for r in records}
    return scoped if complete else None, dict(command=command, returncode=exact.returncode,
                                              stdout=exact.stdout, stderr=exact.stderr)


def parse_members(text, pgid):
    result = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.strip().split(None, 3)
        need(len(fields) == 4, 'malformed scoped process observation')
        pid, parent, group = map(int, fields[:3])
        need(pid > 1 and parent > 0 and group == pgid, 'scoped process escaped owned group')
        result.append(dict(pid=pid, parent_pid=parent, pgid=group, command=fields[3]))
    need(result and len({r['pid'] for r in result}) == len(result), 'missing or duplicate scoped process')
    return result


def group_state(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return 'ABSENT'
    except PermissionError:
        return 'UNOBSERVABLE'
    return 'PRESENT'


def eligible_worker(launched_path, launched, job, job_sha, work_root, coordinator_pid, members):
    """Prove ownership and App-build role before considering any OS signal."""
    pid = launched.get('pid')
    need(type(pid) is int and pid > 1 and pid == launched.get('pgid'), 'unexpected App-build group identity')
    need(job['stage'] == launched['stage'] == 'app-build', 'not an App-build attempt')
    need(Path(job['launched']) == launched_path and launched['job_sha256'] == job_sha,
         'worker/job binding differs')
    prefix = Path(job['arguments']['out'])
    need(prefix == work_root/'attempts'/launched_path.parent.name, 'App-build prefix escaped this experiment')
    seen = set()
    for row in members:
        need(type(row['pid']) is int and row['pid'] > 1 and row['pid'] not in seen and
             row['pgid'] == pid and type(row['parent_pid']) is int and type(row['command']) is str,
             'invalid or duplicated process group member')
        seen.add(row['pid'])
    owner = next((row for row in members if row['pid'] == pid), None)
    job_path = launched_path.with_name('job.json')
    need(owner is not None and owner['parent_pid'] == coordinator_pid and
         'migration_install_v3 _worker ' in owner['command'] and str(job_path) in owner['command'],
         'App-build process is not this coordinator owned worker')
    compiling = [row for row in members if row['pid'] != pid and str(prefix) in row['command'] and
                 'clang' in row['command']]
    return pid, prefix, bool(compiling)


def run(cpu_cache, graphics_cache, pe, profile, identifier, work_root, installation, out, jobs=2):
    paths = {name: Path(value).absolute() for name, value in dict(
        cpu_cache=cpu_cache, graphics_cache=graphics_cache, pe=pe, profile=profile,
        work_root=work_root, installation=installation, out=out).items()}
    for name, path in paths.items():
        need(path == path.resolve(), 'canonical non-symlink path required: ' + name)
    for name in ('work_root', 'installation', 'out'):
        need(not os.path.lexists(paths[name]), 'fresh absent experiment output required: ' + name)
    destinations = [paths[n] for n in ('work_root', 'installation', 'out')]
    for i, left in enumerate(destinations):
        for right in destinations[i+1:]:
            need(not left.is_relative_to(right) and not right.is_relative_to(left), 'experiment outputs overlap')
        for source in (paths['cpu_cache'], paths['graphics_cache'], paths['pe'], paths['profile']):
            need(not left.is_relative_to(source) and not source.is_relative_to(left), 'experiment output overlaps input')
    paths['out'].mkdir(parents=True)
    argv = [sys.executable, '-B', '-m', 'migration_install_v3', 'install']
    for name in ('cpu_cache', 'graphics_cache', 'pe', 'profile', 'identifier', 'work_root'):
        argv.extend(['--' + name.replace('_', '-'), identifier if name == 'identifier' else str(paths[name])])
    argv += ['--out', str(paths['installation']), '--jobs', str(jobs)]
    environment = dict(os.environ)
    environment.pop('PYTHONPATH', None); environment.pop('PYTHONHOME', None)
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    write(paths['out']/'started.json', dict(argv=argv, cwd=str(ROOT),
          source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
          signal_contract='Only the App-build worker of this newly spawned coordinator, after exact ownership checks'))
    source_copy=paths['out']/'sources/migration_install_v3/recovery_probe.py'
    source_copy.parent.mkdir(parents=True)
    source_copy.write_bytes(Path(__file__).read_bytes())
    need(hashlib.sha256(source_copy.read_bytes()).hexdigest()==read(paths['out']/'started.json')['source_sha256'], 'probe source changed while freezing')
    controlled = None
    with (paths['out']/'install.stdout').open('xb') as stdout, (paths['out']/'install.stderr').open('xb') as stderr:
        child = subprocess.Popen(argv, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr, start_new_session=True)
        write(paths['out']/'coordinator.json', dict(pid=child.pid, pgid=child.pid, argv=argv))
        print(json.dumps(dict(status='LIVE_CONTROLLED_INSTALL_COORDINATOR', pid=child.pid,
                              installation=str(paths['installation']))), flush=True)
        try:
            deadline = time.monotonic() + 7200
            while child.poll() is None:
                need(time.monotonic() < deadline, 'experiment observation limit; coordinator may still be live')
                for launched_path in sorted((paths['installation']/'attempts').glob('app-build-*/launched.json')):
                    # Atomic publication is the installer's contract; a partial
                    # read is treated as no observation, never permission to signal.
                    try:
                        launched = read(launched_path)
                        job_path = launched_path.with_name('job.json')
                        job = read(job_path)
                    except (FileNotFoundError, json.JSONDecodeError):
                        continue
                    observed_pid = launched.get('pid')
                    need(type(observed_pid) is int and observed_pid > 1, 'invalid observed worker PID')
                    members, raw_processes = group_members(observed_pid)
                    if members is None:
                        continue
                    pid, prefix, compiling = eligible_worker(launched_path, launched, job,
                        hashlib.sha256(job_path.read_bytes()).hexdigest(), paths['work_root'], child.pid, members)
                    if not compiling:
                        continue
                    need(os.getpgid(pid) == pid and child.poll() is None, 'owned worker changed before signal')
                    controlled = dict(stage='app-build', pid=pid, pgid=pid, coordinator_pid=child.pid,
                                      job=str(job_path), job_sha256=launched['job_sha256'], prefix=str(prefix),
                                      members=members, signal=int(signal.SIGTERM),
                                      observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
                    write(paths['out']/'processes-before-signal.json', raw_processes)
                    controlled['process_observation_sha256'] = hashlib.sha256(
                        (paths['out']/'processes-before-signal.json').read_bytes()).hexdigest()
                    write(paths['out']/'controlled-signal.json', controlled)
                    os.killpg(pid, signal.SIGTERM)
                    write(paths['out']/'signal-sent.json', dict(status='OS_SIGNAL_CALL_SUCCEEDED',pid=pid,pgid=pid,signal=15))
                    print(json.dumps(dict(status='CONTROLLED_OWNED_APP_BUILD_GROUP_SIGTERM', pid=pid, pgid=pid)), flush=True)
                    break
                if controlled:
                    break
                time.sleep(.1)
            code = child.wait(timeout=120) if controlled else child.wait()
        except BaseException as error:
            write(paths['out']/'observation-failure.json', dict(status='EXPERIMENT_NOT_ACCEPTED_CHILD_STATE_REQUIRES_OBSERVATION',
                  coordinator_pid=child.pid, returncode=child.poll(), error_type=type(error).__name__, error=str(error)))
            raise
    need(controlled is not None, 'installation ended before controlled interruption; inspect real logs')
    deadline = time.monotonic()+30
    state = group_state(controlled['pgid'])
    while state == 'PRESENT' and time.monotonic() < deadline:
        time.sleep(.1)
        state = group_state(controlled['pgid'])
    result = read(paths['installation']/'result.json')
    need(code == 1 and result['status'] == 'INSTALL_FAILED' and result['stage'] == 'app-build',
         'controlled interruption did not produce the expected App-build stage failure')
    need(result['completed_stages'] == ['cpu-build', 'switch-build', 'graphics-build'], 'completed stages differ from controlled recovery experiment')
    need(state == 'ABSENT', 'old App-build process group still live/unobservable; do not resume')
    accepted = dict(status='CONTROLLED_REAL_APP_BUILD_INTERRUPTION_OBSERVED_NOT_RESUMED',
                    coordinator_returncode=code, installation=str(paths['installation']),
                    worker_pgid=controlled['pgid'], final_group_state=state,
                    completed_stages=result['completed_stages'], failed_install_status=result['status'],
                    failed_install_result_sha256=hashlib.sha256((paths['installation']/'result.json').read_bytes()).hexdigest(),
                    native_builds_invoked=True, app_executions=0, gpu_executions=0)
    need(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()==read(paths['out']/'started.json')['source_sha256'], 'probe source changed during execution')
    write(paths['out']/'result.json', accepted)
    print(json.dumps(accepted, ensure_ascii=False, indent=2), flush=True)
    return accepted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cpu-cache','graphics-cache','pe','profile','identifier','work-root','installation','out'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    run(**vars(parser.parse_args()))


if __name__ == '__main__':
    main()
