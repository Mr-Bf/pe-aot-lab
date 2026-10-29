"""Controlled interruption of this probe's own fresh graphics build group.

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
    return records


def group_state(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return 'ABSENT'
    except PermissionError:
        return 'UNOBSERVABLE'
    return 'PRESENT'


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
    argv = [sys.executable, '-B', '-m', 'migration_install_v2', 'install']
    for name in ('cpu_cache', 'graphics_cache', 'pe', 'profile', 'identifier', 'work_root'):
        argv.extend(['--' + name.replace('_', '-'), identifier if name == 'identifier' else str(paths[name])])
    argv += ['--out', str(paths['installation']), '--jobs', str(jobs)]
    environment = dict(os.environ)
    environment.pop('PYTHONPATH', None); environment.pop('PYTHONHOME', None)
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    write(paths['out']/'started.json', dict(argv=argv, cwd=str(ROOT),
          source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
          signal_contract='Only the graphics worker of this newly spawned coordinator, after exact ownership checks'))
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
                for launched_path in sorted((paths['installation']/'attempts').glob('graphics-build-*/launched.json')):
                    # Atomic publication is the installer's contract; a partial
                    # read is treated as no observation, never permission to signal.
                    try:
                        launched = read(launched_path)
                        job_path = launched_path.with_name('job.json')
                        job = read(job_path)
                    except (FileNotFoundError, json.JSONDecodeError):
                        continue
                    pid = launched.get('pid')
                    need(type(pid) is int and pid > 1 and pid == launched.get('pgid'), 'unexpected graphics group identity')
                    need(job['stage'] == launched['stage'] == 'graphics-build', 'not a graphics attempt')
                    need(Path(job['launched']) == launched_path and
                         launched['job_sha256'] == hashlib.sha256(job_path.read_bytes()).hexdigest(), 'worker/job binding differs')
                    prefix = Path(job['arguments']['prefix'])
                    need(prefix == paths['work_root']/'attempts'/launched_path.parent.name, 'graphics prefix escaped this experiment')
                    members = group_members(pid)
                    owner = next((row for row in members if row['pid'] == pid), None)
                    need(owner is not None and owner['parent_pid'] == child.pid and
                         'migration_install_v2 _worker ' in owner['command'] and str(job_path) in owner['command'],
                         'graphics process is not this coordinator owned worker')
                    compiling = [row for row in members if str(prefix) in row['command'] and
                                 ('--build ' in row['command'] or 'clang' in row['command'])]
                    if not compiling:
                        continue
                    need(os.getpgid(pid) == pid and child.poll() is None, 'owned worker changed before signal')
                    controlled = dict(stage='graphics-build', pid=pid, pgid=pid, coordinator_pid=child.pid,
                                      job=str(job_path), job_sha256=launched['job_sha256'], prefix=str(prefix),
                                      members=members, signal=int(signal.SIGTERM),
                                      observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
                    write(paths['out']/'controlled-signal.json', controlled)
                    os.killpg(pid, signal.SIGTERM)
                    print(json.dumps(dict(status='CONTROLLED_OWNED_GRAPHICS_GROUP_SIGTERM', pid=pid, pgid=pid)), flush=True)
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
    need(code == 1 and result['status'] == 'INSTALL_FAILED' and result['stage'] == 'graphics-build',
         'controlled interruption did not produce the expected graphics stage failure')
    need(result['completed_stages'] == ['cpu-build', 'switch-build'], 'completed stages differ from controlled recovery experiment')
    need(state == 'ABSENT', 'old graphics process group still live/unobservable; do not resume')
    accepted = dict(status='CONTROLLED_REAL_GRAPHICS_INTERRUPTION_OBSERVED_NOT_RESUMED',
                    coordinator_returncode=code, installation=str(paths['installation']),
                    worker_pgid=controlled['pgid'], final_group_state=state,
                    completed_stages=result['completed_stages'], failed_install_status=result['status'],
                    failed_install_result_sha256=hashlib.sha256((paths['installation']/'result.json').read_bytes()).hexdigest(),
                    native_builds_invoked=True, app_executions=0, gpu_executions=0)
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
