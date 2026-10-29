"""Attach to this experiment's existing coordinator after observer failure.

No installer or builder is started. Only the registered graphics worker may
receive SIGTERM, after rechecking its real parent, group, exact job and active
build command. An orphaned coordinator's OS exit code is not invented.
"""
import argparse
import datetime
import hashlib
import os
from pathlib import Path
import signal
import time

from .recovery_probe import group_members, group_state, need, read, write


def run(probe, out):
    probe, out = Path(probe).resolve(strict=True), Path(out).absolute()
    need(out == out.resolve() and not os.path.lexists(out), 'fresh canonical observer evidence required')
    coordinator = read(probe/'coordinator.json')
    argv = coordinator['argv']; parent = coordinator['pid']
    need(type(parent) is int and parent > 1 and coordinator['pgid'] == parent, 'invalid original coordinator identity')
    installation = Path(argv[argv.index('--out')+1])
    work = Path(argv[argv.index('--work-root')+1])
    out.mkdir(parents=True)
    write(out/'coordinator.json', coordinator)
    write(out/'started.json', dict(status='ATTACHING_NO_NEW_BUILDERS', original_probe=str(probe),
          installation=str(installation), coordinator_pid=parent,
          source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    controlled = None
    deadline = time.monotonic()+3600
    while time.monotonic() < deadline:
        parents = group_members(parent)
        owner = next((row for row in parents if row['pid'] == parent), None)
        if owner is None:
            break
        need('migration_install_v2 install ' in owner['command'] and str(installation) in owner['command'] and
             str(work) in owner['command'], 'original coordinator identity no longer matches')
        for launch_path in sorted((installation/'attempts').glob('graphics-build-*/launched.json')):
            launch = read(launch_path); job_path = launch_path.with_name('job.json'); job = read(job_path)
            pid = launch['pid']
            need(type(pid) is int and pid > 1 and launch['pgid'] == pid and
                 job['stage'] == launch['stage'] == 'graphics-build', 'invalid graphics launch identity')
            need(Path(job['launched']) == launch_path and
                 hashlib.sha256(job_path.read_bytes()).hexdigest() == launch['job_sha256'], 'graphics job differs')
            prefix = Path(job['arguments']['prefix'])
            need(prefix == work/'attempts'/launch_path.parent.name, 'graphics prefix escaped original installation')
            members = group_members(pid)
            worker = next((row for row in members if row['pid'] == pid), None)
            if worker is None:
                continue
            need(worker['parent_pid'] == parent and 'migration_install_v2 _worker ' in worker['command'] and
                 str(job_path) in worker['command'], 'graphics worker not owned by original coordinator')
            compiling = [row for row in members if str(prefix) in row['command'] and
                         ('--build ' in row['command'] or 'clang' in row['command'])]
            if not compiling:
                continue
            need(os.getpgid(pid) == pid and group_state(parent) == 'PRESENT', 'worker or coordinator changed')
            controlled = dict(stage='graphics-build', pid=pid, pgid=pid, coordinator_pid=parent,
                              job=str(job_path), job_sha256=launch['job_sha256'], prefix=str(prefix),
                              members=members, coordinator_observation=owner, signal=int(signal.SIGTERM),
                              observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            write(out/'controlled-signal.json', controlled)
            os.killpg(pid, signal.SIGTERM)
            write(out/'signal-sent.json', dict(status='OS_SIGNAL_CALL_SUCCEEDED', pid=pid, pgid=pid, signal=15))
            print('CONTROLLED_EXISTING_GRAPHICS_SIGTERM ' + str(pid), flush=True)
            break
        if controlled:
            break
        time.sleep(.1)
    need(controlled is not None, 'No owned active graphics compilation observed; no signal sent')
    deadline = time.monotonic()+120
    while time.monotonic() < deadline:
        if group_state(controlled['pgid']) == group_state(parent) == 'ABSENT':
            break
        time.sleep(.1)
    need(group_state(controlled['pgid']) == group_state(parent) == 'ABSENT', 'Prior group/coordinator still live or unobservable')
    failed = read(installation/'result.json')
    need(failed['status'] == 'INSTALL_FAILED' and failed['stage'] == 'graphics-build' and
         failed['completed_stages'] == ['cpu-build','switch-build'], 'Actual installer failure differs')
    exit_path = Path(controlled['job']).with_name('worker-exit.json')
    exited = read(exit_path)
    need(exited['returncode'] == -15 and exited['pid'] == exited['pgid'] == controlled['pid'], 'Worker did not record SIGTERM exit')
    record = dict(status='ATTACHED_REAL_GRAPHICS_INTERRUPTION_OBSERVED_NOT_RESUMED',
                  original_probe=str(probe), installation=str(installation), worker_pgid=controlled['pgid'],
                  final_group_state='ABSENT', coordinator_group_state='ABSENT', coordinator_returncode=None,
                  coordinator_exit_scope='Orphaned non-child; OS PID/group disappearance checked, exit code not observed',
                  completed_stages=failed['completed_stages'], failed_install_status=failed['status'],
                  failed_install_result_sha256=hashlib.sha256((installation/'result.json').read_bytes()).hexdigest(),
                  worker_exit_sha256=hashlib.sha256(exit_path.read_bytes()).hexdigest(),
                  new_builders_started=0, app_executions=0, gpu_executions=0)
    write(out/'result.json', record)
    print(record, flush=True)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True); parser.add_argument('--out', required=True)
    run(**vars(parser.parse_args()))
