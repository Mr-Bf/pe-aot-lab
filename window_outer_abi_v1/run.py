"""Run four serialized diagnostic hosts; TEST_QUEUE input, no timing or replay."""
import fcntl
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time

from graphics_stage5.d3d11_probe import environment
from .build import BASE, STATUS, fresh, identities, need, sha, unchanged, write

SEQUENCE = 'right,right-up,escape'


def active_project_processes(executables):
    args = ['/bin/ps', '-axo', 'pid=,command=']
    proc = subprocess.run(args, capture_output=True, text=True)
    need(proc.returncode == 0, 'cannot observe existing native processes')
    found = []
    for line in proc.stdout.splitlines():
        match = re.fullmatch(r'\s*(\d+)\s+(.+)', line)
        if not match:
            continue
        pid, command = match.groups()
        if (any(command == p or command.startswith(p + ' ') for p in executables)
                or command.startswith('/') and not command.startswith(('/bin/', '/usr/bin/')) and
                ('/Contents/MacOS/pe-aot-window' in command or
                 re.search(r'/outer-(?:reference|inline)-O[03](?: |$)', command))):
            found.append(dict(pid=int(pid), command=command))
    return dict(command=args, returncode=proc.returncode, matching_processes=found,
                all_process_stdout_retained=False)


def run(build, out, timeout=60):
    need(type(timeout) is int and 10 <= timeout <= 120, 'timeout must be 10..120 seconds')
    build = Path(build).resolve(strict=True)
    record = json.loads((build / 'build.json').read_bytes())
    need(record.get('schema') == 1 and record.get('status') == STATUS, 'diagnostic build receipt required')
    need(set(record['configurations']) == {'reference-O0', 'reference-O3', 'inline-O0', 'inline-O3'},
         'four explicit configurations required')
    need(build.parent == BASE and build == build.resolve(), 'diagnostic build must be a direct canonical child')
    for name, config in record['configurations'].items():
        executable = build / ('outer-' + name)
        need(config['executable'] == str(executable) and not executable.is_symlink() and
             record['artifacts'].get(str(executable)) == config['executable_sha256'],
             'executable is not the exact recorded build artifact')
        need(name == config['strategy'] + '-' + config['guest_optimization'] and
             config['runtime_optimization'] == 'O3', 'configuration identity mismatch')
        raw = executable.read_bytes()[:32]
        need(len(raw) == 32 and struct.unpack_from('<III', raw)[:2] == (0xfeedfacf, 0x100000c)
             and struct.unpack_from('<I', raw, 12)[0] == 2, 'ARM64 Mach-O executable required')
    unchanged(record['artifacts']); unchanged(record['inputs'])
    build_sha = sha(build / 'build.json')
    out = fresh(out); out.mkdir()
    sources = identities([Path(__file__), Path(__file__).with_name('build.py')])
    write(out / 'started.json', dict(schema=1, build=str(build), build_receipt_sha256=build_sha,
        timeout=timeout, sources=sources, sequence=SEQUENCE, timing_enabled=False, replay_enabled=False))
    executions = []
    executables = [v['executable'] for v in record['configurations'].values()]
    with (BASE / '.run.lock').open('a+') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            for name in ('reference-O0', 'inline-O0', 'reference-O3', 'inline-O3'):
                config = record['configurations'][name]
                before = active_project_processes(executables)
                need(not before['matching_processes'], 'another project App/diagnostic is running')
                case = out / name; case.mkdir()
                (case / 'data').mkdir(); (case / 'diagnostic').mkdir(); (case / 'cache/dxmt').mkdir(parents=True)
                write(case / 'processes-before.json', before)
                env = environment(case, images=True)
                env['PE_AOT_OUTER_OUTPUT'] = str(case / 'diagnostic')
                argv = [config['executable'], '--data-dir', str(case / 'data'),
                        '--timeout-ms', str((timeout - 5) * 1000), '--test-sequence', SEQUENCE]
                need(sha(argv[0]) == config['executable_sha256'], 'diagnostic executable changed')
                write(case / 'command.json', dict(argv=argv, cwd=str(case), env=env, timeout_seconds=timeout))
                timed_out = False
                interrupted = None
                with (case / 'stdout').open('xb') as stdout, (case / 'stderr').open('xb') as stderr:
                    process = subprocess.Popen(argv, cwd=case, env=env, stdout=stdout, stderr=stderr)
                    try:
                        write(case / 'launched.json', dict(pid=process.pid, executable=argv[0], unix_ns=time.time_ns()))
                        code = process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        process.terminate()
                        try:
                            code = process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill(); code = process.wait(timeout=5)
                    except BaseException as e:
                        interrupted = e
                        if process.poll() is None:
                            process.terminate()
                        try:
                            code = process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill(); code = process.wait(timeout=5)
                after = active_project_processes(executables)
                write(case / 'processes-after.json', after)
                files = identities([p for p in case.rglob('*') if p.is_file() and 'cache' not in p.relative_to(case).parts])
                observed = dict(configuration=name, pid=process.pid, returncode=code,
                    external_timeout=timed_out, interrupted=repr(interrupted) if interrupted else None,
                    directory=str(case), files=files,
                    executable_sha256=config['executable_sha256'])
                write(case / 'execution.json', observed)
                executions.append(dict(path=str(case / 'execution.json'), sha256=sha(case / 'execution.json')))
                if interrupted is not None:
                    raise interrupted
                need(code == 0 and not timed_out and not after['matching_processes'],
                     'diagnostic host did not exit cleanly; failure preserved')
                host = json.loads((case / 'stdout').read_bytes())
                need(host['outcome'] == 'PROCESS_EXITED' and host['proc_translated'] == 0,
                     'native guest process exit required')
                need(host['test_queue']['requested'] == host['test_queue']['posted'] == 3,
                     'declared diagnostic queue sequence not executed')
            unchanged(record['artifacts']); unchanged(record['inputs']); unchanged(sources)
            need(sha(build / 'build.json') == build_sha, 'build receipt changed during execution')
            result = dict(schema=1, status='OUTER_ABI_SINGLE_PASS_RUNS_OBSERVED_NOT_INDEPENDENTLY_ACCEPTED',
                build=str(build), build_receipt_sha256=build_sha, executions=executions, sources=sources,
                timing_enabled=False, replay_enabled=False, input_kind='TEST_QUEUE_NOT_OS_KEYBOARD',
                scope='Four full-runtime diagnostic executions; independent raw snapshot/event review required. No production App or performance claim.')
            write(out / 'run.json', result)
            return result
        except BaseException as e:
            write(out / 'failure.json', dict(status='FAILED_NOT_ACCEPTED', error=repr(e), executions=executions))
            raise
