"""Offline v6 installation with append-only attempts and owned stage workers.

The process protocol assumes pinned builders do not daemonize or escape their
worker's process group. Unknown observation is a refusal, never proof of exit.
Successful prefixes keep their original absolute paths across resume calls.
"""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback

from migration_install_v1 import runner as legacy
from portable_lifter_v1 import build as cpu_builder, tools as cpu_tools, deps as cpu_deps
from portable_graphics_v2 import build as graphics_builder, cache as graphics_cache_module
from window_switch_v1 import provider as switch_builder
from window_switch_v1 import profile as profiles
from migration_v6 import build as app_builder
from window_app_v1.noarg import spec
from portable_app_v1.lift import source_closure

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [Path(__file__).parent / n for n in ('__init__.py', '__main__.py', 'runner.py')]
PLAN_STATUS = 'OFFLINE_V6_INSTALL_PLAN_READY_NOT_DECODED_NOT_BUILT'
STATUS = 'OFFLINE_V6_APP_BUILT_VERIFIED_NOT_EXECUTED'
STAGES = ('cpu-build', 'switch-build', 'graphics-build', 'app-build', 'app-verify')
EXPECTED = {'cpu-build': 'CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED', 'switch-build': switch_builder.STATUS,
            'graphics-build': graphics_builder.STATUS, 'app-build': app_builder.STATUS,
            'app-verify': 'PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED'}
require = legacy.require
_sha = legacy._sha
_write = legacy._write
PROTOCOL = 'REGISTER_BEFORE_BUILDER_V1'


def _read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'regular JSON receipt required: ' + str(path))
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate receipt key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('non-finite receipt value: ' + value)
    return json.loads(path.read_bytes(), object_pairs_hook=unique, parse_constant=constant)


def _durable(path, value):
    path = Path(path)
    payload = _json_bytes(value)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=path.parent, prefix='.'+path.name+'.', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        # Atomic no-replace publication: observers never see partially written
        # JSON and an existing success/failure record is never overwritten.
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode()


def _implementation():
    # A conservative repository-source inventory also covers non-Python runtime
    # includes, patches, lock files and license resources not found by imports.
    suffixes = {'.c', '.cpp', '.h', '.mm', '.inc', '.patch', '.S'}
    result = {str(p.relative_to(ROOT)): _sha(p) for p in source_closure(SOURCES)}
    for directory, names, files in os.walk(ROOT):
        names[:] = sorted(n for n in names if n not in ('.git', 'build', 'work', '.local', '.evidence', '__pycache__'))
        for name in sorted(files):
            path = Path(directory) / name
            selected = (path.suffix in suffixes or name.startswith(('LICENSE', 'NOTICE')) or name.endswith('lock.json'))
            if not selected:
                continue
            require(path.is_file() and not path.is_symlink(), 'regular implementation resource required')
            result[str(path.relative_to(ROOT))] = _sha(path)
    require(all(str(p.relative_to(ROOT)) in result for p in SOURCES), 'installer source inventory incomplete')
    return dict(sorted(result.items()))


def _inputs(pe, profile):
    info = Path(profile).stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= 65536, 'profile regular-file/64KiB bound differs')
    data = profiles.read_input(pe)
    before = _sha(profile)
    value = profiles.read_profile(profile)
    require(_sha(profile) == before, 'profile changed while reading')
    normalized, image, _ = profiles.validate(data, value)
    analysis = profiles.analyze(data, normalized)
    require(analysis['status'] == 'ELIGIBLE_FOR_BUILD_NOT_DECODED', 'unsupported v6 profile')
    return data, normalized, dict(pe_sha256=hashlib.sha256(data).hexdigest(), profile_sha256=before,
                                 canonical_profile_sha256=hashlib.sha256(_json_bytes(normalized)).hexdigest(), analysis=analysis)


def _apple_preflight():
    result = legacy._apple_preflight()
    result['tool_sha256'] = {path: _sha(path) for path in sorted(set(result['tools'].values()))}
    python = Path(sys.executable).resolve(strict=True)
    result['python'] = str(python); result['python_sha256'] = _sha(python)
    return result


def _caches(cpu_cache, graphics_cache):
    remill = Path(cpu_cache) / 'remill.tar.gz'
    require(remill.is_file() and not remill.is_symlink() and _sha(remill) == cpu_builder.REMILL_ARCHIVE_SHA,
            'pinned Remill cache differs')
    return dict(cpu=dict(tools=cpu_tools.check_cache(cpu_cache), sources=cpu_deps.sources(cpu_cache),
                         remill=dict(path=str(remill), sha256=_sha(remill), bytes=remill.stat().st_size)),
                graphics=graphics_cache_module.check_cache(graphics_cache))


def _disk_budget(work_root, out):
    result = legacy._disk_budget(work_root, out)
    result['policy'] = ('6 GiB work plus 1 GiB evidence, including the small driver overlay; failed attempts '
                        'remain on disk and each resumed stage needs fresh space. This is conservative '
                        'headroom, not a measured peak guarantee; ENOSPC is a retained failure.')
    return result


def plan(cpu_cache, graphics_cache, pe, profile, identifier, work_root, out, jobs=2):
    require(type(jobs) is int and 1 <= jobs <= 2, 'jobs must be integer 1 or 2')
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'native Apple Silicon macOS required')
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required')
    paths = legacy._paths(cpu_cache, graphics_cache, pe, profile, work_root, out)
    _, _, inputs = _inputs(paths['pe'], paths['profile'])
    value = spec(dict(identifier=identifier, name='PE AOT Portable Window'))
    return dict(schema=2, status=PLAN_STATUS, paths={k: str(v) for k, v in paths.items()},
                jobs=jobs, identifier=value['identifier'], spec=value, inputs=inputs,
                disk=_disk_budget(paths['work_root'], paths['out']), apple=_apple_preflight(),
                caches=_caches(paths['cpu_cache'], paths['graphics_cache']), implementation=_implementation(),
                stages=list(STAGES), capability=switch_builder.CAPABILITY,
                scope='Pinned offline base CPU -> window switch overlay -> graphics -> v6 App -> static verify. '
                      'No download or App/guest/GPU execution. Resume revalidates identities and OS process groups.',
                guest_executions=0, gpu_executions=0, app_executions=0)


def _environment(plan_value, installation):
    require(_implementation() == plan_value['implementation'], 'implementation changed; do not reuse previous stages')
    p = plan_value['paths']
    _, _, inputs = _inputs(p['pe'], p['profile'])
    require(inputs == plan_value['inputs'], 'original PE/profile changed')
    require(_caches(p['cpu_cache'], p['graphics_cache']) == plan_value['caches'], 'offline caches changed')
    require(_apple_preflight() == plan_value['apple'], 'Apple SDK/tools or Python changed')
    frozen = Path(installation) / 'inputs'
    require(_sha(frozen / 'input.exe') == inputs['pe_sha256'], 'frozen PE changed')
    require(_sha(frozen / 'profile.json') == inputs['canonical_profile_sha256'], 'frozen profile bytes changed')
    value = profiles.read_profile(frozen / 'profile.json')
    require(profiles.validate((frozen / 'input.exe').read_bytes(), value)[0] == value, 'frozen profile invalid')
    require(value == profiles.read_profile(p['profile']), 'frozen profile differs from original profile')


def _group_state(pgid):
    require(type(pgid) is int and pgid > 1, 'invalid owned worker PGID')
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return 'ABSENT'
    except PermissionError:
        return 'UNOBSERVABLE'
    except OSError as error:
        if error.errno == errno.ESRCH:
            return 'ABSENT'
        return 'UNOBSERVABLE'
    return 'PRESENT'


def _lock(work_root, *, create=False):
    work = cpu_tools.real_path(work_root)
    if create:
        work.mkdir(parents=True, exist_ok=False)
    require(work.is_dir(), 'installation work root missing')
    filename = work / '.install.lock'
    flags = os.O_RDWR | os.O_NOFOLLOW
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    fd = os.open(filename, flags, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'regular installation lock required')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _lock_identity(fd, work_root):
    path = Path(work_root)/'.install.lock'
    info = os.fstat(fd); current = path.lstat()
    require(stat.S_ISREG(info.st_mode) and stat.S_ISREG(current.st_mode) and
            (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), 'lock descriptor/path inode differs')
    return dict(path=str(path), device=info.st_dev, inode=info.st_ino)


def _dispatch(stage, arguments):
    function = {'cpu-build': cpu_builder.build, 'switch-build': switch_builder.build,
                'graphics-build': graphics_builder.build, 'app-build': app_builder.build,
                'app-verify': app_builder.verify}[stage]
    return function(**arguments)


def worker(job_path, lock_fd):
    job_path = cpu_tools.real_path(job_path)
    job = _read(job_path)
    require(type(lock_fd) is int and lock_fd >= 0 and stat.S_ISREG(os.fstat(lock_fd).st_mode), 'inherited lock absent')
    expected_lock = job['lock_identity']
    require(_lock_identity(lock_fd, Path(expected_lock['path']).parent) == expected_lock, 'inherited work lock identity differs')
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    require(os.getpid() == os.getpgrp(), 'stage worker must own a new process group')
    # The lock is inherited before Python starts. Registration is durable before
    # any builder is invoked; a lost coordinator cannot hide a live child here.
    launched = dict(schema=1, stage=job['stage'], pid=os.getpid(), pgid=os.getpgrp(),
                    job_sha256=_sha(job_path), started_at=cpu_builder.now(), protocol=PROTOCOL,
                    lock_identity=expected_lock,
                    process_identity=dict(pid=os.getpid(), pgid=os.getpgrp(),
                                          argv=[sys.executable, '-B', '-m', 'migration_install_v2', '_worker', str(job_path)]))
    _durable(job['launched'], launched)
    try:
        returned = _dispatch(job['stage'], job['arguments'])
        _durable(job['worker_result'], dict(status='WORKER_RETURNED', stage=job['stage'],
                 job_sha256=_sha(job_path), returned=returned, finished_at=cpu_builder.now()))
        return 0
    except BaseException as error:
        _durable(job['worker_result'], dict(status='WORKER_FAILED', stage=job['stage'],
                 job_sha256=_sha(job_path), error_type=type(error).__name__, error=str(error),
                 traceback=traceback.format_exc(), finished_at=cpu_builder.now()))
        return 1


def _run_worker(job, lock_fd):
    job_path = Path(job['_job_path'])
    env = dict(os.environ)
    env.pop('PYTHONPATH', None); env.pop('PYTHONHOME', None)
    env.update(PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    argv = [str(Path(sys.executable).resolve()), '-B', '-m', 'migration_install_v2', '_worker',
            str(job_path), '--lock-fd', str(lock_fd)]
    with (job_path.parent / 'worker.stdout').open('xb') as stdout, (job_path.parent / 'worker.stderr').open('xb') as stderr:
        child = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                 start_new_session=True, pass_fds=(lock_fd,))
        while child.poll() is None and not Path(job['launched']).exists():
            time.sleep(0.05)
        if Path(job['launched']).exists():
            launched = _read(job['launched'])
            require(launched['pid'] == launched['pgid'] == child.pid and launched['job_sha256'] == _sha(job_path),
                    'worker registration identity differs')
            print(json.dumps(dict(status='LIVE_INSTALL_STAGE_WORKER', stage=job['stage'], pid=child.pid,
                                  pgid=child.pid, attempt=str(job_path.parent), launched=job['launched'])), flush=True)
        code = child.wait()
    state = _group_state(child.pid)
    return dict(returncode=code, pid=child.pid, pgid=child.pid, group_state=state,
                finished_at=cpu_builder.now(), stdout_sha256=_sha(job_path.parent/'worker.stdout'),
                stderr_sha256=_sha(job_path.parent/'worker.stderr'))


def _sdk(record, proposed):
    external = record['external_prerequisites']
    require(external['sdk'] == proposed['apple']['sdk'] and external['sdk_settings'] == proposed['apple']['sdk_settings'],
            'provider SDK differs from this installation')


def _accept(stage, returned, receipt, arguments, binding):
    require(type(returned) is dict and returned.get('status') == EXPECTED[stage], 'stage status differs: ' + stage)
    normalized = json.loads(json.dumps(returned))
    proposed = binding['plan']
    if stage in ('cpu-build', 'graphics-build'):
        prefix = Path(arguments['prefix']); provider = prefix/'provider.json'
        recorded = _read(receipt)
        require(recorded.get('status') == EXPECTED[stage] and recorded.get('prefix') == str(prefix) and
                recorded.get('provider_sha256') == _sha(provider), 'builder/provider receipt binding differs')
        installed = _read(provider)
        require(installed == normalized, 'provider return differs from installed manifest')
        if stage == 'cpu-build':
            verified, paths = cpu_builder.paths_for(prefix)
            require(verified == installed and cpu_deps.tree(paths['source']) == installed['source_tree'], 'CPU source inventory differs')
        else:
            paths = graphics_builder.paths_for(prefix)
            require(paths['provider_sha256'] == _sha(provider), 'graphics loader selected another provider')
        _sdk(installed, proposed)
    elif stage == 'switch-build':
        prefix = Path(arguments['prefix']); installed = _read(prefix/'provider.json')
        require(_read(receipt) == normalized == installed, 'switch return/outer/provider receipt differs')
        require(installed['prefix'] == str(prefix) and installed['provider'] == arguments['provider'] and
                installed['provider_sha256'] == _sha(Path(arguments['provider'])/'provider.json'), 'switch parent provider differs')
        checked, _ = switch_builder.paths_for(prefix)
        require(checked == installed, 'switch loader differs from installed provider')
    elif stage == 'app-build':
        recorded = _read(receipt)
        expected = dict(profile='window-switch-v6', original_input=arguments['pe'],
                        input_sha256=proposed['inputs']['pe_sha256'],
                        profile_sha256=proposed['inputs']['canonical_profile_sha256'],
                        cpu_prefix=arguments['cpu_prefix'], backend_prefix=arguments['backend_prefix'],
                        cpu_provider_sha256=_sha(Path(arguments['cpu_prefix'])/'provider.json'),
                        graphics_provider_sha256=_sha(Path(arguments['backend_prefix'])/'provider.json'),
                        spec=proposed['spec'], app=str(Path(arguments['out'])/'PE AOT Converted.app'))
        require(recorded == normalized and all(recorded.get(k) == v for k, v in expected.items()), 'App identity/parents/spec differs')
        require(app_builder.verify(arguments['out'])['status'] == EXPECTED['app-verify'], 'App verification failed')
    else:
        checked = app_builder.verify(arguments['out'])
        require(checked == normalized, 'App verify return differs from actual product')
    return normalized


def _session_records(installation, proposed):
    root = Path(installation)
    records = []
    for number, path in enumerate(sorted((root/'sessions').glob('*.json')), 1):
        require(path.name == f'{number:04d}.json', 'session sequence differs')
        value = _read(path)
        require(value['sequence'] == number and value['installation'] == str(root) and
                value['plan_sha256'] == _sha(root/'plan.json'), 'session/plan binding differs')
        session = cpu_tools.real_path(value['directory'])
        require(_read(session/'session.json') == value, 'session/index receipt differs')
        records.append(session)
    require(records and records[0] == root, 'initial installation session missing')
    return records


def _attempts(sessions):
    result = []
    for session in sessions:
        for directory in sorted((session/'attempts').iterdir()):
            require(directory.is_dir() and not directory.is_symlink(), 'invalid attempt directory')
            job = _read(directory/'job.json')
            require(job['stage'] in STAGES and Path(job['launched']).parent == directory and
                    Path(job['worker_result']).parent == directory and Path(job['worker_exit']).parent == directory,
                    'attempt receipt paths differ')
            require(directory.name.startswith(job['stage']+'-'), 'attempt/stage name mismatch')
            result.append((directory, job))
    result.sort(key=lambda item: (STAGES.index(item[1]['stage']), int(item[0].name.rsplit('-', 1)[1])))
    return result


def _completed(sessions, proposed, installation):
    accepted = {}; dependencies = {}
    for directory, job in _attempts(sessions):
        stage = job['stage']
        require(job.get('schema') == 1 and job.get('expected_status') == EXPECTED[stage] and
                job.get('plan_sha256') == _sha(Path(installation)/'plan.json'), 'attempt/plan capability binding differs')
        require(job.get('lock_identity') == _read(Path(installation)/'work-identity.json')['lock_identity'],
                'attempt work lock identity differs')
        prefix = Path(proposed['paths']['work_root'])/'attempts'/directory.name
        expected_arguments = _arguments(stage, prefix, directory/'builder', accepted, proposed, installation)
        require(job['arguments'] == expected_arguments, 'attempt arguments differ from allocated stage and accepted parents')
        expected_receipt = None if stage == 'app-verify' else str(Path(expected_arguments['out'])/'result.json')
        require(job['builder_receipt'] == expected_receipt, 'attempt builder receipt path differs')
        launched_path = Path(job['launched'])
        if launched_path.exists():
            launched = _read(launched_path)
            require(launched.get('protocol') == PROTOCOL and launched['stage'] == job['stage'] and
                    type(launched['pid']) is int and launched['pid'] == launched['pgid'] and
                    launched.get('lock_identity') == job['lock_identity'] and
                    launched['job_sha256'] == _sha(directory/'job.json'), 'worker launch identity differs')
            require(_group_state(launched['pgid']) == 'ABSENT', 'previous worker group is live or cannot be observed')
        else:
            # With the inherited lock acquired and the pinned registration-before-
            # builder protocol, a dead worker without registration ran no builder.
            require(not (directory/'accepted.json').exists() and not Path(job['worker_result']).exists(),
                    'unregistered attempt contains builder results')
            generated = [] if stage == 'app-verify' else [Path(expected_arguments['out'])]
            if 'prefix' in expected_arguments:
                generated.append(Path(expected_arguments['prefix']))
            require(not any(os.path.lexists(path) for path in generated),
                    'unregistered attempt contains builder outputs; child state unknown')
            continue
        marker = directory/'accepted.json'
        if not marker.exists():
            continue
        value = _read(marker)
        require(stage not in accepted and STAGES[len(accepted)] == stage, 'accepted stage order/duplication differs')
        require(value['job_sha256'] == _sha(directory/'job.json') and value['arguments'] == job['arguments'] and
                value['dependencies'] == dependencies, 'accepted stage identity or dependencies differ')
        require(_sha(job['worker_result']) == value['worker_result_sha256'], 'worker result changed')
        require(_sha(job['worker_exit']) == value['worker_exit_sha256'] and
                _sha(job['launched']) == value['launched_sha256'], 'worker exit/registration changed')
        ended = _read(job['worker_exit']); worker_result = _read(job['worker_result'])
        require(ended['returncode'] == 0 and ended['group_state'] == 'ABSENT' and
                ended['pid'] == ended['pgid'] == launched['pid'] and
                worker_result['status'] == 'WORKER_RETURNED' and worker_result['stage'] == stage and
                worker_result['job_sha256'] == _sha(directory/'job.json'), 'accepted worker did not return normally')
        receipt = Path(job['builder_receipt']) if job['builder_receipt'] else None
        if receipt:
            require(_sha(receipt) == value['builder_receipt_sha256'], 'builder receipt changed')
        actual = _accept(stage, worker_result['returned'], receipt, job['arguments'],
                         dict(plan=proposed, installation=str(installation)))
        require(actual == value['returned'], 'accepted return changed')
        accepted[stage] = dict(directory=str(directory), **value)
        if stage in ('cpu-build','switch-build','graphics-build'):
            provider = str(Path(job['arguments']['prefix'])/'provider.json')
            dependencies[provider] = _sha(provider)
    return accepted, dependencies


def _arguments(stage, prefix, builder_out, completed, proposed, installation):
    paths = proposed['paths']; jobs = proposed['jobs']
    if stage == 'cpu-build':
        return dict(prefix=str(prefix), cache=paths['cpu_cache'], out=str(builder_out), jobs=jobs)
    if stage == 'switch-build':
        return dict(provider=completed['cpu-build']['arguments']['prefix'], prefix=str(prefix), out=str(builder_out), jobs=jobs)
    if stage == 'graphics-build':
        return dict(prefix=str(prefix), cache_path=paths['graphics_cache'], out=str(builder_out), jobs=jobs)
    if stage == 'app-build':
        return dict(pe=str(Path(installation)/'inputs/input.exe'), profile=_read(Path(installation)/'inputs/profile.json'),
                    identifier=proposed['identifier'], cpu_prefix=completed['switch-build']['arguments']['prefix'],
                    backend_prefix=completed['graphics-build']['arguments']['prefix'], out=str(prefix))
    return dict(out=completed['app-build']['arguments']['out'])


def _new_session(installation, out, proposed):
    installation, out = Path(installation), Path(out)
    if out != installation:
        require(not os.path.lexists(out), 'new absent resume evidence directory required')
        require(not out.is_relative_to(cpu_builder.OLD_WORK), 'resume evidence must be outside historical work')
        protected = [Path(v) for k,v in proposed['paths'].items() if k in ('cpu_cache','graphics_cache','work_root')]
        protected.extend(_session_records(installation, proposed))
        protected.extend(Path(proposed['paths'][k]) for k in ('pe', 'profile'))
        for p in protected:
            require(not out.is_relative_to(p) and not p.is_relative_to(out), 'resume evidence overlaps cache/work/session')
        out.mkdir(parents=True, exist_ok=False)
    else:
        (out/'sessions').mkdir()
    sequence = len(list((installation/'sessions').glob('*.json'))) + 1
    value = dict(schema=1, sequence=sequence, installation=str(installation), directory=str(out),
                 plan_sha256=_sha(installation/'plan.json'), invocation='install' if out == installation else 'resume',
                 started_at=cpu_builder.now())
    _durable(out/'session.json', value)
    _durable(installation/'sessions'/f'{sequence:04d}.json', value)
    (out/'attempts').mkdir()
    return out


def _execute(proposed, installation, out, lock_fd):
    stage = 'revalidation'; completed = {}; result = dict(schema=2, status='INSTALL_FAILED',
        installation=str(installation), session=str(out), plan_sha256=_sha(Path(installation)/'plan.json'),
        guest_executions=0, gpu_executions=0, app_executions=0, automatic_retry=False)
    try:
        sessions = _session_records(installation, proposed)
        require(_lock_identity(lock_fd, proposed['paths']['work_root']) ==
                _read(Path(installation)/'work-identity.json')['lock_identity'], 'work lock identity changed')
        _environment(proposed, installation)
        historical = []
        for directory, job in _attempts(sessions):
            if not Path(job['launched']).exists():
                continue
            launched = _read(job['launched'])
            require(launched['job_sha256'] == _sha(directory/'job.json') and
                    launched.get('protocol') == PROTOCOL and launched['pid'] == launched['pgid'],
                    'historical worker registration differs')
            observation = dict(attempt=str(directory), job_sha256=_sha(directory/'job.json'),
                               pid=launched['pid'], pgid=launched['pgid'],
                               observed_state=_group_state(launched['pgid']), observed_at=cpu_builder.now())
            historical.append(observation)
        _durable(Path(out)/'historical-groups.json', dict(schema=1, installation=str(installation),
                 session=str(out), observations=historical,
                 scope='Actual process-group observations before any new stage; PRESENT/UNOBSERVABLE refuse retry'))
        require(all(row['observed_state'] == 'ABSENT' for row in historical),
                'historical process group is live or cannot be observed')
        completed, dependencies = _completed(sessions, proposed, installation)
        reused = list(completed)
        _durable(Path(out)/'revalidated.json', dict(completed_stages=reused, dependencies=dependencies,
                  scope='Reopened actual provider/artifact/source/cache/SDK identities; no native/App execution'))
        for stage in STAGES[len(completed):]:
            require(_lock_identity(lock_fd, proposed['paths']['work_root']) ==
                    _read(Path(installation)/'work-identity.json')['lock_identity'], 'work lock identity changed')
            _environment(proposed, installation)
            completed, dependencies = _completed(sessions, proposed, installation)
            index = sum(1 for _, job in _attempts(sessions) if job['stage'] == stage) + 1
            attempt = Path(out)/'attempts'/f'{stage}-{index:04d}'
            attempt.mkdir()
            prefix = Path(proposed['paths']['work_root'])/'attempts'/attempt.name
            require(not os.path.lexists(prefix), 'fresh stage prefix required')
            args = _arguments(stage, prefix, attempt/'builder', completed, proposed, installation)
            receipt = None if stage == 'app-verify' else (Path(args['out'])/'result.json')
            job = dict(schema=1, stage=stage, arguments=args, expected_status=EXPECTED[stage],
                       builder_receipt=str(receipt) if receipt else None,
                       worker_result=str(attempt/'worker-result.json'), launched=str(attempt/'launched.json'),
                       worker_exit=str(attempt/'worker-exit.json'), plan_sha256=_sha(Path(installation)/'plan.json'),
                       lock_identity=_lock_identity(lock_fd, proposed['paths']['work_root']))
            _durable(attempt/'job.json', job)
            observed = _run_worker(dict(job, _job_path=str(attempt/'job.json')), lock_fd)
            _durable(job['worker_exit'], observed)
            require(observed['group_state'] == 'ABSENT', 'worker group remains live or unobservable')
            require(observed['returncode'] == 0, 'stage worker did not exit successfully: ' + stage)
            returned = _read(job['worker_result'])
            require(returned['status'] == 'WORKER_RETURNED' and returned['stage'] == stage and
                    returned['job_sha256'] == _sha(attempt/'job.json'), 'worker result identity differs')
            accepted = _accept(stage, returned['returned'], receipt, args,
                               dict(plan=proposed, installation=str(installation)))
            _environment(proposed, installation)
            require(_lock_identity(lock_fd, proposed['paths']['work_root']) ==
                    _read(Path(installation)/'work-identity.json')['lock_identity'], 'work lock identity changed during worker')
            previous, current_dependencies = _completed(sessions, proposed, installation)
            require(list(previous) == list(completed) and current_dependencies == dependencies, 'prior stages changed during worker')
            _durable(attempt/'accepted.json', dict(schema=1, stage=stage, arguments=args, dependencies=dependencies,
                      job_sha256=_sha(attempt/'job.json'), worker_result_sha256=_sha(job['worker_result']),
                      worker_exit_sha256=_sha(job['worker_exit']), launched_sha256=_sha(job['launched']),
                      builder_receipt_sha256=_sha(receipt) if receipt else None, returned=accepted,
                      accepted_at=cpu_builder.now()))
        completed, dependencies = _completed(sessions, proposed, installation)
        require(list(completed) == list(STAGES), 'incomplete accepted stage closure')
        product = completed['app-build']['arguments']['out']
        result.update(status=STATUS, stage='complete', completed_stages=list(completed), reused_stages=reused,
                      accepted_attempts={k:v['directory'] for k,v in completed.items()}, dependencies=dependencies,
                      product=product, product_sha256=_sha(Path(product)/'result.json'),
                      app=completed['app-build']['returned']['app'])
    except BaseException as error:
        result.update(status='INSTALL_CANCELLED_CHILD_STATE_UNKNOWN' if isinstance(error,(KeyboardInterrupt,SystemExit)) else 'INSTALL_FAILED',
                      stage=stage, completed_stages=list(completed), error_type=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc(), child_policy='No automatic retry; future resume requires installation lock and actual process-group absence')
        _durable(Path(out)/'result.json', dict(result, finished_at=cpu_builder.now()))
        if isinstance(error,(KeyboardInterrupt,SystemExit)):
            raise
        return result
    _durable(Path(out)/'result.json', dict(result, finished_at=cpu_builder.now()))
    return result


def install(cpu_cache, graphics_cache, pe, profile, identifier, work_root, out, jobs=2):
    proposed = plan(cpu_cache, graphics_cache, pe, profile, identifier, work_root, out, jobs)
    paths = legacy._paths(cpu_cache, graphics_cache, pe, profile, work_root, out)
    evidence = paths['out']; evidence.mkdir(parents=True, exist_ok=False)
    _durable(evidence/'plan.json', proposed)
    frozen = evidence/'inputs'; frozen.mkdir()
    data, value, inputs = _inputs(paths['pe'], paths['profile'])
    require(inputs == proposed['inputs'], 'input changed after plan')
    (frozen/'input.exe').write_bytes(data); _durable(frozen/'profile.json', value)
    snapshots = evidence/'sources'; snapshots.mkdir()
    for rel, sha in proposed['implementation'].items():
        dst = snapshots/rel; dst.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(ROOT/rel, dst)
        require(_sha(dst) == sha, 'implementation changed while freezing')
    lock_fd = _lock(paths['work_root'], create=True)
    try:
        _durable(evidence/'work-identity.json', dict(schema=1, work_root=str(paths['work_root']),
                 lock_identity=_lock_identity(lock_fd, paths['work_root'])))
        (paths['work_root']/'attempts').mkdir()
        _new_session(evidence, evidence, proposed)
        return _execute(proposed, evidence, evidence, lock_fd)
    finally:
        os.close(lock_fd)


def resume(installation, out):
    installation = cpu_tools.real_path(installation); out = cpu_tools.real_path(out)
    proposed = _read(installation/'plan.json')
    require(proposed.get('schema') == 2 and proposed.get('status') == PLAN_STATUS and
            proposed.get('capability') == switch_builder.CAPABILITY and proposed.get('stages') == list(STAGES), 'unsupported installation plan')
    require(proposed['paths']['out'] == str(installation), 'initial installation path differs')
    _disk_budget(Path(proposed['paths']['work_root']), out)
    lock_fd = _lock(proposed['paths']['work_root'])
    try:
        identity = _read(installation/'work-identity.json')
        require(identity['work_root'] == proposed['paths']['work_root'] and
                _lock_identity(lock_fd, proposed['paths']['work_root']) == identity['lock_identity'], 'installation lock inode changed')
        # Reject changed source/cache/SDK/inputs and live prior groups BEFORE
        # allocating a new session or any retry prefix.
        _environment(proposed, installation)
        _completed(_session_records(installation, proposed), proposed, installation)
        _new_session(installation, out, proposed)
        return _execute(proposed, installation, out, lock_fd)
    finally:
        os.close(lock_fd)
