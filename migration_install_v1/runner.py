"""Thin offline CPU -> graphics -> v5 App orchestration.

The existing builders own their subprocesses and raw command records. This
module never waits for, signals, retries, or resumes those subprocesses. A
cancelled invocation must not be interpreted as proof that they have stopped.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import traceback

from portable_lifter_v1 import build as cpu_builder, tools as cpu_tools, deps as cpu_deps
from portable_graphics_v2 import build as graphics_builder, cache as graphics_cache_module
from migration_v5 import build as app_builder
from window_profile_v1 import profile as profiles
from window_app_v1.noarg import spec

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [Path(__file__).parent / name for name in ('__init__.py', '__main__.py', 'runner.py')]
PLAN_STATUS = 'OFFLINE_INSTALL_PLAN_READY_NOT_DECODED_NOT_BUILT'
STATUS = 'OFFLINE_V5_APP_BUILT_VERIFIED_NOT_EXECUTED'
WORK_BYTES = 6 * 1024**3
EVIDENCE_BYTES = 1024**3


def require(value, message):
    if not value:
        raise ValueError(message)


def _sha(path):
    return cpu_builder.digest(Path(path))


def _write(path, value):
    cpu_builder.write_json(Path(path), value)


def _stage_receipt(stage, returned, receipt, destinations, expected_app=None):
    """Bind existing builder return values to their own final receipts."""
    if receipt is None:
        return
    require(receipt.is_file() and not receipt.is_symlink(), 'builder success receipt missing: ' + stage)
    recorded = json.loads(receipt.read_bytes())
    normalized = json.loads(json.dumps(returned))
    if stage in ('cpu-build', 'graphics-build'):
        prefix = Path(destinations['cpu_prefix' if stage == 'cpu-build' else 'graphics_prefix'])
        provider_path = prefix / 'provider.json'
        require(provider_path.is_file() and not provider_path.is_symlink(), 'provider manifest absent: ' + stage)
        require(type(recorded) is dict and recorded.get('status') == returned['status'] and
                recorded.get('prefix') == str(prefix) and recorded.get('provider_sha256') == _sha(provider_path),
                'builder receipt does not bind this provider: ' + stage)
        require(json.loads(provider_path.read_bytes()) == normalized, 'returned provider differs from installed manifest: ' + stage)
    else:
        require(recorded == normalized, 'returned App result differs from recorded product')
        require(type(expected_app) is dict and bool(expected_app) and
                all(recorded.get(key) == value for key, value in expected_app.items()),
                'App receipt does not bind this installation input/profile/providers/spec/output')


def _unchanged_providers(providers):
    for path, expected in providers.items():
        require(Path(path).is_file() and not Path(path).is_symlink() and _sha(path) == expected,
                'accepted provider changed between installation stages: ' + path)


def _query(argv):
    """Only bounded Apple tool discovery, with the builders' clean environment."""
    env = {key: os.environ[key] for key in ('HOME', 'TMPDIR') if key in os.environ}
    env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
    result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, env=env, timeout=15)
    return dict(argv=list(map(str, argv)), returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)


def _apple_preflight():
    commands = []

    def path(argv, directory=False):
        row = _query(argv)
        commands.append(row)
        require(type(row.get('returncode')) is int and row['returncode'] == 0, 'Apple discovery failed: ' + str(argv))
        value = row.get('stdout')
        require(type(value) is str and len(value.strip().splitlines()) == 1, 'Apple discovery returned no unique path')
        selected = Path(value.strip())
        require(selected.is_absolute(), 'Apple discovery returned a relative path')
        selected = selected.resolve(strict=True)
        require(selected.is_dir() if directory else selected.is_file(), 'Apple prerequisite has incorrect file type')
        if not directory:
            require(os.access(selected, os.X_OK), 'Apple tool is not executable: ' + str(selected))
        return selected

    developer = path(['/usr/bin/xcode-select', '-p'], directory=True)
    sdk = path(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], directory=True)
    require(sdk.is_relative_to(developer), 'SDK does not belong to selected Xcode')
    require(path(['/usr/bin/xcrun', '--show-sdk-path'], directory=True) == sdk,
            'CPU and graphics builders would select different SDKs')
    settings = {name: _sha(sdk / name) for name in ('SDKSettings.json', 'SDKSettings.plist') if (sdk / name).is_file()}
    require(settings, 'SDK settings identity absent')
    tools = {}
    for name in ('clang', 'clang++', 'ar', 'ld', 'metal', 'metallib'):
        selected = path(['/usr/bin/xcrun', '--sdk', 'macosx', '--find', name])
        tools[name] = str(selected)
    for name in ('touch', 'xxd', 'patch', 'git', 'install_name_tool', 'codesign', 'nm', 'lipo'):
        selected = Path('/usr/bin') / name
        require(selected.is_file() and os.access(selected, os.X_OK), 'system build tool absent: ' + name)
        tools[name] = str(selected)
    return dict(developer=str(developer), sdk=str(sdk), sdk_settings=settings, tools=tools, queries=commands)


def _paths(cpu_cache, graphics_cache, pe, profile, work_root, out):
    values = {key: cpu_tools.real_path(value) for key, value in dict(cpu_cache=cpu_cache,
              graphics_cache=graphics_cache, pe=pe, profile=profile, work_root=work_root, out=out).items()}
    for name in ('cpu_cache', 'graphics_cache'):
        require(values[name].is_dir(), name + ' must be an existing real directory')
    for name in ('pe', 'profile'):
        require(stat.S_ISREG(values[name].stat().st_mode), name + ' must be a regular file')
    for name in ('work_root', 'out'):
        require(not os.path.lexists(values[name]), name + ' must be absent, including symlinks')
        require(not values[name].is_relative_to(cpu_builder.OLD_WORK), name + ' must be outside historical work')
    roots = [values[name] for name in ('work_root', 'out', 'cpu_cache', 'graphics_cache')]
    for index, left in enumerate(roots):
        for right in roots[index + 1:]:
            require(not left.is_relative_to(right) and not right.is_relative_to(left), 'cache/work/evidence roots must be disjoint')
    for name in ('pe', 'profile'):
        for output in roots[:2]:
            require(not values[name].is_relative_to(output) and not output.is_relative_to(values[name]), 'output overlaps an input')
    return values


def _disk_budget(work_root, out):
    groups = {}
    for label, destination, required in (('work_root', work_root, WORK_BYTES), ('out', out, EVIDENCE_BYTES)):
        parent = Path(destination).parent
        while not parent.exists():
            parent = parent.parent
        require(parent.is_dir(), 'output ancestor must be a directory')
        device = parent.stat().st_dev
        group = groups.setdefault(device, dict(device=device, probe_path=str(parent), destinations=[], required_bytes=0))
        group['destinations'].append(dict(name=label, path=str(destination), budget_bytes=required))
        group['required_bytes'] += required
    for group in groups.values():
        group['available_bytes'] = shutil.disk_usage(group['probe_path']).free
        require(group['available_bytes'] >= group['required_bytes'], 'insufficient free space for conservative installation budget: ' + str(group))
    return dict(policy='6 GiB work plus 1 GiB evidence for this fixed profile; summed on a shared filesystem. Based on observed approximately 3.27 GiB providers and 195 MB product, with headroom; not a measured peak guarantee. ENOSPC remains a build failure.',
                filesystems=list(groups.values()))


def _inputs(pe, profile):
    profile_info = Path(profile).stat()
    require(stat.S_ISREG(profile_info.st_mode) and 0 <= profile_info.st_size <= profiles.MAX_PROFILE,
            'profile must be a regular file of at most 64 KiB before hashing')
    data = profiles.read_input(pe)
    before = _sha(profile)
    value = profiles.read_profile(profile)
    require(_sha(profile) == before, 'profile changed while reading')
    analysis = profiles.analyze(data, value)
    require(analysis['status'] == 'ELIGIBLE_FOR_BUILD_NOT_DECODED', 'PE/profile is unsupported: ' + str(analysis.get('error')))
    return data, value, dict(pe_sha256=hashlib.sha256(data).hexdigest(), profile_sha256=before, analysis=analysis)


def plan(cpu_cache, graphics_cache, pe, profile, identifier, work_root, out, jobs=2):
    require(type(jobs) is int and 1 <= jobs <= 2, 'jobs must be integer 1 or 2')
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'native Apple Silicon macOS required')
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required')
    specification = spec(dict(identifier=identifier, name='PE AOT Portable Window'))
    paths = _paths(cpu_cache, graphics_cache, pe, profile, work_root, out)
    _, _, inputs = _inputs(paths['pe'], paths['profile'])
    disk = _disk_budget(paths['work_root'], paths['out'])
    apple = _apple_preflight()
    cpu_cache_result = dict(tools=cpu_tools.check_cache(paths['cpu_cache']), sources=cpu_deps.sources(paths['cpu_cache']))
    remill = paths['cpu_cache'] / 'remill.tar.gz'
    require(remill.is_file() and not remill.is_symlink() and _sha(remill) == cpu_builder.REMILL_ARCHIVE_SHA,
            'Remill archive differs from frozen CPU cache contract')
    cpu_cache_result['remill'] = dict(path=str(remill), sha256=cpu_builder.REMILL_ARCHIVE_SHA, bytes=remill.stat().st_size)
    graphics_cache_result = graphics_cache_module.check_cache(paths['graphics_cache'])
    work, evidence = paths['work_root'], paths['out']
    destinations = dict(cpu_prefix=str(work / 'cpu'), graphics_prefix=str(work / 'graphics'),
                        cpu_build=str(evidence / 'cpu-build'), graphics_build=str(evidence / 'graphics-build'),
                        product=str(evidence / 'product'))
    return dict(schema=1, status=PLAN_STATUS, paths={key: str(value) for key, value in paths.items()}, jobs=jobs,
                identifier=specification['identifier'], inputs=inputs, apple=apple, disk=disk,
                caches=dict(cpu=cpu_cache_result, graphics=graphics_cache_result), destinations=destinations,
                stages=['cpu-build', 'graphics-build', 'app-build', 'app-verify'],
                implementation={str(p.relative_to(ROOT)): _sha(p) for p in SOURCES},
                scope='Existing bounded v5 contract. Profile admission is not instruction decoding or compatibility proof. Offline only; no automatic retry/resume; no App/guest/GPU execution.',
                guest_executions=0, gpu_executions=0, app_executions=0)


def install(cpu_cache, graphics_cache, pe, profile, identifier, work_root, out, jobs=2):
    proposed = plan(cpu_cache, graphics_cache, pe, profile, identifier, work_root, out, jobs)
    paths = _paths(cpu_cache, graphics_cache, pe, profile, work_root, out)
    evidence = paths['out']
    # Atomic mkdir refuses any destination created after the read-only plan.
    evidence.mkdir(parents=True, exist_ok=False)
    stage = 'initialization'
    completed = []
    result = dict(schema=1, status='INSTALL_FAILED', stage=stage, plan=str(evidence / 'plan.json'),
                  completed_stages=completed, guest_executions=0, gpu_executions=0, app_executions=0,
                  child_cleanup='NOT_MANAGED_BY_INSTALLER', automatic_retry=False)
    try:
        _write(evidence / 'plan.json', proposed)
        sources = cpu_builder.source_snapshot(evidence, SOURCES)
        require(sources == proposed['implementation'], 'installer implementation changed after planning')
        paths['work_root'].mkdir(parents=True, exist_ok=False)
        data, profile_value, inputs = _inputs(paths['pe'], paths['profile'])
        require(inputs == proposed['inputs'], 'PE/profile changed after planning')
        snapshot = evidence / 'inputs'; snapshot.mkdir()
        frozen_pe = snapshot / 'input.exe'; frozen_pe.write_bytes(data)
        frozen_profile = snapshot / 'profile.json'
        _write(frozen_profile, profile_value)
        profile_snapshot_sha = _sha(frozen_profile)
        _write(evidence / 'started.json', dict(status='INSTALL_STARTED_NOT_EXECUTED', plan_sha256=_sha(evidence / 'plan.json'),
                                             started_at=cpu_builder.now(), input_snapshot_sha256=_sha(frozen_pe),
                                             profile_snapshot_sha256=profile_snapshot_sha))
        d = proposed['destinations']
        bound_providers = {}
        operations = [
            ('cpu-build', cpu_builder.build, dict(prefix=d['cpu_prefix'], cache=str(paths['cpu_cache']), out=d['cpu_build'], jobs=jobs),
             'CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED', Path(d['cpu_build']) / 'result.json'),
            ('graphics-build', graphics_builder.build, dict(prefix=d['graphics_prefix'], cache_path=str(paths['graphics_cache']), out=d['graphics_build'], jobs=jobs),
             graphics_builder.STATUS, Path(d['graphics_build']) / 'result.json'),
            ('app-build', app_builder.build, dict(pe=str(frozen_pe), profile=profile_value, identifier=identifier,
             cpu_prefix=d['cpu_prefix'], backend_prefix=d['graphics_prefix'], out=d['product']),
             app_builder.STATUS, Path(d['product']) / 'result.json'),
            ('app-verify', app_builder.verify, dict(out=d['product']), 'PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED', None),
        ]
        for stage, function, arguments, expected, receipt in operations:
            result['stage'] = stage
            cpu_builder.check_sources(sources)
            _unchanged_providers(bound_providers)
            expected_app = None
            if stage == 'app-build':
                expected_app = dict(original_input=str(frozen_pe), input_sha256=inputs['pe_sha256'],
                    profile_sha256=profile_snapshot_sha, cpu_prefix=d['cpu_prefix'], backend_prefix=d['graphics_prefix'],
                    cpu_provider_sha256=bound_providers[str(Path(d['cpu_prefix']) / 'provider.json')],
                    graphics_provider_sha256=bound_providers[str(Path(d['graphics_prefix']) / 'provider.json')],
                    spec=spec(dict(identifier=identifier, name='PE AOT Portable Window')),
                    app=str(Path(d['product']) / 'PE AOT Converted.app'))
            started = dict(stage=stage, started_at=cpu_builder.now(), arguments=arguments, expected_status=expected)
            _write(evidence / (stage + '.started.json'), started)
            returned = function(**arguments)
            require(type(returned) is dict, 'builder returned no result: ' + stage)
            row = dict(stage=stage, finished_at=cpu_builder.now(), returned_status=returned.get('status'), expected_status=expected)
            if receipt is not None and receipt.is_file():
                row.update(receipt=str(receipt), receipt_sha256=_sha(receipt))
            _write(evidence / (stage + '.result.json'), row)
            require(returned.get('status') == expected, 'stage did not succeed: ' + stage + ': ' + str(returned.get('status')))
            _stage_receipt(stage, returned, receipt, d, expected_app)
            _unchanged_providers(bound_providers)
            if stage in ('cpu-build', 'graphics-build'):
                provider_path = str(Path(d['cpu_prefix' if stage == 'cpu-build' else 'graphics_prefix']) / 'provider.json')
                bound_providers[provider_path] = _sha(provider_path)
            completed.append(stage)
        cpu_builder.check_sources(sources)
        require(_sha(frozen_pe) == inputs['pe_sha256'], 'frozen PE changed during install')
        require(_sha(frozen_profile) == profile_snapshot_sha, 'frozen profile changed during install')
        product = json.loads((Path(d['product']) / 'result.json').read_bytes())
        result.update(status=STATUS, stage='complete', app=product['app'], product=d['product'],
                      product_sha256=_sha(Path(d['product']) / 'result.json'),
                      cpu_provider_sha256=bound_providers[str(Path(d['cpu_prefix']) / 'provider.json')],
                      graphics_provider_sha256=bound_providers[str(Path(d['graphics_prefix']) / 'provider.json')])
    except BaseException as error:
        cancelled = isinstance(error, (KeyboardInterrupt, SystemExit))
        result.update(status='INSTALL_CANCELLED_CHILD_STATE_UNKNOWN' if cancelled else 'INSTALL_FAILED', stage=stage,
                      error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc(),
                      child_state='UNKNOWN; no cancellation cleanup or termination is claimed' if cancelled else 'NOT_OBSERVED_BY_INSTALLER')
        _write(evidence / 'result.json', {**result, 'finished_at': cpu_builder.now()})
        if cancelled:
            raise
        return result
    _write(evidence / 'result.json', {**result, 'finished_at': cpu_builder.now()})
    return result
