"""Diagnose independent v7 prerequisites; never create an installation.

This is a report over the installer's existing checks, not a saved plan, build
authorization, or substitute for validation at installation time. Checks are
point-in-time observations. Only bounded Apple discovery queries may execute.
"""
import hashlib
import importlib
from pathlib import Path
import platform
import sys

READY = 'V7_PREREQUISITES_READY_NOT_DECODED_NOT_BUILT'
FAILED = 'V7_PREREQUISITES_FAILED_NOT_BUILT'
ROOT = Path(__file__).resolve().parents[1]
SOURCES = tuple(Path(__file__).parent / n for n in
                ('__init__.py', '__main__.py', 'doctor.py'))
RECOVERY = {
    'host_python': 'Use native Apple Silicon macOS and Python >= 3.13.',
    'validator_import': 'Restore the complete public source tree and its Python import dependencies.',
    'arguments': 'Use jobs 1 or 2 and an App identifier accepted by the v7 spec.',
    'paths': 'Use existing regular inputs/caches and absent, mutually disjoint work/evidence destinations; avoid symlink paths.',
    'disk': 'Provide the installer disk reservation on the destination filesystem(s); failed attempts also consume space.',
    'pe_profile': 'Use a matching schema2 win32-d3d11-tile-switch-v1 PE/profile; repair the input rather than bypass admission.',
    'apple': 'Select a complete Xcode/macOS SDK with clang, metal and metallib; rerun the reported discovery command.',
    'cpu_cache': 'Restore the pinned CPU archives and metadata using migration_cache_v2 prepare-cpu in a new cache directory.',
    'graphics_cache': 'Restore the pinned graphics cache using portable_graphics_v2 prepare in a new cache directory.',
    'lookup_runtime': 'Restore the three frozen runtime/transaction/lookup files required by inline-instruction-search-v1; do not rewrite their expected hashes.',
    'implementation': 'Restore the matching source, patches, lock files, headers and licenses from the source release.',
    'doctor_source_snapshot': 'Restore readable regular doctor source files from the same release.',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def host_python():
    value = dict(system=platform.system(), machine=platform.machine(),
                 python=list(sys.version_info[:3]), executable=sys.executable)
    require(value['system'] == 'Darwin' and value['machine'] == 'arm64',
            'native Apple Silicon macOS required; observed ' + repr(value))
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required; observed ' + repr(value))
    return value


def source_snapshot():
    identities = {}
    for path in SOURCES:
        require(path.is_file() and not path.is_symlink(), 'regular readable doctor source required: ' + str(path))
        identities[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return identities


def validator_import():
    """Resolve the current installation contract, never silently use v2/v6."""
    module = importlib.import_module('migration_install_v3.runner')
    require(module.__name__ == 'migration_install_v3.runner' and
            module.PLAN_STATUS == 'OFFLINE_V7_INSTALL_PLAN_READY_NOT_DECODED_NOT_BUILT' and
            module.STATUS == 'OFFLINE_V7_APP_BUILT_VERIFIED_NOT_EXECUTED' and
            module.app_builder.__name__ == 'migration_v7.build',
            'v7 installer/product contract required')
    return module


class Checks:
    def __init__(self):
        self.rows = []
        self.values = {}

    def run(self, name, function, dependencies=(), summarize=None):
        blocked = [key for key in dependencies if key not in self.values]
        if blocked:
            self.rows.append(dict(id=name, status='SKIPPED', blocked_by=blocked,
                                  recovery=RECOVERY[name]))
            return
        try:
            value = function()
            observed = summarize(value) if summarize else value
        except Exception as error:
            self.rows.append(dict(id=name, status='FAIL', error_type=type(error).__name__,
                                  error=str(error), recovery=RECOVERY[name]))
            return
        self.values[name] = value
        self.rows.append(dict(id=name, status='PASS', observed=observed))


def diagnose(cpu_cache, graphics_cache, pe, profile, identifier, work_root, out, jobs=2):
    """Return all independent diagnostics; no report/output paths are written."""
    checks = Checks()
    checks.run('host_python', host_python)
    checks.run('validator_import', validator_import,
               summarize=lambda module: dict(module=module.__name__, source=str(Path(module.__file__).resolve())))
    implementation = checks.values.get('validator_import')

    def arguments():
        require(type(jobs) is int and 1 <= jobs <= 2, 'jobs must be integer 1 or 2')
        return dict(jobs=jobs, spec=implementation.spec(dict(identifier=identifier, name='PE AOT Portable Window')))

    def paths():
        return implementation.legacy._paths(cpu_cache, graphics_cache, pe, profile, work_root, out)

    def inputs():
        raw_pe = implementation.cpu_tools.real_path(pe)
        raw_profile = implementation.cpu_tools.real_path(profile)
        return implementation._inputs(raw_pe, raw_profile)[2]

    def cpu():
        cache = implementation.cpu_tools.real_path(cpu_cache)
        remill = cache / 'remill.tar.gz'
        require(remill.is_file() and not remill.is_symlink() and
                implementation._sha(remill) == implementation.cpu_builder.REMILL_ARCHIVE_SHA,
                'pinned Remill cache differs: ' + str(remill))
        return dict(tools=implementation.cpu_tools.check_cache(cache),
                    sources=implementation.cpu_deps.sources(cache),
                    remill=dict(path=str(remill), sha256=implementation._sha(remill), bytes=remill.stat().st_size))

    loaded = ('validator_import',)
    checks.run('arguments', arguments, loaded)
    checks.run('paths', paths, loaded, summarize=lambda value: {k: str(v) for k, v in value.items()})
    checks.run('disk', lambda: implementation._disk_budget(checks.values['paths']['work_root'],
                checks.values['paths']['out']), ('validator_import', 'paths'))
    # Inputs and caches do not depend on the validity of the output paths or on
    # each other. A missing graphics cache must not hide a bad CPU archive.
    checks.run('pe_profile', inputs, loaded)
    checks.run('apple', lambda: implementation._apple_preflight(), ('validator_import', 'host_python'))
    checks.run('cpu_cache', cpu, loaded)
    checks.run('graphics_cache', lambda: implementation.graphics_cache_module.check_cache(
                implementation.cpu_tools.real_path(graphics_cache)), loaded)
    # Explicit pinned resources are required even when a source inventory omits
    # absent non-Python files. This uses the same pure hook as plan/install.
    checks.run('lookup_runtime', lambda: implementation._lookup_identity(), loaded)
    checks.run('implementation', lambda: implementation._implementation(), loaded,
               summarize=lambda value: dict(files=len(value), sha256=value,
                   scope='Installer inventory plus its mandatory lookup check; completeness of unrelated non-Python resources is not proved.'))
    checks.run('doctor_source_snapshot', source_snapshot)
    counts = {status: sum(row['status'] == status for row in checks.rows)
              for status in ('PASS', 'FAIL', 'SKIPPED')}
    ready = counts['FAIL'] == counts['SKIPPED'] == 0
    return dict(schema=2, status=READY if ready else FAILED, checks=checks.rows, counts=counts,
                doctor_sources=checks.values.get('doctor_source_snapshot'),
                installation_contract='migration_install_v3 / window-lookup-v7',
                input_contract='schema2 / win32-d3d11-tile-switch-v1',
                runtime_lookup=checks.values.get('lookup_runtime'),
                output_policy='JSON returned to stdout; work-root and out are only inspected, never created.',
                native_builds=0, guest_executions=0, app_executions=0, gpu_executions=0,
                limitations=[
                    'Point-in-time prerequisite diagnostics, not instruction decoding, build, App, performance or clean-machine acceptance.',
                    'Each check reports its first error; independent groups continue. Apple discovery uses bounded external queries.',
                    'The installer rechecks all prerequisites; this report cannot authorize reuse or bypass admission.',
                    'Disk reservation is the existing installer policy, not a measured peak-space guarantee.',
                    'The three frozen lookup resources are checked explicitly; completeness of all other non-Python resources still needs an independent release manifest/native build.',
                    'Doctor source hashes describe files read at report time, not proof of loaded-code identity or unchanged sources throughout execution.',
                    'Use Python -B to prevent Python bytecode writes. Apple discovery may update OS-managed tool caches.',
                ])
