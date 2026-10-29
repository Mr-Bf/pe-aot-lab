"""Narrow installer fixtures: real PE/profile admission, zero native builders.

All mutable files live in TemporaryDirectory. External cache/Apple discovery is
mocked; stage stubs write the real provider-plus-outer-receipt shapes. No App,
compiler, subprocess, GUI, download or process cleanup is performed by tests.
"""
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from migration_install_v1 import runner

ROOT = Path(__file__).resolve().parents[1]
PRODUCT = ROOT / 'build/migration-v5/public-graphics-01/product'
STAGES = ['cpu-build', 'graphics-build', 'app-build', 'app-verify']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def tree(root):
    values = {}
    for path in sorted(root.rglob('*')):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            values[relative] = ['link', os.readlink(path)]
        elif path.is_dir():
            values[relative] = ['directory']
        else:
            values[relative] = ['file', digest(path)]
    return values


class Fixture:
    def __enter__(self):
        self.stack = ExitStack()
        name = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='offline-install-fixture-'))
        self.root = Path(name).resolve()
        self.cpu, self.graphics = self.root / 'cpu-cache', self.root / 'graphics-cache'
        self.cpu.mkdir(); self.graphics.mkdir()
        (self.cpu / 'remill.tar.gz').write_bytes(b'tiny pinned source fixture; never extracted')
        (self.graphics / 'fixture-cache').write_bytes(b'never extracted')
        self.pe, self.profile = self.root / 'input.exe', self.root / 'profile.json'
        shutil.copyfile(PRODUCT / 'input.exe', self.pe)
        shutil.copyfile(PRODUCT / 'profile.json', self.profile)
        self.original = {str(p): digest(p) for p in (self.pe, self.profile, self.cpu / 'remill.tar.gz', self.graphics / 'fixture-cache')}
        self.work, self.out = self.root / 'new work', self.root / 'new evidence'
        self.args = dict(cpu_cache=self.cpu, graphics_cache=self.graphics, pe=self.pe,
                         profile=self.profile, identifier='org.peaotlab.install.fixture',
                         work_root=self.work, out=self.out, jobs=2)
        self.calls = []
        self.mode = {}
        self.hooks = {}
        self.stack.enter_context(mock.patch.object(runner.platform, 'system', return_value='Darwin'))
        self.stack.enter_context(mock.patch.object(runner.platform, 'machine', return_value='arm64'))
        self.stack.enter_context(mock.patch.object(runner, '_apple_preflight', return_value={'fixture': 'no Apple query executed'}))
        self.stack.enter_context(mock.patch.object(runner.cpu_tools, 'check_cache', return_value={'fixture': 'cpu tools'}))
        self.stack.enter_context(mock.patch.object(runner.cpu_deps, 'sources', return_value={'fixture': 'cpu source cache'}))
        self.stack.enter_context(mock.patch.object(runner.graphics_cache_module, 'check_cache', return_value={'fixture': 'graphics cache'}))
        self.stack.enter_context(mock.patch.object(runner.cpu_builder, 'REMILL_ARCHIVE_SHA', digest(self.cpu / 'remill.tar.gz')))
        self.stack.enter_context(mock.patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(total=200 * 1024**3, used=0, free=100 * 1024**3)))
        for owner, name, stage in ((runner.cpu_builder, 'build', 'cpu-build'),
                                   (runner.graphics_builder, 'build', 'graphics-build'),
                                   (runner.app_builder, 'build', 'app-build'),
                                   (runner.app_builder, 'verify', 'app-verify')):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=lambda _stage=stage, **kwargs: self.stage(_stage, kwargs)))
        for name in ('run', 'Popen'):
            self.stack.enter_context(mock.patch.object(runner.subprocess, name, side_effect=AssertionError('native/subprocess execution forbidden')))
        for name in ('system', 'posix_spawn', 'waitpid', 'wait4', 'kill', 'killpg'):
            if hasattr(os, name):
                self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError('process ownership operation forbidden')))
        self.source_checks = self.stack.enter_context(mock.patch.object(runner.cpu_builder, 'check_sources', wraps=runner.cpu_builder.check_sources))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def unchanged(self, test):
        test.assertEqual({p: digest(p) for p in self.original}, self.original)

    def stage(self, stage, arguments):
        self.calls.append((stage, copy.deepcopy(arguments)))
        mode = self.mode.get(stage)
        if isinstance(mode, BaseException):
            if stage != 'app-verify':
                write(Path(arguments['out']) / 'failure.json', {'status': 'FAIL', 'fixture': str(mode)})
            raise mode
        if stage in self.hooks:
            self.hooks[stage](arguments)
        if stage in ('cpu-build', 'graphics-build'):
            prefix, output = Path(arguments['prefix']), Path(arguments['out'])
            prefix.mkdir(); output.mkdir()
            status = 'CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED' if stage == 'cpu-build' else runner.graphics_builder.STATUS
            returned = dict(schema=1, status=status, guest_executions=0, gpu_executions=0,
                            fixture_sequence=('tuple normalizes to JSON list', 1))
            provider = prefix / 'provider.json'
            write(provider, returned)
            recorded = dict(status=status, prefix=str(prefix), provider_sha256=digest(provider), commands=[])
            receipt = output / 'result.json'
        elif stage == 'app-build':
            output = Path(arguments['out']); output.mkdir()
            shutil.copyfile(arguments['pe'], output / 'input.exe')
            product_profile = copy.deepcopy(arguments['profile'])
            if mode == 'consistent-wrong-input':
                # Change one padding byte, preserving the PE's admitted code/imports.
                data = bytearray((output / 'input.exe').read_bytes()); data[-1] ^= 1
                (output / 'input.exe').write_bytes(data)
                product_profile['pe_sha256'] = digest(output / 'input.exe')
            if mode == 'consistent-wrong-profile':
                product_profile['save_observation'] = 'different-save.bin'
            write(output / 'profile.json', product_profile)
            returned = dict(schema=1, profile='window-portable-v5', status=runner.app_builder.STATUS,
                            app=str(output / 'PE AOT Converted.app'), original_input=arguments['pe'],
                            input_sha256=digest(output / 'input.exe'), profile_sha256=digest(output / 'profile.json'),
                            cpu_prefix=arguments['cpu_prefix'], backend_prefix=arguments['backend_prefix'],
                            spec={'identifier': arguments['identifier'], 'name': 'PE AOT Portable Window'},
                            cpu_provider_sha256=digest(Path(arguments['cpu_prefix']) / 'provider.json'),
                            graphics_provider_sha256=digest(Path(arguments['backend_prefix']) / 'provider.json'),
                            guest_executions=0, gpu_executions=0, requires_arguments=False,
                            fixture_sequence=('JSON tuple', 2))
            if mode in ('consistent-wrong-cpu', 'consistent-wrong-graphics'):
                returned[mode.removeprefix('consistent-wrong-') + '_provider_sha256'] = hashlib.sha256(b'another provider').hexdigest()
            recorded = copy.deepcopy(returned); receipt = output / 'result.json'
        else:
            # Model the frozen verifier's internal input-file checks. It has no
            # installer plan argument, so only the installer can bind the run.
            output = Path(arguments['out'])
            product = json.loads((output / 'result.json').read_bytes())
            if digest(output / 'input.exe') != product['input_sha256'] or digest(output / 'profile.json') != product['profile_sha256']:
                raise ValueError('fixture product input identity differs')
            analysis = runner.profiles.analyze((output / 'input.exe').read_bytes(), json.loads((output / 'profile.json').read_bytes()))
            if analysis['status'] != 'ELIGIBLE_FOR_BUILD_NOT_DECODED':
                raise ValueError('fixture product no longer internally admitted')
            returned = dict(status='PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED', app=product['app'],
                            files=3, guest_executions=0, gpu_executions=0)
            if mode == 'wrong-status': returned['status'] = 'FAIL'
            if mode == 'not-dict': return None
            return returned
        if mode == 'receipt-failed': recorded['status'] = 'FAIL'
        if mode == 'wrong-provider': recorded['provider_sha256'] = '0' * 64
        if mode == 'wrong-prefix': recorded['prefix'] = str(self.root / 'unrelated')
        if mode == 'provider-return-differs':
            changed = copy.deepcopy(returned); changed['fixture_sequence'] = ['changed', 99]; write(provider, changed)
            recorded['provider_sha256'] = digest(provider)
        if mode == 'wrong-input': recorded['input_sha256'] = '0' * 64
        if mode != 'missing-receipt': write(receipt, recorded)
        if mode == 'wrong-status': returned['status'] = 'FAIL'
        if mode == 'not-dict': return None
        return returned


class InstallTests(unittest.TestCase):
    def assert_stopped(self, fixture, result, stage):
        index = STAGES.index(stage)
        self.assertEqual(result['status'], 'INSTALL_FAILED')
        self.assertEqual(result['stage'], stage)
        self.assertEqual(result['completed_stages'], STAGES[:index])
        self.assertEqual([name for name, _ in fixture.calls], STAGES[:index + 1])
        saved = json.loads((fixture.out / 'result.json').read_bytes())
        self.assertEqual(saved['status'], 'INSTALL_FAILED')
        self.assertFalse(saved['automatic_retry'])
        self.assertEqual(saved['child_cleanup'], 'NOT_MANAGED_BY_INSTALLER')
        fixture.unchanged(self)

    def test_plan_readonly_with_real_PE_profile_admission(self):
        with Fixture() as f:
            before = tree(f.root)
            result = runner.plan(**f.args)
            self.assertEqual(result['status'], runner.PLAN_STATUS)
            self.assertEqual(result['inputs']['analysis']['status'], 'ELIGIBLE_FOR_BUILD_NOT_DECODED')
            self.assertEqual(result['inputs']['pe_sha256'], digest(f.pe))
            self.assertEqual(result['stages'], STAGES)
            self.assertEqual(result['destinations']['cpu_prefix'], str(f.work / 'cpu'))
            self.assertEqual(result['destinations']['product'], str(f.out / 'product'))
            self.assertEqual(tree(f.root), before)
            self.assertEqual(f.calls, [])

    def test_success_stage_order_arguments_real_receipt_shapes(self):
        with Fixture() as f:
            result = runner.install(**f.args)
            self.assertEqual(result['status'], runner.STATUS)
            self.assertEqual(result['completed_stages'], STAGES)
            self.assertEqual([s for s, _ in f.calls], STAGES)
            self.assertEqual(f.calls[0][1], dict(prefix=str(f.work / 'cpu'), cache=str(f.cpu), out=str(f.out / 'cpu-build'), jobs=2))
            self.assertEqual(f.calls[1][1], dict(prefix=str(f.work / 'graphics'), cache_path=str(f.graphics), out=str(f.out / 'graphics-build'), jobs=2))
            app = f.calls[2][1]
            self.assertEqual(app['pe'], str(f.out / 'inputs/input.exe'))
            self.assertEqual(app['profile'], json.loads(f.profile.read_bytes()))
            self.assertEqual(app['cpu_prefix'], str(f.work / 'cpu'))
            self.assertEqual(app['backend_prefix'], str(f.work / 'graphics'))
            self.assertEqual(app['identifier'], f.args['identifier'])
            self.assertEqual(f.calls[3][1], dict(out=str(f.out / 'product')))
            self.assertEqual(f.source_checks.call_count, 5)
            for stage in STAGES:
                row = json.loads((f.out / (stage + '.result.json')).read_bytes())
                self.assertEqual(row['returned_status'], row['expected_status'])
                if stage != 'app-verify': self.assertEqual(row['receipt_sha256'], digest(row['receipt']))
            self.assertEqual(result['product_sha256'], digest(f.out / 'product/result.json'))
            self.assertEqual(result['cpu_provider_sha256'], digest(f.work / 'cpu/provider.json'))
            self.assertEqual(result['graphics_provider_sha256'], digest(f.work / 'graphics/provider.json'))
            started = json.loads((f.out / 'started.json').read_bytes())
            self.assertEqual(started['profile_snapshot_sha256'], digest(f.out / 'inputs/profile.json'))
            self.assertEqual(started['input_snapshot_sha256'], digest(f.pe))
            self.assertEqual((f.out / 'inputs/input.exe').read_bytes(), f.pe.read_bytes())
            self.assertEqual({x.name for x in (f.out / 'sources/migration_install_v1').iterdir()}, {'runner.py', '__main__.py', '__init__.py'})
            f.unchanged(self)

    def test_success_return_with_failed_receipt_stops(self):
        for stage in STAGES[:3]:
            with self.subTest(stage=stage), Fixture() as f:
                f.mode[stage] = 'receipt-failed'
                self.assert_stopped(f, runner.install(**f.args), stage)

    def test_provider_hash_prefix_or_return_mismatch_stops(self):
        for stage in STAGES[:2]:
            for mode in ('wrong-provider', 'wrong-prefix', 'provider-return-differs'):
                with self.subTest(stage=stage, mode=mode), Fixture() as f:
                    f.mode[stage] = mode
                    self.assert_stopped(f, runner.install(**f.args), stage)

    def test_wrong_App_input_receipt_stops_before_verify(self):
        with Fixture() as f:
            f.mode['app-build'] = 'wrong-input'
            self.assert_stopped(f, runner.install(**f.args), 'app-build')

    def test_self_consistent_App_must_bind_current_input_profile_and_providers(self):
        for mode in ('consistent-wrong-input', 'consistent-wrong-profile', 'consistent-wrong-cpu', 'consistent-wrong-graphics'):
            with self.subTest(mode=mode), Fixture() as f:
                f.mode['app-build'] = mode
                self.assert_stopped(f, runner.install(**f.args), 'app-build')

    def test_profile_binding_uses_canonical_snapshot_not_original_whitespace(self):
        with Fixture() as f:
            f.profile.write_text(json.dumps(json.loads(f.profile.read_bytes()), separators=(',', ':')))
            f.original[str(f.profile)] = digest(f.profile)
            result = runner.install(**f.args)
            self.assertEqual(result['status'], runner.STATUS)
            frozen = f.out / 'inputs/profile.json'
            product = json.loads((f.out / 'product/result.json').read_bytes())
            self.assertNotEqual(digest(frozen), digest(f.profile))
            self.assertEqual(product['profile_sha256'], digest(frozen))
            f.unchanged(self)

    def test_accepted_provider_manifest_must_stay_unchanged(self):
        for stage, provider in (('graphics-build', 'cpu'), ('app-verify', 'graphics')):
            with self.subTest(stage=stage), Fixture() as f:
                def mutate(_):
                    path = f.work / provider / 'provider.json'
                    data = json.loads(path.read_bytes()); data['changed_after_acceptance'] = True
                    write(path, data)
                f.hooks[stage] = mutate
                self.assert_stopped(f, runner.install(**f.args), stage)

    def test_missing_receipt_stops(self):
        for stage in STAGES[:3]:
            with self.subTest(stage=stage), Fixture() as f:
                f.mode[stage] = 'missing-receipt'
                self.assert_stopped(f, runner.install(**f.args), stage)

    def test_wrong_status_or_nonobject_stops_every_stage(self):
        for stage in STAGES:
            for mode in ('wrong-status', 'not-dict'):
                with self.subTest(stage=stage, mode=mode), Fixture() as f:
                    f.mode[stage] = mode
                    self.assert_stopped(f, runner.install(**f.args), stage)

    def test_exception_stops_every_stage_and_keeps_builder_failure(self):
        for stage in STAGES:
            with self.subTest(stage=stage), Fixture() as f:
                f.mode[stage] = RuntimeError('synthetic builder failure')
                self.assert_stopped(f, runner.install(**f.args), stage)
                if stage != 'app-verify':
                    folder = {'app-build': 'product'}.get(stage, stage)
                    self.assertEqual(json.loads((f.out / folder / 'failure.json').read_bytes())['fixture'], 'synthetic builder failure')

    def test_cancellation_unknown_and_reraised_without_outer_process_actions(self):
        for stage in STAGES:
            for kind in (KeyboardInterrupt, SystemExit):
                with self.subTest(stage=stage, kind=kind.__name__), Fixture() as f:
                    cancellation = kind('synthetic cancellation')
                    f.mode[stage] = cancellation
                    with self.assertRaises(kind) as raised: runner.install(**f.args)
                    self.assertIs(raised.exception, cancellation)
                    record = json.loads((f.out / 'result.json').read_bytes())
                    self.assertEqual(record['status'], 'INSTALL_CANCELLED_CHILD_STATE_UNKNOWN')
                    self.assertIn('UNKNOWN', record['child_state'])
                    self.assertEqual(record['completed_stages'], STAGES[:STAGES.index(stage)])
                    self.assertEqual([s for s, _ in f.calls], STAGES[:STAGES.index(stage) + 1])
                    self.assertFalse(record['automatic_retry']); f.unchanged(self)

    def test_frozen_PE_and_profile_mutation_reject_final_success(self):
        for name in ('input.exe', 'profile.json'):
            with self.subTest(name=name), Fixture() as f:
                def mutate(_):
                    path = f.out / 'inputs' / name
                    path.write_bytes(path.read_bytes() + b'changed')
                f.hooks['app-verify'] = mutate
                result = runner.install(**f.args)
                self.assertEqual(result['status'], 'INSTALL_FAILED')
                self.assertIn('frozen', result['error'])
                self.assertEqual([s for s, _ in f.calls], STAGES)
                f.unchanged(self)

    def test_initialization_failure_preserved_before_any_builder(self):
        with Fixture() as f, mock.patch.object(runner.cpu_builder, 'source_snapshot', side_effect=OSError('snapshot failed')):
            result = runner.install(**f.args)
            self.assertEqual(result['status'], 'INSTALL_FAILED')
            self.assertEqual(result['stage'], 'initialization')
            self.assertEqual(result['completed_stages'], [])
            self.assertTrue((f.out / 'plan.json').is_file())
            self.assertEqual(json.loads((f.out / 'result.json').read_bytes())['error_type'], 'OSError')
            self.assertEqual(f.calls, []); f.unchanged(self)

    def test_existing_output_refused_without_overwrite(self):
        with Fixture() as f:
            runner.install(**f.args)
            before = tree(f.root); count = len(f.calls)
            with self.assertRaises(ValueError): runner.install(**f.args)
            self.assertEqual(tree(f.root), before)
            self.assertEqual(len(f.calls), count)

    def test_paths_reject_existing_overlap_and_symlinks(self):
        cases = ('existing-work', 'existing-out-file', 'out-in-cache', 'work-out-overlap',
                 'same-caches', 'nested-caches', 'input-symlink', 'output-broken-symlink', 'cache-symlink')
        for case in cases:
            with self.subTest(case=case), Fixture() as f:
                args = dict(f.args)
                if case == 'existing-work': f.work.mkdir()
                elif case == 'existing-out-file': f.out.write_bytes(b'keep')
                elif case == 'out-in-cache': args['out'] = f.cpu / 'new-output'
                elif case == 'work-out-overlap': args['out'] = f.work / 'nested-output'
                elif case == 'same-caches': args['graphics_cache'] = f.cpu
                elif case == 'nested-caches':
                    nested = f.cpu / 'graphics'; nested.mkdir(); args['graphics_cache'] = nested
                elif case == 'input-symlink':
                    link = f.root / 'pe-link'; link.symlink_to(f.pe); args['pe'] = link
                elif case == 'output-broken-symlink': f.out.symlink_to(f.root / 'missing')
                elif case == 'cache-symlink':
                    link = f.root / 'cache-link'; link.symlink_to(f.cpu); args['cpu_cache'] = link
                before = tree(f.root)
                with self.assertRaises((ValueError, FileNotFoundError)): runner.plan(**args)
                self.assertEqual(tree(f.root), before)
                self.assertEqual(f.calls, [])

    def test_shared_filesystem_budgets_are_summed(self):
        with Fixture() as f:
            need = runner.WORK_BYTES + runner.EVIDENCE_BYTES
            with mock.patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=need - 1)):
                with self.assertRaises(ValueError): runner._disk_budget(f.work, f.out)
            with mock.patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=need)):
                result = runner._disk_budget(f.work, f.out)
            self.assertEqual(len(result['filesystems']), 1)
            self.assertEqual(result['filesystems'][0]['required_bytes'], need)
            self.assertEqual({r['name'] for r in result['filesystems'][0]['destinations']}, {'work_root', 'out'})
            self.assertFalse(f.work.exists()); self.assertFalse(f.out.exists())

    def test_preflight_input_and_cache_rejections_do_not_create_outputs(self):
        cases = ('jobs-bool', 'jobs-zero', 'identifier', 'PE', 'profile-json', 'profile-hash', 'cpu-cache', 'graphics-cache')
        for case in cases:
            with self.subTest(case=case), Fixture() as f:
                args = dict(f.args)
                if case == 'jobs-bool': args['jobs'] = True
                elif case == 'jobs-zero': args['jobs'] = 0
                elif case == 'identifier': args['identifier'] = '../unsafe'
                elif case == 'PE': f.pe.write_bytes(b'not PE')
                elif case == 'profile-json': f.profile.write_text('{bad')
                elif case == 'profile-hash':
                    value = json.loads(f.profile.read_bytes()); value['pe_sha256'] = '0' * 64; write(f.profile, value)
                before = tree(f.root)
                with ExitStack() as stack:
                    if case == 'cpu-cache': stack.enter_context(mock.patch.object(runner.cpu_tools, 'check_cache', side_effect=ValueError('bad cpu cache')))
                    if case == 'graphics-cache': stack.enter_context(mock.patch.object(runner.graphics_cache_module, 'check_cache', side_effect=ValueError('bad graphics cache')))
                    with self.assertRaises((ValueError, OSError)): runner.install(**args)
                self.assertEqual(tree(f.root), before)
                self.assertFalse(f.work.exists()); self.assertFalse(f.out.exists()); self.assertEqual(f.calls, [])

    def test_oversized_profile_rejected_before_any_hash_or_PE_read(self):
        with Fixture() as f:
            f.profile.write_bytes(b' ' * (runner.profiles.MAX_PROFILE + 1))
            with mock.patch.object(runner, '_sha', side_effect=AssertionError('large file hashed')), \
                 mock.patch.object(runner.profiles, 'read_input', side_effect=AssertionError('PE read before size rejection')):
                with self.assertRaisesRegex(ValueError, '64 KiB'): runner._inputs(f.pe, f.profile)
            self.assertFalse(f.work.exists()); self.assertFalse(f.out.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
