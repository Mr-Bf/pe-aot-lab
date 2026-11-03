"""Workflow contract tests; real App/compiler backends are never invoked."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from . import config as c, workflow as w


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pe = self.root / 'program.exe'
        self.pe.write_bytes((c.ROOT / 'examples/window-switch/switch_tile.exe').read_bytes())
        self.profile = self.root / 'profile.json'
        self.profile.write_bytes((c.ROOT / 'examples/window-switch/profile.json').read_bytes())
        self.path = self.root / 'config.json'
        self.out = self.root / 'workspace'
        for name in ('cpu', 'graphics', 'cpu-cache', 'graphics-cache'):
            (self.root / name).mkdir()
        self.value = dict(schema=1, pe='program.exe', profile='profile.json',
                          identifier='org.peaotlab.workflowtest',
                          build=dict(mode='providers', cpu_prefix='cpu', graphics_prefix='graphics'))
        self.save()

    def save(self, value=None):
        self.path.write_bytes(c.encode(self.value if value is None else value))

    def mocks(self):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(w, 'host_python', return_value={'python': 'test-host'}))
        stack.enter_context(mock.patch.object(w, '_implementation', return_value={'test-source': 'fixed'}))
        stack.enter_context(mock.patch.object(w, '_backend_check', side_effect=lambda value, out: dict(
            mode=value['build']['mode'], cpu_manifest_sha256='cpu-hash',
            graphics_manifest_sha256='graphics-hash', parent_cpu_manifest_sha256='parent-hash')))
        stack.enter_context(mock.patch.object(w, '_verify_product', side_effect=lambda product, record: dict(
            status='PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED', app=str(Path(product) / 'Test.app'))))
        stack.enter_context(mock.patch.object(w.installer, '_group_state', return_value='ABSENT'))
        return stack

    def worker_result(self, job_path, fd, successful=True, registered=True):
        attempt = Path(job_path).parent
        if registered:
            for name in ('process.json', 'launched.json'):
                w._write(attempt / name, dict(job_sha256=w.installer._sha(job_path), pid=42, pgid=42))
        product = attempt / 'product'; product.mkdir()
        w._write(product / 'result.json', {'fixture': 'not-a-real-App', 'attempt': attempt.name})
        returned = dict(backend_ok=successful, product=str(product), backend={'status': w.app.STATUS if successful else 'BUILD_FAILED'})
        w._write(attempt / 'worker-result.json', dict(status='WORKER_RETURNED',
                 job_sha256=w.installer._sha(job_path), returned=returned))
        exited = dict(returncode=0, group_state='ABSENT', pid=42, pgid=42)
        w._write(attempt / 'exit.json', exited)
        return exited

    def create(self, successful=True):
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=lambda p, fd: self.worker_result(p, fd, successful)):
            return w.build(self.path, self.out)


class ConfigTests(Fixture):
    def test_relative_paths_use_config_directory(self):
        result = c.load_config(self.path)
        self.assertEqual(result['value']['pe'], str(self.pe))
        self.assertEqual(result['value']['profile'], str(self.profile))
        self.assertEqual(result['value']['build']['cpu_prefix'], str(self.root / 'cpu'))
        self.assertEqual(result['sha256'], c.digest(self.path.read_bytes()))

    def test_config_exact_fields_types_and_mode(self):
        cases = []
        for key, val in [('schema', True), ('schema', 2), ('pe', None), ('profile', 1), ('identifier', '../bad')]:
            item = copy.deepcopy(self.value); item[key] = val; cases.append(item)
        item = copy.deepcopy(self.value); item['extra'] = 1; cases.append(item)
        item = copy.deepcopy(self.value); item['build']['jobs'] = 2; cases.append(item)
        item = copy.deepcopy(self.value); item['build']['cpu_prefix'] = 3; cases.append(item)
        for item in cases:
            self.save(item)
            with self.subTest(item=item), self.assertRaises((ValueError, TypeError)):
                c.load_config(self.path)

    def test_offline_job_limit_rejects_bool_and_fraction(self):
        for jobs in (True, 0, 3, 1.5, '2'):
            self.value['build'] = dict(mode='offline', cpu_cache='cpu-cache', graphics_cache='graphics-cache', jobs=jobs)
            self.save()
            with self.subTest(jobs=jobs), self.assertRaises(c.WorkflowError):
                c.load_config(self.path)
        self.value['build']['jobs'] = 2; self.save()
        self.assertEqual(c.load_config(self.path)['value']['build']['jobs'], 2)

    def test_duplicate_and_nonfinite_json_rejected(self):
        for data in (b'{"schema":1,"schema":1}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                c.decode(data)

    def test_symlink_input_and_config_parent_rejected(self):
        alias = self.root / 'alias'; alias.symlink_to(self.pe)
        self.value['pe'] = 'alias'; self.save()
        with self.assertRaises(c.WorkflowError): c.load_config(self.path)
        parent = self.root / 'linked'; parent.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(c.WorkflowError): c.load_config(parent / self.path.name)

    def test_initialize_exclusive_no_overwrite(self):
        before = self.path.read_bytes()
        with self.assertRaises(c.WorkflowError): c.initialize(self.path, self.value)
        self.assertEqual(before, self.path.read_bytes())
        new = self.root / 'new.json'
        self.assertEqual(c.initialize(new, self.value)['status'], 'MIGRATION_CONFIG_CREATED_NOT_CHECKED')

    def test_builtin_only_exact_pe_and_raw_profile_identity(self):
        self.value['profile'] = None; self.save(); cfg = c.load_config(self.path)
        selected = c.select_profile(cfg, self.pe.read_bytes())
        self.assertEqual(selected['selection'], 'builtin_exact_pe_sha256')
        self.assertEqual(selected['profile_sha256'], c.PROFILE_SHA)
        self.assertNotEqual(c.PROFILE_SHA, c.digest(c.encode(c.decode(self.profile.read_bytes()))))
        with self.assertRaises(c.WorkflowError) as error:
            c.select_profile(cfg, self.pe.read_bytes() + b'changed')
        self.assertEqual(error.exception.code, 'PROFILE_REQUIRED')

    def test_oversized_sparse_config_rejected_before_read(self):
        with self.path.open('wb') as stream: stream.truncate(65537)
        with mock.patch.object(c.os, 'fdopen', side_effect=AssertionError('must reject from fstat before reading')) as reader:
            with self.assertRaises(c.WorkflowError): c.load_config(self.path)
        reader.assert_not_called()


class CheckTests(Fixture):
    def test_check_is_read_only_and_not_decode_or_build(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*'))
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=AssertionError('no worker')):
            result = w.check(self.path, self.out)
        self.assertEqual(result['status'], w.READY)
        self.assertEqual(result['app_executions'], 0)
        self.assertFalse(self.out.exists())
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')))

    def test_unknown_null_profile_blocks_without_workspace(self):
        self.value['profile'] = None; self.save(); self.pe.write_bytes(b'MZ-not-an-accepted-PE')
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=AssertionError('no worker')):
            result = w.build(self.path, self.out)
        self.assertEqual(result['status'], 'MIGRATION_BLOCKED')
        self.assertIn('PROFILE_REQUIRED', [r.get('code') for r in result['checks']])
        self.assertFalse(self.out.exists())

    def test_invalid_explicit_profile_does_not_fall_back(self):
        self.profile.write_text('{}')
        with self.mocks(): result = w.check(self.path, self.out)
        self.assertEqual(result['status'], 'MIGRATION_BLOCKED')
        self.assertIn('INPUT_NOT_ADMITTED', [r.get('code') for r in result['checks']])

    def test_output_inside_provider_or_existing_is_blocked(self):
        with self.mocks():
            for out in (self.root / 'cpu' / 'nested', self.root / 'graphics'):
                result = w.check(self.path, out)
                self.assertEqual(result['status'], 'MIGRATION_BLOCKED')
                self.assertEqual(next(r for r in result['checks'] if r['id'] == 'output')['status'], 'FAIL')

    def test_missing_backend_is_actionable_failure(self):
        with self.mocks(), mock.patch.object(w, '_backend_check', side_effect=ValueError('provider absent')):
            result = w.check(self.path, self.out)
        self.assertEqual(result['status'], 'MIGRATION_BLOCKED')
        self.assertEqual(next(r for r in result['checks'] if r['id'] == 'backend')['message'], 'provider absent')

    def test_oversized_profile_is_blocked_before_file_body_read(self):
        with self.profile.open('wb') as stream: stream.truncate(65537)
        original = os.fdopen
        def bounded_open(fd, *args, **kwargs):
            self.assertLessEqual(os.fstat(fd).st_size, 65536, 'oversized profile body must not be read')
            return original(fd, *args, **kwargs)
        with self.mocks(), mock.patch.object(c.os, 'fdopen', side_effect=bounded_open):
            result = w.check(self.path, self.out)
        self.assertEqual(result['status'], 'MIGRATION_BLOCKED')
        self.assertIn('PROFILE_TOO_LARGE', [r.get('code') for r in result['checks']])
        self.assertFalse(self.out.exists())

    def test_workspace_cannot_modify_overlay_parent_cpu_tree(self):
        parent = self.root / 'parent-cpu'; (parent / 'source').mkdir(parents=True)
        candidate = parent / 'source' / 'workspace'
        cpu_record = dict(provider=str(parent), provider_sha256='parent-hash')
        value = c.load_config(self.path)['value']
        with mock.patch.object(w.cpu, 'paths_for', return_value=(cpu_record, {})), \
             mock.patch.object(w.graphics, 'paths_for', return_value={'provider_sha256': 'graphics-hash'}), \
             mock.patch.object(w.installer, '_sha', return_value='fixture-hash'), \
             mock.patch.object(w.installer, '_apple_preflight', return_value={}):
            with self.assertRaises(c.WorkflowError): w._backend_check(value, candidate)
        self.assertFalse(candidate.exists())


class StateTests(Fixture):
    def test_success_freezes_inputs_and_static_state(self):
        result = self.create()
        self.assertEqual(result['status'], w.STATUS)
        self.assertEqual((self.out / 'inputs/program.exe').read_bytes(), self.pe.read_bytes())
        self.assertEqual((self.out / 'inputs/profile.json').read_bytes(), c.encode(c.decode(self.profile.read_bytes())))
        self.assertEqual(result['app_executions'], 0)
        observed = w.status(self.out)
        self.assertEqual(observed['status'], 'MIGRATION_STATUS_OBSERVATION_NOT_VERIFIED')
        self.assertEqual(observed['attempts'], 1)

    def test_build_does_not_overwrite_existing_workspace(self):
        self.create(); before = (self.out / 'workspace.json').read_bytes()
        with self.mocks(): result = w.build(self.path, self.out)
        self.assertEqual(result['status'], 'MIGRATION_BLOCKED')
        self.assertEqual((self.out / 'workspace.json').read_bytes(), before)

    def test_successful_resume_reverifies_without_worker(self):
        self.create()
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=AssertionError('no new worker')):
            result = w.resume(self.out)
            verified = w.verify(self.out)
        self.assertEqual(result['status'], w.STATUS)
        self.assertTrue(result['reused_verified_product'])
        self.assertEqual(verified['status'], w.VERIFIED)

    def test_failed_attempt_retained_and_resume_uses_new_directory(self):
        first = self.create(successful=False)
        self.assertEqual(first['status'], 'MIGRATION_BUILD_FAILED')
        path = self.out / 'attempts/attempt-0001/result.json'; before = path.read_bytes()
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=self.worker_result):
            second = w.resume(self.out)
        self.assertEqual(second['status'], w.STATUS)
        self.assertTrue(second['attempt'].endswith('attempt-0002'))
        self.assertEqual(path.read_bytes(), before)

    def test_orphan_product_can_be_adopted_without_inventing_exit_zero(self):
        self.create(); attempt = self.out / 'attempts/attempt-0001'
        (attempt / 'result.json').unlink(); (attempt / 'exit.json').unlink()
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=AssertionError('do not rebuild verified orphan')):
            result = w.resume(self.out)
            verified = w.verify(self.out)
        self.assertEqual(result['status'], w.STATUS)
        self.assertTrue(result['adopted_completed_worker'])
        self.assertIs(result['worker_exit_status_observed'], False)
        self.assertIsNone(result['worker_exit']['returncode'])
        self.assertFalse((attempt / 'exit.json').exists())
        self.assertEqual(verified['status'], w.VERIFIED)

    def test_known_nonzero_orphan_exit_is_not_adopted(self):
        self.create(); attempt = self.out / 'attempts/attempt-0001'
        (attempt / 'result.json').unlink()
        exited = c.read_json(attempt / 'exit.json'); exited['returncode'] = 9
        (attempt / 'exit.json').write_bytes(c.encode(exited))
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=self.worker_result) as run:
            result = w.resume(self.out)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result['status'], w.STATUS)
        self.assertTrue(result['attempt'].endswith('attempt-0002'))
        self.assertFalse(result.get('adopted_completed_worker', False))
        self.assertEqual(c.read_json(attempt / 'exit.json')['returncode'], 9)

    def test_input_config_and_implementation_changes_block_resume(self):
        self.create(); original = self.path.read_bytes()
        self.path.write_bytes(original + b'\n')
        with self.mocks(), self.assertRaises(c.WorkflowError): w.resume(self.out)
        self.path.write_bytes(original)
        self.pe.write_bytes(self.pe.read_bytes() + b'changed')
        with self.mocks(), self.assertRaises(c.WorkflowError): w.resume(self.out)

    def test_active_group_blocks_resume(self):
        self.create(); process = self.out / 'attempts/attempt-0001/process.json'
        record = c.read_json(process); record.update(pid=42, pgid=42); process.write_bytes(c.encode(record))
        with self.mocks(), mock.patch.object(w.installer, '_group_state', return_value='PRESENT'), self.assertRaises(c.WorkflowError) as error:
            w.resume(self.out)
        self.assertEqual(error.exception.code, 'WORKER_ACTIVE_OR_UNKNOWN')

    def test_unregistered_attempt_blocks_resume(self):
        self.create()
        for name in ('process.json', 'launched.json'):
            (self.out / 'attempts/attempt-0001' / name).unlink()
        with self.mocks(), self.assertRaises(c.WorkflowError) as error: w.resume(self.out)
        self.assertEqual(error.exception.code, 'UNREGISTERED_ATTEMPT')

    def test_attempt_gap_rejected(self):
        self.create(); (self.out / 'attempts/attempt-0001').rename(self.out / 'attempts/attempt-0002')
        with self.assertRaises(c.WorkflowError) as error: w.status(self.out)
        self.assertEqual(error.exception.code, 'ATTEMPT_GAP')

    def test_verify_and_resume_reject_changed_product_receipt(self):
        result = self.create(); path = Path(result['product']) / 'result.json'
        path.write_bytes(path.read_bytes() + b'\n')
        with self.mocks(), self.assertRaises(c.WorkflowError): w.verify(self.out)
        with self.mocks(), self.assertRaises(c.WorkflowError): w.resume(self.out)

    def test_resume_rejects_changed_success_binding(self):
        self.create(); path = self.out / 'attempts/attempt-0001/result.json'
        original = c.read_json(path)
        for field, value in (('attempt', str(self.out / 'attempts/attempt-9999')), ('out', str(self.root)),
                             ('worker_result_sha256', '0' * 64)):
            altered = dict(original); altered[field] = value; path.write_bytes(c.encode(altered))
            with self.subTest(field=field), self.mocks(), self.assertRaises(c.WorkflowError): w.resume(self.out)
        path.write_bytes(c.encode(original))

    def test_verify_failure_cannot_become_success(self):
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=self.worker_result), \
             mock.patch.object(w, '_verify_product', side_effect=c.WorkflowError('BAD_PRODUCT', 'test verification failed')):
            with self.assertRaises(c.WorkflowError): w.build(self.path, self.out)
        self.assertFalse((self.out / 'attempts/attempt-0001/result.json').exists())

    def test_backend_failure_never_accepted_by_verify(self):
        self.create(successful=False)
        with self.mocks(), self.assertRaises(c.WorkflowError): w.verify(self.out)

    def test_product_verifier_binds_input_identifier_and_providers(self):
        built = self.create(); record = c.read_json(self.out / 'workspace.json')
        product = Path(built['product']); receipt = product / 'result.json'
        good = dict(input_sha256=record['inputs']['pe_sha256'],
                    profile_sha256=record['inputs']['canonical_profile_sha256'],
                    spec=dict(identifier=self.value['identifier']),
                    cpu_provider_sha256='cpu-hash', graphics_provider_sha256='graphics-hash')
        receipt.write_bytes(c.encode(good))
        with mock.patch.object(w.app, 'verify', return_value={'app': str(product / 'Test.app')}):
            self.assertEqual(w._verify_product(product, record)['app'], str(product / 'Test.app'))
            for key in ('input_sha256', 'profile_sha256', 'cpu_provider_sha256', 'graphics_provider_sha256'):
                bad = dict(good); bad[key] = 'changed'; receipt.write_bytes(c.encode(bad))
                with self.subTest(key=key), self.assertRaises(c.WorkflowError): w._verify_product(product, record)
            bad = dict(good, spec=dict(identifier='org.peaotlab.other')); receipt.write_bytes(c.encode(bad))
            with self.assertRaises(c.WorkflowError): w._verify_product(product, record)
            with self.assertRaises(c.WorkflowError): w._verify_product(self.root, record)

    def test_spawn_failure_retains_process_record_without_success(self):
        self.create(successful=False)
        attempt = self.out / 'attempts/attempt-0002'; attempt.mkdir()
        job = attempt / 'job.json'; job.write_bytes(c.encode({'fixture': True}))
        with mock.patch.object(w.subprocess, 'Popen', side_effect=OSError('test cannot spawn')):
            result = w._run_worker(job, 123)
        self.assertEqual(result['group_state'], 'NOT_SPAWNED')
        self.assertEqual(c.read_json(attempt / 'process.json')['spawn_error'], 'test cannot spawn')

    def test_actual_worker_inherits_lock_and_own_group_without_app(self):
        # One short Python child exercises the actual worker ownership gate.
        # Its dispatch is replaced in that child before worker(), so no compiler
        # or App backend is reachable, and a failed backend result is expected.
        script = '''import fcntl,json,os,sys
from pathlib import Path
from migration_workflow_v1 import workflow as w
job=Path(sys.argv[1]); fd=int(sys.argv[2]); out=Path(w.read_json(job)['out'])
probe=os.open(out/'.install.lock',os.O_RDWR)
try:
    try: fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: (job.parent/'lock-probe.json').write_text(json.dumps({'independent_open_blocked':True}))
    else: raise RuntimeError('independent open acquired inherited lock')
finally: os.close(probe)
w._dispatch=lambda job,record:dict(backend_ok=False,product=None,backend={'status':'INTENTIONAL_TEST_FAILURE'})
raise SystemExit(w.worker(job,fd))
'''
        observed = {}
        def launch(job, fd):
            command = [sys.executable, '-B', '-c', script, str(job), str(fd)]
            child = subprocess.Popen(command, cwd=c.ROOT, pass_fds=(fd,), start_new_session=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            attempt = Path(job).parent
            w._write(attempt / 'process.json', dict(job_sha256=w.installer._sha(job), pid=child.pid, pgid=child.pid))
            try: stdout, stderr = child.communicate(timeout=15)
            except BaseException:
                child.kill(); child.wait(); raise
            self.assertEqual(child.returncode, 0, stderr.decode())
            observed.update(c.read_json(attempt / 'launched.json'))
            exited = dict(returncode=child.returncode, group_state='ABSENT', pid=child.pid, pgid=child.pid)
            w._write(attempt / 'exit.json', exited)
            return exited
        with self.mocks(), mock.patch.object(w, '_run_worker', side_effect=launch):
            result = w.build(self.path, self.out)
        self.assertEqual(result['status'], 'MIGRATION_BUILD_FAILED')
        self.assertEqual(observed['pid'], observed['pgid'])
        self.assertNotEqual(observed['pid'], os.getpid())
        self.assertTrue(c.read_json(self.out / 'attempts/attempt-0001/lock-probe.json')['independent_open_blocked'])


class RoutingTests(Fixture):
    def test_offline_dispatch_selects_install_then_resume(self):
        self.value['build'] = dict(mode='offline', cpu_cache='cpu-cache', graphics_cache='graphics-cache', jobs=1)
        self.save()
        self.out.mkdir(); (self.out / 'inputs').mkdir(); (self.out / 'attempts').mkdir()
        (self.out / 'inputs/profile.json').write_bytes(self.profile.read_bytes())
        record = dict(out=str(self.out), config=c.load_config(self.path))
        attempt = self.out / 'attempts/attempt-0001'; attempt.mkdir()
        job = dict(attempt=str(attempt))
        returned = dict(status=w.installer.STATUS, product=str(self.out / 'offline-work/app-product'))
        with mock.patch.object(w.installer, 'install', return_value=returned) as install, \
             mock.patch.object(w.installer, 'resume', return_value=returned) as resume:
            first = w._dispatch(job, record)
            self.assertTrue(first['backend_ok']); self.assertEqual(install.call_count, 1); resume.assert_not_called()
            self.assertEqual(install.call_args.kwargs['jobs'], 1)
            (self.out / 'offline-install').mkdir()
            second = w._dispatch(job, record)
            self.assertTrue(second['backend_ok']); self.assertEqual(install.call_count, 1)
            self.assertEqual(resume.call_args.kwargs['installation'], str(self.out / 'offline-install'))
            self.assertEqual(resume.call_args.kwargs['out'], str(attempt / 'offline-resume'))

    def test_cli_init_rejects_mixed_modes_without_output(self):
        from .__main__ import main
        new = self.root / 'new.json'
        with contextlib.redirect_stderr(io.StringIO()) as stream:
            code = main(['init', '--config', str(new), '--pe', str(self.pe), '--cpu-prefix', 'cpu',
                         '--graphics-prefix', 'graphics', '--cpu-cache', 'cpu-cache', '--graphics-cache', 'graphics-cache'])
        self.assertEqual(code, 2); self.assertFalse(new.exists())
        self.assertEqual(json.loads(stream.getvalue())['code'], 'INVALID_BACKEND')

    def test_cli_plan_and_failure_exit_codes(self):
        from .__main__ import main
        with self.mocks(), contextlib.redirect_stdout(io.StringIO()) as stream:
            code = main(['plan', str(self.path), '--out', str(self.out)])
        self.assertEqual(code, 0); self.assertFalse(self.out.exists())
        self.assertTrue(json.loads(stream.getvalue())['plan_only'])
        with mock.patch.object(w, 'build', return_value={'status': 'MIGRATION_BUILD_FAILED'}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['build', str(self.path), '--out', str(self.out)]), 1)

    def test_cli_interrupt_is_not_success(self):
        from .__main__ import main
        with mock.patch.object(w, 'resume', side_effect=KeyboardInterrupt), contextlib.redirect_stderr(io.StringIO()) as stream:
            code = main(['resume', str(self.out)])
        self.assertEqual(code, 130)
        self.assertEqual(json.loads(stream.getvalue())['status'], 'MIGRATION_INTERRUPTED_WORKER_STATE_UNKNOWN')


if __name__ == '__main__': unittest.main()
