"""Fixture diagnostics and filesystem boundaries, with no native/App launches."""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from migration_install_v2 import runner
from migration_doctor_v1 import doctor
from migration_doctor_v1.__main__ import main


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(root):
    return {str(p.relative_to(root)): ('link', str(p.readlink())) if p.is_symlink()
            else ('file', sha(p)) if p.is_file() else ('directory',)
            for p in sorted(Path(root).rglob('*'))}


class Fixture:
    def __enter__(self):
        self.stack = ExitStack()
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='v6-doctor-'))).resolve()
        self.cpu = self.root/'cpu'; self.cpu.mkdir()
        self.gfx = self.root/'graphics'; self.gfx.mkdir()
        for name in ('remill.tar.gz', 'tools.tar.gz', 'sources.fixture'):
            (self.cpu/name).write_bytes(('fixed ' + name).encode())
        (self.gfx/'graphics.fixture').write_bytes(b'fixed graphics fixture')
        self.pe = self.root/'input.exe'; self.profile = self.root/'profile.json'
        shutil.copyfile(doctor.ROOT/'examples/window-switch/switch_tile.exe', self.pe)
        shutil.copyfile(doctor.ROOT/'examples/window-switch/profile.json', self.profile)
        self.args = dict(cpu_cache=self.cpu, graphics_cache=self.gfx, pe=self.pe,
                         profile=self.profile, identifier='org.peaotlab.doctor.fixture',
                         work_root=self.root/'work', out=self.root/'evidence', jobs=2)
        patch = self.stack.enter_context
        patch(mock.patch.object(doctor.platform, 'system', return_value='Darwin'))
        patch(mock.patch.object(doctor.platform, 'machine', return_value='arm64'))
        self.apple = patch(mock.patch.object(runner, '_apple_preflight', return_value={'fixture': 'bounded SDK discovery replaced'}))
        patch(mock.patch.object(runner.cpu_builder, 'REMILL_ARCHIVE_SHA', sha(self.cpu/'remill.tar.gz')))
        patch(mock.patch.object(runner.cpu_tools, 'PACKAGES', {'tools.tar.gz': (sha(self.cpu/'tools.tar.gz'), 'fixture')}))
        patch(mock.patch.object(runner.cpu_deps, 'sources', side_effect=lambda p: {'fixture': sha(Path(p)/'sources.fixture')}))
        self.graphics = patch(mock.patch.object(runner.graphics_cache_module, 'check_cache',
                                               side_effect=lambda p: {'fixture': sha(Path(p)/'graphics.fixture')}))
        self.implementation = patch(mock.patch.object(runner, '_implementation',
            return_value={'migration_install_v2/runner.py': sha(doctor.ROOT/'migration_install_v2/runner.py')}))
        patch(mock.patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=100*1024**3)))
        self.launches = [patch(mock.patch.object(runner.subprocess, name,
                         side_effect=AssertionError('process launch forbidden'))) for name in ('run','Popen')]
        self.builders = [patch(mock.patch.object(module, name,
                         side_effect=AssertionError('builder dispatch forbidden')))
                         for module,name in [(runner, '_run_worker'), (runner, '_dispatch'),
                                             (runner.cpu_builder,'build'), (runner.graphics_builder,'build'),
                                             (runner.switch_builder,'build'), (runner.app_builder,'build')]]
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def diagnose(self, **changes):
        return doctor.diagnose(**(self.args | changes))


def rows(result):
    return {row['id']: row for row in result['checks']}


class DoctorTests(unittest.TestCase):
    def test_ready_is_only_preflight_and_creates_nothing(self):
        with Fixture() as f:
            before = tree(f.root); result = f.diagnose()
            self.assertEqual(result['status'], doctor.READY)
            self.assertEqual(result['counts'], dict(PASS=11, FAIL=0, SKIPPED=0))
            self.assertEqual(before, tree(f.root))
            self.assertFalse(f.args['work_root'].exists()); self.assertFalse(f.args['out'].exists())
            for name in ('native_builds','guest_executions','app_executions','gpu_executions'):
                self.assertEqual(result[name], 0)
            for call in f.builders + f.launches: call.assert_not_called()

    def test_actual_cpu_archive_hash_corruption_is_reported(self):
        for member in ('remill.tar.gz','tools.tar.gz'):
            with self.subTest(member=member), Fixture() as f:
                (f.cpu/member).write_bytes(b'corrupt')
                before = tree(f.root); result = f.diagnose()
                self.assertEqual(rows(result)['cpu_cache']['status'], 'FAIL')
                self.assertEqual(rows(result)['graphics_cache']['status'], 'PASS')
                self.assertEqual(tree(f.root), before)

    def test_multiple_independent_failures_are_not_hidden(self):
        with Fixture() as f:
            f.pe.write_bytes(b'invalid PE'); (f.cpu/'remill.tar.gz').write_bytes(b'wrong')
            f.apple.side_effect = FileNotFoundError('xcrun metal not available')
            result = rows(f.diagnose())
            for name in ('pe_profile','cpu_cache','apple'): self.assertEqual(result[name]['status'], 'FAIL')
            for name in ('graphics_cache','implementation','disk'): self.assertEqual(result[name]['status'], 'PASS')
            self.assertIn('metal', result['apple']['error'])

    def test_missing_graphics_cache_does_not_hide_cpu_or_input(self):
        with Fixture() as f:
            result = rows(f.diagnose(graphics_cache=f.root/'absent-cache'))
            for name in ('paths','graphics_cache'): self.assertEqual(result[name]['status'], 'FAIL')
            self.assertEqual(result['disk']['blocked_by'], ['paths'])
            for name in ('cpu_cache','pe_profile'): self.assertEqual(result[name]['status'], 'PASS')

    def test_output_overlap_and_existing_output_fail_without_changes(self):
        for variant in ('overlap','existing','symlink'):
            with self.subTest(variant=variant), Fixture() as f:
                if variant == 'overlap': output = f.cpu/'new-evidence'
                elif variant == 'existing': output = f.root/'exists'; output.mkdir()
                else:
                    output = f.root/'link'; output.symlink_to(f.root/'absent-target')
                before = tree(f.root); result = rows(f.diagnose(out=output))
                self.assertEqual(result['paths']['status'], 'FAIL')
                self.assertEqual(result['disk']['status'], 'SKIPPED')
                self.assertEqual(result['pe_profile']['status'], 'PASS')
                self.assertEqual(tree(f.root), before)

    def test_shared_filesystem_budget_is_summed(self):
        with Fixture() as f, mock.patch.object(runner.shutil, 'disk_usage', return_value=SimpleNamespace(free=6*1024**3)):
            result = rows(f.diagnose())
            self.assertEqual(result['paths']['status'], 'PASS')
            self.assertEqual(result['disk']['status'], 'FAIL')
            self.assertEqual(result['apple']['status'], 'PASS')

    def test_wrong_host_skips_external_apple_queries(self):
        with Fixture() as f, mock.patch.object(doctor.platform, 'machine', return_value='x86_64'):
            result = rows(f.diagnose())
            self.assertEqual(result['host_python']['status'], 'FAIL')
            self.assertEqual(result['apple']['blocked_by'], ['host_python'])
            self.assertEqual(result['pe_profile']['status'], 'PASS')
            f.apple.assert_not_called()

    def test_old_python_is_a_reported_precondition_failure(self):
        with Fixture() as f, mock.patch.object(doctor.sys, 'version_info', (3,12,9)):
            result = rows(f.diagnose())
            self.assertEqual(result['host_python']['status'], 'FAIL')
            self.assertEqual(result['apple']['status'], 'SKIPPED')
            f.apple.assert_not_called()

    def test_import_failure_is_reported_and_dependent_checks_skip(self):
        with mock.patch.object(doctor.importlib, 'import_module', side_effect=ImportError('fixture missing dependency')):
            result = doctor.diagnose('cpu','gfx','input.exe','profile.json','org.example','work','evidence')
            checks = rows(result)
            self.assertEqual(checks['validator_import']['status'], 'FAIL')
            for name in ('arguments','paths','disk','pe_profile','apple','cpu_cache','graphics_cache','implementation'):
                self.assertEqual(checks[name]['status'], 'SKIPPED')
            self.assertEqual(result['status'], doctor.FAILED)

    def test_jobs_boolean_or_out_of_range_and_invalid_identifier_fail(self):
        for changes in ({'jobs':True},{'jobs':0},{'jobs':3},{'identifier':'bad identifier'}):
            with self.subTest(changes=changes), Fixture() as f:
                result = rows(f.diagnose(**changes))
                self.assertEqual(result['arguments']['status'], 'FAIL')
                self.assertEqual(result['pe_profile']['status'], 'PASS')

    def test_old_profile_rejected_by_real_v6_parser(self):
        with Fixture() as f:
            value = json.loads(f.profile.read_text()); value['schema'] = 1
            f.profile.write_text(json.dumps(value)); result = rows(f.diagnose())
            self.assertEqual(result['pe_profile']['status'], 'FAIL')
            self.assertEqual(result['cpu_cache']['status'], 'PASS')

    def test_implementation_resource_failure_not_hidden_by_other_successes(self):
        with Fixture() as f:
            f.implementation.side_effect = FileNotFoundError('missing runtime.h')
            result = f.diagnose()
            self.assertEqual(result['status'], doctor.FAILED)
            self.assertEqual(rows(result)['implementation']['status'], 'FAIL')
            self.assertEqual(rows(result)['apple']['status'], 'PASS')

    def test_missing_doctor_source_preserves_all_other_diagnostics(self):
        missing = doctor.ROOT/'migration_doctor_v1/not-present.fixture.py'
        with Fixture() as f, mock.patch.object(doctor, 'SOURCES', (missing,)):
            result = f.diagnose()
            self.assertEqual(result['status'], doctor.FAILED)
            self.assertEqual(rows(result)['doctor_source_snapshot']['status'], 'FAIL')
            self.assertIsNone(result['doctor_sources'])
            self.assertEqual(rows(result)['pe_profile']['status'], 'PASS')
            self.assertEqual(rows(result)['cpu_cache']['status'], 'PASS')

    def test_cli_emits_json_and_returns_two_for_failed_diagnostics(self):
        with Fixture() as f:
            argv = [item for name,value in f.args.items() for item in ('--'+name.replace('_','-'), str(value))]
            for corrupt, expected in ((False,0),(True,2)):
                if corrupt: (f.cpu/'remill.tar.gz').write_bytes(b'corrupt')
                output = io.StringIO()
                with redirect_stdout(output): code = main(argv)
                value = json.loads(output.getvalue())
                self.assertEqual(code, expected)
                self.assertEqual(value['status'], doctor.FAILED if corrupt else doctor.READY)
                self.assertFalse(f.args['out'].exists())


if __name__ == '__main__':
    unittest.main()
