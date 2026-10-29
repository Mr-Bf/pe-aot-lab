"""Independent provider/recorder boundary fixtures, without real build or guest execution."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from portable_lifter_v1 import build, deps


class ProviderBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='portable-provider-unit-')
        self.base = Path(self.temp.name).resolve()
        self.prefix = self.base / 'provider'; self.prefix.mkdir()
        self.sdk = self.base / 'sdk'; self.sdk.mkdir()
        (self.sdk / 'SDKSettings.json').write_text('{"fixture":true}\n')
        files = ['build/lifter', 'build/semantics.bc', 'llvm/bin/clang-17',
                 'llvm/bin/opt', 'llvm/bin/llvm-link', 'source/header.h']
        for relative in files:
            path = self.prefix / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('synthetic non-executable fixture: ' + relative).encode())
        (self.prefix / 'llvm/bin/clang').symlink_to('clang-17')
        self.manifest = dict(schema=1, status='CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED',
            layout=dict(lifter='build/lifter', semantics='build/semantics.bc', llvm='llvm', source='source'),
            runtime_files={relative: dict(sha256=build.digest(self.prefix / relative), mode=0o644)
                           for relative in files[:-1]},
            source_tree=deps.tree(self.prefix / 'source'),
            external_prerequisites=dict(sdk=str(self.sdk),
                sdk_settings={'SDKSettings.json': build.digest(self.sdk / 'SDKSettings.json')}))
        self.save(self.manifest)

    def tearDown(self):
        self.temp.cleanup()

    def save(self, manifest):
        (self.prefix / 'provider.json').write_text(json.dumps(manifest))

    def test_complete_provider_with_internal_tool_alias_is_accepted(self):
        manifest, paths = build.paths_for(self.prefix)
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(paths['lifter'], self.prefix / 'build/lifter')
        self.assertEqual(paths['sdk'], self.sdk)

    def test_missing_roles_empty_inventories_and_wrong_status_are_rejected(self):
        cases = []
        for key, value in [('runtime_files', {}), ('source_tree', {}), ('schema', 2),
                           ('status', 'PASS'), ('layout', {})]:
            case = copy.deepcopy(self.manifest); case[key] = value; cases.append(case)
        case = copy.deepcopy(self.manifest); case['layout']['extra'] = 'source'; cases.append(case)
        case = copy.deepcopy(self.manifest); del case['runtime_files']['llvm/bin/opt']; cases.append(case)
        for number, case in enumerate(cases):
            with self.subTest(number=number):
                self.save(case)
                with self.assertRaises(ValueError):
                    build.paths_for(self.prefix)

    def test_absolute_parent_and_symlink_role_escapes_are_rejected(self):
        outside = self.base / 'outside.bc'; outside.write_bytes(b'outside')
        (self.prefix / 'alias.bc').symlink_to(outside)
        for role in ('lifter', 'semantics', 'source', 'llvm'):
            for value in ('/old-work/object', '../outside.bc', 'alias.bc'):
                with self.subTest(role=role, value=value):
                    case = copy.deepcopy(self.manifest); case['layout'][role] = value; self.save(case)
                    with self.assertRaises(ValueError):
                        build.paths_for(self.prefix)

    def test_file_hash_and_mode_changes_are_rejected(self):
        path = self.prefix / 'build/lifter'
        original = path.read_bytes()
        path.write_bytes(original + b'changed')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            build.paths_for(self.prefix)
        path.write_bytes(original); path.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            build.paths_for(self.prefix)

    def test_manifest_symlink_and_sdk_identity_changes_are_rejected(self):
        manifest = self.prefix / 'provider.json'
        outside = self.base / 'outside-manifest.json'; manifest.rename(outside); manifest.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'regular provider manifest'):
            build.paths_for(self.prefix)
        manifest.unlink(); outside.rename(manifest)
        (self.sdk / 'SDKSettings.json').write_text('{}\n')
        with self.assertRaisesRegex(ValueError, 'SDK identity changed'):
            build.paths_for(self.prefix)

    def test_probe_rejects_manifest_replacement_during_operation(self):
        # Only the orchestration runs: replace lifting, Mach-O parsing and source
        # snapshots with fixture boundaries. No executable is started.
        out = self.base / 'probe-evidence'

        def fake_probe(paths, pe, artifacts, recorder):
            artifacts.mkdir(); (artifacts / 'probe.json').write_text('{}\n')
            changed = copy.deepcopy(self.manifest)
            changed['extra_metadata'] = 'changed during operation'
            self.save(changed)
            return {'status': 'PASS', 'validation_level': 'STATIC_LIFT_ARM_OBJECTS_NOT_GUEST_EXECUTED'}

        with patch('portable_lifter_v1.probe.run_probe', side_effect=fake_probe), \
             patch.object(build, 'source_snapshot', return_value={}), \
             patch.object(build.tools, 'selected_closure', return_value={'nodes': {}, 'edges': []}):
            with self.assertRaisesRegex(ValueError, 'manifest changed'):
                build.probe(self.prefix, 'unused-pe', out)
        self.assertFalse((out / 'result.json').exists())
        failure = json.loads((out / 'failure.json').read_text())
        self.assertEqual(failure['status'], 'FAIL')
        self.assertIn('manifest changed', failure['error'])


class RecorderBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='portable-recorder-unit-')
        self.base = Path(self.temp.name).resolve()
        self.recorder = build.Recorder(self.base, self.base / 'provider')

    def tearDown(self):
        self.temp.cleanup()

    def fake_process(self, returncode):
        def execute(argv, cwd, env, stdout, stderr):
            stdout.write(b'raw stdout\x00\xff\n'); stderr.write(b'raw stderr\n')
            return SimpleNamespace(returncode=returncode)
        return execute

    def test_return_code_and_raw_stream_evidence_are_retained_on_failure(self):
        with patch.object(build.subprocess, 'run', side_effect=self.fake_process(7)):
            with self.assertRaisesRegex(ValueError, 'exit 7'):
                self.recorder(['/nonexecuted/tool'], 'fixture-fail')
        self.assertEqual(len(self.recorder.commands), 1)
        record = self.recorder.commands[0]
        self.assertEqual(record['returncode'], 7)
        self.assertEqual(Path(record['stdout_path']).read_bytes(), b'raw stdout\x00\xff\n')
        self.assertEqual(record['stdout_sha256'], hashlib.sha256(b'raw stdout\x00\xff\n').hexdigest())
        self.assertTrue((self.base / 'commands/001-fixture-fail.result.json').is_file())

    def test_same_label_creates_separate_evidence_and_old_work_is_refused(self):
        with patch.object(build.subprocess, 'run', side_effect=self.fake_process(0)) as process:
            first = self.recorder(['/nonexecuted/tool'], 'fixture.same')
            second = self.recorder(['/nonexecuted/tool'], 'fixture.same')
            self.assertNotEqual(first['stdout_path'], second['stdout_path'])
            with self.assertRaisesRegex(ValueError, 'old work dependency'):
                self.recorder([build.OLD_WORK / 'tool'], 'old')
            self.assertEqual(process.call_count, 2)
        self.assertEqual(len(self.recorder.commands), 2)

    def test_launch_error_still_has_failed_receipt_and_hashed_streams(self):
        with patch.object(build.subprocess, 'run', side_effect=FileNotFoundError('synthetic absent tool')):
            with self.assertRaisesRegex(ValueError, 'launch error'):
                self.recorder(['/nonexecuted/missing'], 'fixture-launch-error')
        self.assertEqual(len(self.recorder.commands), 1)
        record = self.recorder.commands[0]
        self.assertIsNone(record['returncode'])
        self.assertIn('synthetic absent tool', record['launch_error'])
        self.assertEqual(record['stderr_sha256'], build.digest(record['stderr_path']))
        self.assertTrue((self.base / 'commands/001-fixture-launch-error.result.json').is_file())

    def test_existing_evidence_directory_is_not_overwritten(self):
        sentinel = self.base / 'original'; sentinel.write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'fresh absent directory'):
            build.fresh(self.base)
        self.assertEqual(sentinel.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main(verbosity=2)
