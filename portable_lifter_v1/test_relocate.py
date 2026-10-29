"""Temporary filesystem relocation boundaries; the native probe is always mocked."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from portable_lifter_v1 import build, deps, relocate


class RelocationBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='portable-relocate-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / 'work/provider'
        self.destination = self.base / 'work/provider-copy'
        self.held = self.base / 'work/provider-withheld'
        self.out = self.base / 'evidence'
        self.pe = self.put(self.base / 'input.exe', b'synthetic PE placeholder; never executed')
        sdk = self.base / 'sdk'
        settings = self.put(sdk / 'SDKSettings.json', b'{"synthetic_sdk": true}\n')
        runtime = {}
        for relative in ('lifter/remill-lift-17', 'semantics/amd64.bc',
                         'llvm/bin/clang', 'llvm/bin/opt', 'llvm/bin/llvm-link'):
            path = self.put(self.source / relative, ('synthetic ' + relative).encode())
            runtime[relative] = dict(sha256=build.digest(path), mode=path.stat().st_mode & 0o777)
        self.put(self.source / 'source/State.h', b'synthetic source identity\n')
        provider = dict(schema=1, status='CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED',
                        runtime_files=runtime, source_tree=deps.tree(self.source / 'source'),
                        layout=dict(lifter='lifter/remill-lift-17', semantics='semantics/amd64.bc',
                                    llvm='llvm', source='source'),
                        external_prerequisites=dict(sdk=str(sdk), sdk_settings={settings.name: build.digest(settings)}))
        build.write_json(self.source / 'provider.json', provider)
        self.original_tree = deps.tree(self.source)
        self.original_manifest = (self.source / 'provider.json').read_bytes()

    @staticmethod
    def put(path, contents):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    def invoke(self):
        return relocate.relocate(self.source, self.destination, self.pe, self.out)

    def assert_withheld_during_probe(self, prefix, pe, out):
        self.assertEqual(prefix, self.destination)
        self.assertEqual(pe, self.pe)
        self.assertEqual(out, self.out / 'probe')
        self.assertFalse(self.source.exists())
        self.assertFalse(self.source.is_symlink())
        self.assertTrue(self.held.is_dir())
        self.assertEqual(deps.tree(self.held), self.original_tree)
        self.assertEqual(deps.tree(self.destination), self.original_tree)
        build.paths_for(prefix)  # Validate relative inventory against the copy.
        return out

    def assert_restored(self, failed):
        self.assertTrue(self.source.is_dir())
        self.assertFalse(self.held.exists())
        self.assertEqual(deps.tree(self.source), self.original_tree)
        self.assertEqual((self.source / 'provider.json').read_bytes(), self.original_manifest)
        record = json.loads((self.out / 'restoration.json').read_bytes())
        self.assertIs(record['original_restored'], True)
        self.assertIs(record['withheld_exists'], False)
        self.assertEqual((self.out / 'failure.json').exists(), failed)
        if failed:
            failure = json.loads((self.out / 'failure.json').read_bytes())
            self.assertEqual(failure['status'], 'FAIL')
            self.assertIs(failure['original_restored'], True)
            self.assertFalse((self.out / 'result.json').exists())

    def test_probe_only_runs_while_original_is_absent_and_restores_unchanged(self):
        def probe(prefix, pe, out):
            out = self.assert_withheld_during_probe(prefix, pe, out)
            out.mkdir()
            build.write_json(out / 'result.json', {'status': 'SYNTHETIC_PROBE_NOT_EXECUTED'})
        with mock.patch.object(build, 'probe', side_effect=probe) as mocked:
            result = self.invoke()
        mocked.assert_called_once()
        self.assert_restored(failed=False)
        self.assertEqual(result['status'], 'COPIED_PROVIDER_STATIC_PROBE_PASSED_ORIGINAL_RESTORED')
        self.assertEqual(result['original_provider_sha256'], result['copied_provider_sha256'])
        self.assertEqual(result['probe_receipt_sha256'], build.digest(self.out / 'probe/result.json'))
        self.assertEqual(deps.tree(self.destination), self.original_tree)
        unavailable = json.loads((self.out / 'original-unavailable.json').read_bytes())
        self.assertIs(unavailable['original_exists'], False)
        self.assertIs(unavailable['withheld_exists'], True)

    def failure_in_probe(self, failure):
        def probe(prefix, pe, out):
            self.assert_withheld_during_probe(prefix, pe, out)
            raise failure
        with mock.patch.object(build, 'probe', side_effect=probe) as mocked:
            with self.assertRaises(type(failure)) as caught:
                self.invoke()
        self.assertIs(caught.exception, failure)
        mocked.assert_called_once()
        self.assert_restored(failed=True)
        self.assertEqual(deps.tree(self.destination), self.original_tree)

    def test_probe_exception_restores_original(self):
        self.failure_in_probe(RuntimeError('synthetic probe failure'))

    def test_probe_keyboard_interrupt_restores_original(self):
        self.failure_in_probe(KeyboardInterrupt('synthetic interruption'))

    def test_restored_directory_with_changed_runtime_is_not_reported_as_verified(self):
        def corrupt(prefix, pe, out):
            self.assert_withheld_during_probe(prefix, pe, out)
            (self.held / 'lifter/remill-lift-17').write_bytes(b'changed held runtime')
            out.mkdir()
            build.write_json(out / 'result.json', {'status': 'SYNTHETIC_PROBE_NOT_EXECUTED'})
        with mock.patch.object(build, 'probe', side_effect=corrupt) as probe:
            with self.assertRaisesRegex(RuntimeError, 'original-prefix restoration failed'):
                self.invoke()
        probe.assert_called_once()
        self.assertTrue(self.source.is_dir())
        self.assertFalse(self.held.exists())
        self.assertEqual((self.source / 'provider.json').read_bytes(), self.original_manifest)
        self.assertEqual((self.source / 'lifter/remill-lift-17').read_bytes(), b'changed held runtime')
        self.assertEqual(deps.tree(self.destination), self.original_tree)
        for name in ('restoration.json', 'failure.json'):
            record = json.loads((self.out / name).read_bytes())
            self.assertIs(record['original_restored'], False)
            self.assertIn('provider file identity changed: lifter/remill-lift-17', record['restore_error'])
        self.assertFalse((self.out / 'result.json').exists())

    def test_occupied_original_path_preserves_both_trees_and_records_restore_failure(self):
        def occupied(prefix, pe, out):
            self.assert_withheld_during_probe(prefix, pe, out)
            self.put(self.source / 'occupied-marker', b'new occupant must not be overwritten')
        with mock.patch.object(build, 'probe', side_effect=occupied) as probe:
            with self.assertRaisesRegex(RuntimeError, 'original-prefix restoration failed'):
                self.invoke()
        probe.assert_called_once()
        self.assertEqual((self.source / 'occupied-marker').read_bytes(), b'new occupant must not be overwritten')
        self.assertEqual(list(self.source.iterdir()), [self.source / 'occupied-marker'])
        self.assertEqual(deps.tree(self.held), self.original_tree)
        self.assertEqual(deps.tree(self.destination), self.original_tree)
        restoration = json.loads((self.out / 'restoration.json').read_bytes())
        self.assertIs(restoration['original_restored'], False)
        self.assertIs(restoration['withheld_exists'], True)
        failure = json.loads((self.out / 'failure.json').read_bytes())
        self.assertEqual(failure['status'], 'FAIL')
        self.assertIs(failure['original_restored'], False)
        self.assertFalse((self.out / 'result.json').exists())

    def test_partial_copy_failure_never_withholds_original(self):
        def failed_copy(source, destination, **kwargs):
            self.assertEqual(source, self.source)
            self.assertEqual(destination, self.destination)
            self.assertTrue(source.is_dir())
            self.assertFalse(self.held.exists())
            self.put(destination / 'partial-copy', b'preserve failed attempt')
            raise OSError('synthetic copy failure')
        with mock.patch.object(relocate.shutil, 'copytree', side_effect=failed_copy), \
             mock.patch.object(build, 'probe') as probe:
            with self.assertRaisesRegex(OSError, 'synthetic copy failure'):
                self.invoke()
        probe.assert_not_called()
        self.assert_restored(failed=True)
        self.assertEqual((self.destination / 'partial-copy').read_bytes(), b'preserve failed attempt')
        self.assertFalse((self.out / 'original-unavailable.json').exists())

    def test_copied_manifest_change_rejected_before_original_rename(self):
        real_copytree = shutil.copytree
        def changed_copy(source, destination, *args, **kwargs):
            result = real_copytree(source, destination, *args, **kwargs)
            if Path(destination) == self.destination:
                with (self.destination / 'provider.json').open('ab') as output:
                    output.write(b'\n')  # Valid JSON, changed exact identity.
            return result
        with mock.patch.object(relocate.shutil, 'copytree', side_effect=changed_copy), \
             mock.patch.object(build, 'probe') as probe:
            with self.assertRaisesRegex(ValueError, 'copied provider metadata changed'):
                self.invoke()
        probe.assert_not_called()
        self.assert_restored(failed=True)
        self.assertFalse((self.out / 'original-unavailable.json').exists())

    def assert_preexisting_rejected(self, path, expected):
        self.put(path / 'marker', b'keep existing')
        with mock.patch.object(build, 'probe') as probe:
            with self.assertRaisesRegex(ValueError, expected):
                self.invoke()
        probe.assert_not_called()
        self.assertEqual((path / 'marker').read_bytes(), b'keep existing')
        self.assertEqual(deps.tree(self.source), self.original_tree)
        self.assertFalse((self.out / 'started.json').exists())

    def test_existing_copy_destination_is_never_overwritten(self):
        self.assert_preexisting_rejected(self.destination, 'copy destination must be absent')
        self.assertFalse(self.held.exists())

    def test_existing_withheld_directory_is_never_overwritten(self):
        self.assert_preexisting_rejected(self.held, 'withheld path must be absent')
        self.assertFalse(self.destination.exists())

    def test_existing_evidence_directory_is_never_overwritten(self):
        self.assert_preexisting_rejected(self.out, 'fresh absent directory required')
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.held.exists())

    def test_identical_or_non_sibling_prefixes_rejected_before_writes(self):
        for destination in (self.source, self.base / 'elsewhere/provider'):
            with self.subTest(destination=str(destination)), mock.patch.object(build, 'probe') as probe:
                with self.assertRaisesRegex(ValueError, 'distinct sibling prefixes required'):
                    relocate.relocate(self.source, destination, self.pe, self.out)
                probe.assert_not_called()
        self.assertEqual(deps.tree(self.source), self.original_tree)
        self.assertFalse(self.out.exists())
        self.assertFalse(self.held.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
