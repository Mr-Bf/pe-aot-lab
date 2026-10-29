"""Tiny receipt/copy/deadline fixtures; no real Git, package reads or network."""
import datetime
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from . import complete as c


class CompletionBoundaries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='graphics-completion-unit-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.out = self.base / 'evidence'; self.out.mkdir(); (self.out / 'logs').mkdir()

    def checkout_arguments(self):
        return ['-C', str(self.out / 'llvm-git'), 'checkout', '--detach', c.cache.LLVM_COMMIT]

    def test_only_fixed_checkout_gets_long_deadline_without_global_changes(self):
        original_timeout = c.network.GIT_SECONDS
        recorder = c.CheckoutRecorder(self.out, 'http://127.0.0.1:8118')
        process = mock.Mock(pid=12345); process.wait.return_value = 0
        with mock.patch.object(c.subprocess, 'Popen', return_value=process) as launch:
            recorder(['--version'], 'git-version')
            recorder(self.checkout_arguments(), 'llvm-selected-checkout')
        self.assertEqual([call.kwargs['timeout'] for call in process.wait.call_args_list], [300, 1200])
        self.assertEqual(c.network.GIT_SECONDS, original_timeout)
        self.assertTrue(all(call.kwargs['start_new_session'] for call in launch.call_args_list))
        row = json.loads((self.out / 'logs/002-llvm-selected-checkout.result.json').read_bytes())
        delta = datetime.datetime.fromisoformat(row['deadline_at']) - datetime.datetime.fromisoformat(row['started_at'])
        self.assertEqual(delta.total_seconds(), 1200)
        self.assertIn('http.proxy=http://127.0.0.1:8118', row['argv'])

    def test_other_command_cannot_claim_checkout_deadline_by_label(self):
        recorder = c.CheckoutRecorder(self.out)
        with mock.patch.object(c.subprocess, 'Popen') as launch, self.assertRaisesRegex(ValueError, 'only for the fixed'):
            recorder(['fetch'], 'llvm-selected-checkout')
        launch.assert_not_called()
        self.assertEqual(list((self.out / 'logs').iterdir()), [])

    def test_timeout_records_exact_owned_group_cleanup_and_actual_wait_status(self):
        recorder = c.CheckoutRecorder(self.out)
        process = mock.Mock(pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired(['git'], 1200), -15, -15]
        with mock.patch.object(c.subprocess, 'Popen', return_value=process), mock.patch.object(c.os, 'killpg') as signal, \
             self.assertRaises(subprocess.TimeoutExpired):
            recorder(self.checkout_arguments(), 'llvm-selected-checkout')
        self.assertEqual([call.args for call in signal.call_args_list], [(12345, c.signal.SIGTERM), (12345, c.signal.SIGKILL)])
        row = json.loads((self.out / 'logs/001-llvm-selected-checkout.result.json').read_bytes())
        self.assertEqual(row['returncode'], -15)
        self.assertEqual(row['error'], {'type': 'TimeoutExpired', 'category': 'git-command-timeout'})
        self.assertEqual(row['timeout_seconds'], 1200)

    def origin(self):
        origin = self.base / 'old'; origin.mkdir(); (origin / 'logs').mkdir()
        old_cache = self.base / 'old-cache'; old_cache.mkdir()
        lock = c.cache.load_lock()
        identities = {}
        for path in c.original.implementation_inputs():
            relative = path.relative_to(c.original.ROOT); target = origin / 'implementation' / relative
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, target)
            identities[str(relative)] = c.digest(target)
        error = {'type': 'TimeoutExpired', 'category': 'git-command-timeout'}
        c.write(origin / 'started.json', {'schema': 2, 'cache': str(old_cache),
                'content_lock_sha256': c.digest(c.cache.LOCK), 'sources': identities, 'git_proxy': None})
        c.write(origin / 'failure.json', {'schema': 2, 'status': 'PUBLIC_GRAPHICS_CACHE_ACQUISITION_FAILED', 'error': error})
        for role in ('dxmt', 'headers', 'cmake', 'ninja', 'meson'):
            spec = lock['packages'][role]
            path = old_cache / spec['archive']; path.write_bytes(('tiny-fixture-' + role).encode())
            spec.update(sha256=c.digest(path), size=path.stat().st_size)
            started = {'name': spec['archive'], 'url': spec['source']['url'], 'sha256_expected': spec['sha256'], 'started_at': 'fixture'}
            status = 'RANGED_DOWNLOAD_AND_HASH_VERIFIED' if role in ('cmake', 'ninja') else 'DOWNLOADED_AND_HASH_VERIFIED'
            c.write(origin / 'logs' / (spec['archive'] + '.started.json'), started)
            c.write(origin / 'logs' / (spec['archive'] + '.result.json'), dict(started, status=status, bytes=spec['size'], sha256=spec['sha256']))
        meson = lock['packages']['meson']
        metadata = {'info': {'name': 'meson', 'version': '1.10.0'}, 'urls': [
            {'filename': meson['archive'], 'packagetype': 'bdist_wheel', 'python_version': 'py3', 'yanked': False,
             'url': meson['source']['url'], 'size': meson['size'], 'digests': {'sha256': meson['sha256']}}]}
        metadata_path = origin / 'pypi-meson-1.10.0.json'; c.write(metadata_path, metadata)
        c.write(origin / 'pypi-check.json', {'selected': c.original.check_meson_metadata(metadata, meson),
                'metadata_url': c.original.PYPI_URL, 'metadata_path': str(metadata_path), 'metadata_sha256': c.digest(metadata_path)})
        run = c.original.git_recorder(origin, None)
        started = {'argv': [*run.prefix, '-C', str(origin / 'llvm-git'), 'checkout', '--detach', c.cache.LLVM_COMMIT],
                   'cwd': str(origin), 'env': run.env, 'started_at': 'fixture'}
        hashes = {}
        for kind in ('stdout', 'stderr'):
            path = origin / 'logs' / ('012-llvm-selected-checkout.' + kind); path.write_bytes(b'')
            started[kind + '_path'] = str(path); hashes[kind + '_sha256'] = c.digest(path)
        c.write(origin / 'logs/012-llvm-selected-checkout.started.json', started)
        c.write(origin / 'logs/012-llvm-selected-checkout.result.json', dict(started, **hashes, returncode=-15, error=error,
                owned_group_cleanup=[{'group': 12345, 'signal': 15}, {'group_absent': True, 'signal': 9}]))
        return origin, old_cache, lock

    def test_five_packages_copied_without_old_llvm_repo_or_old_files_changed(self):
        origin, old_cache, lock = self.origin()
        (origin / 'llvm-git').mkdir(); (origin / 'llvm-git/partial.pack').write_bytes(b'never reused')
        record = c.inspect_acquisition(origin, lock)
        target = self.base / 'new-cache'; target.mkdir()
        copies = c.original.proxy_support.copy_downloads(record, target)
        self.assertEqual(len(copies), 5)
        self.assertEqual({path.name for path in target.iterdir()}, set(copies))
        self.assertFalse((target / 'partial.pack').exists())
        c.original.ranges.check_origin(record)

    def test_package_and_source_snapshot_corruption_are_rejected(self):
        origin, old_cache, lock = self.origin()
        path = old_cache / lock['packages']['dxmt']['archive']; raw = path.read_bytes()
        path.write_bytes(b'X' * len(raw))
        with self.assertRaisesRegex(ValueError, 'package bytes differ'):
            c.inspect_acquisition(origin, lock)
        path.write_bytes(raw)
        (origin / 'implementation/portable_graphics_v2/prepare.py').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'snapshot differs'):
            c.inspect_acquisition(origin, lock)

    def test_success_or_missing_typed_timeout_cannot_serve_as_continuation_origin(self):
        origin, old_cache, lock = self.origin()
        path = origin / 'logs/012-llvm-selected-checkout.result.json'
        row = json.loads(path.read_bytes()); row['error'] = None; path.write_text(json.dumps(row))
        with self.assertRaisesRegex(ValueError, 'timeout record differs'):
            c.inspect_acquisition(origin, lock)
        c.write(origin / 'result.json', {'status': 'claimed-success'})
        with self.assertRaisesRegex(ValueError, 'failed graphics'):
            c.inspect_acquisition(origin, lock)

    def test_bad_proxy_and_existing_outputs_fail_before_origin_inspection(self):
        with mock.patch.object(c, 'inspect_acquisition') as inspect, self.assertRaises(ValueError):
            c.complete(self.base / 'cache', self.out, self.base / 'origin', 'http://u:secret@host')
        inspect.assert_not_called()
        with mock.patch.object(c, 'inspect_acquisition') as inspect, self.assertRaisesRegex(ValueError, 'fresh absent'):
            c.complete(self.base / 'cache', self.out, self.base / 'origin')
        inspect.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
