"""Independent deadline/ownership/continuation boundaries; no real processes."""
import datetime
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

from . import complete as c


class IndependentContinuationReview(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='graphics-complete-review-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.out = self.root / 'out'; (self.out / 'logs').mkdir(parents=True)
        for owner, name in ((c.subprocess, 'Popen'), (c.os, 'killpg'), (c.network, 'opener')):
            patch = mock.patch.object(owner, name, side_effect=AssertionError('real process/signal/network forbidden'))
            patch.start(); self.addCleanup(patch.stop)

    def arguments(self):
        return ['-C', self.out / 'llvm-git', 'checkout', '--detach', c.cache.LLVM_COMMIT]

    def result(self, stem):
        return json.loads((self.out / 'logs' / (stem + '.result.json')).read_bytes())

    def test_only_exact_new_checkout_has_long_deadline_and_no_global_change(self):
        previous_seconds = c.network.GIT_SECONDS
        original = c.original.git_recorder(self.out, 'http://127.0.0.1:8118')
        run = c.CheckoutRecorder(self.out, 'http://127.0.0.1:8118')
        process = mock.Mock(); process.wait.return_value = 0
        with mock.patch.object(c.subprocess, 'Popen', return_value=process) as launched:
            run(self.arguments(), 'llvm-selected-checkout')
            run(['--version'], 'git-version')
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=1200), mock.call(timeout=300)])
        self.assertTrue(all(call.kwargs['start_new_session'] for call in launched.call_args_list))
        for stem, seconds in (('001-llvm-selected-checkout', 1200), ('002-git-version', 300)):
            record = self.result(stem)
            self.assertEqual(record['timeout_seconds'], seconds)
            difference = datetime.datetime.fromisoformat(record['deadline_at']) - datetime.datetime.fromisoformat(record['started_at'])
            self.assertEqual(difference.total_seconds(), seconds)
            self.assertEqual(record['returncode'], 0)
        before = sorted(p.name for p in (self.out / 'logs').iterdir())
        with self.assertRaisesRegex(ValueError, 'only for the fixed new LLVM checkout'):
            run(['-C', self.root / 'old-repo', 'checkout', '--detach', c.cache.LLVM_COMMIT], 'llvm-selected-checkout')
        self.assertEqual(sorted(p.name for p in (self.out / 'logs').iterdir()), before)
        self.assertEqual(c.network.GIT_SECONDS, previous_seconds)
        after = c.original.git_recorder(self.out, 'http://127.0.0.1:8118')
        self.assertEqual((original.prefix, original.env), (after.prefix, after.env))

    def test_timeout_signals_only_its_fake_owned_group_and_preserves_failure(self):
        run = c.CheckoutRecorder(self.out)
        process = mock.Mock(pid=246813)
        process.wait.side_effect = [subprocess.TimeoutExpired('fixture-checkout', 1200), -15, -15]
        with mock.patch.object(c.subprocess, 'Popen', return_value=process), \
             mock.patch.object(c.os, 'killpg', side_effect=[None, ProcessLookupError()]) as kill, \
             self.assertRaises(subprocess.TimeoutExpired):
            run(self.arguments(), 'llvm-selected-checkout')
        self.assertEqual(kill.call_args_list, [mock.call(246813, signal.SIGTERM), mock.call(246813, signal.SIGKILL)])
        self.assertEqual(process.wait.call_args_list, [mock.call(timeout=1200), mock.call(timeout=2), mock.call(timeout=5)])
        result = self.result('001-llvm-selected-checkout')
        self.assertEqual(result['error'], {'type': 'TimeoutExpired', 'category': 'git-command-timeout'})
        self.assertEqual(result['returncode'], -15)
        self.assertEqual(result['owned_group_cleanup'], [{'signal': 15, 'group': 246813}, {'signal': 9, 'group_absent': True}])
        self.assertIn('stdout_sha256', result); self.assertIn('stderr_sha256', result)

    def test_launch_failure_is_not_success_and_does_not_signal_unknown_process(self):
        run = c.CheckoutRecorder(self.out)
        with mock.patch.object(c.subprocess, 'Popen', side_effect=OSError('fixture launch failure')), \
             mock.patch.object(c.os, 'killpg') as kill, self.assertRaises(OSError):
            run(self.arguments(), 'llvm-selected-checkout')
        kill.assert_not_called()
        result = self.result('001-llvm-selected-checkout')
        self.assertIsNone(result['returncode'])
        self.assertEqual(result['error'], {'type': 'OSError'})
        self.assertEqual(result['owned_group_cleanup'], [])

    def test_overlap_with_old_cache_or_failure_directory_rejects_before_new_writes(self):
        old_cache = self.root / 'old-cache'; old_cache.mkdir()
        old_origin = self.root / 'old-origin'; old_origin.mkdir()
        marker = old_origin / 'keep'; marker.write_bytes(b'original failure remains')
        record = {'origin': str(old_origin), 'cache': str(old_cache)}
        for new_cache, out in ((old_cache / 'nested', self.root / 'fresh-out'),
                               (self.root / 'fresh-cache', old_origin / 'nested')):
            with self.subTest(new_cache=new_cache, out=out), \
                 mock.patch.object(c.cache, 'load_lock', return_value={}), \
                 mock.patch.object(c, 'inspect_acquisition', return_value=record), \
                 mock.patch.object(c.original, 'acquire_llvm') as acquire, \
                 self.assertRaisesRegex(ValueError, 'disjoint from old acquisition'):
                c.complete(new_cache, out, old_origin)
            acquire.assert_not_called()
            self.assertFalse(new_cache.exists()); self.assertFalse(out.exists())
            self.assertEqual(marker.read_bytes(), b'original failure remains')

    def test_bare_old_cache_or_unrelated_failure_is_not_a_valid_continuation(self):
        bare = self.root / 'arbitrary-cache'; bare.mkdir()
        (bare / 'dxmt.tar.gz').write_bytes(b'not downloaded')
        with self.assertRaises((ValueError, FileNotFoundError)):
            c.inspect_acquisition(bare, {})
        origin = self.root / 'unrelated-failure'; origin.mkdir()
        (origin / 'started.json').write_text(json.dumps({'schema': 2, 'content_lock_sha256': c.digest(c.cache.LOCK)}))
        (origin / 'failure.json').write_text(json.dumps({'schema': 2, 'status': 'PUBLIC_GRAPHICS_CACHE_ACQUISITION_FAILED',
                                                      'error': {'type': 'ValueError', 'message': 'some other failure'}}))
        with self.assertRaisesRegex(ValueError, 'typed Git timeout'):
            c.inspect_acquisition(origin, {})


if __name__ == '__main__':
    unittest.main()
