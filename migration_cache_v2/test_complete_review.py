"""Independent continuation contracts; tiny fixtures, no network or real cache."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from . import complete as c


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def files(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}


class IndependentCompletionReview(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cache-complete-review-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        for owner, name in ((c.previous, 'opener'), (c.previous.subprocess, 'Popen')):
            patch = mock.patch.object(owner, name, side_effect=AssertionError('network/process forbidden'))
            patch.start(); self.addCleanup(patch.stop)
        self.impl = self.base / 'fixture-source.py'
        self.impl.write_bytes(b'# immutable synthetic acquisition implementation\n')
        for patch in (mock.patch.object(c.sources, 'ROOT', self.base),
                      mock.patch.object(c, 'frozen_range_inputs', return_value=[self.impl])):
            patch.start(); self.addCleanup(patch.stop)
        self.origin = self.base / 'attempt-02'
        self.cache = self.base / 'cache-02'
        self.cache.mkdir(); (self.origin / 'logs').mkdir(parents=True)
        self.plan = {'packages': {}, 'sources': {'gflags': {
            'repository': 'https://github.com/gflags/gflags.git', 'commit': '1' * 40}}}
        for number, name in enumerate(('llvm17.tar.gz', 'cmake.tar.gz', 'ninja.tar.gz',
                                        'remill.tar.gz', 'zstd-1.5.7.tar.gz')):
            raw = ('tiny-package-' + name).encode()
            (self.cache / name).write_bytes(raw)
            kind = 'ghcr' if number < 3 else 'codeload'
            spec = {'kind': kind, 'url': 'https://example.invalid/' + name, 'sha256': sha(raw)}
            self.plan['packages'][name] = spec
            start = {'name': name, 'url': spec['url'], 'sha256_expected': spec['sha256'],
                     'started_at': 'synthetic-start'}
            result = dict(start, status='RANGED_DOWNLOAD_AND_HASH_VERIFIED' if kind == 'ghcr'
                          else 'DOWNLOADED_AND_HASH_VERIFIED', sha256=spec['sha256'], bytes=len(raw))
            write(self.origin / 'logs' / (name + '.started.json'), start)
            write(self.origin / 'logs' / (name + '.result.json'), result)
        write(self.origin / 'started.json', {'schema': 2, 'plan': self.plan, 'cache': str(self.cache),
            'sources': {self.impl.name: sha(self.impl.read_bytes())}})
        write(self.origin / 'failure.json', {'schema': 2, 'status': 'CPU_PUBLIC_CACHE_PREPARATION_FAILED',
            'error': {'type': 'ValueError', 'message': 'Git command failed: gflags-fetch'}})
        (self.origin / 'implementation').mkdir()
        (self.origin / 'implementation' / self.impl.name).write_bytes(self.impl.read_bytes())
        recorder = c.previous.GitRecorder(self.origin)
        start = {'argv': recorder.prefix + ['-C', str(self.origin / 'repositories/gflags.git'),
                 'fetch', '--no-tags', '--depth=1', self.plan['sources']['gflags']['repository'], '1' * 40],
                 'cwd': str(self.origin), 'env': recorder.env, 'started_at': 'synthetic-fetch-start'}
        result = dict(start, returncode=128, error=None)
        for kind, raw in (('stdout', b''), ('stderr', b'fixture network unavailable\n')):
            path = self.origin / 'logs' / ('003-gflags-fetch.' + kind)
            path.write_bytes(raw)
            start[kind + '_path'] = str(path)
            result[kind + '_path'] = str(path)
            result[kind + '_sha256'] = sha(raw)
        write(self.origin / 'logs/003-gflags-fetch.started.json', start)
        write(self.origin / 'logs/003-gflags-fetch.result.json', result)

    def test_proxy_rejects_credentials_before_writes_and_remains_instance_local(self):
        bad = ('http://user:REVIEW_SECRET@127.0.0.1:8118', 'http://user@localhost',
               'http://127.0.0.1:8118?token=REVIEW_SECRET', 'http://127.0.0.1/path',
               'http://127.0.0.1/#REVIEW_SECRET', 'socks5://127.0.0.1:8118',
               'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://localhost\n')
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                c.complete(self.base / 'new-cache', self.base / 'new-out', self.origin, value)
            self.assertNotIn('REVIEW_SECRET', str(c.previous.error_record(error.exception)))
        self.assertFalse((self.base / 'new-cache').exists())
        self.assertFalse((self.base / 'new-out').exists())
        original = c.previous.GitRecorder(self.base)
        proxied = c.ProxyGitRecorder(self.base, 'http://127.0.0.1:8118')
        second = c.ProxyGitRecorder(self.base, 'http://127.0.0.1:8119')
        self.assertEqual(proxied.prefix, original.prefix + ['-c', 'http.proxy=http://127.0.0.1:8118'])
        self.assertEqual(second.prefix, original.prefix + ['-c', 'http.proxy=http://127.0.0.1:8119'])
        self.assertEqual(c.previous.GitRecorder(self.base).prefix, original.prefix)
        self.assertEqual(proxied.env, original.env)
        self.assertEqual(proxied.env['GIT_CONFIG_GLOBAL'], '/dev/null')
        self.assertEqual(proxied.env['GIT_CONFIG_NOSYSTEM'], '1')
        self.assertNotIn('http_proxy', proxied.env)

    def test_five_completed_downloads_copy_only_to_new_cache_and_preserve_origin(self):
        original, packages = files(self.origin), files(self.cache)
        record = c.inspect_downloads(self.origin, self.plan)
        target = self.base / 'cache-03'; target.mkdir()
        copied = c.copy_downloads(record, target)
        self.assertEqual(set(copied), set(self.plan['packages']))
        self.assertEqual(files(target), packages)
        self.assertEqual(files(self.origin), original)
        self.assertEqual(files(self.cache), packages)
        self.assertEqual(c.inspect_downloads(self.origin, self.plan), record)
        with self.assertRaises((ValueError, FileNotFoundError)):
            c.inspect_downloads(self.cache, self.plan)  # Five archives alone have no provenance.

    def test_missing_or_altered_origin_records_and_fixed_bytes_are_rejected(self):
        changes = {
            self.origin / 'logs/llvm17.tar.gz.result.json': None,
            self.origin / 'implementation' / self.impl.name: b'changed implementation',
            self.origin / 'logs/003-gflags-fetch.stderr': b'changed failed command output',
            self.cache / 'cmake.tar.gz': b'different complete package',
        }
        for path, changed in changes.items():
            original = path.read_bytes()
            try:
                path.unlink() if changed is None else path.write_bytes(changed)
                with self.subTest(path=path.name), self.assertRaises((ValueError, FileNotFoundError)):
                    c.inspect_downloads(self.origin, self.plan)
            finally:
                path.write_bytes(original)
        path = self.origin / 'logs/ninja.tar.gz.result.json'
        original = path.read_bytes(); result = json.loads(original)
        result['url'] = 'https://unrecorded.invalid/package'
        write(path, result)
        with self.assertRaises(ValueError): c.inspect_downloads(self.origin, self.plan)
        path.write_bytes(original)
        extra = self.cache / 'gflags.tar'; extra.write_bytes(b'unattested cached source')
        with self.assertRaises(ValueError): c.inspect_downloads(self.origin, self.plan)

    def test_changed_origin_after_inspection_is_rejected_before_copy(self):
        record = c.inspect_downloads(self.origin, self.plan)
        target = self.base / 'cache-03'; target.mkdir()
        (self.cache / 'llvm17.tar.gz').write_bytes(b'changed after inspection')
        with self.assertRaises(ValueError): c.copy_downloads(record, target)
        self.assertEqual(list(target.iterdir()), [])

    def test_new_attempt_paths_cannot_mutate_old_evidence_or_cache(self):
        original, packages = files(self.origin), files(self.cache)
        for cache, out in ((self.cache / 'nested-new', self.base / 'new-out'),
                           (self.base / 'new-cache', self.origin / 'nested-new'),
                           (self.base / 'fresh', self.base / 'fresh/nested')):
            with self.subTest(cache=cache, out=out), mock.patch.object(c.sources, 'plan', return_value=self.plan), \
                    self.assertRaises(ValueError):
                c.complete(cache, out, self.origin, 'http://127.0.0.1:8118')
            self.assertFalse(cache.exists()); self.assertFalse(out.exists())
        self.assertEqual(files(self.origin), original)
        self.assertEqual(files(self.cache), packages)


if __name__ == '__main__':
    unittest.main()
