"""Small metadata/copy/proxy tests; no real Git, network or large package reads."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from . import complete as c


class CompletionBoundaries(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='cache-complete-unit-'); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()

    def origin(self):
        origin = self.base / 'old-evidence'; origin.mkdir(); (origin / 'logs').mkdir()
        cache = self.base / 'old-cache'; cache.mkdir()
        plan = c.sources.plan()
        snapshots = {}
        for source in c.frozen_range_inputs():
            relative = source.relative_to(c.sources.ROOT)
            target = origin / 'implementation' / relative
            target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, target)
            snapshots[str(relative)] = c.digest(target)
        for name, spec in plan['packages'].items():
            path = cache / name; path.write_bytes(('fixture-' + name).encode())
            spec['sha256'] = c.digest(path)
            start = {'name': name, 'url': spec['url'], 'sha256_expected': spec['sha256'], 'started_at': 'fixture'}
            status = 'RANGED_DOWNLOAD_AND_HASH_VERIFIED' if spec['kind'] == 'ghcr' else 'DOWNLOADED_AND_HASH_VERIFIED'
            c.write(origin / 'logs' / (name + '.started.json'), start)
            c.write(origin / 'logs' / (name + '.result.json'), dict(start, status=status, sha256=spec['sha256'], bytes=path.stat().st_size))
        c.write(origin / 'started.json', {'schema': 2, 'cache': str(cache), 'plan': plan, 'sources': snapshots})
        c.write(origin / 'failure.json', {'schema': 2, 'status': 'CPU_PUBLIC_CACHE_PREPARATION_FAILED',
                'error': {'type': 'ValueError', 'message': 'Git command failed: gflags-fetch'}})
        prefix = c.previous.GitRecorder(origin).prefix
        argv = prefix + ['-C', str(origin / 'repositories/gflags.git'), 'fetch', '--no-tags', '--depth=1',
                         plan['sources']['gflags']['repository'], plan['sources']['gflags']['commit']]
        outputs = {kind: origin / 'logs' / ('003-gflags-fetch.' + kind) for kind in ('stdout', 'stderr')}
        for path in outputs.values():
            path.write_bytes(b'synthetic failed fetch')
        start = {'argv': argv, 'cwd': str(origin), 'env': {}, 'started_at': 'fixture',
                 **{kind + '_path': str(path) for kind, path in outputs.items()}}
        c.write(origin / 'logs/003-gflags-fetch.started.json', start)
        c.write(origin / 'logs/003-gflags-fetch.result.json', dict(start, error=None, returncode=128,
                **{kind + '_sha256': c.digest(path) for kind, path in outputs.items()}))
        return origin, cache, plan

    def test_proxy_is_explicit_and_forbids_credentials_or_extra_url_parts(self):
        for value in ('http://127.0.0.1:8118', 'https://proxy.example:443', 'http://[::1]:8118'):
            self.assertEqual(c.validate_proxy(value), value)
        for value in ('file:///tmp/proxy', 'socks5://127.0.0.1:8118', 'http://user:secret@host:80',
                      'http://host:80?token=secret', 'http://host:80#secret', 'http://host:80/path',
                      'http://host:99999', 'http://host:0', 'http://host:abc', 'http://host\n', ''):
            with self.subTest(value=value), self.assertRaises(ValueError):
                c.validate_proxy(value)

    def test_proxy_changes_only_the_new_recorder_instance(self):
        base = c.previous.GitRecorder(self.base)
        before = list(base.prefix)
        proxied = c.ProxyGitRecorder(self.base, 'http://127.0.0.1:8118')
        self.assertEqual(proxied.prefix, [*before, '-c', 'http.proxy=http://127.0.0.1:8118'])
        self.assertEqual(base.prefix, before)
        self.assertEqual(c.previous.GitRecorder(self.base).prefix, before)
        self.assertEqual(proxied.env['GIT_CONFIG_GLOBAL'], '/dev/null')

    def test_exact_five_downloads_and_old_manifest_copy_without_old_mutation(self):
        origin, old_cache, plan = self.origin()
        record = c.inspect_downloads(origin, plan)
        self.assertEqual(len(c.frozen_range_inputs()), 14)
        new = self.base / 'new-cache'; new.mkdir()
        copied = c.copy_downloads(record, new)
        self.assertEqual(set(copied), set(plan['packages']))
        for name in copied:
            self.assertEqual((new / name).read_bytes(), (old_cache / name).read_bytes())
            self.assertNotEqual((new / name).stat().st_ino, (old_cache / name).stat().st_ino)
        c.ranged.check_origin(record)

    def test_failed_or_tampered_package_cannot_be_imported(self):
        origin, old_cache, plan = self.origin()
        first = next(iter(plan['packages']))
        result_path = origin / 'logs' / (first + '.result.json')
        result = json.loads(result_path.read_bytes()); original = dict(result)
        result['status'] = 'DOWNLOAD_FAILED'; result_path.write_text(json.dumps(result))
        with self.assertRaisesRegex(ValueError, 'package identity'):
            c.inspect_downloads(origin, plan)
        result_path.write_text(json.dumps(original))
        (old_cache / first).write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError, 'package bytes'):
            c.inspect_downloads(origin, plan)

    def test_old_source_manifest_or_fetch_logs_cannot_drift(self):
        origin, old_cache, plan = self.origin()
        started = origin / 'started.json'; value = json.loads(started.read_bytes())
        original = json.loads(started.read_bytes()); value['sources']['migration_cache_v2/complete.py'] = '0' * 64
        started.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'manifest differs'):
            c.inspect_downloads(origin, plan)
        started.write_text(json.dumps(original))
        (origin / 'logs/003-gflags-fetch.stderr').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'raw log'):
            c.inspect_downloads(origin, plan)

    def test_copy_refuses_existing_files_and_rechecks_source_before_copy(self):
        origin, old_cache, plan = self.origin()
        record = c.inspect_downloads(origin, plan)
        new = self.base / 'new'; new.mkdir()
        first = next(iter(record['packages']))
        (new / first).write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            c.copy_downloads(record, new)
        self.assertEqual((new / first).read_bytes(), b'keep')
        (old_cache / first).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'origin changed'):
            c.copy_downloads(record, self.base / 'absent')

    def test_invalid_proxy_fails_before_any_source_inspection_or_output(self):
        out = self.base / 'out'
        with mock.patch.object(c, 'inspect_downloads') as read, self.assertRaises(ValueError):
            c.complete(self.base / 'cache', out, self.base / 'old', 'http://u:secret@host')
        read.assert_not_called()
        self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
