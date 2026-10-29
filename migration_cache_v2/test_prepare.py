"""Range/recovery boundaries only: mock HTTP and tiny local prefix fixtures."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from migration_cache_v1.test_prepare import Client, Response as TokenResponse
from . import prepare as p


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Response(io.BytesIO):
    def __init__(self, raw, start, end, total, **overrides):
        super().__init__(raw)
        self.status = overrides.pop('status', 206)
        self.headers = {'Content-Range': f'bytes {start}-{end}/{total}', 'Content-Length': str(len(raw)), **overrides}


def ranged_client(*responses):
    items = []
    for response in responses:
        items.extend([TokenResponse(b'{"token":"private-anonymous-token"}'), response])
    return Client(*items)


class RangeAndResumeBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cache-range-unit-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.cache = self.base / 'new-cache'; self.cache.mkdir()
        self.logs = self.base / 'logs'; self.logs.mkdir()
        self.raw = b'abcdefghij'
        self.name = 'llvm17.tar.gz'
        self.spec = {'kind': 'ghcr', 'repository': 'llvm/17', 'url': 'https://example.invalid/fixed',
                     'sha256': sha(self.raw)}

    def test_fresh_segmented_download_enforces_ranges_and_final_hash(self):
        client = ranged_client(Response(b'abcd', 0, 3, 10), Response(b'efgh', 4, 7, 10), Response(b'ij', 8, 9, 10))
        with mock.patch.object(p, 'CHUNK_BYTES', 4):
            result = p.download_ranges(self.name, self.spec, self.cache, self.logs, client=client)
        self.assertEqual((self.cache / self.name).read_bytes(), self.raw)
        self.assertEqual(result['sha256'], sha(self.raw))
        self.assertEqual(result['resumed_bytes'], 0)
        requests = [request for request, _ in client.requests if request.get_header('Range')]
        self.assertEqual([request.get_header('Range') for request in requests], ['bytes=0-3', 'bytes=4-7', 'bytes=8-9'])
        self.assertEqual([segment['content_range'] for segment in result['segments']], ['bytes 0-3/10', 'bytes 4-7/10', 'bytes 8-9/10'])
        self.assertEqual((self.cache / self.name).stat().st_nlink, 1)
        for path in self.logs.iterdir():
            self.assertNotIn(b'private-anonymous-token', path.read_bytes())

    def test_resume_starts_at_exact_copied_prefix_and_clips_last_segment(self):
        partial = self.cache / (self.name + '.partial'); partial.write_bytes(self.raw[:6])
        prefix = {'package': self.name, 'sha256_expected': sha(self.raw), 'bytes': 6, 'sha256': sha(self.raw[:6])}
        client = ranged_client(Response(b'ghij', 6, 9, 10))
        with mock.patch.object(p, 'CHUNK_BYTES', 16):
            result = p.download_ranges(self.name, self.spec, self.cache, self.logs, prefix, client)
        self.assertEqual(client.requests[-1][0].get_header('Range'), 'bytes=6-21')
        self.assertEqual(result['resumed_bytes'], 6)
        self.assertEqual(result['bytes'], 10)
        self.assertEqual((self.cache / self.name).read_bytes(), self.raw)

    def test_response_header_rejections(self):
        cases = [Response(b'abcd', 0, 3, 10, status=200),
                 Response(b'abcd', 1, 4, 10), Response(b'abcd', 0, 2, 10),
                 Response(b'abcd', 0, 3, 11), Response(b'abcd', 0, 3, 10, **{'Content-Length': '3'}),
                 Response(b'abcd', 0, 3, 10, **{'Content-Range': 'bytes 0-3/*'}),
                 Response(b'abcd', 0, 3, 10, **{'Content-Encoding': 'gzip'}),
                 Response(b'abcd', 0, 3, p.previous.MAX_DOWNLOAD_BYTES + 1)]
        for response in cases:
            with self.subTest(headers=response.headers, status=response.status), self.assertRaises(ValueError):
                p.range_identity(response, 0, 3, 10)

    def test_rejected_http_response_preserves_bounded_actual_headers(self):
        response = Response(b'abcd', 0, 3, 10, status=200)
        with self.assertRaisesRegex(ValueError, 'requires HTTP 206'):
            p.download_ranges(self.name, self.spec, self.cache, self.logs, client=ranged_client(response))
        observed = json.loads((self.logs / (self.name + '.range-001.response.json')).read_bytes())
        self.assertEqual(observed['http_status'], 200)
        self.assertEqual(observed['headers']['Content-Range'], 'bytes 0-3/10')
        self.assertEqual((self.cache / (self.name + '.partial')).read_bytes(), b'')
        large = Response(b'', 0, 0, 1, **{'Content-Range': 'X' * 2000})
        path = self.logs / 'large.json'
        with self.assertRaisesRegex(ValueError, 'recording bounds'):
            p.observe_response(large, path)
        self.assertEqual(len(json.loads(path.read_bytes())['headers']['Content-Range']), 1024)

    def test_changed_total_in_later_segment_preserves_only_accepted_prefix(self):
        client = ranged_client(Response(b'abcd', 0, 3, 10), Response(b'efgh', 4, 7, 11))
        with mock.patch.object(p, 'CHUNK_BYTES', 4), self.assertRaisesRegex(ValueError, 'total changed'):
            p.download_ranges(self.name, self.spec, self.cache, self.logs, client=client)
        self.assertEqual((self.cache / (self.name + '.partial')).read_bytes(), b'abcd')
        self.assertFalse((self.cache / self.name).exists())
        failure = json.loads((self.logs / (self.name + '.failure.json')).read_bytes())
        self.assertEqual(failure['accepted_segments'], 1)

    def test_short_or_extra_payload_never_appends_segment(self):
        for index, raw in enumerate((b'abc', b'abcde')):
            cache = self.base / ('cache-' + str(index)); cache.mkdir()
            logs = self.base / ('logs-' + str(index)); logs.mkdir()
            response = Response(raw, 0, 3, 10, **{'Content-Length': '4'})
            with mock.patch.object(p, 'CHUNK_BYTES', 4), self.assertRaisesRegex(ValueError, 'payload length'):
                p.download_ranges(self.name, self.spec, cache, logs, client=ranged_client(response))
            self.assertEqual((cache / (self.name + '.partial')).read_bytes(), b'')

    def test_interrupted_segment_retains_previous_prefix_and_failure(self):
        response = Response(b'abcd', 0, 3, 10)
        response.read = mock.Mock(side_effect=[b'ab', KeyboardInterrupt()])
        with mock.patch.object(p, 'CHUNK_BYTES', 4), self.assertRaises(KeyboardInterrupt):
            p.download_ranges(self.name, self.spec, self.cache, self.logs, client=ranged_client(response))
        self.assertEqual((self.cache / (self.name + '.partial')).read_bytes(), b'')
        self.assertTrue((self.logs / (self.name + '.range-001.failure.json')).exists())

    def test_final_old_hash_remains_required_after_all_ranges(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            p.download_ranges(self.name, self.spec, self.cache, self.logs,
                              client=ranged_client(Response(b'wrongbytes', 0, 9, 10)))
        self.assertEqual((self.cache / (self.name + '.partial')).read_bytes(), b'wrongbytes')
        self.assertFalse((self.cache / self.name).exists())

    def test_resumed_file_tamper_and_implicit_partial_are_rejected_before_http(self):
        partial = self.cache / (self.name + '.partial'); partial.write_bytes(b'fake')
        prefix = {'package': self.name, 'sha256_expected': sha(self.raw), 'bytes': 4, 'sha256': sha(b'abcd')}
        client = Client()
        with self.assertRaisesRegex(ValueError, 'prefix identity'):
            p.download_ranges(self.name, self.spec, self.cache, self.logs, prefix, client)
        with self.assertRaises(FileExistsError):
            p.download_ranges(self.name, self.spec, self.cache, self.logs, client=client)
        self.assertEqual(client.requests, [])
        self.assertEqual(partial.read_bytes(), b'fake')

    def failed_origin(self):
        origin = self.base / 'old-evidence'; origin.mkdir(); (origin / 'logs').mkdir()
        cache = self.base / 'old-cache'; cache.mkdir()
        partial = cache / (self.name + '.partial'); partial.write_bytes(b'old-public-prefix-fixture')
        plan = p.sources.plan()
        snapshots = {}
        for source in p.v1_inputs():
            relative = source.relative_to(p.sources.ROOT)
            target = origin / 'implementation' / relative; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            snapshots[str(relative)] = p.digest(target)
        spec = plan['packages'][self.name]
        error = {'type': 'ValueError', 'message': 'truncated archive response'}
        start = {'name': self.name, 'url': spec['url'], 'sha256_expected': spec['sha256'],
                 'credential_source': 'anonymous-public-pull', 'started_at': 'fixture'}
        p.write(origin / 'started.json', {'schema': 1, 'cache': str(cache), 'plan': plan, 'sources': snapshots})
        p.write(origin / 'failure.json', {'schema': 1, 'status': 'CPU_PUBLIC_CACHE_PREPARATION_FAILED', 'error': error})
        p.write(origin / 'logs' / (self.name + '.started.json'), start)
        p.write(origin / 'logs' / (self.name + '.failure.json'), dict(start, status='DOWNLOAD_FAILED', error=error,
              partial={'path': str(partial), 'bytes': partial.stat().st_size, 'sha256': p.digest(partial)}))
        return origin, cache, partial, plan

    def test_explicit_failed_receipts_bind_copy_and_old_origin_unchanged(self):
        origin, cache, partial, plan = self.failed_origin()
        record = p.inspect_resume(origin, plan)
        copied = p.copy_resume(record, self.cache)
        self.assertEqual(copied.read_bytes(), partial.read_bytes())
        self.assertNotEqual(copied.stat().st_ino, partial.stat().st_ino)
        self.assertEqual(partial.stat().st_nlink, 1)
        p.check_origin(record)
        self.assertEqual(record['sha256_expected'], plan['packages'][self.name]['sha256'])

    def test_unrecorded_partial_or_success_receipt_cannot_be_resumed(self):
        origin, cache, partial, plan = self.failed_origin()
        p.write(origin / 'result.json', {'status': 'anything'})
        with self.assertRaisesRegex(ValueError, 'failed v1'):
            p.inspect_resume(origin, plan)
        (origin / 'result.json').unlink()
        partial.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'length differs'):
            p.inspect_resume(origin, plan)

    def test_snapshot_and_start_failure_binding_are_checked(self):
        origin, cache, partial, plan = self.failed_origin()
        path = origin / 'logs' / (self.name + '.failure.json')
        value = json.loads(path.read_bytes()); value['url'] = 'https://wrong.invalid'
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'binding differs'):
            p.inspect_resume(origin, plan)
        value['url'] = plan['packages'][self.name]['url']; path.write_text(json.dumps(value))
        snapshot = origin / 'implementation/migration_cache_v1/prepare.py'
        snapshot.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'snapshot differs'):
            p.inspect_resume(origin, plan)

    def test_same_size_prefix_corruption_and_additional_cache_file_are_rejected(self):
        origin, cache, partial, plan = self.failed_origin()
        original = partial.read_bytes(); partial.write_bytes(b'X' * len(original))
        with self.assertRaisesRegex(ValueError, 'partial hash'):
            p.inspect_resume(origin, plan)
        partial.write_bytes(original)
        (cache / 'unrelated-old-cache-file').write_bytes(b'not imported')
        with self.assertRaisesRegex(ValueError, 'only failed LLVM'):
            p.inspect_resume(origin, plan)

    def test_changed_origin_after_binding_is_not_copied(self):
        origin, cache, partial, plan = self.failed_origin()
        record = p.inspect_resume(origin, plan)
        partial.write_bytes(b'X' * partial.stat().st_size)
        with self.assertRaisesRegex(ValueError, 'origin changed'):
            p.copy_resume(record, self.cache)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_existing_copy_and_new_paths_inside_origin_are_refused(self):
        origin, cache, partial, plan = self.failed_origin()
        record = p.inspect_resume(origin, plan)
        target = self.cache / partial.name; target.write_bytes(b'keep')
        with self.assertRaises(FileExistsError):
            p.copy_resume(record, self.cache)
        self.assertEqual(target.read_bytes(), b'keep')
        with self.assertRaisesRegex(ValueError, 'disjoint from resume'):
            p.prepare_cpu(cache / 'nested', self.base / 'new-evidence', origin)


if __name__ == '__main__':
    unittest.main(verbosity=2)
