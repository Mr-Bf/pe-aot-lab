"""Independent bounded-range/resume checks; tiny fixtures, no network or live cache."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import urllib.error

from . import prepare as p


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Response:
    def __init__(self, body=b'', status=206, headers=None):
        self.body = io.BytesIO(body); self.status = status; self.headers = headers or {}
    def read(self, n=-1): return self.body.read(n)
    def __enter__(self): return self
    def __exit__(self, *args): return None


class Client:
    def __init__(self, data, corrupt=None):
        self.data = data; self.corrupt = corrupt; self.requests = []
    def open(self, request, timeout):
        self.requests.append(request)
        if request.full_url.startswith('https://ghcr.io/token?'):
            return Response(json.dumps({'token': 'FIXTURE_SECRET_TOKEN'}).encode(), 200)
        if self.corrupt == 'http-error':
            raise urllib.error.HTTPError('https://redirect.invalid/?sig=FIXTURE_SECRET_TOKEN', 403,
                                         'FIXTURE_SECRET_TOKEN', {}, None)
        first, last = map(int, request.get_header('Range').removeprefix('bytes=').split('-'))
        last = min(last, len(self.data) - 1)
        payload = self.data[first:last + 1]
        headers = {'Content-Range': f'bytes {first}-{last}/{len(self.data)}', 'Content-Length': str(len(payload))}
        if self.corrupt == 'short': payload = payload[:-1]
        if self.corrupt == 'extra': payload += b'X'
        if self.corrupt == 'wrong-start': headers['Content-Range'] = f'bytes {first+1}-{last}/{len(self.data)}'
        return Response(payload, headers=headers)


class IndependentRangeReview(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cache-range-review-'); self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        patch = mock.patch.object(p.previous, 'opener', side_effect=AssertionError('real network forbidden'))
        patch.start(); self.addCleanup(patch.stop)
        self.data = b'abcdefghijk'
        self.spec = {'kind': 'ghcr', 'repository': 'llvm/17', 'sha256': sha(self.data),
                     'url': 'https://ghcr.io/v2/homebrew/core/llvm/17/blobs/sha256:' + sha(self.data)}
        self.counter = 0

    def paths(self):
        self.counter += 1; base = self.base / str(self.counter); base.mkdir()
        cache, logs = base / 'cache', base / 'logs'; cache.mkdir(); logs.mkdir()
        return cache, logs

    def prefix(self, cache):
        value = self.data[:4]; (cache / 'llvm17.tar.gz.partial').write_bytes(value)
        return {'package': 'llvm17.tar.gz', 'bytes': len(value), 'sha256': sha(value), 'sha256_expected': self.spec['sha256']}

    def origin(self):
        cache, _ = self.paths(); origin = cache.parent / 'failed'; (origin / 'logs').mkdir(parents=True)
        impl = self.base / 'fixture-implementation.py'; impl.write_bytes(b'# synthetic immutable v1 implementation\n')
        (origin / 'implementation').mkdir(); (origin / 'implementation/fixture-implementation.py').write_bytes(impl.read_bytes())
        value = self.data[:4]; partial = cache / 'llvm17.tar.gz.partial'; partial.write_bytes(value)
        plan = {'schema': 1, 'packages': {'llvm17.tar.gz': self.spec}}
        start = {'schema': 1, 'cache': str(cache), 'plan': plan, 'sources': {'fixture-implementation.py': sha(impl.read_bytes())}}
        error = {'type': 'ValueError', 'message': 'truncated archive response'}
        package = {'name': 'llvm17.tar.gz', 'url': self.spec['url'], 'sha256_expected': self.spec['sha256'],
                   'credential_source': 'anonymous-public-pull', 'started_at': 'fixture-start'}
        for path, record in ((origin/'started.json', start),
            (origin/'failure.json', {'schema': 1, 'status': 'CPU_PUBLIC_CACHE_PREPARATION_FAILED', 'error': error}),
            (origin/'logs/llvm17.tar.gz.started.json', package),
            (origin/'logs/llvm17.tar.gz.failure.json', {**package, 'status': 'DOWNLOAD_FAILED', 'error': error,
                'partial': {'path': str(partial), 'bytes': len(value), 'sha256': sha(value)}})):
            path.write_text(json.dumps(record))
        return origin, cache, plan, impl

    def inspect(self, origin, plan, impl):
        with mock.patch.object(p.sources, 'ROOT', self.base), mock.patch.object(p, 'v1_inputs', return_value=[impl]):
            return p.inspect_resume(origin, plan)

    def test_range_identity_rejects_wrong_start_total_end_length_encoding_and_status(self):
        valid = {'Content-Range': 'bytes 4-7/11', 'Content-Length': '4'}
        identity = p.range_identity(Response(headers=valid), 4, 7, 11)
        self.assertEqual({k: identity[k] for k in ('start', 'end', 'total', 'bytes')},
                         {'start': 4, 'end': 7, 'total': 11, 'bytes': 4})
        cases = [('Content-Range', 'bytes 3-6/11'), ('Content-Range', 'bytes 4-7/12'),
                 ('Content-Range', 'bytes 4-6/11'), ('Content-Range', 'bytes 4-7/*'),
                 ('Content-Range', f'bytes 4-7/{p.previous.MAX_DOWNLOAD_BYTES+1}'),
                 ('Content-Length', '3'), ('Content-Length', '5'), ('Content-Encoding', 'gzip')]
        for key, value in cases:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                p.range_identity(Response(headers={**valid, key: value}), 4, 7, 11)
        with self.assertRaises(ValueError): p.range_identity(Response(status=200, headers=valid), 4, 7, 11)

    def test_explicit_failed_receipt_is_required_and_binds_prefix_and_source(self):
        origin, old_cache, plan, impl = self.origin()
        record = self.inspect(origin, plan, impl)
        old_files = {str(f): f.read_bytes() for f in origin.rglob('*') if f.is_file()}
        old_prefix = (old_cache/'llvm17.tar.gz.partial').read_bytes()
        cache, _ = self.paths(); target = p.copy_resume(record, cache)
        self.assertEqual(target.read_bytes(), old_prefix)
        self.assertEqual((old_cache/'llvm17.tar.gz.partial').read_bytes(), old_prefix)
        self.assertEqual({str(f): f.read_bytes() for f in origin.rglob('*') if f.is_file()}, old_files)
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.inspect(old_cache, plan, impl)  # A directory with a partial is not a failure receipt.
        (old_cache/'llvm17.tar.gz.partial').write_bytes(b'abcdWRONG')
        with self.assertRaises(ValueError): self.inspect(origin, plan, impl)
        (old_cache/'llvm17.tar.gz.partial').write_bytes(old_prefix)
        (origin/'implementation/fixture-implementation.py').write_bytes(b'wrong-source')
        with self.assertRaises(ValueError): self.inspect(origin, plan, impl)

    def test_valid_ranges_extend_only_new_copy_and_final_fixed_sha_controls_publication(self):
        origin, old_cache, plan, impl = self.origin(); record = self.inspect(origin, plan, impl)
        original = (old_cache/'llvm17.tar.gz.partial').read_bytes()
        cache, logs = self.paths(); p.copy_resume(record, cache); client = Client(self.data)
        with mock.patch.object(p, 'CHUNK_BYTES', 4):
            result = p.download_ranges('llvm17.tar.gz', self.spec, cache, logs, prefix=record, client=client)
        self.assertEqual((cache/'llvm17.tar.gz').read_bytes(), self.data)
        self.assertFalse((cache/'llvm17.tar.gz.partial').exists())
        self.assertEqual(result['sha256'], self.spec['sha256'])
        self.assertEqual(result['resumed_bytes'], 4)
        self.assertEqual([(s['start'], s['end'], s['total']) for s in result['segments']], [(4, 7, 11), (8, 10, 11)])
        self.assertEqual((old_cache/'llvm17.tar.gz.partial').read_bytes(), original)
        self.assertEqual(self.inspect(origin, plan, impl), record)
        self.assertNotIn('FIXTURE_SECRET_TOKEN', ''.join(f.read_text() for f in logs.iterdir()))

    def test_short_extra_or_wrong_range_never_append_an_unverified_segment(self):
        for error in ('short', 'extra', 'wrong-start'):
            cache, logs = self.paths(); prefix = self.prefix(cache)
            with self.subTest(error=error), mock.patch.object(p, 'CHUNK_BYTES', 4), self.assertRaises(ValueError):
                p.download_ranges('llvm17.tar.gz', self.spec, cache, logs, prefix=prefix, client=Client(self.data, error))
            self.assertEqual((cache/'llvm17.tar.gz.partial').read_bytes(), self.data[:4])
            self.assertFalse((cache/'llvm17.tar.gz').exists())
            failure = json.loads((logs/'llvm17.tar.gz.failure.json').read_bytes())
            self.assertEqual(failure['accepted_segments'], 0)
            self.assertEqual(failure['partial']['sha256'], sha(self.data[:4]))
            response = json.loads((logs/'llvm17.tar.gz.range-001.response.json').read_bytes())
            self.assertEqual(response['http_status'], 206)
            self.assertEqual(response['headers']['Content-Range'], 'bytes 5-7/11' if error == 'wrong-start' else 'bytes 4-7/11')

    def test_complete_response_with_wrong_final_sha_remains_unpublished(self):
        cache, logs = self.paths(); prefix = self.prefix(cache)
        spec = {**self.spec, 'sha256': 'f' * 64}; prefix['sha256_expected'] = spec['sha256']
        with mock.patch.object(p, 'CHUNK_BYTES', 4), self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            p.download_ranges('llvm17.tar.gz', spec, cache, logs, prefix=prefix, client=Client(self.data))
        self.assertFalse((cache/'llvm17.tar.gz').exists())
        self.assertEqual((cache/'llvm17.tar.gz.partial').read_bytes(), self.data)
        self.assertEqual(json.loads((logs/'llvm17.tar.gz.failure.json').read_bytes())['status'], 'DOWNLOAD_FAILED')

    def test_signed_redirect_and_bearer_tokens_do_not_enter_failure_logs(self):
        cache, logs = self.paths(); prefix = self.prefix(cache)
        with mock.patch.object(p, 'CHUNK_BYTES', 4), self.assertRaises(urllib.error.HTTPError):
            p.download_ranges('llvm17.tar.gz', self.spec, cache, logs, prefix=prefix, client=Client(self.data, 'http-error'))
        text = ''.join(f.read_text() for f in logs.iterdir())
        self.assertNotIn('FIXTURE_SECRET_TOKEN', text)
        self.assertNotIn('redirect.invalid', text)
        failure = json.loads((logs/'llvm17.tar.gz.failure.json').read_bytes())
        self.assertEqual(failure['error'], {'type': 'HTTPError', 'http_status': 403})
        self.assertEqual((cache/'llvm17.tar.gz.partial').read_bytes(), self.data[:4])


if __name__ == '__main__':
    unittest.main()
