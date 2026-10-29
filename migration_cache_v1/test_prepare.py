"""Synthetic network/Git/filesystem boundaries; no network or native tool runs."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.request

from portable_lifter_v1 import build, deps, tools
from . import prepare as p, sources


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Response(io.BytesIO):
    def __init__(self, raw, status=200, length=None):
        super().__init__(raw)
        self.status = status
        self.headers = {'Content-Length': str(len(raw)) if length is None else length}


class Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, **kwargs):
        self.requests.append((request, kwargs))
        result = self.responses.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


class CacheBoundaries(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='cache-preparation-unit-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.cache = self.base / 'cache'; self.cache.mkdir()
        self.logs = self.base / 'logs'; self.logs.mkdir()
        self.raw = b'ordinary synthetic archive bytes'
        self.spec = {'kind': 'https', 'url': 'https://example.invalid/fixed', 'sha256': sha(self.raw)}

    def test_production_plan_matches_all_existing_consumers(self):
        plan = sources.plan()
        self.assertEqual(len(plan['packages']), 5)
        self.assertEqual(len(plan['sources']), 4)
        self.assertEqual(plan['packages']['remill.tar.gz']['sha256'], build.REMILL_ARCHIVE_SHA)
        for name, expected in tools.PACKAGES.items():
            self.assertEqual(plan['packages'][name]['sha256'], expected[0])
        for name, expected in deps.PINS.items():
            self.assertEqual((plan['sources'][name]['commit'], plan['sources'][name]['tree']), expected)

    def test_changed_lock_is_rejected_without_network(self):
        lock = json.loads(sources.LOCK.read_bytes())
        lock['packages']['remill.tar.gz']['sha256'] = '0' * 64
        path = self.base / 'changed-lock.json'; path.write_text(json.dumps(lock))
        with mock.patch.object(sources, 'LOCK', path), self.assertRaisesRegex(ValueError, 'consumer/lock'):
            sources.plan()

    def test_success_publishes_only_after_hash_verification(self):
        result = p.download('item.tar.gz', self.spec, self.cache, self.logs, Client(Response(self.raw)))
        self.assertEqual(result['status'], 'DOWNLOADED_AND_HASH_VERIFIED')
        self.assertEqual((self.cache / 'item.tar.gz').read_bytes(), self.raw)
        self.assertFalse((self.cache / 'item.tar.gz.partial').exists())
        self.assertEqual((self.cache / 'item.tar.gz').stat().st_nlink, 1)

    def test_hash_mismatch_preserves_partial_and_has_no_published_file(self):
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            p.download('item.tar.gz', self.spec, self.cache, self.logs, Client(Response(b'wrong')))
        self.assertEqual((self.cache / 'item.tar.gz.partial').read_bytes(), b'wrong')
        self.assertFalse((self.cache / 'item.tar.gz').exists())
        failure = json.loads((self.logs / 'item.tar.gz.failure.json').read_text())
        self.assertEqual(failure['partial']['sha256'], sha(b'wrong'))

    def test_http_and_truncation_failures_preserve_failed_attempt(self):
        for case, response in [('status', Response(self.raw, status=206)),
                               ('truncated', Response(self.raw, length=str(len(self.raw) + 1)))]:
            with self.subTest(case=case), self.assertRaises(ValueError):
                p.download(case, self.spec, self.cache, self.logs, Client(response))
            self.assertTrue((self.cache / (case + '.partial')).exists())
            self.assertFalse((self.cache / case).exists())
            self.assertTrue((self.logs / (case + '.failure.json')).exists())

    def test_download_size_and_elapsed_bounds(self):
        with mock.patch.object(p, 'MAX_DOWNLOAD_BYTES', 3), self.assertRaisesRegex(ValueError, 'Content-Length'):
            p.download('length', self.spec, self.cache, self.logs, Client(Response(self.raw)))
        with mock.patch.object(p.time, 'monotonic', side_effect=[0, 1201]), self.assertRaisesRegex(ValueError, 'overall timeout'):
            p.download('elapsed', self.spec, self.cache, self.logs, Client(Response(self.raw)))

    def test_mid_stream_interruption_preserves_bytes_and_logs(self):
        response = Response(self.raw)
        response.read = mock.Mock(side_effect=[self.raw[:7], KeyboardInterrupt()])
        with self.assertRaises(KeyboardInterrupt):
            p.download('interrupt', self.spec, self.cache, self.logs, Client(response))
        self.assertEqual((self.cache / 'interrupt.partial').read_bytes(), self.raw[:7])
        self.assertFalse((self.cache / 'interrupt').exists())

    def test_existing_final_and_dangling_symlink_are_not_clobbered(self):
        for name in ('existing', 'link'):
            final = self.cache / name
            if name == 'existing':
                final.write_bytes(b'preserve')
            else:
                final.symlink_to(self.base / 'absent')
            with self.assertRaises(FileExistsError):
                p.download(name, self.spec, self.cache, self.logs, Client(Response(self.raw)))
            self.assertEqual((self.cache / (name + '.partial')).read_bytes(), self.raw)
        self.assertEqual((self.cache / 'existing').read_bytes(), b'preserve')
        self.assertTrue((self.cache / 'link').is_symlink())

    def test_existing_partial_is_not_overwritten(self):
        partial = self.cache / 'item.partial'; partial.write_bytes(b'keep')
        client = Client(Response(self.raw))
        with self.assertRaises(FileExistsError):
            p.download('item', self.spec, self.cache, self.logs, client)
        self.assertEqual(partial.read_bytes(), b'keep')
        self.assertEqual(client.requests, [])

    def test_ghcr_anonymous_token_is_not_serialized(self):
        secret = 'secret-anonymous-read-token'
        client = Client(Response(json.dumps({'token': secret}).encode()), Response(self.raw))
        p.download('bottle', dict(self.spec, kind='ghcr', repository='ninja'), self.cache, self.logs, client)
        self.assertEqual(client.requests[1][0].get_header('Authorization'), 'Bearer ' + secret)
        for path in self.logs.iterdir():
            self.assertNotIn(secret.encode(), path.read_bytes())
        self.assertIn('repository%3Ahomebrew%2Fcore%2Fninja%3Apull', client.requests[0][0].full_url)

    def test_token_payload_limits_and_type(self):
        for raw in (b'x' * 65537, b'{"token": 2}', b'{"token":"bad\\nheader"}'):
            with self.subTest(raw_length=len(raw)), self.assertRaises(ValueError):
                p.token_for('ninja', Client(Response(raw)))

    def test_redirect_drops_cross_origin_credentials_and_rejects_http(self):
        request = urllib.request.Request('https://ghcr.io/blob', headers={'Authorization': 'Bearer secret'})
        handler = p.HTTPSRedirect()
        redirected = handler.redirect_request(request, None, 302, 'Found', {}, 'https://cdn.example.invalid/blob')
        self.assertIsNone(redirected.get_header('Authorization'))
        same = handler.redirect_request(request, None, 302, 'Found', {}, 'https://ghcr.io/new')
        self.assertEqual(same.get_header('Authorization'), 'Bearer secret')
        for url in ('http://cdn.example.invalid/blob', 'https://name:password@cdn.example.invalid/blob'):
            with self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, 'Found', {}, url)

    def test_network_errors_do_not_expose_signed_urls_or_response_bytes(self):
        url = 'https://cdn.example.invalid/?token=secret'
        cases = [urllib.error.HTTPError(url, 403, 'secret response', {}, None),
                 urllib.error.URLError(url), UnicodeDecodeError('utf8', b'secret\xff', 6, 7, 'bad')]
        for error in cases:
            self.assertNotIn('secret', json.dumps(p.error_record(error)))

    def test_git_source_identity_mismatch_prevents_archive_command(self):
        spec = sources.plan()['sources']['gflags']
        calls = []
        def run(argv, label, **kwargs):
            calls.append(label)
            return (b'0' * 40 + b'\n') if label.endswith('-commit') else (spec['tree'] + '\n').encode()
        with self.assertRaisesRegex(ValueError, 'Git identity'):
            p.acquire_source('gflags', spec, self.cache, self.base, run)
        self.assertFalse(any(label.endswith('-archive') for label in calls))
        self.assertFalse((self.cache / 'gflags.tar').exists())

    def test_git_export_preserves_old_prefix_commit_and_byte_gate(self):
        spec = dict(sources.plan()['sources']['gflags'], sha256=sha(self.raw))
        calls = []
        def run(argv, label, stdout_path=None):
            calls.append([str(v) for v in argv])
            if label.endswith('-commit'):
                return (spec['commit'] + '\n').encode()
            if label.endswith('-tree'):
                return (spec['tree'] + '\n').encode()
            if stdout_path is not None:
                stdout_path.write_bytes(self.raw)
            return b''
        result = p.acquire_source('gflags', spec, self.cache, self.base, run)
        self.assertEqual(result['sha256'], sha(self.raw))
        self.assertEqual(calls[-1][-4:], ['archive', '--format=tar', '--prefix=gflags/', spec['commit']])
        self.assertIn('--depth=1', calls[1])

    def test_git_recorder_timeout_cleans_owned_group_and_disables_credential_helpers(self):
        output = self.base / 'git-evidence'; output.mkdir(); (output / 'logs').mkdir()
        recorder = p.GitRecorder(output)
        process = mock.Mock(pid=123456)
        process.wait.side_effect = [subprocess.TimeoutExpired(['git'], 300), -15, -15]
        def launch(argv, **kwargs):
            self.assertEqual(kwargs['env']['GIT_CONFIG_GLOBAL'], '/dev/null')
            self.assertNotIn('GITHUB_TOKEN', kwargs['env'])
            self.assertIn('credential.helper=', argv)
            self.assertIn('tar.umask=0002', argv)
            self.assertTrue(kwargs['start_new_session'])
            return process
        with mock.patch.object(p.subprocess, 'Popen', side_effect=launch), \
             mock.patch.object(p.os, 'killpg') as killpg, self.assertRaises(subprocess.TimeoutExpired):
            recorder(['fetch'], 'timeout')
        record = json.loads((output / 'logs/001-timeout.result.json').read_text())
        self.assertEqual(record['returncode'], -15)
        self.assertEqual(record['error']['category'], 'git-command-timeout')
        self.assertEqual([call.args for call in killpg.call_args_list], [(123456, p.signal.SIGTERM), (123456, p.signal.SIGKILL)])
        self.assertTrue((output / 'logs/001-timeout.stderr').exists())

    def fixture_contract(self):
        payloads = {name: ('synthetic-' + name).encode() for name in sources.PACKAGES}
        payloads.update({name + '.tar': ('synthetic-' + name).encode() for name in sources.GIT})
        lock = {'schema': 1, 'packages': {name: {'sha256': sha(payloads[name])} for name in sources.PACKAGES},
                'sources': {name: {'archive': name + '.tar', 'sha256': sha(payloads[name + '.tar']),
                                   'commit': pin[0], 'tree': pin[1]} for name, pin in deps.PINS.items()}}
        lockpath = self.base / 'fixture-lock.json'; lockpath.write_text(json.dumps(lock))
        mapping = {name: (sha(payloads[name]), value[1]) for name, value in tools.PACKAGES.items()}
        return payloads, lock, lockpath, mapping

    def test_frozen_readers_accept_synthetic_compatible_metadata_and_moved_path(self):
        payloads, lock, lockpath, mapping = self.fixture_contract()
        for name, raw in payloads.items():
            (self.cache / name).write_bytes(raw)
        (self.cache / 'cache.json').write_text(json.dumps(lock))
        with mock.patch.object(deps, 'LOCK', lockpath), mock.patch.object(tools, 'PACKAGES', mapping), \
             mock.patch.object(build, 'REMILL_ARCHIVE_SHA', sha(payloads['remill.tar.gz'])):
            result = p.validate(self.cache)
            self.assertEqual(len(result['tools']), 4)
            moved = self.base / 'cache with spaces'; self.cache.rename(moved)
            self.assertEqual(p.validate(moved)['remill'], result['remill'])
            (moved / 'remill.tar.gz').write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError, 'Remill'):
                p.validate(moved)

    def test_existing_or_nested_output_is_rejected_before_acquisition(self):
        for cache, out in [(self.cache, self.base / 'new'), (self.base / 'new', self.logs),
                           (self.base / 'fresh', self.base / 'fresh/nested')]:
            with self.subTest(cache=cache, out=out), mock.patch.object(p, 'download') as download, self.assertRaises(ValueError):
                p.prepare_cpu(cache, out)
            download.assert_not_called()
        alias = self.base / 'alias'; alias.symlink_to(self.cache)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            p.prepare_cpu(alias / 'new', self.base / 'uncreated')

    def test_full_synthetic_orchestration_uses_consumers_and_saves_failures(self):
        payloads, lock, lockpath, mapping = self.fixture_contract()
        plan = {'schema': 1, 'lock_sha256': sha(lockpath.read_bytes()),
                'packages': {name: dict(origin, sha256=sha(payloads[name])) for name, origin in sources.PACKAGES.items()},
                'sources': {name: dict(row, repository=sources.GIT[name]) for name, row in lock['sources'].items()}}
        def download(name, spec, cache, logs):
            (cache / name).write_bytes(payloads[name])
            return {'sha256': spec['sha256']}
        def source(name, spec, cache, out, run):
            (cache / spec['archive']).write_bytes(payloads[spec['archive']])
            return spec
        output = self.base / 'fresh-evidence'; cache = self.base / 'fresh-cache'
        with mock.patch.object(sources, 'plan', return_value=plan), mock.patch.object(p, 'download', side_effect=download), \
             mock.patch.object(p, 'acquire_source', side_effect=source), mock.patch.object(p, 'GitRecorder') as runner, \
             mock.patch.object(deps, 'LOCK', lockpath), mock.patch.object(tools, 'PACKAGES', mapping), \
             mock.patch.object(build, 'REMILL_ARCHIVE_SHA', sha(payloads['remill.tar.gz'])):
            runner.return_value.return_value = b'synthetic git\n'
            result = p.prepare_cpu(cache, output)
        self.assertEqual(result['status'], p.STATUS)
        self.assertEqual(result['package_count'], 9)
        self.assertTrue((output / 'result.json').is_file())
        # The normal consumers, not a replacement success stub, validated all
        # fixture hashes. This is still only synthetic, never public evidence.
        failed = self.base / 'failed-evidence'
        with mock.patch.object(p, 'GitRecorder') as runner, mock.patch.object(p, 'download', side_effect=ValueError('injected failure')):
            runner.return_value.return_value = b'synthetic git\n'
            with self.assertRaisesRegex(ValueError, 'injected failure'):
                p.prepare_cpu(self.base / 'failed-cache', failed)
        self.assertTrue((failed / 'failure.json').is_file())
        self.assertFalse((failed / 'result.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
