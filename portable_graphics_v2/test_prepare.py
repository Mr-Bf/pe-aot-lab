"""Small acquisition-plan/metadata fixtures; no public fetch, Git or compilation."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from migration_cache_v1.test_prepare import Client, Response
from . import prepare as p


class PublicPreparationBoundaries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='graphics-public-prepare-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.out = self.base / 'evidence'; self.out.mkdir(); (self.out / 'logs').mkdir()
        self.meson = dict(p.cache.specs()['meson'], **p.cache.PINS['meson'])

    def metadata(self):
        return {'info': {'name': 'meson', 'version': '1.10.0'}, 'urls': [
            {'filename': self.meson['archive'], 'packagetype': 'bdist_wheel', 'python_version': 'py3',
             'yanked': False, 'url': self.meson['source']['url'], 'size': self.meson['size'],
             'digests': {'sha256': self.meson['sha256']}}]}

    def test_fixed_wheel_metadata_is_checked_and_raw_evidence_saved(self):
        raw = json.dumps(self.metadata()).encode()
        client = Client(Response(raw))
        record = p.fetch_meson_metadata(self.meson, self.out, client)
        self.assertEqual(record['selected']['sha256'], self.meson['sha256'])
        self.assertEqual(record['selected']['bytes'], 1057029)
        self.assertEqual((self.out / 'pypi-meson-1.10.0.json').read_bytes(), raw)
        self.assertEqual(client.requests[0][0].full_url, p.PYPI_URL)
        self.assertTrue((self.out / 'pypi-check.json').exists())

    def test_metadata_cannot_redirect_wheel_or_change_identity(self):
        cases = []
        for key, value in [('url', 'https://bad.invalid/wheel'), ('size', True), ('size', 2),
                           ('yanked', True), ('packagetype', 'sdist'), ('python_version', 'cp313')]:
            modified = self.metadata(); modified['urls'][0][key] = value; cases.append(modified)
        modified = self.metadata(); modified['urls'][0]['digests']['sha256'] = '0' * 64; cases.append(modified)
        modified = self.metadata(); modified['urls'].append(copy.deepcopy(modified['urls'][0])); cases.append(modified)
        modified = self.metadata(); modified['info']['version'] = '1.11.0'; cases.append(modified)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                p.check_meson_metadata(value, self.meson)

    def test_metadata_response_bounds_and_duplicate_keys(self):
        client = Client(Response(b'x' * (p.METADATA_LIMIT + 1)))
        with self.assertRaisesRegex(ValueError, 'size limit'):
            p.fetch_meson_metadata(self.meson, self.out, client)
        self.assertFalse((self.out / 'pypi-check.json').exists())
        other = self.base / 'other'; other.mkdir()
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            p.fetch_meson_metadata(self.meson, other, Client(Response(b'{"info":{},"info":{}}')))

    def test_proxy_is_explicit_instance_state_and_covers_all_git_calls(self):
        direct = p.git_recorder(self.out, None)
        proxied = p.git_recorder(self.out, 'http://127.0.0.1:8118')
        self.assertNotIn('http.proxy=http://127.0.0.1:8118', direct.prefix)
        self.assertIn('http.proxy=http://127.0.0.1:8118', proxied.prefix)
        self.assertIn('core.autocrlf=false', proxied.prefix)
        self.assertIn('core.symlinks=true', proxied.prefix)
        self.assertEqual(proxied.env['GIT_ATTR_NOSYSTEM'], '1')
        with self.assertRaises(ValueError):
            p.git_recorder(self.out, 'http://user:secret@host:80')

    def fake_git(self, bad_commit=False, bad_tree=False, extra_root=False):
        calls = []
        def run(argv, label):
            calls.append({'argv': list(map(str, argv)), 'label': label})
            repository = self.out / 'llvm-git'
            if label == 'llvm-init':
                (repository / '.git').mkdir(parents=True)
            if label == 'llvm-commit':
                return ((('0' * 40) if bad_commit else p.cache.LLVM_COMMIT) + '\n').encode()
            if label.startswith('llvm-tree-'):
                name = label.removeprefix('llvm-tree-')
                return ((('0' * 40) if bad_tree else p.cache.LLVM_TREES[name]) + '\n').encode()
            if label == 'llvm-selected-checkout':
                self.assertEqual((repository / '.git/info/attributes').read_bytes(), p.RAW_ATTRIBUTES)
                for name in ('llvm', 'cmake'):
                    (repository / name).mkdir()
                    (repository / name / 'source.txt').write_bytes(b'raw blob\n')
                (repository / 'llvm/link').symlink_to('source.txt')
                if extra_root:
                    (repository / 'README.md').write_bytes(b'unselected')
            return b''
        return run, calls

    def test_sparse_plan_verifies_commit_and_trees_before_checkout_and_exports_only_two_roots(self):
        run, calls = self.fake_git()
        source, record = p.acquire_llvm(self.out, run)
        self.assertEqual({path.name for path in source.iterdir()}, {'llvm', 'cmake'})
        self.assertTrue((source / 'llvm/link').is_symlink())
        self.assertEqual((source / 'llvm/source.txt').read_bytes(), b'raw blob\n')
        self.assertTrue((self.out / 'llvm-git/.git').is_dir())
        labels = [item['label'] for item in calls]
        self.assertLess(labels.index('llvm-tree-llvm'), labels.index('llvm-selected-checkout'))
        fetch = next(item['argv'] for item in calls if item['label'] == 'llvm-fetch')
        self.assertIn('--filter=blob:none', fetch)
        self.assertIn('--depth=1', fetch)
        self.assertEqual(fetch[-1], p.cache.LLVM_COMMIT)
        sparse = next(item['argv'] for item in calls if item['label'] == 'llvm-sparse-set')
        self.assertEqual(sparse[-3:], ['--no-cone', '/llvm/', '/cmake/'])
        self.assertEqual(record['trees'], p.cache.LLVM_TREES)

    def test_wrong_git_identity_never_checks_out_or_copies_sources(self):
        run, calls = self.fake_git(bad_commit=True)
        with self.assertRaisesRegex(ValueError, 'commit differs'):
            p.acquire_llvm(self.out, run)
        self.assertFalse((self.out / 'llvm-source').exists())
        self.assertNotIn('llvm-selected-checkout', [item['label'] for item in calls])

    def test_wrong_selected_tree_or_unselected_root_is_rejected(self):
        run, calls = self.fake_git(bad_tree=True)
        with self.assertRaisesRegex(ValueError, 'selected tree differs'):
            p.acquire_llvm(self.out, run)
        self.assertFalse((self.out / 'llvm-source').exists())
        self.out = self.base / 'other-evidence'; self.out.mkdir()
        run, calls = self.fake_git(extra_root=True)
        with self.assertRaisesRegex(ValueError, 'unexpected root'):
            p.acquire_llvm(self.out, run)

    def test_package_routing_reuses_only_the_selected_fixed_downloaders(self):
        destination = self.base / 'cache'; destination.mkdir()
        for name in ('dxmt', 'headers', 'cmake', 'ninja', 'meson'):
            spec = dict(p.cache.specs()[name], **p.cache.PINS[name])
            with self.subTest(name=name), mock.patch.object(p.network, 'download', return_value={'bytes': spec['size']}) as direct, \
                 mock.patch.object(p.ranges, 'download_ranges', return_value={'bytes': spec['size']}) as ranged:
                p.download_package(name, spec, destination, self.out)
                selected = ranged if name in ('cmake', 'ninja') else direct
                other = direct if selected is ranged else ranged
                selected.assert_called_once(); other.assert_not_called()
                self.assertEqual(selected.call_args.args[1]['sha256'], spec['sha256'])

    def test_unsealed_lock_and_bad_paths_fail_before_any_network_or_output(self):
        cache_path = self.base / 'uncreated-cache'; out = self.base / 'uncreated-evidence'
        with mock.patch.object(p.cache, 'load_lock', side_effect=ValueError('lock is not sealed')), \
             mock.patch.object(p, 'fetch_meson_metadata') as fetch, self.assertRaisesRegex(ValueError, 'not sealed'):
            p.prepare(cache_path, out)
        fetch.assert_not_called()
        self.assertFalse(cache_path.exists()); self.assertFalse(out.exists())
        with mock.patch.object(p.cache, 'load_lock') as load, self.assertRaisesRegex(ValueError, 'disjoint'):
            p.prepare(cache_path, cache_path / 'evidence')
        load.assert_not_called()

    def test_acquisition_failure_remains_failure_without_native_build(self):
        cache_path = self.base / 'uncreated-cache'; out = self.base / 'uncreated-evidence'
        lock = {'packages': {'meson': self.meson}}
        with mock.patch.object(p.cache, 'load_lock', return_value=lock), mock.patch.object(p, 'implementation_inputs', return_value=[]), \
             mock.patch.object(p, 'fetch_meson_metadata', side_effect=ValueError('injected metadata failure')), \
             mock.patch.object(p, 'git_recorder') as git:
            with self.assertRaisesRegex(ValueError, 'injected metadata failure'):
                p.prepare(cache_path, out)
        git.assert_not_called()
        self.assertEqual(json.loads((out / 'failure.json').read_bytes())['status'], 'PUBLIC_GRAPHICS_CACHE_ACQUISITION_FAILED')
        self.assertFalse((out / 'result.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
