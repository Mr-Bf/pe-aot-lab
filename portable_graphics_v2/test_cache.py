"""Small synthetic fixtures only: no network, native build or production tree scan."""
import io
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

from portable_graphics_v2 import cache

TREES = {'llvm': 'ebe1848b8299add7eddb19bfa677d08ffad87c10',
         'cmake': '21545597d6e8cdbd0a543891219e729c8e87ae53'}


class CacheFixtures(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='graphics-cache-v2-test-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.source = self.base / 'source'
        for name, raw, mode in (('llvm/include/readme.txt', b'readme\n', 0o644),
                                ('llvm/lib/core.c', b'int core;\n', 0o644),
                                ('llvm/bin/tool', b'#!/bin/sh\nexit 0\n', 0o755),
                                ('cmake/config.cmake', b'set(SYNTHETIC 1)\n', 0o644)):
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(mode)
        (self.source / 'llvm/link').symlink_to('include/readme.txt')
        self.directory = self.base / 'cache'; self.directory.mkdir()
        pins = {}
        for name, row in cache.specs().items():
            if name == 'llvm': continue
            path = self.directory / row['archive']
            if name in ('dxmt', 'headers'):
                self.archive(path, row['archive_root'])
            else:
                path.write_bytes(('synthetic ' + name).encode())
            pins[name] = dict(sha256=cache.sha(path), size=path.stat().st_size)
        self.lock = self.base / 'fixture-lock.json'
        patch = mock.patch.multiple(cache, PINS=pins, LLVM_TREES=TREES, LLVM_FILE_COUNT=5, LOCK=self.lock)
        patch.start(); self.addCleanup(patch.stop)
        self.exported = cache.export_llvm(self.source, self.directory / 'llvm15-subtrees.tar.gz',
                                          self.directory / 'llvm15-files.json')
        cache.write_json(self.lock, cache.lock_for_export(self.exported))

    @staticmethod
    def archive(path, root, unsafe=None):
        with tarfile.open(path, 'w:gz') as stream:
            member = tarfile.TarInfo(root); member.type = tarfile.DIRTYPE; member.mode = 0o755
            stream.addfile(member)
            if unsafe:
                name, kind, target = unsafe
                member = tarfile.TarInfo(name); member.type = kind; member.linkname = target
                stream.addfile(member)
            else:
                raw = b'fixture license\n'; member = tarfile.TarInfo(root + '/LICENSE')
                member.size = len(raw); member.mode = 0o644; stream.addfile(member, io.BytesIO(raw))

    def test_cache_ignores_machine_receipt_and_has_no_old_source_dependency(self):
        expected = cache.check_cache(self.directory)
        (self.directory / 'acquisition.json').write_text('not valid JSON /old/machine/path')
        (self.directory / 'origins.json').write_text('unrelated old origin')
        self.assertEqual(cache.check_cache(self.directory), expected)
        self.source.rename(self.base / 'withheld')
        result = cache.extract_sources(self.directory, self.base / 'extracted')
        self.assertEqual(set(result), {'llvm', 'dxmt', 'headers'})
        self.assertEqual(cache.source_inventory(result['llvm'])['trees'], TREES)

    def test_export_is_identical_across_roots_modes_and_umask(self):
        source = self.base / 'other'; shutil.copytree(self.source, source, symlinks=True)
        for path in source.rglob('*'):
            if path.is_symlink(): continue
            path.chmod(0o775 if path.is_dir() or path.stat().st_mode & 0o100 else 0o664)
        source.chmod(0o775)
        previous = os.umask(0o077)
        try:
            result = cache.export_llvm(source, self.base / 'second.gz', self.base / 'second.json')
        finally:
            os.umask(previous)
        self.assertEqual(result, self.exported)
        self.assertEqual((self.base / 'second.gz').read_bytes(), (self.directory / 'llvm15-subtrees.tar.gz').read_bytes())
        self.assertEqual((source / 'llvm/lib/core.c').stat().st_mode & 0o777, 0o664)
        with tarfile.open(self.base / 'second.gz') as stream:
            members = stream.getmembers()
        for member in members:
            self.assertEqual((member.uid, member.gid, member.mtime, member.uname, member.gname), (0, 0, 0, '', ''))
            expected = 0o755 if member.isdir() else 0o777 if member.issym() else 0o755 if member.name.endswith('/bin/tool') else 0o644
            self.assertEqual(member.mode, expected)
        self.assertEqual(cache.tar_identity(self.base / 'second.gz'),
                         {key: result['archive'][key] for key in ('tar_sha256', 'tar_size')})

    def test_unsealed_lock_rejects_before_output_creation(self):
        self.lock.write_bytes(cache.encoded(dict(schema=2, status='REFERENCE_NOT_SEALED')))
        target = self.base / 'never'
        with self.assertRaisesRegex(ValueError, 'not sealed'):
            cache.extract_sources(self.directory, target)
        self.assertFalse(target.exists())

    def test_package_and_inventory_changes_fail_before_extraction(self):
        for name in ('dxmt.tar.gz', 'llvm15-files.json'):
            with self.subTest(name=name):
                path = self.directory / name; original = path.read_bytes()
                path.write_bytes(original + b' ')
                try:
                    with self.assertRaisesRegex(ValueError, 'hash'):
                        cache.extract_sources(self.directory, self.base / 'never')
                    self.assertFalse((self.base / 'never').exists())
                finally:
                    path.write_bytes(original)

    def test_tar_digest_cannot_be_replaced_by_compressed_digest(self):
        value = cache.read_json(self.lock); value['packages']['llvm']['tar_sha256'] = '0' * 64
        self.lock.write_bytes(cache.encoded(value))
        with self.assertRaisesRegex(ValueError, 'canonical LLVM tar differs'):
            cache.check_cache(self.directory)

    def test_fixed_package_cannot_be_repinned_in_local_lock(self):
        value = cache.read_json(self.lock); value['packages']['meson']['sha256'] = '0' * 64
        self.lock.write_bytes(cache.encoded(value))
        with self.assertRaisesRegex(ValueError, 'fixed original package differs'):
            cache.check_cache(self.directory)

    def test_tree_content_and_executable_changes_refuse_export(self):
        path = self.source / 'llvm/lib/core.c'
        for change in ('content', 'executable'):
            with self.subTest(change=change):
                if change == 'content': path.write_bytes(b'changed\n')
                else: path.chmod(0o755)
                try:
                    with self.assertRaisesRegex(ValueError, 'fixed LLVM Git trees'):
                        cache.export_llvm(self.source, self.base / 'never.gz', self.base / 'never.json')
                    self.assertFalse((self.base / 'never.gz').exists())
                finally:
                    path.write_bytes(b'int core;\n'); path.chmod(0o644)

    def test_unexpected_source_root_and_hardlink_rejected(self):
        extra = self.source / '.git'; extra.mkdir()
        with self.assertRaisesRegex(ValueError, 'only llvm and cmake'):
            cache.export_llvm(self.source, self.base / 'never.gz', self.base / 'never.json')
        extra.rmdir()
        os.link(self.source / 'llvm/lib/core.c', self.base / 'hardlink')
        with self.assertRaisesRegex(ValueError, 'hardlinked'):
            cache.export_llvm(self.source, self.base / 'never.gz', self.base / 'never.json')
        self.assertFalse((self.base / 'never.gz').exists())

    def test_extracted_wrong_permissions_are_not_ignored(self):
        original = cache.safe_extract
        def changed(archive, destination, root):
            result = original(archive, destination, root)
            if root == 'llvm15-subtrees': (result / 'llvm/lib/core.c').chmod(0o640)
            return result
        target = self.base / 'bad-mode'
        with mock.patch.object(cache, 'safe_extract', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'identity/modes differ'):
                cache.extract_sources(self.directory, target)
        self.assertTrue((target / 'failure.json').is_file())
        self.assertFalse((target / 'result.json').exists())

    def test_archive_escape_and_existing_destination_rejected(self):
        output = self.base / 'extract'; output.mkdir()
        for index, unsafe in enumerate((('root/../../escape', tarfile.REGTYPE, ''),
                                        ('root/link', tarfile.SYMTYPE, '../../escape'),
                                        ('root/hard', tarfile.LNKTYPE, 'root/file'))):
            path = self.base / ('unsafe-' + str(index) + '.gz'); self.archive(path, 'root', unsafe)
            with self.assertRaises(ValueError): cache.safe_extract(path, output, 'root')
            self.assertFalse((self.base / 'escape').exists())
        existing = self.base / 'existing'; existing.mkdir(); marker = existing / 'keep'; marker.write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError, 'fresh source destination'):
            cache.extract_sources(self.directory, existing)
        self.assertEqual(marker.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
