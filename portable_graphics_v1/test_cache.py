"""Small synthetic archives exercise offline identity and extraction boundaries."""
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from portable_graphics_v1 import cache

FIXTURE_TREES = {'llvm': 'ebe1848b8299add7eddb19bfa677d08ffad87c10',
                 'cmake': '21545597d6e8cdbd0a543891219e729c8e87ae53'}


class CacheBoundaries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='portable-graphics-cache-test-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.source = self.base / 'input-source'
        for name, raw, mode in (('llvm/include/readme.txt', b'readme\n', 0o644),
                                ('llvm/lib/core.c', b'int core;\n', 0o644),
                                ('llvm/bin/tool', b'#!/bin/sh\nexit 0\n', 0o755),
                                ('cmake/config.cmake', b'set(SYNTHETIC 1)\n', 0o644)):
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(mode)
        (self.source / 'llvm/link').symlink_to('include/readme.txt')
        self.originals = {}
        for name, spec in cache.specs().items():
            if name == 'llvm':
                continue
            path = self.base / spec['archive']
            if name in ('dxmt', 'headers'):
                self.archive(path, [(spec['archive_root'], tarfile.DIRTYPE, b''),
                                    (spec['archive_root'] + '/LICENSE', tarfile.REGTYPE, b'synthetic license\n')])
            else:
                path.write_bytes(('synthetic tool archive ' + name).encode())
            self.originals[name] = path
        fixed = {name: cache.sha(path) for name, path in self.originals.items()}
        patch = mock.patch.multiple(cache, FIXED_SHA=fixed, LLVM_TREES=FIXTURE_TREES, LLVM_FILE_COUNT=5)
        patch.start(); self.addCleanup(patch.stop)
        self.directory = self.base / 'cache'
        self.lock = self.base / 'test-only-lock.json'
        cache.write_json(self.lock, cache.prepare_cache(self.directory, self.source, self.originals))
        patch = mock.patch.object(cache, 'LOCK', self.lock)
        patch.start(); self.addCleanup(patch.stop)

    @staticmethod
    def archive(path, records):
        with tarfile.open(path, 'w:gz') as output:
            for name, kind, payload in records:
                member = tarfile.TarInfo(name); member.type = kind; member.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
                if kind == tarfile.REGTYPE:
                    member.size = len(payload); output.addfile(member, io.BytesIO(payload))
                else:
                    if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                        member.linkname = payload.decode()
                    output.addfile(member)

    def test_fixed_fixture_cache_extracts_without_consulting_origin_paths(self):
        checked = cache.check_cache(self.directory)
        self.assertEqual(set(checked['packages']), {'llvm', 'dxmt', 'headers', 'cmake', 'ninja', 'meson'})
        # Origin metadata names the inputs, but consumers must not reopen them.
        unavailable = self.source.with_name('source-withheld'); self.source.rename(unavailable)
        for path in self.originals.values():
            path.unlink()
        result = cache.extract_sources(self.directory, self.base / 'extracted')
        self.assertEqual(set(result), {'llvm', 'dxmt', 'headers'})
        self.assertEqual(cache.llvm_inventory(Path(result['llvm']))['trees'], FIXTURE_TREES)
        self.assertEqual((Path(result['llvm']) / 'llvm/bin/tool').stat().st_mode & 0o777, 0o755)
        self.assertEqual(os.readlink(Path(result['llvm']) / 'llvm/link'), 'include/readme.txt')
        self.assertTrue((Path(result['dxmt']) / 'LICENSE').is_file())
        self.assertTrue((Path(result['headers']) / 'LICENSE').is_file())

    def test_export_is_deterministic_and_records_git_modes_links(self):
        target = self.base / 'second.tar.gz'; inventory = self.base / 'second-files.json'
        cache.export_llvm(self.source, target, inventory)
        self.assertEqual(cache.sha(target), cache.sha(self.directory / 'llvm15-subtrees.tar.gz'))
        self.assertEqual(cache.sha(inventory), cache.sha(self.directory / 'llvm15-files.json'))
        self.assertEqual(target.read_bytes()[4:8], b'\0' * 4)
        with tarfile.open(target) as source:
            self.assertTrue(all(m.mtime == m.uid == m.gid == 0 and m.uname == m.gname == '' for m in source))
        files = {row['path']: row for row in cache.read_json(inventory)['files']}
        self.assertEqual(files['llvm/bin/tool']['git_mode'], '100755')
        self.assertEqual(files['llvm/link']['git_mode'], '120000')
        self.assertEqual(files['llvm/link']['link_target'], 'include/readme.txt')

    def test_noncanonical_original_modes_roundtrip_with_explicit_normalization(self):
        ordinary = self.source / 'llvm/lib/core.c'; executable = self.source / 'llvm/bin/tool'
        ordinary.chmod(0o664); executable.chmod(0o775)
        directory = self.base / 'mode-cache'
        lock = self.base / 'mode-lock.json'
        cache.write_json(lock, cache.prepare_cache(directory, self.source, self.originals))
        with mock.patch.object(cache, 'LOCK', lock):
            result = cache.extract_sources(directory, self.base / 'mode-extracted')
        rows = {row['path']: row for row in cache.read_json(directory / 'llvm15-files.json')['files']}
        self.assertEqual(rows['llvm/lib/core.c']['mode'], 0o664)
        self.assertEqual(rows['llvm/bin/tool']['mode'], 0o775)
        self.assertEqual(ordinary.stat().st_mode & 0o777, 0o664)
        self.assertEqual(executable.stat().st_mode & 0o777, 0o775)
        root = Path(result['llvm'])
        self.assertEqual((root / 'llvm/lib/core.c').stat().st_mode & 0o777, 0o644)
        self.assertEqual((root / 'llvm/bin/tool').stat().st_mode & 0o777, 0o755)
        expected = cache.extracted_llvm_inventory(cache.read_json(directory / 'llvm15-files.json'))
        self.assertEqual(cache.llvm_inventory(root), expected)
        with tarfile.open(directory / 'llvm15-subtrees.tar.gz') as archive:
            self.assertEqual(archive.getmember('llvm15-subtrees/llvm/lib/core.c').mode, 0o664)
            self.assertEqual(archive.getmember('llvm15-subtrees/llvm/bin/tool').mode, 0o775)

    def test_unexpected_extracted_mode_is_rejected_even_if_git_tree_matches(self):
        original = cache.safe_extract
        def changed_mode(archive, destination, archive_root):
            root = original(archive, destination, archive_root)
            if archive_root == 'llvm15-subtrees':
                (root / 'llvm/lib/core.c').chmod(0o640)
            return root
        destination = self.base / 'bad-mode'
        with mock.patch.object(cache, 'safe_extract', side_effect=changed_mode):
            with self.assertRaisesRegex(ValueError, 'explicit permission normalization'):
                cache.extract_sources(self.directory, destination)
        self.assertTrue((destination / 'failure.json').exists())
        self.assertFalse((destination / 'result.json').exists())

    def test_changed_archive_rejected_before_source_directory_creation(self):
        with (self.directory / 'dxmt.tar.gz').open('ab') as output:
            output.write(b'changed')
        target = self.base / 'never-created'
        with self.assertRaisesRegex(ValueError, 'cache package hash/size differs'):
            cache.extract_sources(self.directory, target)
        self.assertFalse(target.exists())

    def test_lock_cannot_repin_fixed_original_package(self):
        record = cache.read_json(self.lock); record['packages']['meson']['sha256'] = '0' * 64
        self.lock.write_bytes(cache.encoded(record))
        with self.assertRaisesRegex(ValueError, 'fixed original archive digest differs'):
            cache.check_cache(self.directory)

    def test_changed_manifest_rejected_before_extraction(self):
        with (self.directory / 'llvm15-files.json').open('ab') as output:
            output.write(b' ')
        with self.assertRaisesRegex(ValueError, 'cache metadata hash differs'):
            cache.extract_sources(self.directory, self.base / 'never-created')
        self.assertFalse((self.base / 'never-created').exists())

    def test_matching_tar_digest_cannot_replace_fixed_llvm_git_identity(self):
        target = self.directory / 'llvm15-subtrees.tar.gz'
        with tarfile.open(target) as source:
            members = source.getmembers()
            raw = {m.name: source.extractfile(m).read() for m in members if m.isfile()}
        raw['llvm15-subtrees/llvm/lib/core.c'] = b'int changed;\n'
        with tarfile.open(target, 'w:gz') as output:
            for member in members:
                if member.isfile():
                    member.size = len(raw[member.name]); output.addfile(member, io.BytesIO(raw[member.name]))
                else:
                    output.addfile(member)
        lock = cache.read_json(self.lock); lock['packages']['llvm'].update(sha256=cache.sha(target), size=target.stat().st_size)
        self.lock.write_bytes(cache.encoded(lock))
        destination = self.base / 'rejected-extraction'
        with self.assertRaisesRegex(ValueError, 'fixed selected Git subtrees'):
            cache.extract_sources(self.directory, destination)
        self.assertTrue((destination / 'failure.json').exists())
        self.assertFalse((destination / 'result.json').exists())

    def test_existing_cache_and_extraction_destinations_are_preserved(self):
        marker = self.directory / 'keep'; marker.write_bytes(b'original')
        with self.assertRaisesRegex(ValueError, 'fresh cache directory required'):
            cache.prepare_cache(self.directory, self.source, self.originals)
        self.assertEqual(marker.read_bytes(), b'original')
        destination = self.base / 'existing'; destination.mkdir(); marker = destination / 'keep'; marker.write_bytes(b'original')
        with self.assertRaisesRegex(ValueError, 'fresh source destination required'):
            cache.extract_sources(self.directory, destination)
        self.assertEqual(list(destination.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b'original')

    def test_cache_symlink_and_llvm_hardlink_rejected(self):
        path = self.directory / 'dxmt.tar.gz'; path.unlink(); path.symlink_to(self.originals['dxmt'])
        with self.assertRaisesRegex(ValueError, 'regular unlinked input'):
            cache.check_cache(self.directory)
        os.link(self.source / 'llvm/lib/core.c', self.base / 'outside-hardlink')
        with self.assertRaisesRegex(ValueError, 'non-regular/hardlinked'):
            cache.llvm_inventory(self.source)

    def test_unsafe_tar_members_rejected_before_any_source_write(self):
        cases = {
            'parent': [('root/../outside', tarfile.REGTYPE, b'bad')],
            'absolute': [('/outside', tarfile.REGTYPE, b'bad')],
            'link-escape': [('root/link', tarfile.SYMTYPE, b'../../outside')],
            'hardlink': [('root/link', tarfile.LNKTYPE, b'root/file')],
            'fifo': [('root/pipe', tarfile.FIFOTYPE, b'')],
            'duplicate': [('root/file', tarfile.REGTYPE, b'a'), ('root/file', tarfile.REGTYPE, b'b')],
            'wrong-root': [('elsewhere/file', tarfile.REGTYPE, b'bad')],
            'link-parent': [('root/link', tarfile.SYMTYPE, b'file'), ('root/link/child', tarfile.REGTYPE, b'bad')],
        }
        for name, entries in cases.items():
            with self.subTest(name=name):
                archive = self.base / (name + '.tar.gz'); self.archive(archive, [('root', tarfile.DIRTYPE, b''), *entries])
                destination = self.base / name; destination.mkdir()
                with self.assertRaises(ValueError):
                    cache.safe_extract(archive, destination, 'root')
                self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse((self.base / 'outside').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
