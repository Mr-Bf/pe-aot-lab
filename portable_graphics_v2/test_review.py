"""Independent tiny-fixture contracts; no public fetch, native build or real cache."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

from . import cache as c

TREES = {'llvm': 'ebe1848b8299add7eddb19bfa677d08ffad87c10',
         'cmake': '21545597d6e8cdbd0a543891219e729c8e87ae53'}


class IndependentCacheReview(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='graphics-v2-independent-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / 'original'
        for name, raw, mode in (('llvm/include/readme.txt', b'readme\n', 0o644),
                                ('llvm/lib/core.c', b'int core;\n', 0o644),
                                ('llvm/bin/tool', b'#!/bin/sh\nexit 0\n', 0o755),
                                ('cmake/config.cmake', b'set(SYNTHETIC 1)\n', 0o644)):
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw); path.chmod(mode)
        (self.source / 'llvm/link').symlink_to('include/readme.txt')
        self.cache = self.root / 'cache'; self.cache.mkdir()
        pins = {}
        for name, spec in c.specs().items():
            if name == 'llvm': continue
            path = self.cache / spec['archive']
            if name in ('dxmt', 'headers'):
                with tarfile.open(path, 'w:gz') as stream:
                    root = tarfile.TarInfo(spec['archive_root']); root.type = tarfile.DIRTYPE
                    root.mode = 0o755; stream.addfile(root)
                    item = tarfile.TarInfo(spec['archive_root'] + '/LICENSE')
                    item.mode = 0o644; item.size = 7; stream.addfile(item, io.BytesIO(b'notice\n'))
            else:
                path.write_bytes(('unused tiny tool ' + name).encode())
            pins[name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'size': path.stat().st_size}
        self.lock = self.root / 'lock.json'
        patch = mock.patch.multiple(c, LLVM_TREES=TREES, LLVM_FILE_COUNT=5, PINS=pins, LOCK=self.lock)
        patch.start(); self.addCleanup(patch.stop)
        self.exported = c.export_llvm(self.source, self.cache / 'llvm15-subtrees.tar.gz', self.cache / 'llvm15-files.json')
        c.write_json(self.lock, c.lock_for_export(self.exported))

    def test_reference_is_content_only_and_receipts_do_not_define_identity(self):
        value = c.read_json(self.lock)
        self.assertNotIn('origins', value)
        self.assertNotIn('runtime', value)
        self.assertNotIn(str(self.root), self.lock.read_text())
        self.assertIn('not evidence of a public fetch', self.exported['scope'])
        before = c.check_cache(self.cache)
        (self.cache / 'origins.json').write_text('old path /invalid/unavailable')
        (self.cache / 'acquisition.json').write_text('{ deliberately invalid receipt')
        self.assertEqual(c.check_cache(self.cache), before)
        self.source.rename(self.root / 'source-unavailable')
        self.assertEqual(set(c.extract_sources(self.cache, self.root / 'extracted')), {'llvm', 'dxmt', 'headers'})
        value['origins'] = {'sha256': '0' * 64}
        self.lock.write_bytes(c.encoded(value))
        with self.assertRaises(ValueError): c.load_lock()

    def test_export_normalizes_modes_and_extraction_under_strict_umask_changes_only_links(self):
        other = self.root / 'other-root'; shutil.copytree(self.source, other, symlinks=True)
        for path in other.rglob('*'):
            if not path.is_symlink():
                path.chmod(0o775 if path.is_dir() or path.stat().st_mode & 0o100 else 0o664)
        previous = os.umask(0o077)
        try:
            exported = c.export_llvm(other, self.root / 'again.tar.gz', self.root / 'again.json')
            result = c.extract_sources(self.cache, self.root / 'strict-extract')
        finally:
            os.umask(previous)
        self.assertEqual(exported['archive'], self.exported['archive'])
        self.assertEqual(exported['inventory'], self.exported['inventory'])
        source = Path(result['llvm'])
        self.assertEqual(stat.S_IMODE((source / 'llvm/link').lstat().st_mode), 0o777)
        self.assertEqual(stat.S_IMODE((source / 'llvm/include/readme.txt').stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((source / 'llvm/bin/tool').stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((other / 'llvm/lib/core.c').stat().st_mode), 0o664)
        self.assertEqual(c.source_inventory(source)['trees'], TREES)

    def test_repinning_both_archive_hashes_cannot_replace_fixed_git_trees(self):
        path = self.cache / 'llvm15-subtrees.tar.gz'
        with tarfile.open(path, 'r:gz') as source:
            members = source.getmembers()
            payloads = {m.name: source.extractfile(m).read() for m in members if m.isfile()}
        payloads['llvm15-subtrees/llvm/lib/core.c'] = b'int changed;\n'
        with tarfile.open(path, 'w:gz') as target:
            for member in members:
                if member.isfile():
                    raw = payloads[member.name]; member.size = len(raw)
                    target.addfile(member, io.BytesIO(raw))
                else: target.addfile(member)
        value = c.read_json(self.lock)
        value['packages']['llvm'].update(sha256=c.sha(path), size=path.stat().st_size, **c.tar_identity(path))
        self.lock.write_bytes(c.encoded(value))
        destination = self.root / 'rejected'
        with self.assertRaisesRegex(ValueError, 'fixed LLVM Git trees'):
            c.extract_sources(self.cache, destination)
        self.assertTrue((destination / 'failure.json').is_file())
        self.assertFalse((destination / 'result.json').exists())
        self.assertEqual((self.source / 'llvm/lib/core.c').read_bytes(), b'int core;\n')

    def test_same_tar_with_different_gzip_identity_is_not_silently_accepted(self):
        path = self.cache / 'llvm15-subtrees.tar.gz'
        original = c.tar_identity(path); raw = gzip.decompress(path.read_bytes())
        path.write_bytes(gzip.compress(raw, compresslevel=1, mtime=123))
        self.assertEqual(c.tar_identity(path), original)
        destination = self.root / 'never'
        with self.assertRaisesRegex(ValueError, 'hash/size differs: llvm'):
            c.extract_sources(self.cache, destination)
        self.assertFalse(destination.exists())

    def test_inherited_full_preflight_rejects_link_parent_and_duplicate_without_writes(self):
        for index, entries in enumerate((
            [('root/link', tarfile.SYMTYPE, b'file'), ('root/link/child', tarfile.REGTYPE, b'bad')],
            [('root/file', tarfile.REGTYPE, b'a'), ('root/file', tarfile.REGTYPE, b'b')],
            [('root/escape', tarfile.SYMTYPE, b'../../outside')],
        )):
            archive = self.root / ('unsafe-' + str(index) + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as target:
                item = tarfile.TarInfo('root'); item.type = tarfile.DIRTYPE; target.addfile(item)
                for name, kind, raw in entries:
                    item = tarfile.TarInfo(name); item.type = kind
                    if kind == tarfile.REGTYPE:
                        item.size = len(raw); target.addfile(item, io.BytesIO(raw))
                    else:
                        item.linkname = raw.decode(); target.addfile(item)
            destination = self.root / ('out-' + str(index)); destination.mkdir()
            with self.subTest(index=index), self.assertRaises(ValueError):
                c.safe_extract(archive, destination, 'root')
            self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse((self.root / 'outside').exists())


if __name__ == '__main__':
    unittest.main()
