"""Synthetic command/artifact and archive boundaries; no real compilation."""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from portable_lifter_v1 import deps


class DependencyBoundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='portable-deps-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.cache = self.base / 'cache'; self.cache.mkdir()
        self.prefix = self.base / 'fresh/deps'
        self.sdk = self.base / 'sdk'; self.sdk.mkdir()
        self.python = self.put('tools/python', b'fake python')
        self.tools = {'paths': {'cmake': str(self.put('tools/cmake', b'fake cmake')),
                               'ninja': str(self.put('tools/ninja', b'fake ninja')),
                               'llvm': str(self.base / 'tools/llvm')}}
        self.put('tools/llvm/include/unwind.h', b'fake header')
        self.put('tools/llvm/lib/libunwind.dylib', b'fake dylib')
        self.metadata = {'schema': 1, 'sources': {}}
        for name, (commit, tree) in deps.PINS.items():
            archive = self.cache / (name + '.tar')
            with tarfile.open(archive, 'w') as tar:
                member = tarfile.TarInfo(name); member.type = tarfile.DIRTYPE
                tar.addfile(member)
                for relative in [deps.LICENSES[name], 'CMakeLists.txt']:
                    data = ('synthetic ' + name + '/' + relative).encode()
                    member = tarfile.TarInfo(name + '/' + relative); member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
            self.metadata['sources'][name] = dict(archive=archive.name, sha256=deps.sha(archive), commit=commit, tree=tree)
        self.save_cache()
        self.lock = self.put('fixture-lock.json', json.dumps(self.metadata).encode())
        patch = mock.patch.object(deps, 'LOCK', self.lock); patch.start(); self.addCleanup(patch.stop)
        self.commands = []

    def put(self, name, data):
        path = self.base / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
        return path

    def save_cache(self):
        (self.cache / 'cache.json').write_text(json.dumps(self.metadata))

    def runner(self, argv, label, cwd=None, env=None):
        row = dict(command=argv, label=label, cwd=cwd, env=env, returncode=0, stdout='', stderr='')
        self.commands.append(row)
        if label in ('gflags-install', 'glog-install'):
            name = label.removesuffix('-install')
            libraries = ('libgflags.a', 'libgflags_nothreads.a') if name == 'gflags' else ('libglog.a',)
            for library in libraries:
                self.put(self.prefix / 'lib' / library, b'!<arch>\nsynthetic ' + library.encode())
            header = 'gflags/gflags.h' if name == 'gflags' else 'glog/logging.h'
            self.put(self.prefix / 'include' / header, b'synthetic ' + header.encode())
            self.put(self.prefix / 'lib/cmake' / name / (name + 'Config.cmake'), b'synthetic CMake ' + name.encode())
        if label == 'xed-build-install':
            # The real XED installer resets its install directory. Never model
            # it as appending all dependencies to the shared installation.
            install = Path(next(value.split('=', 1)[1] for value in argv if value.startswith('--install-dir=')))
            self.before_xed = deps.tree(self.prefix)
            install.mkdir(parents=True, exist_ok=True)
            self.put(install / 'prior-install-marker', b'must be removed by installer')
            shutil.rmtree(install)
            for name in ('libxed.a', 'libxed-ild.a'):
                self.put(install / 'lib' / name, b'!<arch>\nsynthetic ' + name.encode())
            for name in ('xed-interface.h', 'xed-ild.h', 'detail/table.h'):
                self.put(install / 'include/xed' / name, b'synthetic ' + name.encode())
            self.put(install / 'bin/not-a-required-tool', b'not merged')
        return row

    def invoke(self, run=None):
        return deps.build(self.prefix, self.cache, self.tools, self.sdk, self.python, run or self.runner)

    def test_synthetic_success_plans_explicit_new_paths_and_retains_licenses(self):
        result = self.invoke()
        self.assertEqual(result['status'], 'BUILT_FROM_FIXED_OFFLINE_SOURCES_NOT_LIFTER_VERIFIED')
        self.assertEqual(len(self.commands), 7)
        self.assertEqual(len(result['libraries']), 5)
        self.assertEqual(set(result['licenses']), set(deps.PINS))
        glog = next(row['command'] for row in self.commands if row['label'] == 'glog-configure')
        self.assertIn('-DUnwind_INCLUDE_DIR=' + self.tools['paths']['llvm'] + '/include', glog)
        self.assertIn('-DUnwind_LIBRARY=' + self.tools['paths']['llvm'] + '/lib/libunwind.dylib', glog)
        self.assertIn('-DCMAKE_OSX_SYSROOT=' + str(self.sdk), glog)
        self.assertIn('-DCMAKE_OSX_ARCHITECTURES=arm64', glog)
        self.assertIn('-DWITH_GTEST=OFF', glog)
        self.assertIn('-DCMAKE_DISABLE_FIND_PACKAGE_GTest=ON', glog)
        xed = self.commands[-1]
        self.assertIn('--host-cpu=aarch64', xed['command'])
        self.assertEqual(xed['command'][:3], [str(self.python), '-S', str(self.prefix.with_name('deps-sources') / 'xed/mfile.py')])
        self.assertEqual(xed['env'], {'SDKROOT': str(self.sdk), 'PYTHONDONTWRITEBYTECODE': '1',
                                     'PYTHONNOUSERSITE': '1',
                                     'PYTHONPATH': str(self.prefix.with_name('deps-sources') / 'mbuild')})
        config = (self.prefix / 'lib/cmake/XED/XEDConfig.cmake').read_text()
        self.assertNotIn(str(self.base), config)
        self.assertIn('${CMAKE_CURRENT_LIST_DIR}/../../..', config)
        self.assertIn('lib/libxed-ild.a', config)
        self.assertFalse((self.prefix / 'lib/cmake/llvm').exists())
        stage = self.prefix.with_name('deps-build') / 'xed-install'
        self.assertIn('--install-dir=' + str(stage), xed['command'])
        self.assertEqual(result['xed_install']['prefix'], str(stage))
        self.assertEqual(result['xed_install']['preserved_install_files'], self.before_xed)
        self.assertEqual(result['xed_install']['installed_files'], deps.tree(stage))
        self.assertEqual(set(result['xed_install']['merged_files']),
                         {'lib/libxed.a', 'lib/libxed-ild.a', 'include/xed/xed-interface.h',
                          'include/xed/xed-ild.h', 'include/xed/detail/table.h'})
        after = deps.tree(self.prefix)
        self.assertEqual({name: after[name] for name in self.before_xed}, self.before_xed)
        for name in ('gflags', 'glog'):
            self.assertIn('lib/cmake/' + name + '/' + name + 'Config.cmake', after)
        self.assertFalse((self.prefix / 'bin').exists())
        self.assertFalse((stage / 'prior-install-marker').exists())

    def test_xed_installer_cannot_modify_shared_prefix(self):
        def corrupt(argv, label, **kwargs):
            row = self.runner(argv, label, **kwargs)
            if label == 'xed-build-install':
                (self.prefix / 'lib/libglog.a').write_bytes(b'!<arch>\ncorrupted')
            return row
        with self.assertRaisesRegex(ValueError, 'installer changed shared'):
            self.invoke(corrupt)
        self.assertFalse((self.prefix / 'lib/libxed.a').exists())
        self.assertTrue((self.prefix.with_name('deps-build') / 'failure.json').exists())

    def test_xed_merge_preserves_colliding_file_without_partial_copy(self):
        def collision(argv, label, **kwargs):
            row = self.runner(argv, label, **kwargs)
            if label == 'glog-install':
                self.put(self.prefix / 'lib/libxed.a', b'keep existing file')
            return row
        with self.assertRaisesRegex(ValueError, 'merge destination already exists'):
            self.invoke(collision)
        self.assertEqual((self.prefix / 'lib/libxed.a').read_bytes(), b'keep existing file')
        self.assertFalse((self.prefix / 'include/xed').exists())
        self.assertFalse((self.prefix / 'lib/libxed-ild.a').exists())

    def test_xed_stage_links_and_special_files_rejected_before_copy(self):
        for kind in ('symlink', 'hardlink', 'fifo', 'directory-symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.base) as temp:
                base = Path(temp); stage = base / 'stage'; prefix = base / 'prefix'; prefix.mkdir()
                for name in ('lib/libxed.a', 'lib/libxed-ild.a'):
                    self.put(stage / name, b'!<arch>\nnot executable')
                for name in ('xed-interface.h', 'xed-ild.h'):
                    self.put(stage / 'include/xed' / name, b'header')
                suspect = stage / 'extra'
                if kind == 'symlink':
                    suspect.symlink_to(stage / 'lib/libxed.a')
                elif kind == 'hardlink':
                    os.link(stage / 'lib/libxed.a', suspect)
                elif kind == 'directory-symlink':
                    suspect.symlink_to(stage / 'include', target_is_directory=True)
                else:
                    os.mkfifo(suspect)
                with self.assertRaisesRegex(ValueError, 'symlink|hardlink|non-regular'):
                    deps.merge_xed(stage, prefix)
                self.assertEqual(list(prefix.iterdir()), [])

    def test_modified_archive_rejected_before_creation_or_commands(self):
        with (self.cache / 'xed.tar').open('ab') as stream:
            stream.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'digest differs'):
            self.invoke()
        self.assertFalse(self.prefix.exists()); self.assertEqual(self.commands, [])

    def test_mutable_cache_cannot_repin_versioned_archive(self):
        self.metadata['sources']['xed']['sha256'] = '0' * 64; self.save_cache()
        with self.assertRaisesRegex(ValueError, 'versioned cache lock'):
            self.invoke()
        self.assertFalse(self.prefix.exists())

    def test_bad_commit_and_escaping_archive_name_rejected(self):
        for field, value in [('commit', '0' * 40), ('archive', '../xed.tar')]:
            previous = self.metadata['sources']['xed'][field]
            self.metadata['sources']['xed'][field] = value; self.save_cache()
            with self.assertRaisesRegex(ValueError, 'fixed source identity'):
                self.invoke()
            self.metadata['sources']['xed'][field] = previous
        self.assertEqual(self.commands, [])

    def test_archive_traversal_links_duplicates_and_special_files_rejected(self):
        cases = [('xed/../outside', tarfile.REGTYPE), ('xed/link', tarfile.SYMTYPE),
                 ('xed/hardlink', tarfile.LNKTYPE), ('xed/pipe', tarfile.FIFOTYPE),
                 ('wrong/file', tarfile.REGTYPE)]
        for index, (name, kind) in enumerate(cases):
            archive = self.base / ('bad-' + str(index) + '.tar')
            with tarfile.open(archive, 'w') as tar:
                member = tarfile.TarInfo(name); member.type = kind; member.linkname = '/outside'
                tar.addfile(member)
            destination = self.base / ('case-' + str(index)) / 'xed'; destination.parent.mkdir()
            with self.assertRaisesRegex(ValueError, 'unsafe/duplicate/link'):
                deps.extract(archive, destination, 'xed')
            self.assertFalse(destination.exists())
        archive = self.base / 'duplicate.tar'
        with tarfile.open(archive, 'w') as tar:
            for _ in range(2):
                tar.addfile(tarfile.TarInfo('xed/file'))
        with self.assertRaisesRegex(ValueError, 'unsafe/duplicate/link'):
            deps.extract(archive, self.base / 'xed', 'xed')

    def test_existing_prefix_or_source_directory_preserved(self):
        self.prefix.mkdir(parents=True); marker = self.prefix / 'marker'; marker.write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError, 'fresh real install'):
            self.invoke()
        self.assertEqual(marker.read_bytes(), b'keep'); marker.unlink(); self.prefix.rmdir()
        self.prefix.with_name('deps-sources').mkdir()
        with self.assertRaisesRegex(ValueError, 'preserve existing'):
            self.invoke()
        self.assertEqual(self.commands, [])

    def test_failed_command_preserves_failure_and_does_not_claim_success(self):
        def failed(*args, **kwargs):
            raise RuntimeError('recorded injected compiler failure')
        with self.assertRaisesRegex(RuntimeError, 'compiler failure'):
            self.invoke(failed)
        builds = self.prefix.with_name('deps-build')
        self.assertTrue((builds / 'failure.json').exists())
        self.assertFalse((builds / 'result.json').exists())

    def test_success_exit_without_libraries_is_rejected(self):
        def empty(argv, label, cwd=None, env=None):
            return dict(command=argv, returncode=0, stdout='', stderr='')
        with self.assertRaisesRegex(ValueError, 'static library absent'):
            self.invoke(empty)

    def test_new_llvm_unwind_required_and_never_falls_back(self):
        (Path(self.tools['paths']['llvm']) / 'lib/libunwind.dylib').unlink()
        with self.assertRaisesRegex(ValueError, 'no global fallback'):
            self.invoke()
        self.assertFalse(self.prefix.exists()); self.assertEqual(self.commands, [])

    def test_xed_python_imports_fresh_mbuild_instead_of_inherited_package(self):
        source = self.prefix.with_name('deps-sources')
        local = self.put(source / 'mbuild/mbuild/__init__.py', b"ORIGIN='fresh-source'\n")
        unrelated = self.put('unrelated-python/mbuild/__init__.py', b"ORIGIN='unexpected-global'\n")
        label, argv, cwd, additions = deps.plans(self.prefix, source, self.prefix.with_name('deps-build'),
                                               self.tools, self.sdk, self.python, 2)[-1]
        env = {key: os.environ[key] for key in ('HOME', 'TMPDIR') if key in os.environ}
        env.update(PATH='/usr/bin:/bin', PYTHONPATH=str(unrelated.parent.parent))
        env.update(additions)
        # Only Python import resolution is exercised; no mfile/compiler runs.
        result = subprocess.run([sys.executable, argv[1], '-c',
            'import json,mbuild,sys; print(json.dumps([mbuild.ORIGIN,mbuild.__file__,sys.flags.no_site,sys.flags.no_user_site]))'],
            cwd=self.base, env=env, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), ['fresh-source', str(local), 1, 1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
