"""Small archive/load-command boundary tests; no toolchain build or image execution."""
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

from portable_lifter_v1 import tools


def member(name, kind='file', data=b'data', target=''):
    info = tarfile.TarInfo(name)
    info.mode = 0o755 if kind == 'dir' else 0o644
    info.type = dict(file=tarfile.REGTYPE, dir=tarfile.DIRTYPE,
                     link=tarfile.SYMTYPE, hard=tarfile.LNKTYPE,
                     fifo=tarfile.FIFOTYPE)[kind]
    info.linkname = target
    info.size = len(data) if kind == 'file' else 0
    return info, data


def archive(path, entries):
    with tarfile.open(path, 'w:gz') as tar:
        for info, data in entries:
            tar.addfile(info, io.BytesIO(data) if info.isfile() else None)


def image(path, dependencies=('/usr/lib/libSystem.B.dylib',), identity=None,
          rpaths=(), cpu=0x100000c):
    commands = []
    strings = [(0xd, identity)] if identity is not None else []
    strings += [(0xc, value) for value in dependencies]
    strings += [(0x8000001c, value) for value in rpaths]
    for command, value in strings:
        offset = 12 if command == 0x8000001c else 24
        raw = value.encode() + b'\0'
        length = (offset + len(raw) + 7) // 8 * 8
        commands.append(struct.pack('<III', command, length, offset) +
                        b'\0' * (offset - 12) + raw + b'\0' * (length - offset - len(raw)))
    body = b''.join(commands)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack('<8I', 0xfeedfacf, cpu, 0, 6 if identity else 2,
                                 len(commands), len(body), 0, 0) + body)
    return path


class ToolsBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='portable-tools-unit-')
        # macOS /var is a symlink. Explicit real roots are part of the API.
        self.base = Path(self.temporary.name).resolve()
        self.destination = self.base / 'destination'; self.destination.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def test_valid_internal_links_and_file_modes(self):
        executable = member('pkg/1/bin/tool', data=b'program')
        executable[0].mode = 0o755
        source = self.base / 'valid.tar.gz'
        archive(source, [member('pkg/1', 'dir'), executable,
                         member('pkg/1/tool', 'link', target='bin/tool')])
        result = tools.extract_archive(source, self.destination, 'pkg/1')
        self.assertEqual(result['symlinks'], 1)
        self.assertEqual((self.destination / 'pkg/1/tool').read_bytes(), b'program')
        self.assertEqual((self.destination / 'pkg/1/bin/tool').stat().st_mode & 0o777, 0o755)

    def test_reject_unsafe_member_graphs_before_writing(self):
        root = member('pkg/1', 'dir')
        cases = {
            'parent': [root, member('pkg/1/../outside')],
            'absolute': [root, member('/pkg/1/outside')],
            'different_root': [root, member('pkg/2/outside')],
            'duplicate': [root, member('pkg/1/x'), member('pkg/1/x')],
            'no_root': [member('pkg/1/x')],
            'hardlink': [root, member('pkg/1/x', 'hard', target='pkg/1/y')],
            'fifo': [root, member('pkg/1/x', 'fifo')],
            'link_escape': [root, member('pkg/1/x', 'link', target='../../outside')],
            'link_absolute': [root, member('pkg/1/x', 'link', target='/tmp/outside')],
            'dangling_link': [root, member('pkg/1/x', 'link', target='missing')],
            'cycle': [root, member('pkg/1/x', 'link', target='y'),
                      member('pkg/1/y', 'link', target='x')],
            'link_parent': [root, member('pkg/1/link', 'link', target='real'),
                            member('pkg/1/real', 'dir'), member('pkg/1/link/x')],
            'file_parent': [root, member('pkg/1/file'), member('pkg/1/file/x')],
        }
        for name, entries in cases.items():
            with self.subTest(name=name):
                source = self.base / (name + '.tar.gz'); archive(source, entries)
                with self.assertRaises(ValueError):
                    tools.extract_archive(source, self.destination, 'pkg/1')
                self.assertEqual(list(self.destination.iterdir()), [])

    def test_existing_parent_symlink_cannot_redirect_extraction(self):
        outside = self.base / 'outside'; outside.mkdir()
        (self.destination / 'pkg').symlink_to(outside, target_is_directory=True)
        source = self.base / 'link-parent.tar.gz'
        archive(source, [member('pkg/1', 'dir'), member('pkg/1/x')])
        with self.assertRaises(ValueError):
            tools.extract_archive(source, self.destination, 'pkg/1')
        self.assertEqual(list(outside.iterdir()), [])

    def test_cache_failure_precedes_output_creation_or_execution(self):
        cache = self.base / 'cache'; cache.mkdir()
        for name in tools.PACKAGES:
            (cache / name).write_bytes(b'not the pinned source')
        output = self.base / 'new-prefix'
        calls = []
        with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
            tools.install(output, cache, lambda *args, **kwargs: calls.append(args))
        self.assertFalse(output.exists())
        self.assertEqual(calls, [])

    def test_existing_content_symlink_prefix_and_invalid_jobs_are_rejected(self):
        sentinel = self.destination / 'original'; sentinel.write_bytes(b'preserve')
        for jobs in (0, 9, True, 1.5):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                tools.install(self.base / 'uncreated', self.base, None, jobs=jobs)
        with self.assertRaisesRegex(ValueError, 'fresh empty'):
            tools.install(self.destination, self.base, None)
        alias = self.base / 'alias'; alias.symlink_to(self.destination)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            tools.install(alias, self.base, None)
        self.assertEqual(sentinel.read_bytes(), b'preserve')

    def test_native_relative_dependency_closure(self):
        library = image(self.destination / 'lib/liba.dylib', identity='@rpath/liba.dylib')
        executable = image(self.destination / 'bin/tool',
                           dependencies=('@rpath/liba.dylib', '/usr/lib/libSystem.B.dylib'),
                           rpaths=('@loader_path/../lib',))
        result = tools.selected_closure(self.destination, [executable])
        self.assertEqual(set(result['nodes']), {str(library), str(executable)})
        self.assertEqual(len(result['edges']), 3)

    def test_absolute_loads_search_escape_and_bad_identity_are_rejected(self):
        cases = [
            dict(dependencies=('/opt/homebrew/opt/zstd/lib/libzstd.1.dylib',)),
            dict(dependencies=('/old-work/llvm/lib/libLLVM.dylib',)),
            dict(dependencies=('@@HOMEBREW_PREFIX@@/opt/zstd/lib/libzstd.1.dylib',)),
            dict(rpaths=('/old-work/llvm/lib',)),
            dict(rpaths=('@loader_path/../../outside',)),
            dict(identity='/old-work/liba.dylib'),
            dict(dependencies=('@rpath/missing.dylib',), rpaths=('@loader_path',)),
        ]
        for number, arguments in enumerate(cases):
            with self.subTest(arguments=arguments):
                executable = image(self.destination / ('tool-' + str(number)), **arguments)
                with self.assertRaises(ValueError):
                    tools.selected_closure(self.destination, [executable])

    def test_dependency_symlink_to_external_image_is_rejected(self):
        outside = image(self.base / 'external.dylib', identity='@rpath/external.dylib')
        alias = self.destination / 'lib/external.dylib'; alias.parent.mkdir()
        alias.symlink_to(outside)
        executable = image(self.destination / 'bin/tool',
                           dependencies=('@rpath/external.dylib',), rpaths=('@loader_path/../lib',))
        with self.assertRaisesRegex(ValueError, 'escaped'):
            tools.selected_closure(self.destination, [executable])

    def test_wrong_architecture_and_truncated_load_commands_are_rejected(self):
        executable = image(self.destination / 'x86', cpu=0x1000007)
        with self.assertRaisesRegex(ValueError, 'ARM64'):
            tools.macho(executable)
        executable = image(self.destination / 'truncated')
        executable.write_bytes(executable.read_bytes()[:-1])
        with self.assertRaisesRegex(ValueError, 'truncated'):
            tools.macho(executable)


if __name__ == '__main__':
    unittest.main(verbosity=2)
