"""Small synthetic ZIPs: no tool execution, downloads or native builds."""
import base64
import csv
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

from . import tooling


def sample():
    return {
        tooling.DIST + '/WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        tooling.DIST + '/METADATA': b'Metadata-Version: 2.4\nName: meson\nVersion: 1.10.0\n',
        tooling.DIST + '/licenses/COPYING': b'fixture notice\n',
        'mesonbuild/mesonmain.py': b'# synthetic test, never executed\n',
    }


def wheel(path, files=None, transform=None, modes=None, extra=None):
    files = sample() if files is None else dict(files)
    rows = []
    for name, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
        rows.append([name, 'sha256=' + digest, str(len(data))])
    rows.append([tooling.DIST + '/RECORD', '', ''])
    if transform:
        transform(rows)
    record = io.StringIO(); csv.writer(record).writerows(rows)
    files[tooling.DIST + '/RECORD'] = record.getvalue().encode()
    with zipfile.ZipFile(path, 'w') as output:
        for name, data in files.items():
            item = zipfile.ZipInfo(name)
            item.create_system = 3
            item.external_attr = (modes or {}).get(name, stat.S_IFREG | 0o644) << 16
            output.writestr(item, data)
        if extra:
            output.writestr(*extra)


class ToolingBoundaries(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='graphics-tooling-test-')
        self.addCleanup(temp.cleanup); self.base = Path(temp.name).resolve()
        self.archive = self.base / 'fixture.whl'

    def test_valid_record_extracts_exact_files_and_preserves_notice(self):
        wheel(self.archive)
        destination = self.base / 'unpacked'
        result = tooling.extract_wheel(self.archive, destination)
        self.assertEqual(set(result), set(sample()) | {tooling.DIST + '/RECORD'})
        self.assertEqual((destination / tooling.DIST / 'licenses/COPYING').read_bytes(), b'fixture notice\n')
        self.assertTrue(all(row['mode'] == 0o644 for row in result.values()))

    def test_record_hash_size_omission_duplicate_and_self_rejected_before_write(self):
        edits = [lambda rows: rows[0].__setitem__(1, 'sha256=' + 'A'*43),
                 lambda rows: rows[0].__setitem__(2, '999'), lambda rows: rows.pop(0),
                 lambda rows: rows.append(list(rows[0])), lambda rows: rows[-1].__setitem__(1, 'sha256=' + 'A'*43)]
        for index, edit in enumerate(edits):
            with self.subTest(index=index):
                wheel(self.archive, transform=edit)
                destination = self.base / ('bad-' + str(index))
                with self.assertRaises(ValueError):
                    tooling.extract_wheel(self.archive, destination)
                self.assertFalse(destination.exists())

    def test_paths_case_collisions_and_parent_files_rejected_before_write(self):
        extras = ['../outside', '/mesonbuild/evil', 'mesonbuild/../evil', 'mesonbuild//evil',
                  'mesonbuild\\evil', 'mesonbuild/drive:x', 'mesonbuild/evil.pth', 'mesonbuild/evil.so',
                  'mesonbuild/MESONMAIN.py', 'mesonbuild']
        for index, name in enumerate(extras):
            with self.subTest(name=name):
                files = sample(); files[name] = b'evil'; wheel(self.archive, files)
                destination = self.base / ('bad-path-' + str(index))
                with self.assertRaises(ValueError):
                    tooling.extract_wheel(self.archive, destination)
                self.assertFalse(destination.exists())

    def test_link_fifo_and_privileged_mode_rejected(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o644, stat.S_IFREG | 0o4644):
            with self.subTest(mode=mode):
                wheel(self.archive, modes={'mesonbuild/mesonmain.py':mode})
                with self.assertRaises(ValueError):
                    tooling.wheel_contents(self.archive)

    def test_wrong_version_and_non_pure_wheel_rejected(self):
        for name, content in [(tooling.DIST+'/METADATA', b'Name: meson\nVersion: 9.0.0\n'),
                              (tooling.DIST+'/WHEEL', b'Root-Is-Purelib: false\nTag: cp313-cp313-macosx\n')]:
            with self.subTest(name=name):
                files = sample(); files[name] = content; wheel(self.archive, files)
                with self.assertRaises(ValueError):
                    tooling.wheel_contents(self.archive)

    def test_existing_destination_is_never_overwritten(self):
        wheel(self.archive); target = self.base / 'existing'; target.mkdir()
        sentinel = target/'keep'; sentinel.write_bytes(b'keep')
        with self.assertRaises(ValueError):
            tooling.extract_wheel(self.archive, target)
        self.assertEqual(sentinel.read_bytes(), b'keep')

    def test_wrong_cache_hash_rejected_before_any_command_or_prefix(self):
        cache = self.base/'cache'; cache.mkdir(); (cache/'cmake.tar.gz').write_bytes(b'incorrect')
        prefix = self.base/'tools'; run = mock.Mock()
        with self.assertRaises(ValueError):
            tooling.install(prefix, cache, self.base, Path(sys.executable), run)
        run.assert_not_called(); self.assertFalse(prefix.exists())

    def test_clean_environment_and_meson_command_contract(self):
        tools = dict(cmake=self.base/'cmake/bin/cmake', ninja=self.base/'ninja/bin/ninja', meson=self.base/'meson')
        with mock.patch.dict(os.environ, {'PATH':'/opt/homebrew/bin', 'PYTHONPATH':'/bad', 'DYLD_LIBRARY_PATH':'/bad',
                                          'DEVELOPER_DIR':'/wrong', 'CFLAGS':'-bad', 'GIT_CONFIG':'/wrong'}):
            env = tooling.meson_env(tools, sys.executable, self.base)
        self.assertEqual(env['PYTHONPATH'], str(tools['meson']))
        self.assertEqual(env['PYTHONNOUSERSITE'], '1')
        self.assertNotIn('/opt/homebrew', env['PATH'])
        self.assertFalse({'DYLD_LIBRARY_PATH','DEVELOPER_DIR','CFLAGS','GIT_CONFIG'} & set(env))

    def test_incomplete_callback_cannot_claim_success(self):
        for record in ({}, dict(returncode=True, stdout='', stderr=''), dict(returncode=0),
                       dict(returncode=1, stdout='', stderr='')):
            with self.subTest(record=record), self.assertRaises(ValueError):
                tooling.call(lambda *a, **k:record, ['fixture'], 'fixture', {})


if __name__ == '__main__':
    unittest.main()
