"""Real locked Meson parser checks; no compiler, guest, or GPU is invoked.

Run this module with the five explicit paths shown by --help. The SDK with
spaces case uses a temporary read-only alias of the actual SDK exclusively to
test serialization; it is not a clean-build or SDK-relocation experiment.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from . import build, tooling


ROOT = Path(__file__).resolve().parents[1]
WHEEL_SHA256 = '4b27aafce281e652dcb437b28007457411245d975c48b5db3a797d3e93ae1585'
CONFIG = None
CASES = {}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def locked_parser(meson, wheel):
    """Authenticate all installed wheel files before importing any Meson code."""
    if sha(wheel) != WHEEL_SHA256:
        raise ValueError('Meson wheel differs from the fixed 1.10.0 input')
    locked = json.loads((ROOT / 'portable_graphics_v1/cache-lock.json').read_text())
    if locked['packages']['meson']['sha256'] != WHEEL_SHA256:
        raise ValueError('versioned Meson lock differs from the independently fixed wheel')
    files = tooling.wheel_contents(wheel)
    installed = tooling.inventory(meson)
    if set(installed) != set(files):
        raise ValueError('installed Meson file set differs from the fixed wheel')
    for name, (data, mode) in files.items():
        if installed[name] != {'sha256': hashlib.sha256(data).hexdigest(), 'mode': mode}:
            raise ValueError('installed Meson content or mode differs: ' + name)
    if any(name == 'mesonbuild' or name.startswith('mesonbuild.') for name in sys.modules):
        raise ValueError('Meson was imported before its installed bytes were verified')
    sys.path.insert(0, str(meson))
    module = importlib.import_module('mesonbuild.machinefile')
    if Path(module.__file__).resolve() != meson / 'mesonbuild/machinefile.py':
        raise ValueError('wrong Meson parser module selected')
    identity = dict(wheel=str(wheel), wheel_sha256=sha(wheel),
                    installed=str(meson), installed_file_count=len(installed),
                    installed_files=installed, parser=str(Path(module.__file__)),
                    parser_sha256=sha(module.__file__))
    return module.MachineFileParser, identity


class NativeMachineFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CONFIG is None:
            raise unittest.SkipTest('explicit installed Meson, wheel, SDK and legacy file required; run module --help')
        cls.parser = CONFIG['parser']

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='meson-machine-check-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()

    def record(self, value, native=None):
        name = self.id().rsplit('.', 1)[-1]
        CASES[name] = value
        if native:
            saved = CONFIG['evidence'] / (name + '.ini')
            with saved.open('xb') as stream:
                stream.write(native.read_bytes())
            CASES[name]['native_file'] = saved.name
            CASES[name]['native_sha256'] = sha(saved)

    def parsed(self, path):
        return self.parser([str(path)], str(self.directory)).sections

    def expected(self, sdk):
        compile_flags = ['-arch', 'arm64', '-isysroot', str(sdk), '-mmacosx-version-min=15.2']
        link_flags = [*compile_flags, '-Wl,-syslibroot,' + str(sdk), '--ld-path=/usr/bin/ld']
        return {'binaries': {'c': '/usr/bin/clang', 'cpp': '/usr/bin/clang++',
                             'ar': '/usr/bin/ar', 'strip': '/usr/bin/strip'},
                'built-in options': {'c_args': compile_flags, 'cpp_args': compile_flags,
                                     'c_link_args': link_flags, 'cpp_link_args': link_flags}}

    def test_actual_sdk_roundtrip(self):
        sdk = CONFIG['sdk']
        self.assertTrue(sdk.is_dir())
        native = self.directory / 'native.ini'
        build.native_file(native, sdk)
        actual = self.parsed(native)
        self.assertEqual(actual, self.expected(sdk))
        self.record(dict(status='PASS', sdk=str(sdk), parsed=actual), native)

    def test_real_sdk_alias_with_spaces_roundtrip(self):
        sdk = self.directory / 'SDK path with spaces' / 'MacOSX.sdk'
        sdk.parent.mkdir()
        sdk.symlink_to(CONFIG['sdk'], target_is_directory=True)
        self.assertTrue(sdk.is_dir())
        self.assertEqual(sdk.resolve(strict=True), CONFIG['sdk'])
        native = self.directory / 'native with spaces.ini'
        build.native_file(native, sdk)
        actual = self.parsed(native)
        self.assertEqual(actual, self.expected(sdk))
        self.record(dict(status='PASS', sdk=str(sdk), actual_sdk=str(CONFIG['sdk']), parsed=actual,
                         fixture='temporary symlink to actual SDK; parser only, no compilation'), native)

    def test_original_double_quoted_json_arrays_are_rejected(self):
        legacy = CONFIG['legacy_native']
        before = sha(legacy)
        with self.assertRaises(Exception) as caught:
            self.parsed(legacy)
        self.assertEqual(type(caught.exception).__name__, 'MesonException')
        self.assertIn('Double quotes are not supported', str(caught.exception))
        self.assertEqual(before, sha(legacy))
        self.record(dict(status='EXPECTED_REJECTION', legacy_file=str(legacy), sha256=before,
                         error_type=type(caught.exception).__name__, error=str(caught.exception)))

    def test_unsafe_characters_fail_before_creating_output(self):
        rows = []
        for index, character in enumerate(("'", '\\', '\r', '\n')):
            with self.subTest(character=repr(character)):
                native = self.directory / ('unsafe-' + str(index) + '.ini')
                sdk = '/SDK prefix' + character + 'suffix/MacOSX.sdk'
                with self.assertRaisesRegex(ValueError, 'unsupported character') as caught:
                    build.native_file(native, sdk)
                self.assertFalse(native.exists())
                rows.append(dict(sdk=sdk, rejected=True, created=False, error=str(caught.exception)))
        self.record(dict(status='PASS', cases=rows))

    def test_existing_machine_file_is_not_overwritten(self):
        native = self.directory / 'keep.ini'
        native.write_bytes(b'preserve original bytes\n')
        before = sha(native)
        with self.assertRaises(FileExistsError):
            build.native_file(native, CONFIG['sdk'])
        self.assertEqual(sha(native), before)
        self.record(dict(status='PASS', retained_sha256=before))

    def test_meson_substitution_tokens_are_rejected_before_output(self):
        rows = []
        for index, marker in enumerate(('@DIRNAME@', '@GLOBAL_SOURCE_ROOT@')):
            with self.subTest(marker=marker):
                sdk = '/SDK ' + marker + ' root/MacOSX.sdk'
                # Demonstrate the real parser's substitution, independently of
                # production serialization, before checking the new guard.
                unsafe = self.directory / ('manual-token-' + str(index) + '.ini')
                unsafe.write_text("[built-in options]\nc_args = ['-isysroot', '" + sdk + "']\n")
                changed = self.parsed(unsafe)['built-in options']['c_args'][1]
                self.assertNotEqual(changed, sdk)
                native = self.directory / ('token-' + str(index) + '.ini')
                with self.assertRaises(ValueError) as caught:
                    build.native_file(native, sdk)
                self.assertFalse(native.exists())
                rows.append(dict(sdk=sdk, unguarded_real_parser_value=changed, rejected=True,
                                 created=False, error=str(caught.exception)))
        self.record(dict(status='PASS', cases=rows))


def main():
    global CONFIG
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('meson-install', 'wheel', 'sdk', 'legacy-native', 'evidence'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    values = {name: item.resolve(strict=True) for name, item in vars(args).items() if name != 'evidence'}
    evidence = args.evidence.absolute()
    evidence.mkdir(parents=True, exist_ok=False)
    sources = {str(path.relative_to(ROOT)): sha(path) for path in
               (Path(__file__), ROOT / 'portable_graphics_v1/build.py',
                ROOT / 'portable_graphics_v1/tooling.py', ROOT / 'portable_graphics_v1/cache-lock.json')}
    record = dict(status='STARTED', scope='real Meson parser only; no native build, guest or GPU',
                  command=[str(Path(sys.executable).resolve()), *sys.orig_argv[1:]], cwd=str(Path.cwd()),
                  python_optimized=sys.flags.optimize, sources=sources, cases=CASES)
    try:
        machine_parser, identity = locked_parser(values['meson_install'], values['wheel'])
        CONFIG = {**values, 'parser': machine_parser, 'evidence': evidence}
        record['meson_identity'] = identity
        with (evidence / 'unittest.txt').open('x') as stream:
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeMachineFileTests)
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        # Recheck all authenticated parser inputs and tested production sources.
        if tooling.inventory(values['meson_install']) != identity['installed_files']:
            raise ValueError('installed Meson changed during parser tests')
        if any(sha(ROOT / relative) != digest for relative, digest in sources.items()):
            raise ValueError('test or production source changed during parser tests')
        record.update(status='PASS' if result.wasSuccessful() else 'FAIL', methods=result.testsRun,
                      failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
        record['unittest_sha256'] = sha(evidence / 'unittest.txt')
        success = result.wasSuccessful()
    except Exception as error:
        record.update(status='FAIL', error_type=type(error).__name__, error=str(error))
        success = False
    write(evidence / 'evidence.json', record)
    print(json.dumps({key: record.get(key) for key in ('status', 'methods', 'failures', 'errors', 'error')}, sort_keys=True))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
