"""Adversarial pure-file tests; no native process or App is launched."""
import ast
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

from . import review as r


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.product = Path(self.tmp.name).resolve()
        self.base = self.product / 'native/runtime-source'
        self.base.mkdir(parents=True)
        self.templates = {str(r.ROOT / name): sha for name, sha in r.PINS.items()}
        generated = {r.RUNTIME: (r.ROOT / r.RUNTIME).read_bytes(),
                     r.TRANSACTION: r.replacement((r.ROOT / r.TRANSACTION).read_bytes(), (r.ROOT / r.LOOKUP).read_bytes())}
        for name, data in generated.items():
            target = self.base / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        self.manifest = dict(schema=1, status='GENERATED_INLINE_LOOKUP_SOURCES_NOT_EXECUTED',
            contract=r.CONTRACT, lookup_sha256=r.PINS[r.LOOKUP], templates=self.templates,
            generated_files={name: r.digest(data) for name, data in generated.items()})
        self.write_manifest()
        self.value = dict(contract=r.CONTRACT, manifest_path=str(self.base / 'runtime.json'),
            manifest_sha256=r.digest((self.base / 'runtime.json').read_bytes()), source_root=str(self.base),
            compile_source=str(self.base / r.RUNTIME), transaction_source=str(self.base / r.TRANSACTION),
            lookup_sha256=r.PINS[r.LOOKUP])
        self.record = {'runtime_lookup': copy.deepcopy(self.value)}
        self.native = {'runtime_lookup': copy.deepcopy(self.value), 'compile_inputs_before': {
            **self.templates, str(self.base / 'runtime.json'): self.value['manifest_sha256'],
            **{str(self.base / name): r.digest(data) for name, data in generated.items()}}}
        r.files.OBSERVED.clear()

    def tearDown(self):
        r.files.OBSERVED.clear()
        self.tmp.cleanup()

    def write_manifest(self):
        (self.base / 'runtime.json').write_text(json.dumps(self.manifest))

    def update_manifest(self):
        self.write_manifest()
        sha = r.digest((self.base / 'runtime.json').read_bytes())
        self.record['runtime_lookup']['manifest_sha256'] = sha
        self.native['runtime_lookup']['manifest_sha256'] = sha
        self.native['compile_inputs_before'][str(self.base / 'runtime.json')] = sha

    def check(self):
        return r.lookup_identity(self.product, self.record, self.native)

    def test_exact_overlay(self):
        self.assertEqual(self.check(), self.value)

    def test_reference_lookup_rejected_even_with_updated_hash(self):
        original = (r.ROOT / r.TRANSACTION).read_bytes()
        (self.base / r.TRANSACTION).write_bytes(original)
        self.manifest['generated_files'][r.TRANSACTION] = r.digest(original)
        self.update_manifest()
        with self.assertRaisesRegex(ValueError, 'generated file identity'): self.check()

    def test_unrelated_runtime_edit_rejected_even_with_updated_hash(self):
        data = (self.base / r.RUNTIME).read_bytes() + b'\n/* change */\n'
        (self.base / r.RUNTIME).write_bytes(data)
        self.manifest['generated_files'][r.RUNTIME] = r.digest(data)
        self.update_manifest()
        with self.assertRaisesRegex(ValueError, 'generated file identity'): self.check()

    def test_wrong_template_hash(self):
        self.manifest['templates'][str(r.ROOT / r.TRANSACTION)] = '0' * 64
        self.update_manifest()
        with self.assertRaisesRegex(ValueError, 'template identity'): self.check()

    def test_missing_compile_identity(self):
        for name in self.native['compile_inputs_before'].copy():
            native = copy.deepcopy(self.native); del native['compile_inputs_before'][name]
            with self.subTest(path=name), self.assertRaisesRegex(ValueError, 'not bound by compilation'):
                r.lookup_identity(self.product, self.record, native)

    def test_mismatched_native_descriptor(self):
        self.native['runtime_lookup']['contract'] = 'other'
        with self.assertRaisesRegex(ValueError, 'native/product'): self.check()

    def test_old_compile_path_rejected(self):
        self.record['runtime_lookup']['compile_source'] = str(r.ROOT / r.RUNTIME)
        self.native['runtime_lookup'] = copy.deepcopy(self.record['runtime_lookup'])
        with self.assertRaisesRegex(ValueError, 'descriptor'): self.check()

    def test_extra_overlay_file_rejected(self):
        (self.base / 'unexpected.c').write_text('')
        with self.assertRaisesRegex(ValueError, 'members'): self.check()

    def test_overlay_symlink_rejected(self):
        (self.base / 'alias').symlink_to(self.base / 'runtime.json')
        with self.assertRaisesRegex(ValueError, 'link'): self.check()

    def test_duplicate_json_key_rejected(self):
        path = self.product / 'duplicate.json'; path.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate'): r.js(path)

    def test_wrong_replacement_anchor(self):
        for raw in (b'', r.ORIGINAL + r.ORIGINAL):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'unique'):
                r.replacement(raw, (r.ROOT / r.LOOKUP).read_bytes())

    def test_wrong_candidate(self):
        with self.assertRaisesRegex(ValueError, 'verified candidate'):
            r.replacement(r.ORIGINAL, b'bad replacement')

    def test_dependency_paths_spaces_continuation(self):
        path = self.product / 'with spaces.c'; path.write_text('')
        escaped = str(path).replace(' ', '\\ ')
        self.assertEqual(r.dependency_paths('probe: \\\n ' + escaped + '\n'), {str(path)})

    def test_dependency_relative_rejected(self):
        with self.assertRaisesRegex(ValueError, 'absolute'): r.dependency_paths('probe: missing.c')

    def test_dependency_target_rejected(self):
        with self.assertRaisesRegex(ValueError, 'target'): r.dependency_paths('wrong: /file')

    @staticmethod
    def symbol_image(name='_aot_begin'):
        strings = b'\0' + name.encode() + b'\0'
        return (struct.pack('<8I', 0xfeedfacf, 0x100000c, 0, 1, 1, 24, 0, 0) +
                struct.pack('<6I', 2, 24, 56, 1, 72, len(strings)) +
                struct.pack('<IBBHQ', 1, 1, 0, 0, 0) + strings)

    def test_symbols_parse_actual_nlist(self):
        self.assertEqual(r.symbols(self.symbol_image('_bsearch')), ['_bsearch'])

    def test_symbols_bad_offset(self):
        data = bytearray(self.symbol_image()); struct.pack_into('<I', data, 56, 1000)
        with self.assertRaisesRegex(ValueError, 'string offset'): r.symbols(data)

    def test_symbols_unterminated(self):
        data = self.symbol_image()[:-1] + b'x'
        with self.assertRaisesRegex(ValueError, 'unterminated'): r.symbols(data)

    def test_wrong_architecture(self):
        data = bytearray(self.symbol_image()); struct.pack_into('<I', data, 4, 0x1000007)
        with self.assertRaisesRegex(ValueError, 'ARM64'): r.symbols(data)

    def test_bad_command_extent(self):
        data = bytearray(self.symbol_image()); struct.pack_into('<I', data, 36, 4096)
        with self.assertRaisesRegex(ValueError, 'length'): r.symbols(data)

    def contexts(self):
        a = dict(cwd=str(self.product / 'native'), env=dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin',
                 HOME='/Users/example', LANG='C', LC_ALL='C', DXMT_LOG_PATH='none'))
        b = dict(cwd=a['cwd'], env=dict(a['env'], PYTHONDONTWRITEBYTECODE='1', GIT_CONFIG_NOSYSTEM='1',
                 GIT_CONFIG_GLOBAL='/dev/null', GIT_CEILING_DIRECTORIES='/providers',
                 DEVELOPER_DIR='/Xcode/Developer', SDKROOT='/Xcode/SDK'))
        return a, b

    def test_requested_and_effective_environment_are_distinct(self):
        a, b = self.contexts()
        self.assertNotEqual(a['env'], b['env'])
        r.command_context(a, b, self.product, '/providers/cpu', '/Xcode/SDK', '/Xcode/Developer')

    def test_changed_requested_environment_rejected(self):
        a, b = self.contexts(); b['env']['DXMT_LOG_PATH'] = 'unexpected'
        with self.assertRaisesRegex(ValueError, 'effective recorder'):
            r.command_context(a, b, self.product, '/providers/cpu', '/Xcode/SDK', '/Xcode/Developer')

    def test_unknown_effective_environment_rejected(self):
        a, b = self.contexts(); b['env']['DYLD_INSERT_LIBRARIES'] = '/unexpected.dylib'
        with self.assertRaisesRegex(ValueError, 'effective recorder'):
            r.command_context(a, b, self.product, '/providers/cpu', '/Xcode/SDK', '/Xcode/Developer')

    def test_changed_command_cwd_rejected(self):
        a, b = self.contexts(); b['cwd'] = str(self.product)
        with self.assertRaisesRegex(ValueError, 'cwd'):
            r.command_context(a, b, self.product, '/providers/cpu', '/Xcode/SDK', '/Xcode/Developer')

    def test_reader_no_production_or_execution_imports(self):
        tree = ast.parse(Path(r.__file__).read_text())
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): imports += [entry.name for entry in node.names]
            elif isinstance(node, ast.ImportFrom): imports.append(node.module)
        self.assertEqual(set(imports), {'argparse', 'json', 'pathlib', 'plistlib', 're', 'shlex', 'struct', 'uuid', 'migration_run_v3'})
        self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))


if __name__ == '__main__':
    unittest.main()
