"""Pure source/provenance gates; no compiler, guest, GPU or App execution."""
import json
from pathlib import Path
import tempfile
import unittest

from window_switch_v1.producer import compilation_units as original_units
from window_lookup_v1 import runtime, producer


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name).resolve() / 'sources'

    def make(self):
        return runtime.prepare(self.out)

    def test_only_lookup_bytes_change(self):
        expected = runtime.expected_sources()
        original = (runtime.ROOT / runtime.TRANSACTION).read_bytes()
        replacement = (runtime.ROOT / runtime.LOOKUP).read_bytes()
        self.assertEqual(expected[runtime.RUNTIME], (runtime.ROOT / runtime.RUNTIME).read_bytes())
        self.assertEqual(expected[runtime.TRANSACTION], original.replace(runtime.ORIGINAL, replacement, 1))
        self.assertNotIn(b'bsearch(', expected[runtime.TRANSACTION])
        self.assertNotIn(b'aot_pair_lookup_mode', expected[runtime.TRANSACTION])
        self.assertEqual(replacement, (runtime.ROOT / 'window_callback_single_v1/lookup_impl.inc').read_bytes())

    def test_frozen_template_gate(self):
        with self.assertRaisesRegex(ValueError, 'template differs'):
            runtime.transform((runtime.ROOT / runtime.TRANSACTION).read_bytes() + b'\n',
                              (runtime.ROOT / runtime.LOOKUP).read_bytes())

    def test_frozen_candidate_gate(self):
        with self.assertRaisesRegex(ValueError, 'lookup differs'):
            runtime.transform((runtime.ROOT / runtime.TRANSACTION).read_bytes(), b'anything\n')

    def test_prepare_and_verify(self):
        record = self.make()
        self.assertEqual(runtime.verify(record)['generated_files'], 2)
        self.assertEqual(json.loads((self.out / 'runtime.json').read_bytes())['templates'],
                         {str(runtime.ROOT / k): v for k, v in runtime.FROZEN.items()})

    def test_existing_output_rejected(self):
        self.make()
        with self.assertRaisesRegex(ValueError, 'fresh'):
            runtime.prepare(self.out)

    def test_generated_transaction_tamper(self):
        record = self.make()
        (self.out / runtime.TRANSACTION).write_bytes((runtime.ROOT / runtime.TRANSACTION).read_bytes())
        with self.assertRaisesRegex(ValueError, 'generated runtime bytes'):
            runtime.verify(record)

    def test_runtime_must_be_byte_identical(self):
        record = self.make()
        with (self.out / runtime.RUNTIME).open('ab') as stream:
            stream.write(b'\n')
        with self.assertRaisesRegex(ValueError, 'generated runtime bytes'):
            runtime.verify(record)

    def test_manifest_tamper_even_rehashed(self):
        record = self.make()
        path = self.out / 'runtime.json'
        value = json.loads(path.read_bytes())
        value['lookup_sha256'] = '0' * 64
        path.write_text(json.dumps(value))
        record['manifest_sha256'] = runtime.lift.sha(path)
        with self.assertRaisesRegex(ValueError, 'manifest differs'):
            runtime.verify(record)

    def test_unexpected_source_member(self):
        record = self.make()
        (self.out / 'extra.c').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'file set'):
            runtime.verify(record)

    def test_symlink_member(self):
        record = self.make()
        (self.out / 'link').symlink_to(self.out / runtime.RUNTIME)
        with self.assertRaisesRegex(ValueError, 'link rejected'):
            runtime.verify(record)

    def test_descriptor_cannot_redirect_compile(self):
        record = self.make()
        record['compile_source'] = str(runtime.ROOT / runtime.RUNTIME)
        with self.assertRaisesRegex(ValueError, 'descriptor differs'):
            runtime.verify(record)

    def test_product_must_bind_own_overlay(self):
        product = Path(self.temp.name).resolve() / 'product'
        product.mkdir()
        record = runtime.prepare(product / 'native/runtime-source')
        self.assertEqual(runtime.verify_product(record, product)['generated_files'], 2)

    def test_product_rejects_same_valid_overlay_from_elsewhere(self):
        record = self.make()
        product = Path(self.temp.name).resolve() / 'product'
        product.mkdir()
        with self.assertRaisesRegex(ValueError, 'not this product overlay'):
            runtime.verify_product(record, product)

    def test_dependency_sources(self):
        record = self.make()
        text = 'probe: ' + record['compile_source'] + ' ' + record['transaction_source'] + '\n'
        # tempfile paths contain no spaces; actual compiler parsing also accepts escaped spaces.
        runtime.validate_dependencies(text, record)
        with self.assertRaisesRegex(ValueError, 'original runtime'):
            runtime.validate_dependencies(text.strip() + ' ' + str(runtime.ROOT / runtime.TRANSACTION) + '\n', record)
        with self.assertRaisesRegex(ValueError, 'absent'):
            runtime.validate_dependencies('probe: ' + record['compile_source'] + '\n', record)

    def test_compilation_units_change_only_runtime_source_and_quote_root(self):
        backend = dict(source='/explicit/backend', minimum_macos='15.2')
        tools = dict(sdk='/explicit/sdk', clang='/explicit/clang', **{'clang++': '/explicit/clang++'})
        old = original_units(self.out, backend, tools)
        new = producer.compilation_units(self.out, backend, tools)
        self.assertEqual(len(old), 6)
        self.assertEqual(len(new), 6)
        for before, after in zip(old, new):
            if before[0] != 'runtime':
                self.assertEqual(before, after)
            else:
                self.assertEqual(after[:3], ('runtime', self.out / 'runtime-source' / runtime.RUNTIME, before[2]))
                self.assertEqual(after[3], before[3] + ['-iquote', str(producer.HOST / 'window_runtime')])


if __name__ == '__main__':
    unittest.main()
