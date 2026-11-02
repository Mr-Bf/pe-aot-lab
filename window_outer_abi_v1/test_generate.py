import hashlib
import json
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import generate as g


class GenerateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def test_both_strategies_are_exact_and_preserve_templates(self):
        before = {n: (g.ROOT / n).read_bytes() for n in g.PINS}
        for strategy in ('reference', 'inline'):
            with self.subTest(strategy=strategy):
                r = g.prepare(self.root / strategy, strategy)
                self.assertEqual(g.verify(r)['generated_files'], 3)
                generated, _, hook = g.expected_sources(strategy)
                self.assertEqual(generated[g.CALLBACK], before[g.CALLBACK].replace(g.CALLBACK_ANCHOR,
                    b'static uint32_t aot_outer_original_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,', 1))
                transaction = before[g.TRANSACTION]
                if strategy == 'inline':
                    transaction = transaction.replace(g.LOOKUP_ANCHOR, before[g.LOOKUP], 1)
                self.assertEqual(generated[g.TRANSACTION], transaction)
                self.assertTrue(generated[g.RUNTIME].endswith(hook))
                self.assertIn(b'aot_outer_observe_ret(state,pc,opaque,signature);return opaque;', generated[g.RUNTIME])
        self.assertEqual(before, {n: (g.ROOT / n).read_bytes() for n in g.PINS})

    def test_unknown_strategy_before_output(self):
        out = self.root / 'new'
        with self.assertRaisesRegex(ValueError, 'strategy'):
            g.prepare(out, 'selector')
        self.assertFalse(out.exists())

    def test_output_must_be_new(self):
        out = self.root / 'new'
        g.prepare(out)
        with self.assertRaisesRegex(ValueError, 'absent'):
            g.prepare(out)

    def test_anchor_count_must_be_exact(self):
        for data in (b'none', b'aot aot'):
            with self.assertRaisesRegex(ValueError, 'exactly once'):
                g.replace_once(data, b'aot', b'other')

    def copy_inputs(self):
        target = self.root / 'inputs'
        for name in [*g.PINS, g.INSTRUMENTATION]:
            p = target / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes((g.ROOT / name).read_bytes())
        return target

    def test_missing_fixed_nonpython_resource_rejected(self):
        target = self.copy_inputs()
        (target / 'window_bridge/user32_v1.inc').unlink()
        with patch.object(g, 'ROOT', target), self.assertRaisesRegex(ValueError, 'missing'):
            g.prepare(self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_changed_callback_template_rejected(self):
        target = self.copy_inputs()
        p = target / g.CALLBACK
        p.write_bytes(p.read_bytes() + b'\n')
        with patch.object(g, 'ROOT', target), self.assertRaisesRegex(ValueError, 'fixed source differs'):
            g.prepare(self.root / 'out')
        self.assertFalse((self.root / 'out').exists())

    def test_missing_instrumentation_rejected(self):
        target = self.copy_inputs()
        (target / g.INSTRUMENTATION).unlink()
        with patch.object(g, 'ROOT', target), self.assertRaisesRegex(ValueError, 'instrumentation'):
            g.prepare(self.root / 'out')

    def test_generated_tamper_not_authorized_by_changed_hash(self):
        out = self.root / 'out'
        r = g.prepare(out)
        p = out / g.RUNTIME
        p.write_bytes(p.read_bytes() + b'/* extra */\n')
        manifest = json.loads((out / 'overlay.json').read_bytes())
        manifest['generated'][g.RUNTIME] = hashlib.sha256(p.read_bytes()).hexdigest()
        (out / 'overlay.json').write_text(json.dumps(manifest))
        r['manifest_sha256'] = hashlib.sha256((out / 'overlay.json').read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, 'generated source differs'):
            g.verify(r)

    def test_extra_file_and_symlink_rejected(self):
        out = self.root / 'out'
        r = g.prepare(out)
        (out / 'extra').write_text('x')
        with self.assertRaisesRegex(ValueError, 'file set'):
            g.verify(r)
        (out / 'extra').unlink()
        (out / 'extra').symlink_to(out / 'overlay.json')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            g.verify(r)

    def test_descriptor_and_diff_rejected(self):
        out = self.root / 'out'
        r = g.prepare(out)
        changed = dict(r, compile_source='/not/the/overlay.c')
        with self.assertRaisesRegex(ValueError, 'descriptor'):
            g.verify(changed)
        (out / 'overlay.diff').write_text('')
        with self.assertRaisesRegex(ValueError, 'diff'):
            g.verify(r)

    def test_normal_callsite_binding_from_fixed_pe_bytes(self):
        # Two PE sites call the same import. The normal message loop loads
        # R12 from its IAT, while the later cleanup/drain loop uses RDI.
        # Check original PE instruction bytes independently of the overlay.
        data = (g.ROOT / 'examples/window-switch/switch_tile.exe').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),
            '39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8')
        pe = struct.unpack_from('<I', data, 0x3c)[0]
        sections = struct.unpack_from('<H', data, pe + 6)[0]
        optional_size = struct.unpack_from('<H', data, pe + 20)[0]
        def raw(rva, size):
            for i in range(sections):
                row = pe + 24 + optional_size + 40 * i
                va, count, offset = struct.unpack_from('<III', data, row + 12)
                if va <= rva and rva + size <= va + count:
                    return data[offset + rva - va:offset + rva - va + size]
            self.fail('test RVA has no raw backing')
        self.assertEqual(raw(5839, 3), bytes.fromhex('41ffd4'))  # CALL R12
        self.assertEqual(raw(6051, 2), bytes.fromhex('ffd7'))   # CALL RDI
        normal_load, drain_load = raw(5457, 7), raw(6022, 7)
        self.assertEqual(normal_load[:3], bytes.fromhex('4c8b25'))
        self.assertEqual(drain_load[:3], bytes.fromhex('488b3d'))
        self.assertEqual(5457 + 7 + struct.unpack_from('<i', normal_load, 3)[0], 10160)
        self.assertEqual(6022 + 7 + struct.unpack_from('<i', drain_load, 3)[0], 10160)
        hook = (g.ROOT / g.INSTRUMENTATION).read_bytes()
        self.assertIn(b'ctx->current->rva!=0x16cf', hook)
        self.assertIn(b'aot_register_calls[i].operand_register!=AOT_R12', hook)
        self.assertNotIn(b'ctx->current->rva!=0x17a3', hook)

    def test_cleanup_callsite_cannot_replace_generated_normal_selector(self):
        out = self.root / 'out'
        r = g.prepare(out)
        path = out / g.RUNTIME
        original = path.read_bytes()
        self.assertEqual(original.count(b'ctx->current->rva!=0x16cf'), 1)
        path.write_bytes(original.replace(b'ctx->current->rva!=0x16cf',
                                        b'ctx->current->rva!=0x17a3', 1))
        with self.assertRaisesRegex(ValueError, 'generated source differs'):
            g.verify(r)


if __name__ == '__main__':
    unittest.main()
