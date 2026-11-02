"""Corrupt-input tests for the independent, non-executing reader."""
import ast
import json
import struct
import tempfile
import unittest
from pathlib import Path

from . import review


def snapshot():
    value = review.MAGIC + struct.pack('<8Q', 1, 3504, 64, 6, 1, 16, 16, 16)
    value += bytes(3504+64+16+16*3)
    for index in range(6):
        value += struct.pack('<3Q', 0x100000+index*4096, 4096, 1)+bytes(4096)+b'\x03'
    return value


class ReaderTests(unittest.TestCase):
    def test_snapshot_roundtrip(self):
        result = review.read_snapshot(snapshot())
        self.assertEqual(len(result['regions']), 6)
        self.assertEqual(len(result['state']), 3504)
        self.assertEqual(review.guest_bytes(result, 0x100000, 8), bytes(8))

    def test_truncated_snapshot(self):
        raw = snapshot()
        for cut in (0, 7, 71, 72, len(raw)-1):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                review.read_snapshot(raw[:cut])

    def test_extra_or_wrong_header(self):
        raw = snapshot()
        for bad in (raw+b'\0', b'X'+raw[1:], raw[:8]+struct.pack('<Q', 2)+raw[16:]):
            with self.assertRaises(ValueError):
                review.read_snapshot(bad)

    def test_sizes_counts_not_trusted(self):
        for off, val in ((16, 3503), (24, 65537), (32, 7), (40, 1048577), (48, 0)):
            raw = bytearray(snapshot());struct.pack_into('<Q', raw, off, val)
            with self.subTest(offset=off), self.assertRaises(ValueError):
                review.read_snapshot(raw)

    def test_region_metadata_rejected(self):
        first = 72+3504+64+16+48
        for off, val in ((first, 2**64-1), (first+8, 0), (first+16, 2)):
            raw = bytearray(snapshot());struct.pack_into('<Q', raw, off, val)
            with self.subTest(offset=off), self.assertRaises(ValueError):
                review.read_snapshot(raw)
        raw = bytearray(snapshot());struct.pack_into('<Q', raw, first+24+4096+1, 0x100000)
        with self.assertRaises(ValueError):
            review.read_snapshot(raw)

    def test_region_wx_rejected(self):
        raw = bytearray(snapshot());raw[-1] = 7
        with self.assertRaises(ValueError):
            review.read_snapshot(raw)

    def test_full_bytes_not_broadly_masked(self):
        review.same_except(b'1234', b'1x34', [(1, 1)], 'state')
        with self.assertRaises(ValueError):
            review.same_except(b'1234', b'1xx4', [(1, 1)], 'state')
        with self.assertRaises(ValueError):
            review.same_except(b'1234', b'1234', [(1, 2), (2, 1)], 'state')

    def test_json_duplicate_and_changed_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve()/'x.json'
            path.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError):
                review.Audit().json(path)
            path.write_text('{"a":1}')
            audit = review.Audit();audit.json(path)
            path.write_text('{"a":2}')
            with self.assertRaises(ValueError):
                audit.unchanged()

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve();(root/'file').write_bytes(b'hi');(root/'link').symlink_to(root/'file')
            with self.assertRaises(ValueError):
                review.Audit().data(root/'link')

    def test_duplicate_trace_json_rejected(self):
        with self.assertRaises(ValueError):
            review.decode_json('{"seq":0,"seq":1}')

    def test_exact_overlay_independently_reconstructed(self):
        from . import generate
        for strategy in ('reference','inline'):
            with tempfile.TemporaryDirectory() as temp:
                output=Path(temp).resolve()/'source'
                record=generate.prepare(output,strategy)
                review.validate_overlay(record,strategy,review.Audit())
                source=output/'window_bridge/window_runtime/runtime.c'
                source.write_bytes(source.read_bytes()+b'\n/* extra modification */\n')
                manifest=Path(record['manifest_path']);value=json.loads(manifest.read_bytes())
                value['generated']['window_bridge/window_runtime/runtime.c']=review.digest(source.read_bytes())
                manifest.write_text(json.dumps(value));record['manifest_sha256']=review.digest(manifest.read_bytes())
                with self.assertRaises(ValueError):
                    review.validate_overlay(record,strategy,review.Audit())

    def test_wrong_strategy_overlay_rejected(self):
        from . import generate
        with tempfile.TemporaryDirectory() as temp:
            record=generate.prepare(Path(temp).resolve()/'source','reference')
            with self.assertRaises(ValueError):
                review.validate_overlay(record,'inline',review.Audit())

    def test_report_cannot_pollute_frozen_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();protected=[root/name for name in ('build','run','product')]
            for path in protected:path.mkdir()
            self.assertEqual(review.validate_output(root/'report.json',protected),root/'report.json')
            for path in protected:
                with self.assertRaisesRegex(ValueError,'overlaps'):
                    review.validate_output(path/'report.json',protected)
                self.assertFalse((path/'report.json').exists())

    def test_report_parent_and_existing_file_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();(root/'real').mkdir();(root/'link').symlink_to(root/'real')
            (root/'used.json').write_text('{}')
            for path in (root/'link/report.json',root/'missing/report.json',root/'used.json'):
                with self.assertRaises(ValueError):review.validate_output(path,[])

    def test_reader_no_execution_or_producer_import(self):
        tree = ast.parse(Path(review.__file__).read_text())
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): modules.extend(n.name.split('.')[0] for n in node.names)
            if isinstance(node, ast.ImportFrom): modules.append((node.module or '').split('.')[0])
        self.assertTrue(set(modules) <= {'argparse','hashlib','json','struct','pathlib'})


if __name__ == '__main__':
    unittest.main()
