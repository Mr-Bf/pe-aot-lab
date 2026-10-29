"""Boundary checks for inventory/admission; no decoder or guest execution."""
import json
from pathlib import Path
import struct
import unittest

from migration_v1.analyze import analyze, inventory

ROOT = Path(__file__).resolve().parents[1]


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT / 'build/process-bridge/fixtures/normal.exe').read_bytes()
        cls.pe = struct.unpack_from('<I', cls.data, 0x3c)[0]
        cls.opt = cls.pe + 24
        cls.table = cls.opt + 240

    def changed(self, fmt, offset, *values):
        data = bytearray(self.data)
        struct.pack_into(fmt, data, offset, *values)
        return bytes(data)

    def reject(self, data, code):
        report = analyze(data)
        self.assertEqual(report['status'], 'UNSUPPORTED')
        self.assertIn(code, [item['code'] for item in report['issues']])
        self.assertEqual(report['guest_executions'], 0)
        return report

    def test_eligible_is_not_instruction_acceptance(self):
        report = analyze(self.data)
        self.assertEqual(report['status'], 'ELIGIBLE_FOR_BUILD_NOT_DECODED')
        self.assertEqual(report['instruction_analysis'], 'NOT_RUN')
        self.assertEqual(len(report['inventory']['imports']), 6)

    def test_truncations(self):
        for size in (0, 2, 63, self.pe + 4, self.opt + 1, self.table + 39, len(self.data) - 1):
            with self.subTest(size=size):
                self.reject(self.data[:size], 'INVENTORY_UNAVAILABLE')

    def test_machine(self):
        self.reject(self.changed('<H', self.pe + 4, 0xaa64), 'ARCH_UNSUPPORTED')

    def test_dll(self):
        value = struct.unpack_from('<H', self.data, self.pe + 22)[0]
        self.reject(self.changed('<H', self.pe + 22, value | 0x2000), 'DLL_UNSUPPORTED')

    def test_gui_not_routed_to_cli(self):
        self.reject(self.changed('<H', self.opt + 68, 2), 'SUBSYSTEM_UNSUPPORTED')

    def test_tls_exception_delay_clr(self):
        for index in (3, 9, 13, 14):
            with self.subTest(index=index):
                result = self.reject(self.changed('<II', self.opt + 112 + index * 8, 8192, 24), 'DIRECTORY_UNSUPPORTED')
                self.assertTrue(any(x.get('directory') == index for x in result['issues']))

    def test_directory_count(self):
        self.reject(self.changed('<I', self.opt + 108, 0xffffffff), 'INVENTORY_UNAVAILABLE')

    def test_partial_directory(self):
        self.reject(self.changed('<II', self.opt + 112 + 72, 8192, 0), 'INVENTORY_UNAVAILABLE')

    def test_image_limit(self):
        self.reject(self.changed('<I', self.opt + 56, 0x80000000), 'LOADER_REJECT')

    def test_writable_executable(self):
        self.reject(self.changed('<I', self.table + 36, 0xe0000020), 'LOADER_REJECT')

    def test_raw_overlap(self):
        first = struct.unpack_from('<I', self.data, self.table + 20)[0]
        self.reject(self.changed('<I', self.table + 40 + 20, first), 'INVENTORY_UNAVAILABLE')

    def test_virtual_overlap(self):
        self.reject(self.changed('<I', self.table + 40 + 12, 4096), 'INVENTORY_UNAVAILABLE')

    def test_unknown_import_name(self):
        changed = self.data.replace(b'ExitProcess\0', b'ExitProcesX\0')
        self.assertNotEqual(changed, self.data)
        report = self.reject(changed, 'IMPORT_UNSUPPORTED')
        self.assertTrue(any(x.get('name') == 'ExitProcesX' for x in report['issues']))

    def test_ordinal(self):
        info = inventory(self.data)
        imp = next(d for d in info['directories'] if d['index'] == 1)
        def file_offset(rva):
            s = next(s for s in info['sections'] if s['rva'] <= rva < s['rva'] + s['raw_size'])
            return s['raw_offset'] + rva - s['rva']
        ilt, _, _, _, iat = struct.unpack_from('<IIIII', self.data, file_offset(imp['address']))
        data = bytearray(self.data)
        for rva in (ilt, iat):
            struct.pack_into('<Q', data, file_offset(rva), (1 << 63) | 123)
        report = self.reject(bytes(data), 'IMPORT_UNSUPPORTED')
        self.assertTrue(any(x.get('ordinal') == 123 for x in report['issues']))


if __name__ == '__main__':
    unittest.main()
