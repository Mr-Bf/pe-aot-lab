"""Meaningful admission/name/identity boundaries, without any guest execution."""
import contextlib
import copy
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from real_pe_inventory_v1.inventory import analyze_bytes, inventory_path, InventoryError
from real_pe_inventory_v1.test_inventory import fixture, directory, add_import, add_delay, OPTIONAL, PE_OFFSET
from . import report as gap
from .__main__ import main


class GapTests(unittest.TestCase):
    def test_known_label_does_not_admit_arguments_or_ordinal(self):
        b = fixture(); add_import(b)
        r = gap.compare_file(analyze_bytes(bytes(b)))
        known, ordinal = r['import_labels']
        self.assertTrue(known['label_known'])
        self.assertEqual(known['status'], 'runtime_arguments_unproven')
        self.assertFalse(known['target_arguments_verified'])
        self.assertNotIn('supported', known)
        self.assertFalse(ordinal['label_known'])
        self.assertEqual(r['unknown_name_or_ordinal_occurrences'], 1)

    def test_dll_case_insensitive_symbol_case_sensitive(self):
        b = fixture(); add_import(b, dll=b'KERNEL32.DLL')
        item = analyze_bytes(bytes(b)); self.assertEqual(gap.compare_file(item)['known_name_occurrences'], 1)
        item['imports'][0]['symbols'][0]['name'] = 'exitprocess'
        self.assertEqual(gap.compare_file(item)['known_name_occurrences'], 0)

    def test_unknown_descriptor_not_lost_or_counted_as_supported(self):
        item = analyze_bytes(bytes(fixture()))
        item['imports'] = [dict(status='unparsed', reason='unknown flags', raw_fields=[3])]
        result = gap.compare_file(item)
        self.assertEqual(result['unparsed_descriptors'], 1)
        self.assertEqual(result['known_name_occurrences'], 0)

    def test_rejected_inventory_no_code_admission(self):
        result = gap.compare_file(analyze_bytes(b'bad'))
        self.assertEqual(result['executable_shape_gate']['status'], 'not_examined')

    def test_named_unparsed_descriptors_preserved(self):
        for kind in ('bound_without_lookup', 'legacy_delay'):
            b = fixture(base=0x400000)
            if kind == 'bound_without_lookup':
                add_import(b, lookup=False, bound=True)
            else:
                add_delay(b, legacy=True)
            item = analyze_bytes(bytes(b))
            with self.subTest(kind=kind):
                self.assertEqual(item['status'], 'INCOMPLETE')
                result = gap.compare_file(item)
                self.assertEqual(result['unparsed_descriptors'], 1)
                self.assertEqual(result['import_labels'][0]['raw']['status'], 'unparsed')
                self.assertIn('dll', result['import_labels'][0]['raw'])
                self.assertEqual(result['known_name_occurrences'], 0)

    def test_code_size_limit_counts_virtual_file_backed_min(self):
        item = analyze_bytes(bytes(fixture()))
        for size, expected in [(32768, 'shape_only_within_gate'), (32769, 'blocked_by_current_gate')]:
            item['sections'][0]['virtual_size'] = size
            item['sections'][0]['raw_size'] = size+512
            result = gap.compare_file(item)['executable_shape_gate']
            self.assertEqual(result['status'], expected)
            self.assertEqual(result['roots_and_text_relocations'], 'not_examined')
        item['sections'].append(copy.deepcopy(item['sections'][0]))
        self.assertEqual(gap.compare_file(item)['executable_shape_gate']['status'], 'blocked_by_current_gate')

    def test_actual_loader_acceptance_only_maps_data(self):
        result = gap.probe(bytes(fixture()))
        self.assertEqual(result['status'], 'loader_admitted_not_decoded')
        self.assertEqual(result['guest_executions'], 0)

    def test_current_resource_and_dll_rejections(self):
        b = fixture(); directory(b, 2, 0x2000, 16)
        result = gap.probe(bytes(b))
        self.assertEqual(result['reason'], 'unsupported directory 2')
        self.assertEqual(gap.compare_file(analyze_bytes(bytes(b)))['nonempty_directories_blocked_by_current_policy'][0]['index'], 2)
        b = fixture(); struct.pack_into('<H', b, PE_OFFSET+22, 0x2022)
        self.assertEqual(gap.probe(bytes(b))['reason'], 'requires AMD64 executable profile')

    def test_bound_reviewed_sources_and_tamper(self):
        self.assertEqual(len(gap.check_sources()), len(gap.PINS))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name in gap.PINS:
                p = root/name; p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes((gap.ROOT/name).read_bytes())
            self.assertEqual(gap.check_sources(root), gap.check_sources())
            name = next(iter(gap.PINS)); (root/name).write_bytes(b'changed')
            with self.assertRaisesRegex(InventoryError, 'reviewed v7 source changed'):
                gap.check_sources(root)

    def test_real_inventory_to_report_no_profile_synthesized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); (root/'main.exe').write_bytes(fixture())
            result = gap.build_report(root, 'main.exe')
            self.assertEqual(result['status'], 'GAP_INVENTORY_ONLY')
            self.assertEqual(result['profile_gate']['status'], 'requires_explicit_profile')
            self.assertEqual(result['converted_third_party_programs'], 0)
            self.assertEqual(result['v7_import_label_count'], 21)
            self.assertEqual(gap.digest(gap.encoded(result['inventory'])), result['inventory_sha256'])
            with self.assertRaisesRegex(InventoryError, 'entry must exactly match'):
                gap.build_report(root, '../main.exe')

    def test_input_mutated_after_inventory_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); p = root/'main.exe'; p.write_bytes(fixture())
            inventory = inventory_path(root); p.write_bytes(p.read_bytes()+b'x')
            with patch.object(gap, 'inventory_path', return_value=inventory):
                with self.assertRaisesRegex(InventoryError, 'input changed'):
                    gap.build_report(root, 'main.exe')

    def test_cli_new_outputs_and_read_only_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root/'input'; source.mkdir()
            (source/'main.exe').write_bytes(fixture())
            target = root/'report.json'
            args = [str(source), '--entry', 'main.exe', '--json-out', str(target)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            self.assertEqual(json.loads(target.read_text())['guest_executions'], 0)
            with self.assertRaises(InventoryError): main(args)
            with self.assertRaises(InventoryError): main(args[:-1]+[str(source/'new.json')])


if __name__ == '__main__':
    unittest.main()
