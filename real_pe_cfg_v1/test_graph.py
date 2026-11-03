"""Graph algorithm invariants with an explicit fake decoder, never PE execution.

These tests do not validate XED decoding. test_decoder and the recorded native
decoder/objdump cross-checks exercise the actual instruction boundaries.
"""
import copy
import struct
import unittest
from unittest.mock import patch

from real_pe_inventory_v1.inventory import InventoryError
from real_pe_inventory_v1.test_inventory import fixture, directory, put, add_import, OPTIONAL
from .graph import discover, validate_decoded, static_iat_references

BASE = 0x140000000


class FakeDecoder:
    identity = {'kind': 'unit_test_fake_not_instruction_oracle'}

    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def decode(self, data, va):
        rva = va-BASE
        self.calls.append(rva)
        if rva not in self.rows:
            return dict(status='invalid', error='not in explicit fake decoder')
        flow, length, target, *extras = self.rows[rva]
        return dict(status='decoded', length=length, bytes_hex=data[:length].hex(),
            iclass='MOCK', category='MOCK', extension='MOCK', isa_set='MOCK', flow=flow,
            target_va=BASE+target if target is not None else None,
            fallthrough_va=va+length if flow in ('normal', 'direct_call', 'indirect_call', 'conditional_branch') else None,
            memory_operands=extras[0] if extras else [], prefixes={}, register_operands=[])


def tls(b, callbacks):
    directory(b, 9, 0x2280, 40)
    put(b, 0x2280, struct.pack('<4Q2I', 0, 0, BASE+0x2900, BASE+0x2320, 0, 0))
    put(b, 0x2320, struct.pack('<'+'Q'*(len(callbacks)+1), *[BASE+r for r in callbacks], 0))


class GraphTests(unittest.TestCase):
    def test_call_return_is_not_ordinary_fallthrough_or_return_edge(self):
        decoder = FakeDecoder({0x1000: ('direct_call', 5, 0x1010), 0x1005: ('return', 1, None),
                               0x1010: ('return', 1, None)})
        r = discover(bytes(fixture()), decoder)
        self.assertEqual(r['summary']['instructions'], 3)
        continuation = next(e for e in r['edges'] if e['kind'] == 'may_return_continuation')
        self.assertFalse(continuation['return_proved'])
        self.assertFalse(r['guarantees']['call_returns_proved'])
        self.assertTrue(all(e['target_rva'] is None for e in r['edges'] if e['kind']=='return_to_runtime_stack'))

    def test_conditional_paths_and_cycle_terminate(self):
        d = FakeDecoder({0x1000: ('conditional_branch', 2, 0x1010), 0x1002: ('direct_jump', 2, 0x1000),
                         0x1010: ('return', 1, None)})
        r = discover(bytes(fixture()), d)
        self.assertEqual(sorted(d.calls), [0x1000, 0x1002, 0x1010])
        self.assertFalse(r['guarantees']['branch_feasibility_proved'])
        self.assertEqual(len(r['blocks']), 3)

    def test_indirect_call_keeps_unknown_edge_and_may_return(self):
        d = FakeDecoder({0x1000: ('indirect_call', 2, None), 0x1002: ('return', 1, None)})
        r = discover(bytes(fixture()), d)
        self.assertEqual({e['kind'] for e in r['edges']},
                         {'indirect_call', 'may_return_continuation', 'return_to_runtime_stack'})
        self.assertEqual(r['summary']['frontier_histogram'], {'unresolved_indirect_call': 1})

    def test_indirect_jump_never_invents_fallthrough(self):
        d = FakeDecoder({0x1000: ('indirect_jump', 2, None), 0x1002: ('return', 1, None)})
        r = discover(bytes(fixture()), d)
        self.assertEqual(d.calls, [0x1000])
        self.assertEqual(r['frontiers'][0]['kind'], 'unresolved_indirect_jump')

    def test_tls_order_origins_and_duplicate_rva(self):
        b = fixture(); tls(b, [0x1010, 0x1000])
        d = FakeDecoder({0x1000: ('direct_jump', 2, 0x1010), 0x1010: ('return', 1, None)})
        r = discover(bytes(b), d)
        self.assertEqual([r['rva'] for r in r['roots']], [0x1000, 0x1010, 0x1000])
        self.assertEqual(r['instructions'][1]['syntactic_may_reach_roots'], ['entry', 'tls_0', 'tls_1'])
        self.assertEqual(len(d.calls), 2)

    def test_pdata_not_seeded_and_exceptions_unproved(self):
        b = fixture(); directory(b, 3, 0x2240, 12)
        put(b, 0x2240, struct.pack('<III', 0x1010, 0x1011, 0x2260)); put(b, 0x2260, b'\x01\0\0\0')
        d = FakeDecoder({0x1000: ('return', 1, None), 0x1010: ('return', 1, None)})
        r = discover(bytes(b), d)
        self.assertEqual(d.calls, [0x1000])
        self.assertEqual(len(r['runtime_function_candidates']), 1)
        self.assertFalse(r['runtime_function_candidates'][0]['seeded'])
        self.assertFalse(r['guarantees']['exception_edges_enumerated'])

    def test_branch_into_instruction_detected(self):
        d = FakeDecoder({0x1000: ('conditional_branch', 5, 0x1002), 0x1005: ('return', 1, None)})
        r = discover(bytes(fixture()), d)
        self.assertEqual(r['summary']['conflicts'], 1)
        self.assertNotIn(0x1002, d.calls)
        self.assertEqual(r['frontiers'][0]['kind'], 'overlapping_instruction_target')

    def test_backward_discovery_overlap_detected(self):
        b = fixture(); struct.pack_into('<I', b, OPTIONAL+16, 0x1010)
        d = FakeDecoder({0x1010: ('direct_jump', 2, 0x100f), 0x100f: ('normal', 4, None)})
        r = discover(bytes(b), d)
        self.assertEqual(r['summary']['conflicts'], 1)
        self.assertEqual([n['rva'] for n in r['instructions']], [0x1010])

    def test_decode_budget_retains_scheduled_frontier(self):
        d = FakeDecoder({0x1000: ('direct_call', 5, 0x1010), 0x1005: ('return', 1, None), 0x1010: ('return', 1, None)})
        r = discover(bytes(fixture()), d, max_instructions=1)
        self.assertEqual(d.calls, [0x1000])
        self.assertEqual(r['summary']['frontier_histogram'], {'instruction_budget_exhausted': 2})
        self.assertTrue(all(e['target_status']=='not_decoded' for e in r['edges']))
        for bad in (0, True, 100001):
            with self.subTest(bad=bad), self.assertRaises(InventoryError):
                discover(bytes(fixture()), d, max_instructions=bad)

    def test_failed_earlier_target_inside_later_instruction_conflicts(self):
        b = fixture(); struct.pack_into('<I', b, OPTIONAL+16, 0x1001); tls(b, [0x1010])
        d = FakeDecoder({0x1010: ('direct_jump', 2, 0x1000), 0x1000: ('normal', 5, None),
                         0x1005: ('return', 1, None)})
        r = discover(bytes(b), d)
        self.assertIn('decode_invalid', r['summary']['frontier_histogram'])
        self.assertEqual(r['summary']['conflicts'], 1)
        self.assertEqual(r['conflicts'][0]['target_rva'], 0x1001)
        self.assertEqual(r['conflicts'][0]['owner_rva'], 0x1000)

    def test_root_limit_preserves_unseeded_declarations(self):
        b = fixture(); tls(b, [0x1010, 0x1020])
        d = FakeDecoder({0x1000: ('return', 1, None), 0x1010: ('return', 1, None), 0x1020: ('return', 1, None)})
        with patch('real_pe_cfg_v1.graph.MAX_ANALYSIS_ROOTS', 2):
            r = discover(bytes(b), d)
        self.assertEqual(len(r['roots']), 3)
        self.assertEqual([r['analysis_seeded'] for r in r['roots']], [True, True, False])
        self.assertEqual(d.calls, [0x1000, 0x1010])
        self.assertEqual(r['summary']['frontier_histogram']['root_budget_exhausted'], 1)
        self.assertFalse(r['summary']['root_origin_enumeration_complete'])

    def test_origin_limit_marks_partial_and_does_not_hide_nodes(self):
        b = fixture(); tls(b, [0x1010])
        d = FakeDecoder({0x1000: ('direct_jump', 2, 0x1010), 0x1010: ('return', 1, None)})
        with patch('real_pe_cfg_v1.graph.MAX_ORIGIN_PAIRS', 1):
            r = discover(bytes(b), d)
        self.assertEqual(r['summary']['instructions'], 2)
        self.assertEqual(r['summary']['origin_pairs'], 1)
        self.assertFalse(r['summary']['root_origin_enumeration_complete'])
        self.assertEqual(r['summary']['frontier_histogram']['origin_pair_budget_exhausted'], 2)
        self.assertTrue(all(not n['root_origin_enumeration_complete'] for n in r['instructions']))

    def test_outside_virtual_or_file_code_remains_frontier(self):
        b = fixture(); struct.pack_into('<I', b, OPTIONAL+240+8, 0x10)
        d = FakeDecoder({0x1000: ('direct_jump', 2, 0x1010)})
        r = discover(bytes(b), d)
        self.assertEqual(r['frontiers'][0]['kind'], 'outside_executable_file_backed_range')
        self.assertEqual(d.calls, [0x1000])

    def test_invalid_decode_and_control_frontiers_stop(self):
        for flow in (None, 'terminal', 'unclassified_control'):
            d = FakeDecoder({} if flow is None else {0x1000: (flow, 2, None)})
            with self.subTest(flow=flow):
                r = discover(bytes(fixture()), d)
                self.assertEqual(d.calls, [0x1000])
                self.assertEqual(r['frontiers'][0]['kind'], flow or 'decode_invalid')

    def test_decoder_contract_failure_is_not_silently_pe_failure(self):
        data = b'\x90\x90\xc3'; row = FakeDecoder({0: ('normal', 1, None)}).decode(data, BASE)
        for key, bad in [('length', 16), ('bytes_hex', 'cc'), ('flow', 'guessed'), ('fallthrough_va', BASE+2), ('target_va', BASE+7)]:
            changed = copy.deepcopy(row); changed[key] = bad
            with self.subTest(key=key), self.assertRaises(InventoryError):
                validate_decoded(changed, data, BASE)

    def test_iat_metadata_reference_is_not_runtime_target(self):
        b = fixture(); add_import(b)
        mem = dict(address_va=BASE+0x20a0, length_bytes=8, address_width=64, segment='DS')
        d = FakeDecoder({0x1000: ('indirect_call', 6, None, [mem]), 0x1006: ('return', 1, None)})
        r = discover(bytes(b), d); ref = r['instructions'][0]['static_iat_references'][0]
        self.assertEqual(ref['candidates'][0]['name'], 'ExitProcess')
        self.assertFalse(ref['runtime_target_verified'])
        self.assertEqual(r['frontiers'][0]['kind'], 'unresolved_indirect_call')
        # ExitProcess name alone must not suppress the may-return continuation.
        self.assertIn(0x1006, d.calls)

    def test_iat_segment_width_and_unknown_contract_never_bound(self):
        row = dict(flow='indirect_call', memory_operands=[dict(address_va=BASE+0x20a0, length_bytes=8, address_width=64, segment='DS')])
        for key, bad in [('segment','FS'), ('segment','GS'), ('segment','unknown'), ('length_bytes',4), ('address_width',32)]:
            changed = copy.deepcopy(row); changed['memory_operands'][0][key]=bad
            with self.subTest(key=key,bad=bad):
                self.assertEqual(static_iat_references(changed, {0x20a0:[dict(name='x')]}, BASE), [])

    def test_basic_blocks_split_at_late_target(self):
        d = FakeDecoder({0x1000: ('normal', 1, None), 0x1001: ('normal', 1, None),
                         0x1002: ('conditional_branch', 2, 0x1001), 0x1004: ('return', 1, None)})
        r = discover(bytes(fixture()), d)
        self.assertEqual([b['instruction_rvas'] for b in r['blocks']], [[0x1000], [0x1001,0x1002], [0x1004]])


if __name__ == '__main__':
    unittest.main()
