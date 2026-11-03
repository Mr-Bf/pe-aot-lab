"""Byte-authored XED checks; set PE_AOT_CFG_DECODER_RECEIPT to run native decoder.

Only the trusted decoder helper runs. Instruction bytes are never executable.
"""
import os
from pathlib import Path
import unittest

from .decoder import Decoder, classify


def decoded(**fields):
    result = dict(iclass='ADD', category='BINARY', length=3, ring0=False,
                  far_transfer=False, branch_displacement=0, branch_displacement_width=0,
                  prefixes=dict(xacquire=False, xrelease=False), memory_operands=[])
    result.update(fields)
    return result


class FlowTests(unittest.TestCase):
    def test_unknown_category_is_frontier(self):
        value = classify(decoded(category='FUTURE_VECTOR_CATEGORY'), 0x1000)
        self.assertEqual(value['flow'], 'unclassified_control')
        self.assertIsNone(value['fallthrough_va'])

    def test_unknown_conditional_form_is_frontier(self):
        value = classify(decoded(category='COND_BR', iclass='FUTURE_BRANCH', branch_displacement_width=8), 0x1000)
        self.assertEqual(value['flow'], 'unclassified_control')
        self.assertIsNone(value['target_va'])

    def test_privileged_nominal_linear_is_frontier(self):
        self.assertEqual(classify(decoded(ring0=True), 0)['flow'], 'unclassified_control')

    def test_far_transfer_is_frontier(self):
        self.assertEqual(classify(decoded(category='CALL', iclass='CALL_FAR', far_transfer=True), 0)['flow'], 'unclassified_control')

    def test_transaction_prefix_is_frontier(self):
        value = decoded(); value['prefixes']['xacquire'] = True
        self.assertEqual(classify(value, 0)['flow'], 'unclassified_control')

    def test_system_not_default_linear(self):
        for category in ('SYSTEM', 'SYSCALL', 'SYSRET', 'INTERRUPT', 'VTX', 'SGX', 'UINTR', 'FRED'):
            with self.subTest(category=category):
                self.assertEqual(classify(decoded(category=category), 0)['flow'], 'unclassified_control')

    def test_unknown_misc_not_default_linear(self):
        self.assertEqual(classify(decoded(category='MISC', iclass='UNKNOWN'), 0)['flow'], 'unclassified_control')


class ActualXEDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        receipt = os.environ.get('PE_AOT_CFG_DECODER_RECEIPT')
        if not receipt:
            raise unittest.SkipTest('PE_AOT_CFG_DECODER_RECEIPT absent: actual XED cases not run')
        cls.decoder = Decoder(Path(receipt))

    @classmethod
    def tearDownClass(cls):
        cls.decoder.close()

    def read(self, hex_bytes, va=0x1000):
        return self.decoder.decode(bytes.fromhex(hex_bytes), va)

    def test_real_startup_gs_and_address_prefix(self):
        value = self.read('6567488b00', 0x140001025)
        self.assertEqual((value['length'], value['iclass'], value['flow']), (5, 'MOV', 'normal'))
        memory = value['memory_operands'][0]
        self.assertEqual((memory['segment'], memory['base'], memory['address_width']), ('GS', 'EAX', 32))
        self.assertIsNone(memory['address_va'])
        self.assertTrue(value['prefixes']['address_size'])

    def test_real_startup_lock_prefix_is_one_instruction(self):
        value = self.read('f0480fb133', 0x140001052)
        self.assertEqual((value['length'], value['bytes_hex'], value['iclass']), (5, 'f0480fb133', 'CMPXCHG_LOCK'))
        self.assertTrue(value['prefixes']['lock'])
        self.assertEqual(value['flow'], 'normal')

    def test_direct_signed_calls(self):
        for data, target in (('e805000000', 0x100a), ('e8fbffffff', 0x1000)):
            value = self.read(data)
            self.assertEqual((value['flow'], value['target_va'], value['fallthrough_va']), ('direct_call', target, 0x1005))

    def test_short_branch_and_loop(self):
        for data in ('75fe', 'e2fe'):
            value = self.read(data)
            self.assertEqual((value['flow'], value['target_va'], value['fallthrough_va']), ('conditional_branch', 0x1000, 0x1002))

    def test_unconditional_jump(self):
        for data in ('ebfe', 'e9fbffffff'):
            value = self.read(data)
            self.assertEqual((value['flow'], value['target_va'], value['fallthrough_va']), ('direct_jump', 0x1000, None))

    def test_rip_indirect_slot_is_address_not_call_target(self):
        for data, flow in (('ff1520000000', 'indirect_call'), ('ff2520000000', 'indirect_jump')):
            value = self.read(data)
            self.assertEqual(value['flow'], flow); self.assertIsNone(value['target_va'])
            memory = value['memory_operands'][0]
            self.assertEqual((memory['base'], memory['address_va'], memory['length_bytes'], memory['address_width']), ('RIP', 0x1026, 8, 64))

    def test_register_call_keeps_unresolved_target(self):
        value = self.read('41ffd4')
        self.assertEqual(value['flow'], 'indirect_call'); self.assertIsNone(value['target_va'])
        self.assertIn('R12', [item['register'] for item in value['register_operands']])

    def test_segment_and_index_do_not_fabricate_addresses(self):
        for data in ('64ff142500100000', 'ff14c500100000'):
            self.assertIsNone(self.read(data)['memory_operands'][0]['address_va'])

    def test_eip_relative_address_truncation(self):
        value = self.read('67ff1520000000', 0x100000000)
        memory = value['memory_operands'][0]
        self.assertEqual((memory['address_width'], memory['address_va']), (32, 0x27))

    def test_near_returns(self):
        for data in ('c3', 'c21000'):
            value = self.read(data)
            self.assertEqual(value['flow'], 'return'); self.assertIsNone(value['fallthrough_va'])

    def test_explicit_stops(self):
        for data in ('0f0b', 'cc', 'f4'):
            self.assertEqual(self.read(data)['flow'], 'terminal')

    def test_system_and_transactions_are_frontiers(self):
        for data in ('0f05', '0f07', 'c7f805000000', '0f01d5', 'c6f800', 'fa', 'fb'):
            value = self.read(data)
            self.assertEqual(value['flow'], 'unclassified_control', value)
            self.assertIsNone(value['fallthrough_va']); self.assertIsNone(value['target_va'])

    def test_chip_all_exposes_feature_dependent_aliases(self):
        for data, cls in (('f30f1efa', 'ENDBR64'), ('f30fbdc0', 'LZCNT'), ('f30fbcc0', 'TZCNT'), ('f390', 'PAUSE')):
            value = self.read(data)
            self.assertEqual(value['iclass'], cls)
        self.assertEqual(self.read('f30f1efa')['flow'], 'unclassified_control')

    def test_vector_instruction_identity_not_lifter_admission(self):
        for data, cls in (('c5f858c1', 'VADDPS'), ('f30f58c1', 'ADDSS')):
            value = self.read(data)
            self.assertEqual((value['iclass'], value['length'], value['flow']), (cls, 4, 'normal'))
            self.assertTrue(value['isa_set']); self.assertTrue(value['extension'])

    def test_truncation_and_oversized_prefix_chain_invalid(self):
        for data in ('0f', 'e80000', '66' * 15):
            value = self.read(data)
            self.assertEqual(value['status'], 'invalid'); self.assertIsNone(value['fallthrough_va'])

    def test_one_instruction_only(self):
        value = self.read('90c3')
        self.assertEqual((value['length'], value['bytes_hex']), (1, '90'))

    def test_input_contract_rejects_ambiguous_ranges(self):
        for data, va in ((b'', 0), (b'\x90' * 16, 0), (bytearray(b'\x90'), 0), (b'\x90', -1), (b'\x90', 1 << 64), (b'\x90', True)):
            with self.assertRaises(ValueError):
                self.decoder.decode(data, va)

    def test_repeat_decode_is_deterministic(self):
        first = self.read('ff1520000000')
        self.assertEqual(first, self.read('ff1520000000'))


if __name__ == '__main__':
    unittest.main()
