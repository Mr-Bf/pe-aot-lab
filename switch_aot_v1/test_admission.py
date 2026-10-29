"""Independent finite-switch admission tests; never execute or decode native code.

The two positive packets are actual frozen XED observations. Negative fixtures
mutate real PE bytes and explicitly update only the corresponding packet fields;
those mutations are synthetic claims, never described as new XED observations.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import unittest

from switch_aot_v1 import admission as gate


ROOT = Path(__file__).resolve().parents[1]
BASE = 0x140000000
FIXTURES = {
    'supported': ('build/switch-supported-fixture-v1/pe-02/switch8.exe',
                  'c34e9d55cc9719fe3219a4f991ec4f53fca5583b5d026eb8cdc58aa26a12181c',
                  'a217157949100dbb756d65018df948b2eb580ca2b9873990a590a39e3b721330'),
    'variant': ('build/switch-variant-fixture-v1/pe-01/switch8_variant.exe',
                '822fbe1e6b82d4229772cd964a5ac27c9c688510206ebc3cb571bae6c2eba099',
                'a226505c8b754d5ed0673f84531745fb540e02029d0a173e3b4fd3d66d1cc244'),
}


def fixture(name='supported'):
    pe_path, pe_hash, packet_hash = FIXTURES[name]
    public_inputs = os.environ.get('PE_AOT_SWITCH_INPUTS')
    if public_inputs is None:
        pe_file = ROOT / pe_path
        packet_file = ROOT / 'build/switch-aot-v1/driver-decode-03' / (name + '.packet.json')
    else:
        input_root = Path(public_inputs).resolve(strict=True)
        pe_file = input_root / ('switch8.exe' if name == 'supported' else 'switch8_variant.exe')
        packet_file = input_root / (name + '.packet.json')
    pe = pe_file.read_bytes()
    packet = packet_file.read_bytes()
    if hashlib.sha256(pe).hexdigest() != pe_hash or hashlib.sha256(packet).hexdigest() != packet_hash:
        raise ValueError('frozen real fixture identity changed')
    return bytearray(pe), json.loads(packet)


def headers(pe):
    nt = struct.unpack_from('<I', pe, 0x3c)[0]
    optional = nt + 24
    sections = optional + struct.unpack_from('<H', pe, nt + 20)[0]
    return nt, optional, sections


def raw_offset(pe, rva):
    nt, _, sections = headers(pe)
    for i in range(struct.unpack_from('<H', pe, nt + 6)[0]):
        vsize, va, raw_size, raw = struct.unpack_from('<IIII', pe, sections + i * 40 + 8)
        if va <= rva < va + raw_size:
            return raw + rva - va
    raise ValueError('fixture RVA is not file backed')


def row_at(packet, rva):
    return next(row for row in packet['instructions'] if row['address'] == BASE + rva)


def change_instruction(pe, packet, rva, raw, **fields):
    row = row_at(packet, rva)
    if len(raw) != row['length']:
        raise ValueError('fixture mutation must preserve existing boundaries')
    offset = raw_offset(pe, rva)
    pe[offset:offset + len(raw)] = raw
    row.update(bytes=raw.hex(), **fields)


def change_target(pe, packet, index, target_rva):
    candidate = packet['switch_candidates'][0]
    delta = BASE + target_rva - candidate['table_pc']
    struct.pack_into('<i', pe, raw_offset(pe, 0x2000) + index * 4, delta)
    candidate['targets'][index] = BASE + target_rva
    candidate['signed_offsets'][index] = delta
    candidate['table_bytes'] = bytes(pe[raw_offset(pe, 0x2000):raw_offset(pe, 0x2000)+32]).hex()


def relocate_base(pe, packet, base):
    _, optional, _ = headers(pe)
    struct.pack_into('<Q', pe, optional + 24, base)
    delta = base - BASE
    for key in ('entry_address', 'text_address', 'data_address'):
        packet[key] += delta
    for row in packet['instructions']:
        for key in ('address', 'next_pc', 'target_pc', 'fallthrough_pc'):
            if row.get(key):
                row[key] += delta
    candidate = packet['switch_candidates'][0]
    for key in list(candidate):
        if key.endswith('_pc'):
            candidate[key] += delta
    candidate['targets'] = [target + delta for target in candidate['targets']]


def add_relocation(pe, target_rva):
    """Add a real PE DIR64 relocation table, using free header capacity."""
    nt, optional, sections = headers(pe)
    count = struct.unpack_from('<H', pe, nt + 6)[0]
    if count != 2 or sections + 3 * 40 > struct.unpack_from('<I', pe, optional + 60)[0]:
        raise ValueError('unexpected fixture section headers')
    raw = (len(pe) + 511) & ~511
    pe.extend(bytes(raw + 512 - len(pe)))
    struct.pack_into('<H', pe, nt + 6, 3)
    flags = struct.unpack_from('<H', pe, nt + 22)[0]
    struct.pack_into('<H', pe, nt + 22, flags & ~1)
    struct.pack_into('<I', pe, optional + 56, 0x4000)
    struct.pack_into('<II', pe, optional + 112 + 5 * 8, 0x3000, 12)
    section = sections + 80
    pe[section:section + 40] = bytes(40)
    pe[section:section + 8] = b'.reloc\0\0'
    struct.pack_into('<IIII', pe, section + 8, 12, 0x3000, 512, raw)
    struct.pack_into('<I', pe, section + 36, 0x42000040)
    struct.pack_into('<IIHH', pe, raw, target_rva & ~4095, 12,
                     0xa000 | (target_rva & 4095), 0)


class AdmissionTests(unittest.TestCase):
    def prove(self, pe, packet):
        return gate.prove_switch(bytes(pe), packet, 0x1000)

    def reject(self, pe, packet, reason=None):
        with self.assertRaisesRegex(gate.AdmissionError, reason or '.'):
            self.prove(pe, packet)

    def test_real_pe_and_xed_packets_roundtrip(self):
        for name, count, index, base, guard in (
                ('supported', 25, 'RCX', 'RDX', 0x1002),
                ('variant', 30, 'RDX', 'R8', 0x1007)):
            with self.subTest(name=name):
                pe, packet = fixture(name)
                original = copy.deepcopy(packet)
                proof = self.prove(pe, packet)
                self.assertEqual(proof['status'], 'PROVEN_STATIC_NOT_LIFTED')
                self.assertEqual(len(proof['instructions']), count)
                self.assertEqual(proof['switch']['index_reg64'], index)
                self.assertEqual(proof['switch']['base_reg64'], base)
                self.assertEqual(proof['switch']['guard_pc'], BASE + guard)
                self.assertTrue(all(value < 0 for value in proof['switch']['signed_offsets']))
                self.assertEqual(gate.validate_switch(proof, bytes(pe), packet), proof)
                self.assertEqual(packet, original)

    def test_unsigned_guard_cannot_be_signed_branch(self):
        pe, packet = fixture()
        change_instruction(pe, packet, 0x1005, bytes.fromhex('7f3b'), iclass='JNLE', flags_read=0x8c0)
        self.reject(pe, packet, 'dispatch grammar')

    def test_count_limits_and_sign_extended_immediate(self):
        for bound in (0, 32, 127, 128, 255):
            with self.subTest(bound=bound):
                pe, packet = fixture()
                change_instruction(pe, packet, 0x1002, bytes((0x83, 0xf9, bound)), immediate=bound)
                self.reject(pe, packet, 'count outside')

    def test_count_32_includes_duplicate_cases(self):
        pe, packet = fixture()
        _, _, sections = headers(pe)
        struct.pack_into('<I', pe, sections + 40 + 8, 128)
        original = bytes(pe[raw_offset(pe, 0x2000):raw_offset(pe, 0x2000) + 32])
        pe[raw_offset(pe, 0x2000):raw_offset(pe, 0x2000) + 128] = original * 4
        change_instruction(pe, packet, 0x1002, bytes.fromhex('83f91f'), immediate=31)
        packet['data_size'] = 128
        candidate = packet['switch_candidates'][0]
        candidate.update(count=32, targets=candidate['targets'] * 4,
                         signed_offsets=candidate['signed_offsets'] * 4,
                         table_bytes=(original * 4).hex())
        self.assertEqual(self.prove(pe, packet)['switch']['count'], 32)

    def test_clear_high32_must_preserve_guarded_index(self):
        pe, packet = fixture()
        change_instruction(pe, packet, 0x1007, bytes.fromhex('89d1'), reg1='EDX')
        self.reject(pe, packet, 'high 32 bits')

    def test_table_scale_signed_load_and_add_contract(self):
        for field in ('scale', 'add', 'jump', 'rex_base'):
            with self.subTest(field=field):
                pe, packet = fixture('variant' if field == 'rex_base' else 'supported')
                if field == 'scale':
                    change_instruction(pe, packet, 0x1010, bytes.fromhex('48630c4a'), mem_scale=2)
                elif field == 'add':
                    change_instruction(pe, packet, 0x1014, bytes.fromhex('4831d1'), iclass='XOR',
                                       flags_written=0x8d5, flags_undefined=0x10)
                elif field == 'jump':
                    change_instruction(pe, packet, 0x1017, bytes.fromhex('ffe2'), reg0='RDX')
                else:
                    # REX.B selects R8 in the real variant load; removing it selects RAX.
                    row = row_at(packet, 0x1015)
                    raw = bytearray.fromhex(row['bytes']); raw[0] &= ~1
                    change_instruction(pe, packet, 0x1015, bytes(raw), mem_base='RAX')
                self.reject(pe, packet, 'dispatch grammar|rel32 dispatch')

    def test_table_must_be_read_only_nonexecutable(self):
        for flags in (0xc0000040, 0x60000040):
            with self.subTest(flags=flags):
                pe, packet = fixture()
                _, _, sections = headers(pe)
                struct.pack_into('<I', pe, sections + 40 + 36, flags)
                self.reject(pe, packet, 'permission')

    def test_table_cannot_be_zero_fill_or_cross_raw_boundary(self):
        for mode in ('zero-fill', 'raw-end'):
            with self.subTest(mode=mode):
                pe, packet = fixture()
                _, _, sections = headers(pe)
                if mode == 'zero-fill':
                    struct.pack_into('<II', pe, sections + 40 + 16, 0, 0)
                else:
                    struct.pack_into('<I', pe, sections + 40 + 8, 0x220)
                    packet['data_address'] += 0x1f0
                self.reject(pe, packet, 'file-backed')

    def test_dir64_overlap_checks_full_eight_byte_interval(self):
        for rva in (0x1000, 0x1ff9, 0x2000, 0x201f):
            with self.subTest(relocation_rva=hex(rva)):
                pe, packet = fixture()
                add_relocation(pe, rva)
                self.reject(pe, packet, 'DIR64 overlaps')

    def test_disjoint_dir64_relocation_is_allowed(self):
        pe, packet = fixture()
        add_relocation(pe, 0x2020)
        self.assertEqual(self.prove(pe, packet)['status'], 'PROVEN_STATIC_NOT_LIFTED')

    def test_signed_target_must_be_external_instruction_boundary(self):
        for target in (0x101a, 0x1010, 0x2000, 0x3000):
            with self.subTest(target=hex(target)):
                pe, packet = fixture()
                change_target(pe, packet, 0, target)
                self.reject(pe, packet, 'external instruction boundary')

    def test_signed_rel32_addition_rejects_both_u64_overflows(self):
        for base, delta in ((0, -(1 << 31)), ((1 << 64) - 0x10000, (1 << 31) - 1)):
            with self.subTest(base=base, delta=delta):
                pe, packet = fixture()
                change_target(pe, packet, 0, 0x2000 + delta)
                relocate_base(pe, packet, base)
                self.reject(pe, packet, 'arithmetic overflow')

    def test_root_direct_jump_cannot_bypass_guard(self):
        pe, packet = fixture()
        change_instruction(pe, packet, 0x1000, bytes.fromhex('eb0e'), iclass='JMP',
                           operand_width=64, reg0='RIP', reg1='INVALID', target_pc=BASE+0x1010)
        self.reject(pe, packet, 'bypass edge')

    def test_default_edge_cannot_enter_dispatch(self):
        pe, packet = fixture()
        change_instruction(pe, packet, 0x1005, bytes.fromhex('7709'), target_pc=BASE+0x1010)
        packet['switch_candidates'][0]['default_pc'] = BASE+0x1010
        self.reject(pe, packet, 'external instruction boundary')

    def test_additional_indirect_jump_rejected(self):
        pe, packet = fixture()
        change_instruction(pe, packet, 0x1040, bytes.fromhex('ffe0'), kind=5, iclass='JMP',
                           operand_width=64, reg0='RAX', reg1='RIP', flags_written=0,
                           call_form='AOT_SWITCH_JUMP')
        self.reject(pe, packet, 'exactly one indirect')

    def test_unsupported_call_store_and_opcode_rejected_from_real_bytes(self):
        for raw in ('ffd0', '8901', '0f05'):
            with self.subTest(raw=raw):
                pe, packet = fixture()
                change_instruction(pe, packet, 0x1000, bytes.fromhex(raw))
                self.reject(pe, packet, 'unsupported|outside')

    def test_overlap_and_duplicate_instructions_rejected(self):
        pe, packet = fixture()
        packet['instructions'].append(copy.deepcopy(packet['instructions'][0]))
        self.reject(pe, packet, 'duplicate instruction')
        pe, packet = fixture()
        # 01 d1 is independently valid ADD ECX,EDX inside 48 01 d1.
        row = copy.deepcopy(row_at(packet, 0x1014))
        row.update(address=BASE+0x1015, length=2, bytes='01d1', operand_width=32,
                   reg0='ECX', reg1='EDX')
        packet['instructions'].append(row)
        self.reject(pe, packet, 'overlapping')

    def test_missing_boundary_rejects_incomplete_closure(self):
        pe, packet = fixture()
        packet['instructions'] = [row for row in packet['instructions'] if row['address'] != BASE+0x101c]
        self.reject(pe, packet, 'incomplete control-flow closure')

    def test_unreachable_record_rejected(self):
        pe, packet = fixture()
        _, _, sections = headers(pe)
        struct.pack_into('<I', pe, sections+8, 68)
        pe[raw_offset(pe, 0x1043)] = 0xc3
        packet['text_size'] = 68
        row = copy.deepcopy(row_at(packet, 0x1042))
        row.update(address=BASE+0x1043, next_pc=BASE+0x1044)
        packet['instructions'].append(row)
        self.reject(pe, packet, 'unreachable')

    def test_undefined_flags_not_accepted_from_forged_packet(self):
        pe, packet = fixture()
        change_instruction(pe, packet, 0x1000, bytes.fromhex('7500'), iclass='JNZ',
                           operand_width=64, reg0='RIP', reg1='RFLAGS',
                           target_pc=BASE+0x1002, fallthrough_pc=BASE+0x1002, flags_read=0x40)
        self.reject(pe, packet, 'undefined flags read')
        row_at(packet, 0x1000)['flags_read'] = 0
        self.reject(pe, packet, 'flag semantics mismatch')

    def test_packet_target_and_operand_claims_are_not_authorities(self):
        for field in ('target', 'signed_offset', 'table_bytes', 'index', 'count', 'extra_candidate',
                      'load_register', 'load_width', 'instruction_bytes', 'flags'):
            with self.subTest(field=field):
                pe, packet = fixture()
                candidate = packet['switch_candidates'][0]
                if field == 'target': candidate['targets'][0] += 1
                elif field == 'signed_offset': candidate['signed_offsets'][0] += 1
                elif field == 'table_bytes': candidate['table_bytes'] = '00' * 32
                elif field == 'index': candidate['index_reg64'] = 'RAX'
                elif field == 'count': candidate['count'] = 7
                elif field == 'extra_candidate': packet['switch_candidates'].append(copy.deepcopy(candidate))
                elif field == 'load_register': row_at(packet, 0x1010)['reg0'] = 'RAX'
                elif field == 'load_width': row_at(packet, 0x1010)['mem_width'] = 64
                elif field == 'instruction_bytes': row_at(packet, 0x1000)['bytes'] = '89c0'
                else: row_at(packet, 0x1002)['flags_written'] = 0
                self.reject(pe, packet)

    def test_proof_tampering_and_current_pe_changes_rejected(self):
        pe, packet = fixture()
        proof = self.prove(pe, packet)
        for field in ('pe_sha256', 'packet_sha256', 'root_rva', 'text_bytes', 'instructions', 'switch'):
            with self.subTest(field=field):
                changed = copy.deepcopy(proof)
                if field == 'switch': changed[field]['targets'][0] += 1
                elif field == 'instructions': changed[field][0]['successors'] = []
                elif field == 'root_rva': changed[field] += 1
                else: changed[field] = '0' * 64
                with self.assertRaises(gate.AdmissionError):
                    gate.validate_switch(changed, bytes(pe), packet)
        pe[-1] ^= 1  # Even unused file padding is bound to the proof identity.
        with self.assertRaisesRegex(gate.AdmissionError, 'proof differs'):
            gate.validate_switch(proof, bytes(pe), packet)

    def test_api_rejects_nonimmutable_pe_and_noninteger_root(self):
        pe, packet = fixture()
        for value in (pe, memoryview(pe), None, 'MZ'):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(gate.AdmissionError):
                    gate.prove_switch(value, packet, 0x1000)
        for root in (True, 4096.0, None, -1, 0x1007):
            with self.subTest(root=root):
                with self.assertRaises(gate.AdmissionError):
                    gate.prove_switch(bytes(pe), packet, root)


if __name__ == '__main__':
    unittest.main()
