"""Static synthetic whole-window packets around frozen real scalar PE bytes.

No new XED, Windows, native/App or GPU execution is claimed by these tests.
The real leaf bytes/packet are the earlier two Clang fixtures; entry/callback,
imports and attack edges below are explicitly synthetic parser/proof inputs.
"""
import copy
import hashlib
import struct
import unittest

from switch_aot_v1 import admission as scalar
from switch_aot_v1.test_admission import fixture, headers, raw_offset
from window_switch_v1 import admission as gate

BASE = 0x140000000
MAIN = 0x1100
CALLBACK = 0x1140
LEAF = 0x1000
ROOTS = [MAIN, CALLBACK]


def row(rva, raw, kind=0, cls='NOP', target=0, form='', **fields):
    return dict(address=BASE+rva, length=len(raw), bytes=raw.hex(), kind=kind,
                iclass=cls, next_pc=BASE+rva+len(raw), target_pc=target,
                call_form=form, **fields)


def call(rva, target):
    return row(rva, b'\xe8'+struct.pack('<i', target-rva-5), 1, 'CALL_NEAR',
               BASE+target, 'DIRECT')


def ret(rva):
    return row(rva, b'\xc3', 2, 'RET_NEAR')


def put(pe, instruction):
    offset = raw_offset(pe, instruction['address']-BASE)
    raw = bytes.fromhex(instruction['bytes'])
    pe[offset:offset+len(raw)] = raw


def imported(pe):
    nt, optional, sections = headers(pe)
    if struct.unpack_from('<H', pe, nt+6)[0] != 2:
        raise ValueError('requires original two-section scalar fixture')
    raw = (len(pe)+511) & ~511
    pe.extend(bytes(raw+512-len(pe)))
    struct.pack_into('<H', pe, nt+6, 3)
    struct.pack_into('<I', pe, optional+56, 0x4000)
    struct.pack_into('<II', pe, optional+112+8, 0x3000, 40)
    struct.pack_into('<II', pe, optional+112+12*8, 0x3040, 16)
    third = sections+80
    pe[third:third+40] = struct.pack('<8sIIIIIIHHI', b'.idata\0\0', 0xc0, 0x3000,
                                  512, raw, 0, 0, 0, 0, 0xc0000040)
    struct.pack_into('<IIIII', pe, raw, 0x3030, 0, 0, 0x3060, 0x3040)
    struct.pack_into('<QQ', pe, raw+0x30, 0x3080, 0)
    struct.pack_into('<QQ', pe, raw+0x40, 0x3080, 0)
    pe[raw+0x60:raw+0x6d] = b'kernel32.dll\0'
    name = b'\0\0GetModuleHandleA\0'
    pe[raw+0x80:raw+0x80+len(name)] = name


def program(name='supported', with_import=False):
    pe, packet = fixture(name)
    _, optional, sections = headers(pe)
    struct.pack_into('<I', pe, optional+16, MAIN)
    struct.pack_into('<H', pe, optional+68, 2)  # Windows GUI subsystem.
    struct.pack_into('<I', pe, sections+8, 0x141)
    packet.update(profile=gate.PROFILE, text_size=0x141, entry_address=BASE+MAIN)
    main = [call(MAIN, LEAF), ret(MAIN+5)]
    if with_import:
        imported(pe)
        iat = row(MAIN, b'\xff\x15'+struct.pack('<i', 0x3040-MAIN-6), 1,
                  'CALL_NEAR', 0, 'IAT_MEM64', iat_slot_pc=BASE+0x3040)
        main = [iat, call(MAIN+6, LEAF), ret(MAIN+11)]
    callback = ret(CALLBACK)
    for ins in [*main, callback]:
        put(pe, ins)
    leaf_rows = copy.deepcopy(packet['instructions'])
    packet['instructions'] = [*leaf_rows, *main]
    empty = {**copy.deepcopy(packet), 'entry_address': BASE+CALLBACK,
             'instructions': [callback], 'switch_candidates': []}
    return pe, [packet, empty]


def prove(pe, packets):
    return gate.prove_program(bytes(pe), packets, LEAF, [CALLBACK])


class WindowAdmissionTests(unittest.TestCase):
    def reject(self, pe, packets, reason='.'):
        with self.assertRaisesRegex(gate.AdmissionError, reason):
            prove(pe, packets)

    def test_both_real_leaf_shapes_in_synthetic_two_root_program(self):
        for name in ('supported', 'variant'):
            with self.subTest(name=name):
                pe, packets = program(name)
                before = bytes(pe), copy.deepcopy(packets)
                result = prove(pe, packets)
                self.assertEqual(result['status'], 'PROVEN_WINDOW_SWITCH_PROGRAM_NOT_LIFTED')
                self.assertEqual(result['root_rvas'], ROOTS)
                self.assertEqual(len(result['switch']['targets']), 8)
                self.assertEqual(result['leaf_proof']['root_rva'], LEAF)
                self.assertEqual(result['root_proofs'][str(MAIN)]['status'], gate.STATUS)
                self.assertIsNone(result['root_proofs'][str(CALLBACK)]['leaf_proof'])
                self.assertEqual((bytes(pe), packets), before)

    def test_actual_import_directory_is_parsed_without_changing_pe_identity(self):
        pe, packets = program(with_import=True)
        result = prove(pe, packets)
        self.assertEqual(result['pe_sha256'], hashlib.sha256(pe).hexdigest())
        self.assertEqual(result['leaf_proof']['pe_sha256'], hashlib.sha256(pe).hexdigest())
        self.assertEqual(gate.load_image(bytes(pe)).imports[0]['name'], 'GetModuleHandleA')
        with self.assertRaises(scalar.AdmissionError):
            scalar.prove_switch(bytes(pe), packets[0], LEAF)

    def test_old_scalar_api_still_requires_pe_entry_and_rejects_window_packets(self):
        pe, packets = program()
        derived = copy.deepcopy(packets[0])
        derived['profile'] = 'clang-rel32-v1'
        derived['entry_address'] = BASE+LEAF
        derived['instructions'] = [r for r in derived['instructions'] if r['address'] < BASE+MAIN]
        with self.assertRaisesRegex(scalar.AdmissionError, 'one PE entry root'):
            scalar.prove_switch(bytes(pe), derived, LEAF)

    def test_candidate_data_and_table_targets_are_recomputed(self):
        pe, packets = program()
        packets[0]['switch_candidates'][0]['targets'][0] += 1
        self.reject(pe, packets)
        pe, packets = program()
        pe[raw_offset(pe, 0x2000)] ^= 4
        self.reject(pe, packets)

    def test_forged_direct_call_target_cannot_hide_bypass(self):
        pe, packets = program()
        call_row = next(r for r in packets[0]['instructions'] if r['address'] == BASE+MAIN)
        actual = call(MAIN, LEAF+2)
        put(pe, actual)
        call_row['bytes'] = actual['bytes']
        self.reject(pe, packets, 'original displacement')

    def test_direct_call_to_leaf_interior_is_rejected(self):
        pe, packets = program()
        legitimate, extra, end = call(CALLBACK, LEAF), call(CALLBACK+5, LEAF+2), ret(CALLBACK+10)
        for ins in (legitimate, extra, end):put(pe, ins)
        _, _, sections = headers(pe)
        struct.pack_into('<I', pe, sections+8, 0x14b)
        for packet in packets:
            packet['text_size'] = 0x14b
        packets[1]['instructions'] = [*copy.deepcopy(packets[0]['instructions'][:-2]), legitimate, extra, end]
        packets[1]['switch_candidates'] = copy.deepcopy(packets[0]['switch_candidates'])
        self.reject(pe, packets, 'external edge')

    def test_external_direct_jump_to_leaf_root_is_rejected(self):
        pe, packets = program()
        ins = row(MAIN, b'\xe9'+struct.pack('<i', LEAF-MAIN-5), 0, 'JMP', BASE+LEAF)
        put(pe, ins)
        packets[0]['instructions'][-2:] = [ins]
        self.reject(pe, packets, 'external edge')

    def test_external_branch_to_case_is_rejected_even_if_guard_is_still_reachable(self):
        pe, packets = program()
        # The call retains legitimate reachability. A second path from the
        # callback to a case block must not be accepted as a separate root.
        target = packets[0]['switch_candidates'][0]['targets'][0]
        jump = row(CALLBACK, b'\xe9'+struct.pack('<i', target-(BASE+CALLBACK+5)), 0, 'JMP', target)
        put(pe, jump)
        _, _, sections = headers(pe)
        struct.pack_into('<I', pe, sections+8, 0x145)
        for packet in packets:
            packet['text_size'] = 0x145
        # This root has no table but decodes a directly reached case+RET.
        pc = target
        by = {r['address']:r for r in packets[0]['instructions']}
        case = []
        while True:
            ins = copy.deepcopy(by[pc]);case.append(ins)
            if ins['kind'] == 2:
                break
            pc = ins['next_pc']
        packets[1]['instructions'] = [jump, *case]
        self.reject(pe, packets, 'external edge')

    def test_external_fallthrough_to_case_is_rejected_at_program_union(self):
        pe, packets = program()
        candidate = packets[0]['switch_candidates'][0]
        old_target = candidate['targets'][0]
        by = {r['address']:r for r in packets[0]['instructions']}
        # Move case zero to unused text padding, leaving a genuinely unused
        # preceding byte for the callback's fallthrough. Leaf bytes stay valid.
        old_case, pc = [], old_target
        while True:
            ins = by[pc];old_case.append(pc)
            if ins['kind'] == 2:break
            pc = ins['next_pc']
        new_case = copy.deepcopy(by[BASE+LEAF])
        new_case.update(address=BASE+0x1080, next_pc=BASE+0x1082)
        new_ret = copy.deepcopy(next(r for r in by.values() if r['kind'] == 2))
        new_ret.update(address=BASE+0x1082, next_pc=BASE+0x1083)
        for ins in (new_case,new_ret):put(pe,ins)
        packets[0]['instructions'] = [r for r in packets[0]['instructions'] if r['address'] not in old_case]+[new_case,new_ret]
        candidate['targets'][0] = BASE+0x1080
        candidate['signed_offsets'][0] = 0x1080-0x2000
        struct.pack_into('<i',pe,raw_offset(pe,0x2000),0x1080-0x2000)
        candidate['table_bytes'] = pe[raw_offset(pe,0x2000):raw_offset(pe,0x2000)+32].hex()
        callback = 0x107f
        nop = row(callback, b'\x90')
        put(pe, nop)
        packets[1].update(entry_address=BASE+callback,instructions=[nop,new_case,new_ret])
        with self.assertRaisesRegex(gate.AdmissionError,'external edge'):
            gate.prove_program(bytes(pe), packets, LEAF, [callback])

    def test_leaf_cannot_be_entry_or_callback(self):
        pe, packets = program()
        for roots in ([LEAF,CALLBACK], [MAIN,LEAF]):
            with self.subTest(roots=roots), self.assertRaises(gate.AdmissionError):
                gate.prove_window_switch(bytes(pe), packets[0], MAIN, LEAF, roots)

    def test_callback_root_cannot_be_a_leaf_case(self):
        pe, packets = program()
        target = packets[0]['switch_candidates'][0]['targets'][0]
        by = {r['address']:r for r in packets[0]['instructions']}
        case, pc = [], target
        while True:
            ins = copy.deepcopy(by[pc]);case.append(ins)
            if ins['kind'] == 2:break
            pc = ins['next_pc']
        packets[1].update(entry_address=target,instructions=case)
        with self.assertRaisesRegex(gate.AdmissionError,'program root enters'):
            gate.prove_program(bytes(pe),packets,LEAF,[target-BASE])

    def test_cross_root_decode_boundaries_cannot_overlap(self):
        pe, packets = program()
        target = packets[0]['switch_candidates'][0]['targets'][0]
        by = {r['address']:r for r in packets[0]['instructions']}
        case = by[target]
        self.assertGreater(case['length'], 1)
        # A counterfeit second packet claims one byte of an existing ADD as
        # an ordinary instruction, followed by the existing RET. Fresh XED
        # binding also constrains these claims; the global proof rejects them.
        callback = target-BASE+case['length']-1
        offset = raw_offset(pe,callback)
        partial = row(callback,bytes(pe[offset:offset+1]),cls='SYNTHETIC_ORDINARY')
        tail = copy.deepcopy(by[case['next_pc']])
        packets[1].update(entry_address=BASE+callback,instructions=[partial,tail])
        with self.assertRaisesRegex(gate.AdmissionError,'overlapping instruction boundaries across'):
            gate.prove_program(bytes(pe),packets,LEAF,[callback])

    def test_all_roots_must_be_provided_once(self):
        pe, packets = program()
        for value in ([packets[0]], [packets[0], packets[0]]):
            with self.subTest(count=len(value)):
                self.reject(pe, value, 'packet per|duplicate|root')

    def test_no_root_reaches_switch_is_rejected(self):
        pe, packets = program()
        main = ret(MAIN)
        put(pe, main)
        packets[0].update(instructions=[main], switch_candidates=[])
        self.reject(pe, packets, 'no declared root reaches')

    def test_unknown_import_and_instruction_kind_are_rejected(self):
        pe, packets = program(with_import=True)
        offset = raw_offset(pe, 0x3082)
        pe[offset:offset+16] = b'UnsupportedName\0'
        self.reject(pe, packets, 'unknown imported function')
        pe, packets = program()
        packets[1]['instructions'][0]['kind'] = True
        self.reject(pe, packets, 'instruction kind')

    def test_overlap_missing_target_and_unused_instruction_are_rejected(self):
        for change in ('overlap','missing','unused'):
            pe, packets = program()
            if change == 'overlap':
                packets[0]['instructions'].append(copy.deepcopy(packets[0]['instructions'][0]))
            elif change == 'missing':
                packets[0]['instructions'].pop()
            else:
                packets[0]['instructions'].append(ret(CALLBACK))
            with self.subTest(change=change):
                self.reject(pe, packets)

    def test_proof_mutation_cannot_be_accepted(self):
        pe, packets = program()
        proof = gate.prove_window_switch(bytes(pe), packets[0], MAIN, LEAF, ROOTS)
        proof['leaf_proof']['switch']['targets'][0] += 1
        with self.assertRaisesRegex(gate.AdmissionError, 'recomputation'):
            gate.validate_window_switch(proof, bytes(pe), packets[0], MAIN, LEAF, ROOTS)


if __name__ == '__main__':
    unittest.main()
