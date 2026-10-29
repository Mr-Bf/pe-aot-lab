"""Versioned whole-window CFG binding plus independent scalar-leaf proof.

The original PE is loaded by the existing strict Windows import loader. No PE
header is rewritten to make the scalar entry-only API accept an imported App.
Outer instruction boundaries remain observations from the freshly bound XED
packet; direct control displacements are recomputed from original bytes here.
The complete leaf is independently decoded by the frozen scalar proof grammar.
"""
import json

from switch_aot_v1 import admission as scalar
from window_inc_v1.loader import load_image

AdmissionError = scalar.AdmissionError
need = scalar.need
integer = scalar.integer
canonical = scalar.canonical
PROFILE = 'window-rel32-v1'
STATUS = 'PROVEN_WINDOW_SWITCH_STATIC_NOT_LIFTED'
CANDIDATE = 'CANDIDATE_CLOSURE_NOT_PROVEN_NOT_LIFTED'


def _roots(image, root_rvas, leaf_rva):
    need(type(root_rvas) in (list, tuple) and 1 <= len(root_rvas) <= 9,
         'one entry and at most eight callback roots required')
    roots = [integer(r, 'program root RVA', 0, len(image.data)-1) for r in root_rvas]
    need(len(roots) == len(set(roots)) and roots[0] == image.entry_rva,
         'program roots must start with the PE entry and contain no duplicates')
    leaf = integer(leaf_rva, 'leaf RVA', 0, len(image.data)-1)
    need(leaf not in roots, 'switch leaf must not be entry or callback root')
    for rva in [*roots, leaf]:
        need(image.permissions[rva//4096] == scalar.READ | scalar.EXEC,
             'program root/leaf is not on a read-execute page')
    return roots


def _flow(row, raw, image, candidates):
    """Classify existing bounded control forms from their exact encoding."""
    pc, length = row['address'], row['length']
    next_pc = scalar.add(pc, length)
    need(type(row.get('next_pc')) is int and row['next_pc'] == next_pc,
         'next PC differs from encoded length')
    kind = integer(row.get('kind'), 'instruction kind', 0, 5)
    target = integer(row.get('target_pc'), 'control target')
    pos = 0
    while pos < len(raw) and (raw[pos] in (0x66, 0xf2, 0xf3) or 0x40 <= raw[pos] <= 0x4f):
        pos += 1
    need(pos < len(raw), 'instruction contains only prefixes')
    op = raw[pos]

    def direct(size, cls, expected_kind, form):
        need(pos == 0 and length == 1 + size, 'unsupported prefixed/long control encoding')
        actual = scalar.add(next_pc, int.from_bytes(raw[1:], 'little', signed=True))
        need(kind == expected_kind and row.get('iclass') == cls and target == actual,
             'control metadata differs from original displacement')
        if form == 'call':
            need(row.get('call_form') == 'DIRECT' and not row.get('iat_slot_pc', 0),
                 'direct call has incompatible metadata')
            need(actual != next_pc, 'call-to-next is unsupported')
            return [(actual, 'call'), (next_pc, 'return-site')]
        return [(actual, 'jump')]

    if op == 0xe8:
        return direct(4, 'CALL_NEAR', 1, 'call')
    if op in (0xe9, 0xeb):
        return direct(4 if op == 0xe9 else 1, 'JMP', 0, 'jump')
    if 0x70 <= op <= 0x7f or op == 0x0f and pos+1 < length and 0x80 <= raw[pos+1] <= 0x8f:
        long = op == 0x0f
        need(pos == 0 and length == (6 if long else 2), 'unsupported conditional encoding')
        cc = raw[1] & 15 if long else op & 15
        actual = scalar.add(next_pc, int.from_bytes(raw[2:] if long else raw[1:], 'little', signed=True))
        need(kind == 0 and row.get('iclass') == scalar.JCC[cc] and target == actual and
             type(row.get('fallthrough_pc')) is int and row['fallthrough_pc'] == next_pc,
             'conditional metadata differs from original displacement')
        return [(actual, 'branch'), (next_pc, 'fallthrough')]
    if op == 0xc3:
        need(pos == 0 and length == 1 and kind == 2 and row.get('iclass') == 'RET_NEAR' and target == 0,
             'unsupported RET encoding/metadata')
        return []
    if op == 0xff:
        need(pos+1 < length, 'truncated FF instruction')
        modrm = raw[pos+1]
        group, mod = (modrm >> 3) & 7, modrm >> 6
        if group == 4:
            need(kind == 5 and row.get('iclass') == 'JMP' and
                 row.get('call_form') == 'AOT_SWITCH_JUMP' and mod == 3 and
                 length == pos+2 and target == 0,
                 'indirect jump outside finite switch contract')
            matching = [c for c in candidates if c.get('jump_pc') == pc]
            need(len(matching) == 1, 'indirect jump lacks one candidate')
            values = matching[0].get('targets')
            need(type(values) is list and 2 <= len(values) <= 32, 'invalid candidate target count')
            targets = [integer(value, 'candidate target') for value in values]
            return [(value, 'switch') for value in sorted(set(targets))]
        if group == 2:
            need(row.get('iclass') == 'CALL_NEAR' and target == 0,
                 'indirect call cannot claim a static target')
            form = row.get('call_form')
            if mod == 3:
                need(kind == 4 and form == 'IAT_REG64' and length == pos+2,
                     'register CALL differs from import-only contract')
            elif mod == 0 and modrm & 7 == 5:
                need(kind == 1 and form == 'IAT_MEM64' and length == pos+6,
                     'RIP CALL differs from IAT contract')
                slot = scalar.add(next_pc, int.from_bytes(raw[pos+2:], 'little', signed=True))
                need(type(row.get('iat_slot_pc')) is int and row['iat_slot_pc'] == slot and
                     any(image.base+i['iat_rva'] == slot for i in image.imports),
                     'IAT slot differs from original bytes/imports')
            else:
                need(kind == 3 and form == 'VTABLE_MEM64' and mod != 3,
                     'memory CALL differs from COM contract')
            return [(next_pc, 'return-site')]
        need(group in (0, 1, 6), 'unsupported FF control operation')
    need(op not in (0xc2, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xe0, 0xe1, 0xe2,
                    0xe3, 0xea, 0x9a, 0xf4) and
         not (op == 0x0f and pos+1 < length and raw[pos+1] in (0x05, 0x07, 0x34, 0x35)),
         'unsupported control opcode')
    need(kind == 0 and target == 0 and not row.get('call_form') and
         not str(row.get('iclass', '')).startswith('J') and row.get('iclass') not in ('CALL_NEAR', 'RET_NEAR'),
         'ordinary instruction has incompatible control metadata')
    return [(next_pc, 'fallthrough')]


def _packet(image, packet, root_rva):
    need(type(packet) is dict and type(packet.get('schema')) is int and packet['schema'] == 1 and
         packet.get('profile') == PROFILE and packet.get('status') == CANDIDATE,
         'unsupported window candidate packet contract')
    need(type(packet.get('entry_address')) is int and packet['entry_address'] == image.base+root_rva,
         'packet root differs')
    text_va = integer(packet.get('text_address'), 'text address')
    text_size = integer(packet.get('text_size'), 'text size', 1, 32768)
    data_va = integer(packet.get('data_address'), 'data address')
    data_size = integer(packet.get('data_size'), 'data size', 1, 65536)
    text = scalar._file_range(image, text_va, text_size, scalar.READ | scalar.EXEC)
    data = scalar._file_range(image, data_va, data_size, scalar.READ)
    candidates = packet.get('switch_candidates')
    need(type(candidates) is list and len(candidates) <= 1 and all(type(c) is dict for c in candidates),
         'at most one switch candidate per root')
    values = packet.get('instructions')
    need(type(values) is list and 1 <= len(values) <= 32768, 'bounded root instructions required')
    rows, owners, edges = {}, {}, {}
    for row in values:
        need(type(row) is dict, 'instruction must be an object')
        pc = integer(row.get('address'), 'instruction address')
        length = integer(row.get('length'), 'instruction length', 1, 15)
        need(text_va <= pc and pc+length <= text_va+text_size, 'instruction outside file-backed text')
        raw = text[pc-text_va:pc-text_va+length]
        need(row.get('bytes') == raw.hex(), 'instruction bytes differ from original PE')
        need(pc not in rows, 'duplicate instruction')
        for address in range(pc, pc+length):
            need(address not in owners, 'overlapping instruction boundaries')
            owners[address] = pc
        rows[pc] = row
        edges[pc] = _flow(row, raw, image, candidates)
    root = image.base+root_rva
    need(root in rows, 'root lacks an instruction boundary')
    need(all(target in rows for links in edges.values() for target, _ in links),
         'incomplete root CFG closure')
    reached, pending = set(), [root]
    while pending:
        pc = pending.pop()
        if pc not in reached:
            reached.add(pc)
            pending.extend(target for target, _ in edges[pc])
    need(reached == set(rows), 'unreachable instructions in root packet')
    jumps = [r for r in rows.values() if r['kind'] == 5]
    need(len(jumps) == len(candidates), 'candidate/jump count differs')
    return rows, edges, text, data


def _leaf(image, pe_bytes, packet, rows, edges, leaf_rva):
    leaf_pc = image.base+leaf_rva
    if leaf_pc not in rows:
        need(not packet['switch_candidates'], 'candidate outside declared leaf')
        return None, set()
    need(len(packet['switch_candidates']) == 1, 'declared leaf lacks its switch candidate')
    reached, pending = set(), [leaf_pc]
    while pending:
        pc = pending.pop()
        if pc not in reached:
            need(rows[pc]['kind'] not in (1, 3, 4), 'switch leaf contains a call')
            reached.add(pc)
            pending.extend(target for target, _ in edges[pc])
    derived = {**packet, 'profile': 'clang-rel32-v1', 'entry_address': leaf_pc,
               'instructions': [rows[pc] for pc in sorted(reached)]}
    proof = scalar._prove(image, pe_bytes, derived, leaf_rva, entry_required=False)
    return proof, reached


def _outside_edges(rows, edges, leaf_pcs, leaf_pc):
    for pc in rows:
        if pc in leaf_pcs:
            continue
        for target, form in edges[pc]:
            if target in leaf_pcs:
                need(form == 'call' and target == leaf_pc,
                     'external edge enters switch leaf outside a direct call to its root')


def prove_window_switch(pe_bytes, packet, root_rva, leaf_rva, full_root_rvas):
    need(type(pe_bytes) is bytes, 'raw immutable original PE bytes required')
    need(type(packet) is dict, 'candidate packet must be an object')
    packet = json.loads(canonical(packet))
    try:
        image = load_image(pe_bytes)
        roots = _roots(image, full_root_rvas, leaf_rva)
        need(type(root_rva) is int and root_rva in roots, 'root is outside declared program roots')
        rows, edges, text, data = _packet(image, packet, root_rva)
        leaf_proof, leaf_pcs = _leaf(image, pe_bytes, packet, rows, edges, leaf_rva)
        _outside_edges(rows, edges, leaf_pcs, image.base+leaf_rva)
        return dict(schema=1, profile=PROFILE, status=STATUS,
                    pe_sha256=scalar.sha(pe_bytes), packet_sha256=scalar.sha(canonical(packet)),
                    root_rva=root_rva, root_rvas=roots, leaf_rva=leaf_rva, image_base=image.base,
                    text_address=packet['text_address'], text_bytes=text.hex(),
                    data_address=packet['data_address'], data_bytes=data.hex(),
                    candidate_packet=packet, leaf_proof=leaf_proof,
                    switch=leaf_proof['switch'] if leaf_proof else None)
    except scalar.ImageError as error:
        raise AdmissionError('PE: ' + str(error)) from error


def validate_window_switch(proof, pe_bytes, packet, root_rva, leaf_rva, full_root_rvas):
    expected = prove_window_switch(pe_bytes, packet, root_rva, leaf_rva, full_root_rvas)
    need(canonical(proof) == canonical(expected), 'window proof differs from input recomputation')
    return expected


def verify_root_set(proofs, pe_bytes, full_root_rvas, leaf_rva):
    need(type(proofs) in (list, tuple) and len(proofs) == len(full_root_rvas),
         'proof count differs from declared roots')
    verified, merged, edges, owners, leaf_proof = {}, {}, {}, {}, None
    for proof in proofs:
        need(type(proof) is dict, 'invalid root proof')
        root = proof.get('root_rva')
        checked = validate_window_switch(proof, pe_bytes, proof.get('candidate_packet'), root,
                                         leaf_rva, full_root_rvas)
        need(root not in verified, 'duplicate root proof')
        verified[root] = checked
        if checked['leaf_proof'] is not None:
            if leaf_proof is not None:
                need(canonical(leaf_proof) == canonical(checked['leaf_proof']), 'conflicting shared switch leaf')
            leaf_proof = checked['leaf_proof']
        packet = checked['candidate_packet']
        image = load_image(pe_bytes)
        rows, links, _, _ = _packet(image, packet, root)
        for pc, row in rows.items():
            need(pc not in merged or merged[pc] == row, 'conflicting instruction across program roots')
            for address in range(pc, pc+row['length']):
                need(address not in owners or owners[address] == pc,
                     'overlapping instruction boundaries across program roots')
                owners[address] = pc
            merged[pc], edges[pc] = row, links[pc]
    need(set(verified) == set(full_root_rvas), 'proof root set differs')
    need(leaf_proof is not None, 'no declared root reaches the switch leaf')
    leaf_pcs = {row['address'] for row in leaf_proof['instructions']}
    need(all(leaf_proof['image_base']+root not in leaf_pcs for root in full_root_rvas),
         'program root enters switch leaf interior')
    _outside_edges(merged, edges, leaf_pcs, leaf_proof['image_base']+leaf_rva)
    return dict(schema=1, profile=PROFILE, status='PROVEN_WINDOW_SWITCH_PROGRAM_NOT_LIFTED',
                pe_sha256=scalar.sha(pe_bytes), root_rvas=list(full_root_rvas), leaf_rva=leaf_rva,
                root_proofs={str(root): verified[root] for root in full_root_rvas},
                leaf_proof=leaf_proof, switch=leaf_proof['switch'])


def prove_program(pe_bytes, packets, leaf_rva, callback_rvas):
    need(type(pe_bytes) is bytes, 'raw immutable original PE bytes required')
    try:
        image = load_image(pe_bytes)
    except scalar.ImageError as error:
        raise AdmissionError('PE: ' + str(error)) from error
    need(type(callback_rvas) is list, 'callback RVAs must be a list')
    roots = [image.entry_rva, *callback_rvas]
    need(type(packets) is list and len(packets) == len(roots), 'one packet per declared root required')
    proofs = []
    for packet in packets:
        need(type(packet) is dict and type(packet.get('entry_address')) is int, 'packet entry address required')
        proofs.append(prove_window_switch(pe_bytes, packet, packet['entry_address']-image.base, leaf_rva, roots))
    return verify_root_set(proofs, pe_bytes, roots, leaf_rva)
