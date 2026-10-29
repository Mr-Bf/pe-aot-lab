"""Recompute one finite Clang rel32 switch from PE bytes.

This gate deliberately accepts a small scalar function grammar. XED's packet
is bound to the bytes, but its targets, flags, register widths and candidate
list are not authorities. A separate byte reader recomputes the entire CFG.
There are no imports, calls, stores, alternate roots or general indirect jumps.
"""
import hashlib
import json
import struct

from memory_stage2.image_loader import load_image, ImageError, READ, WRITE, EXEC


class AdmissionError(ValueError):
    pass


MASK = 0x8d5
U64 = (1 << 64) - 1
REG64 = ('RAX', 'RCX', 'RDX', 'RBX', 'RSP', 'RBP', 'RSI', 'RDI',
         'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15')
REG32 = ('EAX', 'ECX', 'EDX', 'EBX', 'ESP', 'EBP', 'ESI', 'EDI',
         'R8D', 'R9D', 'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D')
JCC = ('JO', 'JNO', 'JB', 'JNB', 'JZ', 'JNZ', 'JBE', 'JNBE',
       'JS', 'JNS', 'JP', 'JNP', 'JL', 'JNL', 'JLE', 'JNLE')
JFLAGS = (0x800, 0x800, 1, 1, 0x40, 0x40, 0x41, 0x41,
          0x80, 0x80, 4, 4, 0x880, 0x880, 0x8c0, 0x8c0)


def need(condition, message):
    if not condition:
        raise AdmissionError(message)


def integer(value, label, low=0, high=U64):
    need(type(value) is int and low <= value <= high, 'invalid ' + label)
    return value


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise AdmissionError('non-JSON packet/proof') from exc


def sha(data):
    return hashlib.sha256(data).hexdigest()


def add(base, delta):
    result = base + delta
    need(0 <= result <= U64, 'address arithmetic overflow')
    return result


def _decode(raw, pc):
    """Independent bounded decoder, not a general x86 decoder/disassembler."""
    pos = 0

    def take(size=1, signed=False):
        nonlocal pos
        need(pos + size <= len(raw), 'truncated scalar encoding')
        value = int.from_bytes(raw[pos:pos+size], 'little', signed=signed)
        pos += size
        return value

    rex = take() if raw and 0x40 <= raw[0] <= 0x4f else 0
    width = 64 if rex & 8 else 32
    regs = REG64 if width == 64 else REG32
    op = take()
    row = dict(address=pc, length=len(raw), bytes=raw.hex(), kind=0,
               reg0='INVALID', reg1='INVALID', memory_count=0,
               mem_base='INVALID', mem_index='INVALID', mem_scale=0,
               mem_displacement=0, mem_width=0, mem_read=False,
               mem_written=False, operand_width=width, flags_read=0,
               flags_written=0, flags_undefined=0, target_pc=0,
               immediate_width=0, immediate=0)

    def modrm():
        value = take()
        mod, group, rm = value >> 6, (value >> 3) & 7, value & 7
        reg = group + (8 if rex & 4 else 0)
        if mod == 3:
            return group, reg, rm + (8 if rex & 1 else 0), None
        base, index, scale, disp = rm + (8 if rex & 1 else 0), None, 1, 0
        if rm == 4:
            sib = take()
            scale = 1 << (sib >> 6)
            ix, b = (sib >> 3) & 7, sib & 7
            if ix != 4 or rex & 2:
                index = ix + (8 if rex & 2 else 0)
            base = b + (8 if rex & 1 else 0)
            need(not (mod == 0 and b == 5), 'absolute SIB addressing unsupported')
        elif mod == 0 and rm == 5:
            base = 'RIP'
            disp = take(4, True)
        if mod == 1:
            disp = take(1, True)
        elif mod == 2:
            disp = take(4, True)
        memory = dict(mem_base=base if base == 'RIP' else REG64[base],
                      mem_index='INVALID' if index is None else REG64[index],
                      mem_scale=scale, mem_displacement=disp)
        return group, reg, None, memory

    def arithmetic(cls):
        row['iclass'] = cls
        row['flags_written'] = MASK
        if cls == 'XOR':
            row['flags_written'] &= ~0x10
            row['flags_undefined'] = 0x10

    if op == 0xc3:
        need(not rex, 'prefixed RET unsupported')
        row.update(iclass='RET_NEAR', kind=2, operand_width=64)
    elif op == 0x90:
        need(not rex, 'prefixed NOP unsupported')
        row['iclass'] = 'NOP'
    elif 0x70 <= op <= 0x7f or op == 0x0f:
        need(not rex, 'prefixed branch unsupported')
        cc = op & 15
        if op == 0x0f:
            second = take()
            need(0x80 <= second <= 0x8f, 'unsupported two-byte opcode')
            cc = second & 15
        displacement = take(4 if op == 0x0f else 1, True)
        row.update(iclass=JCC[cc], target_pc=add(pc+pos, displacement),
                   flags_read=JFLAGS[cc])
    elif op in (0xeb, 0xe9):
        need(not rex, 'prefixed branch unsupported')
        displacement = take(1 if op == 0xeb else 4, True)
        row.update(iclass='JMP', target_pc=add(pc+pos, displacement))
    elif op in (0x05, 0x2d, 0x35, 0x3d):
        need(width == 32, '64-bit accumulator immediate unsupported')
        arithmetic({0x05: 'ADD', 0x2d: 'SUB', 0x35: 'XOR', 0x3d: 'CMP'}[op])
        row.update(reg0='EAX', immediate_width=32, immediate=take(4))
    elif op in (0x89, 0x8b, 0x01, 0x03, 0x29, 0x2b, 0x31, 0x33,
                0x39, 0x3b, 0x81, 0x83, 0x8d, 0x63, 0xff, 0xc1):
        group, reg, rm, memory = modrm()
        if op in (0x8d, 0x63):
            need(memory is not None, 'memory operand required')
            row.update(memory_count=1, reg0=regs[reg], **memory)
            row['iclass'] = 'LEA' if op == 0x8d else 'MOVSXD'
            if op == 0x63:
                need(width == 64, 'MOVSXD requires 64-bit destination')
                row.update(mem_width=32, mem_read=True)
        else:
            need(memory is None, 'scalar memory access outside table load unsupported')
            row['reg0'] = regs[rm]
            if op in (0x81, 0x83):
                need(group in (0, 5, 6, 7) and not rex & 4,
                     'unsupported immediate arithmetic group')
                arithmetic({0: 'ADD', 5: 'SUB', 6: 'XOR', 7: 'CMP'}[group])
                row.update(immediate_width=8 if op == 0x83 else 32,
                           immediate=take(1 if op == 0x83 else 4))
            elif op == 0xff:
                need(group in (0, 4) and not rex & 4, 'unsupported FF group')
                if group == 4:
                    row.update(iclass='JMP', kind=5, operand_width=64,
                               reg0=REG64[rm])
                else:
                    row.update(iclass='INC', flags_written=MASK & ~1)
            elif op == 0xc1:
                need(group == 0 and not rex & 4, 'only immediate ROL supported')
                count = take()
                effective = count & (63 if width == 64 else 31)
                need(not effective or effective % width, 'full-width rotate unsupported')
                row.update(iclass='ROL', immediate_width=8, immediate=count,
                           flags_written=(1 | (0x800 if effective == 1 else 0)) if effective else 0,
                           flags_undefined=0x800 if effective > 1 else 0)
            else:
                cls = {0x89:'MOV', 0x8b:'MOV', 0x01:'ADD', 0x03:'ADD',
                       0x29:'SUB', 0x2b:'SUB', 0x31:'XOR', 0x33:'XOR',
                       0x39:'CMP', 0x3b:'CMP'}[op]
                row['iclass'] = cls
                row['reg1'] = regs[reg]
                if op in (0x8b, 0x03, 0x2b, 0x33, 0x3b):
                    row['reg0'], row['reg1'] = row['reg1'], row['reg0']
                if cls != 'MOV':
                    arithmetic(cls)
    else:
        raise AdmissionError('opcode outside independent scalar grammar')
    need(pos == len(raw), 'instruction length does not match encoding')
    need(row['reg0'] not in ('RSP', 'ESP'), 'explicit stack register unsupported')
    row['next_pc'] = add(pc, pos)
    return row


def _file_range(image, address, size, permission):
    integer(address, 'range address')
    integer(size, 'range size', 1, 65536)
    end = add(address, size)
    found = [s for s in image.sections if image.base+s['rva'] <= address and
             end <= image.base+s['rva']+min(s['virtual_size'], s['raw_size'])]
    need(len(found) == 1, 'range must be within one file-backed virtual section')
    section = found[0]
    need(section['permissions'] == permission, 'section permission mismatch')
    start = image.offset(address, size, permission)
    for page in range(start//4096, (start+size-1)//4096+1):
        need(image.permissions[page] == permission, 'page permission mismatch')
    for relocation in image.relocations:
        lo = image.base + relocation['rva']
        need(max(lo, address) >= min(lo+8, end), 'DIR64 overlaps code or table input')
    return bytes(image.data[start:start+size])


def prove_switch(pe_bytes, decoded_packet, root_rva):
    need(type(pe_bytes) is bytes, 'raw immutable PE bytes required')
    need(type(decoded_packet) is dict, 'decoder packet must be an object')
    packet = json.loads(canonical(decoded_packet))
    try:
        image = load_image(pe_bytes)
        return _prove(image, pe_bytes, packet, root_rva)
    except ImageError as exc:
        raise AdmissionError('PE: ' + str(exc)) from exc


def _prove(image, pe_bytes, packet, root_rva, *, entry_required=True):
    integer(root_rva, 'root RVA', 0, len(image.data)-1)
    root = image.base + root_rva
    if entry_required:
        need(root_rva == image.entry_rva, 'one PE entry root required')
    need(type(packet.get('schema')) is int and packet['schema'] == 1 and
         packet.get('profile') == 'clang-rel32-v1' and
         packet.get('status') == 'CANDIDATE_CLOSURE_NOT_PROVEN_NOT_LIFTED',
         'unsupported decoder packet contract')
    need(type(packet.get('entry_address')) is int and packet['entry_address'] == root,
         'decoder root mismatch')
    text_va = integer(packet.get('text_address'), 'text address')
    text_size = integer(packet.get('text_size'), 'text size', 1, 32768)
    data_va = integer(packet.get('data_address'), 'data address')
    data_size = integer(packet.get('data_size'), 'data size', 1, 65536)
    text = _file_range(image, text_va, text_size, READ | EXEC)
    data = _file_range(image, data_va, data_size, READ)
    need(text_va <= root < text_va+text_size, 'root outside supplied code')
    source_rows = packet.get('instructions')
    need(type(source_rows) is list and 1 <= len(source_rows) <= 32768,
         'invalid instruction list')
    rows, owners = {}, {}
    for source in source_rows:
        need(type(source) is dict, 'invalid instruction record')
        pc = integer(source.get('address'), 'instruction address')
        length = integer(source.get('length'), 'instruction length', 1, 15)
        need(text_va <= pc and pc+length <= text_va+text_size, 'instruction outside text')
        raw = text[pc-text_va:pc-text_va+length]
        need(source.get('bytes') == raw.hex(), 'decoded bytes differ from PE')
        row = _decode(raw, pc)
        for key in ('kind', 'iclass', 'next_pc', 'target_pc'):
            need(type(source.get(key)) is type(row[key]) and source[key] == row[key],
                 'decoder/byte mismatch: ' + key)
        if row['kind'] == 5:
            need(source.get('call_form') == 'AOT_SWITCH_JUMP' and
                 source.get('reg0') == row['reg0'] and
                 type(source.get('operand_width')) is int and
                 source['operand_width'] == 64 and
                 type(source.get('memory_count')) is int and
                 source['memory_count'] == 0, 'indirect jump metadata mismatch')
        if row['iclass'] in JCC:
            need(type(source.get('fallthrough_pc')) is int and
                 source['fallthrough_pc'] == row['next_pc'], 'conditional fallthrough mismatch')
        # XED describes implicit RET stack effects differently from our reader.
        if row['iclass'] not in ('RET_NEAR', 'NOP') and not row['iclass'].startswith('J'):
            for key in ('operand_width', 'reg0', 'reg1', 'memory_count'):
                expected = row[key]
                # REG1 is XED's implicit flag operand for unary/immediate
                # arithmetic; our semantic reader has no second GPR here.
                if key == 'reg1' and expected == 'INVALID' and row['iclass'] in (
                        'CMP', 'ADD', 'SUB', 'XOR', 'INC', 'ROL'):
                    expected = 'RFLAGS'
                need(type(source.get(key)) is type(expected) and source[key] == expected,
                     'decoder/operand mismatch: ' + key)
        if row['memory_count']:
            for key in ('mem_base', 'mem_index', 'mem_displacement'):
                need(type(source.get(key)) is type(row[key]) and source[key] == row[key],
                     'decoder/addressing mismatch: ' + key)
            if row['mem_index'] != 'INVALID':
                need(type(source.get('mem_scale')) is int and
                     source['mem_scale'] == row['mem_scale'], 'decoder scale mismatch')
            if row['iclass'] == 'MOVSXD':
                for key in ('mem_width', 'mem_read', 'mem_written'):
                    need(type(source.get(key)) is type(row[key]) and source[key] == row[key],
                         'decoder/load mismatch: ' + key)
        for key in ('flags_read', 'flags_written', 'flags_undefined'):
            integer(source.get(key), key, 0, 0xffffffff)
        need(source['flags_read'] & MASK == row['flags_read'] and
             source['flags_undefined'] & MASK == row['flags_undefined'] and
             source['flags_written'] & MASK & ~source['flags_undefined'] == row['flags_written'],
             'decoder flag semantics mismatch')
        if row['immediate_width']:
            need(source.get('immediate_width') == row['immediate_width'] and
                 source.get('immediate') == row['immediate'], 'decoder immediate mismatch')
        need(pc not in rows, 'duplicate instruction')
        for byte in range(pc, pc+length):
            need(byte not in owners, 'overlapping decoded instructions')
            owners[byte] = pc
        rows[pc] = row
    need(root in rows, 'root is not a decoded instruction boundary')
    indirect = [r for r in rows.values() if r['kind'] == 5]
    need(len(indirect) == 1, 'exactly one indirect jump required')
    jump = indirect[0]
    previous = {r['next_pc']: r for r in rows.values()}
    seq = [jump]
    for _ in range(6):
        need(seq[0]['address'] in previous, 'noncontiguous dispatch sequence')
        seq.insert(0, previous[seq[0]['address']])
    cmp_, branch, zero, lea, load, plus, jump = seq
    need([r['iclass'] for r in seq] == ['CMP', 'JNBE', 'MOV', 'LEA', 'MOVSXD', 'ADD', 'JMP'],
         'unsupported dispatch grammar')
    need(cmp_['operand_width'] == 32 and cmp_['immediate_width'] in (8, 32) and
         cmp_['reg1'] == 'INVALID', 'guard requires CMP r32, immediate')
    bound = cmp_['immediate']
    bits = cmp_['immediate_width']
    if bound & (1 << (bits-1)):
        bound -= 1 << bits
    need(1 <= bound <= 31, 'switch count outside 2..32')
    count = bound + 1
    index32 = cmp_['reg0']
    need(index32 in REG32 and index32 != 'ESP', 'invalid index')
    index64 = REG64[REG32.index(index32)]
    need(zero['operand_width'] == 32 and zero['reg0'] == zero['reg1'] == index32,
         'index high 32 bits are not cleared')
    base, target = lea['reg0'], load['reg0']
    need(lea['operand_width'] == 64 and lea['mem_base'] == 'RIP' and
         lea['mem_index'] == 'INVALID' and base != index64 and base != target,
         'invalid table base setup')
    need(load['mem_base'] == base and load['mem_index'] == index64 and
         load['mem_scale'] == 4 and load['mem_displacement'] == 0 and
         plus['operand_width'] == 64 and plus['reg0'] == target and
         plus['reg1'] == base and jump['reg0'] == target, 'invalid rel32 dispatch')
    table = add(lea['next_pc'], lea['mem_displacement'])
    need(data_va <= table and table+4*count <= data_va+data_size, 'table outside data input')
    table_bytes = _file_range(image, table, 4*count, READ)
    offsets = list(struct.unpack('<' + 'i'*count, table_bytes))
    targets = [add(table, offset) for offset in offsets]
    interior = {r['address'] for r in seq[1:]}
    for target_pc in targets + [branch['target_pc']]:
        need(target_pc in rows and not cmp_['address'] <= target_pc < jump['next_pc'],
             'case/default target is not an external instruction boundary')
    need(root not in interior, 'root bypasses guard')
    for row in rows.values():
        if row['iclass'] == 'MOVSXD':
            need(row['address'] == load['address'], 'extra memory load outside dispatch')
        if row['kind'] == 2:
            successors = []
        elif row['kind'] == 5:
            successors = sorted(set(targets))
        elif row['iclass'] == 'JMP':
            successors = [row['target_pc']]
        elif row['iclass'] in JCC:
            successors = sorted(set((row['target_pc'], row['next_pc'])))
        else:
            successors = [row['next_pc']]
        need(all(pc in rows for pc in successors), 'incomplete control-flow closure')
        row['successors'] = successors
    predecessors = {pc: set() for pc in rows}
    for row in rows.values():
        for pc in row['successors']:
            predecessors[pc].add(row['address'])
    for before, after in zip(seq, seq[1:]):
        need(predecessors[after['address']] == {before['address']}, 'dispatch has a bypass edge')
    reached, pending = set(), [root]
    while pending:
        pc = pending.pop()
        if pc not in reached:
            reached.add(pc)
            pending.extend(rows[pc]['successors'])
    need(reached == set(rows), 'unreachable records in decoder closure')
    valid = {pc: MASK for pc in rows}
    changed = True
    while changed:
        changed = False
        for pc, row in rows.items():
            incoming = 0 if pc == root else MASK
            for parent in predecessors[pc]:
                prior = rows[parent]
                incoming &= (valid[parent] | prior['flags_written']) & ~prior['flags_undefined']
            if incoming != valid[pc]:
                valid[pc], changed = incoming, True
    for pc, row in rows.items():
        need(not row['flags_read'] & ~valid[pc], 'undefined flags read')
    candidate = dict(zip(('guard_pc', 'branch_pc', 'normalize_pc', 'lea_pc',
                          'load_pc', 'add_pc', 'jump_pc'), (r['address'] for r in seq)))
    candidate.update(table_pc=table, count=count, default_pc=branch['target_pc'],
                     index_reg32=index32, index_reg64=index64, base_reg64=base,
                     target_reg64=load['reg0'], table_bytes=table_bytes.hex(),
                     targets=targets, signed_offsets=offsets)
    need(canonical(packet.get('switch_candidates')) == canonical([candidate]),
         'candidate differs from recomputed proof')
    return dict(schema=1, profile='clang-rel32-v1', status='PROVEN_STATIC_NOT_LIFTED',
                pe_sha256=sha(pe_bytes), packet_sha256=sha(canonical(packet)),
                root_rva=root_rva, image_base=image.base,
                text_address=text_va, text_bytes=text.hex(), data_address=data_va,
                data_bytes=data.hex(), switch=candidate,
                instructions=[rows[pc] for pc in sorted(rows)], candidate_packet=packet)


def validate_switch(proof, pe_bytes, decoded_packet):
    need(type(proof) is dict, 'proof must be an object')
    expected = prove_switch(pe_bytes, decoded_packet, proof.get('root_rva'))
    need(canonical(proof) == canonical(expected), 'proof differs from current input recomputation')
    return expected
