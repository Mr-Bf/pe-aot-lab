"""Recursive byte discovery with explicit may-return and unresolved frontiers.

No linear sweep, guessed jump tables, indirect target guessing, return-edge
matching, branch feasibility or exception-edge reconstruction is performed.
Metadata seeds are not interchangeable with executed functions.
"""
from collections import Counter, defaultdict, deque
import hashlib
import heapq
import json

from real_pe_inventory_v1.inventory import analyze_bytes, need

FLOWS = {'normal', 'direct_call', 'indirect_call', 'conditional_branch',
         'direct_jump', 'indirect_jump', 'return', 'terminal', 'unclassified_control'}
NEXT = {'normal', 'direct_call', 'indirect_call', 'conditional_branch'}
DIRECT = {'direct_call', 'direct_jump', 'conditional_branch'}
MAX_INSTRUCTIONS = 100000
MAX_ANALYSIS_ROOTS = 64
MAX_ORIGIN_PAIRS = 500000


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CodeImage:
    def __init__(self, data, name):
        self.data = data
        self.inventory = analyze_bytes(data, name)
        need(self.inventory['status'] != 'REJECTED', 'PE headers rejected: '+str(self.inventory['findings']))
        self.base = self.inventory['headers']['image_base']
        self.sections = [dict(s, code_bytes=min(s['virtual_size'], s['raw_size']))
                         for s in self.inventory['sections'] if s['executable']]

    def code(self, rva):
        """Conservative: excludes raw alignment padding beyond VirtualSize."""
        for s in self.sections:
            if s['rva'] <= rva < s['rva']+s['code_bytes']:
                offset = s['raw_offset']+rva-s['rva']
                size = min(15, s['rva']+s['code_bytes']-rva)
                return self.data[offset:offset+size], offset
        return b'', None


def roots_and_candidates(inventory):
    roots = []
    entry = inventory['headers']['entry_rva']
    if entry:
        roots.append(dict(id='entry', rva=entry, source='OptionalHeader.AddressOfEntryPoint', role='declared_entry'))
    directory = next(d for d in inventory['directories'] if d['index'] == 9)
    for index, item in enumerate(directory.get('detail', {}).get('callbacks', [])):
        roots.append(dict(id='tls_'+str(index), rva=item.get('rva'), va=item['va'],
            source='TLS.AddressOfCallbacks['+str(index)+']', role='declared_tls_callback',
            reason_arguments='not_assumed_or_executed'))
    exception = next(d for d in inventory['directories'] if d['index'] == 3)
    candidates = [dict(item, candidate_index=i, seeded=False, source='exception_directory.RUNTIME_FUNCTION')
                  for i, item in enumerate(exception.get('detail', {}).get('runtime_functions', []))]
    return roots, candidates


def validate_decoded(row, data, va):
    need(isinstance(row, dict), 'decoder response is not an object')
    need(row.get('status') in ('decoded', 'invalid'), 'unknown decoder status')
    if row['status'] == 'invalid':
        return
    length = row.get('length'); flow = row.get('flow')
    need(type(length) is int and 1 <= length <= min(15, len(data)), 'decoder length outside bytes')
    need(row.get('bytes_hex') == data[:length].hex(), 'decoder bytes do not match original PE')
    need(flow in FLOWS, 'unclassified decoder flow value')
    need(all(isinstance(row.get(k), str) and row[k] for k in ('iclass', 'category', 'extension', 'isa_set')),
         'decoder class metadata missing')
    need(row.get('fallthrough_va') == ((va+length) & ((1 << 64)-1) if flow in NEXT else None),
         'decoder fallthrough differs from byte extent')
    target = row.get('target_va')
    need((type(target) is int and 0 <= target < 1 << 64) if flow in DIRECT else target is None,
         'decoder direct target contract differs')
    need(isinstance(row.get('memory_operands'), list), 'decoder memory operands missing')


def static_iat_references(row, imports, base):
    """This is a syntactic IAT slot reference, never proof of its runtime value."""
    if row['flow'] not in ('indirect_call', 'indirect_jump'):
        return []
    result = []
    for index, mem in enumerate(row['memory_operands']):
        address = mem.get('address_va')
        if (type(address) is not int or mem.get('length_bytes') != 8 or
            mem.get('address_width') != 64 or mem.get('segment') not in ('INVALID', 'DS', 'SS', 'ES', 'CS')):
            continue
        matches = imports.get(address-base, [])
        if matches:
            result.append(dict(memory_operand=index, iat_rva=address-base, candidates=matches,
                resolution='static_iat_slot_reference_only', runtime_target_verified=False))
    return result


def basic_blocks(nodes, edges, roots):
    by_rva = {n['rva']: n for n in nodes}
    incoming, outgoing = defaultdict(list), defaultdict(list)
    for edge in edges:
        outgoing[edge['source_rva']].append(edge)
        if edge['target_rva'] in by_rva:
            incoming[edge['target_rva']].append(edge)
    leaders = {r['rva'] for r in roots if r['rva'] in by_rva}
    for rva in by_rva:
        pred = incoming[rva]
        if len(pred) != 1 or pred[0]['kind'] != 'sequential':
            leaders.add(rva)
    assigned, result = set(), []
    # The second sorted pass also preserves a disconnected cycle if present.
    for start in sorted(leaders)+sorted(by_rva):
        if start in assigned:
            continue
        members, current = [], start
        while current in by_rva and current not in assigned:
            assigned.add(current); members.append(current)
            next_edges = outgoing[current]
            if len(next_edges) != 1 or next_edges[0]['kind'] != 'sequential':
                break
            target = next_edges[0]['target_rva']
            if target in leaders or target not in by_rva:
                break
            current = target
        last = members[-1]
        result.append(dict(start_rva=start, instruction_rvas=members,
            byte_size=sum(by_rva[r]['length'] for r in members),
            outgoing_edge_ids=[e['id'] for e in outgoing[last]]))
    return sorted(result, key=lambda b: b['start_rva'])


def discover(data, decoder, name='input.exe', max_instructions=MAX_INSTRUCTIONS):
    need(type(max_instructions) is int and 1 <= max_instructions <= MAX_INSTRUCTIONS,
         'instruction bound must be in 1..100000')
    image = CodeImage(data, name); inv = image.inventory
    roots, candidates = roots_and_candidates(inv)
    import_slots = defaultdict(list)
    for descriptor in inv['imports']:
        for symbol in descriptor.get('symbols', []):
            import_slots[symbol['iat_rva']].append(dict(dll=descriptor.get('dll'),
                name=symbol.get('name'), ordinal=symbol.get('ordinal'), kind=descriptor.get('kind'),
                descriptor_status=descriptor.get('status')))
    nodes, owners, queue, queued, visited = {}, {}, [], set(), set()
    edges, frontiers, conflicts = [], [], []

    def frontier(kind, rva=None, **detail):
        record = dict(id=len(frontiers), kind=kind, rva=rva, **detail)
        frontiers.append(record)
        return record['id']

    def schedule(rva):
        if rva not in queued:
            queued.add(rva); heapq.heappush(queue, rva)

    def edge(source, target, kind, **detail):
        edges.append(dict(id=len(edges), source_rva=source, target_rva=target, kind=kind, **detail))
        if target is not None:
            schedule(target)

    if not roots:
        frontier('no_declared_entry_or_tls_roots')
    for index, root in enumerate(roots):
        root['analysis_seeded'] = index < MAX_ANALYSIS_ROOTS and type(root['rva']) is int
        if index >= MAX_ANALYSIS_ROOTS:
            frontier('root_budget_exhausted', root['rva'], root_id=root['id'])
        elif root['analysis_seeded']:
            schedule(root['rva'])
        else:
            frontier('root_address_outside_image', root_id=root['id'], va=root.get('va'))
    tls = next(d for d in inv['directories'] if d['index'] == 9)
    if tls['parse_status'] in ('partial', 'invalid', 'unparsed'):
        frontier('tls_roots_incomplete', parse_status=tls['parse_status'])

    while queue:
        rva = heapq.heappop(queue)
        if rva in visited:
            continue
        visited.add(rva)
        if rva in owners:
            conflict = dict(target_rva=rva, owner_rva=owners[rva], reason='target_inside_decoded_instruction')
            conflicts.append(conflict); frontier('overlapping_instruction_target', rva, **conflict)
            continue
        raw, offset = image.code(rva)
        if not raw:
            frontier('outside_executable_file_backed_range', rva)
            continue
        if len(nodes) >= max_instructions:
            frontier('instruction_budget_exhausted', rva)
            continue
        va = image.base+rva
        row = decoder.decode(raw, va)
        # A broken decoder contract is an implementation error, not a PE feature.
        validate_decoded(row, raw, va)
        if row['status'] != 'decoded':
            frontier('decode_invalid', rva, bytes_available_hex=raw.hex(), decoder_error=row.get('error'))
            continue
        occupied = sorted({owners[p] for p in range(rva, rva+row['length']) if p in owners})
        if occupied:
            conflict = dict(target_rva=rva, owner_rvas=occupied, reason='decoded_range_overlaps_existing_instruction')
            conflicts.append(conflict); frontier('overlapping_instruction_extent', rva, **conflict)
            continue
        # A previously rejected/invalid root is still a known control target.
        # Backward discovery must not erase a conflict with its byte position.
        for target in range(rva+1, rva+row['length']):
            if target in visited:
                conflict = dict(target_rva=target, owner_rva=rva,
                    reason='known_unresolved_target_inside_new_instruction')
                conflicts.append(conflict)
                frontier('previous_target_inside_new_instruction', target, **conflict)
        node = dict(row, rva=rva, va=va, file_offset=offset,
            static_iat_references=static_iat_references(row, import_slots, image.base))
        nodes[rva] = node
        for p in range(rva, rva+row['length']):
            owners[p] = rva
        flow, target, continuation = row['flow'], row.get('target_va'), row.get('fallthrough_va')
        if flow in DIRECT:
            edge(rva, target-image.base, flow, target_va=target, basis='decoded_relative_control_transfer')
        if flow in NEXT:
            kind = 'may_return_continuation' if flow in ('direct_call', 'indirect_call') else (
                'conditional_not_taken' if flow == 'conditional_branch' else 'sequential')
            edge(rva, continuation-image.base, kind, target_va=continuation,
                path_feasibility='not_proved', return_proved=False if 'call' in flow else None)
        if flow in ('indirect_call', 'indirect_jump'):
            item = frontier('unresolved_'+flow, rva, static_iat_references=node['static_iat_references'])
            edge(rva, None, flow, frontier_id=item, runtime_target_verified=False)
        elif flow == 'return':
            edge(rva, None, 'return_to_runtime_stack', return_edges_reconstructed=False)
        elif flow in ('terminal', 'unclassified_control'):
            item = frontier(flow, rva, iclass=row['iclass'], reason=row.get('flow_reason'))
            edge(rva, None, flow, frontier_id=item)

    ordered = [nodes[rva] for rva in sorted(nodes)]
    for e in edges:
        e['target_status'] = 'decoded' if e['target_rva'] in nodes else (
            'not_decoded' if e['target_rva'] is not None else 'unresolved_or_terminal')
    adjacency = defaultdict(list)
    for e in edges:
        if e['target_rva'] in nodes:
            adjacency[e['source_rva']].append(e['target_rva'])
    origin = defaultdict(list)
    origin_pairs = 0
    origin_complete = True
    for root in roots:
        if not root['analysis_seeded']:
            root['origin_enumeration_complete'] = False
            origin_complete = False
            continue
        seen, pending = set(), deque([root['rva']] if root['rva'] in nodes else [])
        root['origin_enumeration_complete'] = True
        while pending:
            rva = pending.popleft()
            if rva in seen:
                continue
            if origin_pairs >= MAX_ORIGIN_PAIRS:
                root['origin_enumeration_complete'] = False
                origin_complete = False
                frontier('origin_pair_budget_exhausted', rva, root_id=root['id'])
                break
            origin_pairs += 1
            seen.add(rva); origin[rva].append(root['id']); pending.extend(adjacency[rva])
    incoming = defaultdict(list)
    for e in edges:
        if e['target_rva'] in nodes:
            incoming[e['target_rva']].append(e['id'])
    for node in ordered:
        node['syntactic_may_reach_roots'] = origin[node['rva']]
        node['root_origin_enumeration_complete'] = origin_complete
        node['incoming_edge_ids'] = incoming[node['rva']]
    blocks = basic_blocks(ordered, edges, roots)
    histogram = lambda field: dict(sorted(Counter(n[field] for n in ordered).items()))
    return dict(schema=1, tool='real-pe-cfg-v1', status='PARTIAL_STATIC_GRAPH_NOT_EXECUTED',
        input=dict(name=name, sha256=sha(data), bytes=len(data), image_base=image.base,
            entry_rva=inv['headers']['entry_rva'], metadata_status=inv['status']),
        decoder_identity=decoder.identity, roots=roots, runtime_function_candidates=candidates,
        metadata_gaps=inv['findings'], executable_ranges=image.sections,
        instructions=ordered, edges=edges, blocks=blocks, frontiers=frontiers, conflicts=conflicts,
        limits=dict(max_instructions=max_instructions, max_decode_bytes_per_request=15,
            max_analysis_roots=MAX_ANALYSIS_ROOTS, max_origin_pairs=MAX_ORIGIN_PAIRS),
        summary=dict(instructions=len(ordered), decoded_bytes=sum(n['length'] for n in ordered),
            blocks=len(blocks), edges=len(edges), frontiers=len(frontiers), conflicts=len(conflicts),
            roots=len(roots), pdata_candidates=len(candidates),
            seeded_roots=sum(r['analysis_seeded'] for r in roots), origin_pairs=origin_pairs,
            root_origin_enumeration_complete=origin_complete,
            class_histogram=histogram('iclass'), category_histogram=histogram('category'),
            extension_histogram=histogram('extension'), isa_histogram=histogram('isa_set'),
            frontier_histogram=dict(sorted(Counter(f['kind'] for f in frontiers).items()))),
        guarantees=dict(original_bytes_bound=True, linear_sweep=False, pdata_seeded=False,
            branch_feasibility_proved=False, call_returns_proved=False, indirect_targets_proved=False,
            exception_edges_enumerated=False, whole_program_cfg_complete=False,
            windows_startup_emulated=False, lifter_compatibility_checked=False, guest_executions=0, aot_builds=0),
        scope='Declared entry/TLS-root syntactic may-reach graph, including assumed call continuations. '
              'Decoder success is not instruction semantics, path execution, supported AOT or whole-program coverage.')


def markdown(report):
    def safe(s):
        return str(s).replace('|', '\\|').replace('`', "'").replace('\n', ' ')
    s = report['summary']
    lines = ['# 固定 PE 控制流与指令需求库存', '',
        f"输入 `{safe(report['input']['name'])}`，SHA-256 `{report['input']['sha256']}`。", '',
        f"{s['instructions']} 条解码指令，{s['blocks']} 个基本块，{s['frontiers']} 个未闭合/终止记录。",
        '状态 PARTIAL_STATIC_GRAPH_NOT_EXECUTED；没有执行 guest，没有生成 AOT，不计算支持百分比。', '',
        '## 显式根', '', '| 根 | RVA | 来源 |', '|---|---|---|']
    for root in report['roots']:
        lines.append(f"| {root['id']} | {root['rva']} | {safe(root['source'])} |")
    lines += ['', 'CALL 后继仅为 may-return；条件分支不做可行性证明。间接调用/jump未知，RET不重建调用栈返回边。',
        '`.pdata`只保存候选，不作为根；异常handler边未枚举。指令解码成功不代表当前lifter可执行。', '',
        '## 控制流前沿', '', '| 类型 | 数量 |', '|---|---|']
    lines += [f'| {safe(k)} | {v} |' for k, v in s['frontier_histogram'].items()]
    lines += ['', '## 指令类别需求', '', '| XED class | 数量 |', '|---|---|']
    lines += [f'| {safe(k)} | {v} |' for k, v in s['class_histogram'].items()]
    lines += ['', '完整原字节、文件偏移、边来源、未解析项与各根的语法可达标记见JSON。以上均不是运行路径或完整覆盖率。', '']
    return '\n'.join(lines)
