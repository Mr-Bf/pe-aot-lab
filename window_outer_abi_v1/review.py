"""Independent file-only reader for untimed, single-pass outer ABI traces.

No producer imports, native commands, UI calls, reset or performance inference.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PE_SHA = '39cfa624486b49daebc6ee9c78750ed3b0ba882c443ffe16f26115668c6621d8'
MAGIC = b'AOTABI1\0'
STATUS = 'PASS_UNTIMED_SINGLE_PASS_OUTER_ABI_INDEPENDENTLY_REVIEWED'


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode_json(data):
    def pairs(items):
        result={}
        for key,value in items:
            need(key not in result, 'duplicate JSON key')
            result[key]=value
        return result
    return json.loads(data,object_pairs_hook=pairs)


class Audit:
    def __init__(self):
        self.files = {}

    def data(self, path, expected=None):
        path = Path(path).absolute()
        need(not any(p.is_symlink() for p in [path, *path.parents]), 'symlink input rejected')
        need(path.is_file(), 'regular input required: ' + str(path))
        data = path.read_bytes()
        value = dict(sha256=digest(data), bytes=len(data))
        need(expected is None or value['sha256'] == expected, 'input digest differs: ' + str(path))
        need(str(path) not in self.files or self.files[str(path)] == value, 'input changed during read')
        self.files[str(path)] = value
        return data

    def json(self, path, expected=None):
        return decode_json(self.data(path,expected))

    def unchanged(self):
        for name, value in self.files.items():
            self.data(name, value['sha256'])


def u64(data, offset):
    need(type(offset) is int and 0 <= offset <= len(data)-8, 'u64 offset out of range')
    return struct.unpack_from('<Q', data, offset)[0]


def u32(data, offset):
    need(type(offset) is int and 0 <= offset <= len(data)-4, 'u32 offset out of range')
    return struct.unpack_from('<I', data, offset)[0]


def read_snapshot(data):
    """Decode exact byte lengths; reject trailing, truncated and oversized data."""
    need(data[:8] == MAGIC and len(data) >= 72, 'snapshot magic/header differs')
    version, ns, nc, nr, ni, nd, nu, nw = struct.unpack_from('<8Q', data, 8)
    need(version == 1 and ns == 3504 and 1 <= nc <= 65536, 'snapshot version/layout differs')
    need(nr == 6 and 1 <= ni <= 1048576, 'snapshot regions/instruction count differs')
    need(all(1 <= x <= 65536 for x in (nd, nu, nw)), 'session size invalid')
    pos = 72
    def take(size):
        nonlocal pos
        need(0 <= size <= len(data)-pos, 'snapshot truncated')
        value = data[pos:pos+size]
        pos += size
        return value
    result = dict(state=take(ns), context=take(nc), instructions=take(ni*16),
                  d3d=take(nd), user32=take(nu), callbacks=take(nw), regions=[])
    for _ in range(nr):
        base, size, pages = struct.unpack('<3Q', take(24))
        need(0 < size <= 16*1024*1024 and pages == (size+4095)//4096,
             'region size/page count invalid')
        need(base+size <= 2**64, 'region address overflow')
        need(all(base+size <= r['base'] or r['base']+len(r['bytes']) <= base
                 for r in result['regions']), 'overlapping guest regions')
        raw, permissions = take(size), take(pages)
        need(all(x <= 7 and x & 6 != 6 for x in permissions), 'region permission invalid')
        result['regions'].append(dict(base=base, bytes=raw, permissions=permissions))
    need(pos == len(data), 'snapshot trailing data')
    return result


def same_except(before, after, spans, label):
    need(len(before) == len(after), label + ' length differs')
    covered = set()
    for offset, size in spans:
        need(0 <= offset <= len(before)-size and size > 0, label + ' invalid exception span')
        need(not covered.intersection(range(offset, offset+size)), label + ' overlapping exception spans')
        covered.update(range(offset, offset+size))
    need(all(a == b or i in covered for i, (a, b) in enumerate(zip(before, after))),
         label + ' unexpected byte change')


def guest_bytes(snapshot, address, size):
    for region in snapshot['regions']:
        if region['base'] <= address and address+size <= region['base']+len(region['bytes']):
            off = address-region['base']
            return region['bytes'][off:off+size]
    raise ValueError('guest observation outside a region')


CORE_OFFSETS = {
    'ctx.module_base':0, 'ctx.budget':8, 'ctx.instructions':32,
    'ctx.instruction_count':40, 'ctx.region_count':48, 'ctx.regions':56,
    'ctx.result':696, 'ctx.result.fault.status':696, 'ctx.result.steps':728,
    'ctx.result.call_depth':736, 'ctx.result.returned':740, 'ctx.current_pc':744,
    'ctx.current':752, 'ctx.in_instruction':760, 'ctx.pending_size':764,
    'ctx.pending':768, 'ctx.pending_value':896, 'ctx.frames':904,
    'ctx.snapshot':1936, 'ctx.d3d_binding_valid':5440, 'ctx.import_binding_valid':5472,
    'ctx.import_signature':5476, 'ctx.import_binding_pc':5480,
    'ctx.import_binding_target':5488, 'ctx.switch_commits':5784,
    'region.base':0, 'region.size':8, 'region.bytes':16,
    'region.permissions':24, 'region.page_count':32,
    'frame.pc':0, 'frame.rsp':8,
    'session.running':4, 'session.used':8, 'session.context_identity':24,
    'session.state_identity':32, 'user32.owner':8, 'user32.stats':40,
    'user32.stats.api_calls':40, 'user32.stats.callbacks':152,
    'user32.stats.posted_dispatches':168,
    'callback.owner':0, 'callback.stats.calls':280, 'callback.stats.returns':288,
    'callback.stats.rejections':296, 'callback.stats.depth':304,
    'callback.stats.max_depth':308,
}
REGISTERS = dict(zip(('RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI','R8','R9','R10','R11','R12','R13','R14','R15','RIP'),
                    (2216,2248,2264,2232,2312,2328,2280,2296,2344,2360,2376,2392,2408,2424,2440,2456,2472)))
CORE_OFFSETS.update({'state.'+k:v for k,v in REGISTERS.items()})


def validate_layout(value):
    need(type(value['schema']) is int and value['schema'] == 1 and value['byte_order'] == 'little' and value['pointer_size'] == 8,
         'layout platform differs')
    need(value['max_regions'] == 16 and value['max_calls'] == 64, 'layout capacity differs')
    for key, expected in {'state':3504,'context':5792,'instruction':16,'guest_memory':40,
                          'return_frame':16,'callback_session':312,'result':48,'fault':32,'access_plan':128}.items():
        need(type(value['sizes'].get(key)) is int and value['sizes'][key] == expected,
             'fixed compiled size differs: '+key)
    for key, expected in CORE_OFFSETS.items():
        need(type(value['offsets'].get(key)) is int and value['offsets'][key] == expected,
             'fixed compiled offset differs: '+key)
    for key, expected in {'fixed_dispatch_call_rva':0x16cf,'fixed_dispatch_target_rva':0xf00d6000,
                          'fixed_defproc_call_rva':0x1098,'fixed_defproc_target_rva':0xf00d4000,
                          'msg_rva':0x3190,'state_rva':0x3000,'result_rva':0x30c0}.items():
        need(value.get(key) == expected, 'fixed PE layout differs: '+key)


def validate_snapshot(snapshot, event, layout):
    sizes, offsets = layout['sizes'], layout['offsets']
    for blob, size_name in [('state','state'),('context','context'),('d3d','d3d_session'),
                            ('user32','user32_session'),('callbacks','callback_session')]:
        need(len(snapshot[blob]) == sizes[size_name], 'snapshot and compiled layout differ')
    ctx = snapshot['context']; state = snapshot['state']
    need(u64(ctx, 48) == 6 and u64(ctx, 40)*16 == len(snapshot['instructions']), 'raw Context counts differ')
    for i, region in enumerate(snapshot['regions']):
        off = 56+40*i
        need(u64(ctx, off) == region['base'] and u64(ctx, off+8) == len(region['bytes']) and
             u64(ctx, off+32) == len(region['permissions']), 'raw region metadata differs')
        need(u64(ctx, off+16)>0 and u64(ctx, off+24)>0, 'missing live region pointers')
    need(u64(snapshot['d3d'],24) == event['context_address'] == event['owner_context'] and
         u64(snapshot['d3d'],32) == event['state_address'] == event['owner_state'], 'raw owner differs')
    need(u32(snapshot['d3d'],4) == u32(snapshot['d3d'],8) == 1, 'real live session missing')
    need(u64(snapshot['user32'],8) == u64(snapshot['callbacks'],0) == event['context_address'],
         'raw User32/callback owner differs')
    for key, register in [('rax','RAX'),('rsp','RSP'),('rip','RIP')]:
        need(event[key] == u64(state,REGISTERS[register]), 'event/register mismatch: '+key)
    for key, off, reader in [('steps',728,u64),('depth',736,u32),('fault',696,u32),
                             ('returned',740,u32),('switch_commits',5784,u64)]:
        need(event[key] == reader(ctx,off), 'event/Context mismatch: '+key)
    for key, off, reader in [('callback_calls',280,u64),('callback_returns',288,u64),
                             ('callback_rejections',296,u64),('callback_depth',304,u32)]:
        need(event[key] == reader(snapshot['callbacks'],off), 'event/callback mismatch: '+key)
    need(event['api_calls'] == [u64(snapshot['user32'],40+8*i) for i in range(14)], 'event/API counts mismatch')
    need(event['user32_callbacks'] == u64(snapshot['user32'],152) and
         event['posted_dispatches'] == u64(snapshot['user32'],168), 'event/User32 counts mismatch')
    need(all(event[x] == 0 for x in ('fault','returned','callback_rejections','callback_depth')),
         'snapshot records a fault, return latch or active callback')


def validate_memory(before, after, base, rsp, index):
    need(before['instructions'] == after['instructions'], 'instruction metadata changed')
    for i, (a,b) in enumerate(zip(before['regions'], after['regions'])):
        need(a['base'] == b['base'] and a['permissions'] == b['permissions'], 'region map/permissions changed')
        if a['base'] == base:
            allowed = [(0x3008,4),(0x300c,4),(0x30cc,4),(0x30f8,4)] if index == 0 else []
            same_except(a['bytes'],b['bytes'],allowed,'guest image')
            av=struct.unpack('<5I',a['bytes'][0x3000:0x3014]);bv=struct.unpack('<5I',b['bytes'][0x3000:0x3014])
            need(av[:2] == bv[:2] == (0x31574f43,1), 'sample magic/version differs')
            need(av[2:4] == ((3,0) if index == 0 else (4,1)), 'initial sample input differs')
            need(bv[2:4] == (4,1), 'independent RIGHT/KEYUP sample oracle failed')
            if index == 0:
                need(u32(b['bytes'],0x30cc) == u32(a['bytes'],0x30cc)+1 and
                     u32(b['bytes'],0x30f8) == 1, 'RIGHT keydown/dirty oracle failed')
        elif a['base'] == 0x70000000:
            off=rsp-a['base'];need(0 <= off <= len(a['bytes']), 'stack pointer outside region')
            need(a['bytes'][off:] == b['bytes'][off:], 'callback changed stack above outer RSP')
        else:
            need(a['bytes'] == b['bytes'], 'callback changed non-image/non-stack region')


def validate_event_group(events, snapshots, index):
    types = ['outer-before','callback-before']
    if index: types += ['nested-before','ret-before','ret-after','nested-after']
    types += ['callback-after','ret-before','ret-after','outer-after']
    need([x['type'] for x in events] == types, 'actual call/return event order differs')
    need(all(x['index']==index and x['message']==0x100+index for x in events), 'event scope differs')
    first,last=events[0],events[-1]
    need(all(type(x['thread_id']) is int and x['thread_id']>0 and
             x['thread_id']==first['thread_id'] and x['state_address']==first['state_address'] and
             x['context_address']==first['context_address'] and x['owner_state']==x['state_address'] and
             x['owner_context']==x['context_address'] for x in events), 'live owner/thread changed')
    need(first['state_address']>0 and first['context_address']>0 and
         first['state_address']%16==first['context_address']%16==0 and
         first['state_address']!=first['context_address'], 'invalid live State/Context storage')
    need(all(x['fault']==0 and x['returned']==0 for x in events), 'terminal path in normal trace')
    need(all(a['steps']<=b['steps'] for a,b in zip(events,events[1:])), 'step counter regressed')
    for key in ('last_error','file_bytes_read','file_bytes_written','file_api_calls'):
        need(all(e[key]==first[key] for e in events), 'undeclared file/LastError effect')
    need(first['call_rva']==0x16cf and first['pc']==first['rip'], 'not the real Dispatch callsite')
    base=first['pc']-0xf00d6000
    # No input rewriting: raw MSG is the real guest structure from GetMessage.
    outer_before, outer_after = snapshots['outer-before'], snapshots['outer-after']
    need(base==0x140000000 and u64(outer_before['context'],0)==base and u64(outer_before['state'],REGISTERS['RCX'])==base+0x3190,
         'wrong live guest mapping/MSG argument')
    msg=guest_bytes(outer_before,base+0x3190,48)
    need(u32(msg,8)==0x100+index and u64(msg,16)==0x27 and
         u64(msg,24)==(0x014d0001 if index==0 else 0xc14d0001), 'raw MSG input differs')
    need(u64(msg,0)==u64(guest_bytes(outer_before,base+0x3140,8),0)!=0, 'MSG HWND differs')
    need(first['rsp']%16==8 and first['depth']>0, 'outer import stack contract differs')
    c=outer_before['context']; frame=904+(first['depth']-1)*16
    expected_rip=u64(c,frame);expected_rsp=u64(c,frame+8)
    need(expected_rip==base+0x16d2, 'normal CALL R12 return address differs')
    current_offset=u64(c,752)-u64(c,32)
    need(0<=current_offset<=len(outer_before['instructions'])-16 and current_offset%16==0,
         'current instruction not inside live instruction table')
    current=struct.unpack_from('<IHBBQ',outer_before['instructions'],current_offset)
    need(current[:4]==(0x16cf,3,4,0), 'not the fixed normal Dispatch register CALL')
    need(u32(c,760)==u32(c,764)==0 and u32(c,5472)==1 and u32(c,5476)==214 and
         u64(c,5480)==base+0x16cf and u64(c,5488)==first['pc'], 'raw committed import binding differs')
    need(last['rsp']==expected_rsp==first['rsp']+8 and last['rip']==expected_rip and
         last['depth']==first['depth']-1 and last['rax']==0, 'outer actual import RET failed')
    need(u64(guest_bytes(outer_before,first['rsp'],8),0)==expected_rip, 'real return slot differs')
    same_except(outer_before['state'],outer_after['state'],[(REGISTERS[k],8) for k in ('RAX','RSP','RIP')], 'outer State')
    cb_before,cb_after=snapshots['callback-before'],snapshots['callback-after']
    need(cb_before['state']==cb_after['state'], 'complete callback State was not restored')
    same_except(cb_before['context'],cb_after['context'],[(728,8),(5784,8)], 'complete callback Context')
    need(u64(cb_after['context'],728)>u64(cb_before['context'],728), 'callback executed no instructions')
    need(u64(cb_after['context'],5784)-u64(cb_before['context'],5784)==1-index,
         'actual switch commit oracle failed')
    marker_words=(base+0xe0000010,0,0,0,0)
    for snapshot in (cb_after,outer_after):
        need(struct.unpack('<5Q',guest_bytes(snapshot,first['rsp']-48,40))==marker_words,
             'callback marker/shadow frame differs')
    validate_memory(cb_before,cb_after,base,first['rsp'],index)
    validate_memory(outer_before,outer_after,base,first['rsp'],index)
    need(cb_before['d3d']==cb_after['d3d']==outer_before['d3d']==outer_after['d3d'], 'D3D lifecycle changed inside callback')
    same_except(outer_before['callbacks'],outer_after['callbacks'],[(280,8),(288,8)],'callback registry/statistics')
    need(last['callback_calls']==first['callback_calls']+1 and
         last['callback_returns']==first['callback_returns']+1 and
         first['callback_calls']==first['callback_returns'] and
         last['callback_rejections']==first['callback_rejections']==0 and
         last['callback_depth']==first['callback_depth']==0, 'callback completion counts differ')
    expected_api=[b+int(i==5)+int(index==1 and i==3) for i,b in enumerate(first['api_calls'])]
    need(last['api_calls']==expected_api and last['user32_callbacks']==first['user32_callbacks']+1 and
         last['posted_dispatches']==first['posted_dispatches']+1, 'real User32 API counts differ')
    same_except(outer_before['user32'],outer_after['user32'],[(40+5*8,8),(152,8),(168,8)]+([(40+3*8,8)] if index else []),'User32 session')
    rets=[(a,b) for a,b in zip(events,events[1:]) if a['type']=='ret-before']
    need([a['signature'] for a,b in rets] == ([212,214] if index else [214]), 'RET signatures differ')
    for a,b in rets:
        need(b['type']=='ret-after' and b['signature']==a['signature'] and
             b['steps']==a['steps']+1 and b['depth']==a['depth']-1 and b['rsp']==a['rsp']+8,
             'actual lifted RET transition differs')
    if index:
        nested=events[2]
        need(nested['signature']==212 and nested['call_rva']==0x1098 and
             nested['pc']==base+0xf00d4000 and nested['callback_depth']==1 and
             events[5]['rax']==0, 'KEYUP did not execute real DefWindowProc')
    return dict(message=0x100+index,actual_nested_imports=index,actual_import_rets=len(rets),
                steps=last['steps']-first['steps'],callback_steps=u64(cb_after['context'],728)-u64(cb_before['context'],728),
                switch_commits=last['switch_commits']-first['switch_commits'],
                callback_state_bytes_compared=len(cb_before['state']),
                callback_context_bytes_compared=len(cb_before['context']),
                callback_stack_marker_shadow_bytes_verified=40,raw_msg_hex=msg.hex())


PINS = {
 'window_bridge/window_runtime/runtime.c':'9051c121f680988bc4f13a072dacbf213e8612fd3d095acc5704b388f87defd8',
 'window_bridge/window_runtime/transaction_v1.c':'0b0baf46ea802e3984065dad3be3f36a10a6fcc6d4f0d102e52a5913becaf8ed',
 'window_lookup_v1/lookup_impl.inc':'ebb0a1a8ffa6be1df541b01645dc0a4629b4fb9ad3888def4082eb7c320c3ea0',
 'window_bridge/callback_v1.inc':'fa0c8108f08e10feaed87936a9440503b30ef1eaf2cce4eefb79470781f0ada2',
 'window_bridge/user32_v1.inc':'14a319668cd5e8856b017f9a7d54782556d461295033755f875fafadc14d20cf',
 'window_bridge/file_api.inc':'66c2b474dc296fd198d510252c5b52240f3c3a2b1333b5b50089443a62076b31',
 'window_bridge/window_runtime/runtime.h':'90cc91f6e94ed0fc64468662ee46cbcefb90414ca964209b359adeba2a954344',
 'window_bridge/callback_v1.h':'3e1a77a9b60624b4cd7357177fa4309bcfe351e85243b66db98d5005d901b250',
 'window_bridge/user32_v1.h':'ffd2bc7a3e633a5ef4de49663625fe4f12e763ef6f0f1b193672993709772518',
 'window_switch_v1/runtime_fields.inc':'76914960267b0a9f61909c85e366fbf8c66472f9cc686d3efa6c83c1257c4d2a',
}


def rewrite_once(raw, old, new):
    need(raw.count(old)==1, 'independent overlay anchor not unique')
    return raw.replace(old,new,1)


def validate_overlay(record, strategy, audit):
    need(record['contract']=='outer-abi-single-pass-v1' and record['strategy']==strategy, 'wrong overlay contract')
    manifest=audit.json(record['manifest_path'],record['manifest_sha256'])
    need(manifest['schema']==1 and manifest['strategy']==strategy, 'overlay manifest version differs')
    need(manifest['templates']=={str(ROOT/n):s for n,s in PINS.items()},'fixed source pin set differs')
    sources={n:audit.data(ROOT/n,s) for n,s in PINS.items()}
    hook=ROOT/'window_outer_abi_v1/instrumentation.inc'
    need(manifest['instrumentation']=={str(hook):digest(audit.data(hook))},'instrumentation identity differs')
    runtime=sources['window_bridge/window_runtime/runtime.c']
    runtime=rewrite_once(runtime,b'void *__remill_function_call(void *state,uint64_t pc,void *opaque) {',
        b'static void aot_outer_observe_ret(void *,uint64_t,void *,uint32_t);\nstatic void *aot_outer_original_function_call(void *state,uint64_t pc,void *opaque) {')
    runtime=rewrite_once(runtime,b'    aot_import_ret(state,pc,opaque);return opaque;',
        b'    aot_outer_observe_ret(state,pc,opaque,signature);return opaque;')
    runtime+=b'\n/* Versioned untimed observation; production templates remain unchanged. */\n'+audit.data(hook)
    callback=rewrite_once(sources['window_bridge/callback_v1.inc'],
        b'uint32_t aot_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,',
        b'static uint32_t aot_outer_original_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,')
    transaction=sources['window_bridge/window_runtime/transaction_v1.c']
    old=b'''static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    AotInstruction key={(uint32_t)(pc-ctx->module_base),0,0,0,0};
    return bsearch(&key,ctx->instructions,ctx->instruction_count,sizeof key,compare_instruction);
}
'''
    if strategy=='inline':transaction=rewrite_once(transaction,old,sources['window_lookup_v1/lookup_impl.inc'])
    expected={'window_bridge/window_runtime/runtime.c':runtime,
              'window_bridge/window_runtime/transaction_v1.c':transaction,'window_bridge/callback_v1.inc':callback}
    root=Path(record['source_root'])
    need(record['compile_source']==str(root/'window_bridge/window_runtime/runtime.c'), 'wrong compiled overlay source')
    need(manifest['generated']=={n:digest(v) for n,v in expected.items()},'generated source hashes differ')
    for name,data in expected.items():need(audit.data(root/name)==data,'extra generated source modification: '+name)
    audit.data(root/'overlay.diff',manifest['diff_sha256'])
    need({str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}=={*expected,'overlay.diff','overlay.json'},'unexpected overlay members')


def macho(data, filetype):
    need(len(data)>=32 and struct.unpack_from('<4I',data)==(0xfeedfacf,0x100000c,0,filetype),
         'ARM64 Mach-O header differs')


def validate_build(directory, audit):
    directory=Path(directory)
    record=audit.json(directory/'build.json')
    need(record['schema']==1 and record['status']=='OUTER_ABI_DIAGNOSTICS_BUILT_NOT_EXECUTED_NOT_MEASURED' and
         record['native_executions']==0 and record['timing_enabled'] is False and record['replay_enabled'] is False,
         'wrong build receipt contract')
    for mapping in ('inputs','artifacts','implementation'):
        need(type(record[mapping]) is dict and record[mapping], 'missing build input closure')
        for name,sha in record[mapping].items():audit.data(name,sha)
    producer=audit.json(record['producer'],record['producer_sha256'])
    product=audit.json(Path(record['product'])/'result.json',record['product_receipt_sha256'])
    baseline=audit.json(record['baseline_review'],record['baseline_review_sha256'])
    need(baseline['status']=='PASS_LOOKUP_V7_PRODUCT_INDEPENDENTLY_REVIEWED' and
         baseline['product_receipt_sha256']==record['product_receipt_sha256'], 'wrong reviewed baseline')
    need(producer['input_sha256']==producer['profile']['pe_sha256']==PE_SHA and
         producer['profile']['callback_rvas']==[0x1000], 'wrong PE/profile')
    callback_rows=[r for r in producer['roots'] if r['rva']==0x1000]
    need(len(callback_rows)==1,'one actual WndProc root required')
    instructions=callback_rows[0]['manifest']['instructions']
    by_rva={r['rva']:r for r in instructions}
    need(by_rva[0x1000]['bytes']=='56' and by_rva[0x1001]['bytes']=='4883ec20',
         'fixed callback entry stack prologue differs')
    for ins in instructions:
        if ins.get('mem_written'):
            need(ins['mem_base']=='RIP' or
                 ins['mem_base']=='RSP' and ins['iclass'] in ('PUSH','CALL_NEAR') and ins['mem_displacement']==0,
                 'unproved explicit callback stack/shadow write')
        if ins['reg0']=='RSP':
            need(ins['iclass'] in ('ADD','SUB') and ins['immediate']==32,
                 'unproved callback RSP adjustment')
    for path,sha in baseline['files'].items():need(record['inputs'].get(path)==sha, 'baseline source identity omitted')
    commands=[]
    for row in record['commands']:
        c=audit.json(row['path'],row['sha256']);commands.append(c)
        need(c['returncode']==0 and c['cwd']==str(directory), 'build command failed or wrong cwd')
        audit.data(c['stdout'],c['stdout_sha256']);audit.data(c['stderr'],c['stderr_sha256'])
    labels={c['label']:c for c in commands};need(len(labels)==len(commands),'duplicate build command label')
    need(set(record['configurations'])=={'reference-O0','reference-O3','inline-O0','inline-O3'}, 'incomplete configuration matrix')
    for strategy in ('reference','inline'):
        validate_overlay(record['generated'][strategy],strategy,audit)
        dep=record['dependencies']['runtime-'+strategy]
        need(dep['source']==record['generated'][strategy]['compile_source'], 'compiler selected wrong runtime')
        expected={str(Path(record['generated'][strategy]['source_root'])/n) for n in
                  ('window_bridge/window_runtime/runtime.c','window_bridge/window_runtime/transaction_v1.c','window_bridge/callback_v1.inc')}
        need(expected<=set(dep['paths']), 'diagnostic compilation dependency missing')
        need(not {str(ROOT/n) for n in ('window_bridge/window_runtime/runtime.c','window_bridge/window_runtime/transaction_v1.c','window_bridge/callback_v1.inc')} & set(dep['paths']), 'compiler selected old instrumented source')
        for name in ('window_bridge/user32_v1.inc','window_bridge/file_api.inc'):
            need(str(ROOT/name) in dep['paths'], 'real API implementation not in dependency closure')
        ir=record['runtime_ir'][strategy]
        text=audit.data(ir['path'],ir['sha256']).decode()
        # Real callbacks and I/O require the unrestricted effect declaration.
        for symbol in ('__remill_function_call','aot_wndproc_invoke'):
            lines=[line for line in text.splitlines() if line.startswith('define ') and '@'+symbol+'(' in line]
            need(len(lines)==1 and 'ptr' in lines[0], 'missing actual runtime helper definition')
            suffix=lines[0].split(')')[-1]
            attr=suffix.split('#')[-1].split()[0] if '#' in suffix else None
            declaration=lines[0]+' '.join(line for line in text.splitlines() if attr and line.startswith('attributes #'+attr+' ='))
            need(all(x not in declaration for x in ('nocallback','readnone','readonly','memory(')), 'runtime helper effect attributes invalid')
    for name,dep in record['dependencies'].items():
        audit.data(dep['path'],dep['sha256']);macho(audit.data(dep['object'],dep['object_sha256']),1)
        expected=[record['tools']['clang'],*dep['flags'],'-c',dep['source'],'-o',dep['object']]
        need(labels[name+'-compile']['argv']==expected and '-O3' in dep['flags'], 'actual compiler command differs')
        need(labels[name+'-deps']['argv']==[record['tools']['clang'],*dep['flags'],'-M','-MT','probe',dep['source']], 'dependency command differs')
        need(audit.data(labels[name+'-deps']['stdout'])==audit.data(dep['path'])==audit.data(labels[name+'-deps-after']['stdout']), 'compiler dependency graph changed')
        for path in dep['paths']:need(path in record['inputs'], 'dependency absent from frozen inputs')
    host=record['dependencies']['host']
    need(host['source']==producer['native_objects']['host']['source'] and '-Dmain=aot_window_main' not in host['flags'], 'not the unmodified argument-taking host')
    for name,c in record['configurations'].items():
        strategy,optimization=name.split('-')
        need(c['strategy']==strategy and c['guest_optimization']==optimization and c['runtime_optimization']=='O3', 'configuration identity differs')
        need(c['root_objects']==[r['manifest']['objects'][optimization]['path'] for r in producer['roots']] and
             c['ret_object']==producer['ret_manifest']['objects'][optimization]['path'], 'wrong lifted roots/RET objects')
        expected={host['object'],record['dependencies']['runtime-'+strategy]['object'],
                  *(producer['native_objects'][x]['path'] for x in ('native-backend','window-backend','cocoa')),
                  *c['root_objects'],c['ret_object']}
        need(set(c['linked_objects'])==expected, 'extra/omitted linked native object')
        for path,sha in c['linked_objects'].items():macho(audit.data(path,sha),1)
        argv=labels[name+'-link']['argv']
        need(all(argv.count(p)==1 for p in expected) and argv[-2:]==['-o',c['executable']] and
             '-flto' not in argv, 'actual link did not select exact diagnostic objects')
        macho(audit.data(c['executable'],c['executable_sha256']),2)
    return record


def validate_run(directory, build, audit):
    directory=Path(directory)
    run=audit.json(directory/'run.json')
    need(run['schema']==1 and run['status']=='OUTER_ABI_SINGLE_PASS_RUNS_OBSERVED_NOT_INDEPENDENTLY_ACCEPTED' and
         run['input_kind']=='TEST_QUEUE_NOT_OS_KEYBOARD' and run['timing_enabled'] is False and run['replay_enabled'] is False,
         'run receipt contract differs')
    need(run['build']==str(build['_directory']) and
         run['build_receipt_sha256']==digest(audit.data(build['_directory']/'build.json')), 'run/build identity differs')
    for path,sha in run['sources'].items():audit.data(path,sha)
    need(len(run['executions'])==4, 'four serialized executions required')
    summaries=[];pids=set();last_launch=0
    for expected_name, ref in zip(('reference-O0','inline-O0','reference-O3','inline-O3'),run['executions']):
        execution=audit.json(ref['path'],ref['sha256']);case=directory/expected_name
        need(execution['configuration']==expected_name and execution['directory']==str(case) and
             execution['returncode']==0 and execution['external_timeout'] is False, 'native execution failed or mismatched')
        need(type(execution['pid']) is int and execution['pid']>0 and execution['pid'] not in pids, 'unique native PID required')
        pids.add(execution['pid'])
        expected_files={str(p) for p in case.rglob('*') if p.is_file() and 'cache' not in p.relative_to(case).parts and p.name!='execution.json'}
        need(set(execution['files'])==expected_files,'run evidence omitted or extra file')
        for path,sha in execution['files'].items():audit.data(path,sha)
        config=build['configurations'][expected_name]
        need(execution['executable_sha256']==config['executable_sha256'], 'run executable digest differs')
        command=audit.json(case/'command.json');launch=audit.json(case/'launched.json')
        need(command['argv']==[config['executable'],'--data-dir',str(case/'data'),'--timeout-ms',
             str((command['timeout_seconds']-5)*1000),'--test-sequence','right,right-up,escape'] and
             command['cwd']==str(case) and command['env']['PE_AOT_OUTER_OUTPUT']==str(case/'diagnostic'),
             'actual diagnostic invocation differs')
        need(launch['pid']==execution['pid'] and launch['executable']==config['executable'] and
             launch['unix_ns']>last_launch, 'launched PID/order differs')
        last_launch=launch['unix_ns']
        for name in ('processes-before.json','processes-after.json'):
            processes=audit.json(case/name)
            need(processes['returncode']==0 and processes['matching_processes']==[], 'unexpected live project process')
        host=audit.json(case/'stdout')
        need(host['outcome']=='PROCESS_EXITED' and host['host_exit_code']==host['setup_status']==host['exit_code']==0 and
             host['aot_status']==11 and host['proc_translated']==0 and not host['timed_out'] and
             host['host_finished'] is True and host['fault']['status']==0, 'real native host failed')
        need(host['pe_sha256']==PE_SHA and host['entry_arguments']==0 and host['image_base']==0x140000000, 'wrong guest PE entry')
        queue=host['test_queue']
        need(queue['requested']==queue['posted']==3 and queue['injection_error']==0 and
             [e['name'] for e in queue['events']]==['right','right-up','escape'], 'actual test input sequence differs')
        need(host['callback_stats']['calls']==host['callback_stats']['returns'] and
             all(host['callback_stats'][k]==0 for k in ('rejections','depth','end_status')) and
             host['user32_end_status']==0, 'final callback/User32 cleanup failed')
        need(host['d3d_before_cleanup']['created']==host['d3d_before_cleanup']['guest_released'] and
             all(host['d3d_after_cleanup'][k]==0 for k in ('live_objects','active_maps')) and
             host['host_after_finish']['active_views']==0 and host['files']['open_after_cleanup']==0,
             'real native resources not released')
        save=audit.data(case/'data/switch-tile.bin')
        need(len(save)==20 and struct.unpack('<5I',save)[:4]==(0x31574f43,1,4,1), 'final guest save oracle failed')
        need(host['saved_file']['errno']==0 and host['saved_file']['truncated'] is False and
             host['saved_file']['data_hex']==save.hex(), 'raw saved file differs from host observation')
        observations=host['observations']
        need(bytes.fromhex(observations['window_state'])==save, 'final observed State/save mismatch')
        result_words=struct.unpack('<15I',bytes.fromhex(observations['window_result']))
        need(result_words[3:5]==(2,0) and result_words[9:11]==(1,20) and result_words[13]==1,
             'final guest input/save/exit observations differ')
        need(struct.unpack('<5I',save)[4]==host['d3d_before_cleanup']['present_calls']==result_words[8],
             'actual Present/save counter mismatch')
        diagnostic=case/'diagnostic';layout=audit.json(diagnostic/'layout.json');validate_layout(layout)
        lines=audit.data(diagnostic/'events.jsonl').splitlines()
        events=[decode_json(line) for line in lines]
        keys=set('seq index type signature message pc call_rva rip rsp rax steps depth fault returned switch_commits state_address context_address owner_state owner_context thread_id callback_calls callback_returns callback_rejections callback_depth user32_callbacks posted_dispatches last_error file_bytes_read file_bytes_written snapshot api_calls file_api_calls'.split())
        need(all(type(e) is dict and set(e)==keys for e in events), 'event schema fields differ')
        need(len(events)==16 and [e['seq'] for e in events]==list(range(16)), 'event sequence omitted/duplicated')
        need(all(type(v) is int for e in events for k,v in e.items() if k not in ('type','snapshot','api_calls','file_api_calls')),
             'event numeric type differs')
        need(all(len(e['api_calls'])==14 and len(e['file_api_calls'])==9 and
                 all(type(v) is int and v>=0 for v in e['api_calls']+e['file_api_calls']) for e in events), 'counter array invalid')
        groups=[];expected={'layout.json','events.jsonl'}
        for index in (0,1):
            group=[e for e in events if e['index']==index];snapshots={}
            for e in group:
                wants=e['type'] in ('outer-before','callback-before','callback-after','outer-after')
                need(e['snapshot']==('event-%d-%s.bin'%(index,e['type']) if wants else ''), 'snapshot filename/schema differs')
                if wants:
                    expected.add(e['snapshot']);snapshots[e['type']]=read_snapshot(audit.data(diagnostic/e['snapshot']))
                    validate_snapshot(snapshots[e['type']],e,layout)
            groups.append(validate_event_group(group,snapshots,index))
        need({p.name for p in diagnostic.iterdir()}==expected, 'unexpected diagnostic files')
        need(events[0]['thread_id']==events[-1]['thread_id'] and
             events[0]['context_address']==events[-1]['context_address'], 'two messages used different owner')
        stderr=audit.data(case/'stderr').decode(errors='strict')
        producer=audit.json(build['producer'],build['producer_sha256'])
        for name in ('d3d11','dxgi','winemetal'):
            need(any('dyld['+str(execution['pid'])+']' in line and producer['backend'][name] in line
                     for line in stderr.splitlines()), 'actual backend load missing: '+name)
        summaries.append(dict(configuration=expected_name,pid=execution['pid'],groups=groups,
                              native_exit=0,test_queue_events=3,save_sha256=digest(save)))
    return summaries


def validate_output(out, protected):
    out=Path(out).absolute()
    need(out==out.resolve() and out.parent.is_dir(), 'canonical existing output parent required')
    need(not out.exists() and not out.is_symlink(), 'fresh review output required')
    need(all(not out.is_relative_to(Path(p).resolve()) for p in protected),
         'review output overlaps frozen build/run/product')
    return out


def review(build, run, out):
    build,run=Path(build).absolute(),Path(run).absolute()
    audit=Audit();declared=audit.json(build/'build.json')
    out=validate_output(out,[build,run,declared['product']])
    record=validate_build(build,audit);record['_directory']=build
    executions=validate_run(run,record,audit)
    audit.unchanged()
    result=dict(schema=1,status=STATUS,build=str(build),run=str(run),executions=executions,
                unique_files_read=len(audit.files),files=audit.files,
                timing_verified=False,replay_verified=False,cross_process_full_byte_equivalence=False,
                stack_below_outer_rsp_exact_oracle=False,
                scope='Actual main-to-DispatchMessage/right+keyup/callback/DefWindowProc/import-RET single passes; complete same-process callback State/Context comparison (steps/switch counter exceptions checked), exact image oracle, other region/permission invariants. Full stack bytes retained and 40-byte callback marker/shadow frame independently checked; other below-RSP stack writes do not have an exact independent oracle. Reused root objects. No performance, replay, full budget/negative matrix or production App claim.')
    with out.open('x') as file:json.dump(result,file,sort_keys=True,indent=2);file.write('\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True);parser.add_argument('--run',required=True);parser.add_argument('--out',required=True)
    result=review(**vars(parser.parse_args()))
    print(json.dumps({k:result[k] for k in ('status','unique_files_read')}))
