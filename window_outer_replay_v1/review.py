"""Independent file-only acceptance of same-address outer ABI replay.

The frozen single-pass reader supplies byte parsing and per-call semantic rules.
Replay restoration, per-pass equivalence and cumulative host ledgers are checked
here from raw snapshots; no producer, subprocess, native or UI is invoked.
"""
import argparse
import json
import struct
from pathlib import Path

from window_outer_abi_v1 import review as single

ROOT = Path(__file__).resolve().parents[1]
STATUS = 'PASS_UNTIMED_OUTER_REPLAY_INDEPENDENTLY_REVIEWED'
BASELINE_READER_SHA = '89d117570453413f90d2769e986c09cd56a8d7ddaf5cae23de4b5ff0a9522219'
PE_SHA = single.PE_SHA
HOST_SOURCE_SHA = '9b79aa34c0cfc6302f34d354b39d6bae9678b6b7efe6fe805ddbd7d072e04919'
FIXED_MSG = bytes.fromhex('7856341264000000c8000000')
Audit, need, digest = single.Audit, single.need, single.digest
u64, u32, read_snapshot = single.u64, single.u32, single.read_snapshot
same_except, guest_bytes = single.same_except, single.guest_bytes
validate_snapshot, macho = single.validate_snapshot, single.macho
REGISTERS, PINS = single.REGISTERS, single.PINS
rewrite_once = single.rewrite_once
LEDGER_KEYS = ('diagnostic_calls','continuation_calls','total_guest_steps','total_switch_commits','reset_count')
EVENT_KEYS = set('seq index attempt role type signature message pc call_rva rip rsp rax steps depth fault returned switch_commits state_address context_address owner_state owner_context thread_id callback_calls callback_returns callback_rejections callback_depth user32_callbacks posted_dispatches last_error file_bytes_read file_bytes_written snapshot api_calls file_api_calls'.split()) | set(LEDGER_KEYS)


# Fixed ARM64 LP64 layout of the pinned C structs and State. Values are an
# independent admission contract, never adapted to the current producer layout.
EXPECTED_LAYOUT = {'byte_order': 'little',
 'contract': 'outer-abi-replay-v1',
 'diagnostics_per_event': 2,
 'fixed_defproc_call_rva': 4248,
 'fixed_defproc_target_rva': 4027400192,
 'fixed_dispatch_call_rva': 5839,
 'fixed_dispatch_target_rva': 4027408384,
 'max_calls': 64,
 'max_regions': 16,
 'msg_fixed_hex': '7856341264000000c8000000',
 'msg_rva': 12688,
 'offsets': {'boundary.frames': 7008,
             'boundary.snapshot': 3504,
             'boundary.state': 0,
             'callback.owner': 0,
             'callback.stats': 280,
             'callback.stats.calls': 280,
             'callback.stats.depth': 304,
             'callback.stats.max_depth': 308,
             'callback.stats.rejections': 296,
             'callback.stats.returns': 288,
             'ctx.budget': 8,
             'ctx.current': 752,
             'ctx.current_pc': 744,
             'ctx.d3d_binding_pc': 5456,
             'ctx.d3d_binding_target': 5464,
             'ctx.d3d_binding_valid': 5440,
             'ctx.d3d_map_permissions': 5496,
             'ctx.d3d_object_index': 5444,
             'ctx.d3d_signature': 5448,
             'ctx.exit_pc': 16,
             'ctx.frames': 904,
             'ctx.import_binding_pc': 5480,
             'ctx.import_binding_target': 5488,
             'ctx.import_binding_valid': 5472,
             'ctx.import_signature': 5476,
             'ctx.in_instruction': 760,
             'ctx.initial_rsp': 24,
             'ctx.instruction_count': 40,
             'ctx.instructions': 32,
             'ctx.module_base': 0,
             'ctx.pending': 768,
             'ctx.pending_size': 764,
             'ctx.pending_value': 896,
             'ctx.region_count': 48,
             'ctx.regions': 56,
             'ctx.result': 696,
             'ctx.result.call_depth': 736,
             'ctx.result.fault': 696,
             'ctx.result.fault.access': 700,
             'ctx.result.fault.address': 712,
             'ctx.result.fault.pc': 704,
             'ctx.result.fault.status': 696,
             'ctx.result.fault.width': 720,
             'ctx.result.returned': 740,
             'ctx.result.steps': 728,
             'ctx.snapshot': 1936,
             'ctx.switch_binding_attempted': 5780,
             'ctx.switch_bound': 5776,
             'ctx.switch_commits': 5784,
             'ctx.switch_count': 5768,
             'ctx.switch_pc': 5504,
             'ctx.switch_targets': 5512,
             'frame.pc': 0,
             'frame.rsp': 8,
             'region.base': 0,
             'region.bytes': 16,
             'region.page_count': 32,
             'region.permissions': 24,
             'region.size': 8,
             'session.context_identity': 24,
             'session.exit_requested': 5488,
             'session.running': 4,
             'session.state_identity': 32,
             'session.stats': 312,
             'session.used': 8,
             'state.DF': 2075,
             'state.R10': 2376,
             'state.R11': 2392,
             'state.R12': 2408,
             'state.R13': 2424,
             'state.R14': 2440,
             'state.R15': 2456,
             'state.R8': 2344,
             'state.R9': 2360,
             'state.RAX': 2216,
             'state.RBP': 2328,
             'state.RBX': 2232,
             'state.RCX': 2248,
             'state.RDI': 2296,
             'state.RDX': 2264,
             'state.RIP': 2472,
             'state.RSI': 2280,
             'state.RSP': 2312,
             'user32.owner': 8,
             'user32.stats': 40,
             'user32.stats.api_calls': 40,
             'user32.stats.callbacks': 152,
             'user32.stats.posted_dispatches': 168},
 'pointer_size': 8,
 'result_rva': 12480,
 'schema': 1,
 'sizes': {'access_plan': 128,
           'callback_boundary': 8256,
           'callback_session': 312,
           'context': 5792,
           'd3d_session': 5520,
           'fault': 32,
           'guest_memory': 40,
           'instruction': 16,
           'result': 48,
           'return_frame': 16,
           'state': 3504,
           'user32_session': 408},
 'state_rva': 12288}


def exact_shape(actual, expected):
    if type(actual) is not type(expected):return False
    if isinstance(expected,dict):return actual.keys()==expected.keys() and all(exact_shape(actual[k],v) for k,v in expected.items())
    return actual==expected


def validate_receipt_contract(record, status):
    need(type(record) is dict and type(record.get('schema')) is int and record['schema']==1 and
         record.get('status')==status and record.get('timing_enabled') is False and
         record.get('replay_enabled') is True and type(record.get('diagnostic_rounds')) is int and
         record['diagnostic_rounds']==2 and type(record.get('continuation_rounds')) is int and
         record['continuation_rounds']==1, 'wrong explicit replay receipt contract')


def validate_layout(value):
    need(exact_shape(value,EXPECTED_LAYOUT),'fixed complete layout schema/values differ')
    single.validate_layout(value)
    for name,size in [('d3d_session',5520),('user32_session',408),('callback_boundary',8256)]:
        need(type(value['sizes'].get(name)) is int and value['sizes'][name]==size,
             'complete compiled session size differs: '+name)
    need(value['contract']=='outer-abi-replay-v1' and value['diagnostics_per_event']==2 and
         value['msg_fixed_hex']==FIXED_MSG.hex(), 'replay layout contract differs')


def validate_overlay(record, strategy, audit):
    need(record['contract']=='outer-abi-replay-v1' and record['strategy']==strategy, 'wrong replay overlay contract')
    manifest=audit.json(record['manifest_path'],record['manifest_sha256'])
    need(type(manifest['schema']) is int and manifest['schema']==1 and manifest['strategy']==strategy and
         manifest['contract']=='outer-abi-replay-v1' and manifest['status']=='GENERATED_REPLAY_ABI_SOURCES_NOT_EXECUTED' and
         manifest['replay_enabled'] is True and type(manifest['diagnostics_per_event']) is int and
         manifest['diagnostics_per_event']==2, 'overlay manifest contract differs')
    need(manifest['templates']=={str(ROOT/n):s for n,s in PINS.items()},'fixed source pin set differs')
    sources={n:audit.data(ROOT/n,s) for n,s in PINS.items()}
    hook=ROOT/'window_outer_replay_v1/instrumentation.inc'
    need(manifest['instrumentation']=={str(hook):digest(audit.data(hook))},'instrumentation identity differs')
    runtime=sources['window_bridge/window_runtime/runtime.c']
    runtime=rewrite_once(runtime,b'void *__remill_function_call(void *state,uint64_t pc,void *opaque) {',
        b'static void aot_outer_observe_ret(void *,uint64_t,void *,uint32_t);\nstatic void *aot_outer_original_function_call(void *state,uint64_t pc,void *opaque) {')
    runtime=rewrite_once(runtime,b'    aot_import_ret(state,pc,opaque);return opaque;',
        b'    aot_outer_observe_ret(state,pc,opaque,signature);return opaque;')
    runtime+=b'\n/* Versioned untimed replay; production templates remain unchanged. */\n'+audit.data(hook)
    callback=rewrite_once(sources['window_bridge/callback_v1.inc'],
        b'uint32_t aot_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,',
        b'static uint32_t aot_outer_original_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,')
    transaction=sources['window_bridge/window_runtime/transaction_v1.c']
    original=sources['window_bridge/window_runtime/transaction_v1.c']
    start=original.index(b'static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {')
    end=original.index(b'\n}',start)+3
    old=original[start:end]
    if strategy=='inline':transaction=rewrite_once(transaction,old,sources['window_lookup_v1/lookup_impl.inc'])
    expected={'window_bridge/window_runtime/runtime.c':runtime,
              'window_bridge/window_runtime/transaction_v1.c':transaction,'window_bridge/callback_v1.inc':callback}
    root=Path(record['source_root'])
    need(record['compile_source']==str(root/'window_bridge/window_runtime/runtime.c'), 'wrong compiled overlay source')
    need(manifest['generated']=={n:digest(v) for n,v in expected.items()},'generated source hashes differ')
    for name,data in expected.items():need(audit.data(root/name)==data,'extra generated source modification: '+name)
    audit.data(root/'overlay.diff',manifest['diff_sha256'])
    need({str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}=={*expected,'overlay.diff','overlay.json'},'unexpected overlay members')


def validate_build(directory, audit):
    directory=Path(directory)
    record=audit.json(directory/'build.json')
    validate_receipt_contract(record,'OUTER_REPLAY_DIAGNOSTICS_BUILT_NOT_EXECUTED_NOT_MEASURED')
    need(record['schema']==1 and record['status']=='OUTER_REPLAY_DIAGNOSTICS_BUILT_NOT_EXECUTED_NOT_MEASURED' and
         record['native_executions']==0 and record['timing_enabled'] is False and record['replay_enabled'] is True and record['diagnostic_rounds']==2 and record['continuation_rounds']==1,
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
    fixed_host=str(ROOT/'window_bridge/window_host.c')
    need(host['source']==producer['native_objects']['host']['source']==fixed_host and
         record['inputs'].get(fixed_host)==baseline['files'].get(fixed_host)==HOST_SOURCE_SHA,
         'fixed host CPU allocation source identity differs')
    audit.data(fixed_host,HOST_SOURCE_SHA)
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


def guest_equal(before, after, label, msg_variant=False):
    """Full guest machine equality, with only the declared 12 MSG bytes optional."""
    for field in ('state','context','instructions'):
        need(before[field]==after[field], label+' '+field+' bytes differ')
    need(len(before['regions'])==len(after['regions'])==6, label+' region count differs')
    base=u64(before['context'],0)
    for a,b in zip(before['regions'],after['regions']):
        need(a['base']==b['base'] and a['permissions']==b['permissions'],label+' mapping/permissions differ')
        spans=[(0x3190+32,12)] if msg_variant and a['base']==base else []
        same_except(a['bytes'],b['bytes'],spans,label+' guest backing')


def host_equal(before, after, first_event, last_event, label):
    """Reset may never restore host state, including its accumulating counters."""
    for field in ('d3d','user32','callbacks'):
        need(before[field]==after[field],label+' changed/restored host '+field)
    for key in ('last_error','file_bytes_read','file_bytes_written','file_api_calls',
                'api_calls','callback_calls','callback_returns','callback_rejections',
                'callback_depth','user32_callbacks','posted_dispatches'):
        need(first_event[key]==last_event[key],label+' host/TLS ledger changed: '+key)
    for key in ('state_address','context_address','owner_state','owner_context','thread_id'):
        need(first_event[key]==last_event[key],label+' live owner changed: '+key)


def validate_ledger(events, start, expected_steps, expected_switch, attempt):
    need(attempt in (0,1,2),'invalid replay attempt')
    end=dict(start)
    end['diagnostic_calls' if attempt<2 else 'continuation_calls']+=1
    end['total_guest_steps']+=expected_steps
    end['total_switch_commits']+=expected_switch
    for i,event in enumerate(events):
        expected=end if i==len(events)-1 else start
        need({k:event[k] for k in LEDGER_KEYS}==expected,'independent cumulative replay ledger differs')
    return end


def increment_u64(raw, offsets):
    result=bytearray(raw)
    for offset in offsets:struct.pack_into('<Q',result,offset,u64(raw,offset)+1)
    return bytes(result)


def validate_host_phases(snapshots, index):
    before,entry,returned,after=(snapshots[k] for k in
        ('outer-before','callback-before','callback-after','outer-after'))
    need(before['d3d']==entry['d3d']==returned['d3d']==after['d3d'],
         'complete D3D host bytes changed within selected import')
    need(entry['user32']==increment_u64(before['user32'],[80,152,168]) and
         entry['callbacks']==before['callbacks'],'dispatcher entry host phase differs')
    need(returned['user32']==increment_u64(entry['user32'],[64] if index else []),
         'callback User32 phase differs')
    callbacks=bytearray(increment_u64(entry['callbacks'],[280,288]))
    struct.pack_into('<I',callbacks,308,max(u32(entry['callbacks'],308),u32(entry['callbacks'],304)+1))
    need(returned['callbacks']==bytes(callbacks),'callback registry complete host phase differs')
    need(after['user32']==returned['user32'] and after['callbacks']==returned['callbacks'],
         'import RET changed/restored complete host session')


def validate_outer_bridges(events, snapshots):
    """Reconstruct the two real dispatcher bridges without broad Context masks.

    The fixed helper sets current_pc before wui_dispatch. After wnd_restore it
    writes LRESULT=0, clears only binding-valid flags, then runs the C3 RET:
    begin snapshots State and selects its one metadata row; commit decrements
    depth without clearing any ReturnFrame slot. No guest memory is written.
    """
    before,cb_before,cb_after,after=(snapshots[k] for k in
        ('outer-before','callback-before','callback-after','outer-after'))
    pc=events[0]['pc']
    expected=bytearray(before['context']);struct.pack_into('<Q',expected,744,pc)
    guest_equal({**before,'context':bytes(expected)},cb_before,'actual dispatcher entry bridge')
    context=cb_after['context'];state=cb_after['state']
    depth=u32(context,736);need(1<=depth<=64,'outer RET frame depth invalid')
    frame=904+(depth-1)*16;return_pc,return_rsp=u64(context,frame),u64(context,frame+8)
    need(return_rsp==u64(state,REGISTERS['RSP'])+8,'actual RET frame RSP differs')
    base=u64(context,0);rows=[]
    for offset in range(0,len(cb_after['instructions']),16):
        row=struct.unpack_from('<IHBBQ',cb_after['instructions'],offset)
        if row[0]==pc-base:rows.append((offset,row))
    need(len(rows)==1 and rows[0][1]==(pc-base,1,2,0,0),'one exact import RET instruction required')
    pre_ret=bytearray(state)
    struct.pack_into('<Q',pre_ret,REGISTERS['RAX'],0)
    struct.pack_into('<Q',pre_ret,REGISTERS['RIP'],pc)
    expected=bytearray(context)
    struct.pack_into('<Q',expected,728,u64(context,728)+1)
    struct.pack_into('<I',expected,736,depth-1)
    struct.pack_into('<Q',expected,744,pc)
    struct.pack_into('<Q',expected,752,u64(context,32)+rows[0][0])
    struct.pack_into('<I',expected,760,0)
    struct.pack_into('<I',expected,764,0)
    expected[1936:5440]=pre_ret
    struct.pack_into('<I',expected,5440,0)
    struct.pack_into('<I',expected,5472,0)
    final_state=bytearray(pre_ret)
    struct.pack_into('<Q',final_state,REGISTERS['RSP'],return_rsp)
    struct.pack_into('<Q',final_state,REGISTERS['RIP'],return_pc)
    guest_equal({**cb_after,'state':bytes(final_state),'context':bytes(expected)},after,
                'actual import RET full Context/State bridge')
    ret_before,ret_after=events[-3:-1]
    need(ret_before['type']=='ret-before' and ret_after['type']=='ret-after' and
         ret_before['signature']==ret_after['signature']==214,'actual final outer RET missing')
    for event,raw,steps,event_depth in ((ret_before,pre_ret,u64(context,728),depth),
                                       (ret_after,final_state,u64(context,728)+1,depth-1)):
        need(event['pc']==pc and event['steps']==steps and event['depth']==event_depth and
             all(event[name]==u64(raw,REGISTERS[reg]) for name,reg in
                 [('rax','RAX'),('rsp','RSP'),('rip','RIP')]),'outer RET event differs from reconstructed machine')


def validate_replay_group(events, snapshots, index, ledger):
    """Independently join original, two diagnostic passes and real continuation."""
    need(events and events[0]['type']=='original-capture','original boundary capture missing')
    original_event=events[0]
    need(original_event['attempt']==-1 and original_event['role']=='original' and
         original_event['index']==index and original_event['signature']==214 and
         original_event['message']==0x100+index,'wrong original boundary identity')
    need({k:original_event[k] for k in LEDGER_KEYS}==ledger,'original capture ledger differs')
    original=snapshots[(-1,'original-capture')]
    groups=[]; previous=original;previous_event=original_event
    for attempt in range(3):
        group=[e for e in events[1:] if e['attempt']==attempt]
        need(group and all(e['role']==('diagnostic' if attempt<2 else 'continuation') for e in group),
             'wrong diagnostic/continuation role')
        current={kind:snapshots[(attempt,kind)] for kind in
                 ('outer-before','callback-before','callback-after','outer-after')}
        before=current['outer-before'];after=current['outer-after']
        if attempt==0:
            need(all(original_event[k]==group[0][k] for k in EVENT_KEYS-{'seq','attempt','role','type','snapshot'}),
                 'original capture metadata differs from live prepared boundary')
        if attempt:
            ledger=dict(ledger);ledger['reset_count']+=1
        host_equal(previous,before,previous_event,group[0],'same-address boundary preparation')
        guest_equal(original,before,'original boundary restore',msg_variant=attempt<2)
        base=u64(original['context'],0)
        original_msg=guest_bytes(original,base+0x3190,48)
        before_msg=guest_bytes(before,base+0x3190,48)
        need(before_msg==original_msg[:32]+FIXED_MSG+original_msg[44:] if attempt<2 else before_msg==original_msg,
             'MSG fixed-input whitelist or original continuation differs')
        summary=single.validate_event_group(group,current,index)
        validate_outer_bridges(group,current)
        validate_host_phases(current,index)
        need(summary['steps']==(46 if index==0 else 18) and
             summary['callback_steps']==(45 if index==0 else 17) and
             summary['switch_commits']==1-index,'fixed original PE per-pass execution delta differs')
        ledger=validate_ledger(group,ledger,summary['steps'],summary['switch_commits'],attempt)
        groups.append(dict(attempt=attempt,role='diagnostic' if attempt<2 else 'continuation',**summary))
        previous,previous_event=after,group[-1]
    expected=[events[0]]+[e for attempt in range(3) for e in events[1:] if e['attempt']==attempt]
    need(events==expected and len(events)==(19 if index==0 else 31),'extra/reordered replay event')
    for kind in ('outer-before','callback-before','callback-after','outer-after'):
        guest_equal(snapshots[(0,kind)],snapshots[(1,kind)],'same-process diagnostic '+kind)
        guest_equal(snapshots[(0,kind)],snapshots[(2,kind)],'continuation '+kind,msg_variant=True)
    return dict(index=index,passes=groups,original_msg_hex=original_msg.hex(),
                diagnostic_guest_byte_equivalence=True,continuation_original_restored=True),ledger


def validate_event_counter_progress(before, after):
    for key in ('callback_calls','callback_returns','user32_callbacks','posted_dispatches',
                'file_bytes_read','file_bytes_written'):
        need(after[key]>=before[key],'host counter regressed between selected messages: '+key)
    for key in ('api_calls','file_api_calls'):
        need(len(after[key])==len(before[key]) and all(a>=b for a,b in zip(after[key],before[key])),
             'host API counters regressed between selected messages')


def validate_trace(diagnostic, audit):
    diagnostic=Path(diagnostic)
    layout=audit.json(diagnostic/'layout.json');validate_layout(layout)
    events=[single.decode_json(line) for line in audit.data(diagnostic/'events.jsonl').splitlines()]
    need(len(events)==50 and [e['seq'] for e in events]==list(range(50)), 'replay event count/sequence differs')
    need(all(type(e) is dict and set(e)==EVENT_KEYS for e in events), 'replay event fields differ')
    need(all(type(v) is int for e in events for k,v in e.items()
             if k not in ('type','role','snapshot','api_calls','file_api_calls')), 'event numeric type differs')
    need(all(len(e['api_calls'])==14 and len(e['file_api_calls'])==9 and
             all(type(v) is int and v>=0 for v in e['api_calls']+e['file_api_calls']) for e in events),
         'event counter arrays differ')
    need(all(e[k]>=0 for e in events for k in LEDGER_KEYS),'negative replay counter')
    need(all(e['index'] in (0,1) and e['attempt'] in (-1,0,1,2) for e in events),'unknown replay selection')
    first=events[0]
    need(all(all(e[k]==first[k] for k in ('state_address','context_address','owner_state','owner_context','thread_id'))
             for e in events),'selected messages changed real owner/thread')
    expected_files={'layout.json','events.jsonl'};summary=[];ledger={k:0 for k in LEDGER_KEYS}
    for index in (0,1):
        group=[e for e in events if e['index']==index];snapshots={}
        for e in group:
            wants=e['type'] in ('original-capture','outer-before','callback-before','callback-after','outer-after')
            name='event-%d-attempt-%d-%s.bin'%(index,e['attempt'],e['type']) if wants else ''
            need(e['snapshot']==name,'replay snapshot filename differs')
            if wants:
                need(name not in expected_files,'duplicate replay snapshot')
                expected_files.add(name);snap=read_snapshot(audit.data(diagnostic/name))
                validate_snapshot(snap,e,layout);snapshots[(e['attempt'],e['type'])]=snap
        result,ledger=validate_replay_group(group,snapshots,index,ledger);summary.append(result)
    need([e['index'] for e in events]==[0]*19+[1]*31,'interleaved selected messages')
    validate_event_counter_progress(events[18],events[19])
    need({p.name for p in diagnostic.iterdir()}==expected_files,'extra/omitted replay diagnostic artifact')
    need(ledger==dict(diagnostic_calls=4,continuation_calls=2,total_guest_steps=192,total_switch_commits=3,reset_count=4),
         'final selected replay ledger differs')
    return summary,ledger,events[-1]


def validate_final_host(host, final_event):
    callbacks,user32,files=host['callback_stats'],host['user32_stats'],host['files']
    for key in ('calls','returns'):
        need(type(callbacks[key]) is int and callbacks[key]>=final_event['callback_'+key],
             'host final callback counter lost replay work')
    for key,event_key in [('callbacks','user32_callbacks'),('posted_dispatches','posted_dispatches')]:
        need(type(user32[key]) is int and user32[key]>=final_event[event_key],
             'host final User32 counter lost replay work')
    need(len(user32['api_calls'])==14 and all(type(a) is int and a>=b for a,b in
         zip(user32['api_calls'],final_event['api_calls'])),'host final API ledger regressed')
    for key in ('bytes_read','bytes_written'):
        need(type(files[key]) is int and files[key]>=final_event['file_'+key],
             'host final file byte counter regressed')
    need(len(files['api_calls_4_to_9'])==6 and files['api_calls_4_to_9'][5]==0 and
         all(type(a) is int and a>=b for a,b in zip(files['api_calls_4_to_9'][:5],final_event['file_api_calls'][4:9])),
         'host final file API counter regressed')
    need(host['steps']>=final_event['steps'] and host['switch_commits']>=final_event['switch_commits'],
         'final live Context counters regressed after continuation')
    return dict(callback_calls=callbacks['calls'],callback_returns=callbacks['returns'],
                user32_callbacks=user32['callbacks'],posted_dispatches=user32['posted_dispatches'],
                api_calls=user32['api_calls'],guest_steps=host['steps'],switch_commits=host['switch_commits'])


def validate_run(directory, build, audit):
    directory=Path(directory)
    run=audit.json(directory/'run.json')
    validate_receipt_contract(run,'OUTER_REPLAY_RUNS_OBSERVED_NOT_INDEPENDENTLY_ACCEPTED')
    need(run['schema']==1 and run['status']=='OUTER_REPLAY_RUNS_OBSERVED_NOT_INDEPENDENTLY_ACCEPTED' and
         run['input_kind']=='TEST_QUEUE_NOT_OS_KEYBOARD' and run['timing_enabled'] is False and run['replay_enabled'] is True and run['diagnostic_rounds']==2 and run['continuation_rounds']==1,
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
             command['cwd']==str(case) and command['env']['PE_AOT_OUTER_REPLAY_OUTPUT']==str(case/'diagnostic'),
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
        groups,ledger,last_event=validate_trace(case/'diagnostic',audit)
        final_host=validate_final_host(host,last_event)
        stderr=audit.data(case/'stderr').decode(errors='strict')
        producer=audit.json(build['producer'],build['producer_sha256'])
        for name in ('d3d11','dxgi','winemetal'):
            need(any('dyld['+str(execution['pid'])+']' in line and producer['backend'][name] in line
                     for line in stderr.splitlines()), 'actual backend load missing: '+name)
        summaries.append(dict(configuration=expected_name,pid=execution['pid'],groups=groups,selected_ledger=ledger,final_host_ledger=final_host,
                              native_exit=0,test_queue_events=3,save_sha256=digest(save)))
    return summaries


def reader_identities(audit):
    import sys
    old=Path(single.__file__).resolve()
    audit.data(old,BASELINE_READER_SHA)
    own=Path(__file__).resolve();audit.data(own)
    standard={}
    for name in ('argparse','hashlib','json','struct','pathlib'):
        path=Path(sys.modules[name].__file__).resolve()
        standard[str(path)]=digest(audit.data(path))
    executable=Path(sys.executable).resolve()
    return dict(project_sources={str(p):audit.files[str(p)]['sha256'] for p in (old,own)},
                direct_stdlib_sources=standard,python_executable=str(executable),
                python_executable_sha256=digest(audit.data(executable)),python_version=sys.version,
                scope='Reader-time direct implementation identities, not native compilation inputs or a complete transitive Python dependency closure.')


def review(build, run, out):
    build,run=Path(build).absolute(),Path(run).absolute()
    audit=Audit();declared=audit.json(build/'build.json')
    out=single.validate_output(out,[build,run,declared['product']])
    identities=reader_identities(audit)
    record=validate_build(build,audit);record['_directory']=build
    executions=validate_run(run,record,audit)
    audit.unchanged()
    result=dict(schema=1,status=STATUS,build=str(build),run=str(run),executions=executions,
                unique_files_read=len(audit.files),files=audit.files,reader_implementation=identities,
                timing_verified=False,replay_verified=True,diagnostic_rounds=2,continuation_rounds=1,
                cross_process_full_byte_equivalence=False,stack_below_outer_rsp_exact_oracle=False,
                same_process_diagnostic_guest_full_byte_equivalence=True,host_sessions_restored=False,
                outer_dispatcher_entry_and_ret_full_guest_transition_verified=True,
                independent_file_session_scope='LastError, nine API counters, bytes read/written only; full FileSession is checked by the frozen runtime guard, not independently exported.',
                scope='Two fixed-MSG diagnostic passes and one original-input continuation at each real Dispatch boundary. Same-address complete guest restore, same-process diagnostic guest byte equivalence, exact outer dispatcher-entry and import-RET full Context/State/guest transitions, real callback/DefWindowProc/RET and independently cumulative host counters. Other below-RSP stack has repeatability evidence, not an independent all-byte semantic oracle. Reused roots; no performance, full negative/budget matrix or production App claim.')
    with out.open('x') as file:json.dump(result,file,sort_keys=True,indent=2);file.write('\n')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build',required=True,type=Path)
    parser.add_argument('--run',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    print(json.dumps({k:v for k,v in review(args.build,args.run,args.out).items() if k not in ('files','executions')},sort_keys=True))
