"""Independent, read-only review of callback CPU evidence; never runs a process.

Raw stdout, response bytes, compiler commands/dependencies, source identities and
product/probe receipts are read directly. Runner validators are deliberately not
imported. This checks the bounded RIGHT/transaction experiment, not a Windows
ABI, a game, or the correctness of the entire translator.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import shlex
import statistics
import struct

ROOT = Path(__file__).resolve().parents[1]
BASES = (0x140000000, 0x180000000)
LEVELS = ('O0', 'O3')
STATE_SIZE, STACK_SIZE, MASK = 3504, 65536, (1 << 64)-1
INITIAL_RSP, EXIT_PC = 0x70000000+65536-0x108, 0x7fff00000000
REG_OFFSETS = (2216,2248,2264,2232,2312,2328,2280,2296,2344,2360,2376,2392,2408,2424,2440,2456,2472)
FLAGS = ((2065,0),(2067,2),(2069,4),(2071,6),(2073,7),(2077,11))
RUNTIME = ('window_switch_v1/runtime.h','window_switch_v1/runtime_fields.inc',
           'window_switch_v1/runtime_impl.inc','window_bridge/window_runtime/runtime.h',
           'window_bridge/window_runtime/transaction_v1.c','memory_stage2/guest_memory.h')
CASE_FIELDS = ('initial_position','position','moves','draws','keydowns','dirty',
               'status','returned','call_depth','steps','switch_commits','rejected_api_calls')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def integer(value, lower=0, upper=MASK):
    need(type(value) is int and lower <= value <= upper, 'invalid integer: '+repr(value))
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(data):
    def pairs(items):
        result = {}
        for key,value in items:
            need(key not in result, 'duplicate JSON key: '+key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('nonfinite JSON number: '+value)
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


class Audit:
    """Hash streaming large files; retain bytes only for small evidence reads."""
    def __init__(self):
        self.files = {}

    def file(self, path, expected=None):
        path = Path(path)
        need(path.is_absolute() and path.is_file(), 'missing absolute regular file: '+str(path))
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if expected is not None:
            need(type(expected) is str and len(expected)==64 and actual==expected, 'identity differs: '+str(path))
        if str(path) in self.files:
            need(self.files[str(path)]==actual, 'file changed during review: '+str(path))
        self.files[str(path)] = actual
        return actual

    def raw(self, path):
        path = Path(path)
        need(path.is_absolute() and path.is_file() and path.stat().st_size<=64*1024**2,
             'bounded regular evidence required: '+str(path))
        data = path.read_bytes()
        self.file(path, digest(data))
        return data

    def json(self, path):
        value = parse(self.raw(path))
        need(type(value) is dict, 'JSON object required: '+str(path))
        return value

    def mapping(self, values):
        need(type(values) is dict and bool(values), 'nonempty identity map required')
        for name,expected in values.items():
            self.file(name, expected)

    def finish(self):
        for path,expected in list(self.files.items()):
            self.file(path, expected)


def source_paths(audit):
    """Discover local static imports independently, without importing any code."""
    seeds = [ROOT/'window_callback_bench_v1'/name for name in ('__init__.py','__main__.py','runner.py')]
    pending,seen = list(seeds),set()
    def modules(parts):
        for i in range(1,len(parts)+1):
            initializer = ROOT.joinpath(*parts[:i])/'__init__.py'
            if initializer.is_file(): pending.append(initializer)
        module = ROOT.joinpath(*parts).with_suffix('.py')
        if module.is_file(): pending.append(module)
    while pending:
        path = pending.pop()
        if path in seen: continue
        seen.add(path)
        package = path.parent.relative_to(ROOT).parts
        for node in ast.walk(ast.parse(audit.raw(path), filename=str(path))):
            if isinstance(node,ast.Import):
                for item in node.names: modules(tuple(item.name.split('.')))
            elif isinstance(node,ast.ImportFrom):
                need(node.level<=len(package),'relative import escaped source root')
                base = package[:len(package)+1-node.level] if node.level else ()
                if node.module: base += tuple(node.module.split('.'))
                modules(base)
                for item in node.names:
                    if item.name!='*': modules((*base,item.name))
    return {str(p) for p in seen | {ROOT/'window_callback_bench_v1/benchmark.c',*(ROOT/p for p in RUNTIME)}}


def covered(mapping, paths, description):
    need(set(map(str,paths)) <= set(mapping), 'identity coverage missing: '+description)


def identities(audit, receipt):
    for kind in ('sources','inputs'):
        need(receipt[kind+'_before']==receipt[kind+'_after'], kind+' changed before/after')
        audit.mapping(receipt[kind+'_before'])
    need(set(receipt['sources_before'])==source_paths(audit), 'current static source closure differs')
    audit.mapping(receipt['artifacts'])


def commands(audit, receipt, directory, expected_labels):
    rows = receipt['commands']
    need(type(rows) is list and [r['label'] for r in rows]==expected_labels, 'command order/count differs')
    result = {}
    for row in rows:
        label = row['label']
        need(type(row['returncode']) is int and row['returncode']==0, 'failed command: '+label)
        need(row['cwd']==str(ROOT), 'command cwd differs')
        need(type(row['argv']) is list and all(type(v) is str for v in row['argv']), 'invalid command argv')
        for stream in ('stdout','stderr'):
            path = directory/(label+'.'+stream)
            need(row[stream+'_path']==str(path),'command log path differs')
            covered(receipt['artifacts'], [path], 'command log')
            audit.file(path,row[stream+'_sha256'])
        record = directory/(label+'.command.json')
        covered(receipt['artifacts'], [record], 'command receipt')
        need(audit.json(record)==row, 'command receipt differs')
        result[label] = row
    return result


def flags(state):
    return sum(int(state[offset]!=0)<<bit for offset,bit in FLAGS)


def registers(state):
    need(len(state)==STATE_SIZE, 'wrong State size')
    return [struct.unpack_from('<Q',state,offset)[0] for offset in REG_OFFSETS]


def response_word(payload, image_size, state_rva, result_rva, steps, switch_commits):
    need(len(payload)==STATE_SIZE+image_size+STACK_SIZE, 'response extent differs')
    state,image = payload[:STATE_SIZE],payload[STATE_SIZE:STATE_SIZE+image_size]
    regs = registers(state)
    position,moves = struct.unpack_from('<II',image,state_rva+8)
    keydowns = struct.unpack_from('<I',image,result_rva+12)[0]
    return (regs[0]^regs[4]^regs[16]^flags(state)^steps^(switch_commits<<8)^(position<<32)^moves^keydowns)&MASK


def reset_word(scenario):
    # Initial State is calloc(0) plus the seventeen seeded integer registers;
    # RAX/RIP remain seed values; initial flags/steps/switch/moves/keydowns are0.
    return (0xabc0000000000000 ^ INITIAL_RSP ^
            ((0xabc0000000000000+0x10101010101*16)&MASK) ^ (scenario<<32))&MASK


def golden_case(case, payload, original, state_rva, result_rva, scenario):
    """Check old raw observations against bytes and the restricted RIGHT contract."""
    image_size = len(original)
    need(len(payload)==STATE_SIZE+image_size+STACK_SIZE,'golden response extent differs')
    for key in CASE_FIELDS: integer(case[key])
    after,changed = min(scenario+1,7),int(scenario<7)
    expected = dict(initial_position=scenario,position=after,moves=changed,draws=0,
                    keydowns=1,dirty=changed,status=0,returned=1,call_depth=0,
                    switch_commits=1,rejected_api_calls=0)
    need(all(case[k]==v for k,v in expected.items()),'golden RIGHT semantics differ')
    need(case['setup_status']==case['trace_overflow']==0 and case['call_commits']==1 and
         case['ret_commits']==2 and case['max_call_depth']==1, 'golden transaction counters differ')
    need(case['fault']==dict(status=0,access=0,pc=0,address=0,width=0),'golden fault differs')
    trace = case['trace']
    need(type(trace) is list and len(trace)==integer(case['steps'],1), 'golden trace/steps differ')
    need(all(row['status']==0 for row in trace) and sum(r['kind']==5 for r in trace)==1 and
         sum(r['kind']==1 for r in trace)==1 and sum(r['kind']==2 for r in trace)==2, 'golden trace counters differ')
    need(all(a['next_pc']==b['pc'] and a['after_depth']==b['before_depth'] for a,b in zip(trace,trace[1:])),
         'golden trace continuity differs')
    state = payload[:STATE_SIZE]
    regs = registers(state)
    need(regs==case['registers'] and flags(state)==case['flags'],'golden register/flag stdout differs from bytes')
    need(regs[0]==0 and regs[4]==INITIAL_RSP+8 and regs[16]==EXIT_PC,'golden exit registers differ')
    for reg in (3,5,6,7,12,13,14,15):
        need(regs[reg]==0xabc0000000000000+0x10101010101*reg, 'golden nonvolatile register differs')
    image = bytearray(original)
    struct.pack_into('<II',image,state_rva+8,after,changed)
    struct.pack_into('<I',image,result_rva+12,1)
    struct.pack_into('<I',image,result_rva+56,changed)
    need(payload[STATE_SIZE:STATE_SIZE+image_size]==image, 'golden full image has unexpected effects')
    return response_word(payload,image_size,state_rva,result_rva,case['steps'],1)


def response(value, payloads, goldens, base, mode, iterations, rounds, image_size, state_rva, result_rva):
    """Validate one native stdout with byte responses; returns every sample."""
    integer(iterations,1,65536);integer(rounds,1,20)
    need(value['status']==('PASS_CALLBACK_CPU_CHECK' if mode=='check' else 'PASS_CALLBACK_CPU_MEASURE') and
         value['mode']==mode and value['base']==base,'native mode/base/status differs')
    for key,expected in dict(state_size=STATE_SIZE,image_size=image_size,stack_size=STACK_SIZE,
                             iterations=iterations,rounds=rounds,app_executions=0,gpu_executions=0).items():
        need(integer(value[key])==expected,'native scalar differs: '+key)
    context_size = integer(value['context_size'],1,1024*1024)
    need(integer(value['reset_bytes_per_iteration'])==STATE_SIZE+context_size+image_size+STACK_SIZE,'reset byte count differs')
    for key in ('reset_included','checksum_included','key_invariants_per_iteration','full_comparison_per_batch','reset_control_not_subtracted'):
        need(value[key] is True,'measurement scope differs: '+key)
    for key in ('lto','transaction_trace_hooks','outer_callback_abi_invoked'):
        need(value[key] is False,'measurement scope differs: '+key)
    need(value['legacy_block_fastpath']=='NOT_INTEGRATED','legacy fastpath incorrectly claimed')
    need(value['final_snapshot_capture']=='live final execute batch copied outside clocks into preallocated buffers; file IO after all timed batches',
         'timed final capture scope differs')
    need(value['wall_clock']=='CLOCK_MONOTONIC' and value['cpu_clock']=='CLOCK_THREAD_CPUTIME_ID' and
         value['clock_order']=='wall_start,cpu_start,batch,cpu_end,wall_end','clock definitions/order differ')
    measured = mode=='measure'
    timed = rounds*8*iterations if measured else 0
    untimed = 8+2048+rounds*8 if measured else 8
    expected_counts = dict(actual_callback_executions=timed+untimed,timed_callback_executions=timed,
                           untimed_callback_executions=untimed,reset_control_iterations=timed+untimed-8 if measured else 0,
                           all_reset_calls=2*timed+2*(untimed-8)+8,
                           timer_calls=rounds*16*4 if measured else 0,clock_resolution_queries=2 if measured else 0,
                           warmup_iterations_per_scenario_path=256 if measured else 0)
    for key,expected in expected_counts.items():
        need(integer(value[key])==expected,'execution count differs: '+key)
    for key in ('wall_resolution_ns','thread_cpu_resolution_ns'):
        need(integer(value[key])>0 if measured else integer(value[key])==0,'clock resolution differs')
    need(type(value['cases']) is list and len(value['cases'])==len(goldens)==8,'case count differs')
    expected_files = {'case-%d.bin'%i for i in range(8)}
    if measured: expected_files |= {'final-case-%d.bin'%i for i in range(8)}
    need(set(payloads)==expected_files,'response file coverage differs')
    for i,(case,gold) in enumerate(zip(value['cases'],goldens)):
        for key in CASE_FIELDS:
            need(integer(case[key])==gold['case'][key], 'native case differs: '+key)
        name = 'case-%d.bin'%i
        need(case['response']==name and payloads[name]==gold['payload'],'full callback response differs from golden')
        word = response_word(payloads[name],image_size,state_rva,result_rva,case['steps'],case['switch_commits'])
        need(integer(case['checksum'])==word and integer(case['reset_checksum'])==reset_word(i), 'case checksum differs from raw bytes')
        if measured:
            final = 'final-case-%d.bin'%i
            need(case['timed_final_response']==final and payloads[final]==gold['payload'],'timed final bytes differ from golden')
        else:
            need(case['timed_final_response'] is None,'untimed check claims timed final evidence')
    order = []
    for round_index in range(rounds if measured else 0):
        for offset in range(8):
            scenario = (round_index+offset)%8
            for position in range(2):
                order.append((round_index,scenario,'reset' if (round_index+scenario+position)&1 else 'execute'))
    need(type(value['records']) is list and len(value['records'])==len(order),'measurement record count differs')
    samples = []
    for row,identity in zip(value['records'],order):
        need((integer(row['round']),integer(row['scenario']),row['path'])==identity,'record order/identity differs')
        need(integer(row['iterations'],1)==iterations,'sample iteration count differs')
        scenario,path = row['scenario'],row['path']
        case = value['cases'][scenario]
        execute = path=='execute'
        expected_steps,expected_switch = (case['steps'],1) if execute else (0,0)
        need(integer(row['steps_per_iteration'])==expected_steps and integer(row['switch_commits_per_iteration'])==expected_switch and
             integer(row['rejected_api_calls'])==0 and row['complete_post_batch_match'] is True,'sample transaction result differs')
        if 'errors' in row: need(integer(row['errors'])==0,'sample errors reported')
        word = case['checksum' if execute else 'reset_checksum']
        need(integer(row['checksum'])==(word*iterations)&MASK,'sample checksum differs')
        wall,cpu = integer(row['wall_ns'],1),integer(row['thread_cpu_ns'],1)
        # CPU and wall are separate sampled clocks; report any inversion and
        # its extent, rather than rejecting small quantization/accounting edges.
        samples.append(dict(base=base,**row,wall_ns_per_iteration=wall/iterations,
                            thread_cpu_ns_per_iteration=cpu/iterations,cpu_exceeds_wall_ns=max(cpu-wall,0)))
    return samples


def exact_summary(actual, expected):
    """JSON booleans must never masquerade as a numeric summary field."""
    need(type(actual) is type(expected), 'summary field type differs')
    if isinstance(expected, dict):
        need(set(actual)==set(expected), 'summary keys differ')
        for key in expected: exact_summary(actual[key],expected[key])
    elif isinstance(expected, list):
        need(len(actual)==len(expected), 'summary length differs')
        for first,second in zip(actual,expected): exact_summary(first,second)
    else:
        need(actual==expected, 'recorded summary differs from all raw samples')


def summarize(samples):
    result = []
    for base in BASES:
        for scenario in range(8):
            for path in ('execute','reset'):
                group = [r for r in samples if (r['base'],r['scenario'],r['path'])==(base,scenario,path)]
                if not group: continue
                item = dict(base=base,scenario=scenario,path=path,samples=len(group))
                for clock in ('wall_ns','thread_cpu_ns'):
                    numbers = [r[clock]/r['iterations'] for r in group]
                    item[clock+'_per_iteration'] = dict(median=statistics.median(numbers),min=min(numbers),max=max(numbers))
                result.append(item)
    return result


def native_file(audit, path, filetype):
    raw = audit.raw(path)
    need(len(raw)>=32 and struct.unpack_from('<II',raw)==(0xfeedfacf,0x100000c) and
         struct.unpack_from('<I',raw,12)[0]==filetype,'expected thin ARM64 Mach-O')


def reference(audit, ready):
    """Read frozen correctness evidence, never let its PASS replace new checks."""
    binding = ready['binding']
    product,probe = Path(ready['product']),Path(ready['probe'])
    need(binding['product']==str(product) and binding['probe']==str(probe),'binding paths differ')
    audit.file(product/'result.json',binding['product_receipt_sha256'])
    audit.file(probe/'result.json',binding['probe_receipt_sha256'])
    app,old = audit.json(product/'result.json'),audit.json(probe/'result.json')
    need(app['profile']=='window-switch-v6' and app['stage']=='complete','unexpected product profile')
    for relative,entry in app['files'].items():
        path = product/relative
        need(not Path(relative).is_absolute() and '..' not in Path(relative).parts,'product file escaped')
        audit.file(path,entry['sha256'])
        need(path.stat().st_mode&0o777==entry['mode'],'product file mode differs')
    audit.mapping(app['sources'])
    need(old['status']=='PASS_REAL_ARM64_CALLBACK_TWO_BASES_O0_O3' and old['app']==str(product) and
         old['successful_callbacks']==old['translated_callback_executions']==32 and
         old['api_calls']==old['cocoa_app_executions']==old['gpu_executions']==0,'reference scope differs')
    need(old['inputs_before']==old['inputs_after'],'reference inputs changed')
    for field in ('inputs_before','generated_inputs','compiler','actual_compiler_dependencies'):
        audit.mapping(old[field])
    for name,sha in old['sources'].items(): audit.file(probe/'sources'/name,sha)
    core = [product/'result.json',probe/'result.json',product/'native/input.exe',product/'native/profile.json',
            product/'native/producer.json',product/'native/compiler/window-proc-1000/manifest.json']
    covered(ready['inputs_before'],core,'product core')
    covered(binding['inputs'],core,'binding core')
    audit.mapping(binding['inputs'])
    need(all(ready['inputs_before'].get(k)==v for k,v in binding['inputs'].items()),'binding inputs not preserved')
    config = audit.json(product/'native/profile.json')
    state_rva,result_rva = (config['observations'][name]['rva'] for name in ('window_state','window_result'))
    root = audit.json(product/'native/compiler/window-proc-1000/manifest.json')
    native = audit.json(product/'native/producer.json')
    need(native['compile_inputs_before']==native['compile_inputs_after'],'product compile inputs changed')
    audit.mapping(native['compile_inputs_before'])
    need(root['input_sha256']==old['pe_sha256']==audit.file(product/'native/input.exe') and
         root['root_rva']==0x1000 and root['symbol']=='aot_window_proc_1000','product callback identity differs')
    for name in RUNTIME:
        actual = audit.file(ROOT/name)
        matches = [(p,h) for p,h in native['compile_inputs_before'].items() if p.endswith('/'+name)]
        need(len(matches)==1 and matches[0][1]==actual==old['native_runtime_identities'][name]==old['sources'][name],
             'runtime differs between product/reference/benchmark: '+name)
    need(not any('/window_block_fast_v1/' in p or '/window_block_session_v1/' in p for p in native['compile_inputs_before']),
         'legacy fastpath now integrated; benchmark scope requires a new review')
    ir_path = product/'native/compiler/window-proc-1000/arm64.ll'
    ir = audit.raw(ir_path)
    need(not any(marker in ir for marker in (b'aot_try_wnd_prefix_v1',b'aot_finish_wnd_prefix_v1',b'wbs_scope_enter')),
         'lifted object may contain legacy fastpath')
    for level,name in (('O0','arm64-o0.o'),('O3','arm64.o')):
        path = product/'native/compiler/window-proc-1000'/name
        need(binding['objects'][level]==root['objects'][level]['path']==str(path),'object path differs')
        audit.file(path,root['objects'][level]['sha256']);native_file(audit,path,1)
        need(audit.raw(path)==audit.raw(probe/'inputs'/(level+'.o')),'reference used different object')
        covered(ready['inputs_before'],[path],'real product object')
    need(len(old['records'])==4 and set(binding['goldens'])=={label+'-'+level for label in ('preferred','rebased') for level in LEVELS},
         'reference matrix differs')
    all_goldens = {}
    image_size = integer(binding['image_size'],1,64*1024**2)
    for base,label in zip(BASES,('preferred','rebased')):
        original = audit.raw(probe/(label+'-image.bin'))
        need(len(original)==image_size and struct.unpack_from('<5I',original,state_rva)==(0x31574f43,1,3,0,0) and
             original[result_rva:result_rva+60]==bytes(60),'reference mapped image initialization differs')
        for level in LEVELS:
            key = label+'-'+level
            rows = [r for r in old['records'] if (r['base'],r['optimization'])==(base,level)]
            need(len(rows)==1 and rows[0]['parsed']==str(probe/key/'parsed.json'),'reference duplicate/missing record')
            audit.file(probe/key/'parsed.json',rows[0]['parsed_sha256'])
            rows = [r for r in old['commands'] if r['label']==key+'-run']
            need(len(rows)==1 and type(rows[0]['returncode']) is int and rows[0]['returncode']==0,'reference run missing/failed')
            command = rows[0]
            for stream in ('stdout','stderr'):
                path = probe/(key+'-run.'+stream)
                need(command[stream+'_path']==str(path),'reference log path differs')
                audit.file(path,command[stream+'_sha256'])
            raw,parsed = audit.json(probe/(key+'-run.stdout')),audit.json(probe/key/'parsed.json')
            need(raw['base']==parsed['base']==base and raw['state_size']==STATE_SIZE and
                 raw['image_size']==image_size and raw['stack_size']==STACK_SIZE and len(raw['cases'])==len(parsed['cases'])==8,
                 'reference raw shape differs')
            need({k:v for k,v in raw.items() if k!='cases'}=={k:v for k,v in parsed.items() if k!='cases'},'reference raw/parsed top-level differs')
            golden = []
            need(len(binding['goldens'][key])==8,'binding golden count differs')
            for index,(case,recorded,bound) in enumerate(zip(raw['cases'],parsed['cases'],binding['goldens'][key])):
                path = probe/key/('case-%d.bin'%index);payload = audit.raw(path)
                expected_recorded = dict(case,response_path=str(path),response_sha256=digest(payload),
                    state_sha256=digest(payload[:STATE_SIZE]),image_sha256=digest(payload[STATE_SIZE:STATE_SIZE+image_size]),
                    stack_sha256=digest(payload[STATE_SIZE+image_size:]))
                need(recorded==expected_recorded and bound==dict(path=str(path),sha256=digest(payload),case=case),
                     'reference raw/parsed/bound case differs')
                covered(ready['inputs_before'],[path,probe/(key+'-run.stdout'),probe/key/'parsed.json'],'original golden')
                golden_case(case,payload,original,state_rva,result_rva,index)
                golden.append(dict(case=case,payload=payload))
            all_goldens[key] = golden
        need([g['payload'] for g in all_goldens[label+'-O0']]==[g['payload'] for g in all_goldens[label+'-O3']],
             'reference O0/O3 complete state differs')
    return all_goldens,image_size,state_rva,result_rva


def collect_response(audit, receipt, directory, descriptor, command, golden, image_size, state_rva, result_rva,
                     mode, iterations, rounds):
    label,level,base = descriptor['label'],descriptor['optimization'],descriptor['base']
    output = directory/(label+'-'+level if mode=='check' else label)
    stem = ('check-'+label+'-'+level if mode=='check' else 'measure-'+label)
    need(descriptor['output']==str(output) and descriptor['parsed']==str(output/'parsed.json') and
         descriptor['stdout']==str(directory/(stem+'.stdout')),'run paths differ')
    raw = audit.json(directory/(stem+'.stdout'))
    need(raw==audit.json(output/'parsed.json'),'raw stdout/parsed response differs')
    covered(receipt['artifacts'],[output/'parsed.json'],'parsed response')
    files = {'case-%d.bin'%i for i in range(8)}
    if mode=='measure': files |= {'final-case-%d.bin'%i for i in range(8)}
    covered(receipt['artifacts'],[output/name for name in files],'full binary responses')
    payloads = {name:audit.raw(output/name) for name in files}
    return response(raw,payloads,golden,base,mode,iterations,rounds,image_size,state_rva,result_rva)


def review(prepared, measured=None, audit=None):
    audit = audit or Audit()
    prepared = Path(prepared).resolve(strict=True)
    ready = audit.json(prepared/'result.json')
    need(ready['schema']==1 and ready['status']=='PASS_CALLBACK_BENCH_PREPARED' and ready['out']==str(prepared),
         'preparation receipt differs')
    need(ready['correctness_callbacks']==32 and ready['timed_callback_executions']==ready['app_executions']==ready['gpu_executions']==0,
         'preparation counters differ')
    identities(audit,ready)
    goldens,image_size,state_rva,result_rva = reference(audit,ready)
    labels = ['compiler-path','sdk-path','compiler-version','dependencies','compile-O0','compile-O3','dependencies-after']
    labels += ['check-'+label+'-'+level for label in ('preferred','rebased') for level in LEVELS]
    command = commands(audit,ready,prepared,labels)
    need(command['compiler-path']['argv']==['/usr/bin/xcrun','--find','clang'] and
         command['sdk-path']['argv']==['/usr/bin/xcrun','--show-sdk-path'],'compiler/SDK lookup differs')
    compiler = audit.raw(prepared/'compiler-path.stdout').decode().strip()
    sdk = audit.raw(prepared/'sdk-path.stdout').decode().strip()
    covered(ready['inputs_before'],[compiler,Path(sdk)/'SDKSettings.json'],'compiler and SDK')
    need(command['compiler-version']['argv']==[compiler,'--version'],'compiler version command differs')
    copies = prepared/'inputs'
    for name in ('callback_probe_input.h','preferred-image.bin','preferred-permissions.bin','rebased-image.bin','rebased-permissions.bin'):
        covered(ready['artifacts'],[copies/name],'copied input')
        need(audit.raw(copies/name)==audit.raw(Path(ready['probe'])/name),'copied input differs')
    source = ROOT/'window_callback_bench_v1/benchmark.c'
    flags = [compiler,'-std=c11','-arch','arm64','-isysroot',sdk,'-O3','-Wall','-Wextra','-Werror',
             '-DAOT_WINDOW_SWITCH_V1=1','-I',str(copies),'-I',str(ROOT/'window_switch_v1')]
    deps = audit.raw(prepared/'dependencies.stdout')
    need(deps.startswith(b'bench:') and deps==audit.raw(prepared/'dependencies-after.stdout'),'dependency output changed')
    paths = {str(Path(name).resolve(strict=True)) for name in shlex.split(deps.decode().replace('\\\n',' ').split(':',1)[1])}
    need(set(ready['compiler_dependencies'])==paths,'actual compiler dependency coverage differs')
    covered(ready['compiler_dependencies'],[source,copies/'callback_probe_input.h',*(ROOT/p for p in RUNTIME)],'compiler dependency closure')
    audit.mapping(ready['compiler_dependencies'])
    for label in ('dependencies','dependencies-after'):
        need(command[label]['argv']==flags+['-M','-MT','bench',str(source)],'dependency command differs')
    need(set(ready['binaries'])==set(LEVELS),'prepared binary set differs')
    for level in LEVELS:
        binary = prepared/('benchmark-'+level)
        need(ready['binaries'][level]==str(binary),'prepared binary path differs')
        covered(ready['artifacts'],[binary,copies/(level+'.o')],'benchmark binary/object')
        need(audit.raw(copies/(level+'.o'))==audit.raw(ready['binding']['objects'][level]),'copied object differs')
        native_file(audit,binary,2)
        need(command['compile-'+level]['argv']==flags+[str(source),str(copies/(level+'.o')),'-o',str(binary)],'actual compile command differs')
    expected = [(label,base,level) for base,label in zip(BASES,('preferred','rebased')) for level in LEVELS]
    need([(r['label'],r['base'],r['optimization']) for r in ready['checks']]==expected,'prepared case matrix differs')
    for row in ready['checks']:
        label,level,base = row['label'],row['optimization'],row['base']
        cmd = command['check-'+label+'-'+level]
        argv = [ready['binaries'][level],'--check',str(copies/(label+'-image.bin')),str(copies/(label+'-permissions.bin')),
                hex(base),str(prepared/(label+'-'+level)),'1','1']
        need(cmd['argv']==argv,'check command differs')
        collect_response(audit,ready,prepared,row,cmd,goldens[label+'-'+level],image_size,state_rva,result_rva,'check',1,1)
    samples = []
    if measured is not None:
        measured = Path(measured).resolve(strict=True)
        result = audit.json(measured/'result.json')
        need(result['schema']==1 and result['status']=='PASS_CALLBACK_CPU_BASELINE_MEASURED' and result['out']==str(measured) and
             result['prepared']==str(prepared) and result['prepared_receipt_sha256']==audit.file(prepared/'result.json'),
             'measurement preparation binding differs')
        identities(audit,result)
        need(result['sources_before']==ready['sources_before'] and result['inputs_before']==ready['inputs_before'],
             'measured source/input identity differs from preparation')
        need(result['reset_included'] is True and result['reset_subtracted'] is False and
             result['app_executions']==result['gpu_executions']==0,'measurement scope differs')
        iterations,rounds = integer(result['iterations'],1,65536),integer(result['rounds'],1,20)
        command = commands(audit,result,measured,['measure-preferred','measure-rebased'])
        need([(r['label'],r['base'],r['optimization']) for r in result['runs']]==
             [(label,base,'O3') for base,label in zip(BASES,('preferred','rebased'))],'measure matrix differs')
        for row in result['runs']:
            label,base = row['label'],row['base'];cmd = command['measure-'+label]
            argv = [ready['binaries']['O3'],'--measure',str(copies/(label+'-image.bin')),str(copies/(label+'-permissions.bin')),
                    hex(base),str(measured/label),str(iterations),str(rounds)]
            need(cmd['argv']==argv,'measure command differs')
            samples += collect_response(audit,result,measured,row,cmd,goldens[label+'-O3'],image_size,state_rva,result_rva,
                                        'measure',iterations,rounds)
        exact_summary(result['summary'],summarize(samples))
    audit.file(Path(__file__).resolve())
    audit.finish()
    return dict(schema=1,status='PASS_INDEPENDENT_CALLBACK_CPU_REVIEW' if measured else 'PASS_INDEPENDENT_CALLBACK_PREPARATION_REVIEW',
        prepared=str(prepared),measured=str(measured) if measured else None,correctness_responses=32,
        timed_final_responses=16 if measured else 0,raw_measurement_records=len(samples),samples=samples,summary=summarize(samples),
        performance_clock_status='CLOCK_ANOMALY_REQUIRES_REVIEW' if any(r['cpu_exceeds_wall_ns'] for r in samples) else 'NO_CLOCK_INVERSION_OBSERVED',
        clock_inversions=[{k:r[k] for k in ('base','round','scenario','path','wall_ns','thread_cpu_ns','cpu_exceeds_wall_ns')}
                          for r in samples if r['cpu_exceeds_wall_ns']],
        audited_files=dict(sorted(audit.files.items())),native_executions_by_reviewer=0,timer_calls_by_reviewer=0,
        reset_subtracted=False,slow_samples_removed=0,legacy_block_fastpath='NOT_INTEGRATED',
        limitations=['RIGHT at eight initial positions only; actual lifted O0/O3 objects and transaction runtime.',
                     'Measured O3 reset + transaction execution + checksum and per-iteration invariant checks.',
                     'Full State/image/stack compared for32 prechecks and16 final timed outcomes; private Context comparison is a C assertion, not serialized.',
                     'Each timed iteration checks key invariants; full binary equality is checked at batch boundaries, not after every iteration.',
                     'CPU clock exceeding wall is reported verbatim, not silently removed; no reset subtraction or claimed optimization gain.',
                     'No outer callback ABI dispatcher, Cocoa, GPU, game, Wine, Rosetta or general migration performance acceptance.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared',required=True)
    parser.add_argument('--measured')
    parser.add_argument('--out',required=True,help='Fresh report JSON outside input evidence directories')
    args = parser.parse_args()
    out = Path(args.out).absolute()
    need(out==out.resolve() and not out.exists(),'fresh real report path required')
    for value in (args.prepared,args.measured):
        if value: need(not out.is_relative_to(Path(value).resolve()),'report overlaps immutable evidence')
    audit = Audit()
    try:
        report = review(args.prepared,args.measured,audit)
    except (ValueError,KeyError,TypeError,OSError,struct.error) as error:
        report = dict(schema=1,status='REVIEW_FAILED_NOT_ACCEPTED',error=str(error),
                      audited_files=audit.files,native_executions_by_reviewer=0,timer_calls_by_reviewer=0)
        with out.open('x') as stream: json.dump(report,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n')
        raise
    with out.open('x') as stream: json.dump(report,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n')
    print(json.dumps({k:report[k] for k in ('status','raw_measurement_records','correctness_responses','timed_final_responses')}))


if __name__=='__main__':
    main()
