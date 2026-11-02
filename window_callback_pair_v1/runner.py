"""Prepare a constrained runtime overlay and measure paired lookup strategies.

The existing v1 preparation reader remains the authority for product provenance
and original probe goldens. This module adds only the exact lookup overlay,
clock probe, paired native checks and raw paired record validation.
"""
from pathlib import Path
import json
import shlex
import shutil
import statistics
import struct
import sys
import traceback

from window_callback_bench_v1 import runner as baseline
from portable_app_v1.lift import source_closure

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT/'window_callback_pair_v1'
RUNTIME = 'window_bridge/window_runtime/transaction_v1.c'
ORIGINAL_LOOKUP = '''static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    AotInstruction key={(uint32_t)(pc-ctx->module_base),0,0,0,0};
    return bsearch(&key,ctx->instructions,ctx->instruction_count,sizeof key,compare_instruction);
}
'''
PREPARED = 'PASS_LOOKUP_PAIR_PREPARED'
MEASURED = 'PASS_LOOKUP_PAIR_RAW_MEASURED'
require, read, parse, write = baseline.require, baseline.read, baseline.parse, baseline.write
sha, identities, unchanged = baseline.sha, baseline.identities, baseline.unchanged
BASES = baseline.BASES
MASK = (1 << 64)-1


def sources():
    python = [MODULE/name for name in ('__init__.py','__main__.py','runner.py')]
    native = [MODULE/name for name in ('benchmark.c','lookup_impl.inc','lookup_bounds.inc','clock_probe.c')]
    return identities([*source_closure(python), *native, *(ROOT/n for n in baseline.RUNTIME)])


def overlay_bytes(runtime, replacement):
    """Replace exactly one known function; all other runtime bytes are frozen."""
    anchor = ORIGINAL_LOOKUP.encode()
    require(runtime.count(anchor) == 1, 'original instruction lookup anchor differs')
    require(replacement.startswith(b'static const AotInstruction *instruction(') and
            replacement.endswith(b'\n'), 'replacement must be a complete lookup function')
    return runtime.replace(anchor, replacement, 1)


def generated_overlay():
    result = {name:(ROOT/name).read_bytes() for name in baseline.RUNTIME}
    result[RUNTIME] = overlay_bytes(result[RUNTIME], (MODULE/'lookup_impl.inc').read_bytes())
    return result


def dependencies(raw):
    require(raw.startswith(b'pair:'), 'unexpected compiler dependency target')
    return [Path(p).resolve(strict=True) for p in shlex.split(raw.decode().replace('\\\n',' ').split(':',1)[1])]


def bounded(iterations, rounds):
    require(type(iterations) is int and 1 <= iterations <= 65536, 'iterations must be integer 1..65536')
    require(type(rounds) is int and 1 <= rounds <= 20, 'rounds must be integer 1..20')


def native_binary(path):
    require(Path(path).read_bytes()[:8] == struct.pack('<II',0xfeedfacf,0x100000c), 'native ARM64 Mach-O required')


def integer(value, minimum=0, maximum=MASK):
    require(type(value) is int and minimum <= value <= maximum, 'invalid bounded integer')
    return value


def validate_clock(value):
    require(value['schema']==1 and value['status']=='CLOCK_OBSERVATIONS_RECORDED' and
            value['read_pairs_per_clock']==128 and value['windows_per_wall_clock']==16 and
            value['work_iterations']==65536 and value['warmup_work_calls']==1 and
            value['sample_order']=='wall_start,cpu_start,work,cpu_end,wall_end', 'clock probe contract differs')
    integer(value['timebase_numer'],1); integer(value['timebase_denom'],1)
    expected=0x29dff4c8a1076e35
    for i in range(65536): expected=((expected^(i+0x9e3779b97f4a7c15))*0xbf58476d1ce4e5b9)&MASK
    require(integer(value['work_checksum'])==expected,'clock workload checksum differs')
    names=('CLOCK_MONOTONIC','CLOCK_MONOTONIC_RAW','CLOCK_UPTIME_RAW','CLOCK_THREAD_CPUTIME_ID')
    require([r['name'] for r in value['clocks']]==list(names),'clock inventory differs')
    anomalies=[]
    for index,clock in enumerate(value['clocks']):
        integer(clock['resolution_ns'],1)
        require(len(clock['adjacent_reads'])==128,'clock read count differs')
        last=0
        for pair in clock['adjacent_reads']:
            require(len(pair)==2 and integer(pair[0])>=last and integer(pair[1])>=pair[0],'clock is not monotonic')
            last=pair[1]
        require(len(clock['work_windows'])==(16 if index<3 else 0),'clock work count differs')
        for round_index,window in enumerate(clock['work_windows']):
            require(window['round']==round_index and integer(window['checksum'])==expected,'clock work identity differs')
            wall=integer(window['wall_end'])-integer(window['wall_start'])
            cpu=integer(window['cpu_end'])-integer(window['cpu_start'])
            require(wall>0 and cpu>0,'clock work interval is nonpositive')
            if cpu>wall: anomalies.append(dict(clock=clock['name'],round=round_index,cpu_exceeds_wall_ns=cpu-wall))
    return dict(status='SELF_MONOTONIC_WORKLOAD_VALIDATED_NOT_ACCURACY_CALIBRATED',
                selected_wall_clock='CLOCK_MONOTONIC_RAW',cpu_exceeds_wall=anomalies)


def lookup_expected(base, table):
    contexts=[(base,[(r['rva'],r['length']) for r in table])]
    for start in (0,0x140000000,0x180000000,MASK-0xffffffff):
        for count in (1,2,3,7,8,9,31,32,33,127,256,1024):
            contexts.append((start,[(7+i*17,i%15+1) for i in range(count)]))
        contexts.append((start,[(0xfffffffe,1),(0x7fffffff,1),(0xfffffff0,14),(0,1),(2,1)]))
    total=hits=0
    for start,entries in contexts:
        queries=[0,MASK,start]
        if start:queries.append(start-1)
        if start<=MASK-0xffffffff:queries.append(start+0xffffffff)
        if start<MASK-0xffffffff:queries.append(start+0x100000000)
        addresses={start+rva for rva,_ in entries}
        for rva,length in sorted(entries):
            pc=start+rva
            if pc:queries.append(pc-1)
            queries.extend(pc+offset for offset in range(length+1))
        random=0x91e10da5
        for _ in range(2048):
            random^=(random<<13)&0xffffffff;random^=random>>17;random^=(random<<5)&0xffffffff
            if start<=MASK-random:queries.append(start+random)
        total+=len(queries);hits+=sum(pc in addresses for pc in queries)
    return dict(contexts=len(contexts),queries=total,hits=hits,misses=total-hits)


def record_order(rounds):
    for round_index in range(rounds):
        for offset in range(8):
            scenario=(round_index+offset)%8;reset_slot=4 if (round_index+scenario)&1 else 0
            for slot in range(5):
                if slot==reset_slot:yield round_index,scenario,slot,'reset','none'
                else:
                    execute_slot=slot-int(reset_slot==0)
                    mode=(round_index&1) if execute_slot in (0,3) else 1-(round_index&1)
                    yield round_index,scenario,slot,'execute',('reference','candidate')[mode]


def validate_response(value, directory, goldens, base, mode, iterations, rounds, table):
    bounded(iterations,rounds);directory=Path(directory);measuring=mode=='measure'
    require(mode in ('check','measure'),'unknown mode')
    require(value['status']==('PASS_CALLBACK_PAIR_MEASURE' if measuring else 'PASS_CALLBACK_PAIR_CHECK') and
            value['mode']==mode and value['base']==base and value['iterations']==iterations and value['rounds']==rounds,'pair response identity differs')
    for name,expected in [('state_size',3504),('context_size',5792),('image_size',20480),('stack_size',65536),('reset_bytes_per_iteration',95312),('app_executions',0),('gpu_executions',0)]:
        require(integer(value[name])==expected,'pair shape/scope differs: '+name)
    for name in ('reset_included','checksum_included','key_invariants_per_iteration','full_comparison_per_batch','reset_control_not_subtracted'):
        require(value[name] is True,'pair inclusion policy differs')
    for name in ('lto','transaction_trace_hooks','outer_callback_abi_invoked'):require(value[name] is False,'pair scope differs')
    require(value['legacy_block_fastpath']=='NOT_INTEGRATED' and value['wall_clock']=='CLOCK_MONOTONIC_RAW' and
            value['cpu_clock']=='CLOCK_THREAD_CPUTIME_ID' and value['clock_order']=='wall_start,cpu_start,batch,cpu_end,wall_end' and
            value['strategy_dispatch']=='shared volatile mode load and branch per valid instruction lookup' and
            value['pair_order']=='ABBA even rounds, BAAB odd rounds; reset before/after by round+scenario parity','pair clock/strategy contract differs')
    require(len(value['cases'])==16,'normal pair matrix differs')
    cases={}
    for case,(scenario,lookup_mode) in zip(value['cases'],[(i,m) for i in range(8) for m in ('reference','candidate')]):
        require(case['lookup_mode']==lookup_mode,'normal strategy order differs')
        golden=goldens[scenario]
        for name in ('initial_position','position','moves','draws','keydowns','dirty','status','returned','call_depth','steps','switch_commits','rejected_api_calls'):
            require(integer(case[name])==golden['case'][name],'normal callback semantics differ: '+name)
        response='case-%s-%d.bin'%(lookup_mode,scenario)
        require(case['response']==response and (directory/response).read_bytes()==Path(golden['path']).read_bytes(),'full normal State/image/stack differs')
        integer(case['checksum']);integer(case['reset_checksum']);cases[scenario,lookup_mode]=case
        final='final-case-%s-%d.bin'%(lookup_mode,scenario)
        if measuring:
            require(case['timed_final_response']==final and (directory/final).read_bytes()==Path(golden['path']).read_bytes(),'actual timed final bytes differ')
        else:require(case['timed_final_response'] is None,'untimed check has final timed response')
    for scenario in range(8):
        for key in ('checksum','reset_checksum'):require(cases[scenario,'reference'][key]==cases[scenario,'candidate'][key],'strategies have different checksum')
    budget_count=0 if measuring else sum(g['case']['steps']+1 for g in goldens)
    require(len(value['budget_checks'])==budget_count,'budget matrix count differs')
    budget_matrix=[] if measuring else [(i,b) for i,g in enumerate(goldens) for b in range(g['case']['steps']+1)]
    for row,(scenario,budget) in zip(value['budget_checks'],budget_matrix):
        gold=goldens[scenario]['case'];stopped=budget<gold['steps'];pc=gold['trace'][budget]['pc'] if stopped else 0
        expected_fault=dict(status=4,access=0,pc=pc,address=pc,width=0) if stopped else dict(status=0,access=0,pc=0,address=0,width=0)
        require(row['scenario']==scenario and integer(row['budget'])==integer(row['steps'])==budget and
                row['status']==(4 if stopped else 0) and row['returned']==int(not stopped) and
                row['call_depth']==(gold['trace'][budget]['before_depth'] if stopped else 0) and
                row['fault']==expected_fault and row['full_state_context_image_stack_equal'] is True,'budget fault/equivalence differs')
        integer(row['checksum'])
        if not stopped:require(row['checksum']==cases[scenario,'reference']['checksum'],'complete budget checksum differs')
    require(value['lookup_checks']==(dict(contexts=0,queries=0,hits=0,misses=0) if measuring else lookup_expected(base,table)), 'lookup boundary matrix differs')
    timed=rounds*8*4*iterations if measuring else 0
    untimed=16+(4096+rounds*8*4 if measuring else 2*budget_count)
    reset=2048+rounds*8*(iterations+1) if measuring else 0
    counts=dict(actual_callback_executions=timed+untimed,timed_callback_executions=timed,untimed_callback_executions=untimed,
                reset_control_iterations=reset,all_reset_calls=timed+untimed+reset+8,
                timer_calls=rounds*8*5*4 if measuring else 0,clock_resolution_queries=2 if measuring else 0,
                warmup_iterations_per_scenario_path=256 if measuring else 0)
    for name,expected in counts.items():require(integer(value[name])==expected,'execution count differs: '+name)
    for name in ('wall_resolution_ns','thread_cpu_resolution_ns'):
        require(integer(value[name])>0 if measuring else integer(value[name])==0,'clock resolution differs')
    require(len(value['records'])==(rounds*8*5 if measuring else 0),'raw record count differs')
    for row,identity in zip(value['records'],record_order(rounds if measuring else 0)):
        require(tuple(row[k] for k in ('round','scenario','order_slot','path','lookup_mode'))==identity,'pair record order differs')
        scenario=row['scenario'];execute=row['path']=='execute';case=cases[scenario,'reference']
        for name in ('round','scenario','order_slot','iterations','wall_ns','thread_cpu_ns','checksum','steps_per_iteration','switch_commits_per_iteration','rejected_api_calls'):integer(row[name])
        require(row['iterations']==iterations and row['wall_ns']>0 and row['thread_cpu_ns']>0 and
                row['checksum']==(case['checksum' if execute else 'reset_checksum']*iterations)&MASK and
                row['steps_per_iteration']==(case['steps'] if execute else 0) and row['switch_commits_per_iteration']==int(execute) and
                row['rejected_api_calls']==0 and row['complete_post_batch_match'] is True,'raw batch check differs')


def compiler_flags(compiler, sdk, out, old):
    return [compiler,'-std=c11','-arch','arm64','-isysroot',sdk,'-O3','-Wall','-Wextra','-Werror',
            '-DAOT_WINDOW_SWITCH_V1=1','-I',str(out/'sources'),'-I',str(old/'inputs'),'-I',str(MODULE)]


def prepare(baseline_prepared, out):
    baseline.native_host();old=Path(baseline_prepared).resolve(strict=True)
    ready=baseline.verify_prepared(old);old_receipt=sha(old/'result.json');before=sources()
    out=baseline.fresh(out,[old,ready['product'],ready['probe']]);commands=baseline.Commands(out);checks=[]
    write(out/'started.json',dict(status='PREPARING_NOT_ACCEPTED',baseline_prepared=str(old),baseline_receipt_sha256=old_receipt,sources=before))
    try:
        for name,data in generated_overlay().items():
            path=out/'sources'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        generated=identities(out/'sources'/name for name in baseline.RUNTIME)
        compiler=commands.run(['/usr/bin/xcrun','--find','clang'],'compiler-path').decode().strip()
        sdk=commands.run(['/usr/bin/xcrun','--show-sdk-path'],'sdk-path').decode().strip()
        require(Path(compiler).is_absolute() and Path(compiler).is_file() and Path(sdk).is_dir(),'compiler/SDK absent')
        commands.run([compiler,'--version'],'compiler-version')
        tools=identities([Path(compiler),Path(sys.executable).resolve(),Path(sdk)/'SDKSettings.json'])
        flags=compiler_flags(compiler,sdk,out,old);dependency_hashes={};dependency_logs={};binaries={}
        for name,source in [('pair',MODULE/'benchmark.c'),('clock',MODULE/'clock_probe.c')]:
            raw=commands.run([*flags,'-M','-MT','pair',source],'dependencies-'+name)
            dependency_logs[name]=raw;deps=dependencies(raw)
            require(source in deps,'missing benchmark compiler dependency')
            if name=='pair':
                require({*(out/'sources'/n for n in baseline.RUNTIME),old/'inputs/callback_probe_input.h',
                         MODULE/'lookup_bounds.inc'}<=set(deps),'missing pair runtime dependency')
            dependency_hashes.update(identities(deps))
        for level in ('O0','O3'):
            binary=out/('benchmark-'+level)
            commands.run([*flags,MODULE/'benchmark.c',old/'inputs'/(level+'.o'),'-o',binary],'compile-'+level)
            native_binary(binary);binaries[level]=str(binary)
        clock_binary=out/'clock-probe'
        commands.run([*flags,MODULE/'clock_probe.c','-o',clock_binary],'compile-clock');native_binary(clock_binary)
        for name,source in [('pair',MODULE/'benchmark.c'),('clock',MODULE/'clock_probe.c')]:
            require(commands.run([*flags,'-M','-MT','pair',source],'dependencies-after-'+name)==dependency_logs[name],
                    'compiler dependencies changed')
        raw=commands.run([clock_binary],'clock-probe');clock_value=parse(raw)
        clock_assessment=validate_clock(clock_value);write(out/'clock-parsed.json',clock_value)
        for base in BASES:
            label='preferred' if base==BASES[0] else 'rebased'
            for level in ('O0','O3'):
                key=label+'-'+level;directory=out/key;directory.mkdir()
                raw=commands.run([binaries[level],'--check',old/'inputs'/(label+'-image.bin'),
                                  old/'inputs'/(label+'-permissions.bin'),hex(base),directory,1,1],'check-'+key)
                value=parse(raw);validate_response(value,directory,ready['binding']['goldens'][key],base,'check',1,1,read(Path(ready['binding']['objects']['O3']).parent/'manifest.json')['instructions'])
                write(directory/'parsed.json',value)
                checks.append(dict(label=label,base=base,optimization=level,output=str(directory),
                                   stdout=str(out/('check-'+key+'.stdout')),parsed=str(directory/'parsed.json')))
        unchanged(before);unchanged(tools);unchanged(generated);unchanged(dependency_hashes)
        require(sha(old/'result.json')==old_receipt,'baseline receipt changed');baseline.verify_prepared(old)
        result=dict(schema=1,status=PREPARED,out=str(out),baseline_prepared=str(old),baseline_receipt_sha256=old_receipt,
                    sources_before=before,sources_after=sources(),tools=tools,generated=generated,
                    compiler_dependencies=dependency_hashes,binaries=binaries,
                    clock=dict(binary=str(clock_binary),stdout=str(out/'clock-probe.stdout'),parsed=str(out/'clock-parsed.json'),assessment=clock_assessment),
                    checks=checks,commands=commands.rows,artifacts=identities(p for p in out.rglob('*') if p.is_file()),
                    correctness_callbacks=2976,normal_callbacks=64,budget_callbacks=2912,timed_callback_executions=0,
                    app_executions=0,gpu_executions=0,
                    scope='Exact lookup-only overlay; same-process selector cost included. Clock observations are not accuracy calibration or full ABI/game performance.')
        write(out/'result.json',result);return result
    except BaseException as error:
        write(out/'failure.json',dict(status='PREPARATION_FAILED_NOT_ACCEPTED',error=repr(error),traceback=traceback.format_exc(),commands=commands.rows,checks=checks));raise


def expected_commands(out, old, value):
    compiler=(out/'compiler-path.stdout').read_text().strip();sdk=(out/'sdk-path.stdout').read_text().strip()
    require({compiler,str(Path(sys.executable).resolve()),str(Path(sdk)/'SDKSettings.json')}==set(value['tools']), 'tool identity coverage differs')
    flags=compiler_flags(compiler,sdk,out,old)
    rows=[('compiler-path',['/usr/bin/xcrun','--find','clang']),('sdk-path',['/usr/bin/xcrun','--show-sdk-path']),('compiler-version',[compiler,'--version'])]
    for name,source in [('pair',MODULE/'benchmark.c'),('clock',MODULE/'clock_probe.c')]:
        rows.append(('dependencies-'+name,[*flags,'-M','-MT','pair',source]))
    for level in ('O0','O3'):
        rows.append(('compile-'+level,[*flags,MODULE/'benchmark.c',old/'inputs'/(level+'.o'),'-o',out/('benchmark-'+level)]))
    rows.append(('compile-clock',[*flags,MODULE/'clock_probe.c','-o',out/'clock-probe']))
    for name,source in [('pair',MODULE/'benchmark.c'),('clock',MODULE/'clock_probe.c')]:
        rows.append(('dependencies-after-'+name,[*flags,'-M','-MT','pair',source]))
    rows.append(('clock-probe',[out/'clock-probe']))
    for base in BASES:
        label='preferred' if base==BASES[0] else 'rebased'
        for level in ('O0','O3'):
            key=label+'-'+level
            rows.append(('check-'+key,[out/('benchmark-'+level),'--check',old/'inputs'/(label+'-image.bin'),old/'inputs'/(label+'-permissions.bin'),hex(base),out/key,1,1]))
    return [(label,list(map(str,argv))) for label,argv in rows]


def verify_command_records(out, value, expected):
    require(len(value['commands'])==len(expected),'command count differs')
    for row,(label,argv) in zip(value['commands'],expected):
        require(row['label']==label and row['argv']==argv and row['cwd']==str(ROOT) and
                type(row['returncode']) is int and row['returncode']==0,'command identity differs')
        require(read(out/(label+'.command.json'))==row and
                read(out/(label+'.started.json'))==dict(argv=argv,cwd=str(ROOT)),'command receipt differs')
        for stream in ('stdout','stderr'):
            path=str(out/(label+'.'+stream))
            require(row[stream+'_path']==path and row[stream+'_sha256']==value['artifacts'].get(path),'command raw stream identity differs')


def verify_prepared(prepared):
    out=Path(prepared).resolve(strict=True);value=read(out/'result.json');old=Path(value['baseline_prepared']).resolve(strict=True)
    require(value['schema']==1 and value['status']==PREPARED and value['out']==str(out),'prepared identity differs')
    for name,expected in [('correctness_callbacks',2976),('normal_callbacks',64),('budget_callbacks',2912),('timed_callback_executions',0),('app_executions',0),('gpu_executions',0)]:
        require(type(value[name]) is int and value[name]==expected,'prepared callback/scope count differs')
    require(value['sources_before']==value['sources_after']==sources(),'prepared source closure changed')
    for field in ('sources_before','tools','generated','compiler_dependencies','artifacts'): unchanged(value[field])
    require(sha(old/'result.json')==value['baseline_receipt_sha256'],'baseline receipt differs');ready=baseline.verify_prepared(old)
    actual={str(p) for p in out.rglob('*') if p.is_file() and p!=out/'result.json'}
    require(actual==set(value['artifacts']) and all(Path(p).is_relative_to(out) and str(Path(p).resolve())==p for p in actual),'artifact coverage/path differs')
    expected_overlay=generated_overlay()
    require(set(value['generated'])=={str(out/'sources'/n) for n in expected_overlay},'overlay path coverage differs')
    for name,data in expected_overlay.items():require((out/'sources'/name).read_bytes()==data,'overlay bytes differ')
    require(value['binaries']=={level:str(out/('benchmark-'+level)) for level in ('O0','O3')},'prepared binary paths differ')
    for path in value['binaries'].values():require(path in value['artifacts'],'missing binary identity');native_binary(path)
    verify_command_records(out,value,expected_commands(out,old,value));deps=[]
    for name in ('pair','clock'):
        raw=(out/('dependencies-'+name+'.stdout')).read_bytes()
        require(raw==(out/('dependencies-after-'+name+'.stdout')).read_bytes(),'compiler dependency source changed')
        deps+=dependencies(raw)
    require(identities(deps)==value['compiler_dependencies'],'compiler dependencies differ')
    clock=value['clock']
    require(clock['binary']==str(out/'clock-probe') and clock['stdout']==str(out/'clock-probe.stdout') and
            clock['parsed']==str(out/'clock-parsed.json') and clock['binary'] in value['artifacts'],'clock paths differ')
    native_binary(clock['binary']);raw=parse(Path(clock['stdout']).read_bytes())
    require(raw==read(clock['parsed']) and validate_clock(raw)==clock['assessment'],'clock assessment differs')
    require(len(value['checks'])==4,'correctness matrix count differs')
    for run,(base,level) in zip(value['checks'],[(b,l) for b in BASES for l in ('O0','O3')]):
        label='preferred' if base==BASES[0] else 'rebased';key=label+'-'+level
        require(run==dict(label=label,base=base,optimization=level,output=str(out/key),stdout=str(out/('check-'+key+'.stdout')),parsed=str(out/key/'parsed.json')),'correctness matrix paths differ')
        raw=parse(Path(run['stdout']).read_bytes());require(raw==read(run['parsed']),'correctness parsed/raw differs')
        validate_response(raw,Path(run['output']),ready['binding']['goldens'][key],base,'check',1,1,read(Path(ready['binding']['objects']['O3']).parent/'manifest.json')['instructions'])
    return value,ready


def describe(values):
    return dict(median=statistics.median(values),min=min(values),max=max(values))


def summarize(runs):
    summaries=[];anomalies=[]
    for run in runs:
        value=read(run['parsed']);rows=value['records']
        for row in rows:
            if row['thread_cpu_ns']>row['wall_ns']:
                anomalies.append(dict(base=run['base'],round=row['round'],scenario=row['scenario'],order_slot=row['order_slot'],
                                      cpu_exceeds_wall_ns=row['thread_cpu_ns']-row['wall_ns']))
        for scenario in range(8):
            pairs=[]
            for round_index in range(value['rounds']):
                group=[r for r in rows if r['scenario']==scenario and r['round']==round_index]
                pair=dict(round=round_index)
                for clock in ('wall_ns','thread_cpu_ns'):
                    for lookup_mode in ('reference','candidate'):
                        pair[lookup_mode+'_'+clock]=sum(r[clock] for r in group if r['lookup_mode']==lookup_mode)
                    pair['candidate_over_reference_'+clock]=pair['candidate_'+clock]/pair['reference_'+clock]
                pairs.append(pair)
            ratios=[p['candidate_over_reference_wall_ns'] for p in pairs]
            reset=[r['wall_ns']/r['iterations'] for r in rows if r['scenario']==scenario and r['path']=='reset']
            summaries.append(dict(base=run['base'],scenario=scenario,pairs=pairs,candidate_over_reference_wall=describe(ratios),
                                  candidate_faster=sum(p['candidate_wall_ns']<p['reference_wall_ns'] for p in pairs),
                                  candidate_slower=sum(p['candidate_wall_ns']>p['reference_wall_ns'] for p in pairs),
                                  equal=sum(p['candidate_wall_ns']==p['reference_wall_ns'] for p in pairs),
                                  reset_wall_ns_per_iteration=describe(reset)))
    return dict(by_base_scenario=summaries,cpu_exceeds_wall=anomalies,
                interpretation='Paired descriptive ratios only; wall primary, thread CPU diagnostic. No filtering, reset subtraction, confidence interval or deployment/game speedup claim.')


def measure(prepared, out, iterations=4096, rounds=12):
    baseline.native_host();bounded(iterations,rounds);prepared=Path(prepared).resolve(strict=True)
    ready,old_ready=verify_prepared(prepared);receipt=sha(prepared/'result.json');old=Path(ready['baseline_prepared'])
    out=baseline.fresh(out,[prepared,old,old_ready['product'],old_ready['probe']]);commands=baseline.Commands(out);runs=[]
    write(out/'started.json',dict(status='MEASURING_NOT_ACCEPTED',prepared=str(prepared),prepared_receipt_sha256=receipt,iterations=iterations,rounds=rounds))
    try:
        for base in BASES:
            label='preferred' if base==BASES[0] else 'rebased';directory=out/label;directory.mkdir()
            raw=commands.run([ready['binaries']['O3'],'--measure',old/'inputs'/(label+'-image.bin'),
                              old/'inputs'/(label+'-permissions.bin'),hex(base),directory,iterations,rounds],'measure-'+label)
            value=parse(raw)
            validate_response(value,directory,old_ready['binding']['goldens'][label+'-O3'],base,'measure',iterations,rounds,[])
            write(directory/'parsed.json',value)
            runs.append(dict(label=label,base=base,optimization='O3',output=str(directory),stdout=str(out/('measure-'+label+'.stdout')),parsed=str(directory/'parsed.json')))
        require(sha(prepared/'result.json')==receipt,'prepared receipt changed');verify_prepared(prepared)
        result=dict(schema=1,status=MEASURED,out=str(out),prepared=str(prepared),prepared_receipt_sha256=receipt,
                    iterations=iterations,rounds=rounds,commands=commands.rows,runs=runs,summary=summarize(runs),
                    artifacts=identities(p for p in out.rglob('*') if p.is_file()),
                    sources_before=ready['sources_before'],sources_after=sources(),reset_subtracted=False,
                    app_executions=0,gpu_executions=0,
                    limitations=['Same-process experimental shared strategy dispatch, not a deployed optimized runtime.',
                                 'Complete reset/checksum and key checks included; allocation, full comparisons, IO outside clocks.',
                                 'Warm-cache sequential single-host workload; no CPU affinity, frequency or thermal isolation.',
                                 'RAW wall clock primary; CPU diagnostic, no cross-clock inequality or accuracy guarantee.',
                                 'No outer callback ABI, App, GPU, real game or Wine/Rosetta comparison.'])
        write(out/'result.json',result);return result
    except BaseException as error:
        write(out/'failure.json',dict(status='MEASUREMENT_FAILED_NOT_ACCEPTED',error=repr(error),traceback=traceback.format_exc(),commands=commands.rows,runs=runs));raise
