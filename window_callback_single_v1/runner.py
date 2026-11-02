"""Build fixed reference/candidate artifacts and retain all process-paired records.

Existing production code is immutable. Only the candidate's generated lookup
function differs; startup, file IO and full comparisons are outside batch clocks.
"""
from pathlib import Path
import gzip
from itertools import zip_longest
import json
import statistics
import struct
import sys
import traceback

from window_callback_bench_v1 import runner as baseline
from window_callback_pair_v1 import runner as paired
from portable_app_v1.lift import source_closure

ROOT=Path(__file__).resolve().parents[1]
MODULE=ROOT/'window_callback_single_v1'
RUNTIME='window_bridge/window_runtime/transaction_v1.c'
STRATEGIES=('reference','candidate')
LEVELS=('O0','O3')
BASES=baseline.BASES
PREPARED='PASS_SINGLE_LOOKUP_PREPARED'
MEASURED='PASS_SINGLE_LOOKUP_RAW_MEASURED'
require,read,parse,write=baseline.require,baseline.read,baseline.parse,baseline.write
sha,identities,unchanged=baseline.sha,baseline.identities,baseline.unchanged
integer=paired.integer
PAYLOAD_SIZE=3504+20480+65536
CONTEXT_SIZE=5792
BUDGET_RECORD_SIZE=16+PAYLOAD_SIZE+CONTEXT_SIZE
MASK=(1<<64)-1
NORMALIZATION=dict(schema=1,pointer_width=8,instructions_offset=32,current_offset=752,regions_offset=56,
                   region_size=40,region_bytes_offset=16,region_permissions_offset=24,region_slots=16,
                   pending_offset=768,pending_slots=16,d3d_map_permissions_offset=5496,module_base_offset=0,
                   budget_offset=8,result_offset=696,current_pc_offset=744,result_size=48,result_fault_offset=0,
                   result_steps_offset=32,result_depth_offset=40,result_returned_offset=44,
                   encoding='instructions=1,current=index+1,region pointers=index+1,pending=guestVA,NULL=0; all other bytes preserved')


def sources():
    return identities([*source_closure([MODULE/n for n in ('__init__.py','__main__.py','runner.py')]),
                       *(MODULE/n for n in ('benchmark.c','lookup_impl.inc','lookup_bounds.inc')),
                       *(ROOT/n for n in baseline.RUNTIME)])


def overlay(strategy):
    require(strategy in STRATEGIES,'unknown strategy')
    result={n:(ROOT/n).read_bytes() for n in baseline.RUNTIME}
    if strategy=='candidate':result[RUNTIME]=paired.overlay_bytes(result[RUNTIME],(MODULE/'lookup_impl.inc').read_bytes())
    require(b'aot_pair_lookup_mode' not in result[RUNTIME],'shared strategy selector forbidden')
    return result


def payload(path,size):
    path=Path(path)
    require(path.is_file() and not path.is_symlink(),'regular payload required')
    if path.suffix=='.gz':
        with gzip.open(path,'rb') as stream:data=stream.read(size+1)
    else:data=path.read_bytes()
    require(len(data)==size,'payload extent differs')
    return data


def budget_records(directory,value):
    info=value['budget_stream'];count=len(value['budget_checks'])
    require(info['path']=='budget.bin.gz' and info['record_size']==BUDGET_RECORD_SIZE and info['records']==count and info['uncompressed_bytes']==count*BUDGET_RECORD_SIZE,'budget stream shape differs')
    path=Path(directory)/info['path']
    require(path.is_file() and not path.is_symlink(),'regular budget stream required')
    with gzip.open(path,'rb') as stream:
        for index,row in enumerate(value['budget_checks']):
            require(integer(row['stream_offset'])==index*BUDGET_RECORD_SIZE,'budget offset differs')
            data=stream.read(BUDGET_RECORD_SIZE)
            require(len(data)==BUDGET_RECORD_SIZE,'truncated budget stream')
            require(struct.unpack('<4I',data[:16])==(row['scenario'],row['budget'],row['status'],0),'budget stream header differs')
            yield data
        require(stream.read(1)==b'','trailing budget stream bytes')


def record_order(group):
    for offset in range(8):
        scenario=(group+offset)%8
        for slot in range(2):yield group,scenario,slot,('execute' if ((group+scenario+slot)&1)==0 else 'reset')


def process_order(rounds):
    for base in BASES:
        for group in range(rounds):
            sequence=('reference','candidate','candidate','reference') if group%2==0 else ('candidate','reference','reference','candidate')
            for slot,strategy in enumerate(sequence):yield base,group,slot,strategy


def validate_response(value,directory,goldens,base,strategy,mode,iterations,group,table):
    directory=Path(directory);measuring=mode=='measure'
    require(mode in ('check','measure') and strategy in STRATEGIES,'unsupported identity')
    require(value['status']==('PASS_CALLBACK_SINGLE_MEASURE' if measuring else 'PASS_CALLBACK_SINGLE_CHECK') and
            value['mode']==mode and value['strategy']==strategy and value['base']==base and
            value['iterations']==iterations and value['group']==group,'single response identity differs')
    for k,v in [('state_size',3504),('context_size',CONTEXT_SIZE),('image_size',20480),('stack_size',65536),
                ('reset_bytes_per_iteration',95312),('app_executions',0),('gpu_executions',0)]:
        require(integer(value[k])==v,'shape/scope differs: '+k)
    for k in ('reset_included','checksum_included','key_invariants_per_iteration','full_comparison_per_batch','reset_control_not_subtracted'):
        require(value[k] is True,'inclusion policy differs')
    for k in ('lto','transaction_trace_hooks','outer_callback_abi_invoked','runtime_strategy_selector'):
        require(value[k] is False,'scope/selector differs')
    require(value['wall_clock']=='CLOCK_MONOTONIC_RAW' and value['cpu_clock']=='CLOCK_THREAD_CPUTIME_ID' and
            value['clock_order']=='wall_start,cpu_start,batch,cpu_end,wall_end' and
            value['legacy_block_fastpath']=='NOT_INTEGRATED','clock/fastpath differs')
    require(value['context_normalization']==NORMALIZATION,'context normalization descriptor differs')
    require(len(value['cases'])==8,'case matrix differs')
    for i,(case,gold) in enumerate(zip(value['cases'],goldens)):
        for name in ('initial_position','position','moves','draws','keydowns','dirty','status','returned','call_depth','steps','switch_commits','rejected_api_calls'):
            require(integer(case[name])==gold['case'][name],'normal semantics differ: '+name)
        require(case['response']=='case-%d.bin'%i and case['context_response']=='case-%d.context.bin'%i,'normal paths differ')
        require(payload(directory/case['response'],PAYLOAD_SIZE)==Path(gold['path']).read_bytes(),'normal complete response differs')
        payload(directory/case['context_response'],CONTEXT_SIZE)
        integer(case['checksum']);integer(case['reset_checksum'])
        if measuring:
            require(case['timed_final_response']=='final-case-%d.bin'%i and case['timed_final_context']=='final-case-%d.context.bin'%i,'final paths differ')
            require(payload(directory/case['timed_final_response'],PAYLOAD_SIZE)==Path(gold['path']).read_bytes(),'actual timed final response differs')
            require(payload(directory/case['timed_final_context'],CONTEXT_SIZE)==payload(directory/case['context_response'],CONTEXT_SIZE),'final normalized Context differs')
        else:require(case['timed_final_response'] is None and case['timed_final_context'] is None,'untimed response has timed output')
    expected_budget=[] if measuring else [(i,b) for i,g in enumerate(goldens) for b in range(g['case']['steps']+1)]
    require(len(value['budget_checks'])==len(expected_budget),'budget matrix count differs')
    for row,(scenario,budget) in zip(value['budget_checks'],expected_budget):
        gold=goldens[scenario]['case'];stopped=budget<gold['steps'];pc=gold['trace'][budget]['pc'] if stopped else 0
        fault=dict(status=4,access=0,pc=pc,address=pc,width=0) if stopped else dict(status=0,access=0,pc=0,address=0,width=0)
        require(row['scenario']==scenario and integer(row['budget'])==integer(row['steps'])==budget and row['status']==(4 if stopped else 0) and
                row['returned']==int(not stopped) and row['call_depth']==(gold['trace'][budget]['before_depth'] if stopped else 0) and row['fault']==fault,'budget semantics differ')
        integer(row['checksum'])
    if measuring:require(value['budget_stream']==dict(records=0,record_size=BUDGET_RECORD_SIZE,uncompressed_bytes=0,path=None),'measure budget descriptor differs')
    else:
        for index,data in enumerate(budget_records(directory,value)):
            row=value['budget_checks'][index];i=row['scenario']
            if row['budget']==goldens[i]['case']['steps']:
                require(data[16:16+PAYLOAD_SIZE]==Path(goldens[i]['path']).read_bytes(),'complete budget response differs')
    require(value['lookup_checks']==(dict(contexts=0,queries=0,hits=0,misses=0) if measuring else paired.lookup_expected(base,table)),'lookup matrix differs')
    timed=8*iterations if measuring else 0;untimed=8+(8*256+8 if measuring else len(expected_budget))
    controls=8*256+8*(iterations+1) if measuring else 0
    for name,expected in dict(actual_callback_executions=timed+untimed,timed_callback_executions=timed,untimed_callback_executions=untimed,
                              reset_control_iterations=controls,all_reset_calls=timed+untimed+controls,timer_calls=64 if measuring else 0,
                              clock_resolution_queries=2 if measuring else 0,warmup_iterations_per_scenario_path=256 if measuring else 0).items():
        require(integer(value[name])==expected,'execution count differs: '+name)
    for name in ('wall_resolution_ns','thread_cpu_resolution_ns'):
        require(integer(value[name])>0 if measuring else integer(value[name])==0,'clock resolution differs')
    require(len(value['records'])==(16 if measuring else 0),'record count differs')
    for row,order in zip(value['records'],record_order(group) if measuring else []):
        require(tuple(row[k] for k in ('group','scenario','order_slot','path'))==order,'record order differs')
        execute=row['path']=='execute';case=value['cases'][row['scenario']]
        for k in ('group','scenario','order_slot','iterations','wall_ns','thread_cpu_ns','checksum','steps_per_iteration','switch_commits_per_iteration','rejected_api_calls'):integer(row[k])
        require(row['iterations']==iterations and row['wall_ns']>0 and row['thread_cpu_ns']>0 and
                row['checksum']==(case['checksum' if execute else 'reset_checksum']*iterations)&MASK and
                row['steps_per_iteration']==(case['steps'] if execute else 0) and row['switch_commits_per_iteration']==int(execute) and
                row['rejected_api_calls']==0 and row['complete_post_batch_match'] is True,'raw measurement differs')


def compare_checks(checks):
    require(len(checks)==8,'eight preparation runs required')
    comparisons=0
    for base in BASES:
        runs=[r for r in checks if r['base']==base]
        require(len(runs)==4,'cross-artifact matrix differs')
        first=runs[0];left=read(first['parsed']);root=Path(first['output'])
        for run in runs[1:]:
            right=read(run['parsed']);other=Path(run['output'])
            require(left['budget_checks']==right['budget_checks'],'budget summaries differ between artifacts')
            for i in range(8):
                require(payload(root/left['cases'][i]['context_response'],CONTEXT_SIZE)==payload(other/right['cases'][i]['context_response'],CONTEXT_SIZE),'normalized normal Context differs')
            for a,b in zip_longest(budget_records(root,left),budget_records(other,right)):
                require(a==b,'full budget State/image/stack/normalized Context differs');comparisons+=1
    return comparisons


def flags(compiler,sdk,out,old,strategy):
    return [compiler,'-std=c11','-arch','arm64','-isysroot',sdk,'-O3','-Wall','-Wextra','-Werror','-DAOT_WINDOW_SWITCH_V1=1',
            '-DAOT_SINGLE_CANDIDATE='+str(int(strategy=='candidate')),'-I',str(out/'sources'/strategy),'-I',str(old/'inputs'),'-I',str(MODULE)]


def artifact_inspection(undefined,symbols,disassembly,strategy):
    undefined=undefined.decode();symbols=symbols.decode();disassembly=disassembly.decode()
    require(('_bsearch' in undefined.split())==(strategy=='reference'),'fixed lookup import identity differs')
    require('aot_pair_lookup_mode' not in symbols and 'aot_pair_lookup_mode' not in disassembly,'runtime selector symbol found')
    require('_aot_begin:' in disassembly and '_aot_execute:' in disassembly,'real runtime disassembly missing')
    return dict(strategy=strategy,bsearch_imported=strategy=='reference',shared_selector_symbol=False,
                scope='Exact source overlay plus real undefined-symbol and disassembly records; not an exhaustive machine-code semantic proof.')


def preparation_commands(out,old,compiler,sdk):
    rows=[('compiler-path',['/usr/bin/xcrun','--find','clang']),('sdk-path',['/usr/bin/xcrun','--show-sdk-path']),('compiler-version',[compiler,'--version'])]
    for strategy in STRATEGIES:
        f=flags(compiler,sdk,out,old,strategy)
        rows.append(('dependencies-'+strategy,[*f,'-M','-MT','pair',MODULE/'benchmark.c']))
        for level in LEVELS:
            key=strategy+'-'+level;binary=out/('benchmark-'+key)
            rows.extend([('compile-'+key,[*f,MODULE/'benchmark.c',old/'inputs'/(level+'.o'),'-lz','-o',binary]),
                         ('nm-u-'+key,['/usr/bin/nm','-u',binary]),('nm-'+key,['/usr/bin/nm','-a',binary]),
                         ('disasm-'+key,['/usr/bin/otool','-tvV',binary])])
        rows.append(('dependencies-after-'+strategy,[*f,'-M','-MT','pair',MODULE/'benchmark.c']))
    for base in BASES:
        label='preferred' if base==BASES[0] else 'rebased'
        for level in LEVELS:
            for strategy in STRATEGIES:
                key=label+'-'+level+'-'+strategy
                rows.append(('check-'+key,[out/('benchmark-'+strategy+'-'+level),'--check',old/'inputs'/(label+'-image.bin'),old/'inputs'/(label+'-permissions.bin'),hex(base),out/key,1,0]))
    return [(label,list(map(str,argv))) for label,argv in rows]


def prepare(baseline_prepared,out):
    baseline.native_host();old=Path(baseline_prepared).resolve(strict=True);ready=baseline.verify_prepared(old)
    before=sources();old_receipt=sha(old/'result.json');out=baseline.fresh(out,[old,ready['product'],ready['probe']])
    commands=baseline.Commands(out);checks=[]
    write(out/'started.json',dict(status='PREPARING_NOT_ACCEPTED',baseline_prepared=str(old),baseline_receipt_sha256=old_receipt,sources=before))
    try:
        for strategy in STRATEGIES:
            for name,data in overlay(strategy).items():
                path=out/'sources'/strategy/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
        generated=identities(p for p in (out/'sources').rglob('*') if p.is_file())
        compiler=commands.run(['/usr/bin/xcrun','--find','clang'],'compiler-path').decode().strip()
        sdk=commands.run(['/usr/bin/xcrun','--show-sdk-path'],'sdk-path').decode().strip()
        require(Path(compiler).is_file() and Path(compiler).is_absolute() and Path(sdk).is_dir(),'compiler/SDK missing')
        tool_hashes=identities([Path(compiler),Path(sys.executable).resolve(),Path(sdk)/'SDKSettings.json',Path('/usr/bin/nm'),Path('/usr/bin/otool')])
        expected=preparation_commands(out,old,compiler,sdk);dependency_hashes={};binaries={};inspection={}
        table=read(Path(ready['binding']['objects']['O3']).parent/'manifest.json')['instructions']
        for label,argv in expected[2:]:
            if label.startswith('check-'):(out/label.removeprefix('check-')).mkdir()
            raw=commands.run(argv,label)
            if label.startswith('dependencies-') and not label.startswith('dependencies-after-'):
                strategy=label.removeprefix('dependencies-');deps=paired.dependencies(raw)
                require({MODULE/'benchmark.c',MODULE/'lookup_bounds.inc',old/'inputs/callback_probe_input.h',*(out/'sources'/strategy/n for n in baseline.RUNTIME)}<=set(deps),'dependency coverage differs')
                dependency_hashes.update(identities(deps))
            elif label.startswith('dependencies-after-'):
                require(raw==(out/('dependencies-'+label.removeprefix('dependencies-after-')+'.stdout')).read_bytes(),'compile dependencies changed')
            elif label.startswith('compile-'):
                key=label.removeprefix('compile-');binary=out/('benchmark-'+key);paired.native_binary(binary);binaries[key]=str(binary)
            elif label.startswith('disasm-'):
                key=label.removeprefix('disasm-');strategy=key.split('-')[0]
                inspection[key]=artifact_inspection((out/('nm-u-'+key+'.stdout')).read_bytes(),(out/('nm-'+key+'.stdout')).read_bytes(),raw,strategy)
            elif label.startswith('check-'):
                key=label.removeprefix('check-');base_label,level,strategy=key.split('-');base=BASES[0] if base_label=='preferred' else BASES[1]
                directory=out/key;value=parse(raw);validate_response(value,directory,ready['binding']['goldens'][base_label+'-'+level],base,strategy,'check',1,0,table)
                write(directory/'parsed.json',value);checks.append(dict(label=base_label,base=base,optimization=level,strategy=strategy,output=str(directory),stdout=str(out/(label+'.stdout')),parsed=str(directory/'parsed.json')))
        comparison_count=compare_checks(checks)
        for identity in (before,tool_hashes,generated,dependency_hashes):unchanged(identity)
        require(sha(old/'result.json')==old_receipt,'baseline receipt changed');baseline.verify_prepared(old)
        result=dict(schema=1,status=PREPARED,out=str(out),baseline_prepared=str(old),baseline_receipt_sha256=old_receipt,
                    sources_before=before,sources_after=sources(),tools=tool_hashes,generated=generated,compiler_dependencies=dependency_hashes,
                    binaries=binaries,inspection=inspection,checks=checks,commands=commands.rows,artifacts=identities(p for p in out.rglob('*') if p.is_file()),
                    correctness_callbacks=2976,normal_callbacks=64,budget_callbacks=2912,full_budget_record_comparisons=comparison_count,
                    timed_callback_executions=0,app_executions=0,gpu_executions=0)
        write(out/'result.json',result);return result
    except BaseException as error:
        write(out/'failure.json',dict(status='PREPARATION_FAILED_NOT_ACCEPTED',error=repr(error),traceback=traceback.format_exc(),commands=commands.rows,checks=checks));raise


def verify_prepared(prepared):
    out=Path(prepared).resolve(strict=True);v=read(out/'result.json');old=Path(v['baseline_prepared']).resolve(strict=True)
    require(v['schema']==1 and v['status']==PREPARED and v['out']==str(out),'prepared identity differs')
    for k,n in dict(correctness_callbacks=2976,normal_callbacks=64,budget_callbacks=2912,full_budget_record_comparisons=2184,timed_callback_executions=0,app_executions=0,gpu_executions=0).items():
        require(integer(v[k])==n,'prepared scope differs')
    require(v['sources_before']==v['sources_after']==sources(),'prepared source closure differs')
    for field in ('sources_before','tools','generated','compiler_dependencies','artifacts'):unchanged(v[field])
    actual={str(p) for p in out.rglob('*') if p.is_file() and p!=out/'result.json'}
    require(actual==set(v['artifacts']) and all(Path(p).is_relative_to(out) and str(Path(p).resolve())==p for p in actual),'artifact coverage/path differs')
    require(sha(old/'result.json')==v['baseline_receipt_sha256'],'baseline receipt differs');ready=baseline.verify_prepared(old)
    generated={str(out/'sources'/strategy/n):data for strategy in STRATEGIES for n,data in overlay(strategy).items()}
    require(set(generated)==set(v['generated']),'overlay coverage differs')
    for path,data in generated.items():require(Path(path).read_bytes()==data,'generated runtime differs')
    compiler=(out/'compiler-path.stdout').read_text().strip();sdk=(out/'sdk-path.stdout').read_text().strip()
    require(set(v['tools'])=={compiler,str(Path(sys.executable).resolve()),str(Path(sdk)/'SDKSettings.json'),'/usr/bin/nm','/usr/bin/otool'},'tool coverage differs')
    expected=preparation_commands(out,old,compiler,sdk);paired.verify_command_records(out,v,expected)
    binaries={s+'-'+l:str(out/('benchmark-'+s+'-'+l)) for s in STRATEGIES for l in LEVELS};require(v['binaries']==binaries,'binary identity differs')
    for key,path in binaries.items():
        require(path in v['artifacts'],'binary hash missing');paired.native_binary(path)
        found=artifact_inspection((out/('nm-u-'+key+'.stdout')).read_bytes(),(out/('nm-'+key+'.stdout')).read_bytes(),(out/('disasm-'+key+'.stdout')).read_bytes(),key.split('-')[0])
        require(v['inspection'][key]==found,'artifact inspection differs')
    deps=[]
    for strategy in STRATEGIES:
        raw=(out/('dependencies-'+strategy+'.stdout')).read_bytes()
        require(raw==(out/('dependencies-after-'+strategy+'.stdout')).read_bytes(),'dependencies changed')
        deps+=paired.dependencies(raw)
    require(identities(deps)==v['compiler_dependencies'],'dependency set differs')
    require(len(v['checks'])==8,'check count differs')
    table=read(Path(ready['binding']['objects']['O3']).parent/'manifest.json')['instructions']
    for run,(base,level,strategy) in zip(v['checks'],[(b,l,s) for b in BASES for l in LEVELS for s in STRATEGIES]):
        label='preferred' if base==BASES[0] else 'rebased';key=label+'-'+level+'-'+strategy
        require(run==dict(label=label,base=base,optimization=level,strategy=strategy,output=str(out/key),stdout=str(out/('check-'+key+'.stdout')),parsed=str(out/key/'parsed.json')),'check matrix paths differ')
        raw=parse(Path(run['stdout']).read_bytes());require(raw==read(run['parsed']),'raw/parsed differs')
        validate_response(raw,Path(run['output']),ready['binding']['goldens'][label+'-'+level],base,strategy,'check',1,0,table)
    require(compare_checks(v['checks'])==v['full_budget_record_comparisons'],'full budget comparison count differs')
    return v,ready


def summarize(runs,rounds):
    cells=[];anomalies=[];loaded=[(r,read(r['parsed'])) for r in runs]
    for run,value in loaded:
        for row in value['records']:
            if row['thread_cpu_ns']>row['wall_ns']:
                anomalies.append(dict(base=run['base'],group_index=run['group_index'],process_slot=run['process_slot'],strategy=run['strategy'],scenario=row['scenario'],path=row['path'],cpu_exceeds_wall_ns=row['thread_cpu_ns']-row['wall_ns']))
    for base in BASES:
        for scenario in range(8):
            pairs=[]
            for group in range(rounds):
                pair={'group_index':group}
                for clock in ('wall_ns','thread_cpu_ns'):
                    for strategy in STRATEGIES:
                        pair[strategy+'_'+clock]=sum(row[clock] for r,v in loaded if r['base']==base and r['group_index']==group and r['strategy']==strategy for row in v['records'] if row['scenario']==scenario and row['path']=='execute')
                    pair['candidate_over_reference_'+clock]=pair['candidate_'+clock]/pair['reference_'+clock]
                pairs.append(pair)
            ratios=[p['candidate_over_reference_wall_ns'] for p in pairs]
            cells.append(dict(base=base,scenario=scenario,pairs=pairs,candidate_over_reference_wall=paired.describe(ratios),candidate_faster=sum(p['candidate_wall_ns']<p['reference_wall_ns'] for p in pairs),candidate_slower=sum(p['candidate_wall_ns']>p['reference_wall_ns'] for p in pairs),equal=sum(p['candidate_wall_ns']==p['reference_wall_ns'] for p in pairs)))
    return dict(by_base_scenario=cells,cpu_exceeds_wall=anomalies,interpretation='Process-paired batch intervals only; startup excluded. All rows retained; no filtering/reset subtraction/confidence or App/game claim.')


def measure(prepared,out,iterations=4096,rounds=12):
    baseline.native_host();paired.bounded(iterations,rounds);prepared=Path(prepared).resolve(strict=True)
    ready,old_ready=verify_prepared(prepared);receipt=sha(prepared/'result.json');old=Path(ready['baseline_prepared'])
    out=baseline.fresh(out,[prepared,old,old_ready['product'],old_ready['probe']]);commands=baseline.Commands(out);runs=[]
    write(out/'started.json',dict(status='MEASURING_NOT_ACCEPTED',prepared=str(prepared),prepared_receipt_sha256=receipt,iterations=iterations,rounds=rounds))
    try:
        for base,group,slot,strategy in process_order(rounds):
            label='preferred' if base==BASES[0] else 'rebased';key='%s-g%02d-s%d-%s'%(label,group,slot,strategy);directory=out/key;directory.mkdir()
            raw=commands.run([ready['binaries'][strategy+'-O3'],'--measure',old/'inputs'/(label+'-image.bin'),old/'inputs'/(label+'-permissions.bin'),hex(base),directory,iterations,group],'measure-'+key)
            value=parse(raw);validate_response(value,directory,old_ready['binding']['goldens'][label+'-O3'],base,strategy,'measure',iterations,group,[])
            reference=prepared/(label+'-O3-'+strategy)
            for i in range(8):require(payload(directory/('case-%d.context.bin'%i),CONTEXT_SIZE)==payload(reference/('case-%d.context.bin'%i),CONTEXT_SIZE),'measure normal Context differs from preparation')
            write(directory/'parsed.json',value);runs.append(dict(label=label,base=base,group_index=group,process_slot=slot,strategy=strategy,optimization='O3',output=str(directory),stdout=str(out/('measure-'+key+'.stdout')),parsed=str(directory/'parsed.json')))
        require(sha(prepared/'result.json')==receipt,'prepared receipt changed');verify_prepared(prepared)
        result=dict(schema=1,status=MEASURED,out=str(out),prepared=str(prepared),prepared_receipt_sha256=receipt,iterations=iterations,rounds=rounds,
                    commands=commands.rows,runs=runs,summary=summarize(runs,rounds),artifacts=identities(p for p in out.rglob('*') if p.is_file()),
                    sources_before=ready['sources_before'],sources_after=sources(),reset_subtracted=False,startup_timed=False,
                    app_executions=0,gpu_executions=0,limitations=['Separate fixed-strategy component artifacts, not integrated App runtime.',
                    'Complete reset/checksum and key checks timed; full comparisons, IO and process startup outside clocks.',
                    'Warm-cache single-host sequential samples; scheduling, frequency and temperature uncontrolled.',
                    'No outer ABI, App, GPU, game or Wine/Rosetta performance conclusion.'])
        write(out/'result.json',result);return result
    except BaseException as error:
        write(out/'failure.json',dict(status='MEASUREMENT_FAILED_NOT_ACCEPTED',error=repr(error),traceback=traceback.format_exc(),commands=commands.rows,runs=runs));raise
