"""Read-only independent review of the paired lookup experiment.

Imports the existing independent baseline reader, never either runner.
All raw samples remain visible; clock observations do not certify accuracy.
"""
import argparse
import ast
import json
from pathlib import Path
import shlex
import statistics
import struct

from window_callback_bench_v1 import review as old

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT/'window_callback_pair_v1'
BASES, LEVELS, MASK = old.BASES, old.LEVELS, old.MASK
need, integer = old.need, old.integer
RUNTIME = 'window_bridge/window_runtime/transaction_v1.c'
ANCHOR = b'''static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    AotInstruction key={(uint32_t)(pc-ctx->module_base),0,0,0,0};
    return bsearch(&key,ctx->instructions,ctx->instruction_count,sizeof key,compare_instruction);
}
'''


def clock_report(value):
    need(integer(value['schema'])==1 and value['status']=='CLOCK_OBSERVATIONS_RECORDED','clock receipt differs')
    for name,expected in [('read_pairs_per_clock',128),('windows_per_wall_clock',16),
                          ('work_iterations',65536),('warmup_work_calls',1)]:
        need(integer(value[name])==expected,'clock fixed work differs')
    integer(value['timebase_numer'],1);integer(value['timebase_denom'],1)
    need(value['sample_order']=='wall_start,cpu_start,work,cpu_end,wall_end','clock order differs')
    checksum=0x29dff4c8a1076e35
    for i in range(65536): checksum=((checksum^(i+0x9e3779b97f4a7c15))*0xbf58476d1ce4e5b9)&MASK
    need(integer(value['work_checksum'])==checksum,'clock checksum differs')
    names=['CLOCK_MONOTONIC','CLOCK_MONOTONIC_RAW','CLOCK_UPTIME_RAW','CLOCK_THREAD_CPUTIME_ID']
    need([c['name'] for c in value['clocks']]==names,'clock inventory differs')
    samples=[];anomalies=[]
    for index,c in enumerate(value['clocks']):
        resolution=integer(c['resolution_ns'],1)
        need(len(c['adjacent_reads'])==128,'adjacent read count differs')
        previous=0;deltas=[]
        for pair in c['adjacent_reads']:
            need(type(pair) is list and len(pair)==2,'invalid read pair')
            first,second=map(integer,pair)
            need(previous<=first<=second,'clock regressed');previous=second;deltas.append(second-first)
        need(len(c['work_windows'])==(16 if index<3 else 0),'clock windows differ')
        windows=[]
        for round_index,w in enumerate(c['work_windows']):
            need(integer(w['round'])==round_index and integer(w['checksum'])==checksum,'clock work identity differs')
            wall=integer(w['wall_end'])-integer(w['wall_start']);cpu=integer(w['cpu_end'])-integer(w['cpu_start'])
            need(wall>0 and cpu>0,'nonpositive work interval')
            windows.append(dict(round=round_index,wall_ns=wall,thread_cpu_ns=cpu,cpu_exceeds_wall_ns=max(cpu-wall,0)))
            if cpu>wall:anomalies.append(dict(clock=c['name'],round=round_index,cpu_exceeds_wall_ns=cpu-wall))
        samples.append(dict(name=c['name'],reported_resolution_ns=resolution,zero_adjacent_reads=deltas.count(0),
                            min_adjacent_delta_ns=min(deltas),max_adjacent_delta_ns=max(deltas),work_windows=windows))
    return dict(status='SELF_MONOTONIC_WORKLOAD_VALIDATED_NOT_ACCURACY_CALIBRATED',
                selected_wall_clock='CLOCK_MONOTONIC_RAW',cpu_exceeds_wall=anomalies,observations=samples)


def source_paths(audit):
    pending=[MODULE/n for n in ('__init__.py','__main__.py','runner.py')];seen=set()
    def modules(parts):
        for n in range(1,len(parts)+1):
            initializer=ROOT.joinpath(*parts[:n])/'__init__.py'
            if initializer.is_file():pending.append(initializer)
        module=ROOT.joinpath(*parts).with_suffix('.py')
        if module.is_file():pending.append(module)
    while pending:
        p=pending.pop()
        if p in seen:continue
        seen.add(p);package=p.parent.relative_to(ROOT).parts
        for node in ast.walk(ast.parse(audit.raw(p),filename=str(p))):
            if isinstance(node,ast.Import):
                for item in node.names:modules(tuple(item.name.split('.')))
            elif isinstance(node,ast.ImportFrom):
                need(node.level<=len(package),'source import escaped root')
                base=package[:len(package)+1-node.level] if node.level else ()
                if node.module:base+=tuple(node.module.split('.'))
                modules(base)
                for item in node.names:
                    if item.name!='*':modules((*base,item.name))
    return {str(p) for p in seen|{MODULE/n for n in ('benchmark.c','lookup_impl.inc','lookup_bounds.inc','clock_probe.c')}|
            {ROOT/n for n in old.RUNTIME}}


def artifacts(audit,value,directory):
    expected={str(p) for p in directory.rglob('*') if p.is_file() and p!=directory/'result.json'}
    need(set(value['artifacts'])==expected,'artifact coverage differs')
    for path in expected:
        need(str(Path(path).resolve())==path and Path(path).is_relative_to(directory),'artifact escaped output')
    audit.mapping(value['artifacts'])
    need(value['sources_before']==value['sources_after'] and set(value['sources_before'])==source_paths(audit),
         'source closure changed')
    audit.mapping(value['sources_before'])


def commands(audit,value,directory):
    result={}
    for row in value['commands']:
        label=row['label'];need(label not in result,'duplicate command label')
        need(integer(row['returncode'])==0 and row['cwd']==str(ROOT),'failed command or cwd differs')
        need(type(row['argv']) is list and all(type(v) is str for v in row['argv']),'command argv invalid')
        need(audit.json(directory/(label+'.command.json'))==row,'command record differs')
        need(audit.json(directory/(label+'.started.json'))==dict(argv=row['argv'],cwd=str(ROOT)),'started argv differs')
        for stream in ('stdout','stderr'):
            path=directory/(label+'.'+stream)
            need(row[stream+'_path']==str(path),'command stream escaped')
            audit.file(path,row[stream+'_sha256'])
        result[label]=row
    return result


def overlay(audit,prepared,ready):
    expected={str(prepared/'sources'/name) for name in old.RUNTIME}
    need(set(ready['generated'])==expected,'overlay source coverage differs')
    replacement=audit.raw(MODULE/'lookup_impl.inc')
    need(replacement.startswith(b'static const AotInstruction *instruction(') and replacement.endswith(b'\n'),
         'replacement is not an instruction function')
    for name in old.RUNTIME:
        original=audit.raw(ROOT/name);path=prepared/'sources'/name
        if name==RUNTIME:
            need(original.count(ANCHOR)==1,'runtime anchor differs');original=original.replace(ANCHOR,replacement,1)
        need(audit.raw(path)==original,'overlay changed outside the exact lookup replacement')
        audit.file(path,ready['generated'][str(path)])


def lookup_counts(instructions,base):
    counts=dict(contexts=0,queries=0,hits=0,misses=0)
    def context(rows,address):
        rows=sorted(rows);starts={rva for rva,_ in rows};counts['contexts']+=1
        points=[0,MASK,address]
        if address:points.append(address-1)
        if address<=MASK-0xffffffff:points.append(address+0xffffffff)
        if address<MASK-0xffffffff:points.append(address+0x100000000)
        for rva,length in rows:
            pc=address+rva
            if pc:points.append(pc-1)
            points.extend(pc+i for i in range(length+1))
        random=0x91e10da5
        for _ in range(2048):
            random=(random^(random<<13))&0xffffffff;random^=random>>17;random=(random^(random<<5))&0xffffffff
            if address<=MASK-random:points.append(address+random)
        for pc in points:
            hit=pc>=address and pc-address<=0xffffffff and pc-address in starts
            counts['queries']+=1;counts['hits' if hit else 'misses']+=1
    context([(r['rva'],r['length']) for r in instructions],base)
    for address in (0,BASES[0],BASES[1],MASK-0xffffffff):
        for count in (1,2,3,7,8,9,31,32,33,127,256,1024):
            context([(7+i*17,i%15+1) for i in range(count)],address)
        context([(0xfffffffe,1),(0x7fffffff,1),(0xfffffff0,14),(0,1),(2,1)],address)
    return counts


def response(audit,value,directory,goldens,base,mode,iterations,rounds,image_size,state_rva,result_rva,instructions=None):
    measured=mode=='measure';integer(iterations,1,65536);integer(rounds,1,20)
    need(value['status']==('PASS_CALLBACK_PAIR_MEASURE' if measured else 'PASS_CALLBACK_PAIR_CHECK') and
         value['mode']==mode and integer(value['base'])==base,'native mode/base/status differs')
    for name,expected in dict(state_size=old.STATE_SIZE,image_size=image_size,stack_size=old.STACK_SIZE,
                             iterations=iterations,rounds=rounds,app_executions=0,gpu_executions=0).items():
        need(integer(value[name])==expected,'native scalar differs: '+name)
    context_size=integer(value['context_size'],1,1048576)
    need(integer(value['reset_bytes_per_iteration'])==old.STATE_SIZE+context_size+image_size+old.STACK_SIZE,'reset bytes differ')
    for name in ('reset_included','checksum_included','key_invariants_per_iteration','full_comparison_per_batch','reset_control_not_subtracted'):
        need(value[name] is True,'native scope differs: '+name)
    for name in ('lto','transaction_trace_hooks','outer_callback_abi_invoked'):
        need(value[name] is False,'native scope differs: '+name)
    need(value['legacy_block_fastpath']=='NOT_INTEGRATED' and
         value['strategy_dispatch']=='shared volatile mode load and branch per valid instruction lookup' and
         value['pair_order']=='ABBA even rounds, BAAB odd rounds; reset before/after by round+scenario parity' and
         value['final_snapshot_capture']=='live final execute batch for each mode copied outside clocks; IO after all timed batches',
         'experimental scope/order differs')
    need(value['wall_clock']=='CLOCK_MONOTONIC_RAW' and value['cpu_clock']=='CLOCK_THREAD_CPUTIME_ID' and
         value['clock_order']=='wall_start,cpu_start,batch,cpu_end,wall_end','clock contract differs')
    timed=8*rounds*4*iterations if measured else 0
    untimed=16+4096+32*rounds if measured else 744
    reset=2048+8*rounds*(iterations+1) if measured else 0
    expected_counts=dict(actual_callback_executions=timed+untimed,timed_callback_executions=timed,
                         untimed_callback_executions=untimed,reset_control_iterations=reset,all_reset_calls=timed+untimed+reset+8,
                         timer_calls=rounds*8*5*4 if measured else 0,clock_resolution_queries=2 if measured else 0,
                         warmup_iterations_per_scenario_path=256 if measured else 0)
    for name,count in expected_counts.items():need(integer(value[name])==count,'native counter differs: '+name)
    for name in ('wall_resolution_ns','thread_cpu_resolution_ns'):
        need(integer(value[name])>0 if measured else integer(value[name])==0,'resolution differs')
    if measured:need(value['lookup_checks']==dict(contexts=0,queries=0,hits=0,misses=0),'measured lookup checks claimed')
    else:
        need(instructions is not None,'lookup instruction table missing')
        old.exact_summary(value['lookup_checks'],lookup_counts(instructions,base))
    need(len(value['cases'])==16,'normal case count differs')
    for index,case in enumerate(value['cases']):
        scenario=index//2;strategy=('reference','candidate')[index%2];gold=goldens[scenario]
        need(case['lookup_mode']==strategy,'normal strategy differs')
        for name in old.CASE_FIELDS:need(integer(case[name])==gold['case'][name],'normal case differs: '+name)
        filename='case-%s-%d.bin'%(strategy,scenario)
        need(case['response']==filename and audit.raw(directory/filename)==gold['payload'],'full normal response differs')
        word=old.response_word(gold['payload'],image_size,state_rva,result_rva,gold['case']['steps'],1)
        need(integer(case['checksum'])==word and integer(case['reset_checksum'])==old.reset_word(scenario),'normal checksum differs')
        final='final-'+filename
        if measured:need(case['timed_final_response']==final and audit.raw(directory/final)==gold['payload'],'actual timed final bytes differ')
        else:need(case['timed_final_response'] is None,'check claims timed output')
    need(len(value['budget_checks'])==(0 if measured else 364),'budget matrix size differs')
    if not measured:
        cursor=0
        for scenario,gold in enumerate(goldens):
            steps=gold['case']['steps'];trace=gold['case']['trace']
            for budget in range(steps+1):
                row=value['budget_checks'][cursor];cursor+=1
                status=4 if budget<steps else 0
                depth=trace[budget]['before_depth'] if budget<steps else 0
                fault=dict(status=status,access=0,pc=trace[budget]['pc'] if budget<steps else 0,
                           address=trace[budget]['pc'] if budget<steps else 0,width=0)
                for name,expected in dict(scenario=scenario,budget=budget,status=status,steps=budget,returned=int(budget==steps),call_depth=depth).items():
                    need(integer(row[name])==expected,'budget boundary differs: '+name)
                old.exact_summary(row['fault'],fault);integer(row['checksum'])
                need(row['full_state_context_image_stack_equal'] is True,'budget native full comparison missing')
                if budget==steps:need(row['checksum']==value['cases'][2*scenario]['checksum'],'complete-budget checksum differs')
    expected_order=[]
    for round_index in range(rounds if measured else 0):
        for offset in range(8):
            scenario=(round_index+offset)%8;reset_slot=4 if (round_index+scenario)&1 else 0
            execute_order=('candidate','reference','reference','candidate') if round_index&1 else ('reference','candidate','candidate','reference')
            group=list(execute_order);group.insert(reset_slot,'none')
            for slot,strategy in enumerate(group):expected_order.append((round_index,scenario,slot,strategy))
    need(len(value['records'])==len(expected_order),'raw row count differs')
    samples=[]
    for row,identity in zip(value['records'],expected_order):
        need((integer(row['round']),integer(row['scenario']),integer(row['order_slot']),row['lookup_mode'])==identity,'raw row order differs')
        execute=row['lookup_mode']!='none';scenario=row['scenario'];case=value['cases'][2*scenario]
        need(row['path']==('execute' if execute else 'reset'),'row path differs')
        for name,expected in dict(iterations=iterations,steps_per_iteration=case['steps'] if execute else 0,
                                 switch_commits_per_iteration=int(execute),rejected_api_calls=0).items():
            need(integer(row[name])==expected,'raw row integer differs: '+name)
        word=case['checksum' if execute else 'reset_checksum']
        need(integer(row['checksum'])==(word*iterations)&MASK and row['complete_post_batch_match'] is True,'raw batch completion differs')
        wall=integer(row['wall_ns'],1);cpu=integer(row['thread_cpu_ns'],1)
        samples.append(dict(base=base,**row,cpu_exceeds_wall_ns=max(cpu-wall,0)))
    return samples


def preparation(audit,prepared):
    ready=audit.json(prepared/'result.json')
    need(ready['schema']==1 and ready['status']=='PASS_LOOKUP_PAIR_PREPARED' and ready['out']==str(prepared),
         'preparation identity differs')
    for name,count in [('correctness_callbacks',2976),('normal_callbacks',64),('budget_callbacks',2912),
                       ('timed_callback_executions',0),('app_executions',0),('gpu_executions',0)]:
        need(integer(ready[name])==count,'preparation scope differs: '+name)
    base=Path(ready['baseline_prepared']).resolve(strict=True)
    audit.file(base/'result.json',ready['baseline_receipt_sha256'])
    old.review(base,audit=audit)
    original=audit.json(base/'result.json')
    goldens,image_size,state_rva,result_rva=old.reference(audit,original)
    instructions=audit.json(Path(original['product'])/'native/compiler/window-proc-1000/manifest.json')['instructions']
    artifacts(audit,ready,prepared);overlay(audit,prepared,ready);audit.mapping(ready['tools'])
    cmds=commands(audit,ready,prepared)
    compiler=audit.raw(prepared/'compiler-path.stdout').decode().strip()
    sdk=audit.raw(prepared/'sdk-path.stdout').decode().strip()
    import sys
    need(set(ready['tools'])=={compiler,str(Path(sys.executable).resolve()),str(Path(sdk)/'SDKSettings.json')},
         'tool identity coverage differs')
    flags=[compiler,'-std=c11','-arch','arm64','-isysroot',sdk,'-O3','-Wall','-Wextra','-Werror',
           '-DAOT_WINDOW_SWITCH_V1=1','-I',str(prepared/'sources'),'-I',str(base/'inputs'),'-I',str(MODULE)]
    expected=[('compiler-path',['/usr/bin/xcrun','--find','clang']),('sdk-path',['/usr/bin/xcrun','--show-sdk-path']),
              ('compiler-version',[compiler,'--version'])]
    for kind,source in [('pair',MODULE/'benchmark.c'),('clock',MODULE/'clock_probe.c')]:
        expected.append(('dependencies-'+kind,flags+['-M','-MT','pair',str(source)]))
    for level in LEVELS:
        expected.append(('compile-'+level,flags+[str(MODULE/'benchmark.c'),str(base/'inputs'/(level+'.o')),'-o',str(prepared/('benchmark-'+level))]))
    expected.append(('compile-clock',flags+[str(MODULE/'clock_probe.c'),'-o',str(prepared/'clock-probe')]))
    for kind,source in [('pair',MODULE/'benchmark.c'),('clock',MODULE/'clock_probe.c')]:
        expected.append(('dependencies-after-'+kind,flags+['-M','-MT','pair',str(source)]))
    expected.append(('clock-probe',[str(prepared/'clock-probe')]))
    for label,load_base in zip(('preferred','rebased'),BASES):
        for level in LEVELS:
            key=label+'-'+level
            expected.append(('check-'+key,[str(prepared/('benchmark-'+level)),'--check',str(base/'inputs'/(label+'-image.bin')),
                            str(base/'inputs'/(label+'-permissions.bin')),hex(load_base),str(prepared/key),'1','1']))
    need(list(cmds)==[k for k,_ in expected],'preparation command order differs')
    for label,argv in expected:need(cmds[label]['argv']==argv,'command argv differs: '+label)
    dependencies=set()
    for kind,source in [('pair',MODULE/'benchmark.c'),('clock',MODULE/'clock_probe.c')]:
        raw=audit.raw(prepared/('dependencies-'+kind+'.stdout'))
        need(raw.startswith(b'pair:') and raw==audit.raw(prepared/('dependencies-after-'+kind+'.stdout')),'dependencies changed')
        paths={str(Path(n).resolve(strict=True)) for n in shlex.split(raw.decode().replace('\\\n',' ').split(':',1)[1])}
        need(str(source) in paths,'compiled source missing from dependencies')
        if kind=='pair':
            need({str(prepared/'sources'/n) for n in old.RUNTIME}|
                 {str(base/'inputs/callback_probe_input.h'),str(MODULE/'lookup_bounds.inc')} <= paths,
                 'required native dependencies missing')
        dependencies|=paths
    need(set(ready['compiler_dependencies'])==dependencies,'compiler dependency identity coverage differs')
    audit.mapping(ready['compiler_dependencies'])
    need(ready['binaries']=={level:str(prepared/('benchmark-'+level)) for level in LEVELS},'binary paths differ')
    for path in [*ready['binaries'].values(),str(prepared/'clock-probe')]:
        need(path in ready['artifacts'],'native binary is not frozen');old.native_file(audit,path,2)
    clock=ready['clock']
    need(clock['binary']==str(prepared/'clock-probe') and clock['stdout']==str(prepared/'clock-probe.stdout') and
         clock['parsed']==str(prepared/'clock-parsed.json'),'clock evidence paths differ')
    raw=audit.json(clock['stdout']);need(raw==audit.json(clock['parsed']),'clock parsed/raw differs')
    observed=clock_report(raw)
    need(clock['assessment']=={k:v for k,v in observed.items() if k!='observations'},'clock assessment differs')
    expected_matrix=[(label,load_base,level) for label,load_base in zip(('preferred','rebased'),BASES) for level in LEVELS]
    need([(r['label'],r['base'],r['optimization']) for r in ready['checks']]==expected_matrix,'check matrix differs')
    for row in ready['checks']:
        key=row['label']+'-'+row['optimization'];directory=prepared/key
        need(row['output']==str(directory) and row['stdout']==str(prepared/('check-'+key+'.stdout')) and
             row['parsed']==str(directory/'parsed.json'),'check evidence paths differ')
        raw=audit.json(row['stdout']);need(raw==audit.json(row['parsed']),'check parsed/raw differs')
        response(audit,raw,directory,goldens[key],row['base'],'check',1,1,image_size,state_rva,result_rva,instructions)
    return ready,original,goldens,(image_size,state_rva,result_rva),observed


def summary(samples):
    def describe(values):return dict(median=statistics.median(values),min=min(values),max=max(values))
    inventory={};anomalies=[]
    for row in samples:
        inventory.setdefault((row['base'],row['scenario']),{}).setdefault(row['round'],[]).append(row)
        if row['thread_cpu_ns']>row['wall_ns']:
            anomalies.append({key:row[key] for key in ('base','round','scenario','order_slot')}|
                             dict(cpu_exceeds_wall_ns=row['thread_cpu_ns']-row['wall_ns']))
    result=[]
    for (base,scenario),rounds in sorted(inventory.items()):
        pairs=[];resets=[]
        for round_index,rows in sorted(rounds.items()):
            need(len(rows)==5,'incomplete paired group')
            pair=dict(round=round_index)
            for clock in ('wall_ns','thread_cpu_ns'):
                for mode in ('reference','candidate'):
                    times=[r[clock] for r in rows if r['lookup_mode']==mode]
                    need(len(times)==2,'missing pair member');pair[mode+'_'+clock]=sum(times)
                pair['candidate_over_reference_'+clock]=pair['candidate_'+clock]/pair['reference_'+clock]
            resets.extend(r['wall_ns']/r['iterations'] for r in rows if r['path']=='reset')
            pairs.append(pair)
        result.append(dict(base=base,scenario=scenario,pairs=pairs,
                           candidate_over_reference_wall=describe([p['candidate_over_reference_wall_ns'] for p in pairs]),
                           candidate_faster=sum(p['candidate_wall_ns']<p['reference_wall_ns'] for p in pairs),
                           candidate_slower=sum(p['candidate_wall_ns']>p['reference_wall_ns'] for p in pairs),
                           equal=sum(p['candidate_wall_ns']==p['reference_wall_ns'] for p in pairs),
                           reset_wall_ns_per_iteration=describe(resets)))
    return dict(by_base_scenario=result,cpu_exceeds_wall=anomalies,
                interpretation='Paired descriptive ratios only; wall primary, thread CPU diagnostic. No filtering, reset subtraction, confidence interval or deployment/game speedup claim.')


def review(prepared,measured=None,audit=None):
    audit=audit or old.Audit();prepared=Path(prepared).resolve(strict=True)
    ready,original,goldens,layout,clock=preparation(audit,prepared)
    samples=[]
    if measured is not None:
        measured=Path(measured).resolve(strict=True);receipt=audit.json(measured/'result.json')
        need(receipt['schema']==1 and receipt['status']=='PASS_LOOKUP_PAIR_RAW_MEASURED' and receipt['out']==str(measured) and
             receipt['prepared']==str(prepared) and receipt['prepared_receipt_sha256']==audit.file(prepared/'result.json'),
             'measurement preparation binding differs')
        artifacts(audit,receipt,measured)
        need(receipt['sources_before']==ready['sources_before'],'measurement source binding differs')
        need(receipt['reset_subtracted'] is False and integer(receipt['app_executions'])==integer(receipt['gpu_executions'])==0,
             'measurement scope differs')
        iterations=integer(receipt['iterations'],1,65536);rounds=integer(receipt['rounds'],1,20)
        cmds=commands(audit,receipt,measured);need(list(cmds)==['measure-preferred','measure-rebased'],'measurement command order differs')
        need(len(receipt['runs'])==2,'measurement run matrix differs')
        baseline=Path(ready['baseline_prepared'])
        for row,label,base in zip(receipt['runs'],('preferred','rebased'),BASES):
            directory=measured/label
            need(row==dict(label=label,base=base,optimization='O3',output=str(directory),
                           stdout=str(measured/('measure-'+label+'.stdout')),parsed=str(directory/'parsed.json')),
                 'measurement paths/matrix differ')
            argv=[ready['binaries']['O3'],'--measure',str(baseline/'inputs'/(label+'-image.bin')),
                  str(baseline/'inputs'/(label+'-permissions.bin')),hex(base),str(directory),str(iterations),str(rounds)]
            need(cmds['measure-'+label]['argv']==argv,'measurement argv differs')
            raw=audit.json(row['stdout']);need(raw==audit.json(row['parsed']),'measurement parsed/raw differs')
            samples+=response(audit,raw,directory,goldens[label+'-O3'],base,'measure',iterations,rounds,*layout)
        old.exact_summary(receipt['summary'],summary(samples))
    audit.file(Path(__file__).resolve());audit.file(Path(old.__file__).resolve());audit.finish()
    return dict(schema=1,status='PASS_INDEPENDENT_LOOKUP_PAIR_REVIEW' if measured else 'PASS_INDEPENDENT_LOOKUP_PAIR_PREPARATION_REVIEW',
                prepared=str(prepared),measured=str(measured) if measured else None,
                normal_full_responses=64,timed_final_full_responses=32 if measured else 0,
                budget_pairs_from_native_assertions=1456,budget_full_snapshots_independently_read=0,
                raw_measurement_records=len(samples),samples=samples,summary=summary(samples),clock_probe=clock,
                clock_diagnostic_status='CPU_INTERVAL_EXCEEDS_RAW_WALL_REQUIRES_REVIEW' if any(r['cpu_exceeds_wall_ns'] for r in samples)
                                        else 'NO_CPU_RAW_WALL_INVERSION_OBSERVED_NOT_ACCURACY_CALIBRATED',
                audited_files=dict(sorted(audit.files.items())),native_executions_by_reviewer=0,timer_calls_by_reviewer=0,
                limitations=['64 normal and32 measured-final whole State/image/stack outputs are independently byte-compared when measured.',
                             'Budget full-State/Context/image/stack comparisons and lookup linear oracle are native assertions; reader recomputes their matrix and summaries, not unexported snapshots.',
                             'Same-process selector overhead remains in both paths; ratios do not measure a deployed runtime.',
                             'RAW wall intervals primary, CPU diagnostic; zero observed inversions does not certify clock accuracy or timing stability.',
                             'No filtering, reset subtraction, pooled-base conclusion, full ABI/App/GPU/game or Wine/Rosetta comparison.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared',required=True);parser.add_argument('--measured');parser.add_argument('--out',required=True)
    args=parser.parse_args();out=Path(args.out).absolute()
    need(out==out.resolve() and not out.exists(),'fresh real report required')
    for path in (args.prepared,args.measured):
        if path:need(not out.is_relative_to(Path(path).resolve()),'report overlaps evidence')
    audit=old.Audit()
    try:result=review(args.prepared,args.measured,audit)
    except (ValueError,KeyError,TypeError,OSError,struct.error) as error:
        with out.open('x') as stream:json.dump(dict(status='REVIEW_FAILED_NOT_ACCEPTED',error=str(error),audited_files=audit.files),stream,indent=2,sort_keys=True);stream.write('\n')
        raise
    with out.open('x') as stream:json.dump(result,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n')
    print(json.dumps({key:result[key] for key in ('status','normal_full_responses','timed_final_full_responses','raw_measurement_records')}))


if __name__=='__main__':main()
