"""Independent, read-only single-strategy artifact review.

Never imports either production coordinator. Reuses the frozen independent
baseline reader and pure paired-reader oracle arithmetic.
"""
import argparse
import ast
import json
from pathlib import Path
import shlex
import statistics
import struct
import sys

from window_callback_bench_v1 import review as old
from window_callback_pair_v1 import review as pair

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT/'window_callback_single_v1'
BASES, LEVELS, MASK = old.BASES, old.LEVELS, old.MASK
STRATEGIES = ('reference','candidate')
need, integer = old.need, old.integer
RUNTIME = 'window_bridge/window_runtime/transaction_v1.c'
ANCHOR = pair.ANCHOR


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
    return {str(p) for p in seen|{MODULE/n for n in ('benchmark.c','lookup_impl.inc','lookup_bounds.inc')}|
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


import gzip

PAYLOAD_SIZE=3504+20480+65536
CONTEXT_SIZE=5792
RECORD_SIZE=16+PAYLOAD_SIZE+CONTEXT_SIZE
LAYOUT=dict(schema=1,pointer_width=8,instructions_offset=32,current_offset=752,regions_offset=56,
            region_size=40,region_bytes_offset=16,region_permissions_offset=24,region_slots=16,
            pending_offset=768,pending_slots=16,d3d_map_permissions_offset=5496,module_base_offset=0,budget_offset=8,
            result_offset=696,current_pc_offset=744,result_size=48,result_fault_offset=0,
            result_steps_offset=32,result_depth_offset=40,result_returned_offset=44)
ENCODING='instructions=1,current=index+1,region pointers=index+1,pending=guestVA,NULL=0; all other bytes preserved'


def bounded_payload(audit,path,size):
    path=Path(path);audit.file(path)
    need(not path.is_symlink(),'payload is a symlink')
    if path.suffix=='.gz':
        with gzip.open(path,'rb') as stream:data=stream.read(size+1)
    else:data=audit.raw(path)
    need(len(data)==size,'payload extent differs')
    return data


def context(data,metadata,base,table,row,budget=None):
    need(len(data)==CONTEXT_SIZE,'Context extent differs')
    for k,v in LAYOUT.items():need(integer(metadata[k])==v,'Context layout differs: '+k)
    need(metadata['encoding']==ENCODING,'Context encoding differs')
    u64=lambda offset:struct.unpack_from('<Q',data,offset)[0]
    need(u64(0)==base and u64(8)==(4096 if budget is None else budget),'Context base/budget differs')
    need(u64(32)==1 and u64(40)==len(table) and u64(48)==2,'Context table/region identity differs')
    need(u64(752)<=len(table),'Context current instruction index invalid')
    for i in range(16):
        offset=56+i*40
        need(u64(offset+16)==u64(offset+24)==(i+1 if i<2 else 0),'Context region marker differs')
    need((u64(56),u64(64))==(base,20480) and (u64(96),u64(104))==(0x70000000,65536),'Context regions differ')
    for i in range(16):
        address=u64(768+8*i)
        need(address==0 or base<=address<base+20480 or 0x70000000<=address<0x70010000,'Context pending pointer escaped')
    need(u64(5496)==0,'Context unexpected D3D map')
    fault=row.get('fault',dict(status=0,access=0,pc=0,address=0,width=0))
    need(struct.unpack_from('<IIQQQQII',data,696)==tuple(fault[k] for k in ('status','access','pc','address','width'))+
         (row['steps'],row['call_depth'],row['returned']),'Context result differs from raw completion')


def budgets(audit,directory,value):
    info=value['budget_stream'];rows=value['budget_checks'];count=len(rows)
    expected=dict(path='budget.bin.gz',records=count,record_size=RECORD_SIZE,uncompressed_bytes=count*RECORD_SIZE)
    old.exact_summary(info,expected);path=directory/'budget.bin.gz';audit.file(path)
    need(not path.is_symlink(),'budget stream is a symlink')
    with gzip.open(path,'rb') as stream:
        for index,row in enumerate(rows):
            data=stream.read(RECORD_SIZE);need(len(data)==RECORD_SIZE,'truncated budget stream')
            need(integer(row['stream_offset'])==index*RECORD_SIZE,'budget stream offset differs')
            need(struct.unpack('<4I',data[:16])==(row['scenario'],row['budget'],row['status'],0),'budget header differs')
            yield data
        need(stream.read(1)==b'','budget stream contains trailing bytes')


def response(audit,value,directory,goldens,base,strategy,mode,iterations,group,layout,instructions):
    image_size,state_rva,result_rva=layout;measured=mode=='measure'
    need(value['schema']==1 and value['status']==('PASS_CALLBACK_SINGLE_MEASURE' if measured else 'PASS_CALLBACK_SINGLE_CHECK') and
         value['mode']==mode and value['strategy']==strategy and integer(value['base'])==base,'native identity differs')
    need(strategy in STRATEGIES,'invalid fixed strategy')
    for k,v in dict(state_size=3504,context_size=CONTEXT_SIZE,image_size=image_size,stack_size=65536,reset_bytes_per_iteration=95312,
                    iterations=iterations,group=group,app_executions=0,gpu_executions=0).items():need(integer(value[k])==v,'native scope/count differs: '+k)
    for k in ('reset_included','checksum_included','key_invariants_per_iteration','full_comparison_per_batch','reset_control_not_subtracted'):
        need(value[k] is True,'inclusion differs: '+k)
    for k in ('lto','transaction_trace_hooks','outer_callback_abi_invoked','runtime_strategy_selector'):need(value[k] is False,'scope differs: '+k)
    need(value['wall_clock']=='CLOCK_MONOTONIC_RAW' and value['cpu_clock']=='CLOCK_THREAD_CPUTIME_ID' and
         value['clock_order']=='wall_start,cpu_start,batch,cpu_end,wall_end' and value['legacy_block_fastpath']=='NOT_INTEGRATED','clock/fastpath differs')
    timed=8*iterations if measured else 0;untimed=2064 if measured else 372;reset=2056+8*iterations if measured else 0
    for k,v in dict(actual_callback_executions=timed+untimed,timed_callback_executions=timed,untimed_callback_executions=untimed,
                    reset_control_iterations=reset,all_reset_calls=timed+untimed+reset,timer_calls=64 if measured else 0,
                    clock_resolution_queries=2 if measured else 0,warmup_iterations_per_scenario_path=256 if measured else 0).items():
        need(integer(value[k])==v,'execution ledger differs: '+k)
    for k in ('wall_resolution_ns','thread_cpu_resolution_ns'):need(integer(value[k])>0 if measured else integer(value[k])==0,'resolution differs')
    old.exact_summary(value['lookup_checks'],dict(contexts=0,queries=0,hits=0,misses=0) if measured else pair.lookup_counts(instructions,base))
    need(len(value['cases'])==8,'normal matrix differs');contexts=[]
    for scenario,(case,gold) in enumerate(zip(value['cases'],goldens)):
        for k in old.CASE_FIELDS:need(integer(case[k])==gold['case'][k],'normal semantics differ: '+k)
        filename='case-%d.bin'%scenario;contextname='case-%d.context.bin'%scenario
        need(case['response']==filename and case['context_response']==contextname,'normal path differs')
        need(bounded_payload(audit,directory/filename,PAYLOAD_SIZE)==gold['payload'],'normal full response differs')
        raw_context=bounded_payload(audit,directory/contextname,CONTEXT_SIZE);context(raw_context,value['context_normalization'],base,instructions,case);contexts.append(raw_context)
        need(integer(case['checksum'])==old.response_word(gold['payload'],image_size,state_rva,result_rva,case['steps'],1) and
             integer(case['reset_checksum'])==old.reset_word(scenario),'normal checksum differs')
        if measured:
            need(case['timed_final_response']=='final-'+filename and case['timed_final_context']=='final-'+contextname,'timed final path differs')
            need(bounded_payload(audit,directory/case['timed_final_response'],PAYLOAD_SIZE)==gold['payload'],'actual final response differs')
            need(bounded_payload(audit,directory/case['timed_final_context'],CONTEXT_SIZE)==raw_context,'actual final Context differs')
        else:need(case['timed_final_response'] is None and case['timed_final_context'] is None,'check has timed output')
    need(len(value['budget_checks'])==(0 if measured else 364),'budget matrix differs')
    if measured:old.exact_summary(value['budget_stream'],dict(records=0,record_size=RECORD_SIZE,uncompressed_bytes=0,path=None))
    else:
        cursor=0
        for scenario,gold in enumerate(goldens):
            steps=gold['case']['steps'];trace=gold['case']['trace']
            for budget in range(steps+1):
                row=value['budget_checks'][cursor];cursor+=1;stopped=budget<steps;pc=trace[budget]['pc'] if stopped else 0
                expected=dict(scenario=scenario,budget=budget,status=4 if stopped else 0,steps=budget,returned=int(not stopped),call_depth=trace[budget]['before_depth'] if stopped else 0)
                for k,v in expected.items():need(integer(row[k])==v,'budget semantic differs: '+k)
                old.exact_summary(row['fault'],dict(status=4 if stopped else 0,access=0,pc=pc,address=pc,width=0));integer(row['checksum'])
        for row,data in zip(value['budget_checks'],budgets(audit,directory,value),strict=True):
            payload=data[16:16+PAYLOAD_SIZE];canonical=data[16+PAYLOAD_SIZE:]
            context(canonical,value['context_normalization'],base,instructions,row,row['budget'])
            switch=struct.unpack_from('<Q',canonical,5784)[0]
            need(row['checksum']==old.response_word(payload,image_size,state_rva,result_rva,row['steps'],switch),'budget bytes/checksum differs')
            if row['returned']:need(payload==goldens[row['scenario']]['payload'],'completed budget differs from golden')
    order=[]
    if measured:
        for offset in range(8):
            scenario=(group+offset)%8
            for slot in range(2):order.append((group,scenario,slot,'execute' if (group+scenario+slot)%2==0 else 'reset'))
    need(len(value['records'])==len(order),'raw count differs');samples=[]
    for row,identity in zip(value['records'],order):
        need((integer(row['group']),integer(row['scenario']),integer(row['order_slot']),row['path'])==identity,'native row order differs')
        execute=row['path']=='execute';case=value['cases'][row['scenario']]
        for k,v in dict(iterations=iterations,steps_per_iteration=case['steps'] if execute else 0,switch_commits_per_iteration=int(execute),rejected_api_calls=0).items():need(integer(row[k])==v,'batch integer differs')
        need(integer(row['checksum'])==(case['checksum' if execute else 'reset_checksum']*iterations)&MASK and row['complete_post_batch_match'] is True,'batch completion differs')
        wall=integer(row['wall_ns'],1);cpu=integer(row['thread_cpu_ns'],1)
        samples.append(dict(base=base,strategy=strategy,**row,cpu_exceeds_wall_ns=max(cpu-wall,0)))
    return samples,contexts


def native_inspection(audit,directory,key):
    strategy=key.split('-')[0]
    undefined=audit.raw(directory/('nm-u-'+key+'.stdout')).decode()
    symbols=audit.raw(directory/('nm-'+key+'.stdout')).decode()
    disassembly=audit.raw(directory/('disasm-'+key+'.stdout')).decode()
    need(('_bsearch' in undefined.split())==(strategy=='reference'),'fixed strategy bsearch import differs')
    need('aot_pair_lookup_mode' not in symbols and 'aot_pair_lookup_mode' not in disassembly,'shared selector present')
    need('_aot_begin:' in disassembly and '_aot_execute:' in disassembly,'real callback runtime disassembly absent')
    return dict(strategy=strategy,bsearch_imported=strategy=='reference',shared_selector_symbol=False,
                scope='Exact source overlay plus real undefined-symbol and disassembly records; not an exhaustive machine-code semantic proof.')


def preparation(audit,prepared):
    v=audit.json(prepared/'result.json')
    need(v['schema']==1 and v['status']=='PASS_SINGLE_LOOKUP_PREPARED' and v['out']==str(prepared),'prepared identity differs')
    for k,n in dict(correctness_callbacks=2976,normal_callbacks=64,budget_callbacks=2912,full_budget_record_comparisons=2184,timed_callback_executions=0,app_executions=0,gpu_executions=0).items():
        need(integer(v[k])==n,'prepared scope differs: '+k)
    base=Path(v['baseline_prepared']).resolve(strict=True);audit.file(base/'result.json',v['baseline_receipt_sha256']);old.review(base,audit=audit)
    original=audit.json(base/'result.json');goldens,image_size,state_rva,result_rva=old.reference(audit,original);layout=(image_size,state_rva,result_rva)
    instructions=audit.json(Path(original['product'])/'native/compiler/window-proc-1000/manifest.json')['instructions']
    artifacts(audit,v,prepared);cmds=commands(audit,v,prepared)
    generated={str(prepared/'sources'/s/n) for s in STRATEGIES for n in old.RUNTIME}
    need(set(v['generated'])==generated,'generated source coverage differs')
    replacement=audit.raw(MODULE/'lookup_impl.inc')
    need(replacement.startswith(b'static const AotInstruction *instruction(') and replacement.endswith(b'\n') and b'aot_pair_lookup_mode' not in replacement,'invalid single lookup replacement')
    for strategy in STRATEGIES:
        for name in old.RUNTIME:
            expected=audit.raw(ROOT/name)
            if name==RUNTIME and strategy=='candidate':
                need(expected.count(ANCHOR)==1,'runtime replacement anchor differs');expected=expected.replace(ANCHOR,replacement,1)
            path=prepared/'sources'/strategy/name
            need(audit.raw(path)==expected,'runtime changed outside allowed function');audit.file(path,v['generated'][str(path)])
    compiler=audit.raw(prepared/'compiler-path.stdout').decode().strip();sdk=audit.raw(prepared/'sdk-path.stdout').decode().strip()
    need(set(v['tools'])=={compiler,str(Path(sys.executable).resolve()),str(Path(sdk)/'SDKSettings.json'),'/usr/bin/nm','/usr/bin/otool'},'tool coverage differs');audit.mapping(v['tools'])
    expected=[('compiler-path',['/usr/bin/xcrun','--find','clang']),('sdk-path',['/usr/bin/xcrun','--show-sdk-path']),('compiler-version',[compiler,'--version'])]
    deps=set();binary_paths={}
    for strategy in STRATEGIES:
        flags=[compiler,'-std=c11','-arch','arm64','-isysroot',sdk,'-O3','-Wall','-Wextra','-Werror','-DAOT_WINDOW_SWITCH_V1=1',
               '-DAOT_SINGLE_CANDIDATE='+str(int(strategy=='candidate')),'-I',str(prepared/'sources'/strategy),'-I',str(base/'inputs'),'-I',str(MODULE)]
        expected.append(('dependencies-'+strategy,flags+['-M','-MT','pair',str(MODULE/'benchmark.c')]))
        for level in LEVELS:
            key=strategy+'-'+level;binary=str(prepared/('benchmark-'+key));binary_paths[key]=binary
            expected.extend([('compile-'+key,flags+[str(MODULE/'benchmark.c'),str(base/'inputs'/(level+'.o')),'-lz','-o',binary]),
                             ('nm-u-'+key,['/usr/bin/nm','-u',binary]),('nm-'+key,['/usr/bin/nm','-a',binary]),('disasm-'+key,['/usr/bin/otool','-tvV',binary])])
            need(binary in v['artifacts'],'unfrozen binary');old.native_file(audit,binary,2)
            old.exact_summary(v['inspection'][key],native_inspection(audit,prepared,key))
        expected.append(('dependencies-after-'+strategy,flags+['-M','-MT','pair',str(MODULE/'benchmark.c')]))
        raw=audit.raw(prepared/('dependencies-'+strategy+'.stdout'))
        need(raw.startswith(b'pair:') and raw==audit.raw(prepared/('dependencies-after-'+strategy+'.stdout')),'native dependencies changed')
        paths={str(Path(p).resolve(strict=True)) for p in shlex.split(raw.decode().replace('\\\n',' ').split(':',1)[1])}
        need({str(prepared/'sources'/strategy/n) for n in old.RUNTIME}|{str(MODULE/'benchmark.c'),str(MODULE/'lookup_bounds.inc'),str(base/'inputs/callback_probe_input.h')}<=paths,'required dependency missing')
        deps|=paths
    need(v['binaries']==binary_paths,'binary path matrix differs');need(set(v['compiler_dependencies'])==deps,'native dependency coverage differs');audit.mapping(v['compiler_dependencies'])
    check_order=[(label,b,l,s) for label,b in zip(('preferred','rebased'),BASES) for l in LEVELS for s in STRATEGIES]
    need(len(v['checks'])==len(check_order),'preparation matrix count differs');loaded=[];anchors={}
    for run,(label,load_base,level,strategy) in zip(v['checks'],check_order):
        key=label+'-'+level+'-'+strategy;directory=prepared/key
        need(run==dict(label=label,base=load_base,optimization=level,strategy=strategy,output=str(directory),stdout=str(prepared/('check-'+key+'.stdout')),parsed=str(directory/'parsed.json')),'check matrix/paths differ')
        expected.append(('check-'+key,[binary_paths[strategy+'-'+level],'--check',str(base/'inputs'/(label+'-image.bin')),str(base/'inputs'/(label+'-permissions.bin')),hex(load_base),str(directory),'1','0']))
        raw=audit.json(run['stdout']);need(raw==audit.json(run['parsed']),'check raw/parsed differs')
        _,contexts=response(audit,raw,directory,goldens[label+'-'+level],load_base,strategy,'check',1,0,layout,instructions)
        if load_base not in anchors:anchors[load_base]=contexts
        else:need(anchors[load_base]==contexts,'cross-artifact normal Context differs')
        loaded.append((run,raw))
    need(list(cmds)==[label for label,_ in expected],'actual preparation command sequence differs')
    for label,argv in expected:need(cmds[label]['argv']==argv,'actual argv differs: '+label)
    comparisons=0
    for load_base in BASES:
        group=[(run,raw) for run,raw in loaded if run['base']==load_base];left,lv=group[0]
        for right,rv in group[1:]:
            need(lv['budget_checks']==rv['budget_checks'],'cross-artifact budget summaries differ')
            for a,b in zip(budgets(audit,Path(left['output']),lv),budgets(audit,Path(right['output']),rv),strict=True):
                need(a==b,'full budget State/image/stack/normalized Context differs');comparisons+=1
    need(comparisons==2184,'full comparison count differs')
    return v,original,goldens,layout,instructions,anchors


def process_order(rounds):
    for base in BASES:
        for group in range(rounds):
            order=STRATEGIES+STRATEGIES[::-1] if group%2==0 else STRATEGIES[::-1]+STRATEGIES
            for slot,strategy in enumerate(order):yield base,group,slot,strategy


def summary(samples):
    def stats(values):return dict(median=statistics.median(values),min=min(values),max=max(values))
    groups={};anomalies=[]
    for row in samples:
        groups.setdefault((row['base'],row['scenario']),{}).setdefault(row['group_index'],[]).append(row)
        if row['thread_cpu_ns']>row['wall_ns']:
            anomalies.append({k:row[k] for k in ('base','group_index','process_slot','strategy','scenario','path')}|dict(cpu_exceeds_wall_ns=row['thread_cpu_ns']-row['wall_ns']))
    cells=[]
    for (base,scenario),rounds in sorted(groups.items()):
        pairs=[]
        for group,rows in sorted(rounds.items()):
            need(len(rows)==8,'incomplete process pair group');p=dict(group_index=group)
            for clock in ('wall_ns','thread_cpu_ns'):
                for strategy in STRATEGIES:
                    selected=[r[clock] for r in rows if r['strategy']==strategy and r['path']=='execute'];need(len(selected)==2,'missing paired process')
                    p[strategy+'_'+clock]=sum(selected)
                p['candidate_over_reference_'+clock]=p['candidate_'+clock]/p['reference_'+clock]
            pairs.append(p)
        cells.append(dict(base=base,scenario=scenario,pairs=pairs,candidate_over_reference_wall=stats([p['candidate_over_reference_wall_ns'] for p in pairs]),
                          candidate_faster=sum(p['candidate_wall_ns']<p['reference_wall_ns'] for p in pairs),candidate_slower=sum(p['candidate_wall_ns']>p['reference_wall_ns'] for p in pairs),equal=sum(p['candidate_wall_ns']==p['reference_wall_ns'] for p in pairs)))
    return dict(by_base_scenario=cells,cpu_exceeds_wall=anomalies,interpretation='Process-paired batch intervals only; startup excluded. All rows retained; no filtering/reset subtraction/confidence or App/game claim.')


def review(prepared,measured=None,audit=None):
    audit=audit or old.Audit();prepared=Path(prepared).resolve(strict=True)
    ready,original,goldens,layout,instructions,anchors=preparation(audit,prepared);samples=[];processes=0
    if measured is not None:
        measured=Path(measured).resolve(strict=True);v=audit.json(measured/'result.json')
        need(v['schema']==1 and v['status']=='PASS_SINGLE_LOOKUP_RAW_MEASURED' and v['out']==str(measured) and
             v['prepared']==str(prepared) and v['prepared_receipt_sha256']==audit.file(prepared/'result.json'),'measurement identity differs')
        artifacts(audit,v,measured);need(v['sources_before']==ready['sources_before'],'measurement source changed')
        need(v['reset_subtracted'] is False and v['startup_timed'] is False and integer(v['app_executions'])==integer(v['gpu_executions'])==0,'measurement scope differs')
        iterations=integer(v['iterations'],1,65536);rounds=integer(v['rounds'],1,20);order=list(process_order(rounds));processes=len(order)
        need(len(v['runs'])==processes,'process matrix differs');cmds=commands(audit,v,measured);expected_labels=[];baseprepared=Path(ready['baseline_prepared'])
        for run,(base,group,slot,strategy) in zip(v['runs'],order):
            label='preferred' if base==BASES[0] else 'rebased';key='%s-g%02d-s%d-%s'%(label,group,slot,strategy);directory=measured/key
            need(run==dict(label=label,base=base,group_index=group,process_slot=slot,strategy=strategy,optimization='O3',output=str(directory),stdout=str(measured/('measure-'+key+'.stdout')),parsed=str(directory/'parsed.json')),'process order or paths differ')
            command='measure-'+key;expected_labels.append(command)
            need(cmds[command]['argv']==[ready['binaries'][strategy+'-O3'],'--measure',str(baseprepared/'inputs'/(label+'-image.bin')),str(baseprepared/'inputs'/(label+'-permissions.bin')),hex(base),str(directory),str(iterations),str(group)],'measured process argv differs')
            raw=audit.json(run['stdout']);need(raw==audit.json(run['parsed']),'measurement raw/parsed differs')
            rows,contexts=response(audit,raw,directory,goldens[label+'-O3'],base,strategy,'measure',iterations,group,layout,instructions)
            need(contexts==anchors[base],'measured normal Context differs from preparation')
            samples.extend(dict(**row,group_index=group,process_slot=slot) for row in rows)
        need(list(cmds)==expected_labels,'measure command sequence differs');old.exact_summary(v['summary'],summary(samples))
    audit.file(Path(__file__).resolve());audit.file(Path(pair.__file__).resolve());audit.finish()
    return dict(schema=1,status='PASS_INDEPENDENT_SINGLE_LOOKUP_REVIEW' if measured else 'PASS_INDEPENDENT_SINGLE_LOOKUP_PREPARATION_REVIEW',
                prepared=str(prepared),measured=str(measured) if measured else None,normal_prepared_full_responses=64,
                full_budget_records_read=2912,full_budget_cross_artifact_comparisons=2184,normal_measured_full_responses=processes*8,
                timed_final_full_responses=processes*8,measured_processes=processes,raw_measurement_records=len(samples),samples=samples,
                summary=summary(samples),clock_diagnostic_status='CPU_INTERVAL_EXCEEDS_RAW_WALL_REQUIRES_REVIEW' if any(r['cpu_exceeds_wall_ns'] for r in samples) else 'NO_CPU_RAW_WALL_INVERSION_OBSERVED_NOT_ACCURACY_CALIBRATED',
                audited_files=dict(sorted(audit.files.items())),native_executions_by_reviewer=0,timer_calls_by_reviewer=0,
                limitations=['Budget records include full State/image/stack and pointer-canonical Context; all other Context bytes retained.',
                             'Separate fixed-strategy component binaries, no integrated App/ABI/game/Wine performance claim.',
                             'Process startup excluded, uncontrolled scheduling/frequency/thermal state, all samples retained, no reset subtraction.'])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--prepared',required=True);parser.add_argument('--measured');parser.add_argument('--out',required=True)
    args=parser.parse_args();out=Path(args.out).absolute();need(out==out.resolve() and not out.exists(),'fresh real report required')
    for path in (args.prepared,args.measured):
        if path:need(not out.is_relative_to(Path(path).resolve()),'report overlaps evidence')
    audit=old.Audit()
    try:result=review(args.prepared,args.measured,audit)
    except (ValueError,KeyError,TypeError,OSError,struct.error) as error:
        with out.open('x') as stream:json.dump(dict(status='REVIEW_FAILED_NOT_ACCEPTED',error=str(error),audited_files=audit.files),stream,indent=2,sort_keys=True);stream.write('\n')
        raise
    with out.open('x') as stream:json.dump(result,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n')
    print(json.dumps({k:result[k] for k in ('status','normal_prepared_full_responses','full_budget_records_read','raw_measurement_records')}))


if __name__=='__main__':main()
