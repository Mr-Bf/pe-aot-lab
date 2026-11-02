"""Pure evidence-mutation tests; no native process or performance sampling."""
import copy
from pathlib import Path
import unittest

from window_callback_bench_v1.test_review import fixture as old_fixture, IMAGE_SIZE, STATE_RVA, RESULT_RVA
from . import review as r


class BytesAudit:
    def __init__(self,payloads):self.payloads=payloads
    def raw(self,path):return self.payloads[Path(path).name]


def fixture(measured=True):
    value,_,goldens,_=old_fixture();base=r.BASES[0];rounds=3;iterations=3
    cases=[];payloads={};budget=[]
    for scenario,gold in enumerate(goldens):
        steps=45 if scenario<7 else 41
        gold['case']['steps']=steps
        gold['case']['trace']=[dict(pc=base+16*i,before_depth=int(10<=i<20)) for i in range(steps)]
        for mode in ('reference','candidate'):
            case={k:gold['case'][k] for k in r.old.CASE_FIELDS}
            name='case-%s-%d.bin'%(mode,scenario)
            case.update(lookup_mode=mode,response=name,timed_final_response='final-'+name if measured else None,
                        checksum=r.old.response_word(gold['payload'],IMAGE_SIZE,STATE_RVA,RESULT_RVA,steps,1),
                        reset_checksum=r.old.reset_word(scenario))
            cases.append(case);payloads[name]=gold['payload']
            if measured:payloads['final-'+name]=gold['payload']
        for b in range(steps+1):
            fault_pc=gold['case']['trace'][b]['pc'] if b<steps else 0
            budget.append(dict(scenario=scenario,budget=b,status=4 if b<steps else 0,steps=b,returned=int(b==steps),
                               call_depth=gold['case']['trace'][b]['before_depth'] if b<steps else 0,
                               checksum=cases[-1]['checksum'] if b==steps else 99,
                               fault=dict(status=4 if b<steps else 0,access=0,pc=fault_pc,address=fault_pc,width=0),
                               full_state_context_image_stack_equal=True))
    instructions=[dict(rva=0x1000,length=5)]
    timed=8*rounds*4*iterations if measured else 0;untimed=16+4096+32*rounds if measured else 744
    resets=2048+8*rounds*(iterations+1) if measured else 0
    value.update(status='PASS_CALLBACK_PAIR_MEASURE' if measured else 'PASS_CALLBACK_PAIR_CHECK',
                 mode='measure' if measured else 'check',iterations=iterations,rounds=rounds,
                 actual_callback_executions=timed+untimed,timed_callback_executions=timed,untimed_callback_executions=untimed,
                 reset_control_iterations=resets,all_reset_calls=timed+untimed+resets+8,
                 timer_calls=rounds*8*5*4 if measured else 0,clock_resolution_queries=2 if measured else 0,
                 warmup_iterations_per_scenario_path=256 if measured else 0,
                 wall_resolution_ns=42 if measured else 0,thread_cpu_resolution_ns=42 if measured else 0,
                 wall_clock='CLOCK_MONOTONIC_RAW',
                 strategy_dispatch='shared volatile mode load and branch per valid instruction lookup',
                 pair_order='ABBA even rounds, BAAB odd rounds; reset before/after by round+scenario parity',
                 final_snapshot_capture='live final execute batch for each mode copied outside clocks; IO after all timed batches',
                 cases=cases,budget_checks=[] if measured else budget,
                 lookup_checks=dict(contexts=0,queries=0,hits=0,misses=0) if measured else r.lookup_counts(instructions,base),records=[])
    if measured:
        for round_index in range(rounds):
            for offset in range(8):
                scenario=(round_index+offset)%8;order=['reference','candidate','candidate','reference']
                if round_index&1:order.reverse();order=['candidate','reference','reference','candidate']
                order.insert(4 if (round_index+scenario)&1 else 0,'none')
                for slot,mode in enumerate(order):
                    execute=mode!='none';word=cases[2*scenario]['checksum' if execute else 'reset_checksum']
                    wall={'reference':1000,'candidate':800,'none':300}[mode]*(round_index+1)
                    value['records'].append(dict(round=round_index,scenario=scenario,order_slot=slot,lookup_mode=mode,
                         path='execute' if execute else 'reset',iterations=iterations,wall_ns=wall,thread_cpu_ns=wall-100,
                         checksum=(word*iterations)&r.MASK,steps_per_iteration=goldens[scenario]['case']['steps'] if execute else 0,
                         switch_commits_per_iteration=int(execute),rejected_api_calls=0,complete_post_batch_match=True))
    return value,payloads,goldens,instructions


def clock_fixture():
    checksum=0x29dff4c8a1076e35
    for i in range(65536):checksum=((checksum^(i+0x9e3779b97f4a7c15))*0xbf58476d1ce4e5b9)&r.MASK
    names=['CLOCK_MONOTONIC','CLOCK_MONOTONIC_RAW','CLOCK_UPTIME_RAW','CLOCK_THREAD_CPUTIME_ID']
    return dict(schema=1,status='CLOCK_OBSERVATIONS_RECORDED',read_pairs_per_clock=128,windows_per_wall_clock=16,
                work_iterations=65536,warmup_work_calls=1,timebase_numer=125,timebase_denom=3,work_checksum=checksum,
                sample_order='wall_start,cpu_start,work,cpu_end,wall_end',clocks=[dict(name=name,resolution_ns=42,
                adjacent_reads=[[i*100,i*100+42] for i in range(128)],work_windows=[dict(round=i,wall_start=100000+i*10000,
                wall_end=100000+i*10000+1000,cpu_start=10000+i*1000,cpu_end=10000+i*1000+900,checksum=checksum)
                for i in range(16)] if n<3 else []) for n,name in enumerate(names)])


class ReviewTests(unittest.TestCase):
    def validate(self,values=None):
        v,p,g,insns=values or fixture()
        return r.response(BytesAudit(p),v,Path('/synthetic'),g,v['base'],v['mode'],v['iterations'],v['rounds'],
                          IMAGE_SIZE,STATE_RVA,RESULT_RVA,insns)

    def bad(self,change,measured=True):
        values=fixture(measured);change(*values)
        with self.assertRaises(ValueError):self.validate(values)

    def test_all_pairs_recomputed(self):
        rows=self.validate();s=r.summary(rows)
        self.assertEqual(len(rows),120);self.assertEqual(len(s['by_base_scenario']),8)
        self.assertEqual(s['by_base_scenario'][0]['candidate_over_reference_wall'],dict(median=.8,min=.8,max=.8))
        self.assertEqual(s['by_base_scenario'][0]['candidate_faster'],3)

    def test_normal_budget_lookup_check(self):self.assertEqual(self.validate(fixture(False)),[])

    def test_slow_and_inverse_samples_retained(self):
        values=fixture();row=next(x for x in values[0]['records'] if x['lookup_mode']=='candidate')
        row['wall_ns']=10_000_000;row['thread_cpu_ns']=10_000_001
        rows=self.validate(values);s=r.summary(rows)
        self.assertEqual(len(rows),120);self.assertEqual(len(s['cpu_exceeds_wall']),1)
        self.assertGreater(s['by_base_scenario'][0]['candidate_over_reference_wall']['max'],1000)

    def test_bases_kept_separate(self):
        a=self.validate();b=copy.deepcopy(a)
        for row in b:row['base']=r.BASES[1]
        self.assertEqual(len(r.summary(a+b)['by_base_scenario']),16)

    def test_pair_order_rejected(self):self.bad(lambda v,p,g,i:v['records'].reverse())
    def test_missing_sample_rejected(self):self.bad(lambda v,p,g,i:v['records'].pop())
    def test_duplicate_pair_member_rejected(self):
        self.bad(lambda v,p,g,i:v['records'].__setitem__(2,copy.deepcopy(v['records'][1])))
    def test_final_bytes_rejected(self):
        self.bad(lambda v,p,g,i:p.__setitem__('final-case-candidate-0.bin',bytes(len(p['case-candidate-0.bin']))))
    def test_normal_bytes_rejected(self):
        self.bad(lambda v,p,g,i:p.__setitem__('case-reference-0.bin',bytes(len(p['case-reference-0.bin']))))
    def test_batch_checksum_rejected(self):self.bad(lambda v,p,g,i:v['records'][1].__setitem__('checksum',0))
    def test_scope_and_counter_rejected(self):
        for key,bad in [('reset_included',False),('lto',True),('actual_callback_executions',1),('all_reset_calls',1)]:
            with self.subTest(key=key):self.bad(lambda v,p,g,i:v.__setitem__(key,bad))
    def test_boolean_sample_rejected(self):self.bad(lambda v,p,g,i:v['records'][0].__setitem__('wall_ns',True))
    def test_nonpositive_interval_rejected(self):self.bad(lambda v,p,g,i:v['records'][0].__setitem__('thread_cpu_ns',0))
    def test_budget_fault_pc_rejected(self):self.bad(lambda v,p,g,i:v['budget_checks'][2]['fault'].__setitem__('pc',0),False)
    def test_budget_full_comparison_required(self):self.bad(lambda v,p,g,i:v['budget_checks'][2].__setitem__('full_state_context_image_stack_equal',False),False)
    def test_budget_count_rejected(self):self.bad(lambda v,p,g,i:v['budget_checks'].pop(),False)
    def test_lookup_counts_recomputed(self):self.bad(lambda v,p,g,i:v['lookup_checks'].__setitem__('hits',0),False)
    def test_summary_forgery_rejected(self):
        original=r.summary(self.validate());changed=copy.deepcopy(original)
        changed['by_base_scenario'][0]['candidate_faster']=True
        with self.assertRaises(ValueError):r.old.exact_summary(changed,original)
    def test_clock_observations_and_inverse_retained(self):
        value=clock_fixture();value['clocks'][1]['work_windows'][0]['cpu_end']+=101
        got=r.clock_report(value)
        self.assertEqual(got['status'],'SELF_MONOTONIC_WORKLOAD_VALIDATED_NOT_ACCURACY_CALIBRATED')
        self.assertEqual(got['cpu_exceeds_wall'][0]['cpu_exceeds_wall_ns'],1)
    def test_clock_regression_rejected(self):
        value=clock_fixture();value['clocks'][0]['adjacent_reads'][5][1]=0
        with self.assertRaises(ValueError):r.clock_report(value)
    def test_clock_checksum_recomputed(self):
        value=clock_fixture();value['work_checksum']^=1
        with self.assertRaises(ValueError):r.clock_report(value)
    def test_clock_inventory_rejected(self):
        value=clock_fixture();value['clocks'].pop()
        with self.assertRaises(ValueError):r.clock_report(value)


if __name__=='__main__':unittest.main()
