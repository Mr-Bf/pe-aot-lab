"""Synthetic rejection tests: no compiler, callback, App or timer is executed."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from . import runner as r


def clock_fixture():
    checksum=0x29dff4c8a1076e35
    for i in range(65536):checksum=((checksum^(i+0x9e3779b97f4a7c15))*0xbf58476d1ce4e5b9)&r.MASK
    clocks=[]
    for index,name in enumerate(('CLOCK_MONOTONIC','CLOCK_MONOTONIC_RAW','CLOCK_UPTIME_RAW','CLOCK_THREAD_CPUTIME_ID')):
        clocks.append(dict(name=name,resolution_ns=42,adjacent_reads=[[i*100,i*100+42] for i in range(128)],
                           work_windows=[] if index==3 else [dict(round=i,wall_start=1000*i,wall_end=1000*i+900,
                                                                  cpu_start=1000*i,cpu_end=1000*i+800,checksum=checksum) for i in range(16)]))
    return dict(schema=1,status='CLOCK_OBSERVATIONS_RECORDED',read_pairs_per_clock=128,windows_per_wall_clock=16,
                work_iterations=65536,warmup_work_calls=1,sample_order='wall_start,cpu_start,work,cpu_end,wall_end',
                timebase_numer=125,timebase_denom=3,work_checksum=checksum,clocks=clocks)


def measure_fixture(root):
    cases=[];goldens=[];iterations=2;rounds=1
    for scenario in range(8):
        normal=dict(initial_position=scenario,position=min(scenario+1,7),moves=int(scenario<7),draws=0,
                    keydowns=1,dirty=int(scenario<7),status=0,returned=1,call_depth=0,
                    steps=45 if scenario<7 else 41,switch_commits=1,rejected_api_calls=0)
        payload=('fixture-state-%d'%scenario).encode();gold=root/('gold-%d.bin'%scenario);gold.write_bytes(payload)
        goldens.append(dict(path=str(gold),case=normal))
        for mode in ('reference','candidate'):
            response='case-%s-%d.bin'%(mode,scenario);final='final-'+response
            (root/response).write_bytes(payload);(root/final).write_bytes(payload)
            cases.append(dict(**normal,lookup_mode=mode,response=response,timed_final_response=final,checksum=scenario+1,reset_checksum=scenario+9))
    rows=[]
    for round_index,scenario,slot,path,mode in r.record_order(rounds):
        execute=path=='execute'
        rows.append(dict(round=round_index,scenario=scenario,order_slot=slot,path=path,lookup_mode=mode,iterations=iterations,
                         wall_ns=100 if mode=='candidate' else 200,thread_cpu_ns=90,checksum=(scenario+(1 if execute else 9))*iterations,
                         steps_per_iteration=(45 if scenario<7 else 41) if execute else 0,switch_commits_per_iteration=int(execute),
                         rejected_api_calls=0,complete_post_batch_match=True))
    timed=rounds*8*4*iterations;untimed=16+4096+rounds*8*4;reset=2048+rounds*8*(iterations+1)
    value=dict(status='PASS_CALLBACK_PAIR_MEASURE',mode='measure',base=r.BASES[0],iterations=iterations,rounds=rounds,
               state_size=3504,context_size=5792,image_size=20480,stack_size=65536,reset_bytes_per_iteration=95312,
               app_executions=0,gpu_executions=0,reset_included=True,checksum_included=True,key_invariants_per_iteration=True,
               full_comparison_per_batch=True,reset_control_not_subtracted=True,lto=False,transaction_trace_hooks=False,
               outer_callback_abi_invoked=False,legacy_block_fastpath='NOT_INTEGRATED',wall_clock='CLOCK_MONOTONIC_RAW',
               cpu_clock='CLOCK_THREAD_CPUTIME_ID',clock_order='wall_start,cpu_start,batch,cpu_end,wall_end',
               strategy_dispatch='shared volatile mode load and branch per valid instruction lookup',
               pair_order='ABBA even rounds, BAAB odd rounds; reset before/after by round+scenario parity',
               cases=cases,budget_checks=[],lookup_checks=dict(contexts=0,queries=0,hits=0,misses=0),
               actual_callback_executions=timed+untimed,timed_callback_executions=timed,untimed_callback_executions=untimed,
               reset_control_iterations=reset,all_reset_calls=timed+untimed+reset+8,timer_calls=rounds*8*5*4,
               clock_resolution_queries=2,warmup_iterations_per_scenario_path=256,wall_resolution_ns=42,thread_cpu_resolution_ns=42,records=rows)
    return value,goldens


class PairRunnerTests(unittest.TestCase):
    def test_exact_overlay_only(self):
        original=b'prefix\n'+r.ORIGINAL_LOOKUP.encode()+b'suffix\n';replacement=b'static const AotInstruction *instruction(void) { return 0; }\n'
        self.assertEqual(r.overlay_bytes(original,replacement),b'prefix\n'+replacement+b'suffix\n')
        for bad in (b'none',original+original,original.replace(b'bsearch',b'bsearch_changed')):
            with self.assertRaises(ValueError):r.overlay_bytes(bad,replacement)

    def test_workload_bounds(self):
        for args in ((0,1),(1,0),(True,1),(1,21),(65537,1)):
            with self.assertRaises(ValueError):r.bounded(*args)
        r.bounded(4096,12)

    def test_clock_valid_and_inverse_retained(self):
        value=clock_fixture();self.assertEqual(r.validate_clock(value)['cpu_exceeds_wall'],[])
        value['clocks'][1]['work_windows'][0]['cpu_end']=950
        self.assertEqual(r.validate_clock(value)['cpu_exceeds_wall'],[dict(clock='CLOCK_MONOTONIC_RAW',round=0,cpu_exceeds_wall_ns=50)])

    def test_clock_nonmonotonic_and_bad_checksum_rejected(self):
        good=clock_fixture()
        bad=copy.deepcopy(good);bad['clocks'][1]['adjacent_reads'][2]=[0,1]
        with self.assertRaises(ValueError):r.validate_clock(bad)
        bad=copy.deepcopy(good);bad['work_checksum']+=1
        with self.assertRaises(ValueError):r.validate_clock(bad)
        bad=copy.deepcopy(good);bad['clocks'][0]['work_windows'].pop()
        with self.assertRaises(ValueError):r.validate_clock(bad)

    def test_pair_sequence_even_and_odd(self):
        rows=list(r.record_order(2))
        for round_index,want in ((0,['reference','candidate','candidate','reference']),(1,['candidate','reference','reference','candidate'])):
            for scenario in range(8):
                group=[row for row in rows if row[0]==round_index and row[1]==scenario]
                self.assertEqual([row[4] for row in group if row[3]=='execute'],want)
                reset=[row for row in group if row[3]=='reset']
                self.assertEqual(reset[0][2],4 if (round_index+scenario)&1 else 0)

    def test_valid_complete_measure_and_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);value,gold=measure_fixture(root)
            r.validate_response(value,root,gold,r.BASES[0],'measure',2,1,[])
            r.write(root/'parsed.json',value)
            result=r.summarize([dict(base=r.BASES[0],parsed=str(root/'parsed.json'))])
            self.assertEqual(len(result['by_base_scenario']),8)
            for row in result['by_base_scenario']:
                self.assertEqual(row['candidate_over_reference_wall'],dict(median=.5,min=.5,max=.5))
                self.assertEqual((row['candidate_faster'],row['candidate_slower'],row['equal']),(1,0,0))

    def test_timed_final_must_be_live_golden_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);value,gold=measure_fixture(root)
            (root/value['cases'][1]['timed_final_response']).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'timed final'):r.validate_response(value,root,gold,r.BASES[0],'measure',2,1,[])

    def test_bad_order_checksum_counts_and_clock_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);good,gold=measure_fixture(root)
            for field,replacement in [('order_slot',7),('checksum',0),('wall_ns',0),('iterations',True)]:
                bad=copy.deepcopy(good);bad['records'][0][field]=replacement
                with self.assertRaises(ValueError):r.validate_response(bad,root,gold,r.BASES[0],'measure',2,1,[])
            bad=copy.deepcopy(good);bad['all_reset_calls']-=8
            with self.assertRaises(ValueError):r.validate_response(bad,root,gold,r.BASES[0],'measure',2,1,[])

    def test_measure_rejects_before_native_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'new-output'
            with patch.object(r.baseline,'native_host'),patch.object(r,'verify_prepared',side_effect=ValueError('changed source')),patch.object(r.baseline.Commands,'run') as native:
                with self.assertRaisesRegex(ValueError,'changed source'):r.measure(root,out)
                native.assert_not_called();self.assertFalse(out.exists())

    def test_lookup_counts_include_edges(self):
        value=r.lookup_expected(r.BASES[0],[dict(rva=7,length=1)])
        self.assertEqual(value['contexts'],53)
        self.assertEqual(value['queries'],value['hits']+value['misses'])
        self.assertGreater(value['hits'],0);self.assertGreater(value['misses'],0)


if __name__=='__main__':
    unittest.main()
