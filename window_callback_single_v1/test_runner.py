"""Synthetic boundary tests; no compiler, native callback or timing is run."""
import copy
import gzip
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from . import runner as r


def fixture(root,base=None,strategy='reference',group=0):
    base=r.BASES[0] if base is None else base;cases=[];goldens=[];n=2
    for i in range(8):
        normal=dict(initial_position=i,position=min(i+1,7),moves=int(i<7),draws=0,keydowns=1,dirty=int(i<7),status=0,returned=1,call_depth=0,steps=45 if i<7 else 41,switch_commits=1,rejected_api_calls=0)
        data=bytes([i])*r.PAYLOAD_SIZE;gold=root/('gold-%d.bin'%i);gold.write_bytes(data);goldens.append(dict(case=normal,path=str(gold)))
        for prefix in ('','final-'):
            (root/(prefix+'case-%d.bin'%i)).write_bytes(data)
            (root/(prefix+'case-%d.context.bin'%i)).write_bytes(bytes(r.CONTEXT_SIZE))
        cases.append(dict(**normal,response='case-%d.bin'%i,context_response='case-%d.context.bin'%i,timed_final_response='final-case-%d.bin'%i,timed_final_context='final-case-%d.context.bin'%i,checksum=i+1,reset_checksum=i+9))
    rows=[]
    for g,i,slot,path in r.record_order(group):
        execute=path=='execute';rows.append(dict(group=g,scenario=i,order_slot=slot,path=path,iterations=n,wall_ns=100 if strategy=='reference' else 80,thread_cpu_ns=70,checksum=(i+(1 if execute else 9))*n,steps_per_iteration=cases[i]['steps'] if execute else 0,switch_commits_per_iteration=int(execute),rejected_api_calls=0,complete_post_batch_match=True))
    timed=8*n;untimed=2064;control=8*n+2056
    return dict(schema=1,status='PASS_CALLBACK_SINGLE_MEASURE',mode='measure',strategy=strategy,base=base,iterations=n,group=group,state_size=3504,context_size=5792,image_size=20480,stack_size=65536,reset_bytes_per_iteration=95312,app_executions=0,gpu_executions=0,reset_included=True,checksum_included=True,key_invariants_per_iteration=True,full_comparison_per_batch=True,reset_control_not_subtracted=True,lto=False,transaction_trace_hooks=False,outer_callback_abi_invoked=False,runtime_strategy_selector=False,wall_clock='CLOCK_MONOTONIC_RAW',cpu_clock='CLOCK_THREAD_CPUTIME_ID',clock_order='wall_start,cpu_start,batch,cpu_end,wall_end',legacy_block_fastpath='NOT_INTEGRATED',context_normalization=r.NORMALIZATION.copy(),cases=cases,budget_checks=[],budget_stream=dict(records=0,record_size=r.BUDGET_RECORD_SIZE,uncompressed_bytes=0,path=None),lookup_checks=dict(contexts=0,queries=0,hits=0,misses=0),actual_callback_executions=timed+untimed,timed_callback_executions=timed,untimed_callback_executions=untimed,reset_control_iterations=control,all_reset_calls=timed+untimed+control,timer_calls=64,clock_resolution_queries=2,warmup_iterations_per_scenario_path=256,wall_resolution_ns=42,thread_cpu_resolution_ns=42,records=rows),goldens


class SingleRunnerTests(unittest.TestCase):
    def test_exact_fixed_overlay(self):
        ref=r.overlay('reference');cand=r.overlay('candidate')
        self.assertEqual(ref[r.RUNTIME],(r.ROOT/r.RUNTIME).read_bytes())
        self.assertNotIn(b'aot_pair_lookup_mode',cand[r.RUNTIME]);self.assertNotIn(b'bsearch(',cand[r.RUNTIME])
        for n in ref:
            if n!=r.RUNTIME:self.assertEqual(ref[n],cand[n])
        with self.assertRaises(ValueError):r.overlay('unknown')

    def test_binary_inspection_rejects_wrong_strategy_and_selector(self):
        dis=b'_aot_begin:\n_aot_execute:\n'
        r.artifact_inspection(b'_bsearch\n',b'symbols',dis,'reference')
        r.artifact_inspection(b'_calloc\n',b'symbols',dis,'candidate')
        for args in ((b'_bsearch',b'',dis,'candidate'),(b'',b'',dis,'reference'),(b'',b'_aot_pair_lookup_mode',dis,'candidate'),(b'',b'',b'no body','candidate')):
            with self.assertRaises(ValueError):r.artifact_inspection(*args)

    def test_process_pair_order(self):
        rows=list(r.process_order(2));self.assertEqual(len(rows),16)
        for base in r.BASES:
            for group,want in ((0,['reference','candidate','candidate','reference']),(1,['candidate','reference','reference','candidate'])):
                self.assertEqual([s for b,g,_,s in rows if b==base and g==group],want)

    def test_valid_measure_payload_and_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);v,g=fixture(root);r.validate_response(v,root,g,r.BASES[0],'reference','measure',2,0,[])

    def test_changed_final_and_context_rejected(self):
        for target in ('final-case-0.bin','final-case-0.context.bin'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);v,g=fixture(root);p=root/target;data=bytearray(p.read_bytes());data[0]^=1;p.write_bytes(data)
                with self.assertRaises(ValueError):r.validate_response(v,root,g,r.BASES[0],'reference','measure',2,0,[])

    def test_invalid_order_counts_selector_and_clock_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);good,g=fixture(root)
            for name,value in (('group',1),('all_reset_calls',1),('runtime_strategy_selector',True),('wall_clock','CLOCK_MONOTONIC')):
                bad=copy.deepcopy(good);bad[name]=value
                with self.assertRaises(ValueError):r.validate_response(bad,root,g,r.BASES[0],'reference','measure',2,0,[])
            for name,value in (('order_slot',9),('checksum',0),('wall_ns',0),('iterations',True)):
                bad=copy.deepcopy(good);bad['records'][0][name]=value
                with self.assertRaises(ValueError):r.validate_response(bad,root,g,r.BASES[0],'reference','measure',2,0,[])

    def test_budget_full_stream_header_extent_and_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);rows=[dict(scenario=0,budget=b,status=4,stream_offset=b*r.BUDGET_RECORD_SIZE) for b in range(2)]
            value=dict(budget_checks=rows,budget_stream=dict(path='budget.bin.gz',records=2,record_size=r.BUDGET_RECORD_SIZE,uncompressed_bytes=2*r.BUDGET_RECORD_SIZE))
            raw=b''.join(struct.pack('<4I',0,b,4,0)+bytes(r.BUDGET_RECORD_SIZE-16) for b in range(2))
            for data,valid in ((raw,True),(raw+b'x',False),(raw[:-1],False),(b'x'+raw[1:],False)):
                (root/'budget.bin.gz').write_bytes(gzip.compress(data))
                if valid:self.assertEqual(len(list(r.budget_records(root,value))),2)
                else:
                    with self.assertRaises(ValueError):list(r.budget_records(root,value))

    def test_cross_process_budget_byte_difference_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);runs=[]
            rows=[dict(scenario=0,budget=0,status=4,stream_offset=0)]
            raw=struct.pack('<4I',0,0,4,0)+bytes(r.BUDGET_RECORD_SIZE-16)
            for base in r.BASES:
                for level in r.LEVELS:
                    for strategy in r.STRATEGIES:
                        out=root/('%d-%s-%s'%(base,level,strategy));out.mkdir()
                        cases=[]
                        for i in range(8):
                            name='case-%d.context.bin'%i;(out/name).write_bytes(bytes(r.CONTEXT_SIZE));cases.append(dict(context_response=name))
                        value=dict(cases=cases,budget_checks=rows,budget_stream=dict(path='budget.bin.gz',records=1,record_size=r.BUDGET_RECORD_SIZE,uncompressed_bytes=r.BUDGET_RECORD_SIZE))
                        (out/'budget.bin.gz').write_bytes(gzip.compress(raw));(out/'parsed.json').write_text(json.dumps(value))
                        runs.append(dict(base=base,output=str(out),parsed=str(out/'parsed.json')))
            self.assertEqual(r.compare_checks(runs),6)
            bad=bytearray(raw);bad[-1]=1
            (Path(runs[-1]['output'])/'budget.bin.gz').write_bytes(gzip.compress(bad))
            with self.assertRaisesRegex(ValueError,'full budget'):r.compare_checks(runs)

    def test_gzip_payload_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'payload.gz';path.write_bytes(gzip.compress(b'abcd'))
            self.assertEqual(r.payload(path,4),b'abcd')
            with self.assertRaises(ValueError):r.payload(path,3)

    def test_process_summary_keeps_slow_and_clock_inverse(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);runs=[]
            for base,group,slot,strategy in r.process_order(1):
                d=root/('%d-%d-%s'%(base,slot,strategy));d.mkdir();v,_=fixture(d,base,strategy,group)
                if base==r.BASES[0] and slot==0:v['records'][0]['thread_cpu_ns']=200
                p=d/'parsed.json';p.write_text(json.dumps(v));runs.append(dict(base=base,group_index=group,process_slot=slot,strategy=strategy,parsed=str(p)))
            summary=r.summarize(runs,1);self.assertEqual(len(summary['by_base_scenario']),16)
            self.assertEqual(summary['by_base_scenario'][0]['candidate_over_reference_wall']['median'],.8)
            self.assertEqual(len(summary['cpu_exceeds_wall']),1)

    def test_identity_failure_before_measurement_or_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);out=root/'out'
            with patch.object(r.baseline,'native_host'),patch.object(r,'verify_prepared',side_effect=ValueError('changed')),patch.object(r.baseline.Commands,'run') as native:
                with self.assertRaises(ValueError):r.measure(root,out)
                native.assert_not_called();self.assertFalse(out.exists())


if __name__=='__main__':unittest.main()
