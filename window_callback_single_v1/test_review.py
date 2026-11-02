"""Independent evidence rejection tests; no native process or timer execution."""
import copy
import gzip
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from window_callback_bench_v1.test_review import fixture as old_fixture, IMAGE_SIZE, STATE_RVA, RESULT_RVA
from . import review as r


class MemoryAudit:
    def __init__(self,files):self.files=files
    def raw(self,path):return self.files[Path(path).name]
    def file(self,path,expected=None):return r.old.digest(self.raw(path))


def context(row,base,budget=4096):
    data=bytearray(r.CONTEXT_SIZE)
    for off,n in [(0,base),(8,budget),(32,1),(40,1),(48,2),(56,base),(64,IMAGE_SIZE),
                  (72,1),(80,1),(96,0x70000000),(104,65536),(112,2),(120,2)]:struct.pack_into('<Q',data,off,n)
    fault=row.get('fault',dict(status=0,access=0,pc=0,address=0,width=0))
    struct.pack_into('<IIQQQQII',data,696,*(fault[k] for k in ('status','access','pc','address','width')),
                     row['steps'],row['call_depth'],row['returned'])
    return bytes(data)


def fixture():
    value,_,goldens,_=old_fixture();base=r.BASES[0];group=1;iterations=3;files={};cases=[]
    for i,g in enumerate(goldens):
        g['case']['steps']=45 if i<7 else 41
        case={k:g['case'][k] for k in r.old.CASE_FIELDS};name='case-%d.bin'%i;ctxname='case-%d.context.bin'%i
        case.update(response=name,context_response=ctxname,timed_final_response='final-'+name,timed_final_context='final-'+ctxname,
                    checksum=r.old.response_word(g['payload'],IMAGE_SIZE,STATE_RVA,RESULT_RVA,case['steps'],1),reset_checksum=r.old.reset_word(i))
        cases.append(case);files[name]=files['final-'+name]=g['payload'];files[ctxname]=files['final-'+ctxname]=context(case,base)
    value.update(schema=1,status='PASS_CALLBACK_SINGLE_MEASURE',mode='measure',strategy='candidate',base=base,
                 context_size=r.CONTEXT_SIZE,reset_bytes_per_iteration=95312,iterations=iterations,group=group,
                 actual_callback_executions=8*iterations+2064,timed_callback_executions=8*iterations,untimed_callback_executions=2064,
                 reset_control_iterations=2056+8*iterations,all_reset_calls=16*iterations+4120,timer_calls=64,
                 clock_resolution_queries=2,warmup_iterations_per_scenario_path=256,wall_resolution_ns=42,thread_cpu_resolution_ns=42,
                 runtime_strategy_selector=False,wall_clock='CLOCK_MONOTONIC_RAW',context_normalization=dict(r.LAYOUT,encoding=r.ENCODING),
                 lookup_checks=dict(contexts=0,queries=0,hits=0,misses=0),budget_checks=[],
                 budget_stream=dict(records=0,record_size=r.RECORD_SIZE,uncompressed_bytes=0,path=None),cases=cases,records=[])
    for offset in range(8):
        scenario=(group+offset)%8
        for slot in range(2):
            execute=(group+scenario+slot)%2==0;case=cases[scenario]
            value['records'].append(dict(group=group,scenario=scenario,order_slot=slot,path='execute' if execute else 'reset',iterations=iterations,
                wall_ns=1000 if execute else 500,thread_cpu_ns=900 if execute else 400,checksum=case['checksum' if execute else 'reset_checksum']*iterations&r.MASK,
                steps_per_iteration=case['steps'] if execute else 0,switch_commits_per_iteration=int(execute),rejected_api_calls=0,complete_post_batch_match=True))
    return value,files,goldens,[dict(rva=0x1000,length=5)]


class ReviewTests(unittest.TestCase):
    def validate(self,values=None):
        v,f,g,t=values or fixture()
        return r.response(MemoryAudit(f),v,Path('/synthetic'),g,v['base'],v['strategy'],'measure',v['iterations'],v['group'],(IMAGE_SIZE,STATE_RVA,RESULT_RVA),t)
    def reject(self,change):
        values=fixture();change(*values)
        with self.assertRaises(ValueError):self.validate(values)
    def test_valid_measured_full_responses(self):
        rows,contexts=self.validate();self.assertEqual(len(rows),16);self.assertEqual(len(contexts),8)
    def test_unsafe_pointer_marker(self):
        def mutation(v,f,g,t):
            c=bytearray(f['case-0.context.bin']);struct.pack_into('<Q',c,32,0x12345678);f['case-0.context.bin']=bytes(c)
        self.reject(mutation)
    def test_context_result_bound_to_summary(self):
        def mutation(v,f,g,t):
            c=bytearray(f['case-0.context.bin']);struct.pack_into('<Q',c,728,44);f['case-0.context.bin']=bytes(c)
        self.reject(mutation)
    def test_pending_pointer_outside_guest(self):
        def mutation(v,f,g,t):
            c=bytearray(f['case-0.context.bin']);struct.pack_into('<Q',c,768,123);f['case-0.context.bin']=bytes(c)
        self.reject(mutation)
    def test_layout_rejected(self):self.reject(lambda v,f,g,t:v['context_normalization'].__setitem__('current_offset',8))
    def test_timed_final_context_changed(self):self.reject(lambda v,f,g,t:f.__setitem__('final-case-0.context.bin',bytes(r.CONTEXT_SIZE)))
    def test_normal_complete_bytes_changed(self):self.reject(lambda v,f,g,t:f.__setitem__('case-0.bin',bytes(r.PAYLOAD_SIZE)))
    def test_final_complete_bytes_changed(self):self.reject(lambda v,f,g,t:f.__setitem__('final-case-0.bin',bytes(r.PAYLOAD_SIZE)))
    def test_selector_claim_rejected(self):self.reject(lambda v,f,g,t:v.__setitem__('runtime_strategy_selector',True))
    def test_execution_ledger(self):self.reject(lambda v,f,g,t:v.__setitem__('all_reset_calls',0))
    def test_checksum_rejected(self):self.reject(lambda v,f,g,t:v['records'][0].__setitem__('checksum',0))
    def test_row_order_rejected(self):self.reject(lambda v,f,g,t:v['records'].reverse())
    def test_missing_row_rejected(self):self.reject(lambda v,f,g,t:v['records'].pop())
    def test_boolean_time_rejected(self):self.reject(lambda v,f,g,t:v['records'][0].__setitem__('wall_ns',True))
    def test_nonpositive_time_rejected(self):self.reject(lambda v,f,g,t:v['records'][0].__setitem__('thread_cpu_ns',0))
    def test_slow_inverse_records_retained(self):
        v=fixture();v[0]['records'][0].update(wall_ns=10_000_000,thread_cpu_ns=10_000_001)
        rows,_=self.validate(v);self.assertEqual(len(rows),16);self.assertEqual(rows[0]['cpu_exceeds_wall_ns'],1)
    def test_process_orders(self):
        rows=list(r.process_order(2));self.assertEqual(len(rows),16)
        self.assertEqual([x[3] for x in rows[:8]],['reference','candidate','candidate','reference','candidate','reference','reference','candidate'])
    def test_process_pairs_recomputed(self):
        rows=[]
        for base,group,slot,strategy in r.process_order(2):
            original,_=self.validate()
            for row in original:
                row.update(base=base,group_index=group,process_slot=slot,strategy=strategy,wall_ns=800 if strategy=='candidate' else 1000,thread_cpu_ns=700)
                rows.append(row)
        s=r.summary(rows);self.assertEqual(len(s['by_base_scenario']),16)
        self.assertEqual(s['by_base_scenario'][0]['candidate_over_reference_wall'],dict(median=.8,min=.8,max=.8))
        with self.assertRaises(ValueError):r.summary(rows[:-1])
    def stream_test(self,change=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);data=struct.pack('<4I',0,0,4,0)+bytes(r.RECORD_SIZE-16)
            value=dict(budget_checks=[dict(scenario=0,budget=0,status=4,stream_offset=0)],budget_stream=dict(path='budget.bin.gz',records=1,record_size=r.RECORD_SIZE,uncompressed_bytes=r.RECORD_SIZE))
            if change:data=change(data,value)
            (directory/'budget.bin.gz').write_bytes(gzip.compress(data));return list(r.budgets(r.old.Audit(),directory,value))
    def test_full_budget_stream(self):self.assertEqual(len(self.stream_test()),1)
    def test_trailing_budget_rejected(self):
        with self.assertRaises(ValueError):self.stream_test(lambda data,v:data+b'x')
    def test_truncated_budget_rejected(self):
        with self.assertRaises(ValueError):self.stream_test(lambda data,v:data[:-1])
    def test_budget_header_rejected(self):
        with self.assertRaises(ValueError):self.stream_test(lambda data,v:bytes(16)+data[16:])
    def test_bsearch_binary_identity(self):
        for strategy,undefined in [('reference',b'_bsearch\n'),('candidate',b'_memcpy\n')]:
            audit=MemoryAudit({'nm-u-'+strategy+'-O3.stdout':undefined,'nm-'+strategy+'-O3.stdout':b'_aot_begin','disasm-'+strategy+'-O3.stdout':b'_aot_begin:\n_aot_execute:'})
            self.assertEqual(r.native_inspection(audit,Path('/tmp'),strategy+'-O3')['bsearch_imported'],strategy=='reference')
        with self.assertRaises(ValueError):
            r.native_inspection(MemoryAudit({'nm-u-candidate-O3.stdout':b'_bsearch','nm-candidate-O3.stdout':b'','disasm-candidate-O3.stdout':b'_aot_begin:\n_aot_execute:'}),Path('/tmp'),'candidate-O3')
    def test_selector_in_disassembly(self):
        with self.assertRaises(ValueError):
            r.native_inspection(MemoryAudit({'nm-u-candidate-O3.stdout':b'','nm-candidate-O3.stdout':b'','disasm-candidate-O3.stdout':b'_aot_begin:\n_aot_execute:\naot_pair_lookup_mode'}),Path('/tmp'),'candidate-O3')


if __name__=='__main__':unittest.main()
