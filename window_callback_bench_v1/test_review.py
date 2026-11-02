"""Pure reader counterexamples. These tests never compile or execute native code."""
import copy
from pathlib import Path
import struct
import tempfile
import unittest

from . import review as r

IMAGE_SIZE, STATE_RVA, RESULT_RVA = 20480, 512, 640


def fixture(mode='measure', base=r.BASES[0], iterations=3, rounds=3):
    original = bytearray(IMAGE_SIZE)
    struct.pack_into('<5I',original,STATE_RVA,0x31574f43,1,3,0,0)
    goldens,payloads,cases = [],{},[]
    for i in range(8):
        state = bytearray(r.STATE_SIZE)
        regs = [0xabc0000000000000+0x10101010101*n for n in range(17)]
        regs[0],regs[4],regs[16] = 0,r.INITIAL_RSP+8,r.EXIT_PC
        for value,offset in zip(regs,r.REG_OFFSETS): struct.pack_into('<Q',state,offset,value)
        state[2067] = 1
        image = bytearray(original)
        moved = int(i<7)
        struct.pack_into('<II',image,STATE_RVA+8,min(i+1,7),moved)
        struct.pack_into('<I',image,RESULT_RVA+12,1)
        struct.pack_into('<I',image,RESULT_RVA+56,moved)
        stack = bytes(r.STACK_SIZE)
        payload = bytes(state+image+stack)
        trace = [dict(pc=base+100+n,next_pc=base+101+n,before_depth=0,after_depth=0,status=0,kind=kind)
                 for n,kind in enumerate((0,1,5,2,2))]
        old = dict(initial_position=i,position=min(i+1,7),moves=moved,draws=0,keydowns=1,dirty=moved,
                   status=0,returned=1,call_depth=0,steps=5,switch_commits=1,rejected_api_calls=0,
                   setup_status=0,trace_overflow=0,call_commits=1,ret_commits=2,max_call_depth=1,
                   fault=dict(status=0,access=0,pc=0,address=0,width=0),trace=trace,registers=regs,flags=4)
        goldens.append(dict(case=old,payload=payload))
        case = {key:old[key] for key in r.CASE_FIELDS}
        case.update(response='case-%d.bin'%i,checksum=r.response_word(payload,IMAGE_SIZE,STATE_RVA,RESULT_RVA,5,1),
                    reset_checksum=r.reset_word(i),timed_final_response='final-case-%d.bin'%i if mode=='measure' else None)
        cases.append(case);payloads[case['response']] = payload
        if mode=='measure': payloads[case['timed_final_response']] = payload
    measured = mode=='measure'
    timed = rounds*8*iterations if measured else 0
    untimed = 8+2048+rounds*8 if measured else 8
    value = dict(status='PASS_CALLBACK_CPU_MEASURE' if measured else 'PASS_CALLBACK_CPU_CHECK',mode=mode,base=base,
        state_size=r.STATE_SIZE,context_size=12384,image_size=IMAGE_SIZE,stack_size=r.STACK_SIZE,
        iterations=iterations,rounds=rounds,warmup_iterations_per_scenario_path=256 if measured else 0,
        actual_callback_executions=timed+untimed,timed_callback_executions=timed,untimed_callback_executions=untimed,
        reset_control_iterations=timed+untimed-8 if measured else 0,all_reset_calls=2*timed+2*(untimed-8)+8,
        timer_calls=rounds*16*4 if measured else 0,clock_resolution_queries=2 if measured else 0,
        wall_clock='CLOCK_MONOTONIC',cpu_clock='CLOCK_THREAD_CPUTIME_ID',clock_order='wall_start,cpu_start,batch,cpu_end,wall_end',
        wall_resolution_ns=1 if measured else 0,thread_cpu_resolution_ns=1 if measured else 0,
        reset_bytes_per_iteration=r.STATE_SIZE+12384+IMAGE_SIZE+r.STACK_SIZE,reset_included=True,checksum_included=True,
        key_invariants_per_iteration=True,full_comparison_per_batch=True,reset_control_not_subtracted=True,
        lto=False,transaction_trace_hooks=False,legacy_block_fastpath='NOT_INTEGRATED',outer_callback_abi_invoked=False,
        final_snapshot_capture='live final execute batch copied outside clocks into preallocated buffers; file IO after all timed batches',
        app_executions=0,gpu_executions=0,cases=cases,records=[])
    for round_index in range(rounds if measured else 0):
        for offset in range(8):
            scenario = (round_index+offset)%8
            for position in range(2):
                reset = (round_index+scenario+position)&1
                wall = (round_index+1)*1000+scenario*10+reset
                cpu = wall-100
                checksum = cases[scenario]['reset_checksum' if reset else 'checksum']
                value['records'].append(dict(round=round_index,scenario=scenario,path='reset' if reset else 'execute',
                    iterations=iterations,wall_ns=wall,thread_cpu_ns=cpu,checksum=(checksum*iterations)&r.MASK,
                    steps_per_iteration=0 if reset else 5,switch_commits_per_iteration=0 if reset else 1,
                    rejected_api_calls=0,complete_post_batch_match=True))
    return value,payloads,goldens,bytes(original)


class ReviewTests(unittest.TestCase):
    def validate(self, values=None):
        value,payloads,goldens,_ = values or fixture()
        return r.response(value,payloads,goldens,value['base'],value['mode'],value['iterations'],value['rounds'],
                          IMAGE_SIZE,STATE_RVA,RESULT_RVA)

    def changed(self, mutate):
        values = fixture();mutate(*values[:3])
        with self.assertRaises(ValueError): self.validate(values)

    def test_recomputes_every_sample_and_all_statistics(self):
        values = fixture();rows = values[0]['records']
        # A deliberate slow sample must survive both output and max/median.
        chosen = [row for row in rows if row['scenario']==0 and row['path']=='execute']
        chosen[-1]['wall_ns'] = 3_000_000
        samples = self.validate(values)
        self.assertEqual(len(samples),48)
        summary = r.summarize(samples)
        item = next(s for s in summary if s['scenario']==0 and s['path']=='execute')
        self.assertEqual(item['samples'],3)
        self.assertEqual(item['wall_ns_per_iteration'],dict(min=1000/3,median=2000/3,max=1_000_000))
        self.assertEqual([s['wall_ns'] for s in samples if s['scenario']==0 and s['path']=='execute'],[1000,2000,3_000_000])

    def test_summary_forgery_and_boolean_count_rejected(self):
        summary = r.summarize(self.validate())
        r.exact_summary(copy.deepcopy(summary),summary)
        changed = copy.deepcopy(summary)
        changed[0]['wall_ns_per_iteration']['median'] += 1
        with self.assertRaises(ValueError):r.exact_summary(changed,summary)
        changed = copy.deepcopy(summary)
        changed[0]['samples'] = True
        with self.assertRaises(ValueError):r.exact_summary(changed,summary)

    def test_untimed_check_contains_no_timer_records(self):
        self.assertEqual(self.validate(fixture(mode='check',iterations=1,rounds=1)),[])

    def test_clock_small_inversion_is_reported_and_retained(self):
        values = fixture();values[0]['records'][0]['thread_cpu_ns'] = values[0]['records'][0]['wall_ns']+1
        samples = self.validate(values)
        self.assertEqual(len(samples),48)
        self.assertEqual(samples[0]['cpu_exceeds_wall_ns'],1)

    def test_nonpositive_clocks_rejected(self):
        for clock in ('wall_ns','thread_cpu_ns'):
            with self.subTest(clock=clock):
                self.changed(lambda v,p,g:v['records'][0].__setitem__(clock,0))

    def test_duplicate_round_case_path_rejected(self):
        self.changed(lambda v,p,g:v['records'].__setitem__(1,copy.deepcopy(v['records'][0])))

    def test_reordered_samples_rejected(self):
        self.changed(lambda v,p,g:v['records'].reverse())

    def test_missing_slow_sample_rejected(self):
        self.changed(lambda v,p,g:v['records'].pop())

    def test_forged_batch_checksum_rejected(self):
        self.changed(lambda v,p,g:v['records'][0].__setitem__('checksum',0))

    def test_case_checksum_is_not_a_trusted_oracle(self):
        def change(value,payloads,goldens):
            value['cases'][0]['checksum'] ^= 1
            for row in value['records']:
                if row['scenario']==0 and row['path']=='execute':
                    row['checksum'] = (value['cases'][0]['checksum']*row['iterations'])&r.MASK
        self.changed(change)

    def test_reset_checksum_recomputed_from_initial_state(self):
        def change(value,payloads,goldens):
            value['cases'][0]['reset_checksum'] ^= 1
            for row in value['records']:
                if row['scenario']==0 and row['path']=='reset':
                    row['checksum'] = (value['cases'][0]['reset_checksum']*row['iterations'])&r.MASK
        self.changed(change)

    def test_api_steps_switch_and_full_compare_gates(self):
        for key,bad in (('rejected_api_calls',1),('steps_per_iteration',99),('switch_commits_per_iteration',0),
                        ('complete_post_batch_match',False)):
            with self.subTest(key=key):
                self.changed(lambda v,p,g:v['records'][0].__setitem__(key,bad))

    def test_integer_booleans_rejected(self):
        for key in ('wall_ns','round','scenario','iterations','checksum','steps_per_iteration','switch_commits_per_iteration'):
            with self.subTest(key=key):
                self.changed(lambda v,p,g:v['records'][0].__setitem__(key,True))

    def test_precheck_full_state_tail_corruption_rejected(self):
        def change(value,payloads,goldens):
            name = 'case-0.bin';payloads[name] = payloads[name][:-1]+b'\x01'
        self.changed(change)

    def test_timed_final_tail_corruption_rejected_even_when_checksum_same(self):
        def change(value,payloads,goldens):
            name = 'final-case-7.bin';payloads[name] = payloads[name][:-1]+b'\x01'
        self.changed(change)

    def test_missing_timed_final_rejected(self):
        self.changed(lambda v,p,g:p.pop('final-case-0.bin'))

    def test_traversal_response_path_rejected(self):
        self.changed(lambda v,p,g:v['cases'][0].__setitem__('response','../case-0.bin'))

    def test_execution_accounting_rejected(self):
        for key in ('actual_callback_executions','timed_callback_executions','untimed_callback_executions',
                    'reset_control_iterations','all_reset_calls','timer_calls','clock_resolution_queries'):
            with self.subTest(key=key):
                self.changed(lambda v,p,g:v.__setitem__(key,v[key]+1))

    def test_claimed_outer_abi_or_legacy_hit_rejected(self):
        self.changed(lambda v,p,g:v.__setitem__('outer_callback_abi_invoked',True))
        self.changed(lambda v,p,g:v.__setitem__('legacy_block_fastpath',0))

    def test_reset_subtraction_and_trace_hooks_rejected(self):
        self.changed(lambda v,p,g:v.__setitem__('reset_control_not_subtracted',False))
        self.changed(lambda v,p,g:v.__setitem__('transaction_trace_hooks',True))

    def test_golden_raw_register_metadata_must_match_state_bytes(self):
        _,_,goldens,original = fixture()
        case,payload = goldens[0]['case'],goldens[0]['payload']
        r.golden_case(case,payload,original,STATE_RVA,RESULT_RVA,0)
        case['registers'][3] ^= 1
        with self.assertRaises(ValueError):r.golden_case(case,payload,original,STATE_RVA,RESULT_RVA,0)

    def test_golden_unobserved_image_byte_rejected(self):
        _,_,goldens,original = fixture()
        case = goldens[0]['case'];payload = bytearray(goldens[0]['payload'])
        payload[r.STATE_SIZE+1000] ^= 1
        with self.assertRaises(ValueError):r.golden_case(case,bytes(payload),original,STATE_RVA,RESULT_RVA,0)

    def test_duplicate_json_and_nonfinite_numbers_rejected(self):
        for raw in ('{"wall_ns":1,"wall_ns":2}','{"clock":NaN}','{"clock":Infinity}'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):r.parse(raw)

    def test_changed_binary_after_read_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'binary';path.write_bytes(b'original')
            audit = r.Audit();audit.file(path)
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):audit.finish()

    def test_old_receipt_hash_cannot_approve_changed_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'benchmark.c';path.write_bytes(b'old')
            expected = r.digest(path.read_bytes());path.write_bytes(b'new')
            with self.assertRaises(ValueError):r.Audit().mapping({str(path):expected})

    def test_omitted_binary_identity_is_rejected(self):
        with self.assertRaises(ValueError):r.covered({'/tmp/unrelated':'hash'},['/tmp/benchmark-O3'],'binary')


if __name__=='__main__':
    unittest.main()
