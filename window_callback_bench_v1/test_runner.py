"""Fail-closed orchestration tests. No native compilation or timing occurs."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from . import runner as r


class ResponseFixture:
    def __init__(self, directory, measure=True):
        self.directory=directory;self.golden=[]
        self.iterations=3;self.rounds=2
        self.mode='measure' if measure else 'check'
        count=8+8*256+self.rounds*8*(self.iterations+1) if measure else 8
        timed=self.rounds*8*self.iterations if measure else 0
        self.value=dict(status='PASS_CALLBACK_CPU_'+('MEASURE' if measure else 'CHECK'),mode=self.mode,
            base=r.BASES[0],state_size=r.STATE_SIZE,context_size=r.CONTEXT_SIZE,image_size=20480,stack_size=r.STACK_SIZE,
            iterations=self.iterations,rounds=self.rounds,warmup_iterations_per_scenario_path=256 if measure else 0,
            actual_callback_executions=count,timed_callback_executions=timed,untimed_callback_executions=count-timed,
            reset_control_iterations=count-8,all_reset_calls=2*count-8,timer_calls=self.rounds*16*4 if measure else 0,
            clock_resolution_queries=2 if measure else 0,wall_resolution_ns=1 if measure else 0,
            thread_cpu_resolution_ns=1 if measure else 0,wall_clock='CLOCK_MONOTONIC',cpu_clock='CLOCK_THREAD_CPUTIME_ID',
            clock_order='wall_start,cpu_start,batch,cpu_end,wall_end',reset_bytes_per_iteration=95312,
            reset_included=True,checksum_included=True,key_invariants_per_iteration=True,full_comparison_per_batch=True,
            reset_control_not_subtracted=True,lto=False,transaction_trace_hooks=False,legacy_block_fastpath='NOT_INTEGRATED',
            outer_callback_abi_invoked=False,app_executions=0,gpu_executions=0,cases=[],records=[])
        for index in range(8):
            moved=int(index<7)
            case=dict(initial_position=index,position=min(index+1,7),moves=moved,draws=0,keydowns=1,dirty=moved,
                      status=0,returned=1,call_depth=0,steps=45 if moved else 41,switch_commits=1,rejected_api_calls=0,
                      response='case-%d.bin'%index,checksum=r.MASK-index,reset_checksum=20+index,
                      timed_final_response='final-case-%d.bin'%index if measure else None)
            payload=bytes([index])*(r.STATE_SIZE+20480+r.STACK_SIZE)
            golden=directory/('golden-%d.bin'%index);golden.write_bytes(payload)
            (directory/case['response']).write_bytes(payload)
            if measure: (directory/case['timed_final_response']).write_bytes(payload)
            self.golden.append(dict(path=str(golden),case=copy.deepcopy(case)))
            self.value['cases'].append(case)
        if measure:
            for round_index in range(self.rounds):
                for offset in range(8):
                    scenario=(round_index+offset)%8
                    for position in range(2):
                        execute=(round_index+scenario+position)%2==0
                        case=self.value['cases'][scenario]
                        self.value['records'].append(dict(round=round_index,scenario=scenario,path='execute' if execute else 'reset',
                            iterations=self.iterations,wall_ns=100+round_index,thread_cpu_ns=101+round_index,
                            checksum=(case['checksum' if execute else 'reset_checksum']*self.iterations)&r.MASK,
                            steps_per_iteration=case['steps'] if execute else 0,switch_commits_per_iteration=int(execute),
                            rejected_api_calls=0,complete_post_batch_match=True))

    def validate(self):
        r.validate_response(self.value,self.directory,self.golden,r.BASES[0],self.mode,self.iterations,self.rounds,20480)


class InputTests(unittest.TestCase):
    def test_strict_json(self):
        for value in ('{"a":1,"a":2}','{"a":NaN}','{"a":Infinity}'):
            with self.subTest(value=value),self.assertRaises(ValueError):r.parse(value)

    def test_bounded_not_bool_or_unbounded(self):
        for args in ((True,1),(1,False),(0,1),(65537,1),(1,0),(1,21),(1.0,1)):
            with self.subTest(args=args),self.assertRaises(ValueError):r.bounded(*args)
        r.bounded(65536,20)

    def test_no_output_reuse_or_input_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();existing=root/'used';existing.mkdir()
            with self.assertRaises(ValueError):r.fresh(existing,[])
            with self.assertRaises(ValueError):r.fresh(existing/'child',[existing])
            self.assertFalse((existing/'child').exists())

    def test_timeout_logs_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();command=r.Commands(root)
            with patch.object(r.subprocess,'run',side_effect=subprocess.TimeoutExpired(['fake'],1,output=b'partial',stderr=b'timeout')):
                with self.assertRaises(ValueError):command.run(['fake'],'timeout',1)
            self.assertEqual((root/'timeout.stdout').read_bytes(),b'partial')
            self.assertEqual((root/'timeout.stderr').read_bytes(),b'timeout')
            self.assertIsNone(r.read(root/'timeout.command.json')['returncode'])

    def test_failed_prepare_gate_never_spawns_or_creates_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            prepared=Path(tmp).resolve();out=prepared/'not-created'
            with patch.object(r,'native_host'),patch.object(r,'verify_prepared',side_effect=ValueError('changed source')),patch.object(r.subprocess,'run') as spawn:
                with self.assertRaises(ValueError):r.measure(prepared,out)
                spawn.assert_not_called()
            self.assertFalse(out.exists())

    def test_prepare_missing_artifact_coverage_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            prepared=Path(tmp).resolve();foreign=prepared/'unrecorded';foreign.write_bytes(b'bytes')
            value=dict(schema=1,status=r.PREPARED,out=str(prepared),correctness_callbacks=32,
                       timed_callback_executions=0,app_executions=0,gpu_executions=0,sources_before={},sources_after={},
                       inputs_before={},inputs_after={},compiler_dependencies={},artifacts={},product='product',probe='probe',binding={'inputs':{}})
            r.write(prepared/'result.json',value)
            with patch.object(r,'sources',return_value={}),patch.object(r,'bind',return_value=value['binding']):
                with self.assertRaisesRegex(ValueError,'artifact coverage'):r.verify_prepared(prepared)


class ResponseTests(unittest.TestCase):
    def test_complete_check_and_measure_shapes_allow_cpu_above_wall(self):
        for mode in (False,True):
            with self.subTest(measure=mode),tempfile.TemporaryDirectory() as tmp:
                ResponseFixture(Path(tmp),mode).validate()

    def test_full_state_or_timed_final_mutation_rejected(self):
        for name in ('case-3.bin','final-case-3.bin'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                fixture=ResponseFixture(Path(tmp));path=Path(tmp)/name
                data=bytearray(path.read_bytes());data[3000]^=1;path.write_bytes(data)
                with self.assertRaisesRegex(ValueError,'State/image/stack'):fixture.validate()

    def test_raw_record_identity_clock_checksum_and_scope_rejected(self):
        mutations=(('order',lambda v:v['records'].reverse()),
                   ('boolean sample',lambda v:v['records'][0].update(wall_ns=True)),
                   ('zero clock',lambda v:v['records'][0].update(thread_cpu_ns=0)),
                   ('checksum',lambda v:v['records'][0].update(checksum=0)),
                   ('missing final',lambda v:v['cases'][0].update(timed_final_response='case-0.bin')),
                   ('boolean top',lambda v:v.update(iterations=True)),
                   ('count',lambda v:v.update(actual_callback_executions=v['actual_callback_executions']-1)),
                   ('checksum type',lambda v:v['cases'][0].update(reset_checksum=True)),
                   ('reset cost omitted',lambda v:v.update(reset_included=False)),
                   ('ABI claim',lambda v:v.update(outer_callback_abi_invoked=True)),
                   ('incomplete final',lambda v:v['records'][0].update(complete_post_batch_match=False)))
        for name,mutate in mutations:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                fixture=ResponseFixture(Path(tmp));mutate(fixture.value)
                with self.assertRaises(ValueError):fixture.validate()

    def test_summary_keeps_outlier_without_reset_subtraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp);fixture=ResponseFixture(directory)
            fixture.value['records'][0]['wall_ns']=10_000_000
            r.write(directory/'parsed.json',fixture.value)
            result=r.summarize([dict(base=r.BASES[0],parsed=str(directory/'parsed.json'))])
            self.assertEqual(len(result),16)
            entry=next(row for row in result if row['scenario']==0 and row['path']=='execute')
            self.assertEqual(entry['samples'],2)
            self.assertEqual(entry['wall_ns_per_iteration']['max'],10_000_000/3)
            self.assertGreater(entry['wall_ns_per_iteration']['median'],1_000_000)


if __name__=='__main__':unittest.main()
