"""Synthetic file/byte rejection tests; no native process or producer validator."""
import copy
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import review


def synthetic_group():
    """Exercise new replay relations independently of the frozen per-call oracle.

    Deliberately synthetic snapshots; these are not presented as native evidence.
    The separate inherited per-call validator is replaced only inside these tests.
    """
    context=bytearray(5792);struct.pack_into('<Q',context,0,0x140000000)
    image=bytearray(0x4000);image[0x3190:0x31c0]=bytes(range(48))
    original=dict(state=bytes(3504),context=bytes(context),instructions=bytes(16),
                  d3d=bytes(64),user32=bytes(192),callbacks=bytes(312),regions=[])
    for i in range(6):
        original['regions'].append(dict(base=0x140000000 if i==0 else 0x70000000+i*0x10000,
            bytes=bytes(image) if i==0 else bytes(4096),permissions=bytes([3])*(4 if i==0 else 1)))
    def event(kind,attempt,ledger,counter):
        row={k:0 for k in review.EVENT_KEYS}; row.update(type=kind,attempt=attempt,index=0,
            role='original' if attempt==-1 else 'diagnostic' if attempt<2 else 'continuation',
            signature=214,message=0x100,api_calls=[0]*14,file_api_calls=[0]*9,snapshot='',
            state_address=32,context_address=16,owner_state=32,owner_context=16,thread_id=7,
            callback_calls=counter,callback_returns=counter,user32_callbacks=counter,posted_dispatches=counter)
        row['api_calls'][5]=counter;row.update(ledger);return row
    def host(snapshot,counter):
        snapshot['user32']=struct.pack('<Q',counter)+bytes(184)
        snapshot['callbacks']=struct.pack('<Q',counter)+bytes(304)
    ledger={k:0 for k in review.LEDGER_KEYS};events=[event('original-capture',-1,ledger,0)]
    snaps={(-1,'original-capture'):copy.deepcopy(original)}
    for attempt in range(3):
        if attempt:ledger['reset_count']+=1
        before=copy.deepcopy(original)
        if attempt<2:
            raw=bytearray(before['regions'][0]['bytes']);raw[0x31b0:0x31bc]=review.FIXED_MSG
            before['regions'][0]['bytes']=bytes(raw)
        host(before,attempt)
        after=copy.deepcopy(before)
        context=bytearray(after['context']);struct.pack_into('<Q',context,728,46);struct.pack_into('<Q',context,5784,1)
        after['context']=bytes(context)
        state=bytearray(after['state']);state[100]=5;after['state']=bytes(state)
        region=bytearray(after['regions'][0]['bytes']);region[0x3008]=4;after['regions'][0]['bytes']=bytes(region)
        host(after,attempt+1)
        for kind in ('outer-before','callback-before','callback-after','ret-before','ret-after'):
            events.append(event(kind,attempt,ledger,attempt))
        ledger['diagnostic_calls' if attempt<2 else 'continuation_calls']+=1
        ledger['total_guest_steps']+=46;ledger['total_switch_commits']+=1
        events.append(event('outer-after',attempt,ledger,attempt+1))
        for kind in ('outer-before','callback-before','callback-after','outer-after'):
            snaps[(attempt,kind)]=copy.deepcopy(before if kind.endswith('before') else after)
    for i,row in enumerate(events):row['seq']=i
    return events,snaps


def validate_synthetic(events,snaps):
    with patch.object(review.single,'validate_event_group',return_value=dict(steps=46,callback_steps=45,switch_commits=1)), \
         patch.object(review,'validate_outer_bridges'), patch.object(review,'validate_host_phases'):
        return review.validate_replay_group(events,snaps,0,{k:0 for k in review.LEDGER_KEYS})


def bridge_fixture():
    _,raw=synthetic_group();before=copy.deepcopy(raw[(-1,'original-capture')])
    base=0x140000000;pc=base+0xf00d6000;rsp=0x70000808;ret=base+0x16d2
    before['d3d']=bytes(5520);before['user32']=bytes(408);before['callbacks']=bytes(308)+struct.pack('<I',1)
    state=bytearray(before['state'])
    for reg,value in [('RAX',13),('RSP',rsp),('RIP',pc)]:struct.pack_into('<Q',state,review.REGISTERS[reg],value)
    before['state']=bytes(state)
    ctx=bytearray(before['context'])
    for off,value in [(32,0x10000000),(40,2),(728,20),(744,base+0x16cf),(752,0x10000000),(904,ret),(912,rsp+8),(5784,7)]:struct.pack_into('<Q',ctx,off,value)
    struct.pack_into('<I',ctx,736,1);struct.pack_into('<I',ctx,5472,1)
    before['context']=bytes(ctx)
    before['instructions']=struct.pack('<IHBBQ',0x16cf,3,4,0,0)+struct.pack('<IHBBQ',0xf00d6000,1,2,0,0)
    entry=copy.deepcopy(before);ctx=bytearray(entry['context']);struct.pack_into('<Q',ctx,744,pc);entry['context']=bytes(ctx)
    entry['user32']=review.increment_u64(before['user32'],[80,152,168])
    returned=copy.deepcopy(entry);ctx=bytearray(returned['context'])
    struct.pack_into('<Q',ctx,728,65);struct.pack_into('<Q',ctx,5784,8);returned['context']=bytes(ctx)
    data=bytearray(returned['regions'][0]['bytes']);data[0x3008]=4;returned['regions'][0]['bytes']=bytes(data)
    returned['callbacks']=review.increment_u64(entry['callbacks'],[280,288])
    after=copy.deepcopy(returned);pre=bytearray(returned['state']);struct.pack_into('<Q',pre,review.REGISTERS['RAX'],0)
    ctx=bytearray(returned['context']);ctx[1936:5440]=pre
    struct.pack_into('<Q',ctx,728,66);struct.pack_into('<I',ctx,736,0);struct.pack_into('<Q',ctx,752,0x10000010);struct.pack_into('<I',ctx,5472,0)
    after['context']=bytes(ctx)
    struct.pack_into('<Q',pre,review.REGISTERS['RSP'],rsp+8);struct.pack_into('<Q',pre,review.REGISTERS['RIP'],ret);after['state']=bytes(pre)
    events=[dict(pc=pc),{}, {},dict(type='ret-before',signature=214,pc=pc,steps=65,depth=1,rax=0,rsp=rsp,rip=pc),
            dict(type='ret-after',signature=214,pc=pc,steps=66,depth=0,rax=0,rsp=rsp+8,rip=ret),{}]
    return events,dict(zip(('outer-before','callback-before','callback-after','outer-after'),(before,entry,returned,after)))


def flip(snapshot,field,offset=0):
    raw=bytearray(snapshot[field]);raw[offset]^=1;snapshot[field]=bytes(raw)


class ReplayReaderTests(unittest.TestCase):
    def test_valid_synthetic_replay_relationships(self):
        groups,ledger=validate_synthetic(*synthetic_group())
        self.assertTrue(groups['diagnostic_guest_byte_equivalence'])
        self.assertEqual(ledger,dict(diagnostic_calls=2,continuation_calls=1,total_guest_steps=138,total_switch_commits=3,reset_count=2))

    def test_original_capture_required(self):
        events,snaps=synthetic_group();events[0]['type']='outer-before'
        with self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_original_metadata_cannot_be_forged(self):
        events,snaps=synthetic_group();events[0]['pc']=777
        with self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_no_broad_msg_normalization(self):
        for offset in (0x3190,0x319c,0x31ac,0x31bc):
            events,snaps=synthetic_group();raw=bytearray(snaps[(0,'outer-before')]['regions'][0]['bytes'])
            raw[offset]^=1;snaps[(0,'outer-before')]['regions'][0]['bytes']=bytes(raw)
            with self.subTest(offset=offset),self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_fixed_input_must_have_exact_bytes(self):
        events,snaps=synthetic_group();raw=bytearray(snaps[(0,'outer-before')]['regions'][0]['bytes'])
        raw[0x31b0]^=1;snaps[(0,'outer-before')]['regions'][0]['bytes']=bytes(raw)
        with self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_continuation_restores_original_msg(self):
        events,snaps=synthetic_group();snaps[(2,'outer-before')]['regions'][0]['bytes']=snaps[(0,'outer-before')]['regions'][0]['bytes']
        with self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_complete_state_context_restore(self):
        for field,offset in [('state',1),('context',1936),('context',56+16),('context',896),('instructions',0)]:
            events,snaps=synthetic_group();flip(snaps[(1,'outer-before')],field,offset)
            with self.subTest(field=field,offset=offset),self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_stack_bytes_must_restore(self):
        events,snaps=synthetic_group();raw=bytearray(snaps[(1,'outer-before')]['regions'][1]['bytes']);raw[123]=1
        snaps[(1,'outer-before')]['regions'][1]['bytes']=bytes(raw)
        with self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_permissions_must_not_change(self):
        events,snaps=synthetic_group();snaps[(1,'outer-before')]['regions'][2]['permissions']=b'\x01'
        with self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_host_sessions_never_roll_back(self):
        for field in ('d3d','user32','callbacks'):
            events,snaps=synthetic_group();flip(snaps[(1,'outer-before')],field)
            with self.subTest(field=field),self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_tls_counter_never_rolls_back(self):
        events,snaps=synthetic_group();events[7]['file_bytes_read']=1
        with self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_owner_must_stay_same_address(self):
        events,snaps=synthetic_group();events[7]['state_address']=48
        with self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_each_cumulative_ledger_checked(self):
        for key in review.LEDGER_KEYS:
            events,snaps=synthetic_group();events[6][key]+=1
            with self.subTest(key=key),self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_complete_after_state_equivalence(self):
        for field,offset in [('state',3000),('context',1936),('instructions',0)]:
            events,snaps=synthetic_group();flip(snaps[(1,'callback-after')],field,offset)
            with self.subTest(field=field),self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_attempt_order_and_roles(self):
        for change in ('role','order','missing'):
            events,snaps=synthetic_group()
            if change=='role':events[7]['role']='continuation'
            elif change=='order':events[1],events[7]=events[7],events[1]
            else:events.pop(7)
            with self.subTest(change=change),self.assertRaises(ValueError):validate_synthetic(events,snaps)

    def test_explicit_replay_contract_types(self):
        good=dict(schema=1,status='TEST',timing_enabled=False,replay_enabled=True,diagnostic_rounds=2,continuation_rounds=1)
        review.validate_receipt_contract(good,'TEST')
        for key,value in [('schema',True),('replay_enabled',1),('timing_enabled',0),('diagnostic_rounds',1),('continuation_rounds',True)]:
            bad={**good,key:value}
            with self.subTest(key=key),self.assertRaises(ValueError):review.validate_receipt_contract(bad,'TEST')

    def test_output_cannot_pollute_frozen_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();protected=root/'run';protected.mkdir()
            with self.assertRaises(ValueError):review.single.validate_output(protected/'review.json',[protected])
            self.assertEqual(review.single.validate_output(root/'review.json',[protected]),root/'review.json')

    def test_final_host_may_advance_but_not_reset_counters(self):
        events,_=synthetic_group();last=events[-1]
        host=dict(callback_stats=dict(calls=5,returns=5),user32_stats=dict(callbacks=5,posted_dispatches=5,api_calls=[5]*14),
                  files=dict(bytes_read=1,bytes_written=20,api_calls_4_to_9=[2]*5+[0]),steps=100,switch_commits=3)
        review.validate_final_host(host,last)
        paths=[('callback_stats','calls'),('callback_stats','returns'),('user32_stats','callbacks'),
               ('user32_stats','posted_dispatches')]
        for section,key in paths:
            bad=copy.deepcopy(host);bad[section][key]=0
            with self.subTest(key=key),self.assertRaises(ValueError):review.validate_final_host(bad,last)
        bad=copy.deepcopy(host);bad['user32_stats']['api_calls'][5]=0
        with self.assertRaises(ValueError):review.validate_final_host(bad,last)

    def test_final_file_ledger_and_context_not_reset(self):
        events,_=synthetic_group();last=events[-1]
        last.update(file_bytes_read=7,file_bytes_written=3,steps=48,switch_commits=1)
        last['file_api_calls'][4]=2
        host=dict(callback_stats=dict(calls=5,returns=5),user32_stats=dict(callbacks=5,posted_dispatches=5,api_calls=[5]*14),
                  files=dict(bytes_read=7,bytes_written=20,api_calls_4_to_9=[2]*5+[0]),steps=100,switch_commits=3)
        review.validate_final_host(host,last)
        for key in ('bytes_read','bytes_written'):
            bad=copy.deepcopy(host);bad['files'][key]=0
            with self.subTest(key=key),self.assertRaises(ValueError):review.validate_final_host(bad,last)
        bad=copy.deepcopy(host);bad['files']['api_calls_4_to_9'][0]=0
        with self.assertRaises(ValueError):review.validate_final_host(bad,last)
        for key in ('steps','switch_commits'):
            bad=copy.deepcopy(host);bad[key]=0
            with self.subTest(key=key),self.assertRaises(ValueError):review.validate_final_host(bad,last)

    def test_counters_cannot_reset_between_messages(self):
        events,_=synthetic_group();before=events[-1];after=copy.deepcopy(before)
        review.validate_event_counter_progress(before,after)
        for key in ('callback_calls','callback_returns','user32_callbacks','posted_dispatches'):
            after=copy.deepcopy(before);after[key]=0
            with self.subTest(key=key),self.assertRaises(ValueError):review.validate_event_counter_progress(before,after)
        after=copy.deepcopy(before);after['api_calls'][5]=0
        with self.assertRaises(ValueError):review.validate_event_counter_progress(before,after)

    def test_exact_outer_machine_bridges(self):
        events,snaps=bridge_fixture()
        review.validate_outer_bridges(events,snaps);review.validate_host_phases(snaps,0)

    def test_common_outer_context_corruption_rejected(self):
        for off in (8,16,24,32,72,80,695,768,896,1912,5496,5768):
            events,snaps=bridge_fixture();flip(snaps['outer-after'],'context',off)
            with self.subTest(offset=off),self.assertRaises(ValueError):review.validate_outer_bridges(events,snaps)

    def test_callback_entry_bridge_cannot_share_wrong_guest_bytes(self):
        for field,off in [('state',100),('context',8),('instructions',0)]:
            events,snaps=bridge_fixture()
            for kind in ('callback-before','callback-after'):flip(snaps[kind],field,off)
            with self.subTest(field=field),self.assertRaises(ValueError):review.validate_outer_bridges(events,snaps)
        for off in (0x3018,0x31b0):
            events,snaps=bridge_fixture()
            for kind in ('callback-before','callback-after'):
                data=bytearray(snaps[kind]['regions'][0]['bytes']);data[off]^=1;snaps[kind]['regions'][0]['bytes']=bytes(data)
            with self.subTest(offset=off),self.assertRaises(ValueError):review.validate_outer_bridges(events,snaps)

    def test_ret_snapshot_and_frame_transform_exact(self):
        for field,off in [('context',1936),('context',728),('context',736),('context',752),('context',5472),('state',2312),('state',2472)]:
            events,snaps=bridge_fixture();flip(snaps['outer-after'],field,off)
            with self.subTest(field=field,offset=off),self.assertRaises(ValueError):review.validate_outer_bridges(events,snaps)
        events,snaps=bridge_fixture();events[-3]['rip']+=1
        with self.assertRaises(ValueError):review.validate_outer_bridges(events,snaps)

    def test_callback_host_middle_phase_cannot_be_jointly_forged(self):
        for field,offset in [('user32',224),('callbacks',16),('d3d',100)]:
            events,snaps=bridge_fixture()
            for kind in ('callback-before','callback-after'):flip(snaps[kind],field,offset)
            with self.subTest(field=field),self.assertRaises(ValueError):review.validate_host_phases(snaps,0)

    def test_full_layout_sizes_offsets_and_types_are_fixed(self):
        review.validate_layout(copy.deepcopy(review.EXPECTED_LAYOUT))
        for section in ('sizes','offsets'):
            for key in review.EXPECTED_LAYOUT[section]:
                value=copy.deepcopy(review.EXPECTED_LAYOUT);value[section][key]+=1
                with self.subTest(section=section,key=key),self.assertRaises(ValueError):review.validate_layout(value)
        for key,value in [('schema',True),('diagnostics_per_event',2.0),('extra_field',1)]:
            layout=copy.deepcopy(review.EXPECTED_LAYOUT);layout[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):review.validate_layout(layout)
        for key,size in [('d3d_session',40),('user32_session',176),('callback_boundary',1)]:
            value=copy.deepcopy(review.EXPECTED_LAYOUT);value['sizes'][key]=size
            with self.subTest(key=key),self.assertRaises(ValueError):review.validate_layout(value)

    def test_independent_replay_overlay(self):
        from . import generate
        for strategy in ('reference','inline'):
            with tempfile.TemporaryDirectory() as temp:
                output=Path(temp).resolve()/'source';record=generate.prepare(output,strategy)
                review.validate_overlay(record,strategy,review.Audit())
                source=output/'window_bridge/window_runtime/runtime.c';source.write_bytes(source.read_bytes()+b'\n/* changed */\n')
                manifest=Path(record['manifest_path']);value=json.loads(manifest.read_bytes())
                value['generated']['window_bridge/window_runtime/runtime.c']=review.digest(source.read_bytes())
                manifest.write_text(json.dumps(value));record['manifest_sha256']=review.digest(manifest.read_bytes())
                with self.assertRaises(ValueError):review.validate_overlay(record,strategy,review.Audit())


if __name__=='__main__':unittest.main()
