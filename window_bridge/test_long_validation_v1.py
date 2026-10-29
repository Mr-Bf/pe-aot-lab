"""Synthetic JSON parser gates, explicitly zero real elapsed-duration evidence."""
from __future__ import annotations
import argparse,copy,json
from pathlib import Path
from window_bridge import long_validation_v1 as v
from window_bridge import save_load_bindings_v1 as source
from graphics_stage5 import d3d11_probe as g
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'build/window-bridge/save-load-run-roundtrip-v1/phase-1/run.stdout'
BUILD=ROOT/'build/window-bridge/save-load-program-v1-01'

def require(x,m):
    if not x:raise ValueError(m)

def sample(smoke):
    r=g.strict_json(BASE.read_text());start=10000000000000;ready=start+1000000;previous=ready;events=[];duration=10000 if smoke else 1800000
    for i in range(4*(duration//1000)+1):
        begin=previous+250000000;end=begin+100
        events.append({'name':'escape' if i==4*(duration//1000) else ('right','right-up','left','left-up')[i%4],
            'origin':3,'wait_count':i+1,'elapsed_ms':(begin-ready)//1000000,'elapsed_ns':begin-ready,'post_begin_ns':begin,'post_end_ns':end});previous=end
    r['test_queue'].update(requested=len(events),posted=len(events),events=events)
    r['long_run']={'profile':'bounded-duration-controller-v1','mode':'SMOKE_10_SECONDS' if smoke else 'FORMAL_AT_LEAST_30_MINUTES','duration_ms':duration,'event_period_ms':250,'capacity':8192,'protection_ms':2100000,'stall_limit_ms':5000,'controller_error':0,'phase':0,'clock':'CLOCK_MONOTONIC',
        'start_ns':start,'first_ready_ns':ready,'escape_begin_ns':events[-1]['post_begin_ns'],'escape_end_ns':previous,'worker_done_ns':previous+1000000,'finish_ns':previous+2000000,'max_gap_ns':250000000,'max_lateness_ns':0}
    r['resources']={}
    for name,stamp in [('start',start+1),('first_ready',ready+1),('finished',previous+2000001)]:
        r['resources'][name]={k:0 for k in ('queried','usage_status','usage_errno','mach_status','timestamp_ns','user_cpu_ns','system_cpu_ns','maxrss_native','resident_bytes','resident_peak_bytes','virtual_bytes','minor_faults','major_faults','voluntary_switches','involuntary_switches')};r['resources'][name].update(queried=1,timestamp_ns=stamp)
    return r

def run():
    p=source.Program.from_build(BUILD);cases=[]
    for smoke in (True,False):
        r=sample(smoke);got=v.validate_execution(p,r,0,None,100000000)
        require(got['smoke'] is smoke and got['events']==len(r['test_queue']['events']),'mode parsing differs');cases.append({'name':'synthetic-mode-'+str(smoke),'result':got['status']})
    base=sample(True)
    mutations={
      'formal-name-with-10s':lambda r:r['long_run'].update(mode='FORMAL_AT_LEAST_30_MINUTES'),
      'formal-duration-with-short-trace':lambda r:r['long_run'].update(mode='FORMAL_AT_LEAST_30_MINUTES',duration_ms=1800000),
      'wrong-period':lambda r:r['long_run'].update(event_period_ms=249),
      'capacity-unbounded':lambda r:r['long_run'].update(capacity=999999),
      'event-gap-burst':lambda r:r['test_queue']['events'][2].update(post_begin_ns=r['test_queue']['events'][1]['post_end_ns']+1),
      'wrong-elapsed':lambda r:r['test_queue']['events'][2].update(elapsed_ns=0),
      'float-time':lambda r:r['test_queue']['events'][2].update(post_begin_ns=1.5),
      'bool-time':lambda r:r['test_queue']['events'][2].update(elapsed_ms=True),
      'wrong-cycle':lambda r:r['test_queue']['events'][2].update(name='right'),
      'duplicate-wait':lambda r:r['test_queue']['events'][2].update(wait_count=2),
      'false-origin':lambda r:r['test_queue']['events'][2].update(origin=1),
      'extra-event-field':lambda r:r['test_queue']['events'][2].update(fake=1),
      'worker-before-escape':lambda r:r['long_run'].update(worker_done_ns=r['long_run']['first_ready_ns']),
      'wrong-end':lambda r:r['long_run'].update(escape_end_ns=1),
      'wrong-max-gap':lambda r:r['long_run'].update(max_gap_ns=1),
      'wrong-max-lateness':lambda r:r['long_run'].update(max_lateness_ns=1),
      'requested-over-cap':lambda r:r['test_queue'].update(requested=8193),
      'missing-resources':lambda r:r['resources'].pop('first_ready'),
      'resource-failure-hidden':lambda r:r['resources']['finished'].update(usage_status=-1,usage_errno=1),
      'resource-backward':lambda r:r['resources']['start'].update(user_cpu_ns=1),
      'peak-below-current':lambda r:r['resources']['start'].update(resident_bytes=2,resident_peak_bytes=1),
      'ready-before-start':lambda r:r['long_run'].update(first_ready_ns=1),
      'unknown-actual-PE':lambda r:r.update(pe_sha256='0'*64),
      'steps-above-bound':lambda r:r.update(steps=100000001),
    }
    for name,mutate in mutations.items():
        r=copy.deepcopy(base);mutate(r)
        try:v.validate_execution(p,r,0,None,100000000)
        except ValueError as e:cases.append({'name':name,'rejected':str(e)})
        else:raise ValueError('accepted mutant '+name)
    r=copy.deepcopy(base);r['long_run']['controller_error']=3;r['test_queue']['injection_error']=3;r['host_exit_code']=64
    require(v.validate_execution(p,r,64,None,100000000)['status']=='INCOMPLETE_OR_FAILED_NOT_DURATION_ACCEPTED','stall allowed as duration');cases.append({'name':'explicit-stall','result':'not duration accepted'})
    # Common parser acceptance is deliberately insufficient to authenticate a
    # fabricated trace or gameplay. The unchanged real state cannot match this
    # synthetic 41-message history; semantic checks must still reject it.
    try:v.semantic_acceptance_long({'result':base,'returncode':0,'external_timeout':False,'test_sequence':[e['name'] for e in base['test_queue']['events']]},None,bytes.fromhex(base['saved_file']['data_hex']))
    except ValueError as e:cases.append({'name':'parser-only-is-not-gameplay','rejected':str(e)})
    else:raise ValueError('fabricated trace accepted as actual gameplay')
    before=g.hashes([__file__,v.__file__,source.__file__,BASE,BUILD/'program-build.json'])
    return {'status':'PASS_SYNTHETIC_PARSER_GATES_NOT_RUNTIME','cases':cases,'positive_parsers':2,'rejections':25,'explicit_nonacceptance':1,
        'inputs':before,'scope':{'new_guest_executions':0,'new_gpu_executions':0,'actual_long_duration_runs':0,'synthetic_json_only':True}}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();r=run()
    with a.out.open('x') as f:json.dump(r,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps({k:r[k] for k in ('status','positive_parsers','rejections','explicit_nonacceptance','scope')}))
