"""Independent stdlib-only read-only recomputation; never launches native guest."""
import argparse,hashlib,json,struct,statistics,time,subprocess,inspect,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-directory',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
RUN=args.run_directory.resolve()
SDK_MAN=Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/share/man/man3/clock_gettime.3')
checks=0

def need(x,m):
    global checks
    checks+=1
    if not x:raise ValueError(m)

def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()

def read(name):return json.loads((RUN/name).read_text())
def exact_current(mapping):
    for name,digest in mapping.items():need(sha(name)==digest,'input/artifact changed: '+name)

start=read('started.json');launched=read('launched.json');r=read('evidence.json');raw=read('run.stdout')
need(r['result']==raw,'receipt not raw stdout');need(r['started_sha256']==sha(RUN/'started.json'),'start SHA')
need(type(start['smoke']) is bool and type(start['duration_ms']) is int,'explicit actual duration mode')
smoke=start['smoke'];expected_status='PASS_10_SECOND_SMOKE_NOT_SUSTAINED' if smoke else 'PASS_AT_LEAST_30_MINUTES_TEST_QUEUE_ACTIVITY'
need(r['status']==expected_status and (start['duration_ms']==10000 if smoke else 1800000<=start['duration_ms']<=2047000),'mode cannot be relabeled')
expected_timeout=60 if smoke else 2160
need(launched['pid']==r['pid'] and launched['supervisor_begin_ns']==r['supervisor_begin_ns'] and launched['started_sha256']==r['started_sha256'] and launched['external_timeout_seconds']==expected_timeout,'launch binding')
exact_current(start['inputs_before']);exact_current(r['artifacts']);need(start['inputs_before']==r['inputs_after'],'after identity')
need(r['returncode']==0 and r['external_timeout'] is False and raw['outcome']=='PROCESS_EXITED' and raw['exit_code']==0 and raw['exit_requested']==1 and raw['proc_translated']==0,'actual native endpoint')
need(raw['fault']['status']==0 and raw['returned']==0 and raw['steps']<=start['budget'],'fault/steps')
c=raw['long_run'];events=raw['test_queue']['events'];need(len(events)==raw['test_queue']['posted']==raw['test_queue']['requested']<=8192,'event counts')
need(raw['test_queue']['injection_error']==c['controller_error']==0,'controller failure')
need((len(events)-1)%4==0 and len(events)>4,'cycles length');cycles=(len(events)-1)//4
need([e['name'] for e in events]==['right','right-up','left','left-up']*cycles+['escape'],'complete actual order')
need(r['supervisor_begin_ns']<=c['start_ns']<=c['first_ready_ns']<c['escape_begin_ns']<=c['worker_done_ns']<=c['finish_ns']<=r['supervisor_end_ns'],'same-clock causal interval')
rows=[];last=c['first_ready_ns'];last_wait=0
for index,e in enumerate(events):
    b,eend=e['post_begin_ns'],e['post_end_ns'];gap=b-last;spent=eend-b;late=gap-250000000
    need(type(b) is int and type(eend) is int and 250000000<=gap<=5000000000 and 0<=spent<=5000000000,'gap/post duration '+str(index))
    need(e['origin']==3 and e['wait_count']>last_wait,'origin/wait '+str(index))
    need(e['elapsed_ns']==b-c['first_ready_ns'] and e['elapsed_ms']==(b-c['first_ready_ns'])//1000000,'elapsed '+str(index))
    rows.append({'index':index,'name':e['name'],'wait_count':e['wait_count'],'gap_ns':gap,'post_ns':spent,'lateness_ns':late})
    last=eend;last_wait=e['wait_count']
need(events[-1]['post_begin_ns']==c['escape_begin_ns'] and events[-1]['post_end_ns']==c['escape_end_ns'],'Escape source row')
active=c['escape_begin_ns']-c['first_ready_ns'];native=c['finish_ns']-c['start_ns']
need(active>=start['duration_ms']*1000000,'actual Escape activity below requested duration')
need((active<1800000000000) if smoke else (active>=1800000000000),'actual smoke/formal threshold')
need(c['duration_ms']==start['duration_ms'] and c['mode']==('SMOKE_10_SECONDS' if smoke else 'FORMAL_AT_LEAST_30_MINUTES'),'native actual mode differs')
need(c['event_period_ms']==250 and c['capacity']==8192 and c['protection_ms']==2100000 and c['stall_limit_ms']==5000 and c['clock']=='CLOCK_MONOTONIC','native controller constants differ')
need(native<2100000000000 and r['supervisor_end_ns']-r['supervisor_begin_ns']<=expected_timeout*1000000000,'native/supervisor elapsed above limits')
need(c['phase']==0 and c['max_gap_ns']==max(x['gap_ns'] for x in rows) and c['max_lateness_ns']==max(x['lateness_ns'] for x in rows),'trace max statistics')
need(active==r['timing']['active_ns'] and native==r['timing']['native_elapsed_ns'] and cycles==r['timing']['cycles'],'receipt timing independently agrees')
before=None if start['before_hex'] is None else bytes.fromhex(start['before_hex'])
if before is None:
    initial=(0x31574f43,1,3,0,0);need(not (RUN/'initial-save.bin').exists(),'unexpected initial snapshot')
else:
    need(len(before)==20 and (RUN/'initial-save.bin').read_bytes()==before,'actual historical initial save')
    initial=struct.unpack('<5I',before);need(initial[:2]==(0x31574f43,1) and initial[2]<=7,'valid original save format')
state=struct.unpack('<5I',bytes.fromhex(raw['observations']['window_state']));position=initial[2];moves=initial[3];current_moves=0
for event in events:
    if event['name']=='right' and position<7:position+=1;moves=(moves+1)&0xffffffff;current_moves+=1
    if event['name']=='left' and position>0:position-=1;moves=(moves+1)&0xffffffff;current_moves+=1
need(state[:4]==(0x31574f43,1,position,moves),'independent integer movement state')
saved=(RUN/'data/integer-tile.bin').read_bytes();need(len(saved)==20 and saved==bytes.fromhex(raw['observations']['window_state'])==bytes.fromhex(raw['saved_file']['data_hex']),'actual disk equals complete guest state')
need(raw['saved_file']['errno']==0 and raw['saved_file']['truncated'] is False,'file read observation')
fields=('stage','exit','create','keydown','repeat','paint','close','destroy','present','save','saved_bytes','error','hr','quit','dirty')
result=dict(zip(fields,struct.unpack('<15I',bytes.fromhex(raw['observations']['window_result']))))
d=raw['d3d_before_cleanup'];present=d['present_calls']
need(state[4]==(initial[4]+present)&0xffffffff and present>=1+current_moves,'persisted cumulative draw total, frame per move')
for k,v in {'stage':5,'exit':0,'create':2,'keydown':2*cycles+1,'repeat':0,'close':0,'destroy':1,'present':present,'save':1,'saved_bytes':20,'error':0,'hr':0,'quit':1,'dirty':0}.items():need(result[k]==v,'guest result '+k)
expected_load=(1,0,1,0,0,0,2,0,0) if before is None else (1,1,0,0,20,0,0,0,0)
need(struct.unpack('<9I',bytes.fromhex(raw['observations']['window_load_result']))==expected_load,'actual guest load/EOF/close result')
need(bytes.fromhex(raw['observations']['window_load_candidate'])==(bytes(20) if before is None else before),'guest candidate is exact historical file or zero if missing')
need(struct.unpack('<I',bytes.fromhex(raw['observations']['window_load_count']))[0]==(0 if before is None else 20) and bytes.fromhex(raw['observations']['window_load_extra_count'])==bytes(4) and bytes.fromhex(raw['observations']['window_load_extra'])==bytes(1),'load byte count and EOF probe')
f=raw['files'];need(f['api_calls_4_to_9']==([2,1,0,1,1,0] if before is None else [2,1,2,2,0,0]) and f['bytes_read']==(0 if before is None else 20) and f['bytes_written']==20 and f['last_error']==(0 if before is None else 183),'actual file API trace')
for k in ('open_before_cleanup','open_after_cleanup','cleanup_closes','cleanup_errors'):need(f[k]==0,'no cleanup-masked file leak '+k)
for k in ('clear_calls','om_set_calls','rs_set_calls','viewport_calls','topology_calls','vs_set_calls','ps_set_calls','draw_calls','present_calls'):need(d[k]==present,'actual graphics calls '+k)
need(d['created']==d['release_calls']==d['guest_released']==8 and d==raw['d3d_after_cleanup'],'eight guest refs returned before cleanup')
for k in ('active_maps','live_objects','cleanup_releases','cleanup_unmaps','cleanup_clear_state_calls','cleanup_flush_calls'):need(d[k]==0,'no cleanup-masked graphics '+k)
for name in ('host_before_finish','host_after_finish'):
    h=raw[name];need(h['windows_created']==h['windows_destroyed']==h['views_created']==h['views_released']==1,'window view 1:1')
    need(h['test_queue_events']==len(events) and h['cocoa_key_events']==0 and h['error']==h['stopped']==1 and h['pending_messages']==h['paint_invalid']==0,'queue actual terminal')
    for k in ('active_views','forced_cleanup_windows','queue_overflows'):need(h[k]==0,'host leak '+k)
cb=raw['callback_stats'];need(cb['calls']==cb['returns']>0 and cb['depth']==cb['rejections']==cb['end_status']==0,'callback complete')
u=raw['user32_stats'];need(u['classes_registered']==u['classes_unregistered']==u['windows_created']==u['windows_destroyed']==1 and u['registered']==0 and u['window_state']==4,'User32 lifecycle')
resources=raw['resources'];rs,rr,rf=(resources[k] for k in ('start','first_ready','finished'))
for snap in resources.values():need(snap['queried']==1 and snap['usage_status']==snap['usage_errno']==snap['mach_status']==0,'actual resource syscall success')
resource_keys=('user_cpu_ns','system_cpu_ns','minor_faults','major_faults','voluntary_switches','involuntary_switches')
for k in resource_keys:need(rs[k]<=rr[k]<=rf[k],'resource cumulative '+k)
cpu=(rf['user_cpu_ns']+rf['system_cpu_ns'])-(rs['user_cpu_ns']+rs['system_cpu_ns']);need(cpu==r['timing']['process_cpu_ns'],'CPU delta')
info=time.get_clock_info('monotonic');need(subprocess._time is time.monotonic,'actual subprocess wait clock')
man=SDK_MAN.read_text();need('will continue to increment while the system is asleep' in man and 'does not increment while the system is asleep' in man,'local SDK sleep contracts')
record={'status':'PASS_INDEPENDENT_READONLY_SMOKE_RECOMPUTATION' if smoke else 'PASS_INDEPENDENT_READONLY_FORMAL_RECOMPUTATION','checks':checks,'pid':r['pid'],'new_guest_executions':0,'scope':'read-only existing actual mode; no new guest/GPU execution, pixels, physical keyboard or performance advantage claim',
 'actual_artifacts':{str(RUN/p):sha(RUN/p) for p in ('evidence.json','started.json','launched.json','run.stdout','run.stderr','data/integer-tile.bin')},
 'timeline':{'active_ns':active,'native_ns':native,'supervisor_ns':r['supervisor_end_ns']-r['supervisor_begin_ns'],'ready_delay_ns':c['first_ready_ns']-c['start_ns'],'escape_to_worker_done_ns':c['worker_done_ns']-c['escape_begin_ns'],'events':len(events),'cycles':cycles,'gap_min_ns':min(x['gap_ns'] for x in rows),'gap_max_ns':max(x['gap_ns'] for x in rows),'gap_median_ns':statistics.median(x['gap_ns'] for x in rows),'max_post_ns':max(x['post_ns'] for x in rows),'events_recomputed':rows},
 'gameplay':{'initial_state':initial,'restored':before is not None,'current_moves':current_moves,'position':position,'moves':moves,'draws':state[4],'result_fields':result,'state_hex':saved.hex(),'saved_sha256':sha(RUN/'data/integer-tile.bin'),'steps':raw['steps'],'guest_released_refs':8,'file_api_calls':f['api_calls_4_to_9'],'callbacks':cb['calls']},
 'resources':{'cpu_user_delta_ns':rf['user_cpu_ns']-rs['user_cpu_ns'],'cpu_system_delta_ns':rf['system_cpu_ns']-rs['system_cpu_ns'],'cpu_total_ns':cpu,'resource_snapshots':resources,'first_ready_to_finished_resident_delta_bytes':rf['resident_bytes']-rr['resident_bytes'],'whole_native_cpu_over_elapsed_fraction':cpu/native,'caveat':'single low-load run, three snapshots; no FPS/throughput/leak trend claim'},
 'clock_evidence':{'sdk_man_path':str(SDK_MAN),'sdk_man_sha256':sha(SDK_MAN),'subprocess_path':subprocess.__file__,'subprocess_sha256':sha(subprocess.__file__),'python_executable':sys.executable,'python_sha256':sha(sys.executable),'python_monotonic':vars(info),'wait_uses':'subprocess._time is time.monotonic','native_and_recording_clock':'explicit CLOCK_MONOTONIC; includes system sleep per SDK','limit':'Popen.wait timeout uses mach_absolute_time and can extend in wall time during sleep; final same-clock elapsed and native 5s post-ready stall reject false activity PASS. No system sleep experiment performed.'},
 'reviewer_sha256':sha(__file__)}
exact_current(start['inputs_before']);exact_current(r['artifacts']);record['checks']=checks
if before is not None:record['actual_artifacts'][str(RUN/'initial-save.bin')]=sha(RUN/'initial-save.bin')
with args.out.open('x') as f:json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps({k:record[k] for k in ('status','checks','pid','new_guest_executions')}));print(json.dumps({k:v for k,v in record['timeline'].items() if k!='events_recomputed'}));print(json.dumps({k:v for k,v in record['resources'].items() if k not in ('resource_snapshots',)}))
