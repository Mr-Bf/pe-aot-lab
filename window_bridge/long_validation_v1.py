"""Versioned long trace validation; no execution or duration claim from a build."""
from __future__ import annotations
import ast
import re
import textwrap
from pathlib import Path
from window_bridge import save_load_bindings_v1 as source
graphics=source.graphics;STATS_FIELDS=source.STATS_FIELDS;TEST_EVENTS=source.TEST_EVENTS

def _validate_common(self,result,returncode,base=None,budget=None):
    if type(returncode) is not int or not isinstance(result,dict):raise ValueError('invalid execution result')
    if result.get('outcome')=='HOST_ERROR':
        if returncode!=64 or set(result)!={'outcome','error'} or not isinstance(result['error'],str):raise ValueError('host error contract')
        return
    fields={'outcome','aot_status','setup_status','pe_sha256','image_base','entry_rva','entry_arguments',
        'host_exit_code','proc_translated','proc_translated_errno','timed_out','join_status','host_finished',
        'exit_requested','exit_code','exit_pc','exit_rsp','exit_depth','returned','steps','call_depth',
        'fault','rax','rsp','rip','d3d_cleanup_result','d3d_before_cleanup','d3d_after_cleanup',
        'callback_stats','user32_stats','user32_end_status','host_before_finish','host_after_finish',
        'files','test_queue','observations','saved_file'}
    if set(result)!=fields:raise ValueError('host result field closure differs')
    nested={'outcome','pe_sha256','timed_out','host_finished','fault','d3d_before_cleanup','d3d_after_cleanup','callback_stats','user32_stats','host_before_finish','host_after_finish','files','test_queue','observations','saved_file'}
    if any(not graphics.uint(result[k],0xffffffffffffffff) for k in fields-nested):raise ValueError('host scalar type differs')
    if type(result['timed_out']) is not bool or type(result['host_finished']) is not bool:raise ValueError('host boolean types')
    if result['host_exit_code']!=returncode or result['proc_translated']!=0:raise ValueError('actual child exit/ISA differs')
    if budget is not None and (type(budget) is not int or not 1<=budget<=0xffffffffffffffff or result['steps']>budget):raise ValueError('observed guest steps exceed the executed budget')
    def uint_dict(value,expected):
        if not isinstance(value,dict) or set(value)!=set(expected) or any(not graphics.uint(v,0xffffffffffffffff) for v in value.values()):raise ValueError('statistics type/field closure differs')
    uint_dict(result['fault'],('status','pc','address','width','access'))
    for k in ('d3d_before_cleanup','d3d_after_cleanup'):uint_dict(result[k],STATS_FIELDS)
    uint_dict(result['callback_stats'],('calls','returns','rejections','depth','max_depth','end_status'))
    host_fields=('windows_created','windows_destroyed','forced_cleanup_windows','views_created','views_released','active_views','cocoa_key_events','cocoa_window_events','test_queue_events','focus_recovery_events','guest_queue_events','ignored_keys','messages_taken','waits','quit_messages','queue_overflows','main_dispatches','event_pumps','close_requests','resize_events','api_focus_transitions','sent_notifications','pending_messages','error','stopped','worker_bound','paint_invalid','tombstones')
    for k in ('host_before_finish','host_after_finish'):uint_dict(result[k],host_fields)
    user=result['user32_stats'];uint_dict({k:v for k,v in user.items() if k!='api_calls'},('callbacks','sent_notifications','posted_dispatches','discarded_stale','classes_registered','classes_unregistered','windows_created','windows_destroyed','registered','window_state','hwnd'))
    if not isinstance(user.get('api_calls'),list) or len(user['api_calls'])!=14 or any(not graphics.uint(v,0xffffffffffffffff) for v in user['api_calls']):raise ValueError('User32 call vector differs')
    files=result['files'];uint_dict({k:v for k,v in files.items() if k!='api_calls_4_to_9'},('last_error','open_before_cleanup','open_after_cleanup','cleanup_closes','cleanup_errors','bytes_read','bytes_written'))
    if not isinstance(files.get('api_calls_4_to_9'),list) or len(files['api_calls_4_to_9'])!=6 or any(not graphics.uint(v,0xffffffffffffffff) for v in files['api_calls_4_to_9']):raise ValueError('file call vector differs')
    queue=result['test_queue'];uint_dict({k:v for k,v in queue.items() if k!='events'},('requested','posted','injection_error','observed_hwnd'))
    if not isinstance(queue.get('events'),list) or len(queue['events'])!=queue['posted'] or queue['posted']>queue['requested'] or queue['requested']>8192:raise ValueError('queue count differs')
    previous=0
    for event in queue['events']:
        if set(event)!={'name','origin','wait_count','elapsed_ms','elapsed_ns','post_begin_ns','post_end_ns'} or event['name'] not in TEST_EVENTS or event['origin']!=3 or not graphics.uint(event['wait_count'],0xffffffffffffffff) or event['wait_count']<=previous:raise ValueError('queue origin/wait boundary differs')
        previous=event['wait_count']
    saved=result['saved_file']
    if set(saved)!={'name','errno','truncated','data_hex'} or saved['name']!='integer-tile.bin' or not graphics.uint(saved['errno'],0xffffffff) or type(saved['truncated']) is not bool:raise ValueError('saved file observation differs')
    if saved['errno']:
        if saved['data_hex'] is not None:raise ValueError('failed file read claims bytes')
    elif not isinstance(saved['data_hex'],str) or not re.fullmatch(r'(?:[0-9a-f]{2}){0,4096}',saved['data_hex']):raise ValueError('invalid saved bytes')
    expected=self.build_manifest['observations']
    if set(result['observations'])!=set(expected):raise ValueError('guest observation set differs')
    for name,item in expected.items():
        value=result['observations'][name]
        if not isinstance(value,str) or not (result['setup_status'] and value=='') and not re.fullmatch('[0-9a-f]{%d}'%(item['size']*2),value):raise ValueError('guest observation bytes differ')
    if result['pe_sha256']!=self.source_sha256 or result['entry_rva']!=self.image.entry_rva or result['entry_arguments']!=0 or result['image_base']!=(self.image.base if base is None else base):raise ValueError('actual PE/entry/base differs')
    if result['outcome']=='SETUP_ERROR':
        if not result['setup_status'] or returncode!=64:raise ValueError('setup error contract')
        return
    if result['setup_status']:raise ValueError('execution with setup failure')
    status=result['aot_status'];fault=result['fault']['status']
    if result['outcome']=='PROCESS_EXITED':
        if status!=11 or result['exit_requested']!=1 or result['returned'] or fault or result['exit_code']>0xffffffff:raise ValueError('ExitProcess endpoint differs')
    elif result['outcome']=='FUNCTION_RETURN':
        if status or result['exit_requested'] or result['returned']!=1 or fault:raise ValueError('function return endpoint differs')
    elif result['outcome']=='FAULT':
        if not 1<=status<=17 or status==11 or fault!=status:raise ValueError('fault endpoint differs')
    else:raise ValueError('unknown outcome')
    cleanup_bad=(result['join_status'] or not result['host_finished'] or result['host_after_finish']['active_views'] or result['d3d_after_cleanup']['live_objects'] or result['d3d_after_cleanup']['active_maps'] or files['cleanup_errors'] or files['open_after_cleanup'] or result['callback_stats']['end_status'] or result['user32_end_status'] or result['timed_out'] or queue['injection_error'])
    expected_exit=64 if cleanup_bad else {'PROCESS_EXITED':0,'FUNCTION_RETURN':2,'FAULT':3}[result['outcome']]
    if returncode!=expected_exit:raise ValueError('cleanup/host exit contract differs')


def verify_common_source():
    """The inherited validator is text-identical except capacity/trace fields."""
    def function(path,classname,name):
        text=Path(path).read_text();tree=ast.parse(text)
        nodes=tree.body
        if classname:nodes=next(n for n in nodes if isinstance(n,ast.ClassDef) and n.name==classname).body
        node=next(n for n in nodes if isinstance(n,ast.FunctionDef) and n.name==name)
        return textwrap.dedent(''.join(text.splitlines(True)[node.lineno-1:node.end_lineno]))
    expected=function(source.__file__,'Program','validate_execution')
    expected=expected.replace('def validate_execution(','def _validate_common(').replace("queue['requested']>64","queue['requested']>8192").replace("set(event)!={'name','origin','wait_count'}","set(event)!={'name','origin','wait_count','elapsed_ms','elapsed_ns','post_begin_ns','post_end_ns'}")
    if expected!=function(__file__,None,'_validate_common'):raise ValueError('versioned common validator changed beyond explicit trace delta')
    expected=function(semantic_source.__file__,None,'semantic_acceptance').replace('def semantic_acceptance(', 'def semantic_acceptance_long(').replace('    require(sequence == SEQUENCE, \"closed roundtrip workload differs\")','    require_cycle(sequence)').replace('same original save/load PE with supplied historical before/after snapshots; no pixel/physical-key/performance acceptance','same original save/load PE with long TEST_QUEUE trace and historical snapshots; no pixel/physical-key/performance acceptance')
    if expected!=function(__file__,None,'semantic_acceptance_long'):raise ValueError('versioned semantic validator changed beyond closed long cycle')


def require(value,message):
    if not value:raise ValueError(message)


def validate_execution(program,result,returncode,base=None,budget=None):
    verify_common_source()
    if isinstance(result,dict) and result.get('outcome')=='HOST_ERROR':
        _validate_common(program,result,returncode,base,budget);return {'status':'HOST_ERROR_NOT_DURATION_ACCEPTED'}
    require(isinstance(result,dict) and 'long_run' in result and 'resources' in result,'missing duration/resource fields')
    common={k:v for k,v in result.items() if k not in ('long_run','resources')}
    _validate_common(program,common,returncode,base,budget)
    long=result['long_run'];resources=result['resources'];queue=result['test_queue']
    fixed={'profile':'bounded-duration-controller-v1','event_period_ms':250,'capacity':8192,'protection_ms':2100000,'stall_limit_ms':5000,'clock':'CLOCK_MONOTONIC'}
    scalars={'duration_ms','controller_error','phase','start_ns','first_ready_ns','escape_begin_ns','escape_end_ns','worker_done_ns','finish_ns','max_gap_ns','max_lateness_ns'}
    require(isinstance(long,dict) and set(long)==set(fixed)|scalars|{'mode'},'long controller field closure differs')
    require(all(long[k]==v and type(long[k]) is type(v) for k,v in fixed.items()),'long controller constants differ')
    require(all(graphics.uint(long[k],0xffffffffffffffff) for k in scalars),'long controller scalar types differ')
    smoke=long['mode']=='SMOKE_10_SECONDS'
    require(long['mode'] in ('SMOKE_10_SECONDS','FORMAL_AT_LEAST_30_MINUTES'),'unknown duration mode')
    require(long['duration_ms']==10000 if smoke else 1800000<=long['duration_ms']<=2047000,'duration profile differs')
    require(long['controller_error']<=7 and long['phase']<=3 and long['controller_error']==queue['injection_error'],'controller error/phase differs')
    require(0<long['start_ns']<=long['worker_done_ns']<=long['finish_ns'],'actual worker/main timestamp order differs')
    ready=long['first_ready_ns'];require(not ready or long['start_ns']<=ready<=long['finish_ns'],'ready timestamp differs')
    require(type(resources) is dict and set(resources)=={'start','first_ready','finished'},'resource snapshot set differs')
    resource_fields={'queried','usage_status','usage_errno','mach_status','timestamp_ns','user_cpu_ns','system_cpu_ns','maxrss_native','resident_bytes','resident_peak_bytes','virtual_bytes','minor_faults','major_faults','voluntary_switches','involuntary_switches'}
    for name,r in resources.items():
        require(type(r) is dict and set(r)==resource_fields,'resource field closure differs')
        require(all(type(v) is int for v in r.values()) and all(graphics.uint(v,0xffffffffffffffff) for k,v in r.items() if k!='usage_status'),'resource scalar differs')
        require(r['usage_status'] in (-1,0) and r['queried'] in (0,1),'resource status differs')
        if not r['queried']:require(not any(r.values()),'unqueried resource contains values')
        else:
            require(long['start_ns']<=r['timestamp_ns'],'resource precedes native start')
            if not r['usage_status']:require(r['usage_errno']==0,'successful getrusage claims error')
            if not r['mach_status']:require(r['resident_peak_bytes']>=r['resident_bytes'],'resident peak below current')
    require(resources['start']['queried']==resources['finished']['queried']==1,'start/finished resources missing')
    require(resources['start']['timestamp_ns']<=long['worker_done_ns'] and resources['finished']['timestamp_ns']>=long['finish_ns'],'resource timestamp endpoints differ')
    if ready:require(resources['first_ready']['queried']==1 and ready<=resources['first_ready']['timestamp_ns']<=long['finish_ns'],'ready resource timestamp differs')
    else:require(resources['first_ready']['queried']==0,'resource claims unobserved ready')
    previous=ready;phase=0;escape=None;maxgap=0;maxlate=0
    sequence=('right','right-up','left','left-up')
    for index,event in enumerate(queue['events']):
        require(all(graphics.uint(event[k],0xffffffffffffffff) for k in ('elapsed_ms','elapsed_ns','post_begin_ns','post_end_ns')),'event timestamp type differs')
        begin=event['post_begin_ns'];end=event['post_end_ns'];require(ready>0 and begin>=previous+250000000 and begin<=end<=long['finish_ns'],'event gap/order violates no-burst rule')
        require(event['elapsed_ns']==begin-ready and event['elapsed_ms']==event['elapsed_ns']//1000000,'event elapsed reconstruction differs')
        if event['name']=='escape':
            require(phase==0 and index==len(queue['events'])-1 and begin-ready>=long['duration_ms']*1000000,'Escape precedes duration or complete cycle')
            escape=event
        else:require(event['name']==sequence[phase],'actual regular event cycle differs');phase=(phase+1)%4
        maxgap=max(maxgap,begin-previous);maxlate=max(maxlate,begin-previous-250000000);previous=end
    require(phase==long['phase'] and maxgap==long['max_gap_ns'] and maxlate==long['max_lateness_ns'],'controller trace statistics differ')
    require((long['escape_begin_ns'],long['escape_end_ns'])==((escape['post_begin_ns'],escape['post_end_ns']) if escape else (0,0)),'Escape fields differ from actual event')
    if long['controller_error'] or result['timed_out'] or not escape:
        require(long['controller_error']!=0,'unfinished duration has no explicit failure')
        return {'status':'INCOMPLETE_OR_FAILED_NOT_DURATION_ACCEPTED','smoke':smoke,'events':queue['posted']}
    require(queue['requested']==queue['posted'] and queue['posted']<=8192,'successful post count differs')
    require(long['worker_done_ns']>=escape['post_begin_ns'],'worker stopped before actual Escape submission')
    require(maxgap<=5000000000 and all(e['post_end_ns']-e['post_begin_ns']<=5000000000 for e in queue['events']),'successful trace contains a five-second stall')
    require(long['finish_ns']-long['start_ns']<2100000000000,'completed workload exceeded internal protection')
    require(all(r['queried']==1 and r['usage_status']==r['usage_errno']==r['mach_status']==0 for r in resources.values()),'successful workload lacks successful resource calls')
    for key in ('user_cpu_ns','system_cpu_ns','minor_faults','major_faults','voluntary_switches','involuntary_switches'):
        require(resources['start'][key]<=resources['first_ready'][key]<=resources['finished'][key],'cumulative resource counter went backwards')
    return {'status':'SMOKE_TIMING_OBSERVED_NOT_SUSTAINED_ACCEPTANCE' if smoke else 'FORMAL_TIMING_OBSERVED_REQUIRES_GAME_AND_ARTIFACT_ACCEPTANCE',
            'smoke':smoke,'events':queue['posted'],'cycles':(queue['posted']-1)//4,
            'active_ns':escape['post_begin_ns']-ready,'worker_after_ready_ns':long['worker_done_ns']-ready,
            'native_elapsed_ns':long['finish_ns']-long['start_ns'],
            'process_cpu_ns':sum(resources['finished'][k]-resources['start'][k] for k in ('user_cpu_ns','system_cpu_ns'))}

# The semantic model is versioned from the frozen save/load acceptance body.
# Only its old fixed eight-event workload restriction changes to a full cycle.
import struct
from window_bridge import save_load_acceptance_v1 as semantic_source
PE_SHA256=semantic_source.PE_SHA256
RESULT_FIELDS=semantic_source.RESULT_FIELDS

def require_cycle(sequence):
    require(type(sequence) is list and 5<=len(sequence)<=8192 and (len(sequence)-1)%4==0 and sequence[-1]=='escape','complete bounded cycles plus Escape required')
    require(sequence[:-1]==list(('right','right-up','left','left-up'))*((len(sequence)-1)//4),'closed long cycle differs')

def semantic_acceptance_long(record, before_bytes, after_bytes):
    """Pure semantic check of supplied snapshots, after producer.verify_run.

    Never read phase-1 output from the current shared disk: phase 2 legitimately
    replaced it. This function does not authenticate a caller-forged record.
    """
    r = record["result"]
    sequence = record["test_sequence"]
    require(isinstance(sequence, list) and sequence, "explicit workload required")
    require(sequence[-1] in ("escape", "close"), "final event must request exit")
    require(all(x not in ("escape", "close") for x in sequence[:-1]),
            "an early exit leaves later events unconsumed")
    require(r["pe_sha256"] == PE_SHA256, "original PE identity differs")
    require(r["outcome"] == "PROCESS_EXITED" and record["returncode"] == 0,
            "actual child did not exit normally")
    require(r["proc_translated"] == 0 and r["exit_requested"] == 1 and
            r["exit_code"] == 0 and r["fault"]["status"] == 0,
            "guest exit/ISA/fault differs")
    require(not r["timed_out"] and not record["external_timeout"], "timeout")
    require(r["steps"] > 0 and r["entry_arguments"] == 0, "entry not executed")
    queue = r["test_queue"]
    require(queue["posted"] == queue["requested"] == len(sequence) and
            queue["injection_error"] == 0, "incomplete workload")
    require([e["name"] for e in queue["events"]] == sequence and
            all(e["origin"] == 3 for e in queue["events"]), "input source differs")
    host = r["host_before_finish"]
    require(host["cocoa_key_events"] == 0, "real input contaminated deterministic workload")
    require(host["test_queue_events"] == len(sequence), "queue event count differs")

    require_cycle(sequence)
    require(before_bytes is None or type(before_bytes) is bytes, "before must be bytes or None")
    require(type(after_bytes) is bytes and len(after_bytes) == 20, "after snapshot must be 20 bytes")
    if before_bytes is None:
        initial = (0x31574F43, 1, 3, 0, 0)
    else:
        require(len(before_bytes) == 20, "before snapshot must be 20 bytes")
        initial = struct.unpack("<5I", before_bytes)
        require(initial[:2] == (0x31574F43, 1) and initial[2] <= 7, "invalid successful-restore input format")
    position, moves, initial_draws = initial[2], initial[3], initial[4]
    keydowns, repeats, closes, current_moves = 0, 0, 0, 0
    for event in sequence:
        if event == "close":
            closes += 1
        elif not event.endswith("-up"):
            keydowns += 1
            if event.endswith("-repeat"):
                repeats += 1
            elif event == "right" and position < 7:
                position += 1
                moves = (moves + 1) & 0xffffffff
                current_moves += 1
            elif event == "left" and position > 0:
                position -= 1
                moves = (moves + 1) & 0xffffffff
                current_moves += 1
    state_bytes = bytes.fromhex(r["observations"]["window_state"])
    require(len(state_bytes) == 20, "state layout differs")
    magic, version, actual_position, actual_moves, draws = struct.unpack("<5I", state_bytes)
    require((magic, version, actual_position, actual_moves) ==
            (0x31574F43, 1, position, moves), "guest movement/repeat semantics differ")
    current_presents = r["d3d_before_cleanup"]["present_calls"]
    require(type(current_presents) is int and 1 + current_moves <= current_presents <= 0xffffffff,
            "guest did not render each changed position")
    require(draws == (initial_draws + current_presents) & 0xffffffff,
            "persisted draws must be initial total plus current presents")
    result_bytes = bytes.fromhex(r["observations"]["window_result"])
    require(len(result_bytes) == 60, "result layout differs")
    observations = dict(zip(RESULT_FIELDS, struct.unpack("<15I", result_bytes)))
    expected = dict(stage=5, exit_code=0, create_messages=2, keydowns=keydowns,
                    ignored_repeats=repeats, closes=closes, destroys=1,
                    presents=current_presents, saves=1, saved_bytes=20, win32_error=0,
                    graphics_hr=0, quit_requested=1, dirty=0)
    require(all(observations[k] == v for k, v in expected.items()),
            "original PE observation counters differ")
    require(bytes.fromhex(r["observations"]["window_handle"]) == bytes(8),
            "guest retained its window handle")
    require(bytes.fromhex(r["observations"]["window_feature"]) == struct.pack("<I", 0xB000),
            "actual feature level differs")
    require(bytes.fromhex(r["observations"]["window_client"]) == struct.pack("<4i", 0, 0, 640, 360),
            "actual guest client rectangle differs")

    saved = r["saved_file"]
    require(saved["name"] == "integer-tile.bin" and saved["errno"] == 0 and
            not saved["truncated"] and saved["data_hex"] == state_bytes.hex(),
            "actual disk save differs from original PE state")
    require(after_bytes == state_bytes, "historical after snapshot differs from actual guest state")
    load_bytes = bytes.fromhex(r["observations"]["window_load_result"])
    require(len(load_bytes) == 36, "load observation layout")
    load = list(struct.unpack("<9I", load_bytes))
    expected_load = [1,0,1,0,0,0,2,0,0] if before_bytes is None else [1,1,0,0,20,0,0,0,0]
    require(load == expected_load, "guest load attempt/EOF/validation/close observations differ")
    candidate = bytes.fromhex(r["observations"]["window_load_candidate"])
    require(candidate == (bytes(20) if before_bytes is None else before_bytes), "guest load candidate is not actual prior file bytes")
    require(bytes.fromhex(r["observations"]["window_load_count"]) == struct.pack("<I", 0 if before_bytes is None else 20)
            and bytes.fromhex(r["observations"]["window_load_extra_count"]) == bytes(4)
            and bytes.fromhex(r["observations"]["window_load_extra"]) == bytes(1), "load count/EOF byte output differs")
    files = r["files"]
    expected_calls = [2,1,0,1,1,0] if before_bytes is None else [2,1,2,2,0,0]
    require(files["bytes_written"] == 20 and files["bytes_read"] == (0 if before_bytes is None else 20)
            and files["api_calls_4_to_9"] == expected_calls, "guest file API trace differs")
    # Success does not universally clear Win32 LastError. In particular the
    # second CREATE_ALWAYS normally leaves ERROR_ALREADY_EXISTS (183).
    require(type(files["last_error"]) is int and 0 <= files["last_error"] <= 0xffffffff,
            "LastError type/range differs")
    # This fixed local profile leaves the final CREATE_ALWAYS result in its
    # shared LastError: new file -> 0; existing file -> 183. Later successful
    # WriteFile/CloseHandle and admitted teardown calls preserve it. This is
    # not a claim that every successful general Win32 API preserves LastError.
    require(files["last_error"] == (0 if before_bytes is None else 183),
            "fixed profile LastError after actual CREATE_ALWAYS differs")
    require(all(files[k] == 0 for k in ("open_before_cleanup", "open_after_cleanup",
                "cleanup_closes", "cleanup_errors")), "host cleanup masked guest file leak")

    d = r["d3d_before_cleanup"]
    require(d["exit_calls"] == 1, "guest ExitProcess count differs")
    for key in ("clear_calls", "om_set_calls", "rs_set_calls", "viewport_calls",
                "topology_calls", "vs_set_calls", "ps_set_calls", "draw_calls", "present_calls"):
        require(d[key] == current_presents, "Draw/Present call count differs: " + key)
    for key in ("create_swapchain_calls", "get_buffer_calls", "create_rtv_calls",
                "create_vs_calls", "create_ps_calls", "create_rasterizer_calls",
                "clear_state_calls", "flush_calls"):
        require(d[key] == 1, "graphics lifecycle count differs: " + key)
    require(d["created"] == d["guest_released"] == d["release_calls"] == 8,
            "guest graphics ownership is incomplete")
    require(all(d[k] == 0 for k in ("live_objects", "active_maps", "cleanup_releases",
                "cleanup_unmaps", "cleanup_clear_state_calls", "cleanup_flush_calls")),
            "host cleanup masked guest graphics leak")
    require(d == r["d3d_after_cleanup"] and r["d3d_cleanup_result"] == 0,
            "terminal cleanup changed graphics ownership")
    for h in (host, r["host_after_finish"]):
        require(h["windows_created"] == h["windows_destroyed"] == 1 and
                h["views_created"] == h["views_released"] == 1 and
                h["active_views"] == h["forced_cleanup_windows"] == h["queue_overflows"] == 0,
                "native window/view lifecycle differs")
    user = r["user32_stats"]
    require(user["classes_registered"] == user["classes_unregistered"] == 1 and
            user["windows_created"] == user["windows_destroyed"] == 1 and
            user["registered"] == 0 and user["window_state"] == 4,
            "guest User32 lifecycle incomplete")
    for signature in (201, 210, 211, 213, 215, 217, 218, 219, 220, 221):
        index = 0 if signature == 201 else signature - 209
        require(user["api_calls"][index] == 1, "User32 API count differs: " + str(signature))
    require(user["api_calls"][222 - 209] == observations["paints"],
            "paint validation count differs")
    callbacks = r["callback_stats"]
    require(callbacks["calls"] == callbacks["returns"] and callbacks["calls"] > 0 and
            callbacks["rejections"] == callbacks["depth"] == callbacks["end_status"] == 0,
            "callback completion differs")
    return {"position": position, "moves": moves, "persisted_draws": draws,
            "initial_position": initial[2], "initial_moves": initial[3], "initial_draws": initial_draws,
            "current_moves": current_moves, "current_presents": current_presents,
            "load_observations": load, "restored": before_bytes is not None,
            "file_api_calls": expected_calls, "bytes_read": files["bytes_read"], "last_error": files["last_error"],
            "keydowns": keydowns, "ignored_repeats": repeats,
            "paint_messages": observations["paints"], "steps": r["steps"],
            "saved_bytes": len(state_bytes), "guest_released_objects": 8,
            "real_keyboard_events": host["cocoa_key_events"], "test_queue_events": len(sequence),
            "scope": "same original save/load PE with long TEST_QUEUE trace and historical snapshots; no pixel/physical-key/performance acceptance"}

