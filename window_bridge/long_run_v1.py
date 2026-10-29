"""Supervised bounded duration experiment. Read-only by default; --run is explicit.

TEST_QUEUE events are not physical keyboard input. A ten-second smoke result
cannot be accepted as thirty minutes. No pixel or throughput claim is made.
"""
from __future__ import annotations
import argparse,json,re,subprocess,time
from pathlib import Path
from window_bridge import long_run_bindings_v1 as producer
from window_bridge import long_validation_v1 as validation
from graphics_stage5 import d3d11_probe as g

FORMAL_STATUS='PASS_AT_LEAST_30_MINUTES_TEST_QUEUE_ACTIVITY'
SMOKE_STATUS='PASS_10_SECOND_SMOKE_NOT_SUSTAINED'


def require(x,m):
    if not x:raise ValueError(m)


def write(path,value):
    with Path(path).open('x') as stream:json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')


def inputs(p):
    return {**p.build_manifest['inputs_before'],**p.build_manifest['artifacts'],
            **g.hashes([p.out/'program-build.json',__file__,validation.__file__])}


def expected_start(out,p,duration,smoke,initial):
    require(type(smoke) is bool and type(duration) is int,'explicit mode/duration types')
    command=p.command(io_directory=out/'data',duration_ms=duration,smoke=smoke,budget=100000000)
    return {'status':'STARTED_NOT_ACCEPTED','program':str(p.out),'duration_ms':duration,'smoke':smoke,
            'command':command,'environment':g.environment(out,images=True),'inputs_before':inputs(p),
            'external_timeout_seconds':60 if smoke else 2160,'budget':100000000,
            'before_hex':None if initial is None else initial.hex(),'initial_data_files':[] if initial is None else ['integer-tile.bin'],
            'scope':'same save/load Windows PE; paced TEST_QUEUE, no physical key/pixel/performance acceptance'}


def validate(out,record):
    out=Path(out).resolve();start=g.read_json(out/'started.json')
    require(record['started_sha256']==g.sha(out/'started.json'),'immutable start differs')
    p=producer.Program.from_build(start['program']);before=None if start['before_hex'] is None else bytes.fromhex(start['before_hex'])
    require(before is None or len(before)==20,'initial snapshot width differs')
    if before is not None:require((out/'initial-save.bin').read_bytes()==before,'historical initial snapshot differs')
    else:require(not (out/'initial-save.bin').exists(),'unexpected initial snapshot')
    require(start==expected_start(out,p,start['duration_ms'],start['smoke'],before),'recorded inputs/config/command differ')
    g.same(start['inputs_before'])
    require(record['external_timeout'] is False and type(record['returncode']) is int and type(record['pid']) is int and record['pid']>0,'actual child failed or not observed')
    require(type(record['supervisor_begin_ns']) is int and type(record['supervisor_end_ns']) is int and 0<record['supervisor_begin_ns']<record['supervisor_end_ns'],'supervisor clock ordering differs')
    data=out/'data';require(data.is_dir() and not data.is_symlink() and {x.name for x in data.iterdir()}=={'integer-tile.bin'},'actual data file set differs')
    require(g.read_json(out/'launched.json')=={'status':'PROCESS_LAUNCHED_NOT_ACCEPTED','pid':record['pid'],'supervisor_begin_ns':record['supervisor_begin_ns'],'started_sha256':record['started_sha256'],'external_timeout_seconds':start['external_timeout_seconds']},'actual launch identity differs')
    paths=[out/'started.json',out/'attempt.json',out/'launched.json',out/'run.stdout',out/'run.stderr',data/'integer-tile.bin']
    if before is not None:paths.append(out/'initial-save.bin')
    for path in paths:require(path.is_file() and not path.is_symlink(),'regular captured artifact required')
    artifacts=g.hashes(paths)
    require((out/'run.stdout').stat().st_size<=4*1024*1024 and (out/'run.stderr').stat().st_size<=4*1024*1024,'captured output exceeds bounded profile')
    result=g.strict_json((out/'run.stdout').read_text());stderr=(out/'run.stderr').read_text()
    timing=p.validate_execution(result,record['returncode'],None,start['budget'])
    expected_timing='SMOKE_TIMING_OBSERVED_NOT_SUSTAINED_ACCEPTANCE' if start['smoke'] else 'FORMAL_TIMING_OBSERVED_REQUIRES_GAME_AND_ARTIFACT_ACCEPTANCE'
    require(timing['status']==expected_timing and result['long_run']['duration_ms']==start['duration_ms'] and timing['smoke'] is start['smoke'],'actual duration mode/incomplete activity differs')
    long=result['long_run'];require(record['supervisor_begin_ns']<=long['start_ns']<=long['finish_ns']<=record['supervisor_end_ns'],'native monotonic timestamps fall outside supervisor')
    require(record['supervisor_end_ns']-record['supervisor_begin_ns']<=start['external_timeout_seconds']*1000000000,'supervisor limit exceeded')
    sequence=[x['name'] for x in result['test_queue']['events']]
    gameplay=validation.semantic_acceptance_long({'result':result,'returncode':record['returncode'],'test_sequence':sequence,'external_timeout':False},before,(data/'integer-tile.bin').read_bytes())
    # Queue STOPPED is the successful terminal state, not a message failure.
    for h in ('host_before_finish','host_after_finish'):
        require(result[h]['error']==1 and result[h]['stopped']==1,'native queue did not finish STOPPED')
    require(result['host_finished'] and not result['join_status'],'actual worker/main completion differs')
    loaded=g.loaded_images(stderr,p.executable,p.build_manifest['library_graph']['nodes'])
    require(set(map(int,re.findall(r'^dyld\[(\d+)\]:',stderr,re.M)))=={record['pid']},'dyld records do not belong to actual child')
    require(g.read_json(out/'attempt.json')=={'status':'PREFLIGHT_NOT_EXECUTED','driver_sha256':g.sha(__file__),'program':str(p.out),'smoke':start['smoke'],'duration_ms':start['duration_ms']},'attempt identity differs')
    g.same(artifacts);g.same(start['inputs_before'])
    return {'result':result,'timing':timing,'gameplay':gameplay,'loaded_images':loaded,'artifacts':artifacts,
            'inputs_after':g.hashes(start['inputs_before']),'supervisor_elapsed_ns':record['supervisor_end_ns']-record['supervisor_begin_ns']}


def verify(out):
    out=Path(out).resolve();record=g.read_json(out/'evidence.json');start=g.read_json(out/'started.json')
    expected=SMOKE_STATUS if start['smoke'] is True else FORMAL_STATUS
    require(record['status']==expected,'run has no accepted exact mode')
    actual=validate(out,record);require(all(record[k]==v for k,v in actual.items()),'record differs from actual sources/stdio/trace/save')
    return {'status':expected,'timing':actual['timing'],'gameplay':actual['gameplay'],'new_guest_executions':0}


def run(out,program,duration,smoke,initial_path=None):
    out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
    write(out/'attempt.json',{'status':'PREFLIGHT_NOT_EXECUTED','driver_sha256':g.sha(__file__),'program':str(Path(program).resolve()),'smoke':smoke,'duration_ms':duration})
    record={'status':'NOT_EXECUTED'}
    try:
        p=producer.Program.from_build(program);data=out/'data';data.mkdir();before=None
        if initial_path is not None:
            initial=Path(initial_path).resolve();require(initial.is_file() and not initial.is_symlink(),'regular initial save required')
            before=initial.read_bytes();require(len(before)==20,'initial save must be 20 bytes')
            magic,version,pos,_,_=validation.struct.unpack('<5I',before);require((magic,version)==(0x31574F43,1) and pos<=7,'initial save must be valid for successful restore')
            (out/'initial-save.bin').write_bytes(before);(data/'integer-tile.bin').write_bytes(before)
        start=expected_start(out,p,duration,smoke,before);write(out/'started.json',start)
        record={'status':'STARTED_NOT_ACCEPTED','started_sha256':g.sha(out/'started.json')}
        # Output goes directly to bounded-observation files; no long-lived pipe
        # can fill and deadlock the native worker. Validate size before parsing.
        with (out/'run.stdout').open('x') as stdout,(out/'run.stderr').open('x') as stderr:
            record['supervisor_begin_ns']=time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            child=subprocess.Popen(start['command'],env=start['environment'],stdout=stdout,stderr=stderr)
            record['pid']=child.pid;timeout=False
            write(out/'launched.json',{'status':'PROCESS_LAUNCHED_NOT_ACCEPTED','pid':child.pid,'supervisor_begin_ns':record['supervisor_begin_ns'],'started_sha256':record['started_sha256'],'external_timeout_seconds':start['external_timeout_seconds']})
            try:child.wait(timeout=start['external_timeout_seconds'])
            except subprocess.TimeoutExpired:
                timeout=True;child.terminate()
                try:child.wait(timeout=3)
                except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
            record.update(returncode=child.returncode,external_timeout=timeout,supervisor_end_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        actual=validate(out,record);write(out/'observed.json',{**record,**actual,'status':'OBSERVED_NOT_ACCEPTED'})
        record.update(actual,status=SMOKE_STATUS if smoke else FORMAL_STATUS)
        # PASS is written only after command, mode, all 8192-or-fewer actual
        # events, full source/object identities, save and teardown are checked.
        write(out/'evidence.json',record)
        print(json.dumps({'status':record['status'],'pid':record['pid'],'timing':actual['timing'],'gameplay':actual['gameplay']},ensure_ascii=False),flush=True)
    except Exception as error:
        write(out/'failure.json',{**record,'status':'FAIL_PRESERVED','error':str(error)});raise

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--program',type=Path,default=producer.OUT)
    parser.add_argument('--duration-ms',type=int);parser.add_argument('--smoke',action='store_true');parser.add_argument('--initial-save',type=Path);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if args.run:run(args.out,args.program,args.duration_ms if args.duration_ms is not None else (10000 if args.smoke else 1800000),args.smoke,args.initial_save)
    else:print(json.dumps(verify(args.out),ensure_ascii=False))
