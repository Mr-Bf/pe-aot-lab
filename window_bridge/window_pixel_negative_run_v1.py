"""Supervised real skip-Draw negative; defaults to read-only verification.

An expected failure of the full tile-image predicate is accepted only after
actual clean guest/capture execution and a complete exact-background check.
This module is not a mock renderer and never modifies guest state or shaders.
"""
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess

from window_bridge import negative_pixel_bindings_v1 as producer
from window_bridge import window_bindings as binding
from window_bridge import window_pixels_v1 as pixels

SEQUENCE=['escape']
STATUS='PASS_EXPECTED_PIXEL_REJECTION'
RESULT_FIELDS=('stage','exit_code','create_messages','keydowns','ignored_repeats','paints',
               'closes','destroys','presents','saves','saved_bytes','win32_error','graphics_hr','quit_requested','dirty')


def require(value,reason):
    if not value:raise ValueError(reason)


def write(path,record):
    with Path(path).open('x') as stream:json.dump(record,stream,indent=2,sort_keys=True);stream.write('\n')


def output(path):
    path=Path(path).absolute()
    require(path==path.resolve() and path.parent==binding.ROOT/'build/window-bridge' and path.name.startswith('window-pixel-negative-'),
            'separate window-pixel-negative-* output directory required')
    return path


def inputs(program):
    # The negative supervisor and independent pixel predicate are additional
    # consumers, not part of the frozen executable build's source closure.
    return {**program.build_manifest['inputs_before'],**program.build_manifest['artifacts'],
            **binding.snapshot([program.out/'program-build.json',__file__,pixels.__file__])}


def background_frames(directory,count):
    """Every raw channel, exact RGBA (32,32,32,255); no center-only shortcut."""
    require(type(count) is int and 1<=count<=64,'invalid captured frame count')
    reports=[]
    for frame in range(1,count+1):
        raw=(directory/f'frame-{frame:06d}.rgba').read_bytes()
        require(len(raw)==640*360*4,'incomplete background frame')
        bad_channels=bad_pixels=maximum=0;previous=-1;first=[]
        for index,actual in enumerate(raw):
            expected=pixels.BACKGROUND[index%4];difference=abs(actual-expected)
            maximum=max(maximum,difference)
            if difference:
                bad_channels+=1;pixel=index//4
                if pixel!=previous:bad_pixels+=1;previous=pixel
                if len(first)<8:first.append({'x':pixel%640,'y':pixel//640,'channel':index%4,'actual':actual,'expected':expected})
        reports.append({'frame':frame,'checked_pixels':640*360,'checked_channels':len(raw),'tolerance_per_channel':0,
            'max_channel_error':maximum,'mismatched_pixels':bad_pixels,'mismatched_channels':bad_channels,
            'first_mismatches':first,'all_background':bad_channels==0})
    return {'status':'ALL_FRAMES_EXACT_BACKGROUND' if all(r['all_background'] for r in reports) else 'FAIL_EXACT_BACKGROUND',
            'expected_rgba':[32,32,32,255],'frames':reports,'checked_pixels':count*640*360,'checked_channels':count*640*360*4,
            'scope':'actual full pre-Present RGBA; no compositor/physical-input/performance claim'}


def observe(out,record):
    require((pixels.WIDTH,pixels.HEIGHT,pixels.BACKGROUND,pixels.GREEN,pixels.TOLERANCE)==
            (640,360,bytes((32,32,32,255)),bytes((0,255,0,255)),1),'independent pixel predicate contract changed')
    start=binding.graphics.read_json(out/'started.json')
    require(record['started_sha256']==binding.sha(out/'started.json'),'immutable start changed')
    require(start['status']=='STARTED_NEGATIVE_NOT_ACCEPTED','negative start status differs')
    program=producer.Program.from_build(Path(start['program']))
    require(start['inputs_before']==inputs(program),'negative source/object/consumer closure differs')
    binding.unchanged(start['inputs_before'])
    data=out/'data';capture_dir=out/'pixels'
    command=[str(program.executable),'--data-dir',str(data),'--pixel-dir',str(capture_dir),
             '--budget','1000000','--timeout-ms','45000','--test-sequence','escape']
    require(start['negative_pe_sha256']==producer.NEGATIVE_SHA and start['sequence']==SEQUENCE and
            start['command']==command and start['initial_data_files']==start['initial_pixel_files']==[],
            'fixed negative command/setup differs')
    require(start['environment']==binding.graphics.environment(out,images=True),'negative execution environment differs')
    require(record['external_timeout'] is False and type(record['returncode']) is int and record['returncode']==0 and
            type(record['pid']) is int and record['pid']>0,'negative did not complete as a clean actual child')
    # Bind bytes before parsing/comparing them; recheck all artifacts after the
    # complete image walk and again before accepting gameplay/cleanup evidence.
    io_before=binding.snapshot([out/'run.stdout',out/'run.stderr',data/'integer-tile.bin'])
    stdout=(out/'run.stdout').read_text();stderr=(out/'run.stderr').read_text()
    result=binding.graphics.strict_json(stdout)
    normal=program.validate_execution(result,record['returncode'],None,1000000)
    require(normal is not None,'negative host setup failed')
    capture=program.validate_capture(result,capture_dir)
    loaded=binding.graphics.loaded_images(stderr,program.executable,program.build_manifest['library_graph']['nodes'])
    require(set(map(int,re.findall(r'^dyld\[(\d+)\]:',stderr,re.M)))=={record['pid']},'actual dyld/child PID differs')
    # No gameplay/Draw-count rejection may run before these full image reads.
    image_report=pixels.inspect_frames(capture_dir,capture['frames'],SEQUENCE)
    background=background_frames(capture_dir,capture['frames'])
    artifacts={**capture['artifacts'],**io_before}
    binding.unchanged(artifacts);binding.unchanged(start['inputs_before'])
    return {'result':result,'normal_result':normal,'capture':capture,'pixels':image_report,'background':background,
            'loaded_images':loaded,'artifacts':artifacts}


def accept_negative(actual,out,record):
    """Full pixel failure first; gameplay counters are additional evidence."""
    image=actual['pixels'];background=actual['background'];count=actual['capture']['frames']
    require(image['status']=='FAIL_FULL_RGBA_SCENE' and image['expected_positions']==[3] and
            image['observed_position_transitions']==[None],'tile predicate did not fail in the expected missing-tile form')
    require(len(image['frames'])==count and image['checked_pixels']==count*640*360 and
            image['checked_channels']==count*640*360*4,'incomplete actual tile comparison')
    for index,frame in enumerate(image['frames'],1):
        require(frame['frame']==index and frame['expected_position']==3 and frame['observed_position'] is None and
                frame['center_candidates']==[] and frame['matches'] is False and frame['checked_pixels']==640*360 and
                frame['checked_channels']==640*360*4 and frame['mismatched_pixels']==6400 and
                frame['mismatched_channels']==19200,'wrong full-frame missing-tile mismatch evidence')
    require(background['status']=='ALL_FRAMES_EXACT_BACKGROUND' and background['expected_rgba']==[32,32,32,255] and
            len(background['frames'])==count and all(f['all_background'] is True and f['mismatched_pixels']==0 and
                f['mismatched_channels']==0 and f['checked_pixels']==640*360 and f['checked_channels']==640*360*4
                for f in background['frames']),'negative frame is not entirely the actual expected background')
    r=actual['normal_result']
    require(r['pe_sha256']==producer.NEGATIVE_SHA and r['outcome']=='PROCESS_EXITED' and r['proc_translated']==0 and
            r['exit_requested']==1 and r['exit_code']==0 and r['fault']['status']==0 and r['returned']==0 and
            r['steps']>0 and r['entry_arguments']==0 and not r['timed_out'] and record['external_timeout'] is False,
            'negative PE entry/exit/ISA/fault differs')
    queue=r['test_queue']
    require(queue['posted']==queue['requested']==1 and queue['injection_error']==0 and
            [e['name'] for e in queue['events']]==SEQUENCE and all(e['origin']==3 for e in queue['events']),
            'negative TEST_QUEUE workload differs')
    host=r['host_before_finish']
    require(host['cocoa_key_events']==0 and host['test_queue_events']==1,'real input contaminated negative workload')
    state=bytes.fromhex(r['observations']['window_state'])
    require(len(state)==20,'negative state layout differs')
    magic,version,position,moves,draws=struct.unpack('<5I',state)
    require((magic,version,position,moves)==(0x31574f43,1,3,0) and draws==count and draws>0,
            'negative state or retained frame counter differs')
    raw_result=bytes.fromhex(r['observations']['window_result']);require(len(raw_result)==60,'negative observation layout differs')
    observed=dict(zip(RESULT_FIELDS,struct.unpack('<15I',raw_result)))
    expected={'stage':5,'exit_code':0,'create_messages':2,'keydowns':1,'ignored_repeats':0,
              'closes':0,'destroys':1,'presents':draws,'saves':1,'saved_bytes':20,'win32_error':0,
              'graphics_hr':0,'quit_requested':1,'dirty':0}
    require(all(observed[k]==v for k,v in expected.items()),'negative guest observation counters differ')
    require(bytes.fromhex(r['observations']['window_handle'])==bytes(8) and
            bytes.fromhex(r['observations']['window_feature'])==struct.pack('<I',0xb000) and
            bytes.fromhex(r['observations']['window_client'])==struct.pack('<4i',0,0,640,360),
            'negative guest window/feature/client endpoint differs')
    saved=r['saved_file'];disk=out/'data/integer-tile.bin'
    require(saved['name']=='integer-tile.bin' and saved['errno']==0 and saved['truncated'] is False and
            saved['data_hex']==state.hex() and disk.is_file() and not disk.is_symlink() and disk.read_bytes()==state,
            'negative actual disk save differs from retained state')
    files=r['files']
    require(files['api_calls_4_to_9']==[1,1,0,1,0,0] and files['bytes_written']==20 and files['bytes_read']==0 and
            all(files[k]==0 for k in ('last_error','open_before_cleanup','open_after_cleanup','cleanup_closes','cleanup_errors')),
            'negative file API/cleanup differs')
    d=r['d3d_before_cleanup']
    require(d['draw_calls']==0 and d['exit_calls']==1,'negative executed Draw or wrong ExitProcess count')
    for name in ('clear_calls','om_set_calls','rs_set_calls','viewport_calls','topology_calls','vs_set_calls','ps_set_calls','present_calls'):
        require(d[name]==draws,'negative retained graphics call count differs: '+name)
    for name in ('create_swapchain_calls','get_buffer_calls','create_rtv_calls','create_vs_calls','create_ps_calls','create_rasterizer_calls','clear_state_calls','flush_calls'):
        require(d[name]==1,'negative graphics lifecycle differs: '+name)
    require(d['created']==d['guest_released']==d['release_calls']==8 and
            all(d[k]==0 for k in ('live_objects','active_maps','cleanup_releases','cleanup_unmaps','cleanup_clear_state_calls','cleanup_flush_calls')),
            'negative guest reference cleanup is incomplete')
    require(d==r['d3d_after_cleanup'] and r['d3d_cleanup_result']==0,'host cleanup masked negative graphics ownership')
    for h in (host,r['host_after_finish']):
        require(h['windows_created']==h['windows_destroyed']==1 and h['views_created']==h['views_released']==1 and
                all(h[k]==0 for k in ('active_views','forced_cleanup_windows','queue_overflows')) and
                h['stopped']==1 and h['error']==1,  # WB_HOST_ERROR_STOPPED after normal queue shutdown.
                'negative native window/view cleanup differs')
    user=r['user32_stats']
    require(user['classes_registered']==user['classes_unregistered']==1 and user['windows_created']==user['windows_destroyed']==1 and
            user['registered']==0 and user['window_state']==4 and r['user32_end_status']==0,'negative User32 lifecycle differs')
    for signature in (201,210,211,213,215,217,218,219,220,221):
        require(user['api_calls'][0 if signature==201 else signature-209]==1,'negative User32 call count differs')
    require(user['api_calls'][222-209]==observed['paints'],'negative paint/ValidateRect differs')
    callbacks=r['callback_stats']
    require(callbacks['calls']==callbacks['returns'] and callbacks['calls']>0 and
            all(callbacks[k]==0 for k in ('rejections','depth','end_status')),'negative callback completion differs')
    binding.unchanged(actual['artifacts'])
    return {'status':STATUS,'negative_pe_sha256':producer.NEGATIVE_SHA,'frames':count,
            'tile_predicate':'FAIL_FULL_RGBA_SCENE','background_predicate':'ALL_FRAMES_EXACT_BACKGROUND',
            'mismatched_tile_pixels_per_frame':6400,'mismatched_tile_channels_per_frame':19200,
            'draw_calls':0,'clear_calls':draws,'present_calls':draws,'game_draw_counter':draws,
            'position':position,'moves':moves,'saved_bytes':20,'guest_released_objects':8,'steps':r['steps'],
            'scope':'new self-authored skip-Draw PE; actual full pixel negative; not failure of unchanged positive PE or a performance sample'}


def verify(path):
    out=output(path);record=binding.graphics.read_json(out/'evidence.json')
    require(record['status']==STATUS,'negative not accepted as expected pixel rejection')
    actual=observe(out,record)
    require(all(record[k]==v for k,v in actual.items()),'negative record differs from actual artifacts')
    summary=accept_negative(actual,out,record);require(record['acceptance']==summary,'negative acceptance differs')
    start=binding.graphics.read_json(out/'started.json');binding.unchanged(start['inputs_before']);binding.unchanged(actual['artifacts'])
    return {**summary,'new_guest_executions':0}


def run(path,program_directory=producer.OUT):
    out=output(path);out.mkdir(parents=True,exist_ok=False)
    write(out/'attempt.json',{'status':'NEGATIVE_PREFLIGHT_NOT_EXECUTED','program':str(Path(program_directory).resolve()),
                            'driver_sha256':binding.sha(__file__)})
    record={'status':'NOT_EXECUTED'}
    try:
        program=producer.Program.from_build(program_directory)
        data=out/'data';capture=out/'pixels';data.mkdir();capture.mkdir()
        command=[str(program.executable),'--data-dir',str(data),'--pixel-dir',str(capture),
                 '--budget','1000000','--timeout-ms','45000','--test-sequence','escape']
        env=binding.graphics.environment(out,images=True)
        start={'status':'STARTED_NEGATIVE_NOT_ACCEPTED','program':str(program.out),'negative_pe_sha256':producer.NEGATIVE_SHA,
               'sequence':SEQUENCE,'command':command,'environment':env,'inputs_before':inputs(program),
               'initial_data_files':[],'initial_pixel_files':[],
               'scope':'one real new skip-Draw PE; TEST_QUEUE; expected full-pixel rejection still requires actual evidence'}
        write(out/'started.json',start)
        record={'status':'STARTED_NEGATIVE_NOT_ACCEPTED','started_sha256':binding.sha(out/'started.json')}
        child=subprocess.Popen(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);record['pid']=child.pid
        timeout=False
        try:stdout,stderr=child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            timeout=True;child.terminate()
            try:stdout,stderr=child.communicate(timeout=3)
            except subprocess.TimeoutExpired:child.kill();stdout,stderr=child.communicate(timeout=3)
        (out/'run.stdout').write_text(stdout);(out/'run.stderr').write_text(stderr)
        record.update(returncode=child.returncode,external_timeout=timeout)
        actual=observe(out,record)
        write(out/'observed.json',{**record,**actual,'status':'NEGATIVE_OBSERVED_NOT_ACCEPTED'})
        summary=accept_negative(actual,out,record)
        binding.unchanged(start['inputs_before']);binding.unchanged(actual['artifacts'])
        record.update(actual);record['acceptance']=summary;record['status']=STATUS
        write(out/'evidence.json',record)
        print(json.dumps(summary,ensure_ascii=False),flush=True)
    except Exception as error:
        write(out/'failure.json',{**record,'status':'FAIL_PRESERVED_NOT_EXPECTED_PIXEL_ACCEPTANCE','error':str(error)})
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--program',type=Path,default=producer.OUT);parser.add_argument('--run',action='store_true');args=parser.parse_args()
    if args.run:run(args.out,args.program)
    else:print(json.dumps(verify(args.out),ensure_ascii=False))
