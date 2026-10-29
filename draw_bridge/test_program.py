#!/usr/bin/env python3
"""Build-only gates or explicitly requested real D3D11 guest execution.

No implicit GPU execution: --build-only compiles/links; --run-existing launches
one already-built program; --verify only rechecks recorded identities/results.
No exhaustive 1..N loop-budget sweep and no game/performance claim.
"""
import argparse
import copy
import json
from pathlib import Path
import struct
import sys
import traceback

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from draw_bridge.bindings import Program,sha,snapshot,unchanged,output_directory,generate_headers,verify_lift,verify_run
from draw_bridge import fixtures
from graphics_stage5 import d3d11_probe as graphics

FIXTURES=ROOT/'build/draw-bridge/fixtures'
BASELINE=ROOT/'build/draw-bridge/first-native-run/evidence.json'
REFERENCE_STEPS=39415


def require(value,message):
    if not value:raise RuntimeError(message)


def metadata():
    fixtures.verify(FIXTURES)
    return graphics.read_json(FIXTURES/'manifest.json')['draw_readback']


def read_result(result,meta):
    raw=bytes.fromhex(result['observations']['graphics_result'])
    require(len(raw)==4*len(meta['result_fields']),'guest graphics result width differs')
    return dict(zip(meta['result_fields'],struct.unpack('<%dI'%len(meta['result_fields']),raw)))


def check_shared(result,meta):
    require(result['entry_arguments']==0 and result['entry_rva']==meta['entry_rva'],'wrong no-argument PE entry')
    observations=result['observations']
    require(observations['graphics_after_exit']=='00000000','post-ExitProcess marker executed')
    anchor=meta['observations']['graphics_image_anchor']
    require(int.from_bytes(bytes.fromhex(observations['graphics_image_anchor']),'little')==result['image_base']+anchor['target_rva'],
            'static DIR64 anchor not rebased')
    before=result['d3d_before_cleanup'];after=result['d3d_after_cleanup']
    require(after['live_objects']==0 and after['active_maps']==0,'application objects/maps survive cleanup')
    require(before['created']==before['guest_released']+before['cleanup_releases']+before['live_objects'],
            'pre-cleanup application-reference accounting differs')
    require(after['created']==after['guest_released']+after['cleanup_releases'],
            'post-cleanup application-reference accounting differs')
    require(result['d3d_cleanup_result']==after['cleanup_releases']-before['cleanup_releases'],
            'cleanup return count differs from cleanup counters')
    for field in before:
        if field not in ('cleanup_releases','cleanup_unmaps','live_objects','active_maps','last_native_release'):
            require(after[field]==before[field],'cleanup fabricated guest counter: '+field)
    return read_result(result,meta)


def check_normal(result,meta):
    require(result['outcome']=='PROCESS_EXITED' and result['aot_status']==11 and result['host_returncode']==0,
            'guest did not explicitly exit')
    require(result['exit_requested']==1 and result['exit_code']==0 and result['returned']==0 and result['fault']['status']==0,
            'ExitProcess / RET / fault distinction failed')
    require(result['exit_pc']==result['rip'] and result['exit_rsp']==result['rsp'] and
            result['exit_depth']==result['call_depth']>=1,'real committed ExitProcess CALL state not retained')
    fields=check_shared(result,meta)
    for key,value in {'stage':11,'feature_level':0xb000,'create_device_hr':0,'create_target_hr':0,
                      'create_rtv_hr':0,'create_staging_hr':0,'map_hr':0,'device_removed_hr':0,
                      'pixels_checked':1024,'channels_checked':4096,'mismatched_pixels':0,'mismatched_channels':0,
                      'clear_called':1,'copy_called':1,'unmap_called':1,'released_objects':8,'exit_code':0,
                      'create_vs_hr':0,'create_ps_hr':0,'create_rasterizer_hr':0,'draw_called':1}.items():
        require(fields[key]==value,'guest pixel/API observation differs: '+key)
    require(fields['row_pitch']>=128 and fields['max_error']<=1,'mapped row pitch/pixel tolerance differs')
    expected={'create_device_calls':1,'create_texture_calls':2,'create_rtv_calls':1,'clear_calls':1,
              'copy_calls':1,'map_calls':1,'unmap_calls':1,'get_removed_calls':1,
              'create_vs_calls':1,'create_ps_calls':1,'create_rasterizer_calls':1,'om_set_calls':1,
              'rs_set_calls':1,'viewport_calls':1,'topology_calls':1,'vs_set_calls':1,'ps_set_calls':1,'draw_calls':1,'release_calls':8,
              'exit_calls':1,'this_checks':26,'created':8,'guest_released':8,'cleanup_releases':0,
              'cleanup_unmaps':0,'map_bytes_copied':4096,'map_postcall_failures':0,'live_objects':0,'active_maps':0}
    for name,value in expected.items():
        require(result['d3d_before_cleanup'][name]==value and result['d3d_after_cleanup'][name]==value,
                'actual D3D lifecycle counter differs: '+name)
    require(result['d3d_cleanup_result']==0,'successful guest required residual host cleanup')
    mapped=bytes.fromhex(result['observations']['graphics_mapped'])
    pointer,row_pitch,depth_pitch=struct.unpack('<QII',mapped)
    require(0x61000000<=pointer<0x61100000 and row_pitch==fields['row_pitch'] and depth_pitch==fields['depth_pitch'],
            'mapped guest descriptor does not identify the guest readback arena')
    require(type(result['steps']) is int and result['steps']==REFERENCE_STEPS,'normal instruction count differs from first real baseline')
    return fields


def check_budget(result,meta,budget):
    require(type(budget) is int and budget>0,'budget expectation needs a positive budget')
    require(result['outcome']=='FAULT' and result['aot_status']==4 and result['fault']['status']==4 and
            result['host_returncode']==3 and result['steps']==budget,'budget did not stop at exact instruction boundary')
    require(result['exit_requested']==0 and result['returned']==0 and
            all(result[key]==0 for key in ('exit_code','exit_pc','exit_rsp','exit_depth')),'budget fabricated process exit')
    fields=check_shared(result,meta)
    require(result['d3d_before_cleanup']['exit_calls']==0,'budget prefix invoked ExitProcess')
    before=result['d3d_before_cleanup'];after=result['d3d_after_cleanup']
    if budget==19:
        require(all(value==0 for value in before.values()) and after==before,'pre-Create budget produced a native API effect')
    elif budget==21:
        require(before['create_device_calls']==1 and before['created']==2 and before['live_objects']==2 and
                before['this_checks']==0 and before['guest_released']==0 and before['cleanup_releases']==0,
                'completed CreateDevice/RET effects did not survive next-instruction budget stop')
        require(after['cleanup_releases']==2 and result['d3d_cleanup_result']==2,'CreateDevice residual references not cleaned')
    elif budget==REFERENCE_STEPS-1:
        require(before['created']==before['guest_released']==8 and before['release_calls']==8 and
                before['live_objects']==0 and before['active_maps']==0 and after['cleanup_releases']==0,
                'pre-Exit budget lost completed GPU/release effects')
    return fields


def metadata_gates(program,out):
    """Pure rejection checks. No executable or dynamic library is launched."""
    records=[]
    def reject(name,operation):
        try:operation()
        except ValueError as error:records.append({'name':name,'status':'EXPECTED_REJECT','error':str(error)})
        else:raise RuntimeError('metadata gate accepted: '+name)
    for profile in ('d3d11-bridge','com-bridge','process-bridge','file-bridge','callback-bridge','native-bridge','integration-stage3'):
        reject('old-profile-'+profile,lambda profile=profile:output_directory(ROOT/'build'/profile/'must-not-write'))
    for label,field,value in [('global-signature','method_signature',110),('legacy-signature','signature',110),
                              ('queryinterface-slot','slot',0),('rsp-base','base_reg','RSP'),
                              ('unaligned-slot','displacement',41),('static-target','target_rva',1)]:
        fake=copy.copy(program);fake.manifest=copy.deepcopy(program.manifest)
        row=next(i for i in fake.manifest['instructions'] if i['kind']==3);row[field]=value
        fake.out=out/'metadata-gates'/label;fake.out.mkdir(parents=True,exist_ok=True)
        meta=graphics.read_json(program.out/'fixture-metadata.json')
        reject(label,lambda fake=fake:generate_headers(fake,meta))
    # Exercise the exact required source set using a private copy of the actual
    # manifest/artifacts. No original build objects are temporarily altered.
    import shutil
    directory=out/'metadata-gates/source-omission';directory.mkdir(parents=True,exist_ok=True)
    altered=copy.deepcopy(program.manifest)
    for name in altered['artifact_sha256']:shutil.copy2(program.out/'compiler'/name,directory/name)
    altered['object']=str(directory/'arm64.o');altered['source_sha256'].pop('draw_bridge/lift.py')
    (directory/'manifest.json').write_text(json.dumps(altered))
    reject('producer-source-omission',lambda:verify_lift(directory,altered,program.source_sha256,'aot_entry'))
    return records


def verify_evidence(path):
    path=Path(path).resolve();record=graphics.read_json(path)
    require(record['status'] in ('PASS_BUILD_ONLY_NOT_EXECUTED','PASS_ACTUAL_PE_DRAW_NORMAL','PASS_ACTUAL_PE_BUDGET_PREFIX'),
            'program evidence not passing')
    unchanged(record['inputs_before']);unchanged(record['artifacts'])
    require(record['inputs_before']==record['inputs_after'],'test source changed during verification')
    program=Program.from_build(record['program_out'])
    require(sha(program.out/'program-build.json')==record['program_build_sha256'],'program build identity changed')
    if record['guest_executions']:
        require(record['guest_executions']==1 and record['run_evidence'],'wrong actual launch count')
        executed=verify_run(record['run_evidence'])
        result={**executed['result'],'host_returncode':executed['returncode']}
        require(result==record['raw_result'],'test summary differs from actual stdout')
        fields=check_normal(result,record['metadata']) if record['expectation']=='normal' else check_budget(result,record['metadata'],record['budget'])
        require(fields==record['guest_fields'],'decoded guest-result summary differs')
        require(record['create_device_calls']==result['d3d_before_cleanup']['create_device_calls'],
                'native CreateDevice count summary differs')
    else:
        require(record['status']=='PASS_BUILD_ONLY_NOT_EXECUTED' and len(record['metadata_rejections'])==14,'build-only gate count/scope differs')
    return record


def main(args):
    out=output_directory(args.out or ROOT/'build/draw-bridge/program-tests'/args.mode)
    out.mkdir(parents=True,exist_ok=True);evidence=out/'evidence.json'
    if args.verify:
        verified=verify_evidence(evidence)
        print(json.dumps({'status':verified['status'],'guest_executions':verified['guest_executions'],'evidence':str(evidence)}))
        return verified
    meta=metadata()
    adopted=verify_run(args.adopt_run) if args.adopt_run else None
    program_out=output_directory(args.program_out or (adopted['program_out'] if adopted else out/'program'))
    baseline=verify_run(BASELINE)
    require(baseline['result']['steps']==REFERENCE_STEPS and baseline['result']['pe_sha256']==meta['pe_sha256'],
            'first actual PE baseline identity/steps differ')
    inputs=snapshot([Path(__file__),ROOT/'draw_bridge/bindings.py',FIXTURES/'manifest.json',FIXTURES/'evidence.json',meta['pe_path'],
                     BASELINE,baseline['stdout_path'],baseline['stderr_path']])
    record={'schema':1,'status':'RUNNING_NOT_ACCEPTED','metadata':meta,'inputs_before':inputs,
            'program_out':str(program_out),'expectation':args.expect,'budget':args.budget,'guest_executions':0,
            'new_guest_launches':0,'baseline_evidence_sha256':sha(BASELINE),'reference_steps':REFERENCE_STEPS,
            'scope':'one self-authored no-argument D3D11 PE with fixed VS/PS and Draw; no window/game/performance claim'}
    graphics.save(evidence,record)
    try:
        if args.build_only:
            program=Program(meta['pe_path'],program_out,optimization=args.mode,metadata=meta,
                            metadata_sources=[FIXTURES/'manifest.json',FIXTURES/'evidence.json'])
            program.verify_build()
            record['metadata_rejections']=metadata_gates(program,out)
            record['status']='PASS_BUILD_ONLY_NOT_EXECUTED'
            record['run_evidence']=None
        else:
            program=Program.from_build(program_out)
            require(program.optimization==args.mode,'selected mode differs from built program')
            if adopted:
                require(args.expect=='normal' and args.base is None and args.budget is None,'adopt only the unchanged normal run')
                result={**adopted['result'],'host_returncode':adopted['returncode']}
                record['run_evidence']=str(Path(args.adopt_run).resolve())
            else:
                record['new_guest_launches']=1
                result=program.run(base=args.base,budget=args.budget,log_path=out/'actual-run.json')
                record['run_evidence']=result.pop('run_evidence')
                result.pop('loaded_images');result.pop('actual_executable_sha256')
            record['guest_executions']=1
            record['raw_result']=result
            record['create_device_calls']=result.get('d3d_before_cleanup',{}).get('create_device_calls')
            record['guest_fields']=check_normal(result,meta) if args.expect=='normal' else check_budget(result,meta,args.budget)
            record['status']='PASS_ACTUAL_PE_DRAW_NORMAL' if args.expect=='normal' else 'PASS_ACTUAL_PE_BUDGET_PREFIX'
        record['program_build_sha256']=sha(program.out/'program-build.json')
        record['inputs_after']=snapshot(inputs);require(record['inputs_after']==inputs,'program test source changed')
        artifact_paths=[program.out/'program-build.json']
        if record['run_evidence']:artifact_paths.append(Path(record['run_evidence']))
        else:artifact_paths.extend(p for p in (out/'metadata-gates').rglob('*') if p.is_file())
        record['artifacts']=snapshot(artifact_paths)
        graphics.save(evidence,record);verify_evidence(evidence)
        print(json.dumps({'status':record['status'],'guest_executions':record['guest_executions'],
                          'new_guest_launches':record['new_guest_launches'],'create_device_calls':record.get('create_device_calls',0),'evidence':str(evidence),
                          'executable':str(program.executable)}));return record
    except Exception as error:
        record.update(status='FAIL_NOT_ACCEPTANCE',error=str(error),traceback=traceback.format_exc())
        graphics.save(evidence,record)
        if not (out/'first-failure.json').exists():graphics.save(out/'first-failure.json',record)
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser();actions=parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--build-only',action='store_true');actions.add_argument('--run-existing',action='store_true');actions.add_argument('--verify',action='store_true')
    actions.add_argument('--adopt-run',type=Path)
    parser.add_argument('--mode',choices=('O3','O0'),default='O3');parser.add_argument('--out',type=Path);parser.add_argument('--program-out',type=Path)
    parser.add_argument('--base',type=lambda value:int(value,0));parser.add_argument('--budget',type=lambda value:int(value,0))
    parser.add_argument('--expect',choices=('normal','budget'),default='normal');main(parser.parse_args())
