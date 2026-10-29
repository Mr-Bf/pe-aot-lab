#!/usr/bin/env python3
"""Native DXMT DXBC Draw v1: build, real GPU execution and read-only verification.

This profile imports frozen provenance/parser helpers, without monkeypatching
those modules. Shader compilation is a separate native build-time operation.
A successful no-Draw control is explicitly NOT successful triangle rendering.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from graphics_stage5 import d3d11_probe as base
from graphics_stage5 import build_shaders

ROOT, HERE, WORK = base.ROOT, base.HERE, base.WORK
OUT = ROOT / 'build/graphics-stage5/d3d11-draw-v1'
SOURCE = HERE / 'd3d11_draw_probe.cpp'
SOURCE_SHA = '0ad57822339f440ccfdeb95e06b9e4c6ba3542ba86641920b75c9d10db8b3f0d'
HELPER_SHA = '83b43032207870ec62e5a12b9b8491228d84d4efc93282135e213b4a0f6e7465'
SCOPE = 'native DXMT DXBC VS/PS Draw(3,0) plus complete readback; no window, PE, guest ABI or performance claim'
BUILD_STATUS = 'BUILT_NATIVE_DXBC_DRAW_NOT_EXECUTED'
require, sha, hashes, same = base.require, base.sha, base.hashes, base.same
strict_json, read_json, save = base.strict_json, base.read_json, base.save
uint = base.uint
WRAPPER_SHA = sha(__file__)
SHADER_PRODUCER_SHA = sha(build_shaders.__file__)


def output(path):
    path = Path(path).resolve()
    require(path.is_relative_to(OUT.resolve()), 'output must stay within ' + str(OUT))
    return path


def shader_proof():
    require(sha(__file__) == WRAPPER_SHA, 'loaded Draw wrapper source changed')
    require(sha(build_shaders.__file__) == SHADER_PRODUCER_SHA, 'loaded shader producer source changed')
    require(sha(base.__file__) == HELPER_SHA, 'frozen provenance helper changed')
    require(sha(SOURCE) == SOURCE_SHA, 'reviewed Draw source changed')
    try:
        value = build_shaders.verify_shaders()
    except FileNotFoundError as error:
        raise base.DependencyNotReady('shader build/provenance not ready: ' + str(error)) from error
    require(value['status'] == 'SHADERS_CURRENT_NOT_EXECUTED', 'shader producer not current')
    return value


def validate_result(result, exit_code, shaders, *, skip_draw=False):
    fields = {'schema', 'probe', 'status', 'failure_stage', 'scope', 'compile_arch', 'native_arm64',
              'translation', 'feature_level', 'feature_level_hex', 'hresult', 'clear_called',
              'copy_called', 'unmap_called', 'format', 'width', 'height', 'row_pitch', 'depth_pitch',
              'expected_rgba8', 'tolerance_per_channel', 'pixels_checked', 'channels_checked',
              'mismatched_pixels', 'mismatched_channels', 'max_absolute_error', 'first_mismatch',
              'released_application_objects', 'all_application_references_released',
              'skip_draw', 'draw_called', 'pipeline_bound', 'clear_state_called', 'vertex_count',
              'start_vertex', 'vertex_shader_bytes', 'pixel_shader_bytes', 'clear_rgba8', 'cull_mode',
              'topology', 'input_layout', 'vertex_buffers'}
    require(type(exit_code) is int and exit_code == (1 if skip_draw else 0), 'D3D11 probe did not exit successfully')
    require(isinstance(result, dict) and set(result) == fields, 'D3D11 result fields missing or unknown')
    require(result['status'] == ('FAIL' if skip_draw else 'PASS') and
            result['failure_stage'] == ('pixel_mismatch' if skip_draw else None), 'unexpected Draw result status')
    require(result['probe'] == 'native_dxmt_d3d11_dxbc_draw', 'unexpected D3D11 probe identity')
    require(result['scope'] == {'shader': True, 'triangle': True, 'window': False, 'guest': False}
            and all(type(v) is bool for v in result['scope'].values()), 'unexpected claimed graphics scope')
    require(result['compile_arch'] == 'arm64' and result['native_arm64'] is True, 'native ARM64 absent')
    for field, value in {'schema': 1, 'feature_level': 0xb000, 'width': 32, 'height': 32,
                         'tolerance_per_channel': 1, 'pixels_checked': 1024, 'channels_checked': 4096,
                         'mismatched_pixels': 1024 if skip_draw else 0,
                         'mismatched_channels': 3072 if skip_draw else 0,
                         'released_application_objects': 8, 'vertex_count': 0 if skip_draw else 3,
                         'start_vertex': 0, 'vertex_buffers': 0}.items():
        require(type(result[field]) is int and result[field] == value, 'D3D11 result mismatch: ' + field)
    require(result['feature_level_hex'] == '0xb000', 'feature level representation mismatch')
    require(result['format'] == 'R8G8B8A8_UNORM', 'unexpected texture format')
    require(result['expected_rgba8'] == [0, 255, 0, 255]
            and all(type(x) is int for x in result['expected_rgba8']), 'unexpected clear color')
    for field in ('clear_called', 'copy_called', 'unmap_called', 'all_application_references_released',
                  'pipeline_bound', 'clear_state_called'):
        require(result[field] is True, 'D3D11 operation/cleanup missing: ' + field)
    require(uint(result['row_pitch']) and result['row_pitch'] >= 128 and uint(result['depth_pitch']),
            'invalid mapping pitch')
    require(type(result['max_absolute_error']) is int and
            (result['max_absolute_error'] == 255 if skip_draw else uint(result['max_absolute_error'], 1)),
            'pixel error/control mismatch')
    require(result['first_mismatch'] == ({'x':0,'y':0,'channel':0,'expected':0,'actual':255}
            if skip_draw else None), 'unexpected first mismatch')
    if skip_draw:
        require(all(type(v) is int for v in result['first_mismatch'].values()), 'invalid mismatch integer types')
    require(result['skip_draw'] is skip_draw and result['draw_called'] is (not skip_draw), 'Draw/control mismatch')
    require(result['clear_rgba8'] == [255,0,255,255] and all(type(v) is int for v in result['clear_rgba8']),
            'clear color must differ from shader output')
    require(result['cull_mode'] == 'NONE' and result['topology'] == 'TRIANGLELIST'
            and result['input_layout'] is None, 'pipeline contract mismatch')
    for key, stage in (('vertex_shader_bytes','vs'), ('pixel_shader_bytes','ps')):
        require(type(result[key]) is int and result[key] == shaders['bytecode'][stage]['size'],
                'shader bytecode size mismatch')
    translation = result['translation']
    require(isinstance(translation, dict) and set(translation) ==
            {'sysctl_return', 'errno', 'raw_value', 'known', 'rosetta'}, 'translation fields mismatch')
    require(translation['known'] is True and translation['rosetta'] is False, 'native query unverified')
    require(all(type(translation[k]) is int for k in ('sysctl_return', 'errno', 'raw_value')),
            'invalid native query types')
    require(tuple(translation[k] for k in ('sysctl_return', 'errno', 'raw_value')) in
            ((0, 0, 0), (-1, 2, -1)), 'unexpected native sysctl result')
    results = result['hresult']
    require(isinstance(results, dict) and set(results) == {'D3D11CreateDevice', 'CreateTexture2D_render_target',
            'CreateRenderTargetView', 'CreateTexture2D_staging', 'Map', 'GetDeviceRemovedReason',
            'CreateVertexShader', 'CreatePixelShader', 'CreateRasterizerState'},
            'HRESULT operation set mismatch')
    for name, hr in results.items():
        require(isinstance(hr, dict) and set(hr) == {'signed', 'hex', 'succeeded'} and
                type(hr['signed']) is int and hr['signed'] == 0 and hr['hex'] == '0x00000000'
                and hr['succeeded'] is True, 'HRESULT not S_OK: ' + name)


def discover_inputs(config, out, discovered, *, write=False):
    shader = shader_proof()
    library, records, bound = base.provenance(config)
    cpp = base.flags(config, discovered)
    dependencies = {}
    for stem, source in [('probe', SOURCE), ('loadcheck', out / 'loadcheck.cpp')]:
        text = base.invoke([discovered['clang++'], *cpp, '-M', '-MT', 'probe', source],
                           base.environment(out), out / (stem + '-dependencies.log') if write else None)
        dependencies[stem] = text
        path = out / (stem + '.d')
        if write:
            path.write_text(text)
        else:
            require(path.read_text() == text, 'actual C++ dependency set changed: ' + stem)
    graph = base.library_graph(library, out / 'draw-probe', [library.parent])
    base.require_graph_provenance(graph, bound)
    paths = [Path(__file__), Path(base.__file__), base.SOURCE, SOURCE, Path(build_shaders.__file__),
             Path(shader['evidence']), out/'loadcheck.cpp', out/'probe.d', out/'loadcheck.d',
             *records, *(discovered[x] for x in ('clang++','ld','xcrun','python')), *graph['nodes'],
             *shader['inputs'], *shader['artifacts']]
    for text in dependencies.values():
        paths.extend(base.dependency_paths(text))
    require({SOURCE.resolve(), build_shaders.HEADER.resolve()}.issubset(
                set(base.dependency_paths(dependencies['probe']))), 'source/shader header missing from actual -M closure')
    return hashes(paths), graph, library, shader


def immutable_executable(path, stem):
    target = path.parent / (stem + '-' + sha(path))
    if target.exists():
        require(target.read_bytes() == path.read_bytes(), 'immutable executable collision')
        path.unlink()
    else:
        path.rename(target)
    return target


def artifact_paths(out, record):
    names = ('compile.log','loadcheck-compile.log','probe-dependencies.log','loadcheck-dependencies.log')
    return [out/name for name in names] + [Path(record[key]) for key in ('executable','loadcheck')]


def build(out=OUT):
    out = output(out)
    require(not (out/'build.json').exists(), 'recorded build exists; preserve it and use a fresh --out')
    out.mkdir(parents=True, exist_ok=True)
    (out/'cache/dxmt').mkdir(parents=True, exist_ok=True)
    config = {'dxmt_source': str((WORK/('sources/dxmt-'+base.DXMT)).resolve()),
              'dxmt_build': str((WORK/'dxmt-build').resolve())}
    initial = {'schema':1, 'status':'BUILD_STARTED_NOT_EXECUTED', 'scope':SCOPE,
               'config':config, 'wrapper_sha256':sha(__file__), 'source_sha256':sha(SOURCE)}
    save(out/'build-attempt.json', initial)
    try:
        shader_proof()
        base.provenance(config)
        (out/'loadcheck.cpp').write_text(base.LOAD_SOURCE)
        discovered = base.tools(out)
        before, graph, library, shaders = discover_inputs(config,out,discovered,write=True)
        common = [discovered['clang++'], *base.flags(config,discovered),
                  '--ld-path='+discovered['ld'], '-Wl,-rpath,'+str(library.parent)]
        env = base.environment(out)
        base.invoke([*common,SOURCE,library,'-o',out/'draw-probe.tmp'],env,out/'compile.log')
        base.invoke([*common,out/'loadcheck.cpp','-o',out/'loadcheck.tmp'],env,out/'loadcheck-compile.log')
        executable = immutable_executable(out/'draw-probe.tmp','draw-probe')
        loadcheck = immutable_executable(out/'loadcheck.tmp','loadcheck')
        linked = base.library_graph(executable,executable)
        require(set(linked['nodes'])-{str(executable)} == set(graph['nodes']), 'actual linked dependency closure differs')
        require(base.macho(loadcheck)['filetype'] == 2, 'load checker is not native ARM64 executable')
        after, graph_after, library_after, shaders_after = discover_inputs(config,out,discovered)
        require((before,graph,library,shaders) == (after,graph_after,library_after,shaders_after),
                'build source/tool/shader/library changed')
        record = {**initial,'status':BUILD_STATUS,'tools':discovered,'inputs_before':before,'inputs_after':after,
                  'library':str(library),'library_graph':graph,'executable_graph':linked,
                  'executable':str(executable),'loadcheck':str(loadcheck),'shaders':shaders,
                  'load_verified':False,'draw_verified':False,
                  'identity_scope':'frozen helper and shader compiler provenance; actual -M inputs/tools; linked non-system dylibs; system cache not hashed'}
        record['artifacts'] = hashes(artifact_paths(out,record))
        save(out/'build.json',record)
        save(out/'build-attempt.json',{**initial,'status':BUILD_STATUS,'build_sha256':sha(out/'build.json')})
        return record
    except Exception as error:
        failure = {**initial,'status':'DEPENDENCY_NOT_READY' if isinstance(error,base.DependencyNotReady) else 'FAIL',
                   'exception':type(error).__name__,'error':str(error),'draw_verified':False}
        save(out/'build-attempt.json',failure)
        if not (out/'first-failure.json').exists():
            save(out/'first-failure.json',failure)
        raise


def verify_build(out=OUT):
    out = output(out)
    record = read_json(out/'build.json')
    require(type(record['schema']) is int and record['schema']==1 and record['status']==BUILD_STATUS
            and record['scope']==SCOPE, 'unexpected Draw build profile')
    require(record['load_verified'] is False and record['draw_verified'] is False, 'build claims runtime success')
    require(record['wrapper_sha256']==sha(__file__) and record['source_sha256']==SOURCE_SHA, 'producer identity changed')
    require((out/'loadcheck.cpp').read_text()==base.LOAD_SOURCE, 'native load checker changed')
    require(record['tools']==base.tools(out),'actual tool/SDK selection changed')
    expected,graph,library,shaders = discover_inputs(record['config'],out,record['tools'])
    require(record['inputs_before']==record['inputs_after']==expected,'source closure missing or changed')
    require(record['library_graph']==graph and record['library']==str(library) and record['shaders']==shaders,
            'library/shader resolution changed')
    for key,stem in (('executable','draw-probe'),('loadcheck','loadcheck')):
        path = Path(record[key])
        require(path.parent==out and path.name==stem+'-'+sha(path) and base.macho(path)['filetype']==2,
                'immutable native executable identity mismatch')
    require(record['executable_graph']==base.library_graph(Path(record['executable']),Path(record['executable'])),
            'actual executable dependency graph changed')
    require(record['artifacts']==hashes(artifact_paths(out,record)), 'mandatory native artifact set changed')
    return record


def execution_inputs(out, record):
    return hashes([*record['inputs_after'], *record['artifacts'], out/'build.json'])


def execute(out=OUT, *, skip_draw=False):
    out = output(out)
    run_dir = out/('negative-no-draw' if skip_draw else 'draw')
    # Never overwrite streams belonging to an already-recorded actual execution.
    require(not run_dir.exists(), 'execution directory exists; preserve it and use a fresh --out')
    b = verify_build(out)
    before = execution_inputs(out,b)
    run_dir.mkdir()
    env = base.environment(out,images=True)
    streams = [run_dir/name for name in ('load.stdout','load.stderr','stdout.json','stderr.log')]
    for path in streams:
        path.write_text('')
    record = {'schema':1,'status':'FAIL','scope':SCOPE,'negative_control':skip_draw,'environment':env,
              'build':str(out/'build.json'),'inputs_before':before,'load_result':None,'result':None,
              'load_exit_code':None,'exit_code':None,'validation_error':None,'load_images':[],
              'probe_images':[],'gpu_probe_started':False,'draw_accepted':False}
    try:
        load = base.run_child([b['loadcheck'],b['library']],env,streams[0],streams[1])
        record['load_exit_code']=load.returncode
        record['load_result']=strict_json(load.stdout)
        base.validate_load_result(record['load_result'],load.returncode)
        record['load_images']=base.loaded_images(load.stderr,Path(b['loadcheck']),b['library_graph']['nodes'])
        same(before)
        command = [b['executable']] + (['--skip-draw'] if skip_draw else [])
        record['command']=command
        record['gpu_probe_started']=True
        probe = base.run_child(command,env,streams[2],streams[3])
        record['exit_code']=probe.returncode
        record['result']=strict_json(probe.stdout)
        record['probe_images']=base.loaded_images(probe.stderr,Path(b['executable']),b['library_graph']['nodes'])
        validate_result(record['result'],probe.returncode,b['shaders'],skip_draw=skip_draw)
        same(before)
        verify_build(out)
        record['status']='NEGATIVE_CONTROL_EXPECTED_PIXEL_FAILURE' if skip_draw else 'PASS_NATIVE_DXBC_DRAW'
        record['draw_accepted']=not skip_draw
    except Exception as error:
        record['validation_error']=type(error).__name__+': '+str(error)
    try:
        record['inputs_after']=hashes(before)
    except OSError as error:
        record['inputs_after']=None
        record['identity_error']=str(error)
    if record['inputs_after']!=before:
        record['status']='FAIL'
        record['draw_accepted']=False
        record['validation_error']='execution input closure changed'
    record['artifacts']=hashes(streams)
    save(run_dir/'evidence.json',record)
    if record['status']=='FAIL' and not (out/'first-runtime-failure.json').exists():
        save(out/'first-runtime-failure.json',record)
    return record


def verify(out=OUT, *, skip_draw=False):
    out=output(out)
    b=verify_build(out)
    run_dir=out/('negative-no-draw' if skip_draw else 'draw')
    r=read_json(run_dir/'evidence.json')
    expected_status='NEGATIVE_CONTROL_EXPECTED_PIXEL_FAILURE' if skip_draw else 'PASS_NATIVE_DXBC_DRAW'
    require(type(r['schema']) is int and r['schema']==1 and r['status']==expected_status and r['scope']==SCOPE,
            'Draw/control evidence not accepted')
    require(r['negative_control'] is skip_draw and r['draw_accepted'] is (not skip_draw), 'control/Draw scope mismatch')
    require(r['build']==str(out/'build.json') and r['command']==[b['executable']]+(['--skip-draw'] if skip_draw else []),
            'executed command/build identity mismatch')
    require(r['environment']==base.environment(out,images=True),'execution environment changed')
    require(r['gpu_probe_started'] is True and r['validation_error'] is None,'execution validation failed')
    require(r['inputs_before']==r['inputs_after']==execution_inputs(out,b),'execution identity incomplete or changed')
    streams=[run_dir/name for name in ('load.stdout','load.stderr','stdout.json','stderr.log')]
    require(r['artifacts']==hashes(streams),'actual output streams changed')
    load=strict_json(streams[0].read_text())
    require(load==r['load_result'],'load summary differs from actual stdout')
    base.validate_load_result(load,r['load_exit_code'])
    require(r['load_images']==base.loaded_images(streams[1].read_text(),Path(b['loadcheck']),b['library_graph']['nodes']),
            'load image summary differs from actual stderr')
    require(r['probe_images']==base.loaded_images(streams[3].read_text(),Path(b['executable']),b['library_graph']['nodes']),
            'probe image summary differs from actual stderr')
    result=strict_json(streams[2].read_text())
    require(r['result']==result,'Draw result summary differs from actual stdout')
    validate_result(result,r['exit_code'],b['shaders'],skip_draw=skip_draw)
    return {'status':expected_status+'_CURRENT','scope':SCOPE,'draw_accepted':not skip_draw,
            'evidence_sha256':sha(run_dir/'evidence.json')}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    for mode in ('build','verify-build','run','verify'):
        group.add_argument('--'+mode,action='store_true')
    parser.add_argument('--out',type=Path,default=OUT)
    parser.add_argument('--skip-draw',action='store_true',help='real negative control; never accepted as Draw success')
    args=parser.parse_args()
    try:
        require(not args.skip_draw or args.run or args.verify,'--skip-draw applies only to runtime/control verification')
        value=build(args.out) if args.build else verify_build(args.out) if args.verify_build else \
              execute(args.out,skip_draw=args.skip_draw) if args.run else verify(args.out,skip_draw=args.skip_draw)
        print(json.dumps({key:value[key] for key in ('status','scope','draw_accepted','validation_error') if key in value}))
        return 2 if value['status']=='FAIL' else 0
    except Exception as error:
        print(json.dumps({'status':'DEPENDENCY_NOT_READY' if isinstance(error,base.DependencyNotReady) else 'REJECT',
                          'exception':type(error).__name__,'error':str(error),'scope':SCOPE}))
        return 2


if __name__=='__main__':
    raise SystemExit(main())
