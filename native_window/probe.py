#!/usr/bin/env python3
"""Versioned native Cocoa/DXMT window probe; never writes old graphics evidence."""
from __future__ import annotations
import argparse
import json
import math
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as base
from native_window import build as backend
HERE=Path(__file__).resolve().parent
OUT=ROOT/'build/native-window/probe-v1'
SOURCES=[HERE/'probe.cpp',HERE/'cocoa_registry.mm',HERE/'cocoa_registry.h',HERE/'native_wsi.h',Path(__file__)]
BUILD_STATUS='BUILT_NATIVE_WINDOW_PROBE_NOT_EXECUTED'
SCOPE={'native_window':True,'present0':True,'resize':True,'shader_draw':False,
       'guest':False,'user_input':False,'visual_compositor_verified':False}
PLIST={'CFBundleIdentifier':'org.peaotlab.NativeWindowProbe','CFBundleName':'PE AOT Window Probe',
       'CFBundleDisplayName':'PE AOT Window Probe','CFBundleExecutable':'native-window-probe',
       'CFBundlePackageType':'APPL','CFBundleVersion':'1','NSHighResolutionCapable':True}


def require(x,m):
    if not x:raise RuntimeError(m)


def executable(out):return Path(out)/'PE AOT Window Probe.app/Contents/MacOS/native-window-probe'


def own_output(out):
    out=Path(out).resolve()
    require(out.is_relative_to(ROOT/'build/native-window'),'independent native-window output required')
    return out


def run_command(command,env,log):
    command=list(map(str,command));p=subprocess.run(command,env=env,text=True,capture_output=True)
    base.save(log,{'command':command,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    require(p.returncode==0,'command failed: '+str(log))
    return p.stdout


def options(record,tools):
    source=Path(record['source'])
    common=['-arch','arm64','-isysroot',tools['sdk'],'-std=c++20','-O2','-Wall','-Wextra','-Werror']
    cpp=[*common,'-Wno-extern-c-compat','-I'+str(source/'include/native/windows'),'-I'+str(source/'include/native/directx')]
    objc=[*common,'-Wno-deprecated-declarations']
    return cpp,objc


def discover(out,tools,write=False):
    record=backend.verify()
    cpp,objc=options(record,tools)
    env=base.environment(out)
    dependencies=[]
    for name,source,flags in [('cpp',HERE/'probe.cpp',cpp),('objc',HERE/'cocoa_registry.mm',objc)]:
        args=[tools['clang++'],*flags,'-M','-MT','probe',source]
        text=run_command(args,env,out/(name+'-dependencies.log')) if write else base.invoke(args,env)
        dependencies+=base.dependency_paths(text)
    files=[*SOURCES,Path(base.__file__),Path(backend.__file__),backend.OUT/'evidence.json',
           *[Path(v) for k,v in tools.items() if k!='sdk'],*dependencies,*map(Path,record['outputs']),
           *map(Path,record['artifacts']),*map(Path,record['inputs_after']['files'])]
    return base.hashes(files),record


def build(out=OUT):
    out=own_output(out);out.mkdir(parents=True,exist_ok=True)
    tools=base.tools(out);before,record=discover(out,tools,True)
    cpp,objc=options(record,tools);env=base.environment(out)
    exe=executable(out);exe.parent.mkdir(parents=True,exist_ok=True)
    plist=exe.parents[1]/'Info.plist';plist.write_bytes(plistlib.dumps(PLIST,sort_keys=True))
    run_command([tools['clang++'],*cpp,'-c',HERE/'probe.cpp','-o',out/'probe.o'],env,out/'compile-cpp.log')
    run_command([tools['clang++'],*objc,'-c',HERE/'cocoa_registry.mm','-o',out/'registry.o'],env,out/'compile-objc.log')
    library=Path(record['library']);metal=Path(record['build'])/'src/nativemetal/winemetal.dylib'
    run_command([tools['clang++'],'-arch','arm64','-isysroot',tools['sdk'],'--ld-path='+tools['ld'],
                 out/'probe.o',out/'registry.o',library,metal,'-framework','Cocoa','-framework','Metal',
                 '-framework','QuartzCore','-Wl,-rpath,'+str(library.parent),'-Wl,-rpath,'+str(metal.parent),
                 '-o',exe],env,out/'link.log')
    graph=base.library_graph(exe,exe)
    require(set(graph['nodes'])-{str(exe)}==set(record['library_graph']['nodes']),'link mixed old/new backend')
    after,again=discover(out,tools)
    require(before==after and again==record,'build dependencies changed')
    artifacts=[exe,plist,out/'probe.o',out/'registry.o']+[out/(n+'.log') for n in ('compile-cpp','compile-objc','link','cpp-dependencies','objc-dependencies')]
    result={'schema':1,'status':BUILD_STATUS,'scope':SCOPE,'tools':tools,
            'inputs_before':before,'inputs_after':after,'artifacts':base.hashes(artifacts),
            'backend_evidence_sha256':base.sha(backend.OUT/'evidence.json'),
            'executable':str(exe),'library_graph':graph,'package_relocatable':False,
            'identity_scope':'actual C/C++ header closure and exact new backend linked images; system dyld cache not hashed'}
    base.save(out/'build.json',result)
    verify_build(out)
    return result


def verify_build(out=OUT):
    out=own_output(out);r=base.read_json(out/'build.json')
    require(r['schema']==1 and r['status']==BUILD_STATUS and r['scope']==SCOPE,'probe build scope/status differs')
    require(r['tools']==base.tools(out),'selected build tools changed')
    current,record=discover(out,r['tools'])
    require(current==r['inputs_before']==r['inputs_after'],'probe build inputs changed')
    require(base.sha(backend.OUT/'evidence.json')==r['backend_evidence_sha256'],'backend evidence changed')
    exe=executable(out)
    required={str(p.resolve()) for p in [exe,exe.parents[1]/'Info.plist',out/'probe.o',out/'registry.o',
        *[out/(n+'.log') for n in ('compile-cpp','compile-objc','link','cpp-dependencies','objc-dependencies')]]}
    require(set(r['artifacts'])==required,'probe artifact closure missing or added')
    base.same(r['artifacts'])
    require(plistlib.loads((exe.parents[1]/'Info.plist').read_bytes())==PLIST,'App metadata differs')
    require(r['executable']==str(exe) and r['package_relocatable'] is False,'unsupported App packaging claim')
    graph=base.library_graph(exe,exe)
    require(graph==r['library_graph'] and set(graph['nodes'])-{str(exe)}==set(record['library_graph']['nodes']),'actual link graph changed')
    return r


def hr(value,expected=0):
    require(isinstance(value,dict) and set(value)=={'signed','hex','succeeded'},'missing HRESULT')
    signed=expected if expected<0x80000000 else expected-0x100000000
    require(type(value['signed']) is int and value['signed']==signed and value['hex']=='0x%08x'%expected
            and value['succeeded'] is (signed>=0),'unexpected HRESULT')


def validate_result(r,returncode):
    fields={'schema','probe','status','failure_stage','scope','native_arm64','translation','feature_level',
      'hresult','phases_done','phases','installed','repeat_install_rejected','wrong_version_rejected',
      'unknown_query_rejected','invalid_resize_rejected','resize_callback','synthetic_close_kept_view',
      'window_destroyed','tombstone_rejected','released_application_references','registry'}
    require(type(returncode) is int and returncode==0,'native window execution failed')
    require(isinstance(r,dict) and set(r)==fields,'unknown/missing window result fields')
    require(type(r['schema']) is int and r['schema']==1 and r['probe']=='native_dxmt_window_v1' and r['status']=='PASS' and r['failure_stage'] is None,'window result not PASS')
    require(r['scope']==SCOPE and all(type(v) is bool for v in r['scope'].values()) and r['native_arm64'] is True,'unsupported graphics/native claim')
    t=r['translation'];require(set(t)=={'returncode','errno','value','size'},'translation shape changed')
    require(all(type(v) is int for v in t.values()),'translation values must be integers')
    require((t=={'returncode':0,'errno':0,'value':0,'size':4}) or
            (t['returncode']==-1 and t['errno']==2 and t['value']==-1 and t['size']==4),'native translation identity unverified')
    require(r['feature_level']==0xb000 and r['phases_done']==2 and r['released_application_references']==13,'execution/cleanup count differs')
    for field in ('installed','repeat_install_rejected','wrong_version_rejected','unknown_query_rejected',
        'invalid_resize_rejected','resize_callback','synthetic_close_kept_view','window_destroyed','tombstone_rejected'):
        require(r[field] is True,'required window check absent: '+field)
    names={'D3D11CreateDevice','QueryIDXGIDevice','GetAdapter','GetFactory','CreateSwapChain',
           'UnknownWindow','CreateQuery','ResizeBuffers','GetDeviceRemovedReason','UnsupportedPresent1'}
    require(set(r['hresult'])==names,'window method set differs')
    for name,value in r['hresult'].items():hr(value,0x887a0001 if name=='UnknownWindow' else 0x887a0004 if name=='UnsupportedPresent1' else 0)
    require(len(r['phases'])==2,'phase set incomplete')
    for p,(width,height,color) in zip(r['phases'],[(640,360,[17,85,170,255]),(800,450,[34,170,85,255])]):
        require(set(p)=={'width','height','expected_rgba8','hresult','window','clear','copy','unmap',
            'gpu_query_complete','row_pitch','pixels_checked','channels_checked','bad_pixels','bad_channels','max_error'},'phase fields differ')
        for key,value in {'width':width,'height':height,'pixels_checked':width*height,'channels_checked':width*height*4,'bad_pixels':0,'bad_channels':0}.items():
            require(type(p[key]) is int and p[key]==value,'phase value differs: '+key)
        require(p['expected_rgba8']==color and type(p['row_pitch']) is int and p['row_pitch']>=width*4 and type(p['max_error']) is int and 0<=p['max_error']<=1,'phase pixel contract differs')
        require(set(p['hresult'])=={'GetBuffer','CreateRTV','CreateStaging','Map','Present','GetData'},'phase call set differs')
        for value in p['hresult'].values():hr(value)
        for key in ('clear','copy','unmap','gpu_query_complete'):require(p[key] is True,'phase operation absent')
        w=p['window'];require(set(w)=={'width_pixels','height_pixels','flags'},'window query shape differs')
        require(w['width_pixels']==width and w['height_pixels']==height and type(w['flags']) is int and
                0<=w['flags']<=7 and w['flags']&1 and not w['flags']&2,'window actual backing size/visibility differs')
    s=r['registry']
    keys={'created','destroyed','queries','query_rejections','resizes','resize_rejections','views_created',
          'views_released','active_views','view_rejections','release_rejections','close_requests','main_dispatches',
          'event_pumps','visible_observations','main_thread_violations','width_pixels','height_pixels','window_number','tombstones','backing_scale'}
    require(set(s)==keys,'registry field set differs')
    for key,value in s.items():
        if key!='backing_scale':require(type(value) is int and 0<=value<=0xffffffff,'invalid registry count')
    for key,value in {'created':1,'destroyed':1,'resizes':1,'views_created':1,'views_released':1,'active_views':0,
          'view_rejections':0,'release_rejections':0,'close_requests':1,'main_thread_violations':0,'width_pixels':800,'height_pixels':450,'tombstones':1}.items():
        require(s[key]==value,'registry lifecycle differs: '+key)
    require(s['queries']>=3 and s['query_rejections']>=3 and s['main_dispatches']>0 and s['event_pumps']>0
            and s['visible_observations']>=2 and s['window_number']>0,'main-thread/visibility evidence absent')
    require(type(s['backing_scale']) in (int,float) and math.isfinite(s['backing_scale']) and 0<s['backing_scale']<=8,'invalid backing scale')


def execute(out=OUT,label='host',hold_ms=1000):
    out=own_output(out);require(label.isidentifier(),'invalid record label');require(0<=hold_ms<=10000,'hold bound')
    record=verify_build(out);exe=executable(out)
    paths=[out/'build.json',exe,*map(Path,record['inputs_before']),*map(Path,record['artifacts'])]
    before=base.hashes(paths);env=base.environment(out,images=True)
    command=[str(exe),'--hold-ms',str(hold_ms)]
    stdout=out/(label+'.stdout');stderr=out/(label+'.stderr')
    initial={'schema':1,'status':'RUNNING_NOT_ACCEPTED','scope':SCOPE,'command':command,'inputs_before':before,
             'build_sha256':base.sha(out/'build.json'),'label':label}
    base.save(out/(label+'.json'),initial)
    try:
        with stdout.open('w') as output,stderr.open('w') as error:
            p=subprocess.run(command,env=env,stdout=output,stderr=error,timeout=60)
        result=base.strict_json(stdout.read_text());validate_result(result,p.returncode)
        images=base.loaded_images(stderr.read_text(),exe,record['library_graph']['nodes'])
        after=base.hashes(paths);require(before==after,'runtime inputs changed')
        verify_build(out)
        final={**initial,'status':'PASS','returncode':p.returncode,'result':result,'loaded_images':images,
               'inputs_after':after,'artifacts':base.hashes([stdout,stderr])}
        base.save(out/(label+'.json'),final);return final
    except Exception as error:
        final={**initial,'status':'FAIL','error':str(error),'inputs_after':base.hashes(paths),
               'artifacts':base.hashes([p for p in (stdout,stderr) if p.exists()])}
        base.save(out/(label+'.json'),final);raise


def verify(out=OUT,label='host'):
    out=own_output(out);require(label.isidentifier(),'invalid record label')
    build_record=verify_build(out);r=base.read_json(out/(label+'.json'));exe=executable(out)
    require(r['schema']==1 and r['status']=='PASS' and r['scope']==SCOPE and r['label']==label,'run scope/status differs')
    paths=[out/'build.json',exe,*map(Path,build_record['inputs_before']),*map(Path,build_record['artifacts'])]
    require(r['inputs_before']==r['inputs_after']==base.hashes(paths),'run dependency closure changed')
    require(r['build_sha256']==base.sha(out/'build.json'),'run/build mismatch')
    require(len(r['command'])==3 and r['command'][:2]==[str(exe),'--hold-ms'] and
            r['command'][2].isdigit() and 0<=int(r['command'][2])<=10000,'run command differs')
    stdout=out/(label+'.stdout');stderr=out/(label+'.stderr')
    require(base.hashes([stdout,stderr])==r['artifacts'],'run stream identity differs')
    actual=base.strict_json(stdout.read_text());require(actual==r['result'],'stdout/result mismatch')
    validate_result(actual,r['returncode'])
    require(base.loaded_images(stderr.read_text(),exe,build_record['library_graph']['nodes'])==r['loaded_images'],'runtime loaded closure differs')
    return {'status':'NATIVE_WINDOW_PRESENT_CURRENT','run_sha256':base.sha(out/(label+'.json')),
            'phases':2,'pixels_checked':590400,'channels_checked':2361600,'guest_executions':0,
            'visual_compositor_verified':False,'scope':SCOPE}


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['build','run','verify']);p.add_argument('--out',type=Path,default=OUT)
    p.add_argument('--label',default='host');p.add_argument('--hold-ms',type=int,default=1000);a=p.parse_args()
    if a.command=='build':r=build(a.out);print(json.dumps({'status':r['status'],'executable':r['executable']}))
    elif a.command=='run':r=execute(a.out,a.label,a.hold_ms);print(json.dumps({'status':r['status'],'result':r['result']}))
    else:print(json.dumps(verify(a.out,a.label),indent=2))


if __name__=='__main__':main()
