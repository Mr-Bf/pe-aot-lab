"""Execute existing real ARM64 WndProc O0/O3 objects at two guest bases.

This is a callback/transaction correctness harness, not Cocoa/App/COM/GPU or
performance acceptance. It never patches PE/IR/object bytes or launches an App.
Eight host-selected initial positions are inputs to copies of the real image.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import struct
import subprocess
import sys
import traceback

from migration_v6 import build as app_build
from window_switch_v1 import admission, profile
from window_inc_v1.loader import load_image

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('window_switch_v1/callback_probe.py','window_switch_v1/callback_probe.c',
           'window_switch_v1/runtime.h','window_switch_v1/runtime_fields.inc',
           'window_switch_v1/runtime_impl.inc','window_bridge/window_runtime/runtime.h',
           'window_bridge/window_runtime/transaction_v1.c','memory_stage2/guest_memory.h')
STACK_BASE = 0x70000000
STACK_SIZE = 65536
INITIAL_RSP = STACK_BASE+STACK_SIZE-0x108
EXIT_PC = 0x7fff00000000
STATE_SIZE = 3504


def require(value,message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path,value):
    with Path(path).open('x') as stream:
        json.dump(value,stream,sort_keys=True,indent=2)
        stream.write('\n')


def thin_arm64(path,filetype):
    raw = Path(path).read_bytes()[:16]
    require(len(raw)==16 and struct.unpack('<IIII',raw)[0]==0xfeedfacf and
            struct.unpack('<IIII',raw)[1]==0x0100000c and struct.unpack('<IIII',raw)[3]==filetype,
            'expected thin ARM64 Mach-O')


def run_probe(app,out,expect_rebase_switch_fault=False):
    require(platform.system()=='Darwin' and platform.machine()=='arm64','native macOS ARM64 required')
    require(sys.version_info>=(3,13),'Python 3.13 required')
    app,out=(Path(p).resolve() for p in (app,out))
    require(app.is_dir() and not out.exists(),'existing App product and fresh absent output required')
    require(not out.is_relative_to(app) and not app.is_relative_to(out),'probe/product outputs must be disjoint')
    out.mkdir(parents=True)
    commands=[]
    results=[]
    sources={name:sha(ROOT/name) for name in SOURCES}
    for name in SOURCES:
        destination=out/'sources'/name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/name,destination)
    write(out/'started.json',dict(status='STARTED_NOT_ACCEPTED',app=str(app),sources=sources,
          expected='OLD_REBASED_SWITCH_FAILURE' if expect_rebase_switch_fault else 'PASS_TWO_BASES_O0_O3',
          observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    environment={k:os.environ[k] for k in ('HOME','TMPDIR') if k in os.environ}
    environment.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin',LANG='C',LC_ALL='C')

    def command(argv,label):
        argv=list(map(str,argv))
        executed=subprocess.run(argv,cwd=ROOT,env=environment,capture_output=True,timeout=90)
        record=dict(argv=argv,cwd=str(ROOT),label=label,returncode=executed.returncode)
        for stream in ('stdout','stderr'):
            path=out/(label+'.'+stream);path.write_bytes(getattr(executed,stream))
            record[stream+'_path']=str(path);record[stream+'_sha256']=sha(path)
        commands.append(record);write(out/(label+'.command.json'),record)
        require(executed.returncode==0,'command failed: '+label)
        return executed.stdout.decode()

    try:
        static=app_build.verify(app)
        pe=app/'native/input.exe'
        config_path=app/'native/profile.json'
        manifest_path=app/'native/compiler/window-proc-1000/manifest.json'
        native_path=app/'native/producer.json'
        data=pe.read_bytes();config=json.loads(config_path.read_bytes())
        normalized,image,_=profile.validate(data,config)
        require(normalized['callback_rvas']==[0x1000],'probe requires actual window-proc-1000 callback')
        root=json.loads(manifest_path.read_bytes())
        require(root['root_rva']==0x1000 and root['symbol']=='aot_window_proc_1000' and
                root['input_sha256']==digest(data),'callback object identity differs')
        proof=root['switch_proof']
        admission.validate_window_switch(proof,data,proof['candidate_packet'],0x1000,
                                          normalized['switch_leaf_rva'],[image.entry_rva,0x1000])
        switch=proof['switch']
        require(switch is not None and switch['count']==8,'probe requires real eight-way leaf')
        observations=normalized['observations']
        state=observations['window_state'];result=observations['window_result']
        require(state['size']==20 and result['size']==60,'expected sample observation layouts')
        state_rva,result_rva=state['rva'],result['rva']
        require(struct.unpack_from('<5I',image.data,state_rva)==(0x31574f43,1,3,0,0),
                'original initialized SampleState differs')
        require(bytes(image.data[result_rva:result_rva+60])==bytes(60),'original observation BSS differs')
        native=json.loads(native_path.read_bytes())
        compile_inputs=native['compile_inputs_before']
        runtime_identity={name:compile_inputs.get(str(ROOT/name)) for name in SOURCES[2:]}
        runtime_matches=all(value==sources[name] for name,value in runtime_identity.items())
        require(runtime_matches or expect_rebase_switch_fault,'probe runtime differs from the new native build sources')
        inputs={str(p):sha(p) for p in (app/'result.json',pe,config_path,manifest_path,native_path)}
        inputs_directory=out/'inputs';inputs_directory.mkdir()
        shutil.copyfile(pe,inputs_directory/'input.exe')
        shutil.copyfile(config_path,inputs_directory/'profile.json')
        shutil.copyfile(manifest_path,inputs_directory/'root-manifest.json')
        objects={}
        for level in ('O0','O3'):
            descriptor=root['objects'][level]
            obj=Path(descriptor['path']).resolve()
            require(obj.parent==manifest_path.parent and sha(obj)==descriptor['sha256'],
                    'recorded callback object differs')
            thin_arm64(obj,1)
            inputs[str(obj)]=sha(obj)
            copy=inputs_directory/(level+'.o');shutil.copyfile(obj,copy)
            require(sha(copy)==descriptor['sha256'],'copied object changed')
            objects[level]=copy
        rows=root['instructions']
        require(rows==sorted(rows,key=lambda r:r['rva']),'normalized instructions are not sorted')
        for row in rows:
            rva,length=row['rva'],row['length']
            require(bytes(image.data[rva:rva+length]).hex()==row['bytes'],'normalized instruction bytes differ')
        header='/* Generated from frozen source PE, normalized instructions and proof. */\n'
        for name,value,ctype in (
            ('kProbeImageSize',len(image.data),'size_t'),('kProbePageCount',len(image.permissions),'size_t'),
            ('kProbeRootRva',0x1000,'uint32_t'),('kProbeStateRva',state_rva,'uint32_t'),
            ('kProbeResultRva',result_rva,'uint32_t'),
            ('kProbeJumpRva',switch['jump_pc']-image.base,'uint32_t'),
            ('kProbeTableRva',switch['table_pc']-image.base,'uint32_t'),('kProbeTargetCount',8,'size_t')):
            header+='static const %s %s=%du;\n'%(ctype,name,value)
        header+='static const uint8_t kProbeTableBytes[]={'+','.join(map(str,bytes.fromhex(switch['table_bytes'])))+'};\n'
        header+='static const uint32_t kProbeTargetRvas[]={'+','.join(str(pc-image.base)+'u' for pc in switch['targets'])+'};\n'
        header+='static const AotInstruction kProbeInstructions[]={\n'+''.join(
            '{%du,%du,%du,0,UINT64_C(%d)},\n'%(r['rva'],r['length'],r['kind'],r.get('target_rva',0)) for r in rows)+'};\n'
        generated=out/'callback_probe_input.h';generated.write_text(header)
        compiler=command(['/usr/bin/xcrun','--find','clang'],'compiler-path').strip()
        sdk=command(['/usr/bin/xcrun','--show-sdk-path'],'sdk-path').strip()
        require(Path(compiler).is_absolute() and Path(compiler).is_file(),'compiler absent')
        compiler_identity={compiler:sha(compiler)}
        compiler_version=command([compiler,'--version'],'compiler-version')
        compile_flags=[compiler,'-std=c11','-arch','arm64','-isysroot',sdk,'-Wall','-Wextra','-Werror',
                       '-O3','-DAOT_WINDOW_SWITCH_V1=1','-I',out]
        dependencies=command([*compile_flags,'-M','-MT','probe',ROOT/'window_switch_v1/callback_probe.c'],
                             'compiler-dependencies')
        require(dependencies.startswith('probe:'),'unexpected compiler dependency target')
        dependency_paths=[Path(name).resolve(strict=True) for name in shlex.split(
            dependencies.replace('\\\n',' ').split(':',1)[1])]
        require([p for p in dependency_paths if p.name=='callback_probe_input.h']==[generated.resolve()],
                'compiler selected a different generated input header')
        require({(ROOT/name).resolve() for name in SOURCES[1:]} <= set(dependency_paths),
                'compiler omitted expected transaction/runtime source dependency')
        dependency_identity={str(p):sha(p) for p in dependency_paths}
        generated_identity={str(generated):sha(generated),**{str(obj):sha(obj) for obj in objects.values()}}
        write(out/'compiler-inputs.json',dict(dependencies=dependency_identity,generated=generated_identity))
        binaries={}
        for level in ('O0','O3'):
            binary=out/('callback_probe_'+level)
            command([*compile_flags,ROOT/'window_switch_v1/callback_probe.c',
                     objects[level],'-o',binary],level+'-compile')
            thin_arm64(binary,2);binaries[level]=binary
        dependencies_after=command([*compile_flags,'-M','-MT','probe',ROOT/'window_switch_v1/callback_probe.c'],
                                   'compiler-dependencies-after')
        require(dependencies_after==dependencies,'compiler dependency graph changed while compiling')
        bases=[image.preferred_base,0x180000000]
        require(len(set(bases))==2,'second base must differ from preferred')
        responses={}
        for base in bases:
            mapped=load_image(data,load_base=base)
            label='preferred' if base==image.preferred_base else 'rebased'
            image_file=out/(label+'-image.bin');image_file.write_bytes(mapped.data)
            rights_file=out/(label+'-permissions.bin');rights_file.write_bytes(bytes(mapped.permissions))
            for level in ('O0','O3'):
                directory=out/(label+'-'+level);directory.mkdir()
                response=json.loads(command([binaries[level],image_file,rights_file,hex(base),directory],label+'-'+level+'-run'))
                require(response['transport']=='CALLBACK_PROBE_RECORDED' and response['base']==base and
                        response['state_size']==STATE_SIZE and response['image_size']==len(mapped.data) and
                        response['stack_size']==STACK_SIZE and len(response['cases'])==8,'response shape differs')
                for index,case in enumerate(response['cases']):
                    require(case['initial_position']==index and case['setup_status']==0 and
                            case['rejected_api_calls']==0 and case['trace_overflow']==0,'invalid setup/API/trace record')
                    response_file=directory/('case-%d.bin'%index)
                    payload=response_file.read_bytes()
                    require(len(payload)==STATE_SIZE+len(mapped.data)+STACK_SIZE,'binary response extent differs')
                    actual_state=payload[:STATE_SIZE]
                    actual_image=payload[STATE_SIZE:STATE_SIZE+len(mapped.data)]
                    actual_stack=payload[STATE_SIZE+len(mapped.data):]
                    case.update(response_path=str(response_file),response_sha256=digest(payload),
                                state_sha256=digest(actual_state),image_sha256=digest(actual_image),
                                stack_sha256=digest(actual_stack))
                    require(case['steps']==len(case['trace']) and case['call_commits']==1 and
                            case['max_call_depth']==1 and case['switch_commits']==1,'real CALL/switch trace differs')
                    calls=[item for item in case['trace'] if item['kind']==1]
                    jumps=[item for item in case['trace'] if item['kind']==5]
                    require(len(calls)==1 and calls[0]['next_pc']==base+normalized['switch_leaf_rva'] and
                            calls[0]['before_depth']==0 and calls[0]['after_depth']==1,'leaf CALL depth/target differs')
                    require(len(jumps)==1 and jumps[0]['pc']==base+switch['jump_pc']-image.base and
                            jumps[0]['next_pc']==base+switch['targets'][index]-image.base and
                            jumps[0]['before_depth']==jumps[0]['after_depth']==1 and jumps[0]['status']==0,
                            'finite jump did not commit the actual selected relocated target')
                    expected=bytearray(mapped.data)
                    if expect_rebase_switch_fault and base!=image.preferred_base:
                        require(case['status']==6 and case['returned']==0 and case['call_depth']==1 and
                                case['ret_commits']==0 and case['position']==index and case['moves']==0 and
                                case['dirty']==0 and case['keydowns']==1 and
                                case['fault']['pc']==base+switch['jump_pc']-image.base and
                                case['fault']['address']==base+switch['targets'][index]-image.base,
                                'expected old rebased switch-dispatch fault was not reproduced')
                        after=index;changed=0
                    else:
                        after=min(index+1,7);changed=int(after!=index)
                        require(case['status']==0 and case['fault']['status']==0 and case['returned']==1 and
                                case['call_depth']==0 and case['ret_commits']==2 and
                                case['position']==after and case['moves']==changed and case['dirty']==changed and
                                case['draws']==0 and case['keydowns']==1,'RIGHT callback behavior differs')
                        regs=case['registers']
                        require(len(regs)==17 and regs[0]==0 and regs[4]==INITIAL_RSP+8 and regs[16]==EXIT_PC,
                                'callback return State differs')
                        for reg in (3,5,6,7,12,13,14,15):
                            require(regs[reg]==0xabc0000000000000+0x10101010101*reg,'Win64 nonvolatile GPR changed')
                    struct.pack_into('<II',expected,state_rva+8,after,changed)
                    struct.pack_into('<I',expected,result_rva+12,1)
                    struct.pack_into('<I',expected,result_rva+56,changed)
                    require(actual_image==bytes(expected),'callback changed unexpected image bytes')
                write(directory/'parsed.json',response)
                responses[(base,level)]=response
                results.append(dict(base=base,optimization=level,parsed=str(directory/'parsed.json'),
                                    parsed_sha256=sha(directory/'parsed.json'),cases=8,
                                    statuses=[c['status'] for c in response['cases']]))
                print(label+' '+level+' recorded',flush=True)
        comparisons=[]
        for base in bases:
            for index in range(8):
                first=responses[(base,'O0')]['cases'][index]
                second=responses[(base,'O3')]['cases'][index]
                require(Path(first['response_path']).read_bytes()==Path(second['response_path']).read_bytes(),
                        'O0/O3 complete State/image/stack differs')
                require(first['trace']==second['trace'],'O0/O3 dynamic commit trace differs')
                comparisons.append(dict(base=base,initial_position=index,response_sha256=first['response_sha256'],
                                        complete_state_image_stack_and_trace_equal=True))
        require(inputs=={name:sha(name) for name in inputs},'input product/object changed during probe')
        require(sources=={name:sha(ROOT/name) for name in SOURCES},'probe/runtime source changed during execution')
        require(compiler_identity=={name:sha(name) for name in compiler_identity},'compiler changed during execution')
        require(dependency_identity=={name:sha(name) for name in dependency_identity},'actual compile dependency changed')
        require(generated_identity=={name:sha(name) for name in generated_identity},'generated header/object changed')
        status='REPRODUCED_OLD_REBASED_SWITCH_FAILURE_NOT_ACCEPTED' if expect_rebase_switch_fault else 'PASS_REAL_ARM64_CALLBACK_TWO_BASES_O0_O3'
        result=dict(schema=1,status=status,app=str(app),static_verification=static,pe_sha256=digest(data),
                    inputs_before=inputs,inputs_after={name:sha(name) for name in inputs},sources=sources,
                    native_runtime_source_matches_current=runtime_matches,native_runtime_identities=runtime_identity,
                    compiler=compiler_identity,compiler_version=compiler_version,sdk=sdk,
                    actual_compiler_dependencies=dependency_identity,generated_inputs=generated_identity,
                    probe_executable_sha256={level:sha(binary) for level,binary in binaries.items()},
                    image_initialization='Original PE mapped by strict loader; only the initial position input is selected per copy. No PE/IR/object patch.',
                    commands=commands,records=results,comparisons=comparisons,
                    translated_callback_executions=32,successful_callbacks=16 if expect_rebase_switch_fault else 32,
                    expected_rebased_faults=16 if expect_rebase_switch_fault else 0,
                    cocoa_app_executions=0,gpu_executions=0,api_calls=0,
                    limitations='Actual ARM64 WndProc objects and real window transaction/switch hooks. Rejecting COM/IAT stubs; RIGHT path invokes no API. Full State/image/stack and trace compared within each base. Not Cocoa/App/COM/GPU, original-x86 differential or performance acceptance.')
        write(out/'result.json',result)
        return result
    except BaseException as error:
        write(out/'failure.json',dict(status='FAILED_OR_CANCELLED_NOT_ACCEPTED',error=repr(error),
              traceback=traceback.format_exc(),commands=commands,completed_records=results,sources=sources))
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app',required=True)
    parser.add_argument('--out',required=True)
    parser.add_argument('--expect-rebase-switch-fault',action='store_true')
    value=run_probe(**vars(parser.parse_args()))
    print(json.dumps({k:value[k] for k in ('status','translated_callback_executions','successful_callbacks','expected_rebased_faults')}))
