#!/usr/bin/env python3
"""Actual callback PE execution; explicit current-evidence gate, no assert gates."""
import argparse
import copy
import json
from pathlib import Path
import random
import struct
import sys

ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from callback_bridge.bindings import (Program,Region,STATUS,EXIT_VA,sha,snapshot,unchanged,
    python_closure,validate_callbacks,merge_instructions,verify_lift)
from callback_bridge.loader import load_image,SIGNATURES,ImageError
from callback_bridge.fixtures import expected
from callback_bridge.oracle import Oracle

OUT=ROOT/'build/callback-bridge/program-tests';MASK=(1<<64)-1
NAMES=('leaf','import','direct','nested')
def require(value,message):
    if not value:raise RuntimeError(message)
def rejected(function,message):
    try:function()
    except ValueError:return
    raise RuntimeError('accepted invalid input: '+message)
def registry(record):
    return [{'rva':rva,'symbol':'aot_callback_'+format(rva,'x'),'signature':1} for rva in record['callback_rvas']]
def source_inputs():
    sources=python_closure([Path(__file__),HERE/'fixtures.py',HERE/'oracle.py'])
    sources.update([HERE/'runtime.c',HERE/'runtime.h',HERE/'oracle_x86.c',
        ROOT/'integration_stage3/runtime.c',ROOT/'integration_stage3/runtime.h',ROOT/'memory_stage2/guest_memory.h',
        ROOT/'build/callback-bridge/fixtures/manifest.json'])
    sources.update(ROOT/'build/callback-bridge/fixtures'/(name+'.exe') for name in NAMES)
    return sources
def verify_evidence(out=OUT):
    out=Path(out).resolve();evidence=json.loads((out/'evidence.json').read_text())
    require(evidence.get('schema')==1 and evidence.get('status')=='PASS','callback Program evidence not PASS')
    require(evidence['inputs_before']==evidence['inputs_after'],'Program inputs changed during tests')
    require(set(map(str,source_inputs()))<=set(evidence['inputs_before']),'source closure omitted required inputs')
    unchanged(evidence['inputs_before'])
    require(evidence['unique_normal_inputs']==len(NAMES)*evidence['vectors_per_fixture'],'normal case count')
    require(evidence['modes']==['O3','O0'] and evidence['raw_x86_cases']==evidence['unique_normal_inputs'],'mode/oracle coverage')
    for file,digest in evidence['artifacts_sha256'].items():require(sha(file)==digest,'Program artifact changed: '+file)
    return evidence

def run(out,count):
    out=out.resolve();out.mkdir(parents=True,exist_ok=True);evidence_path=out/'evidence.json'
    if evidence_path.exists():
        history=out/'history';history.mkdir(exist_ok=True)
        (history/(sha(evidence_path)+'.json')).write_bytes(evidence_path.read_bytes())
    evidence_path.write_text('{"status":"RUNNING"}\n')
    before=snapshot(source_inputs());inputs=dict(before);records=[];programs={};artifacts=[]
    try:
        fixtures=json.loads((ROOT/'build/callback-bridge/fixtures/manifest.json').read_text())
        rng=random.Random(0xc411bac)
        vectors=[(0,)*6,(MASK,)*6,tuple(range(1,7)),tuple(1<<i for i in range(6)),
                 tuple(1<<(63-i) for i in range(6)),tuple(MASK if i%2 else 0 for i in range(6))]
        vectors=vectors[:count]+[tuple(rng.getrandbits(64) for _ in range(6)) for _ in range(max(0,count-len(vectors)))]
        # The new versioned parser preserves the old accepted profile, without editing it.
        from native_bridge.loader import load_image as old_loader
        for name in ('pid','six'):
            path=ROOT/'build/native-bridge/fixtures'/(name+'.exe')
            for base in (None,0x180000000):require(vars(load_image(path,base))==vars(old_loader(path,base)),'parser parity')
            inputs.update(snapshot([path,ROOT/'native_bridge/loader.py']))
        corrupt=(ROOT/'build/callback-bridge/fixtures/leaf.exe').read_bytes().replace(b'NativeInvokeCallback',b'NativeInvokeCallbacx')
        rejected(lambda:load_image(corrupt),'unknown import function')
        try:SIGNATURES[('aotdemo.dll','Unknown')]=4
        except TypeError:pass
        else:raise RuntimeError('signature profile is mutable')
        image=load_image(ROOT/'build/callback-bridge/fixtures/leaf.exe');valid=registry(fixtures['leaf'])
        bad_registry=[[],valid*2,[{**valid[0],'signature':2}],[{**valid[0],'rva':0x1000,'symbol':'aot_callback_1000'}],
                      [{**valid[0],'rva':0x2000,'symbol':'aot_callback_2000'}],[{**valid[0],'symbol':'aot_entry'}],
                      [{**valid[0],'rva':1<<32,'symbol':'aot_callback_100000000'}]]
        for index,bad in enumerate(bad_registry):rejected(lambda:validate_callbacks(bad,image),'registry '+str(index))
        records.append({'kind':'loader_registry','parity_cases':4,'rejections':9,'status':'PASS'})
        by_name={name:([(v[0]%9,*v[1:]) for v in vectors] if name=='nested' else vectors) for name in NAMES}
        require(all(len(set(rows))==count for rows in by_name.values()),'duplicate vectors would inflate unique count')
        raw={}
        for name in NAMES:
            oracle=Oracle(ROOT/'build/callback-bridge/fixtures'/(name+'.exe'),out/'oracle'/name)
            raw[name]=oracle.run_many(by_name[name])
            require(len(raw[name])==count,'oracle result count')
            inputs.update(snapshot(oracle.sources))
            artifacts.extend(oracle.out_dir.rglob('*'))
        for optimization in ('O3','O0'):
            for name in NAMES:
                fixture=fixtures[name];path=ROOT/'build/callback-bridge/fixtures'/(name+'.exe')
                require(sha(path)==fixture['pe_sha256'],'fixture manifest stale')
                program=Program(path,out/optimization/name,optimization,callbacks=registry(fixture));programs[(optimization,name)]=program
                inputs.update(program.build_manifest['native_inputs']);artifacts.extend(program.out.rglob('*'))
                inputs[str(program.library_path)]=program.library_sha256
                normal_steps=None;step_counts=[];counters={k:[] for k in ('api_calls','callback_calls','callback_returns','max_callback_depth')}
                for index,args in enumerate(by_name[name]):
                    base=fixture['image_base'] if index%2==0 else 0x180000000
                    kept={reg:rng.getrandbits(64) for reg in ('RBX','RBP','RSI','RDI','R12','R13','R14','R15')}
                    regs={**kept,**dict(zip(('RCX','RDX','R8','R9'),args[:4]))}
                    result=program.run(gpr=regs,stack_args=args[4:],base=base)
                    require(result.status==0 and result.returned and result.call_depth==0,'normal callback failed')
                    wanted=expected(args,name)
                    require(result.registers['RAX']==wanted==raw[name][index]['result'],'raw x86 callback differential')
                    depth=args[0]+1 if name=='nested' else 1
                    api_calls=depth if name=='nested' else fixture['api_calls']
                    require(result.api_calls==api_calls and result.callback_calls==result.callback_returns==result.max_callback_depth==depth,'callback counters')
                    expected_regs={**kept,'RAX':wanted,'RCX':base+fixture['callback_rva'],'RDX':args[0],
                        'R8':args[1],'R9':args[2],'R10':args[4],'R11':args[5],
                        'RSP':result.stack.base+len(result.stack.data)-0x100,'RIP':EXIT_VA}
                    require(result.registers==expected_regs,'GPR or logical return mismatch')
                    if name!='nested':require(result.steps==len(program.manifest['instructions'])+fixture['api_calls'],'real instruction count')
                    normal_steps=result.steps
                    step_counts.append(result.steps)
                    for key in counters:counters[key].append(getattr(result,key))
                records.append({'kind':'normal','mode':optimization,'fixture':name,'cases':count,'step_range':[min(step_counts),max(step_counts)],
                                'counter_ranges':{key:[min(values),max(values)] for key,values in counters.items()},
                                'library':str(program.library_path),'library_sha256':program.library_sha256,'status':'PASS'})
                # Exhaust every incomplete budget. The same Context budget covers all roots and shims.
                probe=program.run(gpr={'RCX':1,'RDX':2,'R8':3,'R9':4},stack_args=[5,6])
                require(probe.status==0 and probe.registers['RAX']==expected((1,2,3,4,5,6),name),'budget probe failed')
                normal_steps=probe.steps
                for budget in range(1,normal_steps):
                    result=program.run(gpr={'RCX':1,'RDX':2,'R8':3,'R9':4},stack_args=[5,6],max_steps=budget)
                    require(result.status==4 and not result.returned and result.steps==budget,'cross-callback budget escaped')
                    require(result.callback_returns<=result.callback_calls<=(2 if name=='nested' else 1) and
                            result.max_callback_depth<=(2 if name=='nested' else 1),'fault counter invariant')
                    if result.callback_calls and result.callback_returns<result.callback_calls:
                        require(result.fault['pc']!=fixture['image_base']+fixture['labels']['main_after_call'],
                                'failed callback continued caller')
                    records.append({'kind':'budget','mode':optimization,'fixture':name,'budget':budget,'fault':result.fault,
                                    'api_calls':result.api_calls,'callback_calls':result.callback_calls,
                                    'callback_returns':result.callback_returns,'status':'PASS'})
                stack=Region(0x70000000,bytearray(65536),bytearray([1]+[3]*15));original=bytes(stack.data)
                result=program.run(gpr={'RCX':1,'RDX':2,'R8':3,'R9':4},stack_args=[5,6],stack=stack,rsp=stack.base+0x1078)
                require(result.status==2 and result.api_calls==result.callback_calls==result.callback_returns==0,'callback frame rights check')
                require(stack.data[0xff8:0x1000]==original[0xff8:0x1000],'rejected callback frame partially wrote return slot')
                records.append({'kind':'readonly_callback_frame','mode':optimization,'fixture':name,'fault':result.fault,'status':'PASS'})
                result=program.run(gpr={'RCX':1,'RDX':2,'R8':3,'R9':4},stack_args=[5,6],return_address=0)
                require(result.status==5 and result.callback_returns==(2 if name=='nested' else 1) and
                        result.api_calls==(2 if name=='nested' else fixture['api_calls']),
                        'post-callback outer return failure')
                records.append({'kind':'outer_bad_return','mode':optimization,'fixture':name,'status':'PASS'})
                mapped=load_image(program.source_bytes);mapped.data[fixture['callback_rva']]^=1
                rejected(lambda:program.run(regions=[Region(mapped.base,mapped.data,mapped.permissions)]),'changed callback bytes')
                records.append({'kind':'callback_code_identity','mode':optimization,'fixture':name,'status':'PASS'})
                if name=='import':
                    mapped=load_image(program.source_bytes);binding=next(x for x in mapped.imports if x['signature']==2)
                    struct.pack_into('<Q',mapped.data,binding['iat_rva'],mapped.base+binding['target_rva']+8)
                    result=program.run(gpr={'RCX':1,'RDX':2,'R8':3,'R9':4},stack_args=[5,6],regions=[Region(mapped.base,mapped.data,mapped.permissions)])
                    require(result.status==6 and result.callback_calls==1 and result.callback_returns==0 and result.api_calls==1,
                            'nested imported-call failure continued outer native function')
                    require(result.fault['pc']==mapped.base+fixture['labels']['callback_call'],'wrong nested failure PC')
                    records.append({'kind':'nested_bad_IAT','mode':optimization,'fixture':name,'fault':result.fault,'status':'PASS'})
                if name=='nested':
                    result=program.run(gpr={'RCX':16,'RDX':2,'R8':3,'R9':4},stack_args=[5,6])
                    require(result.status==8 and result.callback_calls==result.api_calls==result.max_callback_depth==16 and
                            result.callback_returns==0 and not result.returned,'callback depth cap did not propagate')
                    recovered=program.run(stack_args=[0,0])
                    require(recovered.status==0 and recovered.registers['RAX']==47 and recovered.callback_returns==1,
                            'failed nested callback leaked host session state into next run')
                    records.append({'kind':'nested_depth_cap_and_reset','mode':optimization,'fixture':name,
                                    'fault':result.fault,'call_depth':result.call_depth,'status':'PASS'})
        # Mutate producer-owned artifacts/metadata, then restore exact bytes.
        # Gates run with explicit exceptions and remain active under python -O.
        root=programs[('O3','leaf')].roots[1];directory=root['directory'];manifest=root['manifest']
        object_path=directory/'arm64.o';object_bytes=object_path.read_bytes()
        try:
            object_path.write_bytes(programs[('O3','leaf')].out.joinpath('ret-shim/arm64.o').read_bytes())
            rejected(lambda:verify_lift(directory,manifest,programs[('O3','leaf')].source_sha256,root['symbol'],root['rva']),
                     'substituted actual callback object')
        finally:object_path.write_bytes(object_bytes)
        manifest_path=directory/'manifest.json';manifest_bytes=manifest_path.read_bytes()
        for collection,key in [('artifact_sha256','arm64.o'),('source_sha256','callback_bridge/lift.py'),
                               ('external_source_sha256','callback_bridge/imports_v1.py')]:
            changed=copy.deepcopy(manifest);del changed[collection][key]
            try:
                manifest_path.write_text(json.dumps(changed))
                rejected(lambda:verify_lift(directory,changed,programs[('O3','leaf')].source_sha256,root['symbol'],root['rva']),
                         'self-reported omitted dependency '+key)
            finally:manifest_path.write_bytes(manifest_bytes)
        conflicting=copy.deepcopy(root);conflicting['manifest']['instructions'][0]['kind']=2
        rejected(lambda:merge_instructions([root,conflicting],programs[('O3','leaf')].image),'conflicting root metadata')
        records.append({'kind':'build_identity_gates','rejections':5,'status':'PASS'})
        # Same original PE path/output: only the callback body changes between A and B.
        changing=out/'identity/source.exe';changing.parent.mkdir(exist_ok=True)
        original=(ROOT/'build/callback-bridge/fixtures/leaf.exe').read_bytes();changing.write_bytes(original)
        first=Program(changing,out/'identity/shared',callbacks=registry(fixtures['leaf']))
        inputs[str(first.library_path)]=first.library_sha256
        altered=original.replace(b'\x48\x83\xc0\x11',b'\x48\x83\xc0\x12')
        require(altered!=original and len(altered)==len(original),'callback mutation missing');changing.write_bytes(altered)
        second=Program(changing,out/'identity/shared',callbacks=registry(fixtures['leaf']))
        inputs[str(second.library_path)]=second.library_sha256
        changing.write_bytes(original);third=Program(changing,out/'identity/shared',callbacks=registry(fixtures['leaf']))
        inputs[str(third.library_path)]=third.library_sha256
        for p,want in [(first,47),(second,48),(third,47)]:
            result=p.run(stack_args=[0,0]);require(result.status==0 and result.registers['RAX']==want,'callback A/B/A stale cache')
            artifacts.append(p.library_path)
        inputs.update(third.build_manifest['native_inputs']);artifacts.extend(third.out.rglob('*'))
        records.append({'kind':'callback_A_B_A','status':'PASS','libraries':[str(p.library_path) for p in (first,second,third)],
                        'input_sha256':[p.source_sha256 for p in (first,second,third)]})
        unchanged(before);unchanged(inputs)
        result={'schema':1,'status':'PASS','vectors_per_fixture':count,'unique_normal_inputs':len(NAMES)*count,
                'raw_x86_cases':len(NAMES)*count,'modes':['O3','O0'],'records':records,
                'unique_budget_cases':sum(r['kind']=='budget' and r['mode']=='O3' for r in records),
                'inputs_before':inputs,'inputs_after':snapshot(inputs),
                'artifacts_sha256':{str(p.resolve()):sha(p) for p in sorted(set(artifacts)) if p.is_file() and p.name!='.program-build.lock'},
                'limits':['raw x86 oracle is Rosetta, not Windows','GPR/full return checked; not complete Remill State equivalence',
                          'only explicit synchronous six-u64 callbacks; no arbitrary callback discovery',
                          'trusted host metadata and allocations; no security-boundary claim']}
        evidence_path.write_text(json.dumps(result,indent=2)+'\n');verify_evidence(out)
        print(json.dumps({'status':'PASS','unique_normal_inputs':len(NAMES)*count,'unique_budget_cases':result['unique_budget_cases']}))
    except Exception as error:
        evidence_path.write_text(json.dumps({'status':'FAIL','error':str(error)},indent=2)+'\n');raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT)
    parser.add_argument('--count',type=int,default=512);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    if args.verify:
        result=verify_evidence(args.out);print(json.dumps({'status':'PASS_CURRENT','unique_normal_inputs':result['unique_normal_inputs']}))
    else:
        require(args.count>0,'positive vector count required');run(args.out,args.count)
