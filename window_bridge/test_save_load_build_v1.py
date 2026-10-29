"""Static save/load consumer checks only. Never invoke Program.run or load code."""
import copy, json, struct, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from window_bridge import save_load_bindings_v1 as b
OUT=ROOT/'build/window-bridge/save-load-static-review-v1'
PROGRAM=ROOT/'build/window-bridge/save-load-program-v1-01'
MODE='optimized' if sys.flags.optimize else 'ordinary'
def require(value,reason):
    if not value:raise RuntimeError(reason)
def rejected(name,operation,reason):
    try:operation()
    except ValueError as error:
        require(reason in str(error),'wrong rejection '+name+': '+str(error));return {'case':name,'rejected':True,'reason':str(error)}
    raise RuntimeError('expected rejection '+name)

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    program=b.Program.from_build(PROGRAM);record=program.verify_build();metadata=b.fixture_metadata()
    require(record['status']=='BUILT_NATIVE_SAVE_LOAD_WINDOW_PE_NOT_EXECUTED','wrong build status')
    require(record['input_sha256']==b.PE_SHA and len(record['imports'])==21,'fixed original PE/import closure')
    require(record['observations']==metadata['observations'] and len(record['observations'])==14,'new observation closure')
    require(record['observations']['window_load_result']=={'rva':0x30fc,'size':36} and
            record['observations']['window_load_candidate']=={'rva':0x3120,'size':20},'load observations')
    calls=[r for r in record['calls'] if r['signature']==6]
    require(len(calls)==2 and all(r['iat_rva']==0x2728 for r in calls),'two real ReadFile call sites')
    rows=record['commands'];units=program.compilation_units()
    require(len(rows)==6,'five actual native compiles plus link required')
    for (name,compiler,flags),command in zip(units,rows[:5],strict=True):
        expected=list(map(str,[compiler,*flags,'-c',b.HERE/name,'-o',PROGRAM/(name.replace('/','__')+'.o')]))
        require(command==expected,'native compilation not recorded for '+name)
        dep=record['dependency_graphs'][name];actual=b.graphics.dependency_paths(dep)
        generated={'window_host.c':'native_image.h','window_runtime/runtime.c':'native_imports.h'}.get(name)
        if generated:require([Path(p).resolve() for p in actual if Path(p).name==generated]==[PROGRAM/generated], 'old generated header mixed in')
    linked=record['commands'][-1]
    expected_objects=[PROGRAM/(name.replace('/','__')+'.o') for name,_,_ in units]+[
        PROGRAM/'compiler/main/arm64.o',PROGRAM/'compiler/window-proc-1000/arm64.o',PROGRAM/'ret-shim/arm64.o']
    require({x for x in linked if x.endswith('.o')}==set(map(str,expected_objects)),'wrong native/guest object link set')
    exe=program.executable.read_bytes()
    require(struct.unpack_from('<II',exe)==(0xfeedfacf,0x100000c),'not thin ARM64 executable')
    require(b.PE_SHA.encode() in exe and b'window_load_result' in exe and b'window_load_candidate' in exe,'new PE/observations not embedded')
    require(b'a9997a6e542efee64c19d8a2ac343d28e294341a187ab954b9d8e0a6a9824da1' not in exe,'old positive image leaked')
    require(len(record['executable_graph']['nodes'])==4,'expected executable+three backend libraries')
    negatives=[rejected('old_output_namespace',lambda:b.output_directory(ROOT/'build/window-bridge/program-build-03'),'separate save-load')]
    target=ROOT/'build/window-bridge'/('save-load-program-rejections-'+MODE)
    negatives.append(rejected('old_save_only_PE',lambda:b.Program(ROOT/'build/window-bridge/prepared-v2/integer-tile.exe',target/'old-pe'),'metadata refers to another PE'))
    bad=copy.deepcopy(metadata);bad['observations']['window_load_result']['size']=35
    negatives.append(rejected('wrong_load_observation_size',lambda:b.Program(b.PREPARED/'integer-tile.exe',target/'wrong-metadata',metadata=bad),'closed save/load window metadata differs'))
    candidate=copy.copy(program);candidate.roots=copy.deepcopy(program.roots)
    ins=next(i for i in candidate.roots[0]['manifest']['instructions'] if i.get('signature')==6);ins['signature']=5
    negatives.append(rejected('ReadFile_rebound_to_WriteFile',lambda:b.generate_headers(candidate,metadata,write=False),'IAT metadata target/signature differs'))
    for child in ('old-pe','wrong-metadata'):
        area=target/child
        require((area/'started.json').exists() and not (area/'compiler').exists() and not list(area.rglob('*.o')),'negative unexpectedly reached compile')
    proof={'status':'PASS_STATIC_SAVE_LOAD_NATIVE_BUILD','mode':MODE,'program_build_sha256':b.sha(PROGRAM/'program-build.json'),
        'original_pe_sha256':b.PE_SHA,'native_sha256':program.executable_sha256,'root_count':len(program.roots),
        'reachable_original_instructions':len(program.root_manifest['instructions']),'imports':21,'readfile_calls':calls,
        'observations':14,'native_units_recompiled':[name for name,_,_ in units],'native_object_reuse':False,
        'negative_checks':negatives,'guest_executions':0,'window_executions':0,'gpu_executions':0,'save_load_executions':0,
        'identities':b.snapshot([Path(__file__),Path(b.__file__),PROGRAM/'program-build.json',program.executable,
            b.PREPARED/'manifest.json',b.PREPARED/'evidence.json',*(target/child/'started.json' for child in ('old-pe','wrong-metadata'))]),
        'scope':'build/identity/schema gates only; no native code loaded or launched, no successful save/restore acceptance'}
    with (OUT/(MODE+'-evidence.json')).open('x') as stream:json.dump(proof,stream,indent=2);stream.write('\n')
    print(json.dumps({k:v for k,v in proof.items() if k!='identities'},indent=2))

if __name__=='__main__':main()
