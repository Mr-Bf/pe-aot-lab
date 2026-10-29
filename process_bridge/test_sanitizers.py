#!/usr/bin/env python3
"""Actual process-entry PE LLVM/C sanitizers and terminal-state boundaries."""
import argparse,json,os,re,shlex,shutil,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent;WORKSPACE=ROOT.parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from native_bridge.test_sanitizers import require,sha,identity,unchanged,local_python_closure,run,instrument,LLVM
from process_bridge.lift import lift_pe,build_ret_shim
from process_bridge.loader import load_image
from process_bridge.bindings import verify_lift
from callback_bridge.fixtures import pe_image,make_idata
OUT=ROOT/'build/process-bridge/sanitizers';NAMES=('normal','open_exit','after_exit','return_only','exit_only')
LOG_NAMES=('dependencies','dependencies-recheck','main-build','main-symbols','ret_shim-build','ret_shim-symbols',
           'compile-plain','compile-sanitized','ubsan-symbols','linked','asan-link','asan-sign','plain-run','sanitized-run')


def initial_paths(fixtures):
    paths=[HERE/n for n in ('test_sanitizers.py','sanitizer_driver.c','runtime.c','runtime.h','bindings.py','loader.py','lift.py','fixtures.py','process_fixture.c','kernel32.def')]
    paths += list(local_python_closure(paths))
    paths += [ROOT/'build/process-bridge/fixtures/manifest.json',*[Path(fixtures[n]['pe_path']) for n in NAMES[:4]],
              ROOT/'integration_stage3/runtime.c',ROOT/'integration_stage3/runtime.h',ROOT/'file_bridge/runtime.h',
              ROOT/'memory_stage2/guest_memory.h',Path(sys.executable),LLVM/'clang',LLVM/'opt',LLVM/'llvm-symbolizer',
              *[Path(shutil.which(n)) for n in ('xcrun','nm','otool','install_name_tool','codesign')]]
    return paths


def dependency_command(folder):
    sdk=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip()
    return list(map(str,[LLVM/'clang','-target','arm64-apple-macos11','-isysroot',sdk,'-std=c11','-O1',
                '-fsanitize=address,undefined','-I',HERE,'-I',folder,'-M','-MT','process-driver',HERE/'sanitizer_driver.c']))


def fixture_artifacts(folder):
    return [folder/n for n in ('input.exe','sanitizer_fixture.h','process-plain','process-sanitized','driver.d',
             'main-asan.ll','main-asan.o','ret_shim-asan.ll','ret_shim-asan.o')]+[folder/(n+'.log') for n in LOG_NAMES]


def no_noreturn(ir):
    text=ir.read_text();attributes={k:v for k,v in re.findall(r'^attributes #(\d+) = \{([^\n]*)\}',text,re.M)};checked=0
    for line in text.splitlines():
        if '@__remill_function_call(' in line or (line.startswith('define ') and any('@'+symbol+'(' in line for symbol in ('aot_entry','aot_import_ret'))):
            combined=line+' '+' '.join(attributes.get(k,'') for k in re.findall(r'#(\d+)',line))
            require(not re.search(r'\bnoreturn\b',combined),'returning C path falsely marked noreturn');checked+=1
    require(checked>0,'entry/helper attribute review found nothing');return checked


def prepare(pe,folder,metadata,variant):
    folder.mkdir(parents=True,exist_ok=True);main=lift_pe(pe,folder/'compiler');ret=build_ret_shim(folder/'ret-shim');image=load_image(pe)
    verify_lift(folder/'compiler',main,sha(pe),'aot_entry');verify_lift(folder/'ret-shim',ret,sha(folder/'ret-shim/synthetic-ret.exe'),'aot_import_ret')
    imports={r['iat_rva']:r for r in image.imports};rows=[];calls=[]
    for ins in main['instructions']:
        target=ins.get('target_rva') or 0;slot=ins.get('iat_slot_rva');kind=ins['kind']
        if slot:
            binding=imports[slot];target=binding['target_rva'];calls.append((ins['rva'],slot,target,binding['signature']))
        rows.append((ins['rva'],ins['length'],kind,target))
    thunks=sorted({r['target_rva'] for r in image.imports});rows += [(r,1,2,0) for r in thunks]
    (folder/'native_imports.h').write_text('#define AOT_IMPORT_CALL_COUNT %du\nstatic const AotImportCall aot_import_calls[]={%s};\n'%(len(calls),','.join('{%du,%du,%du,%du}'%r for r in calls) if calls else '{0,0,0,0}'))
    values={'Variant':variant,'ThunkCount':len(thunks),'ImportCount':len(image.imports),'RelocCount':len(image.relocations),
            'PreferredBase':image.preferred_base,'EntryRva':image.entry_rva,'ExitCode':metadata.get('expected_exit_code') or 0,
            'SourceRva':metadata.get('source_rva',0),'SourceLength':metadata.get('source_length',0),
            'DestinationRva':metadata.get('destination_rva',0),'ResultRva':metadata.get('result_rva',0),
            'MarkerRva':metadata.get('marker_rva',0),'CallerMarkerRva':metadata.get('caller_marker_rva',0),
            'ExitThunk':next((r['target_rva'] for r in image.imports if r['signature']==9),0),
            'ExitIat':next((r['iat_rva'] for r in image.imports if r['signature']==9),0)}
    text='/* Actual image and instruction metadata, test-only private entry noted in evidence. */\n'
    for k,v in values.items():text+='static const %s k%s=%s;\n'%('uint64_t' if k in ('PreferredBase','ExitThunk') else 'unsigned',k,'UINT64_C(%d)'%v if k in ('PreferredBase','ExitThunk') else str(v))
    for label,vs in [('IatRvas',[r['iat_rva'] for r in image.imports]),('ImportTargets',[r['target_rva'] for r in image.imports]),
                     ('Thunks',thunks),('RelocRvas',[r['rva'] for r in image.relocations]),('RelocOld',[r['old'] for r in image.relocations])]:
        text+='static const uint64_t k%s[]={%s};\n'%(label,','.join('UINT64_C(%d)'%v for v in vs) if vs else '0')
    text+='static const uint8_t kImage[]={'+','.join(map(str,image.data))+'};\n'
    text+='static const uint8_t kImagePermissions[]={'+','.join(map(str,image.permissions))+'};\n'
    text+='static const AotInstruction kInstructions[]={'+','.join('{%d,%d,%d,0,UINT64_C(%d)}'%r for r in rows)+'};\n'
    header=folder/'sanitizer_fixture.h';header.write_text(text)
    return main,ret,header


def validate_report(r,name):
    require(r.get('status')=='PASS' and r.get('variant')==NAMES.index(name)+1 and r.get('normal_cases')==16,'runtime cases incomplete')
    require(r.get('budget_cuts')==r.get('success_steps',0)-1 and r.get('exact_budget_success')==1,'budget boundary absent')
    require(r.get('bad_exit_IAT')==int(name!='return_only'),'bad Exit IAT coverage')
    require(r.get('private_boundaries')==(3 if name=='exit_only' else 0),'private Exit boundaries missing')
    expected=16+r['success_steps']+int(name!='return_only')+(4 if name=='exit_only' else 0)
    require(r.get('public_reentry_checks')==expected,'reentry/lifecycle execution count changed')
    require(r.get('terminal_no_mutation_checks')==expected-(17 if name=='return_only' else 1 if name=='exit_only' else 0),'terminal latch coverage changed')


def verify_evidence(out=OUT):
    out=Path(out).resolve();e=json.loads((out/'evidence.json').read_text());require(e.get('schema')==1 and e.get('status')=='PASS','process sanitizer evidence not PASS')
    require(set(e['fixtures'])==set(NAMES),'missing fixture closure');require(e['inputs_before']==e['inputs_after'],'inputs changed');unchanged(e['inputs_before'])
    fixtures=json.loads((ROOT/'build/process-bridge/fixtures/manifest.json').read_text());initial=initial_paths(fixtures)
    all_inputs=set(map(lambda p:str(p.absolute()),initial));expected_artifacts=[]
    asan_source=LLVM.parent/'lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib'
    asan_copy=WORKSPACE/'work/process-bridge/sanitizers-runtime'/asan_source.name
    for name,r in e['fixtures'].items():
        folder=out/name;pe=folder/'input.exe'
        require(r['status']=='PASS' and r['input_pe_sha256']==sha(pe),'fixture status/identity changed')
        if name!='exit_only':require(sha(pe)==fixtures[name]['pe_sha256']==sha(fixtures[name]['pe_path']),'original PE identity changed')
        dependencies=subprocess.check_output(dependency_command(folder),text=True)
        require(dependencies==(folder/'driver.d').read_text(),'C dependency discovery changed')
        paths=[*initial,*[Path(p) for p in shlex.split(dependencies.replace('\\\n',' ').split(':',1)[1])],
               pe,folder/'sanitizer_fixture.h',asan_source,asan_copy]
        for label,directory,symbol,input_path in [('main',folder/'compiler','aot_entry',pe),
                ('ret_shim',folder/'ret-shim','aot_import_ret',folder/'ret-shim/synthetic-ret.exe')]:
            manifest=json.loads((directory/'manifest.json').read_text());verify_lift(directory,manifest,sha(input_path),symbol)
            paths += [directory/'manifest.json',*[Path(p) for p in manifest['inputs_after']],
                      *[directory/p for p in manifest['artifact_sha256']],
                      *[ROOT/p for field in ('source_sha256','external_source_sha256') for p in manifest[field]]]
            require(r['returning_function_attribute_checks'][label]==no_noreturn(directory/'arm64.ll'),'returning helper review changed')
        required_inputs=set(str(p.absolute()) for p in paths)
        require(set(r['inputs_before'])==required_inputs,'fixture dependency closure incomplete or unknown')
        all_inputs.update(required_inputs);expected_artifacts += fixture_artifacts(folder)
        require(r['reports']['plain']==r['reports']['sanitized'],'replays differ');require(r['inputs_before']==r['inputs_after'],'fixture inputs changed');unchanged(r['inputs_before'])
        require(set(r['instrumented_lifted_functions'])=={'main','ret_shim'} and all(r['instrumented_lifted_functions'].values()),'actual roots absent')
        for mode in ('plain','sanitized'):
            validate_report(r['reports'][mode],name);execution=r['executions'][mode]
            require(execution['inputs_before']==execution['inputs_after'],'execution artifacts changed');unchanged(execution['inputs_before'])
            require(sha(execution['log'])==execution['log_sha256'],'log changed')
            require(Path(execution['log']).resolve()==folder/(mode+'-run.log'),'execution log path mismatch')
            require(json.loads(Path(execution['log']).read_text().split('\n',1)[1])==r['reports'][mode],'report differs from actual execution log')
            actual_disk={str(p.relative_to(folder/(mode+'-files'))):sha(p) for p in (folder/(mode+'-files')).rglob('*') if p.is_file()}
            require(actual_disk==r['disk_sha256'][mode],'disk evidence incomplete or changed')
            for file,digest in r['disk_sha256'][mode].items():require(sha(out/name/(mode+'-files')/file)==digest,'disk output changed')
        require(r['disk_sha256']['plain']==r['disk_sha256']['sanitized'],'disk replays differ')
    require(set(e['inputs_before'])==all_inputs,'global dependency closure incomplete or unknown')
    require(set(e['artifacts_sha256'])=={str(p.relative_to(ROOT)) for p in expected_artifacts},'artifact closure incomplete or unknown')
    for path,digest in e['artifacts_sha256'].items():require(sha(ROOT/path)==digest,'artifact changed')
    return e


def main(out=OUT):
    out=Path(out).resolve();require(out.is_relative_to(ROOT/'build/process-bridge'),'private output required');out.mkdir(parents=True,exist_ok=True)
    evidence=out/'evidence.json'
    if evidence.exists():
        history=out/'history';history.mkdir(exist_ok=True);(history/(sha(evidence)+'.json')).write_bytes(evidence.read_bytes())
    evidence.write_text('{"status":"RUNNING"}\n')
    try:
        manifest=ROOT/'build/process-bridge/fixtures/manifest.json';fixtures=json.loads(manifest.read_text())
        initial=initial_paths(fixtures)
        before=identity(initial);all_inputs=dict(before)
        sdk=Path(subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip());asan_source=LLVM.parent/'lib/clang/17/lib/darwin/libclang_rt.asan_osx_dynamic.dylib'
        support=WORKSPACE/'work/process-bridge/sanitizers-runtime';support.mkdir(parents=True,exist_ok=True);asan_copy=support/asan_source.name;asan_copy.write_bytes(asan_source.read_bytes())
        run(['install_name_tool','-id',asan_copy,asan_copy],out/'asan-id.log');run(['codesign','--force','--sign','-',asan_copy],out/'asan-sign.log')
        records={};artifacts=[]
        for variant,name in enumerate(NAMES,1):
            folder=out/name;folder.mkdir(exist_ok=True);pe=folder/'input.exe'
            if name=='exit_only':
                imported=[('kernel32.dll','ExitProcess',9)];_,slots,*_=make_idata(imported);slot=slots['ExitProcess']['iat_rva']
                code=bytes.fromhex('4883ec28b92a000000ff15')+struct.pack('<i',slot-(0x1000+15))+bytes.fromhex('4883c428c3')
                pe.write_bytes(pe_image(code,imported));metadata={'expected_exit_code':42,'scope':'private self-authored Exit-only boundary PE, not public fixture'}
            else:
                metadata=fixtures[name];source=Path(metadata['pe_path']);require(sha(source)==metadata['pe_sha256'],'fixture stale');pe.write_bytes(source.read_bytes())
            main_m,ret_m,header=prepare(pe,folder,metadata,variant)
            roots=[('main',folder/'compiler',main_m),('ret_shim',folder/'ret-shim',ret_m)]
            common=[LLVM/'clang','-target','arm64-apple-macos11','-isysroot',sdk,'-Wl,-syslibroot,'+str(sdk),'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-I',HERE,'-I',folder]
            dep_command=dependency_command(folder)
            deps=run(dep_command,folder/'dependencies.log');(folder/'driver.d').write_text(deps)
            dependencies=[Path(p) for p in shlex.split(deps.replace('\\\n',' ').split(':',1)[1])]+[pe,header,asan_source,asan_copy]
            checked={}
            for label,directory,m in roots:
                dependencies.append(directory/'manifest.json');require(m['inputs_before']==m['inputs_after'],'lift inputs changed')
                for file,digest in m['inputs_after'].items():require(sha(file)==digest,'lift dependency changed');dependencies.append(Path(file))
                for file,digest in m['artifact_sha256'].items():require(sha(directory/file)==digest,'lift artifact changed');dependencies.append(directory/file)
                for field in ('source_sha256','external_source_sha256'):
                    for file,digest in m[field].items():require(sha(ROOT/file)==digest,'lift source changed');dependencies.append(ROOT/file)
                checked[label]=no_noreturn(directory/'arm64.ll')
            inputs=identity([*initial,*dependencies]);all_inputs.update(inputs);objects=[];plain_objects=[];instrumented={}
            for label,directory,_ in roots:
                ir=folder/(label+'-asan.ll');obj=folder/(label+'-asan.o');instrumented[label]=instrument(directory/'arm64.ll',ir)
                run([LLVM/'clang','-target','arm64-apple-macos11','-O1','-fsanitize=address','-c',ir,'-o',obj],folder/(label+'-build.log'))
                require('__asan_report_' in run(['nm',obj],folder/(label+'-symbols.log')),'actual IR lacks ASan');objects.append(obj);plain_objects.append(directory/'arm64.o');artifacts += [ir,obj]
            plain=folder/'process-plain';sanitized=folder/'process-sanitized'
            run(common+[HERE/'sanitizer_driver.c',*plain_objects,'-o',plain],folder/'compile-plain.log')
            run(common+['-fsanitize=address,undefined',HERE/'sanitizer_driver.c',*objects,'-o',sanitized],folder/'compile-sanitized.log')
            require('__ubsan_handle_' in run(['nm',sanitized],folder/'ubsan-symbols.log'),'C lacks UBSan')
            linked=run(['otool','-L',sanitized],folder/'linked.log');names=[l.strip().split(' (',1)[0] for l in linked.splitlines()[1:] if asan_source.name in l];require(len(names)==1,'ASan runtime linkage')
            run(['install_name_tool','-change',names[0],asan_copy,sanitized],folder/'asan-link.log');run(['codesign','--force','--sign','-',sanitized],folder/'asan-sign.log')
            env={**os.environ,'ASAN_OPTIONS':'halt_on_error=1:detect_leaks=0','UBSAN_OPTIONS':'halt_on_error=1:print_stacktrace=1','ASAN_SYMBOLIZER_PATH':str(LLVM/'llvm-symbolizer')}
            reports={};executions={};disk={}
            for mode,exe,environment in [('plain',plain,None),('sanitized',sanitized,env)]:
                files=folder/(mode+'-files');files.mkdir(exist_ok=True);stable=identity([exe,asan_copy,*objects] if mode=='sanitized' else [exe]);log=folder/(mode+'-run.log')
                report=json.loads(run([exe,files],log,environment));validate_report(report,name);unchanged(stable)
                reports[mode]=report;executions[mode]={'inputs_before':stable,'inputs_after':identity(stable),'log':str(log),'log_sha256':sha(log)}
                disk[mode]={str(p.relative_to(files)):sha(p) for p in sorted(files.rglob('*')) if p.is_file()}
            require(reports['plain']==reports['sanitized'] and disk['plain']==disk['sanitized'],'replay differs')
            require(run(dep_command,folder/'dependencies-recheck.log')==deps,'C closure changed');unchanged(inputs)
            verify_lift(folder/'compiler',main_m,sha(pe),'aot_entry');verify_lift(folder/'ret-shim',ret_m,sha(folder/'ret-shim/synthetic-ret.exe'),'aot_import_ret')
            records[name]={'status':'PASS','input_pe_sha256':sha(pe),'scope':metadata.get('scope','original compiler no-argument PE'),
                           'reports':reports,'executions':executions,'disk_sha256':disk,'instrumented_lifted_functions':instrumented,
                           'returning_function_attribute_checks':checked,'inputs_before':inputs,'inputs_after':identity(inputs)}
            artifacts += [pe,header,plain,sanitized,folder/'driver.d',*folder.glob('*.log')]
        unchanged(before);unchanged(all_inputs)
        result={'schema':1,'status':'PASS','fixtures':records,'inputs_before':all_inputs,'inputs_after':identity(all_inputs),
                'artifacts_sha256':{str(p.relative_to(ROOT)):sha(p) for p in sorted(set(artifacts))},
                'limits':['single guest thread/noDLL exit subset','Exit status is distinct from host OS exit status','ASan does not prove LLVM noalias/noreturn semantics','LeakSanitizer disabled'],
                'sanitizer_environment':{k:env[k] for k in ('ASAN_OPTIONS','UBSAN_OPTIONS','ASAN_SYMBOLIZER_PATH')}}
        evidence.write_text(json.dumps(result,indent=2)+'\n');verify_evidence(out)
        print(json.dumps({'status':'PASS','fixtures':len(records),'budget_cuts':sum(r['reports']['plain']['budget_cuts'] for r in records.values()),
                          'actual_executions_per_mode':sum(r['reports']['plain']['public_reentry_checks'] for r in records.values())}))
    except Exception as error:evidence.write_text(json.dumps({'status':'FAIL','error':str(error)},indent=2)+'\n');raise

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT);parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    if args.verify:verify_evidence(args.out);print('{"status":"PASS_CURRENT"}')
    else:main(args.out)
