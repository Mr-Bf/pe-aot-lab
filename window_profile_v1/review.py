"""Independent stdlib-only evidence reader; never imports or runs the producer."""
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT=Path(__file__).resolve().parents[1]
BUILD=ROOT/'build/migration-v3/configured-02'
RUNS=ROOT/'build/migration-v3/execution-02'
checked={}


def require(ok,message):
    if not ok:raise ValueError(message)


def read(path,expected=None):
    path=Path(path);data=path.read_bytes();digest=hashlib.sha256(data).hexdigest()
    require(expected is None or expected==digest,'file digest: '+str(path))
    require(str(path) not in checked or checked[str(path)]==digest,'file changed during review')
    checked[str(path)]=digest
    return data


def js(path,expected=None):return json.loads(read(path,expected))


def identities(table):
    for path,digest in table.items():read(path,digest)


def offset(data,rva,length):
    pe=struct.unpack_from('<I',data,60)[0];count=struct.unpack_from('<H',data,pe+6)[0]
    optional=struct.unpack_from('<H',data,pe+20)[0];found=[]
    for i in range(count):
        at=pe+24+optional+40*i
        _,start,size,file=struct.unpack_from('<4I',data,at+8)
        if start<=rva and rva+length<=start+size:found.append(file+rva-start)
    require(len(found)==1,'unique file-backed instruction range required')
    return found[0]


def command_log(path):
    commands=[]
    for line in read(path).decode().splitlines():
        if line.startswith('["'):
            try:value=json.loads(line)
            except json.JSONDecodeError:continue
            if type(value) is list and all(type(x) is str for x in value):commands.append(value)
    return commands


def product(directory,accepted):
    record=js(directory/'result.json',accepted['receipt_sha256'])
    require(record['status']=='BUILT_NATIVE_WINDOW_NOT_PACKAGED_NOT_EXECUTED','build status')
    actual=set()
    for path in directory.rglob('*'):
        require(not path.is_symlink(),'symlink in product')
        relative=path.relative_to(directory)
        if relative in (Path('result.json'),Path('native/.program-build.lock')) or relative.is_relative_to('native/cache'):continue
        if path.is_file():actual.add(str(relative))
    require(actual==set(record['files']),'actual artifact closure')
    for name,item in record['files'].items():
        path=directory/name;read(path,item['sha256'])
        require(path.stat().st_mode&0o777==item['mode'],'actual artifact mode')
    identities(record['sources']);identities(record['source_inputs'])
    require({str(ROOT/'window_profile_v1'/name) for name in ('profile.py','build.py','bindings.py')}<=set(record['sources']),
            'configured producer sources absent')
    profile=js(directory/'profile.json');data=read(directory/'input.exe',accepted['input_sha256'])
    require(data==read(directory/'native/input.exe'),'input snapshot bytes')
    require(profile==js(directory/'native/window-profile.json'),'caller profile snapshot')
    require(profile['pe_sha256']==accepted['input_sha256'],'profile PE binding')
    native=js(directory/'native/program-build.json')
    require(native['native_inputs']==native['native_inputs_after']==record['source_inputs'],'native input closure')
    require(str(ROOT/'window_bridge/fixture_v2.cpp') not in native['native_inputs'],'unexpected fixed fixture dependency')
    require(native['compile_inputs_before']==native['compile_inputs_after'],'native compile inputs changed')
    identities(native['artifacts'])
    commands=command_log(directory/'native/native-build.log')
    require(len(native['commands'])==6 and all(command in commands for command in native['commands']),
            'five actual native compilations and link required')
    require(all('-c' in command for command in native['commands'][:5]),'native compilation omitted')
    require(all(str(directory/'native') in command[-1] for command in native['commands'][:5]),'new native object destinations')
    roots=js(directory/'native/compiler/roots.json');all_instructions={}
    pe=struct.unpack_from('<I',data,60)[0];image_base=struct.unpack_from('<Q',data,pe+24+24)[0]
    require([r['rva'] for r in roots['roots']]==profile['callback_rvas'],'configured roots differ')
    require(roots['input_sha256']==accepted['input_sha256'],'root input identity')
    for root in [roots['main'],*roots['roots']]:
        location=Path(root['directory']);manifest=js(location/'manifest.json')
        require(manifest==root['manifest'] and manifest['input_sha256']==accepted['input_sha256'],'root manifest identity')
        require(manifest['inputs_before']==manifest['inputs_after'],'lift inputs differ')
        identities(manifest['inputs_before'])
        for name,digest in manifest['artifact_sha256'].items():read(location/name,digest)
        logged=command_log(location/'commands.log')
        require(any('--entry_address='+str(manifest['entry_rva']+image_base) in c for c in logged), 'actual decoder root command')
        require(any(str(location/'arm64.o') in c for c in logged),'actual ARM64 object command')
        require(str(location/'arm64.o') in native['commands'][-1],'new root object absent from link')
        for instruction in manifest['instructions']:
            rva=instruction['rva'];length=instruction['length'];at=offset(data,rva,length)
            require(data[at:at+length].hex()==instruction['bytes'],'instruction differs from input PE bytes')
            require(rva not in all_instructions or all_instructions[rva]==instruction,'root overlap differs')
            all_instructions[rva]=instruction
    require([all_instructions[r] for r in sorted(all_instructions)]==roots['instructions'],'merged instruction table')
    require(len(all_instructions)==643==accepted['instructions'],'instruction count')
    exe=read(record['executable'],accepted['executable_sha256'])
    require(struct.unpack_from('<III',exe)==(0xfeedfacf,0x100000c,0),'thin ARM64 executable')
    require(struct.unpack_from('<I',exe,12)[0]==2,'Mach-O file type')
    return record,native,profile,data


def main():
    derivation=js(ROOT/'window_profile_v1/derivation.json')
    before=read(derivation['base'],derivation['base_sha256']).decode()
    reverse=read(derivation['derived'],derivation['derived_sha256']).decode()
    for change in reversed(derivation['replacements']):
        require(reverse.count(change['new'])==change.get('count',1),'derivation edit count')
        reverse=reverse.replace(change['new'],change['old'])
    require(reverse==before,'reversible derivation differs')
    builds=js(BUILD/'evidence.json');runs=js(RUNS/'evidence.json')
    require(builds['status']=='PASS_REAL_CONFIGURED_BUILDS_NOT_EXECUTED','build batch failed')
    read(BUILD/'evidence.json',runs['build_receipt_sha256'])
    require(runs['status']=='PASS_TWO_CONFIGURED_PES_TWO_PROCESS_RESTORE' and len(runs['runs'])==4,'execution batch failed')
    require(len(builds['commands'])==11,'CLI command chain incomplete')
    for command in builds['commands']:
        output=js(command['stdout'],command['stdout_sha256']);read(command['stderr'],command['stderr_sha256'])
        expected=64 if command['label']=='overwrite-rejected' else 2 if command['label']=='invalid-root-rejected' else 0
        require(command['returncode']==expected,'CLI result class')
        if command['label'].endswith('-build'):require(output['instructions']==643,'CLI real build result')
    products={name:product(BUILD/name/'product',builds[name]) for name in ('original','renamed')}
    original=products['original'][3];renamed=products['renamed'][3]
    require(original.count(b'integer-tile.bin\0')==1 and original.replace(b'integer-tile.bin\0',b'profile-save.bin\0')==renamed,
            'data-only original PE variation')
    states={name:[827805507,1,3,0,0] for name in products};pids=set();observed=[]
    for row in runs['runs']:
        name=row['variant'];index=row['index'];receipt,native,profile,data=products[name]
        record=js(row['evidence'],row['evidence_sha256']);pids.add(record['pid'])
        start=js(record['started_path'],record['started_sha256'])
        require(all(record[k]==v for k,v in start.items() if k!='status'),'execution differs from start command')
        require(record['external_timeout'] is False and record['returncode']==0,'actual child completion')
        require(record['inputs_before']==record['inputs_after'],'execution input drift')
        identities(record['inputs_before']);identities(record['outputs'])
        require(all(record['inputs_before'].get(p)==h for p,h in native['native_inputs'].items()),'runtime input closure')
        result=js(record['stdout_path']);require(result==record['result'],'raw stdout interpretation')
        stderr=read(record['stderr_path']).decode();loaded=set()
        for match in re.finditer(r'^dyld\[(\d+)\]: <[^>]+> (/.*)$',stderr,re.M):
            require(int(match[1])==record['pid'],'dyld PID differs')
            loaded.add(match[2])
        require(loaded==set(record['loaded_images']),'raw loaded image list differs')
        require({receipt['executable'],*native['library_graph']['nodes']}<=loaded,'native host/backend not actually loaded')
        backend_names={'d3d11.dylib','dxgi.dylib','winemetal.dylib'}
        require({p for p in loaded if Path(p).name in backend_names}==set(native['library_graph']['nodes']),
                'different backend image mixed into actual execution')
        require(result['outcome']=='PROCESS_EXITED' and result['exit_code']==0 and result['proc_translated']==0,'guest/architecture result')
        require(result['pe_sha256']==profile['pe_sha256'] and record['command'][0]==receipt['executable'],'actual input/executable')
        require(result['fault']==dict(status=0,pc=0,address=0,width=0,access=0),'fault-free execution')
        sequence=['right','right','left','escape'] if index==1 else ['right','close']
        require(record['command']==[receipt['executable'],'--budget','10000000','--data-dir',record['data_directory'],
                                    '--timeout-ms','20000','--test-sequence',','.join(sequence)],'actual complete command differs')
        require(record['test_sequence']==sequence and [e['name'] for e in result['test_queue']['events']]==sequence,'actual event sequence')
        require(all(e['origin']==3 for e in result['test_queue']['events']),'TEST_QUEUE origin')
        require(result['host_after_finish']['cocoa_key_events']==0,'unexpected keyboard origin')
        state=states[name];state[4]+=2
        for event in sequence:
            if event in ('right','left'):
                state[2]+=1 if event=='right' else -1;state[3]+=1;state[4]+=1
        saved=read(row['save'],row['save_sha256'])
        require(struct.unpack('<5I',saved)==tuple(state),'independent event/state model')
        file=result['saved_file'];require(file['name']==profile['save_observation'] and file['errno']==0 and not file['truncated'], 'save observation status')
        require(bytes.fromhex(file['data_hex'])==saved,'actual guest save observation bytes')
        require(result['files']['bytes_read']==20*(index-1) and result['files']['bytes_written']==20,'guest I/O totals')
        require(result['files']['cleanup_closes']==0 and result['d3d_before_cleanup']['guest_released']==8,'guest release ownership')
        require(result['d3d_before_cleanup']['present_calls']==(5 if index==1 else 3),'actual Present count')
        require(result['host_after_finish']['active_views']==0 and result['d3d_after_cleanup']['live_objects']==0,'native resource release')
        expect={}
        for label,value in profile['observations'].items():
            at=offset(data,value['rva'],value['size']);expect[label]=data[at:at+value['size']].hex()
        require(result['observations']==expect,'configured read-only observation')
        if index==2:
            directory=Path(record['data_directory'])
            require({p.name for p in directory.iterdir()}=={profile['save_observation']},'actual filename set')
            require(read(directory/profile['save_observation'])==saved,'final disk file differs')
        observed.append(dict(variant=name,index=index,pid=record['pid'],steps=result['steps'],saved_words=list(state)))
    require(len(pids)==4,'four independent target processes required')
    rejected=BUILD.parent/'rejections-01';rejection=js(rejected/'evidence.json')
    require(rejection['status']=='PASS_METADATA_ELIGIBLE_ACTUAL_DECODER_REJECTED','actual rejection batch')
    mutant=read(rejected/'syscall.exe',rejection['input_sha256']);mutation=rejection['mutation']
    at=offset(original,mutation['rva'],2)
    require(at==mutation['offset'] and original[at:at+2].hex()==mutation['old_hex'],'rejection mutation source')
    require(original[:at]+b'\x0f\x05'+original[at+2:]==mutant,'only actual entry SYSCALL bytes changed')
    for label,command,expected in zip(('analyze','build'),rejection['commands'],(0,2),strict=True):
        result=js(rejected/(label+'.stdout'),command['stdout_sha256'])
        read(rejected/(label+'.stderr'),command['stderr_sha256'])
        require(command['returncode']==expected,'rejection CLI status')
        require(result['status']==('ELIGIBLE_FOR_BUILD_NOT_DECODED' if label=='analyze' else 'UNSUPPORTED'),
                'metadata analysis confused with actual decode')
    negative=js(rejected/'product/result.json')
    require('SYSCALL' in negative['error'] and negative['guest_executions']==0,'unknown instruction silently accepted')
    for name,item in negative['files'].items():read(rejected/'product'/name,item['sha256'])
    decoder_log=read(rejected/'product/native/compiler/main/commands.log').decode()
    require('REJECT iclass SYSCALL' in decoder_log,'actual decoder rejection absent')
    output=dict(status='PASS_INDEPENDENT_CONFIGURED_WINDOW_REVIEW',files_checked=len(checked),
                inputs=2,instructions_each=643,processes=4,runs=observed,actual_decoder_rejections=1,
                scope='stdlib-only source/command/PE bytes/file/actual stdout review; not external audit, pixel, App or performance acceptance')
    print(json.dumps(output,sort_keys=True,indent=2))


if __name__=='__main__':main()
