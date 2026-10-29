"""Stdlib-only reconstruction of configured App builds and actual two-run restore."""
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'build/window-app-v1'
BUILD=BASE/'app-01'
IDENTIFIER='org.peaotlab.configured254be0c3.v1'
PE_SHA='254be0c36be784a028db912eb89522a963039a9ec140941fb41ea1643f1730ac'
PINS={'app-01/evidence.json':'251164f99f52c3a7d9609b49daaeb656e77e77f8f69e4bc0c993da9a46f01d55',
      'app-01/entry/entry-build.json':'4e6bd1e6b2bdb3785dd76e8f814073944880f333700f87b829b2fe7f4be81aea',
      'run-original-02/evidence.json':'4371077e69e9727803e4512b256198915be3738789d3ec49658562e7be0f32bb',
      'run-relocated-01/evidence.json':'19eea298548e1eba245f012752474a286166bd063385307314f235fb4284953d'}
checked={}


def need(ok,message):
    if not ok:raise ValueError(message)


def read(path,digest=None):
    path=Path(path);data=path.read_bytes();value=hashlib.sha256(data).hexdigest()
    need(digest is None or value==digest,'file hash: '+str(path))
    need(str(path) not in checked or checked[str(path)]==value,'file changed during review')
    checked[str(path)]=value;return data


def js(path,digest=None):return json.loads(read(path,digest))


def hashes(values):
    for path,digest in values.items():read(path,digest)


def sections(path):
    data=read(path);magic,cpu,_,filetype,ncommands,commands=struct.unpack_from('<6I',data)
    need(magic==0xfeedfacf and cpu==0x100000c and filetype in (2,6),'thin ARM64 Mach-O required')
    position=32;result={}
    for _ in range(ncommands):
        command,size=struct.unpack_from('<II',data,position)
        need(size>=8 and position+size<=len(data),'load command bounds')
        if command==0x19:
            count=struct.unpack_from('<I',data,position+64)[0];need(size==72+count*80,'section table length')
            for index in range(count):
                at=position+72+index*80
                name=data[at:at+16].split(b'\0')[0].decode();segment=data[at+16:at+32].split(b'\0')[0].decode()
                address,length,offset,align,_,relocs,flags,a,b,c=struct.unpack_from('<QQ8I',data,at+32)
                zero=flags&255 in (1,12,18)
                need(zero or offset+length<=len(data),'section payload bounds')
                result[segment+'/'+name]=dict(address=address,size=length,alignment=align,flags=flags,reserved=[a,b,c],
                    relocation_count=relocs,sha256=None if zero else hashlib.sha256(data[offset:offset+length]).hexdigest())
        position+=size
    need(position==32+commands and result,'load command/section closure')
    return result


def load_commands(path):
    data=read(path);count=struct.unpack_from('<I',data,16)[0];at=32;rpaths=[];dependencies=[];identity=None
    for _ in range(count):
        command,size=struct.unpack_from('<II',data,at)
        if command in (0x8000001c,0xd,0xc,0x80000018,0x8000001f,0x20,0x80000023):
            off=struct.unpack_from('<I',data,at+8)[0];need(0<off<size,'load command string bounds')
            text=data[at+off:at+size].split(b'\0')[0].decode()
            if command==0x8000001c:rpaths.append(text)
            elif command==0xd:identity=text
            else:dependencies.append(text)
        at+=size
    return rpaths,identity,dependencies


def app_tree(app,expected):
    actual={str(p.relative_to(app)) for p in app.rglob('*') if p.is_file()}
    need(actual==set(expected),'App file closure')
    for path in app.rglob('*'):need(not path.is_symlink(),'App symlink')
    for name,item in expected.items():
        path=app/name;read(path,item['sha256']);need(path.stat().st_mode&0o777==item['mode'],'App mode')
    info=plistlib.loads(read(app/'Contents/Info.plist'))
    need(info['CFBundleIdentifier']==IDENTIFIER and info['CFBundleExecutable']=='pe-aot-window','App identity')
    names={'d3d11.dylib','dxgi.dylib','winemetal.dylib'}
    need({p.name for p in (app/'Contents/Frameworks').iterdir()}==names,'three library set')
    paths=[app/'Contents/MacOS/pe-aot-window',*[app/'Contents/Frameworks'/name for name in sorted(names)]]
    for index,path in enumerate(paths):
        sections(path);rpaths,identity,deps=load_commands(path)
        need(rpaths==(['@executable_path/../Frameworks'] if index==0 else ['@loader_path/']),'bundle relative search path')
        if index:need(identity=='@rpath/'+path.name,'bundle relative library ID')
        need(all(d.startswith(('/usr/lib/','/System/Library/')) or d in {'@rpath/'+n for n in names} for d in deps),
             'external library dependency')
    return {str(path) for path in paths}


def main():
    records={name:js(BASE/name,digest) for name,digest in PINS.items()}
    package=records['app-01/evidence.json'];entry=records['app-01/entry/entry-build.json']
    need(package['status']=='CONFIGURED_APP_STATICALLY_VERIFIED_NOT_EXECUTED' and package['guest_executions']==0,'static package scope')
    need(entry['pe_sha256']==package['pe_sha256']==PE_SHA and entry['spec']==package['spec'],'source/configuration identity')
    need(entry['spec']['identifier']==IDENTIFIER,'configured namespace')
    for record in (entry,package):
        need(record['inputs_before']==record['inputs_after'],'build input drift')
        hashes(record['inputs_before']);hashes(record['artifacts'])
    need((BUILD/'entry/app_config.h').read_text().endswith('static NSString *const kApplication = @"'+IDENTIFIER+'";\n'),'compiled App identifier')
    derivation=js(ROOT/'window_app_v1/entry-derivation.json')
    original=read(ROOT/derivation['base'],derivation['base_sha256']).decode()
    derived=read(ROOT/derivation['derived'],derivation['derived_sha256']).decode()
    for change in reversed(derivation['replacements']):
        need(derived.count(change['new'])==1,'entry derivation count');derived=derived.replace(change['new'],change['old'])
    need(derived==original,'entry changed beyond configuration and diagnostic text')
    source=Path(entry['source_product']);product=js(source/'result.json',entry['source_receipt_sha256'])
    need(product['input_sha256']==PE_SHA and product['instructions']==643,'real AOT source')
    native=js(source/'native/program-build.json');roots=js(source/'native/compiler/roots.json')
    root_objects={str(Path(r['directory'])/'arm64.o') for r in [roots['main'],*roots['roots']]}
    need(root_objects<={r['source'] for r in entry['reused_objects'].values()},'caller AOT roots missing')
    need(len(entry['reused_objects'])==7,'current two-root object set')
    for name,item in entry['reused_objects'].items():
        need(read(item['source'],item['sha256'])==read(BUILD/'entry/reused'/name),'copied object identity')
    need(len(entry['commands'])==9,'entry command count')
    for name,item in entry['commands'].items():
        command=js(item['path'],item['sha256']);need(command['returncode']==0,'entry command failed')
        args=command['command']
        if name=='deps-entry':need(str(BUILD/'entry/app_config.h') in command['stdout'],'actual entry consumed configured header')
        if name=='compile-host':need('-Dmain=aot_window_main' in args and str(source/'native') in args,'actual host rename/header')
        if name=='link':
            need(all(str(BUILD/'entry/reused'/name) in args for name in entry['reused_objects']),'new objects absent from link')
            need(str(BUILD/'entry/host.o') in args and str(BUILD/'entry/entry.o') in args,'new host/entry absent from link')
    need(len(package['commands'])==10,'package command count')
    for row in package['commands']:
        command=js(row['path'],row['sha256']);need(row['returncode']==command['returncode']==0,'package command failed')
    app=Path(package['app']);relocated=Path(package['relocated'])
    code_paths=[app_tree(app,package['app_tree']),app_tree(relocated,package['relocated_tree'])]
    need(package['app_tree']==package['relocated_tree'],'static relocation file identity')
    for name,row in package['copied_code'].items():
        read(row['source'],row['original_sha256']);read(app/name,row['packaged_sha256'])
        need(sections(row['source'])==sections(app/name)==sections(relocated/name)==row['section_identity'],'package changed code/data sections')
    observed=[];prior=None
    for index,name in enumerate(('run-original-02','run-relocated-01')):
        out=BASE/name;r=records[name+'/evidence.json'];target=relocated if index else app;exe=target/'Contents/MacOS/pe-aot-window'
        need(r['status']=='ACTUAL_CONFIGURED_APP_EXECUTION_OBSERVED_NOT_ACCEPTED' and r['returncode']==0 and r['external_timeout'] is False,'actual process did not complete normally')
        need(r['command']==[str(exe)] and r['argv_count']==1 and r['app']==str(target),'actual zero-argument bundle path')
        read(exe,r['executable_sha256']);read(BUILD/'evidence.json',r['package_receipt_sha256'])
        raw=js(out/'stdout',r['stdout_sha256']);need(raw==r['result'],'raw execution result differs')
        text=read(out/'stderr',r['stderr_sha256']).decode();loaded=set()
        for match in re.finditer(r'^dyld\[(\d+)\]: <[^>]+> (/.*)$',text,re.M):
            need(int(match[1])==r['pid'],'actual library loader PID');loaded.add(match[2])
        need(loaded==set(r['loaded_images']) and code_paths[index]<=loaded,'actual native bundle code not loaded')
        need({p for p in loaded if Path(p).name in ('d3d11.dylib','dxgi.dylib','winemetal.dylib')}==code_paths[index]-{str(exe)},'external backend loaded')
        need(raw['pe_sha256']==PE_SHA and raw['proc_translated']==0 and raw['outcome']=='PROCESS_EXITED' and raw['exit_code']==0,'native guest identity/exit')
        need(raw['test_queue']['requested']==raw['test_queue']['posted']==0,'synthetic guest queue used')
        need(raw['fault']==dict(status=0,pc=0,address=0,width=0,access=0),'unexpected guest fault')
        host=raw['host_after_finish'];need(host['cocoa_key_events']==(8 if index==0 else 2) and host['close_requests']==index,'Cocoa key/close observations')
        need(host['test_queue_events']==0 and host['windows_destroyed']==1 and host['forced_cleanup_windows']==0 and host['active_views']==0,'normal window/resource teardown')
        # The frozen header defines STOPPED=1; queue.end() sets it on normal shutdown.
        need(host['error']==host['stopped']==1 and host['pending_messages']==0,'queue completion differs')
        need(raw['d3d_before_cleanup']['guest_released']==8 and raw['d3d_after_cleanup']['live_objects']==0 and raw['d3d_after_cleanup']['active_maps']==0,'D3D lifecycle')
        need(raw['d3d_cleanup_result']==raw['user32_end_status']==raw['callback_stats']['end_status']==0,'session cleanup failure')
        need(raw['files']['bytes_read']==20*index and raw['files']['bytes_written']==20 and raw['files']['cleanup_closes']==raw['files']['cleanup_errors']==0,'guest file operation totals')
        saved=read(out/'data-after/profile-save.bin');words=list(struct.unpack('<5I',saved))
        expected=[827805507,1,4+index,3+index,5+3*index]
        need(words==expected and raw['saved_file']['data_hex']==saved.hex() and raw['saved_file']['name']=='profile-save.bin','actual disk/guest state')
        need(set(r['data_after'])=={'profile-save.bin'} and r['data_after']['profile-save.bin']['sha256']==hashlib.sha256(saved).hexdigest(),'default data file identity')
        if index:
            need(read(out/'data-before/profile-save.bin')==prior,'cross-process disk continuity')
        else:need(r['data_before']=={},'initial data was not empty')
        prior=saved
        need(len(r['new_run_directories'])==1,'wrapper run count')
        wrapper=out/'wrapper-runs'/r['new_run_directories'][0]
        started=js(wrapper/'entry-started.json');finished=js(wrapper/'entry-finished.json')
        need(started['pid']==finished['pid']==r['pid'] and started['argument_count']==1,'wrapper actual PID/argc')
        need(started['bundle_identifier']==IDENTIFIER and started['bundle_path']==str(target),'wrapper actual bundle identity')
        need(started['data_directory']==str(Path(r['expected_support'])/'Data'),'default data directory')
        need(started['instance_lock_held'] and finished['instance_lock_held_until_host_return'] and finished['host_returncode']==0,'wrapper lifecycle/lock')
        need(started['test_queue_requested'] is False and finished['test_queue_requested'] is False,'wrapper requested test input')
        cleanup=js(out/'extra-instance-cleanup.json')
        need(cleanup['save_before_sha256']==cleanup['save_after_sha256']==hashlib.sha256(saved).hexdigest(),'extra-instance cleanup changed save')
        extra=[cleanup] if 'pid' in cleanup else cleanup['cleaned']
        for item in extra:need(item['pid']!=r['pid'] and item['signal']=='SIGTERM' and item['normal_guest_exit'] is False and item['process_no_longer_present'],'extra instance mixed into successful runs')
        observed.append(dict(pid=r['pid'],relocated=bool(index),steps=raw['steps'],cocoa_key_events=host['cocoa_key_events'],saved_words=words,extra_cleaned=[item['pid'] for item in extra]))
    failure=js(BASE/'run-original-01/evidence.json');need(failure['pid']==99206 and failure['external_timeout'] and failure['returncode']==-15 and failure['data_after']=={},'first failed attempt lost')
    cleanup=js(BASE/'ui-delay-01/cleanup.json');need(cleanup['pid']==99925 and cleanup['normal_guest_exit'] is False and cleanup['data_before']==cleanup['data_after']=={},'first extra instance lost')
    capture=js(BASE/'final-default-data-01/evidence.json')
    need(capture['status']=='POST_CLEANUP_DEFAULT_SAVE_CAPTURED' and capture['bytes']==20,'final default-data capture scope')
    need(capture['source']==str(Path.home()/'Library/Application Support'/IDENTIFIER/'Data/profile-save.bin'),'captured default data path')
    need(read(BASE/'final-default-data-01/profile-save.bin',capture['sha256'])==prior,'post-cleanup default save snapshot differs')
    read(ROOT/'window_bridge/cocoa_host.h');read(ROOT/'window_bridge/message_queue.h')
    print(json.dumps(dict(status='PASS_CONFIGURED_APP_TWO_RUN_REVIEW',files_checked=len(checked),normal_processes=2,runs=observed,
        failed_supervised_attempts=1,extra_instances_cleaned=3,
        scope='stdlib-only actual artifacts/commands/Mach-O/raw output/dyld/wrapper/disk review; direct bundled launch and OS-synthetic Cocoa input; no Finder, physical-keyboard, pixel, performance or unexplained-extra-instance resolution'),indent=2,sort_keys=True))


if __name__=='__main__':main()
