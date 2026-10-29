"""One real three-library load/registry probe; no rendering requested.

--build compiles only, --run starts exactly one bounded child. Default reads.
The frozen post-build consumer must pass before either activity.
"""
import argparse
import errno
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import traceback

from native_window.present_diag_v1 import accept_build_v2 as accepted
from native_window.present_diag_v1 import build as b

ROOT=b.ROOT
SOURCE=Path(__file__).with_name('probe.c')
BUILD=ROOT/'build/native-present-diag-load-v1/build-01'
RUN=ROOT/'build/native-present-diag-load-v1/run-01'
EXE=BUILD/'provider-load-probe'
BACKEND_SHA='e589cd6d06a02d230938e5ae3c728945e5eb5c2736cb31ec745556457fb2cd1e'
BUILD_STATUS='BUILT_PROVIDER_LOAD_PROBE_NOT_EXECUTED'
RUN_STATUS='PASS_REAL_LIBRARIES_ONE_PROVIDER_LOAD_ONLY'
LIMIT='no explicit D3D/Metal device, queue, WSI, guest or render calls; library initializers and process-exit destructors may execute; not rendering or performance acceptance'
need=b.need
write=b.write
sha=b.source.sha
g=b.g

def backend():
    need(re.fullmatch('[0-9a-f]{64}',BACKEND_SHA) is not None,'backend receipt not frozen')
    r=b.Reads();e=r.parsed(accepted.OUT/'evidence.json',BACKEND_SHA)
    accepted.verify();r.finish()
    libraries=e['libraries']
    need(set(libraries['graph']['nodes'])==set(map(str,library_paths())),'exact real library closure')
    need(g.hashes(libraries['outputs'])==libraries['outputs'],'actual new library bytes')
    return e

def library_paths():
    return [b.BUILD/'src/d3d11/d3d11.dylib',b.BUILD/'src/dxgi/dxgi.dylib',b.BUILD/'src/nativemetal/winemetal.dylib']

def symbols(e):
    values=e['libraries']['selected_symbols']
    result=[values[n] for n in (*b.API,*b.HOOKS)]
    need(all(s.startswith('_') for s in result),'Mach-O external symbol spelling')
    return [s[1:] for s in result]

def initial(e):
    return set(b.old.python_closure(__file__))|{SOURCE,accepted.OUT/'evidence.json',
        b.source.DEST/'include/dxmt_present_diagnostics_v1.h',Path(sys.executable),
        Path(subprocess.__file__),Path('/usr/bin/otool'),*map(Path,e['libraries']['outputs'])}

def env(out):return g.environment(out)

def invoke(argv,name,out,records,timeout=30):
    argv=list(map(str,argv))
    try:
        p=subprocess.run(argv,cwd=ROOT,env=env(out),capture_output=True,timeout=timeout)
    except subprocess.TimeoutExpired as error:
        (out/(name+'.stdout')).write_bytes(error.stdout or b'')
        (out/(name+'.stderr')).write_bytes(error.stderr or b'')
        records.append({'argv':argv,'cwd':str(ROOT),'timeout_seconds':timeout,
                        'returncode':None,'status':'TIMEOUT_RUN_KILLED_AND_WAITED_BY_SUBPROCESS'})
        raise
    (out/(name+'.stdout')).write_bytes(p.stdout)
    (out/(name+'.stderr')).write_bytes(p.stderr)
    records.append({'argv':argv,'cwd':str(ROOT),'returncode':p.returncode,
                    'stdout':name+'.stdout','stderr':name+'.stderr'})
    need(p.returncode==0,'command failed '+name)
    return p.stdout

def deps(raw):
    text=raw.decode().replace('\\\n',' ')
    need(text.startswith('deps: '),'actual dependency target')
    paths={Path(x).resolve() for x in shlex.split(text[6:])}
    header=b.source.DEST/'include/dxmt_present_diagnostics_v1.h'
    need(SOURCE in paths and header in paths,'actual compiler consumed intended source and public header')
    need({p for p in paths if p.name==header.name}=={header},'shadowed public header in actual compiler dependencies')
    return paths

def flags(t):
    return ['--driver-mode=gcc','-arch','arm64','-std=c11','-O2','-Wall','-Wextra','-Werror',
            '-isysroot',t['sdk'],'-I'+str(b.source.DEST/'include')]

def plans(t):
    f=flags(t)
    return {'deps':[t['clang'],*f,'-M','-MT','deps',str(SOURCE)],
            'compile':[t['clang'],*f,'-v',str(SOURCE),'-o',str(EXE)],
            'libraries':['/usr/bin/otool','-L',str(EXE)]}

def build():
    need(not BUILD.exists(),'fresh build directory required')
    e=backend();t,roots=b.configuration()
    paths=initial(e)|{Path(v) for k,v in t.items() if k!='sdk'}
    start=g.hashes(paths);BUILD.mkdir(parents=True)
    write(BUILD/'started.json',{'backend_sha256':BACKEND_SHA,'inputs':start,'tools':t,'scope':LIMIT})
    records=[]
    try:
        plan=plans(t)
        raw=invoke(plan['deps'],'deps',BUILD,records)
        paths|=deps(raw);before=g.hashes(paths)
        need(all(before[k]==v for k,v in start.items()),'initial inputs changed')
        for name in ('compile','libraries'):invoke(plan[name],name,BUILD,records)
        info=g.macho(EXE)
        need(info['filetype']==2 and info['rpaths']==[] and info['dependencies']==[{'command':12,'name':'/usr/lib/libSystem.B.dylib'}],'probe has only system runtime')
        need(g.hashes(paths)==before and backend()==e,'inputs changed during build')
        artifacts=g.hashes(p for p in BUILD.iterdir() if p.is_file())
        write(BUILD/'evidence.json',{'schema':1,'status':BUILD_STATUS,'scope':LIMIT,
              'backend_sha256':BACKEND_SHA,'inputs_before':before,'inputs_after':before,
              'tools':t,'commands':records,'macho':info,'artifacts':artifacts})
        return verify_build()
    except BaseException as error:
        write(BUILD/'failure.json',{'error':repr(error),'traceback':traceback.format_exc(),'commands':records})
        raise

def verify_build():
    r=b.Reads();e=backend();receipt=r.parsed(BUILD/'evidence.json')
    need(set(receipt)=={'schema','status','scope','backend_sha256','inputs_before','inputs_after','tools','commands','macho','artifacts'},'exact build fields')
    need(type(receipt['schema']) is int and receipt['schema']==1 and receipt['status']==BUILD_STATUS and receipt['scope']==LIMIT and receipt['backend_sha256']==BACKEND_SHA,'build status/scope')
    t,roots=b.configuration();need(receipt['tools']==t,'current build tools')
    paths=initial(e)|{Path(v) for k,v in t.items() if k!='sdk'}
    names={'started.json','provider-load-probe',*(n+s for n in ('deps','compile','libraries') for s in ('.stdout','.stderr'))}
    need(set(p.name for p in BUILD.iterdir())==names|{'evidence.json'},'exact build artifact set')
    need(set(receipt['artifacts'])=={str(BUILD/n) for n in names},'complete build artifact binding')
    blobs={n:r.take(BUILD/n,receipt['artifacts'][str(BUILD/n)]) for n in names}
    need(g.strict_json(blobs['started.json'].decode())=={'backend_sha256':BACKEND_SHA,'inputs':g.hashes(paths),'tools':t,'scope':LIMIT},'build start inputs')
    paths|=deps(blobs['deps.stdout'])
    need(receipt['inputs_before']==receipt['inputs_after']==g.hashes(paths),'actual -M source/tool/library closure')
    expected=[{'argv':argv,'cwd':str(ROOT),'returncode':0,'stdout':name+'.stdout','stderr':name+'.stderr'} for name,argv in plans(t).items()]
    need(receipt['commands']==expected and all(type(c['returncode']) is int for c in receipt['commands']),'actual build commands')
    need(blobs['deps.stderr']==blobs['libraries.stderr']==b'','dependency/inspection stderr')
    info=g.macho(EXE)
    need(receipt['macho']==info and info['filetype']==2 and info['rpaths']==[] and info['dependencies']==[{'command':12,'name':'/usr/lib/libSystem.B.dylib'}],'thin ARM64 system-only load probe')
    lines=blobs['libraries.stdout'].decode().splitlines()
    need(len(lines)==2 and lines[0]==str(EXE)+':' and lines[1].strip().startswith('/usr/lib/libSystem.B.dylib (compatibility version '),'actual library inspection')
    need(backend()==e and g.hashes(paths)==receipt['inputs_before'],'build final identity')
    r.finish();return {'status':BUILD_STATUS+'_CURRENT','evidence_sha256':sha(r.values[(BUILD/'evidence.json').resolve()]),'new_probe_executions':0}

def command(e):return list(map(str,[EXE,*library_paths(),*symbols(e)]))

def validate(raw,e):
    rows=[g.strict_json(line) for line in raw.decode().splitlines()]
    need(len(rows)==29,'exact actual output row count')
    n=rows[0];need(set(n)=={'event','returncode','errno','value','size'} and n['event']=='native_identity','identity row')
    need(all(type(n[k]) is int for k in ('returncode','errno','value','size')),'typed native identity')
    need((n['returncode']==0 and n['errno']==0 and n['value']==0 and n['size']==4) or
         (n['returncode']==-1 and n['errno']==errno.ENOENT),'native ARM64 not translated')
    for i,p in enumerate(library_paths()):need(rows[1+i]=={'event':'loaded','index':i,'path':str(p)},'exact loaded handle')
    names=symbols(e);addresses={}
    for index,row in enumerate(rows[4:19]):
        i,j=divmod(index,5)
        need(set(row)=={'event','handle','symbol','address','owner'} and row['event']=='symbol' and row['handle']==i and row['symbol']==names[j],'symbol order and identity')
        need(type(row['address']) is str and re.fullmatch('0x[0-9a-f]+',row['address']) and int(row['address'],16)>0,'actual nonnull symbol address')
        need(Path(row['owner']).is_absolute() and Path(row['owner']).resolve()==library_paths()[2],'exact loaded provider owner')
        if j in addresses:need(row['address']==addresses[j],'same provider function across handles')
        else:addresses[j]=row['address']
    expected=[]
    for label,configured in [('before',0),('after-other-handle',1),('after-rejection',1)]:
        expected.append({'event':'snapshot','name':label,'returncode':2,'configured':configured,
            'bytes_compared':45152,'queues_seen':0,'queues_live':0,'queues_closed':0})
    need(rows[19]==expected[0] and rows[21]==expected[1] and rows[23]==expected[2],'complete empty snapshots')
    need(rows[20]=={'event':'configure','handle':2,'returncode':0} and rows[22]=={'event':'configure','handle':0,'returncode':4},'cross-handle registry configuration')
    images={}
    for row in rows[24:28]:
        need(set(row)=={'event','index','path'} and row['event']=='non_system_image' and type(row['index']) is int and 0<=row['index']<4 and row['index'] not in images,'unique non-system loaded image')
        images[row['index']]=row['path']
    need(images=={i:str(p) for i,p in enumerate([EXE,*library_paths()])},'complete actual non-system image set')
    result=rows[28]
    need(type(result.get('loaded_images_total')) is int and result['loaded_images_total']>=4,'actual total loaded image count')
    total=result['loaded_images_total']
    need(result=={'event':'result','status':'PASS_SHARED_PROVIDER_LOAD_ONLY','checks':89+total,
        'loaded_images_total':total,'library_handles':3,'symbol_lookups':15,'snapshot_checks':3,
        'configure_calls':2,'non_system_images':4,'explicit_device_queue_render_guest_calls':0},'complete load-only result')
    return result

def run():
    need(not RUN.exists(),'fresh run directory required')
    build_info=verify_build();e=backend();paths=initial(e)|{BUILD/'evidence.json',EXE}
    before=g.hashes(paths);RUN.mkdir(parents=True);records=[]
    write(RUN/'started.json',{'status':'STARTED_NOT_ACCEPTED','build':build_info,'backend_sha256':BACKEND_SHA,
          'inputs':before,'argv':command(e),'environment':env(RUN),'timeout_seconds':20,'scope':LIMIT})
    try:
        raw=invoke(command(e),'run',RUN,records,20);result=validate(raw,e)
        need((RUN/'run.stderr').read_bytes()==b'','unexpected child stderr')
        need(g.hashes(paths)==before and verify_build()==build_info and backend()==e,'inputs changed during actual load')
        write(RUN/'evidence.json',{'schema':1,'status':RUN_STATUS,'scope':LIMIT,'backend_sha256':BACKEND_SHA,
            'build':build_info,'inputs_before':before,'inputs_after':before,'commands':records,'result':result,
            'artifacts':g.hashes(p for p in RUN.iterdir() if p.is_file())})
        return verify()
    except BaseException as error:
        write(RUN/'failure.json',{'error':repr(error),'traceback':traceback.format_exc(),'commands':records,'scope':LIMIT})
        raise

def verify():
    r=b.Reads();e=backend();build_info=verify_build();receipt=r.parsed(RUN/'evidence.json')
    need(set(receipt)=={'schema','status','scope','backend_sha256','build','inputs_before','inputs_after','commands','result','artifacts'},'exact run receipt fields')
    need(type(receipt['schema']) is int and receipt['schema']==1 and receipt['status']==RUN_STATUS and receipt['scope']==LIMIT and receipt['backend_sha256']==BACKEND_SHA and receipt['build']==build_info,'run source/scope')
    paths=initial(e)|{BUILD/'evidence.json',EXE};before=g.hashes(paths)
    need(receipt['inputs_before']==receipt['inputs_after']==before,'run input closure')
    names={'started.json','run.stdout','run.stderr'}
    need(set(p.name for p in RUN.iterdir())==names|{'evidence.json'} and set(receipt['artifacts'])=={str(RUN/n) for n in names},'exact run artifact set')
    blobs={n:r.take(RUN/n,receipt['artifacts'][str(RUN/n)]) for n in names}
    need(g.strict_json(blobs['started.json'].decode())=={'status':'STARTED_NOT_ACCEPTED','build':build_info,'backend_sha256':BACKEND_SHA,
        'inputs':before,'argv':command(e),'environment':env(RUN),'timeout_seconds':20,'scope':LIMIT},'actual run start')
    need(receipt['commands']==[{'argv':command(e),'cwd':str(ROOT),'returncode':0,'stdout':'run.stdout','stderr':'run.stderr'}] and type(receipt['commands'][0]['returncode']) is int,'actual bounded command returned zero')
    need(blobs['run.stderr']==b'' and validate(blobs['run.stdout'],e)==receipt['result'],'actual shared provider output')
    need(g.hashes(paths)==before and backend()==e,'final run identity');r.finish()
    return {'status':RUN_STATUS+'_CURRENT','evidence_sha256':sha(r.values[(RUN/'evidence.json').resolve()]),
            'actual_library_load_probe_processes':1,'new_probe_executions':0,'scope':LIMIT}

if __name__=='__main__':
    parser=argparse.ArgumentParser();group=parser.add_mutually_exclusive_group()
    group.add_argument('--build',action='store_true');group.add_argument('--run',action='store_true');group.add_argument('--verify-build',action='store_true')
    args=parser.parse_args()
    print(json.dumps(build() if args.build else run() if args.run else verify_build() if args.verify_build else verify(),sort_keys=True))
