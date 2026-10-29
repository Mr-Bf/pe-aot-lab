"""Versioned static acceptance of preserved backend-01; never rebuild or load.

Ninja counts dependency rows, including repeated paths. This reader preserves
multiplicity for count validation and binds unique canonical files separately.
Original command return codes were not persisted: completion is an explicitly
limited inference from the frozen producer control flow and preserved logs.
"""
import argparse,hashlib,json,os,re,shlex,stat,struct,subprocess,sys
from pathlib import Path
from native_window.present_diag_v1 import build as b

ROOT=b.ROOT;BUILD=b.BUILD;ORIGINAL=b.OUT
OUT=ROOT/'build/native-present-diag-v1/backend-acceptance-v2-01'
COPIES=b.source.DEST.parent/'acceptance-v2-library-bytes'
STATUS='STATIC_DIAGNOSTIC_BACKEND_ACCEPTED_NOT_LOADED'
PINS={'build.log':'64a43cb1344469cba045003f372998f0a0820bad80ccea0e884e034e03c9ae87',
 'compile_commands.json':'bbb870eead9dd40ccf12363121ff01ca7573c061a9c2e63f1b10116063fa838e',
 'compilers.json':'086c0b5e48bafeb84883527edf0d8643bbe48ca122bc1f67742a28de4c1827a6',
 'configure.log':'4cf6ffc8f878c7432951693fbb543675b612680320714fe9f332d225b2ce6537',
 'failure.json':'38dd8e61bb22b55936da04cb13f4cfa132e578cbc4d04ca37bd7045dff8c1a94',
 'ninja-deps.log':'4b7110e1394c4d6e0c9d73dbd5ca2d8ce88e8182e279b3e7814fb33efff19938',
 'started.json':'67beb7302ff60d27963b6687abd2855d0dcbd06a59b340b1d505924f5a1722b6'}
PRODUCER_SHA='a4ca538cb2df064743272fd6a953c36b84d7af287bbe47609e0de0f6153dd9e3'
need=b.need
def sha(raw):return hashlib.sha256(raw).hexdigest()
def strict(raw):return b.g.strict_json(raw.decode())
def write(path,value):b.write(path,value)

class Reads:
    """Hash each actual stream; retain parsed bytes. Recheck files/trees at end.

    Large SDK/LLVM trees are streamed rather than retained in RAM. No metadata
    is parsed from a second unauthenticated read of an already bound path.
    """
    def __init__(self):self.hashes={};self.bytes={};self.trees={}
    def bind(self,path,digest,want=None):
        key=str(Path(path).resolve())
        need(want is None or digest==want,'expected identity '+key)
        need(key not in self.hashes or self.hashes[key]==digest,'changed bound file '+key)
        self.hashes[key]=digest;return digest
    def hash(self,path,want=None):
        path=Path(path);h=hashlib.sha256()
        with path.open('rb') as f:
            before=os.fstat(f.fileno())
            while chunk:=f.read(1024*1024):h.update(chunk)
            after=os.fstat(f.fileno())
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'file changed while hashing '+str(path))
        return self.bind(path,h.hexdigest(),want)
    def take(self,path,want=None):
        path=Path(path).resolve();raw=path.read_bytes();self.bind(path,sha(raw),want)
        need(path not in self.bytes or self.bytes[path]==raw,'changed parsed bytes '+str(path))
        self.bytes[path]=raw;return raw
    def tree(self,root):
        root=Path(root);identity={}
        for path in sorted(root.rglob('*')):
            name=path.relative_to(root).as_posix();kind=path.lstat().st_mode
            if stat.S_ISLNK(kind):identity[name]=['symlink',str(path.readlink())]
            elif stat.S_ISDIR(kind):identity[name]=['directory']
            elif stat.S_ISREG(kind):identity[name]=['file',self.hash(path)]
            else:raise ValueError('special tree file '+str(path))
        key=str(root)
        need(key not in self.trees or self.trees[key]==identity,'tree changed '+key)
        self.trees[key]=identity;return identity
    def finish(self):
        for root in list(self.trees):self.tree(root)
        roots=[Path(x) for x in self.trees]
        for path,want in list(self.hashes.items()):
            if not any(Path(path).is_relative_to(root) for root in roots):self.hash(path,want)
        for path,raw in self.bytes.items():need(path.read_bytes()==raw,'parsed bytes changed at finish '+str(path))

def parse_dep_blocks(raw,build=BUILD):
    names=set();blocks={};target=None;rows=[];declared=0;mtime=0
    def complete():
        if target is None:return
        need(len(rows)==declared,'literal dependency row count differs')
        counts={}
        for row in rows:counts[row]=counts.get(row,0)+1
        blocks[target]={'declared':declared,'row_count':len(rows),'unique_spelling_count':len(counts),
            'duplicate_rows':len(rows)-len(counts),'repeated_paths':{k:v for k,v in sorted(counts.items()) if v>1},'mtime_ns':mtime}
    for line in raw.decode().splitlines():
        if line=='':continue
        if line.startswith('    '):
            name=line[4:]
            need(target is not None and name and name.strip()==name,'orphan/empty dependency')
            rows.append(name);names.add(name)
        else:
            complete()
            match=re.fullmatch(r'(.+): #deps ([0-9]+), deps mtime ([0-9]+) \(VALID\)',line)
            need(match is not None,'invalid/stale/count-missing dependency block')
            target=str((Path(build)/match[1]).resolve())
            need(Path(target).is_relative_to(Path(build).resolve()) and target not in blocks,'duplicate/outside Ninja target')
            declared=int(match[2]);mtime=int(match[3]);rows=[]
    complete();need(blocks,'empty dependency blocks')
    return names,blocks

def dependency_graph(raw,compile_raw,roots,r):
    names,blocks=parse_dep_blocks(raw);commands=strict(compile_raw)
    need(type(commands) is list and commands,'compile database absent')
    provider=b.source.DEST/'src/nativemetal/present_diagnostics_v1.cpp'
    expected=set();found=[];untracked=[]
    for item in commands:
        directory=Path(item['directory']);file=(directory/Path(item['file'])).resolve()
        need(directory.resolve()==BUILD,'actual compilation outside build')
        if file==provider:found.append(item)
        args=shlex.split(item['command'])
        if '-MD' in args:
            need(args.count('-o')==args.count('-MQ')==1,'actual -MD output flags')
            output=str((directory/args[args.index('-o')+1]).resolve());quoted=str((directory/args[args.index('-MQ')+1]).resolve())
            need(output==quoted and output not in expected,'duplicate/ambiguous compilation target');expected.add(output)
        else:untracked.append(item)
    need(expected==set(blocks),'Ninja targets differ from all -MD commands')
    paths={}
    for name in names:
        path=(BUILD/Path(name)).resolve()
        need(path.is_file() and (path.is_relative_to(BUILD) or any(path.is_relative_to(root) for root in roots.values())),'unbound/missing compiler dependency '+str(path))
        paths[str(path)]=r.hash(path)
    targets={}
    for path,block in blocks.items():
        need(Path(path).is_file() and Path(path).stat().st_mtime_ns==block['mtime_ns'],'current target stale against preserved Ninja dependencies '+path)
        targets[path]=r.hash(path)
    need(len(found)==1 and '-MD' in shlex.split(found[0]['command']),'one actual provider compile')
    need({str(provider),str(b.source.DEST/'include/dxmt_present_diag_internal_v1.hpp'),str(b.source.DEST/'include/dxmt_present_diagnostics_v1.h')}<=paths.keys(),'actual provider headers missing')
    return {'target_count':len(blocks),'targets':sorted(blocks),'target_sha256':targets,'blocks':blocks,'paths':dict(sorted(paths.items())),
        'literal_rows':sum(x['row_count'] for x in blocks.values()),'targets_with_duplicate_rows':sum(x['duplicate_rows']>0 for x in blocks.values()),
        'duplicate_rows':sum(x['duplicate_rows'] for x in blocks.values()),'provider_compile':found[0],'non_MD_compile_commands':untracked}

def macho_bytes(data):
    """Same thin ARM64 load-command contract as frozen g.macho, bound bytes."""
    need(len(data)>=32,'short Mach-O');magic,cpu,subtype,kind,count,size,flags,reserved=struct.unpack_from('<8I',data)
    need(magic==0xfeedfacf and cpu==0x100000c and kind==6,'thin ARM64 dylib required')
    need(size<=len(data)-32 and count<=size//8,'load command bounds')
    result={'filetype':kind,'cpu_subtype':subtype,'id':None,'rpaths':[],'dependencies':[]};off=32
    for _ in range(count):
        cmd,n=struct.unpack_from('<II',data,off);need(n>=8 and n%8==0 and off+n<=32+size,'command bounds')
        if cmd in (0xc,0x80000018,0x8000001f,0x80000023,0xd,0x8000001c):
            minimum=12 if cmd==0x8000001c else 24;need(n>minimum,'short load path')
            index=struct.unpack_from('<I',data,off+8)[0];need(minimum<=index<n,'path offset')
            end=data.find(b'\0',off+index,off+n);need(end!=-1,'path termination');name=data[off+index:end].decode()
            need(name and '\n' not in name,'invalid path')
            if cmd==0xd:need(result['id'] is None,'duplicate ID');result['id']=name
            elif cmd==0x8000001c:result['rpaths'].append(name)
            else:result['dependencies'].append({'command':cmd,'name':name})
        elif cmd in (0x27,0x20,0x10):raise ValueError('unsupported dyld environment/lazy/prebound')
        off+=n
    need(off==32+size and result['id'] is not None,'complete dylib commands');return result

def library_inspection(r,persist):
    files=sorted(path.resolve() for path in BUILD.rglob('*.dylib') if path.is_file())
    need(len(files)==len(set(files))==4,'exact four distinct emitted dylibs')
    blobs={str(path):r.take(path) for path in files};outputs={path:sha(raw) for path,raw in blobs.items()}
    parsed={path:macho_bytes(raw) for path,raw in blobs.items()}
    library=BUILD/'src/d3d11/d3d11.dylib';provider=BUILD/'src/nativemetal/winemetal.dylib'
    graph=b.g.library_graph(library,OUT/'future-host',[library.parent])
    need(set(graph['nodes'])=={str(library),str(BUILD/'src/dxgi/dxgi.dylib'),str(provider)},'exact reachable three-library graph')
    need(all(parsed[path]==info for path,info in graph['nodes'].items()),'graph parsed from different library bytes')
    symbols={};commands=[]
    if persist:COPIES.mkdir(parents=True,exist_ok=True)
    for i,path in enumerate(files):
        raw=blobs[str(path)];copy=COPIES/(outputs[str(path)]+'.dylib')
        if persist and not copy.exists():
            with copy.open('xb') as f:f.write(raw)
        need(copy.is_file() and r.take(copy)==raw,'immutable nm input copy')
        item={}
        for label,flag in [('defined','-gjU'),('undefined','-gju')]:
            args=['/usr/bin/nm',flag,str(copy)]
            process=subprocess.run(args,env=b.environment(),capture_output=True)
            need(process.returncode==0 and process.stderr==b'','static nm inspection failed')
            record={'argv':args,'returncode':process.returncode,'stdout':process.stdout.decode(),'stderr':process.stderr.decode(),
                'input_original':str(path),'input_sha256':outputs[str(path)]}
            name=f'nm-{i}-{label}.json';commands.append(name)
            if persist:write(OUT/name,record)
            else:need(strict(r.take(OUT/name))==record,'nm observation changed')
            item[label]=record['stdout'].splitlines()
        symbols[str(path)]=item
    definitions=symbols[str(provider)]['defined'];selected={name:name for name in b.API}
    for hook in b.HOOKS:
        matches=[s for s in definitions if s.startswith('__ZN4dxmt15present_diag_v1') and hook in s]
        need(len(matches)==1,'unique provider hook '+hook);selected[hook]=matches[0]
    for symbol in selected.values():need([p for p in symbols if symbol in symbols[p]['defined']]==[str(provider)],'provider symbol duplicated/absent')
    need({selected[h] for h in b.HOOKS}<=set(symbols[str(library)]['undefined']),'actual D3D11 provider references')
    return {'outputs':outputs,'graph':graph,'symbols':symbols,'provider':str(provider),'selected_symbols':selected},commands

def collect(persist=False):
    r=Reads()
    consumer_files=b.old.python_closure(__file__)
    own={str(p.resolve()):r.hash(p) for p in sorted(consumer_files)}
    r.take(Path(b.__file__),PRODUCER_SHA)
    need({p.name for p in ORIGINAL.iterdir()}==set(PINS),'original preserved artifact set')
    raw={name:r.take(ORIGINAL/name,want) for name,want in PINS.items()};start=strict(raw['started.json'])
    need(strict(raw['failure.json'])=={'error':"ValueError('orphan/empty/duplicate dependency')",'scope':b.SCOPE,'status':'BUILD_FAILED_PRESERVED_NOT_EXECUTION_ACCEPTANCE'},'original failure kind')
    t,roots=b.configuration()
    need(start['tools']==t and start['roots']=={k:str(v) for k,v in roots.items()} and start['scope']==b.SCOPE and start['source_receipt_sha256']==b.SOURCE_SHA and start['status']=='BUILD_STARTED_NOT_LOADED','actual starting configuration')
    need(type(start['jobs']) is int and 1<=start['jobs']<=4,'original jobs')
    plans=b.plan(roots['llvm'],start['jobs'])
    need(len(start['plan'])==2 and all(Path(x[0]).resolve()==Path(t['python']).resolve() for x in start['plan']),'original Python executable')
    for expected,actual in zip(plans,start['plan']):need(expected[1:]==actual[1:],'original build plan');expected[0]=actual[0]
    for name,args in zip(('configure.log','build.log','ninja-deps.log'),[*plans,list(map(str,[b.bootstrap.NINJA,'-C',BUILD,'-t','deps']))]):need(strict(raw[name].split(b'\n',1)[0])==args,'actual preserved log command')
    need(re.search(rb'\[167/167\] Linking target src/airconv/darwin/airconv\n',raw['build.log']) is not None,'final build progress not preserved')
    required=b.old.python_closure(b.__file__)|set(b.source.sources())|{b.source.OUT/n for n in ('evidence.json','started.json','changes.json','present-diagnostics-v1.patch')}
    required|={b.source.BACKEND,b.bootstrap.NINJA,Path(t['python']),Path('/usr/bin/nm'),Path('/usr/bin/otool')}
    required|={Path(v) for k,v in t.items() if k!='sdk'}
    need(set(start['inputs']['files'])=={str(p.resolve()) for p in required},'exact frozen producer input set')
    current={'files':{str(p.resolve()):r.hash(p,start['inputs']['files'][str(p.resolve())]) for p in sorted(required)},
        'trees':{k:{'root':str(path),'identity':r.tree(path)} for k,path in roots.items()}}
    need(current==start['inputs'],'all input trees equal pre-build snapshot')
    for name,path in [('compile_commands.json',BUILD/'compile_commands.json'),('compilers.json',BUILD/'meson-info/intro-compilers.json')]:need(r.take(path)==raw[name],'live compilation metadata differs')
    b.compiler_gate(raw['compilers.json'])
    deps=dependency_graph(raw['ninja-deps.log'].split(b'\n',1)[1],raw['compile_commands.json'],roots,r)
    # Snapshot all current build artifacts, not a retrospective pre-build hash.
    build_tree={'root':str(BUILD),'identity':r.tree(BUILD)}
    libs,tools=library_inspection(r,persist)
    need(b.old.python_closure(__file__)==consumer_files,'consumer closure changed')
    need({str(p.resolve()):r.hash(p) for p in sorted(consumer_files)}==own,'consumer source changed during acceptance')
    r.finish()
    result={'schema':2,'status':STATUS,'scope':b.SCOPE,'source_receipt_sha256':b.SOURCE_SHA,
        'historical_build':{'original_status':'BUILD_FAILED_PRESERVED_NOT_EXECUTION_ACCEPTANCE','failure':'duplicate dependency paths rejected by old parser',
            'per_command_returncodes_persisted':False,'completion_inference':'Frozen producer reached dependency parsing after setup, compile and ninja-deps command success checks; preserved log shows 167/167. No retrospective command returncode receipt is invented.'},
        'original_artifacts':{str(ORIGINAL/n):s for n,s in PINS.items()},'producer_sha256':PRODUCER_SHA,
        'inputs_before':start['inputs'],'inputs_at_acceptance':current,'tools':t,'roots':start['roots'],
        'consumer_inputs':own,'dependencies':deps,'libraries':libs,'current_build_tree':build_tree,
        'static_inspection_records':tools,'new_compilation_commands':0,
        'scope_limits':'Current complete trees/outputs authenticated; trusted-host before/after consistency, not proof against hostile transient replacement, not runtime loading or Present acceptance.'}
    return result

def accept():
    need(not OUT.exists(),'fresh acceptance output required')
    OUT.mkdir(parents=True)
    try:
        result=collect(True)
        result['artifacts']={str(p):sha(p.read_bytes()) for p in sorted(OUT.iterdir()) if p.is_file()}
        write(OUT/'evidence.json',result);return verify()
    except BaseException as error:
        write(OUT/'failure.json',{'status':'FAIL_READONLY_ACCEPTANCE_PRESERVED','error':repr(error),'scope':b.SCOPE});raise
def verify():
    path=OUT/'evidence.json';raw=path.read_bytes();e=strict(raw)
    expected=set(e['static_inspection_records'])|{'evidence.json'}
    need({p.name for p in OUT.iterdir()}==expected,'exact acceptance output set')
    need(set(e['artifacts'])=={str(OUT/n) for n in e['static_inspection_records']},'complete static observations')
    before={p:Path(p).read_bytes() for p in e['artifacts']}
    need({p:sha(v) for p,v in before.items()}==e['artifacts'],'bound observation bytes')
    actual=collect(False)
    need({k:v for k,v in e.items() if k!='artifacts'}==actual,'current independent static acceptance differs')
    need(path.read_bytes()==raw and all(Path(p).read_bytes()==v for p,v in before.items()),'receipt/observation drift')
    return {'status':STATUS+'_CURRENT','evidence_sha256':sha(raw),'provider':e['libraries']['provider'],
        'libraries':len(e['libraries']['outputs']),'dependency_files':len(e['dependencies']['paths']),
        'dependency_targets':e['dependencies']['target_count'],'duplicate_rows':e['dependencies']['duplicate_rows'],'scope':b.SCOPE}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--accept',action='store_true');args=parser.parse_args()
    print(json.dumps(accept() if args.accept else verify(),sort_keys=True))
