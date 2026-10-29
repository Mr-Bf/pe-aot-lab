#!/usr/bin/env python3
"""Recover only independently Git-tree-verified subtrees from a truncated tar.

No downloads, tar.extractall, or EOF-as-whole-archive-success. Regular-file
contents are staged under private opaque names, hashed, and checked against
fixed official Git tree IDs before any source tree is materialized/published.
"""
import argparse
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT.parents[1]/'work/graphics-stage5'
OUT=ROOT/'build/graphics-stage5/llvm-recovery'
COMMIT='8dfdcc7b7bf66834a761bd8de445840ef68e4d1a'
PREFIX='llvm-project-'+COMMIT
EXPECTED={'llvm':'eca74668552b64f2cb839a2084f8b5bbfe680a9b',
          'cmake':'1facab5a57298bef497f4a6d184184c87267c749'}
ARCHIVE_SHA='5f1d3698447c064a19398591d3d7b1d9e0054b3fade8761a38a38542f35ec36a'
ARCHIVE_SIZE=165675008
ARCHIVE=WORK/'downloads'/(PREFIX+'.tar.partial')
METADATA=ROOT/'build/graphics-stage5/bootstrap/llvm-root-trees.json'
DESTINATION=WORK/'sources'/('llvm-core-verified-'+COMMIT)
MAX_FILES=200000
MAX_SELECTED_BYTES=8*1024*1024*1024
ATTRIBUTES_GIT_OID='b07b652eee02eab7057a3d6996ab195698df6937'
# Exact five-path archive conversion profile. Both identities were verified
# against official fixed-commit blobs and the committed .gitattributes. This is
# not a generic line-ending normalization rule: all other bytes remain literal.
CRLF_PROFILE={
 'llvm/test/MC/AsmParser/preserve-comments-crlf.s':
  ('1d21c1e5dc6bc57809bbac59bdcdfd1c7b99c1531ffdc700ee1ad02cc02d5d7b','8bf094b73ef96aaf874bf3644274cb5e92d73401','27c5b2e070719e34eaba9eadc007ed1ed54376a0'),
 'llvm/test/tools/llvm-mca/X86/directives-handle-crlf.s':
  ('61d867b1992032a4ae53890210fd3ee4e1ed68f40e982616d784412d1c017044','67821474be72a9f142d4ddbc2f1ed9820924700f','db797a75c2617e4152cd8d06a45a8d69a1c91270'),
 'llvm/test/tools/split-file/basic.crlf.test':
  ('e239166284fa9beea9834cd772966f75fcc28215da442980bfc392dc693972b7','6d89c69064e5e9a89db3ff2b0dc5f4ff2090f309','f01074a87963028ea5fe008ea6452c06b8dd644b'),
 'llvm/test/tools/split-file/Inputs/basic-aa.crlf':
  ('c0f4c51937b2bd9b8582d7a66a41d98991e7df263cb0582925e3702c4f239e1e','aa8822c8e1453543a4c9a1b012e8865b2fb2f7d8','0b9ddeb2fc12a1405569a5269f37d4c41f4b4654'),
 'llvm/test/tools/split-file/Inputs/basic-bb.crlf':
  ('71049ad75863b7c2bb17720bcfc11945b9cbfed2507e8e3e2571fb06f6058c65','3c765c42c01271a3a3ceaa92e8bf5e0d44c4153e','b6c3c808ec62fd7b693e657312037160695bbfda')}

class TreeNode(dict):
    """Separate directory nodes from file records, even for a file named git_mode."""

def require(value,message):
    if not value:raise ValueError(message)
def encode(value):return value.encode('utf-8','surrogateescape')
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def git_object(kind,data):
    return hashlib.sha1(kind.encode()+b' '+str(len(data)).encode()+b'\0'+data).hexdigest()
def canonicalize_known(path,data):
    if path not in CRLF_PROFILE:return data,None
    raw_sha,raw_oid,canonical_oid=CRLF_PROFILE[path]
    require(hashlib.sha256(data).hexdigest()==raw_sha and git_object('blob',data)==raw_oid,
            'known CRLF archive blob differs: '+path)
    canonical=data.replace(b'\r\n',b'\n')
    require(b'\r' not in canonical and git_object('blob',canonical)==canonical_oid,
            'canonical Git blob differs: '+path)
    return canonical,{'path':path,'raw_archive_sha256':raw_sha,'raw_archive_git_oid':raw_oid,
                      'raw_archive_size':len(data),'canonical_git_oid':canonical_oid,
                      'canonical_sha256':hashlib.sha256(canonical).hexdigest(),
                      'canonical_size':len(canonical),'rule':'exact-five-path CRLF-to-LF; official .gitattributes text eol=crlf'}
def name_parts(name):
    require(isinstance(name,str) and name and '\0' not in name and not name.startswith('/'),'absolute/empty/NUL member')
    parts=name.rstrip('/').split('/')
    require(all(part not in ('','..','.') for part in parts),'non-canonical member path: '+repr(name))
    return tuple(parts)
def safe_link(parts,target):
    require(target and '\0' not in target and not PurePosixPath(target).is_absolute(),'absolute/empty/NUL symlink target')
    stack=list(parts[:-1])
    for component in target.split('/'):
        if component in ('','.'):continue
        if component=='..':
            require(len(stack)>1,'symlink leaves selected forest')
            stack.pop()
        else:stack.append(component)
    require(stack and stack[0] in EXPECTED,'symlink leaves selected subtrees')

def hash_stream(stream,size,output=None):
    git=hashlib.sha1(b'blob '+str(size).encode()+b'\0');digest=hashlib.sha256();remaining=size
    while remaining:
        block=stream.read(min(1024*1024,remaining))
        require(bool(block),'incomplete selected file payload')
        remaining-=len(block);git.update(block);digest.update(block)
        if output is not None:output.write(block)
    return git.hexdigest(),digest.hexdigest()

def collect_archive(archive,blobs,prefix=PREFIX):
    """Stage complete selected blobs only. No tar-controlled filesystem paths."""
    files={};directories={};seen=set();selected_bytes=0;last_member=None;error=None;normalizations=[];attributes_verified=False
    require(blobs.is_dir() and not blobs.is_symlink(),'private blob store absent')
    try:
        with tarfile.open(archive,'r|gz',encoding='utf-8',errors='surrogateescape') as stream:
            for member in stream:
                last_member=member.name;parts=name_parts(member.name)
                require(parts[0]==prefix,'unexpected archive root')
                require(member.isdir() or member.isfile() or member.issym(),'unsupported special/hardlink archive member')
                require(member.isdir() or not member.name.endswith('/'),'non-directory has trailing slash')
                require(not member.sparse,'sparse archive member unsupported')
                require(not member.mode&0o7000,'special permission bits unsupported')
                if len(parts)==1:
                    require(member.isdir(),'archive root is not a directory');continue
                if parts[1] not in EXPECTED:continue
                relative=parts[1:];key='/'.join(relative)
                require(key not in seen,'duplicate selected archive path');seen.add(key)
                require(len(seen)<=MAX_FILES,'selected entry count limit')
                mode=member.mode&0o777
                if member.isdir():directories[key]=mode;continue
                require(len(relative)>1,'selected subtree root must be a directory')
                record={'path':key,'mode':mode}
                if member.issym():
                    safe_link(relative,member.linkname);data=encode(member.linkname)
                    record.update(git_mode='120000',size=len(data),git_oid=git_object('blob',data),
                                  sha256=hashlib.sha256(data).hexdigest(),link_target=member.linkname)
                else:
                    require(member.size>=0 and selected_bytes+member.size<=MAX_SELECTED_BYTES,'selected byte limit')
                    selected_bytes+=member.size
                    blob=blobs/('%08d'%len(files))
                    source=stream.extractfile(member);require(source is not None,'regular payload absent')
                    canonical_size=member.size
                    with source,blob.open('xb') as target:
                        if key in CRLF_PROFILE:
                            require(attributes_verified,'canonicalization before verified official attributes')
                            require(member.size<=4096,'known CRLF blob unexpectedly large')
                            raw=source.read();require(len(raw)==member.size,'incomplete known CRLF blob')
                            data,normalization=canonicalize_known(key,raw);target.write(data)
                            oid=git_object('blob',data);digest=hashlib.sha256(data).hexdigest();canonical_size=len(data)
                            normalizations.append(normalization)
                        else:oid,digest=hash_stream(source,member.size,target)
                    if key=='llvm/.gitattributes':
                        require(oid==ATTRIBUTES_GIT_OID,'official LLVM attributes differ')
                        attributes_verified=True
                    record.update(git_mode='100755' if mode&0o100 else '100644',size=canonical_size,git_oid=oid,sha256=digest)
                    record['_blob']=str(blob)
                files[key]=record
                if len(files)%20000==0:print(json.dumps({'phase':'collected','files':len(files),'bytes':selected_bytes}),flush=True)
    except (EOFError,tarfile.ReadError) as failure:
        # The only permission to proceed is the full independent tree match
        # below. This exception never establishes archive completeness.
        error={'type':type(failure).__name__,'message':str(failure),'last_member':last_member}
    return files,directories,{'stream_error':error,'last_member':last_member,
                              'whole_archive_verified':False,'selected_regular_bytes':selected_bytes,
                              'canonicalizations':normalizations,'official_attributes_verified':attributes_verified}

def build_trie(files):
    roots={name:TreeNode() for name in EXPECTED}
    for key,record in files.items():
        parts=name_parts(key);require(parts[0] in roots and len(parts)>1,'unexpected selected file path')
        node=roots[parts[0]]
        for part in parts[1:-1]:
            child=node.setdefault(part,TreeNode())
            require(isinstance(child,TreeNode),'file/link is used as a directory')
            node=child
        require(parts[-1] not in node,'duplicate file or directory collision')
        node[parts[-1]]=record
    return roots

def tree_id(node):
    entries=[]
    for name,value in node.items():
        raw=encode(name);require(raw and b'/' not in raw and b'\0' not in raw,'invalid Git entry name')
        if isinstance(value,TreeNode):mode='40000';oid=tree_id(value);sort_key=raw+b'/'
        else:mode=value['git_mode'];oid=value['git_oid'];sort_key=raw
        entries.append((sort_key,mode.encode()+b' '+raw+b'\0'+bytes.fromhex(oid)))
    return git_object('tree',b''.join(entry for _,entry in sorted(entries,key=lambda item:item[0])))

def trees(files):return {name:tree_id(node) for name,node in build_trie(files).items()}
def public_record(record):return {key:value for key,value in record.items() if key!='_blob'}
def inventory_lines(files):
    for key in sorted(files,key=encode):
        yield (json.dumps(public_record(files[key]),ensure_ascii=True,sort_keys=True,separators=(',',':'))+'\n').encode()
def inventory_sha(files):
    h=hashlib.sha256()
    for line in inventory_lines(files):h.update(line)
    return h.hexdigest()

def materialize(files,directories,destination):
    require(not destination.exists() and not destination.is_symlink(),'materialization target already exists')
    destination.mkdir()
    paths=set(EXPECTED)
    for key in files:
        parts=key.split('/')
        paths.update('/'.join(parts[:i]) for i in range(1,len(parts)))
    require(not (set(files)&paths),'file/link overlaps required directory')
    for key in sorted(paths,key=lambda p:(p.count('/'),encode(p))):
        path=destination/key;path.mkdir();os.chmod(path,directories.get(key,0o755))
    # Stage all ordinary files before any symlink exists, so a tar-controlled
    # symlink can never become the parent of a materialization write.
    for key,record in files.items():
        if record['git_mode']=='120000':continue
        target=destination/key
        with Path(record['_blob']).open('rb') as source,target.open('xb') as output:shutil.copyfileobj(source,output,1024*1024)
        os.chmod(target,record['mode'])
    for key,record in files.items():
        if record['git_mode']!='120000':continue
        target=destination/key;os.symlink(record['link_target'],target)
        if stat.S_IMODE(target.lstat().st_mode)!=record['mode']:
            require(hasattr(os,'lchmod'),'cannot preserve symlink mode on this host')
            os.lchmod(target,record['mode'])
    root=destination.resolve()
    for key,record in files.items():
        if record['git_mode']=='120000':
            require((destination/key).resolve().is_relative_to(root),'resolved symlink chain escapes selected forest')

def scan_filesystem(directory):
    directory=Path(directory)
    require(directory.is_dir() and not directory.is_symlink(),'source root must be a real directory')
    root=directory.resolve();files={}
    def walk(path,parts):
        require(not path.is_symlink(),'directory symlink cannot be traversed')
        entries=list(os.scandir(path));require(bool(entries),'untracked empty directory in recovered subtree')
        for entry in entries:
            child=path/entry.name;relative=(*parts,entry.name);key='/'.join(relative);info=entry.stat(follow_symlinks=False)
            require(not stat.S_IMODE(info.st_mode)&0o7000,'special filesystem permission bits')
            if stat.S_ISDIR(info.st_mode):walk(child,relative);continue
            record={'path':key,'mode':stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode):
                target=os.readlink(child);safe_link(relative,target)
                require(child.resolve().is_relative_to(root),'filesystem link chain escapes source')
                data=encode(target);record.update(git_mode='120000',size=len(data),git_oid=git_object('blob',data),
                    sha256=hashlib.sha256(data).hexdigest(),link_target=target)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'special/hardlinked filesystem file unsupported')
                with child.open('rb') as f:oid,digest=hash_stream(f,info.st_size)
                after=child.stat(follow_symlinks=False)
                require((info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_mode)==
                        (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_mode),'source file changed during hashing')
                record.update(git_mode='100755' if info.st_mode&0o100 else '100644',size=info.st_size,git_oid=oid,sha256=digest)
            files[key]=record
    for name in EXPECTED:
        path=directory/name
        require(path.is_dir() and not path.is_symlink(),'selected subtree absent or symlink: '+name)
        walk(path,(name,))
    return files

def verify_recovered(directory):
    """Re-read actual filesystem blobs and Git trees; the proof is not a stamp."""
    directory=Path(directory)
    require(directory.is_dir() and not directory.is_symlink(),'recovered source root is absent or a symlink')
    directory=directory.resolve()
    require({p.name for p in directory.iterdir()}=={*EXPECTED,'.recovery.json'},'recovered root has unknown/missing entries')
    proof=json.loads((directory/'.recovery.json').read_text())
    require(proof.get('commit')==COMMIT and proof.get('expected_trees')==EXPECTED,'wrong recovered-source profile')
    actual=scan_filesystem(directory);computed=trees(actual)
    require(computed==EXPECTED,'actual filesystem Git tree differs from pinned official source')
    digest=inventory_sha(actual)
    require(digest==proof['file_inventory_sha256'],'actual filesystem file inventory differs from recovery')
    return {'status':'VERIFIED_SUBTREES_CURRENT','directory':str(directory),'commit':COMMIT,'trees':computed,
            'file_count':len(actual),'file_inventory_sha256':digest,'whole_archive_verified':False,
            'scope':'only complete llvm and cmake subtrees; no third-party, whole archive, build or rendering proof'}

def recover(archive=ARCHIVE,destination=DESTINATION,metadata=METADATA):
    archive=Path(archive).resolve(strict=True);destination=Path(destination).absolute();metadata=Path(metadata).resolve(strict=True)
    OUT.mkdir(parents=True,exist_ok=True);ep=OUT/'evidence.json'
    if ep.exists():
        history=OUT/'history';history.mkdir(exist_ok=True);shutil.copyfile(ep,history/(sha(ep)+'.json'))
    inputs={'archive':{'path':str(archive),'size':archive.stat().st_size,'sha256':sha(archive)},
            'metadata':{'path':str(metadata),'sha256':sha(metadata)},
            'script':{'path':str(Path(__file__).resolve()),'sha256':sha(__file__)},
            'python':{'path':str(Path(sys.executable).resolve()),'sha256':sha(sys.executable)}}
    record={'status':'RUNNING','inputs_before':inputs,'command':[sys.executable,*sys.argv],
            'whole_archive_verified':False,'scope':'selected-subtree recovery from a known incomplete archive'}
    ep.write_text(json.dumps(record,indent=2)+'\n')
    published=False
    try:
        require(inputs['archive']['size']==ARCHIVE_SIZE and inputs['archive']['sha256']==ARCHIVE_SHA,'not the pinned truncated input')
        official=json.loads(metadata.read_text())
        require(official['repository']=='llvm/llvm-project' and official['commit']==COMMIT,'wrong expected-tree authority/commit')
        entries={r['path']:r for r in official['entries']}
        require(len(entries)==len(official['entries']) and all(entries[n]['type']=='tree' and entries[n]['mode']=='040000'
                and entries[n]['sha']==oid for n,oid in EXPECTED.items()),'official expected Git trees differ')
        shutil.copyfile(metadata,OUT/'expected-trees.json')
        require(not destination.exists() and not destination.is_symlink(),'publish destination already exists; use --verify')
        destination.parent.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.llvm-recovery-',dir=destination.parent) as temporary:
            staging=Path(temporary);blobs=staging/'blobs';blobs.mkdir()
            files,directories,termination=collect_archive(archive,blobs)
            computed=trees(files);record.update(collection=termination,collected_trees=computed,collected_file_count=len(files))
            ep.write_text(json.dumps(record,indent=2)+'\n')
            require(termination['official_attributes_verified'] and
                    {item['path'] for item in termination['canonicalizations']}==set(CRLF_PROFILE),
                    'incomplete exact-five-path conversion evidence')
            require(computed==EXPECTED,'selected archive files do not equal complete official Git trees; nothing published')
            print(json.dumps({'phase':'official_git_trees_match','trees':computed,'files':len(files)}),flush=True)
            target=staging/'materialized';materialize(files,directories,target)
            actual=scan_filesystem(target);require(trees(actual)==EXPECTED,'materialized filesystem tree mismatch')
            require(inventory_sha(actual)==inventory_sha(files),'materialized file contents/modes/links differ')
            inventory=OUT/'files.jsonl.gz'
            with inventory.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as output:
                for line in inventory_lines(actual):output.write(line)
            proof={'schema':2,'status':'VERIFIED_CANONICAL_SUBTREES_ONLY','commit':COMMIT,'expected_trees':EXPECTED,
                   'file_count':len(actual),'file_inventory_sha256':inventory_sha(actual),'archive':inputs['archive'],
                   'metadata_sha256':inputs['metadata']['sha256'],'recovery_script_sha256':inputs['script']['sha256'],
                   'whole_archive_verified':False,'stream_termination':termination,
                   'scope':'canonical Git bytes for llvm and cmake only; five explicit eol=crlf tests restored to LF; incomplete archive remains incomplete; third-party is not supplied'}
            (target/'.recovery.json').write_text(json.dumps(proof,indent=2)+'\n')
            for key in ('archive','metadata','script','python'):
                require(sha(inputs[key]['path'])==inputs[key]['sha256'],'recovery input changed: '+key)
            require(archive.stat().st_size==ARCHIVE_SIZE,'truncated archive size changed')
            require(not destination.exists() and not destination.is_symlink(),'publish target appeared concurrently')
            target.rename(destination)
            published=True
        verified=verify_recovered(destination)
        record.update(status='VERIFIED_SUBTREES_PUBLISHED',inputs_after=inputs,expected_trees=EXPECTED,
            filesystem_verification=verified,file_inventory=str(inventory),file_inventory_gzip_sha256=sha(inventory),
            expected_metadata_sha256=sha(OUT/'expected-trees.json'),destination=str(destination),
            note='EOF/truncation was not accepted as complete archive; official Git tree identity is the independent completeness criterion')
        ep.write_text(json.dumps(record,indent=2)+'\n');return record
    except Exception as error:
        record.update(status='PUBLISHED_REVERIFY_FAILED' if published else 'REJECTED_NOT_PUBLISHED',error=str(error))
        ep.write_text(json.dumps(record,indent=2)+'\n');raise

def self_test():
    """Independent native Git comparison plus safe synthetic archive failures."""
    import io
    records=[]
    with tempfile.TemporaryDirectory(prefix='llvm-recovery-tests-') as temporary:
        area=Path(temporary);repo=area/'objects.git'
        subprocess.run(['git','init','--bare',str(repo)],capture_output=True,check=True)
        oid=git_object('blob',b'x');node=TreeNode({'foo':TreeNode({'child':{'git_mode':'100644','git_oid':oid}}),
             'foo.bar':{'git_mode':'100644','git_oid':oid},'foo0':{'git_mode':'100755','git_oid':oid},
             'utf8-é':{'git_mode':'120000','git_oid':oid},'raw-\udcff':{'git_mode':'100644','git_oid':oid}})
        def native_tree(value):
            data=b''
            for name,entry in reversed(list(value.items())):
                is_file=not isinstance(entry,TreeNode);mode=entry['git_mode'] if is_file else '040000'
                child=entry['git_oid'] if is_file else native_tree(entry)
                data+=encode(mode+' '+('blob' if is_file else 'tree')+' '+child+'\t'+name)+b'\0'
            return subprocess.run(['git','--git-dir='+str(repo),'mktree','-z','--missing'],input=data,capture_output=True,check=True).stdout.decode().strip()
        require(tree_id(node)==native_tree(node),'Git directory slash/UTF8/surrogateescape sort mismatch')
        records.append({'case':'native-git-tree-sorting-and-modes','status':'PASS'})
        require(git_object('blob',b'x')==subprocess.run(['git','hash-object','--stdin'],input=b'x',capture_output=True,check=True).stdout.decode().strip(),
                'Git blob header/hash mismatch')
        records.append({'case':'native-git-blob-hash','status':'PASS'})
        cases=[('absolute','/outside',tarfile.REGTYPE,''),('dotdot',PREFIX+'/llvm/../escape',tarfile.REGTYPE,''),
               ('hardlink',PREFIX+'/llvm/link',tarfile.LNKTYPE,PREFIX+'/llvm/a'),
               ('fifo',PREFIX+'/llvm/fifo',tarfile.FIFOTYPE,''),
               ('symlink-escape',PREFIX+'/llvm/link',tarfile.SYMTYPE,'../../outside')]
        for label,name,kind,link in cases:
            archive=area/(label+'.tar.gz');blobs=area/label;blobs.mkdir()
            with tarfile.open(archive,'w:gz') as t:
                member=tarfile.TarInfo(name);member.type=kind;member.mode=0o644;member.linkname=link
                member.size=1 if kind==tarfile.REGTYPE else 0;t.addfile(member,io.BytesIO(b'x') if member.size else None)
            try:collect_archive(archive,blobs)
            except ValueError as error:records.append({'case':label,'status':'REJECT','reason':str(error)})
            else:raise RuntimeError('unsafe archive accepted: '+label)
        # Neither removing nor changing one blob may preserve the tree hash.
        changed=copy.deepcopy(node);changed['foo0']['git_oid']=git_object('blob',b'y')
        require(tree_id(changed)!=tree_id(node),'changed blob not detected')
        copy_node=copy.deepcopy(node)
        del copy_node['foo.bar'];require(tree_id(copy_node)!=tree_id(node),'missing blob not detected')
        records.append({'case':'changed-and-missing-tree-contents','status':'REJECT'})
        known='llvm/test/tools/split-file/Inputs/basic-aa.crlf'
        data,proof=canonicalize_known(known,b'\r\naa\r\n')
        require(data==b'\naa\n' and proof['canonical_git_oid']==CRLF_PROFILE[known][2],'exact CRLF rule failed')
        records.append({'case':'exact-known-CRLF-to-canonical-LF','status':'PASS'})
        for label,bad in [('already-LF',b'\naa\n'),('changed-CRLF',b'\r\nab\r\n'),('mixed-newlines',b'\naa\r\n')]:
            try:canonicalize_known(known,bad)
            except ValueError as error:records.append({'case':label,'status':'REJECT','reason':str(error)})
            else:raise RuntimeError('changed normalization input accepted: '+label)
        data,proof=canonicalize_known('llvm/test/tools/llvm-ar/Inputs/mri-crlf.mri',b'literal\r\n')
        require(data==b'literal\r\n' and proof is None,'unlisted CRLF bytes were changed')
        records.append({'case':'unlisted-CRLF-byte-identity','status':'PASS'})
    return {'status':'SELF_TEST_PASS','records':records,'case_count':len(records),
            'scope':'local Git object oracle and synthetic boundary tests; no download or production source mutation'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,default=ARCHIVE);parser.add_argument('--destination',type=Path,default=DESTINATION)
    parser.add_argument('--metadata',type=Path,default=METADATA);parser.add_argument('--verify',type=Path);parser.add_argument('--self-test',action='store_true')
    args=parser.parse_args()
    if args.self_test:result=self_test()
    elif args.verify:result=verify_recovered(args.verify)
    else:result=recover(args.archive,args.destination,args.metadata)
    print(json.dumps(result,indent=2))
