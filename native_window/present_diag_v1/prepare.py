"""Prepare a private source-only diagnostic tree. Never configure/build/load/run.

Default is read-only verification; --prepare requires fresh exact paths.
"""
import argparse,difflib,hashlib,json,shutil,stat
from pathlib import Path
from native_window.present_diag_v1.source_transform import TARGETS,derive

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
BASE=ROOT.parents[1]/'work/native-window-v2/dxmt-source-v2'
DEST=ROOT.parents[1]/'work/native-present-diag-v1/dxmt-source-v1'
OUT=ROOT/'build/native-present-diag-v1/source-01'
BACKEND=ROOT/'build/native-window/backend-v2/evidence.json'
BACKEND_SHA='48c76b4a26f1364ac583579d22e8340815465339bb936d63e977624780a3671b'
ADAPTERS={'diagnostics.h':'include/dxmt_present_diagnostics_v1.h',
          'diagnostics_internal.hpp':'include/dxmt_present_diag_internal_v1.hpp',
          'diagnostics.cpp':'src/nativemetal/present_diagnostics_v1.cpp'}
STATUS='SOURCE_PREPARED_NOT_COMPILED_OR_EXECUTED'
def need(x,m):
    if not x:raise ValueError(m)
def sha(data):return hashlib.sha256(data).hexdigest()
def tree(path):
    result={}
    for p in sorted(path.rglob('*')):
        name=p.relative_to(path).as_posix();kind=p.lstat().st_mode
        if stat.S_ISLNK(kind):result[name]=['symlink',str(p.readlink())]
        elif stat.S_ISDIR(kind):result[name]=['directory']
        elif stat.S_ISREG(kind):result[name]=['file',sha(p.read_bytes())]
        else:raise ValueError('special source file '+name)
    return result
def sources():return sorted([HERE/'prepare.py',HERE/'source_transform.py',*(HERE/name for name in ADAPTERS)])
def snapshot(paths):return {str(p.resolve()):sha(p.read_bytes()) for p in paths}
def write(path,value):
    with path.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def reference():
    raw=BACKEND.read_bytes();need(sha(raw)==BACKEND_SHA,'frozen native-window backend receipt')
    e=json.loads(raw);before=e['inputs_before']['source'];after=e['inputs_after']['source']
    need(before==after and Path(after['root'])==BASE,'fixed source pre/post identity')
    need(e['profile']=='native-window-wsi-v1-plus-lifetime-v2-r2','actual WSI/lifetime profile')
    need(tree(BASE)==after['tree_identity'],'base source differs from exact patched build source')
    return e,raw
def render(e):
    original={}
    for p in TARGETS:
        raw=(BASE/p).read_bytes()
        need(e['inputs_after']['source']['tree_identity'][p]==['file',sha(raw)],'actual transformed bytes not bound to original receipt: '+p)
        original[p]=raw.decode('utf-8')
    derived,changes=derive(original)
    expected=dict(e['inputs_after']['source']['tree_identity'])
    for path,text in derived.items():expected[path]=['file',sha(text.encode())]
    for source,target in ADAPTERS.items():
        need(target not in expected,'adapter path already exists in old tree')
        expected[target]=['file',sha((HERE/source).read_bytes())]
    patch=''.join(''.join(difflib.unified_diff(original[p].splitlines(True),derived[p].splitlines(True),fromfile='a/'+p,tofile='b/'+p)) for p in TARGETS)
    return derived,changes,expected,patch
def no_hardlinks(expected):
    for name,identity in expected.items():
        p=BASE/name;q=DEST/name
        if identity[0]=='file' and p.is_file():
            a=p.stat();b=q.stat();need((a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino),'source hardlink '+name)
def prepare():
    need(not OUT.exists() and not DEST.exists(),'fresh private source/evidence required')
    OUT.mkdir(parents=True);inputs=snapshot([BACKEND,*sources()]);write(OUT/'started.json',{'status':'PREPARE_STARTED_NO_BUILD','inputs':inputs})
    try:
        e,receipt=reference();derived,changes,expected,patch=render(e)
        DEST.parent.mkdir(parents=True,exist_ok=True)
        shutil.copytree(BASE,DEST,symlinks=True,copy_function=shutil.copy2)
        need(tree(DEST)==e['inputs_after']['source']['tree_identity'],'copy not equal before transform')
        no_hardlinks(e['inputs_after']['source']['tree_identity'])
        for path,text in derived.items():(DEST/path).write_text(text)
        for source,target in ADAPTERS.items():shutil.copy2(HERE/source,DEST/target)
        (OUT/'present-diagnostics-v1.patch').write_text(patch)
        write(OUT/'changes.json',changes)
        need(tree(DEST)==expected,'exact source transform')
        need(tree(BASE)==e['inputs_after']['source']['tree_identity'],'original source changed')
        need(snapshot([BACKEND,*sources()])==inputs and BACKEND.read_bytes()==receipt,'prepare inputs changed')
        write(OUT/'evidence.json',{'schema':1,'status':STATUS,'base':str(BASE),'destination':str(DEST),
          'backend_receipt_sha256':BACKEND_SHA,'inputs_before':inputs,'inputs_after':inputs,
          'source_tree':expected,'patch_sha256':sha(patch.encode()),'changes_sha256':sha((OUT/'changes.json').read_bytes()),
          'new_build':0,'new_native_guest_gui_gpu_executions':0,
          'scope':'Exact source-only private copy and diagnostic transform; no compiler, symbol, layout, linkage or lifecycle test has run.'})
        return verify()
    except BaseException as error:
        write(OUT/'failure.json',{'status':'FAIL_PREPARE_PRESERVED','error':repr(error)});raise
def verify():
    need((OUT/'evidence.json').is_file(),'NOT_READY: source preparation absent')
    need({p.name for p in OUT.iterdir()}=={'started.json','present-diagnostics-v1.patch','changes.json','evidence.json'},'exact successful source artifact set')
    raw=(OUT/'evidence.json').read_bytes();r=json.loads(raw)
    input_paths=[BACKEND,*sources()];inputs=snapshot(input_paths)
    need(r['status']==STATUS and r['schema']==1 and r['base']==str(BASE) and r['destination']==str(DEST),'source receipt identity')
    e,receipt=reference();derived,changes,expected,patch=render(e)
    need(r['backend_receipt_sha256']==BACKEND_SHA and r['source_tree']==expected==tree(DEST),'exact current source tree')
    need(r['inputs_before']==r['inputs_after']==inputs,'complete producer input closure')
    started=json.loads((OUT/'started.json').read_bytes())
    need(started=={'status':'PREPARE_STARTED_NO_BUILD','inputs':inputs},'actual source preparation start identity')
    need((OUT/'present-diagnostics-v1.patch').read_bytes()==patch.encode() and r['patch_sha256']==sha(patch.encode()),'exact patch bytes')
    changes_raw=(OUT/'changes.json').read_bytes();need(json.loads(changes_raw)==changes and sha(changes_raw)==r['changes_sha256'],'exact replacement log')
    no_hardlinks(expected)
    need(r['new_build']==r['new_native_guest_gui_gpu_executions']==0,'source-only scope')
    need(snapshot(input_paths)==inputs and BACKEND.read_bytes()==receipt and (OUT/'evidence.json').read_bytes()==raw,'inputs or receipts changed')
    need(tree(BASE)==e['inputs_after']['source']['tree_identity'] and tree(DEST)==expected,'source trees changed during verify')
    return {'status':STATUS+'_CURRENT','source_receipt_sha256':sha(raw),'new_build':0,'new_native_guest_gui_gpu_executions':0}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--prepare',action='store_true');a=p.parse_args()
    print(json.dumps(prepare() if a.prepare else verify(),sort_keys=True))
