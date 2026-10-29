"""Filesystem and recipe gates on synthetic temp data; zero App/GUI/events."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest.mock import patch
from window_bridge import window_app_launch_v4 as wrapper
from window_bridge import noarg_tmpio_v1 as f


def require(value, reason):
    if not value: raise ValueError(reason)


def run(out):
    require(not out.exists(), 'preserve previous tests'); out.mkdir(parents=True)
    cases=[];commands=[];created=[]
    def good(name, action): action();cases.append({'case':name,'result':'PASS'})
    def reject(name, action):
        try:action()
        except (ValueError,OSError):cases.append({'case':name,'result':'REJECTED'});return
        raise ValueError('unexpected acceptance: '+name)
    def source():
        p=f.allocate();p.mkdir();(p/'sample.bin').write_bytes(bytes(range(64)))
        (p.parent/'proof.json').write_text('{"synthetic":true}\n');created.append(str(p));return p
    def dest(name):
        return f.ROOT/'build/window-bridge'/('window-run-app-v4-gate-'+out.name+'-'+name)
    source_text,proof=wrapper.derivation()
    good('exact_four_region_recipe',lambda:require(proof['baseline_source_sha256']==proof['restored_baseline_sha256']==wrapper.BASELINE_SHA and proof['changed_regions']==['output_path_validator','private_output_import','default_output','observation_scope'],'derivation'))
    with patch.object(wrapper,'BASELINE_SHA','0'*64):reject('baseline_identity_changed',wrapper.derivation)
    parent=f.allocate();created.append(str(parent));good('owned_0700_empty_parent',lambda:f.output(parent))
    os.chmod(parent.parent,0o755)
    try:reject('wide_parent_mode',lambda:f.output(parent))
    finally:os.chmod(parent.parent,0o700)
    uid=os.geteuid()
    with patch.object(f.os,'geteuid',lambda:uid+1):reject('foreign_uid_predicate',lambda:f.output(parent))
    # Real Darwin ACL negative uses only our newly created empty test parent.
    cmd=['/bin/chmod','+a','everyone allow read,search',str(parent.parent)]
    p=subprocess.run(cmd,capture_output=True,text=True);commands.append({'command':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    require(p.returncode==0,'ACL test preparation failed')
    try:reject('real_nonempty_acl',lambda:f.output(parent))
    finally:
        cmd=['/bin/chmod','-N',str(parent.parent)];p=subprocess.run(cmd,capture_output=True,text=True);commands.append({'command':cmd,'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr});require(p.returncode==0,'ACL cleanup failed')
    good('empty_acl_restored',lambda:f.output(parent))
    alias=f.allocate();alias.parent.rmdir();os.symlink(parent.parent,alias.parent)
    try:reject('parent_symlink_alias',lambda:f.output(alias))
    finally:alias.parent.unlink()
    reject('dotdot_path_alias',lambda:f.output(parent.parent/'a/../records'))
    reject('wrong_records_name',lambda:f.output(parent.parent/'other'))
    p=source();target=dest('positive')
    good('archive_preserves_raw_bytes_and_modes',lambda:f.archive(p,target))
    good('archive_original_retained',lambda:require(p.exists() and f.tree(p.parent)==f.tree(target/'original'),'retained'))
    reject('archive_destination_reuse',lambda:f.archive(p,target))
    reject('records_reuse_before_target',lambda:wrapper.execute(records=p,archive_out=dest('not-started'),timeout=180,preflight=True))
    p=source();target=dest('tamper');f.archive(p,target)
    (target/'original/records/sample.bin').write_bytes(b'changed')
    reject('archive_byte_mutation',lambda:f.verify_archive(target))
    p=source();target=dest('mode');f.archive(p,target)
    os.chmod(target/'original/records/sample.bin',0o600)
    reject('archive_mode_mutation',lambda:f.verify_archive(target))
    p=source();target=dest('rootmode');f.archive(p,target)
    os.chmod(target/'original',0o755)
    try:reject('archive_root_mode_mutation',lambda:f.verify_archive(target))
    finally:os.chmod(target/'original',0o700)
    p=source();os.symlink('sample.bin',p/'link')
    reject('source_symlink_rejected',lambda:f.archive(p,dest('symlink')))
    p=source();os.mkfifo(p/'fifo',0o600)
    reject('source_special_file_rejected',lambda:f.archive(p,dest('fifo')))
    p=source();target=dest('copyfail');before=f.tree(p.parent)
    with patch.object(f.shutil,'copy2',side_effect=OSError('injected archive copy failure')):
        reject('archive_copy_failure',lambda:f.archive(p,target))
    good('copy_failure_retains_original',lambda:require(f.tree(p.parent)==before and (target/'archive-failure.json').is_file() and not(target/'archive.json').exists(),'failure retention'))
    reject('partial_archive_not_accepted',lambda:f.verify_archive(target))
    result={'status':'PASS_V4_OUTPUT_AND_ARCHIVE_COMPONENT_GATES','cases':cases,'count':len(cases),'commands':commands,
       'source_sha256':{str(Path(x).resolve()):f.sha(x) for x in [__file__,wrapper.__file__,f.__file__,wrapper.baseline.__file__]},
       'derivation':proof,'synthetic_private_records':created,
       'scope':{'App_launches':0,'GUI':0,'GPU':0,'events':0,'signals':0,'real_owned_temp_ACL_negative':1,'mock_foreign_UID':1,'mock_archive_failure':1}}
    f.write(out/'evidence.json',result);return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    print(json.dumps(run(a.out.resolve()),indent=2,sort_keys=True))
