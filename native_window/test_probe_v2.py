#!/usr/bin/env python3
"""Static bundle gates. Never launch the App, load its libraries, or use a GPU."""
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from native_window import probe_v2 as p


def main():
    positive=p.verify();original_loads=json.loads;cases=[]
    def reject(name,mutation):
        def read(text,*args,**kwargs):
            value=original_loads(text,*args,**kwargs)
            if isinstance(value,dict) and value.get('status')==p.STATUS:
                value=copy.deepcopy(value);mutation(value)
            return value
        try:
            with patch.object(p.json,'loads',read):p.verify()
        except (RuntimeError,p.base.IntegrityError) as error:
            cases.append({'name':name,'rejected':True,'reason':str(error)})
        else:raise RuntimeError('accepted bad static bundle metadata: '+name)
    reject('invented_runtime_relocation',lambda r:r.update(runtime_relocation_verified=True))
    reject('missing_copy_provenance',lambda r:r.update(copied_libraries={}))
    reject('missing_sign_command',lambda r:r.update(commands=[c for c in r['commands'] if c['name']!='sign-app']))
    def remove_input(r):
        key=str(p.backend.OUT/'evidence.json');r['inputs_before'].pop(key);r['inputs_after'].pop(key)
    reject('missing_backend_identity',remove_input)
    # These are actual private copies of the signed App, not mutations of its
    # receipt alone. Original App/relocation/output identities remain frozen.
    with tempfile.TemporaryDirectory(prefix='window-static-gates-') as directory:
        base=Path(directory)
        absent=base/'missing library.app';shutil.copytree(p.app_path(),absent)
        (p.framework(absent)/'winemetal.dylib').unlink()
        try:p.package_graph(absent)
        except (RuntimeError,p.base.IntegrityError) as e:cases.append({'name':'actual_missing_library','rejected':True,'reason':str(e)})
        else:raise RuntimeError('missing actual bundled library accepted')
        extra=base/'extra library.app';shutil.copytree(p.app_path(),extra)
        shutil.copyfile(p.framework(extra)/'dxgi.dylib',p.framework(extra)/'unexpected.dylib')
        try:p.package_graph(extra)
        except (RuntimeError,p.base.IntegrityError) as e:cases.append({'name':'actual_extra_library','rejected':True,'reason':str(e)})
        else:raise RuntimeError('unexpected actual bundled library accepted')
        changed=base/'modified signature.app';shutil.copytree(p.app_path(),changed)
        # Signed Info.plist is a covered resource; a parse-valid byte edit must
        # be rejected by Apple's actual verifier, not just our JSON gate.
        info=changed/'Contents/Info.plist';info.write_bytes(info.read_bytes().replace(b'PE AOT Window Probe V2',b'PE AOT Window Probe XX'))
        result=subprocess.run([p.tools()['codesign'],'--verify','--deep','--strict',str(changed)],capture_output=True,text=True)
        p.require(result.returncode!=0,'modified signed Info.plist accepted')
        cases.append({'name':'actual_signature_resource_mutation','rejected':True,'returncode':result.returncode,'reason':result.stderr})
    p.require(len(cases)==7 and all(c['rejected'] for c in cases),'static gate counts differ')
    record={'status':'STATIC_BUNDLE_GATE_PASS','positive':1,'rejections':7,'cases':cases,
            'python_optimized':bool(sys.flags.optimize),'source_sha256':p.base.sha(__file__),
            'producer_sha256':p.base.sha(p.__file__),'evidence_sha256':positive['evidence_sha256'],
            'scope':p.SCOPE,'note':'metadata gates plus actual temporary App/library/signature mutations; no application execution'}
    suffix='-optimized' if sys.flags.optimize else ''
    (p.OUT/('gate'+suffix+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
