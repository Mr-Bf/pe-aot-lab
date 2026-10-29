#!/usr/bin/env python3
"""Read-only verification of the single recorded v3 native window execution."""
from pathlib import Path
import copy,json,sys
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from graphics_stage5 import d3d11_probe as base
from native_window import probe as contract
from native_window import probe_v3 as package
OUT=ROOT/'build/native-window/launch-v3'

def verify():
    static=package.verify()
    p=base.read_json(OUT/'prepared.json');r=base.read_json(OUT/'direct.json')
    app=Path(p['copy']);exe=package.executable(app)
    package.require(app.is_relative_to('/private/tmp') and ' ' in str(app),'actual relocated copy is not the required separate path')
    package.require(p['status']=='TMP_COPY_STATICALLY_VERIFIED_NOT_LAUNCHED' and
                    p['producer_result']==static and p['source_evidence_sha256']==static['evidence_sha256'],'preparation does not bind current producer')
    package.require(base.sha(OUT/'run.py')==p['launcher_sha256'] and
                    base.sha(OUT/'copy-signature.json')==p['signature_record_sha256'],'preparation/launcher changed')
    graph=package.package_graph(app)
    package.require(package.tree(app)==p['tree']==package.tree(package.app_path()) and graph==p['library_graph'],'executed copy changed')
    expected_inputs=base.hashes([OUT/'run.py',OUT/'prepared.json',package.OUT/'evidence.json',
                                *[app/name for name in p['tree']],Path('/usr/bin/open'),Path('/bin/ps')])
    package.require(r['inputs_before']==r['inputs_after']==expected_inputs,'exact recorded execution inputs differ')
    package.require(r['status']=='TMP_NATIVE_WINDOW_EXECUTION_PASS' and r['method']=='direct'
                    and type(r['child_exit_code']) is int and r['child_exit_code']==0
                    and not r.get('timed_out') and 'error' not in r,'actual child execution did not succeed')
    package.require(r['command']==[str(exe),'--hold-ms','500'] and r['copy']==str(app)
                    and r['environment']==base.environment(OUT,images=True),'execution command/environment changed')
    expected_artifacts=base.hashes([OUT/'direct.stdout',OUT/'direct.stderr'])
    package.require(r['artifacts']==expected_artifacts,'raw stdout/stderr identity differs')
    raw=base.strict_json((OUT/'direct.stdout').read_text())
    package.require(raw==r['child_result'],'summary differs from raw stdout')
    contract.validate_result(raw,r['child_exit_code'])
    loaded=base.loaded_images((OUT/'direct.stderr').read_text(),exe,graph['nodes'])
    package.require(r['loaded_images']==loaded,'actual loaded images differ')
    return {'status':'NATIVE_WINDOW_V3_EXECUTION_CURRENT','native_executions':1,'present_calls':2,
            'pixels_checked':sum(x['pixels_checked'] for x in raw['phases']),
            'channels_checked':sum(x['channels_checked'] for x in raw['phases']),
            'loaded_images':len(loaded),'guest_executions':0,'draw_calls':0,'compositor_observations':0,
            'direct_evidence_sha256':base.sha(OUT/'direct.json'),'package_evidence_sha256':static['evidence_sha256'],
            'checker_sha256':base.sha(__file__),'result_validator_sha256':base.sha(contract.__file__),
            'note':'integrity and stale-evidence checks, not a digital signature; no new App/GPU execution'}

def gates():
    positive=verify();real_read=base.read_json;cases=[]
    def reject(name,edit):
        def read(path):
            value=real_read(path)
            if Path(path)==OUT/'direct.json':value=copy.deepcopy(value);edit(value)
            return value
        try:
            with patch.object(base,'read_json',read):verify()
        except (RuntimeError,base.IntegrityError) as e:cases.append({'name':name,'rejected':True,'reason':str(e)})
        else:raise RuntimeError('accepted bad execution metadata: '+name)
    reject('nonzero_child_exit',lambda r:r.update(child_exit_code=1))
    reject('timeout_with_PASS',lambda r:r.update(timed_out=True))
    reject('raw_stdout_summary_disagreement',lambda r:r['child_result'].update(phases_done=1))
    reject('missing_actual_loaded_images',lambda r:r.update(loaded_images={}))
    reject('missing_stdout_identity',lambda r:r['artifacts'].pop(str(OUT/'direct.stdout')))
    def remove_input(r):
        k=str(package.OUT/'evidence.json');r['inputs_before'].pop(k);r['inputs_after'].pop(k)
    reject('matching_but_incomplete_input_maps',remove_input)
    package.require(len(cases)==6 and all(c['rejected'] for c in cases),'gate count differs')
    return {'status':'NATIVE_WINDOW_V3_READ_ONLY_GATE_PASS','positive':positive,'rejections':6,'cases':cases,
            'python_optimized':bool(sys.flags.optimize),'additional_native_executions':0,'additional_gpu_executions':0}

if __name__=='__main__':
    if sys.argv[1:]==['--test-gates']:result=gates()
    elif not sys.argv[1:]:result=verify()
    else:raise SystemExit('usage: verify_launch_v3.py [--test-gates]')
    print(json.dumps(result,indent=2,sort_keys=True))
