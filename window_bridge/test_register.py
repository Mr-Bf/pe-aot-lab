#!/usr/bin/env python3
"""Actual register CALL matrix plus separate, read-only strict acceptance."""
import argparse,json,traceback
from pathlib import Path
from window_bridge import register_probe as p
from window_bridge.register_acceptance import verify_run

OUT=p.ROOT/'build/window-bridge/register-acceptance-v1'
NAMES=('good','bad-offset','bad-guest','bad-method','bad-release-target')
def specifications():
    rows=[]
    for mode in ('O3','O0'):
        for name in NAMES:
            _,_,module=p.select_fixture(name);m=p.graphics.read_json(module/'manifest.json')
            call=m['register_calls'][0]['call_rva'];prefix=sum(i['rva']<call for i in m['instructions'])
            budgets=(None,3,4,5,6,7) if name=='good' else (None,prefix)
            build=p.OUT/(name+'-'+mode+'-r3')
            rows += [(name,mode,budget,build,build/('run-None-'+str(budget))) for budget in budgets]
    return rows
def audit():
    records=[];results={};identity=p.snapshot(p.python_closure([Path(__file__)]))
    for name,mode,budget,build,directory in specifications():
        e=verify_run(directory);raw=p.graphics.read_json(directory/'evidence.json')['result']
        records.append({k:v for k,v in e.items() if k not in ('inputs_before','inputs_after')})
        identity.update(e['inputs_before']);results[name,mode,budget]=raw
    comparisons=[]
    for name in NAMES:
        budgets=[b for n,m,b,_,_ in specifications() if n==name and m=='O3']
        for budget in budgets:
            a,b=results[name,'O3',budget],results[name,'O0',budget]
            p.require(a==b,'O3/O0 complete observations differ: '+name+'/'+str(budget))
            comparisons.append({'kind':'O3_O0_complete_result','name':name,'budget':budget,
                                'state_bytes':3504,'stack_bytes':65536})
        if name!='good':
            prefix=next(b for b in budgets if b is not None)
            for mode in ('O3','O0'):
                a,b=results[name,mode,None],results[name,mode,prefix]
                p.require(a['state_hex']==b['state_hex'] and a['stack_hex']==b['stack_hex'],
                          'rejected CALL differs from before-CALL full checkpoint: '+name+'/'+mode)
                p.require(a['steps']==b['steps']+1,'rejected CALL was not attempted exactly once')
                comparisons.append({'kind':'CALL_rejection_rollback','name':name,'mode':mode,
                                    'state_bytes':3504,'stack_bytes':65536,'fault_steps_delta':1})
    p.unchanged(identity);after=p.snapshot(identity);p.require(identity==after,'matrix inputs changed')
    return {'status':'PASS_STRICT_REGISTER_MATRIX','records':records,'comparisons':comparisons,
            'historical_guest_executions_verified':len(records),'new_guest_executions':0,
            'gpu_api_calls':0,'windows_oracle_executions':0,'all_runs_at_preferred_base':True,
            'inputs_before':identity,'inputs_after':after,
            'scope':'closed register-import targets, explicit budgets, full State/stack O3/O0 and failed CALL rollback; no window/API200+/GPU'}
def execute():
    p.require(not (OUT/'evidence.json').exists(),'refuse replay of completed matrix');OUT.mkdir(parents=True,exist_ok=True)
    executions=0;adopted=0
    try:
        for name,mode,budget,build,directory in specifications():
            if not build.exists():p.build(name,mode,build)
            if directory.exists():verify_run(directory);adopted+=1
            else:
                print(json.dumps(p.run(build,budget)),flush=True);executions+=1
                verify_run(directory)
        result=audit();result['execution_batch']={'new_guest_executions':executions,'adopted_existing_runs':adopted}
        p.graphics.save(OUT/'evidence.json',result)
        print(json.dumps({'status':result['status'],'new_guest_executions':executions,'adopted':adopted,
                          'records':len(result['records']),'comparisons':len(result['comparisons'])}),flush=True)
    except Exception as error:
        p.graphics.save(OUT/'failure.json',{'status':'MATRIX_FAILED','error':str(error),'traceback':traceback.format_exc(),
            'completed_new_runs':executions,'adopted':adopted,'source_sha256':p.sha(__file__)})
        raise
def verify():
    saved=p.graphics.read_json(OUT/'evidence.json');current=audit()
    p.require({k:v for k,v in saved.items() if k!='execution_batch'}==current,'stored matrix differs from rederived matrix')
    batch=saved['execution_batch'];p.require(batch['new_guest_executions']+batch['adopted_existing_runs']==len(current['records']),'matrix execution accounting differs')
    return {'status':'PASS_STRICT_REGISTER_MATRIX_READ_ONLY','records':len(current['records']),
            'comparisons':len(current['comparisons']),'new_guest_executions':0}
if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--verify-only',action='store_true');args=a.parse_args()
    if args.verify_only:print(json.dumps(verify()))
    else:execute()
