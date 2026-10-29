#!/usr/bin/env python3
"""Stricter, read-only consumer for immutable register probe executions.

The build/run producer stays frozen. Adding this verifier does not rerun guest
code or change previously recorded commands, binaries, streams or outcomes.
"""
import argparse,json
from pathlib import Path
from window_bridge import register_probe as probe

def verify_run(directory):
    directory=Path(directory).resolve()
    paths=[directory/name for name in ('started.json','evidence.json','stdout','stderr')]
    paths += probe.python_closure([Path(__file__)])
    before=probe.snapshot(paths)
    e=probe.verify_run(directory);r=probe.verify(directory.parent)
    probe.require(directory.name=='run-'+str(e['base'])+'-'+str(e['budget']),
                  'execution directory differs from recorded configuration')
    started=probe.graphics.read_json(directory/'started.json')
    expected={'status':'RUN_STARTED','command':e['command'],'budget':e['budget'],'base':e['base'],
              'inputs_before':e['inputs_before'],'build_sha256':e['build_sha256'],
              'new_guest_executions':0,'gpu_api_calls':0}
    probe.require(started==expected,'initial command/configuration differs from accepted execution')
    probe.require(e['inputs_before']==probe.run_inputs(directory.parent,r),'execution closure differs')
    identity={**before,**e['inputs_before']};probe.unchanged(identity)
    after=probe.snapshot(identity);probe.require(identity==after,'acceptance inputs changed during verification')
    return {'status':'PASS_STRICT_REGISTER_EXECUTION','build':str(directory.parent),
            'name':r['name'],'mode':r['mode'],'run':str(directory),'budget':e['budget'],'base':e['base'],
            'expectation':e['expectation'],'steps':e['result']['steps'],
            'new_guest_executions':0,'verified_historical_guest_executions':1,
            'inputs_before':identity,'inputs_after':after}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--out',type=Path);a=p.parse_args()
    result=verify_run(a.directory)
    if a.out:
        probe.require(not a.out.exists(),'refuse overwrite of acceptance record')
        probe.graphics.save(a.out,result)
    print(json.dumps({key:value for key,value in result.items() if key not in ('inputs_before','inputs_after')}))
