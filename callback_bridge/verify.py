#!/usr/bin/env python3
"""Read-only callback milestone acceptance; reruns no guest code."""
import argparse,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from callback_bridge.test_program import verify_evidence as verify_program
from callback_bridge.test_sanitizers import verify_evidence as verify_sanitizers
BASE=ROOT/'build/callback-bridge'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def require(value,message):
    if not value:raise ValueError(message)
def verify():
    program=verify_program(BASE/'program-tests')
    require(program['unique_normal_inputs']==program['raw_x86_cases']==2048 and program['unique_budget_cases']==148,
            'expected final Program coverage absent')
    sanitizer=verify_sanitizers(BASE/'sanitizers')
    path=BASE/'lift-tests/evidence.json';lift=json.loads(path.read_text())
    require(lift.get('status')=='PASS' and lift['positive_cases']==7 and lift['rejected_cases']==37 and
            lift['lifted_root_modules']==11,'lifter coverage incomplete')
    require(lift['inputs_before']==lift['inputs_after'],'lifter inputs changed during tests')
    for name,digest in lift['inputs_after'].items():require(sha(name)==digest,'lifter input changed: '+name)
    for name,digest in lift['artifact_sha256'].items():require(sha(path.parent/name)==digest,'lifter artifact changed: '+name)
    return {'status':'ACCEPTANCE_CURRENT','mode':'existing_evidence_and_hashes_only',
        'unique_raw_x86_inputs':2048,'program_modes':['O3','O0'],'program_budget_cases':148,
        'sanitizer_normal_calls':sanitizer['unique_normal_calls'],
        'sanitizer_mutant_rejections':sanitizer['unique_mutant_rejections'],
        'evidence_sha256':{str(p.relative_to(ROOT)):sha(p) for p in
            [path,BASE/'program-tests/evidence.json',BASE/'sanitizers/evidence.json']},
        'scope':'registered synchronous integer callbacks; no Windows execution, async callbacks or game claim'}
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--record',type=Path);args=parser.parse_args()
    result=json.dumps(verify(),indent=2)+'\n'
    if args.record:args.record.write_text(result)
    print(result,end='')
