#!/usr/bin/env python3
"""Read-only shader metadata/structure rejection checks, no GPU execution."""
from pathlib import Path
import copy
import hashlib
import json
import struct
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from graphics_stage5 import build_shaders as build


def main():
    positive = build.verify_shaders()
    original_loads = json.loads
    cases = []
    def reject(name, mutation):
        def reader(text, *args, **kwargs):
            record = original_loads(text, *args, **kwargs)
            if isinstance(record, dict) and record.get('status') == 'SHADERS_BUILT_NOT_EXECUTED':
                record = copy.deepcopy(record)
                mutation(record)
            return record
        try:
            with patch.object(build.json, 'loads', reader):
                build.verify_shaders()
        except RuntimeError as error:
            cases.append({'name': name, 'rejected': True, 'reason': str(error)})
        else:
            raise RuntimeError('accepted invalid shader evidence: '+name)
    reject('false_status', lambda r: r.update(status='FAIL'))
    reject('invented_gpu_execution', lambda r: r.update(gpu_executions=1))
    reject('wrong_output_color', lambda r: r.update(expected_rgba8=[255,0,0,255]))
    reject('missing_stage', lambda r: r['bytecode'].pop('ps'))
    reject('empty_artifacts', lambda r: r.update(artifacts={}))
    reject('missing_input', lambda r: (r['inputs_before'].pop(str(build.COMPILER)),r['inputs_after'].pop(str(build.COMPILER))))
    reject('nested_failed_compile', lambda r: r['commands'][0].update(returncode=1))
    reject('wrong_bytecode_stage', lambda r: r['bytecode']['vs'].update(shader_type=0))
    original = (build.OUT/'triangle.vs.dxbc').read_bytes()
    malformed = {
        'truncated_container': original[:31],
        'wrong_magic': b'FAIL'+original[4:],
        'incorrect_total': original[:24]+struct.pack('<I',len(original)+4)+original[28:],
        'out_of_range_chunk': original[:32]+struct.pack('<I',len(original))+original[36:],
    }
    for name, data in malformed.items():
        try:
            build.inspect_dxbc(data, 1)
        except RuntimeError as error:
            cases.append({'name':name,'rejected':True,'reason':str(error)})
        else:
            raise RuntimeError('accepted malformed DXBC structure: '+name)
    build.require(len(cases)==12 and all(c['rejected'] for c in cases), 'gate count/status differs')
    record = {'status':'SHADER_GATE_PASS','positive':1,'rejections':12,'cases':cases,
              'gpu_executions':0,'guest_executions':0,'python_optimized':bool(sys.flags.optimize),
              'source_sha256':build.sha(__file__),'producer_sha256':build.sha(build.__file__),
              'evidence_sha256':positive['evidence_sha256'],
              'scope':'in-memory metadata mutations and bounded container parsing; no compiler/GPU/guest replay; integrity, not digital signatures'}
    suffix = '-optimized' if sys.flags.optimize else ''
    build.dump(build.OUT/('gate'+suffix+'.json'),record)
    print(json.dumps(record,indent=2))


if __name__ == '__main__':
    main()
