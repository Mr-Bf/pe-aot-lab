"""Real CLI builds of unchanged and data-renamed PEs; never starts guest/GPU."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def main(out):
    out = Path(out).resolve()
    if out.parent != ROOT/'build/migration-v3':
        raise ValueError('new batch directory directly under build/migration-v3 required')
    out.mkdir(parents=True, exist_ok=False)
    source = ROOT/'build/window-bridge/save-load-program-v1-01/input.exe'
    profile_path = ROOT/'window_profile_v1/examples/integer-tile.json'
    data = source.read_bytes(); profile = json.loads(profile_path.read_bytes())
    record = dict(status='STARTED_NOT_ACCEPTED', source=str(source), source_sha256=digest(source),
                  profile_source=str(profile_path), profile_sha256=digest(profile_path), commands=[],
                  guest_executions=0, gpu_executions=0)
    evidence = out/'evidence.json'; save(evidence, record)
    def command(label, arguments, expected=0, optimized=False):
        argv = [sys.executable, *(['-O'] if optimized else []), '-m', 'migration_v3', *map(str, arguments)]
        stdout=out/(label+'.stdout'); stderr=out/(label+'.stderr')
        before=time.time_ns()
        with stdout.open('x') as o, stderr.open('x') as e:
            process=subprocess.run(argv,cwd=ROOT,stdout=o,stderr=e)
        row=dict(label=label, command=argv, returncode=process.returncode,
                 started_unix_ns=before, ended_unix_ns=time.time_ns(),
                 stdout=str(stdout), stdout_sha256=digest(stdout), stderr=str(stderr), stderr_sha256=digest(stderr))
        record['commands'].append(row);save(evidence,record)
        if process.returncode!=expected:raise RuntimeError('CLI return differs: '+label)
        return json.loads(stdout.read_bytes())
    try:
        for name in ('original', 'renamed'):
            directory=out/name;directory.mkdir();current=copy.deepcopy(profile);current_data=data
            if name=='renamed':
                old,new=b'integer-tile.bin\0',b'profile-save.bin\0'
                if data.count(old)!=1 or len(old)!=len(new):raise ValueError('unique equal-length data rename required')
                current_data=data.replace(old,new)
                current['pe_sha256']=hashlib.sha256(current_data).hexdigest()
                current['save_observation']=new[:-1].decode()
                current['observations']={'callback_prefix':{'rva':current['callback_rvas'][0],'size':8}}
                record['input_variation']=dict(kind='only equal-length original PE string bytes',
                    offset=data.index(old), old_hex=old.hex(), new_hex=new.hex(),
                    changed_offsets=[i for i,(a,b) in enumerate(zip(data,current_data)) if a!=b])
            pe=directory/'input.exe';pe.write_bytes(current_data)
            config=directory/'profile.json';save(config,current)
            analysis=command(name+'-analyze',['analyze',pe,'--profile',config])
            if analysis['status']!='ELIGIBLE_FOR_BUILD_NOT_DECODED':raise ValueError('analysis failed')
            product=directory/'product'
            built=command(name+'-build',['build',pe,'--profile',config,'--out',product])
            if built['status']!='BUILT_NATIVE_WINDOW_NOT_PACKAGED_NOT_EXECUTED':raise ValueError('not actually built')
            verified=command(name+'-verify',['verify',product])
            optimized=command(name+'-verify-optimized',['verify',product],optimized=True)
            if verified!=optimized:raise ValueError('optimized verification differs')
            record[name]=dict(input_sha256=digest(pe), profile_sha256=digest(config),
                              product=str(product), receipt_sha256=digest(product/'result.json'),
                              executable_sha256=built['executable_sha256'], instructions=built['instructions'],
                              callback_count=built['callback_count'])
        product=out/'original/product'
        existing=digest(product/'result.json')
        command('overwrite-rejected',['build',source,'--profile',profile_path,'--out',product],64)
        if digest(product/'result.json')!=existing:raise ValueError('existing receipt modified')
        invalid=copy.deepcopy(profile);invalid['callback_rvas']=[0]
        path=out/'invalid-profile.json';save(path,invalid)
        command('invalid-root-rejected',['analyze',source,'--profile',path],2)
        # Exercise unchanged process dispatch using its already accepted product.
        command('process-v2-verify',['verify',ROOT/'build/migration-v2/counter-01/product'])
        record.update(status='PASS_REAL_CONFIGURED_BUILDS_NOT_EXECUTED',
                      scope='two real PE AOT builds; data-name variation and optional observation; no window runtime/App/performance acceptance')
    except Exception as error:
        record.update(status='FAIL_NOT_ACCEPTED',error_type=type(error).__name__,error=str(error))
        save(evidence,record);raise
    save(evidence,record)
    print(json.dumps({k:v for k,v in record.items() if k not in ('commands',)},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True)
    main(parser.parse_args().out)
