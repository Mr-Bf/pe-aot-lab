"""Explicit GUI execution of newly built caller-configured native programs."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from window_profile_v1.bindings import Program, ROOT


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def require(value, message):
    if not value: raise ValueError(message)


def main(builds, out):
    builds=Path(builds).resolve();out=Path(out).resolve()
    require(out.parent==ROOT/'build/migration-v3', 'new execution batch directory required')
    out.mkdir(parents=True,exist_ok=False)
    source=json.loads((builds/'evidence.json').read_bytes())
    require(source['status']=='PASS_REAL_CONFIGURED_BUILDS_NOT_EXECUTED','actual builds required')
    record=dict(status='STARTED_NOT_ACCEPTED', builds=str(builds), build_receipt_sha256=sha(builds/'evidence.json'),
                runs=[], scope='new configured native hosts; TEST_QUEUE input; not App/Cocoa-input/pixel/performance acceptance')
    evidence=out/'evidence.json';save(evidence,record)
    try:
        for name in ('original','renamed'):
            product=builds/name/'product'
            require(sha(product/'result.json')==source[name]['receipt_sha256'],'build receipt changed')
            program=Program.from_build(product/'native')
            profile=json.loads((product/'profile.json').read_bytes());filename=profile['save_observation']
            directory=out/name;directory.mkdir();data=directory/'data';data.mkdir()
            sequences=[['right','right','left','escape'], ['right','close']]
            expected=[(827805507,1,4,3,5),(827805507,1,5,4,8)]
            for index,sequence in enumerate(sequences,1):
                path=directory/('run-%d.json'%index)
                result=program.run(io_directory=data,test_sequence=sequence,timeout_ms=20000,log_path=path)
                row=dict(variant=name,index=index,evidence=str(path),evidence_sha256=sha(path))
                record['runs'].append(row);save(evidence,record)
                require(result['outcome']=='PROCESS_EXITED' and result['exit_code']==0 and result['host_returncode']==0,
                        'guest did not exit normally')
                require(result['proc_translated']==0 and result['test_queue']['posted']==len(sequence), 'ISA/input differs')
                require(result['host_after_finish']['cocoa_key_events']==0,'unexpected Cocoa key input')
                require(result['files']['bytes_written']==20 and result['files']['bytes_read']==(0 if index==1 else 20),
                        'actual guest file I/O differs')
                require(result['files']['cleanup_closes']==0 and result['d3d_before_cleanup']['guest_released']==8,
                        'guest resource release differs')
                actual=(data/filename).read_bytes();snapshot=directory/('save-%d.bin'%index);snapshot.write_bytes(actual)
                require(actual==struct.pack('<5I',*expected[index-1]),'on-disk saved state differs')
                require(result['saved_file']['name']==filename and result['saved_file']['data_hex']==actual.hex(),
                        'configured save observation does not match actual file')
                require({p.name for p in data.iterdir()}=={filename},'unexpected/original hardcoded save file')
                if name=='renamed':
                    rva=profile['observations']['callback_prefix']['rva']
                    require(result['observations']=={'callback_prefix':program.image.data[rva:rva+8].hex()},
                            'configured observation differs from original mapped PE bytes')
                else: require(result['observations']=={},'empty observation configuration ignored')
                row.update(save=str(snapshot),save_sha256=sha(snapshot),saved_words=list(expected[index-1]),
                           steps=result['steps'], present_calls=result['d3d_before_cleanup']['present_calls'])
                save(evidence,record)
        record.update(status='PASS_TWO_CONFIGURED_PES_TWO_PROCESS_RESTORE', guest_executions=4)
    except Exception as error:
        record.update(status='FAIL_NOT_ACCEPTED',error_type=type(error).__name__,error=str(error))
        save(evidence,record);raise
    save(evidence,record);print(json.dumps(record,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--builds',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();main(args.builds,args.out)
