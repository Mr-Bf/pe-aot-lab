#!/usr/bin/env python3
"""Build four native process hosts and an ad-hoc signed normal-variant App."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from process_bridge.bindings import Program,sha,snapshot,unchanged,run_command

FIXTURES=ROOT/'build/process-bridge/fixtures/manifest.json'
OUT=ROOT/'build/process-bridge/native'
def text_bytes(executable,log):
    output=run_command(['otool','-s','__TEXT','__text',executable],log)
    data=''.join(''.join(line.split()[1:]) for line in output.splitlines() if re.match(r'^[0-9a-fA-F]+\s+',line))
    if not data:raise ValueError('native text section absent')
    return bytes.fromhex(data)

def package_app(program,directory):
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=True)
    app=directory/'PE AOT Process Demo.app'
    contents=app/'Contents';macos=contents/'MacOS';resources=contents/'Resources'
    macos.mkdir(parents=True,exist_ok=True);resources.mkdir(exist_ok=True)
    if sha(program.executable)!=program.executable_sha256:raise ValueError('source executable changed before packaging')
    executable=macos/'process-demo';shutil.copy2(program.executable,executable)
    plist={'CFBundleExecutable':'process-demo','CFBundleIdentifier':'org.peaotlab.processdemo',
        'CFBundleName':'PE AOT Process Demo','CFBundleDisplayName':'PE AOT Process Demo','CFBundlePackageType':'APPL',
        'CFBundleVersion':'1','CFBundleShortVersionString':'0.1.0','LSUIElement':True,
        'NSHighResolutionCapable':True}
    with (contents/'Info.plist').open('wb') as stream:plistlib.dump(plist,stream,sort_keys=True)
    (resources/'Build.json').write_text(json.dumps({'pe_sha256':program.source_sha256,
        'original_native_sha256':program.executable_sha256,'entry_arguments':0,
        'launch':'Contents/MacOS/process-demo --data-dir <existing directory>',
        'scope':'CLI foundation bundle; no window or Finder default data directory in this milestone'},indent=2)+'\n')
    log=directory/'app-build.log';log.write_text('')
    inputs=snapshot([program.executable,program.out/'program-build.json',Path(__file__),
        contents/'Info.plist',resources/'Build.json',Path(shutil.which('codesign')),Path(shutil.which('otool'))])
    original_text=text_bytes(program.executable,log)
    run_command(['codesign','--force','--sign','-','--identifier','org.peaotlab.processdemo',app],log)
    run_command(['codesign','--verify','--deep','--strict',app],log)
    if text_bytes(executable,log)!=original_text:raise ValueError('App signing changed native machine code')
    unchanged(inputs)
    result={'schema':1,'status':'BUILT_APP_NOT_EXECUTED','app':str(app),'executable':str(executable),
        'input_pe_sha256':program.source_sha256,'original_native_sha256':program.executable_sha256,
        'app_executable_sha256':sha(executable),'native_text_sha256':hashlib.sha256(original_text).hexdigest(),
        'inputs_before':inputs,'inputs_after':snapshot(inputs),
        'artifacts_sha256':{str(p):sha(p) for p in sorted(app.rglob('*')) if p.is_file()},
        'signing':'local ad-hoc, not notarized','ui':'CLI host packaged as App; no GUI or default data-directory setup'}
    (directory/'app-build.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

def build(directory=OUT):
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=True)
    records=json.loads(FIXTURES.read_text());programs={};manifest={}
    for name in ('normal','open_exit','after_exit','return_only'):
        record=records[name]
        program=Program(record['pe_path'],directory/name,metadata=record,metadata_sources=[FIXTURES])
        programs[name]=program;manifest[name]={'program_build':str(program.out/'program-build.json'),
            'program_build_sha256':sha(program.out/'program-build.json'),'executable':str(program.executable),
            'executable_sha256':program.executable_sha256,'pe_sha256':program.source_sha256}
    app=package_app(programs['normal'],directory/'app')
    result={'schema':1,'status':'BUILT_NATIVE_AND_APP_NOT_EXECUTED','programs':manifest,'app':app,
            'sources':{str(Path(__file__)):sha(__file__),str(FIXTURES):sha(FIXTURES)}}
    (directory/'build.json').write_text(json.dumps(result,indent=2)+'\n')
    return programs,result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=OUT);args=parser.parse_args()
    _,result=build(args.out);print(json.dumps({'status':result['status'],'app':result['app']['app']},indent=2))
