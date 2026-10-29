#!/usr/bin/env python3
"""Pure native WSI callback protocol, deliberately no Cocoa/GPU implementation."""
import argparse,json,shlex,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];HERE=Path(__file__).resolve().parent;OUT=ROOT/'build/native-window/contract'
sys.path.insert(0,str(ROOT))
from graphics_stage5.d3d11_probe import hashes,save,read_json,sha,require

def verify():
 e=read_json(OUT/'evidence.json');require(e['status']=='PASS' and e['scope']=='pure callbacks; no Cocoa/GPU','wrong scope');require(e['inputs_before']==e['inputs_after']==hashes(e['inputs_before']),'inputs drift');require(e['artifacts']==hashes(e['artifacts']),'artifacts drift');require(json.loads((OUT/'stdout').read_text())==e['result'],'stdout differs');return e

def main():
 OUT.mkdir(parents=True,exist_ok=True);compiler=Path(subprocess.check_output(['xcrun','--find','clang'],text=True).strip());sdk=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip();flags=['-arch','arm64','-isysroot',sdk,'-std=c11','-O2','-Wall','-Wextra','-Werror','-I',str(HERE)]
 paths=[Path(__file__),HERE/'native_wsi.h',HERE/'native_wsi.c',HERE/'test_contract.c',compiler,Path('/usr/bin/xcrun'),Path(sys.executable)]
 for name in ('test_contract.c','native_wsi.c'):
  deps=subprocess.check_output([compiler,*flags,'-M','-MT','protocol',HERE/name],text=True);(OUT/(name+'.d')).write_text(deps);paths += [Path(x) for x in shlex.split(deps.replace('\\\n',' ').split(':',1)[1])]
 before=hashes(paths);cmd=list(map(str,[compiler,*flags,HERE/'test_contract.c',HERE/'native_wsi.c','-o',OUT/'test']))
 run=subprocess.run(cmd,capture_output=True,text=True);(OUT/'compile.log').write_text(json.dumps(cmd)+'\n'+run.stdout+run.stderr);require(run.returncode==0,'compile failed')
 r=subprocess.run([OUT/'test'],capture_output=True,text=True);(OUT/'stdout').write_text(r.stdout);(OUT/'stderr').write_text(r.stderr);require(r.returncode==0,'protocol failed');value=json.loads(r.stdout);require(value=={'status':'PASS','checks':62,'query_callbacks':18,'create_callbacks':3,'release_callbacks':3,'gpu_calls':0,'cocoa_calls':0},'coverage changed');require(before==hashes(paths),'source drift')
 save(OUT/'evidence.json',{'status':'PASS','scope':'pure callbacks; no Cocoa/GPU','result':value,'inputs_before':before,'inputs_after':hashes(paths),'artifacts':hashes([OUT/'test',OUT/'compile.log',OUT/'stdout',OUT/'stderr',OUT/'test_contract.c.d',OUT/'native_wsi.c.d'])});verify();print(r.stdout.strip())
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--verify',action='store_true');a=p.parse_args()
 if a.verify:verify();print('{"status":"PASS_CURRENT","gpu_calls":0,"cocoa_calls":0}')
 else:main()
