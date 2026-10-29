#!/usr/bin/env python3
"""Build isolated transaction-instrumented Remill, reusing read-only stage2 tools."""
import hashlib,json,os,pathlib,subprocess,sys
HERE=pathlib.Path(__file__).resolve().parent;REPO=HERE.parent
WORK=REPO.parent.parent/'work'/'integration-stage3'
BASE=REPO.parent.parent/'work'/'remill-stage2'
SHA='56918a8c2554088e93389e97d292f4035286506c'
SRC=WORK/('remill-'+SHA)
OUT=REPO/'build/integration-stage3/lifter'
BUILD=OUT/'build'
LLVM=BASE/'llvm@17/17.0.6/bin'
LIFTER=BUILD/'bin/lift/remill-lift-17'
PATCHES=['xed-only.patch','transactions.patch','aot-profile.patch']
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(args,log,**kw):
 with (OUT/log).open('w') as f:subprocess.run(list(map(str,args)),stdout=f,stderr=subprocess.STDOUT,check=True,**kw)
def build():
 if sys.version_info<(3,9):raise RuntimeError('Requires Python>=3.9; tested 3.13')
 OUT.mkdir(parents=True,exist_ok=True);WORK.mkdir(parents=True,exist_ok=True)
 (OUT/'build-manifest.json').write_text(json.dumps({'status':'RUNNING'})+'\n')
 archive=BASE/'remill.tar.gz'
 assert digest(archive)=='4ba4218566367fad162ed0427ee32221a55134eca2eee5efc2436be67b46885f'
 if not SRC.exists():subprocess.run(['tar','-xzf',str(archive),'-C',str(WORK)],check=True)
 for patch in PATCHES:
  p=HERE/patch
  # Reverse dry-run proves the exact patch is already applied.
  reversed_ok=subprocess.run(['patch','-R','--dry-run','-p1','-i',str(p)],cwd=SRC,capture_output=True).returncode==0
  if not reversed_ok:run(['patch','-p1','-i',p],'patch-'+patch+'.log',cwd=SRC)
 cm=BASE/'cmake/4.4.4/bin/cmake'
 env=os.environ.copy();env['PATH']=str(cm.parent)+':'+str(BASE/'ninja/1.13.2/bin')+':'+str(LLVM)+':'+env['PATH']
 run([cm,'-G','Ninja','-S',SRC,'-B',BUILD,'-DCMAKE_BUILD_TYPE=Release',
      '-DCMAKE_C_COMPILER=/usr/bin/clang','-DCMAKE_CXX_COMPILER=/usr/bin/clang++',
      '-DCMAKE_PREFIX_PATH='+str(BASE/'deps-install-apple')+';'+str(LLVM.parent),
      '-DCMAKE_INSTALL_PREFIX='+str(WORK/'install'),'-DREMILL_ENABLE_TESTING=OFF',
      '-DREMILL_ENABLE_INSTALL_TARGET=OFF','-DGIT_FAIL_IF_NONZERO_EXIT=OFF'], 'configure.log',env=env)
 run([cm,'--build',BUILD,'--target','remill-lift-17','amd64','--parallel','6'],'build.log',env=env)
 manifest={'status':'PASS','remill_sha':SHA,'patch_sha256':{p:digest(HERE/p) for p in PATCHES},
           'lifter':str(LIFTER),'lifter_sha256':digest(LIFTER),
           'semantics_sha256':digest(BUILD/'lib/Arch/X86/Runtime/amd64.bc'),
           'readonly_stage2_manifest_sha256':digest(REPO/'build/remill-stage2/build-manifest.json')}
 (OUT/'build-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
 print(LIFTER)
 return manifest
if __name__=='__main__':build()
