"""Build/run the real transaction engine tests; no PE, window or GPU runs."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import traceback

ROOT=Path(__file__).resolve().parents[1]
SOURCES=("window_switch_v1/runtime.h", "window_switch_v1/runtime_fields.inc",
         "window_switch_v1/runtime_impl.inc", "window_switch_v1/runtime_test.c",
         "window_switch_v1/run_runtime_tests.py", "window_bridge/window_runtime/runtime.h",
         "window_bridge/window_runtime/transaction_v1.c", "memory_stage2/guest_memory.h")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()


def write(path,value):
    with Path(path).open("x") as stream:
        json.dump(value,stream,sort_keys=True,indent=2);stream.write("\n")


def require(condition,message):
    if not condition:raise ValueError(message)


def run_tests(out):
    require(platform.system()=="Darwin" and platform.machine()=="arm64","native macOS ARM64 required")
    out=Path(out).resolve()
    require(not out.exists(),"new absent evidence directory required")
    out.mkdir(parents=True)
    sources={rel:sha(ROOT/rel) for rel in SOURCES}
    for rel in SOURCES:
        target=out/"sources"/rel;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/rel,target)
    write(out/"started.json",dict(status="STARTED_NOT_ACCEPTED",sources=sources,
          observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat()))
    commands=[];results=[]
    environment={k:os.environ[k] for k in ("HOME","TMPDIR") if k in os.environ}
    environment.update(PATH="/usr/bin:/bin:/usr/sbin:/sbin",LANG="C",LC_ALL="C")

    def command(argv,label):
        argv=list(map(str,argv))
        executed=subprocess.run(argv,cwd=ROOT,env=environment,capture_output=True,timeout=60)
        record=dict(argv=argv,cwd=str(ROOT),label=label,returncode=executed.returncode)
        for name in ("stdout","stderr"):
            target=out/(label+"."+name);target.write_bytes(getattr(executed,name))
            record[name+"_path"]=str(target);record[name+"_sha256"]=sha(target)
        commands.append(record);write(out/(label+".command.json"),record)
        require(executed.returncode==0,"command failed: "+label)
        return executed.stdout.decode()

    try:
        compiler=command(["/usr/bin/xcrun","--find","clang"],"compiler-path").strip()
        sdk=command(["/usr/bin/xcrun","--show-sdk-path"],"sdk-path").strip()
        require(Path(compiler).is_absolute() and Path(compiler).is_file(),"compiler absent")
        identity={compiler:sha(compiler)}
        compiler_version=command([compiler,"--version"],"compiler-version")
        for mode in ("legacy","switch"):
            for level,flags in (("O0",["-O0"]),("O3",["-O3"]),
                                ("sanitized",["-O1","-g","-fno-omit-frame-pointer","-fsanitize=address,undefined"])):
                label=mode+"-"+level;binary=out/label
                argv=[compiler,"-std=c11","-arch","arm64","-isysroot",sdk,"-Wall","-Wextra","-Werror",*flags]
                if mode=="switch":argv.append("-DAOT_WINDOW_SWITCH_V1=1")
                command([*argv,ROOT/"window_switch_v1/runtime_test.c","-o",binary],label+"-compile")
                response=json.loads(command([binary],label+"-run"))
                require(response.get("status")=="PASS","native checks did not pass")
                results.append(dict(mode=mode,optimization=level,response=response,binary_sha256=sha(binary)))
                print(label+" PASS",flush=True)
        require(sources=={rel:sha(ROOT/rel) for rel in SOURCES},"source changed during tests")
        require(identity=={path:sha(path) for path in identity},"compiler changed during tests")
        result=dict(status="PASS_WINDOW_SWITCH_TRANSACTION_AND_LEGACY_BOUNDARIES",sources=sources,
                    compiler=identity,compiler_version=compiler_version,sdk=sdk,commands=commands,results=results,
                    translated_pe_executions=0,app_executions=0,gpu_executions=0,
                    limitations="Real window transaction C plus new hooks; C simulates instruction effects; COM/IAT dispatch uses rejecting stubs. Not translated PE/App/GPU or performance acceptance.")
        write(out/"result.json",result)
        return result
    except BaseException as error:
        write(out/"failure.json",dict(status="FAILED_OR_CANCELLED",error=repr(error),
              traceback=traceback.format_exc(),commands=commands,completed_results=results))
        raise


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",required=True)
    value=run_tests(**vars(parser.parse_args()))
    print(json.dumps({key:value[key] for key in ("status","translated_pe_executions","app_executions","gpu_executions")}))
