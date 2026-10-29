"""Supervised direct execution of a relocated, self-contained original-PE App.

This does not launch through Finder/LaunchServices or claim real keyboard input.
The copied App runs without a usable PATH; Python remains the external verifier.
"""
import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from window_bridge import app_v1 as package
from window_bridge import window_bindings as bindings
from window_bridge import window_execution_acceptance as acceptance

SEQUENCE = ["right", "right-repeat", "right-up", "right", "right-up", "left", "left-up", "escape"]


def require(value, reason):
    if not value:
        raise ValueError(reason)


def write(path, record):
    with Path(path).open("x") as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write("\n")


def verify(out, candidate=None):
    out = Path(out).resolve()
    r = bindings.graphics.read_json(out / "evidence.json") if candidate is None else candidate
    expected_status = "PASS_RELOCATED_APP_DIRECT_SAVE_ONLY" if candidate is None else "OBSERVED_NOT_ACCEPTED"
    require(r["status"] == expected_status, "App run status differs")
    s = bindings.graphics.read_json(out / "started.json")
    require(r["started_sha256"] == bindings.sha(out / "started.json"), "start identity differs")
    require(s["driver_sha256"] == bindings.sha(__file__) and
            s["acceptance_sha256"] == bindings.sha(acceptance.__file__), "verifier source changed")
    bindings.unchanged(r["outputs"])
    package.verify(Path(s["package_directory"]))
    receipt = bindings.graphics.read_json(Path(s["package_directory"]) / "evidence.json")
    require(bindings.sha(Path(s["package_directory"]) / "evidence.json") == s["package_sha256"],
            "source package receipt changed")
    app = Path(s["relocated_app"])
    require(package.tree(app) == s["app_tree"] == receipt["app_tree"], "copied App changed")
    graph = package.package_graph(app)
    require(package.normalized_graph(graph, app) == receipt["normalized_graph"], "moved dependency graph differs")
    exe = package.executable(app)
    expected = [str(exe), "--data-dir", s["data_directory"], "--budget", "1000000",
                "--timeout-ms", "45000", "--test-sequence", ",".join(SEQUENCE)]
    require(s["command"] == expected and s["test_sequence"] == SEQUENCE and
            s["environment"]["PATH"] == "/nonexistent" and s["initial_data_files"] == [],
            "recorded run setup differs")
    require(r["external_timeout"] is False and r["returncode"] == 0, "not a clean actual child exit")
    stdout = (out / "run.stdout").read_text()
    stderr = (out / "run.stderr").read_text()
    parsed = bindings.graphics.strict_json(stdout)
    require(parsed == r["result"], "raw stdout/result differs")
    program = bindings.Program.from_build(package.SOURCE_BUILD)
    program.validate_execution(parsed, r["returncode"], None, 1000000)
    loaded = bindings.graphics.loaded_images(stderr, exe, graph["nodes"])
    require(loaded == r["loaded_images"], "actual loaded image set differs")
    require(set(map(int, re.findall(r"^dyld\[(\d+)\]:", stderr, re.M))) == {r["pid"]},
            "dyld identity differs from actual child PID")
    semantic = acceptance.semantic_acceptance({"result": parsed, "test_sequence": SEQUENCE,
        "data_directory": s["data_directory"], "external_timeout": False, "returncode": r["returncode"]})
    require(semantic == r["semantic"], "semantic summary differs")
    disk = Path(s["data_directory"]) / "integer-tile.bin"
    require(r["outputs"] == bindings.snapshot([out / "run.stdout", out / "run.stderr", disk]),
            "actual output closure differs")
    return {"status": "PASS_RELOCATED_APP_DIRECT_SAVE_ONLY", "pid": r["pid"], "semantic": semantic,
            "runtime_requires_python": False, "runtime_requires_rosetta": False,
            "launchservices_tested": False, "finder_no_arguments_ready": False}


def run(package_directory, out):
    package_directory = Path(package_directory).resolve()
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    package.verify(package_directory)
    receipt = bindings.graphics.read_json(package_directory / "evidence.json")
    temporary = Path(tempfile.mkdtemp(prefix="pe-aot-original-window-", dir="/private/tmp"))
    app = temporary / "relocation with spaces" / "PE AOT Integer Tile V1.app"
    app.parent.mkdir()
    shutil.copytree(receipt["app"], app)
    require(package.tree(app) == receipt["app_tree"], "copy changed App bytes/modes")
    graph = package.package_graph(app)
    require(package.normalized_graph(graph, app) == receipt["normalized_graph"], "copied graph differs")
    data = out / "data"
    data.mkdir()
    exe = package.executable(app)
    command = [str(exe), "--data-dir", str(data), "--budget", "1000000",
               "--timeout-ms", "45000", "--test-sequence", ",".join(SEQUENCE)]
    env = bindings.graphics.environment(out, images=True)
    env["PATH"] = "/nonexistent"
    start = {"status": "STARTED_NOT_ACCEPTED", "package_directory": str(package_directory),
             "package_sha256": bindings.sha(package_directory / "evidence.json"),
             "driver_sha256": bindings.sha(__file__), "acceptance_sha256": bindings.sha(acceptance.__file__),
             "relocated_app": str(app), "app_tree": package.tree(app), "command": command,
             "environment": env, "data_directory": str(data), "initial_data_files": [],
             "test_sequence": SEQUENCE, "scope": "direct App executable, TEST_QUEUE, save-only; no Finder/real-keyboard/pixel/performance claim"}
    write(out / "started.json", start)
    record = {"status": "STARTED_NOT_ACCEPTED", "started_sha256": bindings.sha(out / "started.json")}
    try:
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        timeout = False
        try:
            stdout, stderr = child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            timeout = True
            child.terminate()
            try:
                stdout, stderr = child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate(timeout=3)
        (out / "run.stdout").write_text(stdout)
        (out / "run.stderr").write_text(stderr)
        record.update(pid=child.pid, returncode=child.returncode, external_timeout=timeout)
        require(not timeout, "external supervision timed out")
        result = bindings.graphics.strict_json(stdout)
        program = bindings.Program.from_build(package.SOURCE_BUILD)
        program.validate_execution(result, child.returncode, None, 1000000)
        loaded = bindings.graphics.loaded_images(stderr, exe, graph["nodes"])
        semantic = acceptance.semantic_acceptance({"result": result, "test_sequence": SEQUENCE,
            "data_directory": str(data), "external_timeout": timeout, "returncode": child.returncode})
        record.update(status="OBSERVED_NOT_ACCEPTED", result=result, loaded_images=loaded,
                      semantic=semantic, outputs=bindings.snapshot([out / "run.stdout", out / "run.stderr",
                                                                   data / "integer-tile.bin"]))
        validated = verify(out, record)
        record["status"] = "PASS_RELOCATED_APP_DIRECT_SAVE_ONLY"
        write(out / "evidence.json", record)
        print(json.dumps(validated, ensure_ascii=False), flush=True)
    except Exception as error:
        write(out / "failure.json", {**record, "status": "FAIL_PRESERVED", "error": str(error)})
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=package.OUT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        run(args.package, args.out)
    else:
        print(json.dumps(verify(args.out), ensure_ascii=False))
