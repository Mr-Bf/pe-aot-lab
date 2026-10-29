"""Bounded actual original-PE pixel experiment; defaults to read-only verify."""
import argparse
import json
import re
import subprocess
from pathlib import Path

from window_bridge import pixel_bindings_v1 as producer
from window_bridge import window_bindings as binding
from window_bridge import window_execution_acceptance as semantic
from window_bridge import window_pixels_v1 as pixels

WORKLOADS = {
    "stationary": ["escape"],
    "movement": ["right", "right-repeat", "right-up", "right", "right-up", "left", "left-up", "escape"],
}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def write(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def inputs(program):
    return {**program.build_manifest["inputs_before"], **program.build_manifest["artifacts"],
            **binding.snapshot([program.out / "program-build.json", __file__, pixels.__file__, semantic.__file__])}


def validate(out, record):
    start = binding.graphics.read_json(out / "started.json")
    require(record["started_sha256"] == binding.sha(out / "started.json"), "immutable start changed")
    program = producer.Program.from_build(Path(start["program"]))
    require(inputs(program) == start["inputs_before"], "actual input closure differs")
    binding.unchanged(start["inputs_before"])
    require(start["workload"] in WORKLOADS and start["sequence"] == WORKLOADS[start["workload"]], "workload differs")
    sequence = start["sequence"]
    data = out / "data"
    capture_dir = out / "pixels"
    command = [str(program.executable), "--data-dir", str(data), "--pixel-dir", str(capture_dir),
               "--budget", "1000000", "--timeout-ms", "45000", "--test-sequence", ",".join(sequence)]
    require(start["command"] == command and start["initial_data_files"] == start["initial_pixel_files"] == [],
            "recorded command/directory setup differs")
    require(start["environment"] == binding.graphics.environment(out, images=True), "run environment differs")
    require(record["external_timeout"] is False, "external timeout is not a normal execution")
    observed_outputs = binding.snapshot([out / "run.stdout", out / "run.stderr", data / "integer-tile.bin"])
    stdout = (out / "run.stdout").read_text()
    stderr = (out / "run.stderr").read_text()
    result = binding.graphics.strict_json(stdout)
    normal = program.validate_execution(result, record["returncode"], None, 1000000)
    require(normal is not None, "host setup failed")
    gameplay = semantic.semantic_acceptance({"result": normal, "returncode": record["returncode"],
        "external_timeout": False, "data_directory": str(data), "test_sequence": sequence})
    capture = program.validate_capture(result, capture_dir)
    loaded = binding.graphics.loaded_images(stderr, program.executable, program.build_manifest["library_graph"]["nodes"])
    require(set(map(int, re.findall(r"^dyld\[(\d+)\]:", stderr, re.M))) == {record["pid"]},
            "actual dyld/child PID mismatch")
    image_result = pixels.inspect_frames(capture_dir, capture["frames"], sequence)
    artifacts = {**capture["artifacts"], **observed_outputs}
    binding.unchanged(artifacts)
    binding.unchanged(start["inputs_before"])
    return {"result": result, "gameplay": gameplay, "capture": capture, "pixels": image_result,
            "loaded_images": loaded, "artifacts": artifacts}


def verify(out):
    out = Path(out).resolve()
    record = binding.graphics.read_json(out / "evidence.json")
    require(record["status"] == "PASS_ORIGINAL_PE_WINDOW_PIXELS", "pixel run not accepted")
    actual = validate(out, record)
    require(all(record[k] == v for k, v in actual.items()), "recorded results differ from actual artifacts")
    require(actual["pixels"]["status"] == "PASS_FULL_RGBA_SCENE", "pixel contents failed")
    binding.unchanged(actual["artifacts"])
    return {"status": record["status"], "gameplay": actual["gameplay"],
            "frames": actual["capture"]["frames"], "pixels": actual["pixels"], "new_guest_executions": 0}


def run(out, workload, program_directory):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    write(out / "attempt.json", {"status": "PREFLIGHT_NOT_EXECUTED", "workload": workload,
          "program": str(Path(program_directory).resolve()), "driver_sha256": binding.sha(__file__)})
    record = {"status": "NOT_EXECUTED"}
    try:
        program = producer.Program.from_build(program_directory)
        data, capture_dir = out / "data", out / "pixels"
        data.mkdir()
        capture_dir.mkdir()
        sequence = WORKLOADS[workload]
        command = [str(program.executable), "--data-dir", str(data), "--pixel-dir", str(capture_dir),
                   "--budget", "1000000", "--timeout-ms", "45000", "--test-sequence", ",".join(sequence)]
        env = binding.graphics.environment(out, images=True)
        start = {"status": "STARTED_NOT_ACCEPTED", "program": str(program.out), "workload": workload,
                 "sequence": sequence, "command": command, "environment": env,
                 "inputs_before": inputs(program), "initial_data_files": [], "initial_pixel_files": [],
                 "scope": "one actual original PE execution with synchronous native observation; not performance or real keyboard evidence"}
        write(out / "started.json", start)
        record = {"status": "STARTED_NOT_ACCEPTED", "started_sha256": binding.sha(out / "started.json")}
        child = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        record["pid"] = child.pid
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
        record.update(returncode=child.returncode, external_timeout=timeout)
        actual = validate(out, record)
        write(out / "observed.json", {**record, **actual, "status": "OBSERVED_NOT_ACCEPTED"})
        require(actual["pixels"]["status"] == "PASS_FULL_RGBA_SCENE", "full RGBA scene mismatch; actual frames preserved")
        record.update(actual)
        record["status"] = "PASS_ORIGINAL_PE_WINDOW_PIXELS"
        write(out / "evidence.json", record)
        print(json.dumps({"status": record["status"], "pid": child.pid, "gameplay": actual["gameplay"],
            "frames": actual["capture"]["frames"], "pixels": actual["pixels"]}, ensure_ascii=False), flush=True)
    except Exception as error:
        write(out / "failure.json", {**record, "status": "FAIL_PRESERVED", "error": str(error)})
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--program", type=Path, default=producer.OUT)
    parser.add_argument("--workload", choices=WORKLOADS, default="stationary")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run:
        run(args.out, args.workload, args.program)
    else:
        print(json.dumps(verify(args.out), ensure_ascii=False))
