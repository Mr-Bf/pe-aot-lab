"""Two actual starts of the same new PE, sharing its own real save file.

The coordinator never installs saved bytes into guest memory or rewrites the
shared save between launches. Per-phase copies preserve the historical disk
contents after the second original-PE save updates the live file.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from window_bridge import save_load_bindings_v1 as binding

PROGRAM = binding.ROOT / "build/window-bridge/save-load-program-v1-01"
PE_SHA = "0e1bcf809cb2aa56f23526f3bbd80e9ee233488a1a5b215f1f810b4bb67aa976"
SEQUENCE = ["right", "right-repeat", "right-up", "right", "right-up", "left", "left-up", "escape"]


def require(value, reason):
    if not value:
        raise ValueError(reason)


def write(path, value):
    with Path(path).open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def before_snapshot(save, phase):
    require(not save.is_symlink(), "save symlink rejected")
    if not save.exists():
        record = {"name": save.name, "exists": False, "sha256": None, "data_hex": None, "size": None}
        value = None
    else:
        require(save.is_file(), "save is not a regular file")
        value = save.read_bytes()
        with (phase / "input-before.bin").open("xb") as stream:
            stream.write(value)
        record = {"name": save.name, "exists": True, "sha256": hashlib.sha256(value).hexdigest(),
                  "data_hex": value.hex(), "size": len(value)}
    write(phase / "before.json", record)
    return value


def basic_check(record, before, after):
    r = record["result"]
    require(r["pe_sha256"] == PE_SHA and r["outcome"] == "PROCESS_EXITED" and
            r["exit_code"] == 0 and record["returncode"] == 0 and not record["external_timeout"],
            "same original PE did not exit successfully")
    require(r["saved_file"]["data_hex"] == r["observations"]["window_state"] == after.hex(),
            "actual saved state differs")
    require(len(after) == 20, "saved format differs")
    state = struct.unpack("<5I", after)
    old = (0x31574F43, 1, 3, 0, 0) if before is None else struct.unpack("<5I", before)
    require(state[:4] == (0x31574F43, 1, old[2] + 1, old[3] + 3),
            "loaded position or cumulative moves differ")
    current_frames = r["d3d_before_cleanup"]["present_calls"]
    require(state[4] == old[4] + current_frames and current_frames >= 4,
            "persisted draw total is not initial plus current presents")
    load = list(struct.unpack("<9I", bytes.fromhex(r["observations"]["window_load_result"])))
    expected_load = [1, 0, 1, 0, 0, 0, 2, 0, 0] if before is None else [1, 1, 0, 0, 20, 0, 0, 0, 0]
    require(load == expected_load, "guest loading outcome differs")
    candidate = bytes.fromhex(r["observations"]["window_load_candidate"])
    require(candidate == (bytes(20) if before is None else before), "guest candidate is not actual prior disk bytes")
    files = r["files"]
    require(files["api_calls_4_to_9"] == ([2, 1, 0, 1, 1, 0] if before is None else [2, 1, 2, 2, 0, 0]),
            "actual read/write/open/close API trace differs")
    require(files["bytes_read"] == (0 if before is None else 20) and files["bytes_written"] == 20,
            "actual file transfer sizes differ")
    stderr = Path(record["stderr_path"]).read_text()
    require(set(map(int, re.findall(r"^dyld\[(\d+)\]:", stderr, re.M))) == {record["pid"]},
            "dyld/child identity differs")
    return {"position": state[2], "moves": state[3], "persisted_draws": state[4],
            "current_presents": current_frames, "steps": r["steps"], "load_observations": load,
            "file_api_calls": files["api_calls_4_to_9"], "last_error": files["last_error"]}


def run(out):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    write(out / "attempt.json", {"status": "PREFLIGHT_NOT_EXECUTED", "driver_sha256": binding.sha(__file__)})
    summary = []
    try:
        program = binding.Program.from_build(PROGRAM)
        require(program.source_sha256 == PE_SHA, "wrong original PE")
        data = out / "data"
        data.mkdir()
        save = data / "integer-tile.bin"
        write(out / "coordinator.started.json", {"status": "STARTED_NOT_ACCEPTED",
              "program": str(PROGRAM), "program_build_sha256": binding.sha(PROGRAM / "program-build.json"),
              "pe_sha256": PE_SHA, "driver_sha256": binding.sha(__file__), "data_directory": str(data),
              "initial_files": [], "sequence": SEQUENCE, "budget": 1000000, "timeout_ms": 45000,
              "scope": "two starts of the same PE; original file retained between starts; no host restoration into guest memory"})
        previous = None
        for index in (1, 2):
            phase = out / f"phase-{index}"
            phase.mkdir()
            before = before_snapshot(save, phase)
            require(before == previous, "shared file changed between original-PE launches")
            program.run(io_directory=data, budget=1000000, timeout_ms=45000,
                        test_sequence=SEQUENCE, log_path=phase / "run.json")
            record = binding.verify_run(phase / "run.json")
            require(save.is_file() and not save.is_symlink(), "original PE did not produce a regular save")
            after = save.read_bytes()
            with (phase / "saved-after.bin").open("xb") as stream:
                stream.write(after)
            outcome = basic_check(record, before, after)
            artifacts = [phase / "before.json", phase / "saved-after.bin", phase / "run.json",
                         phase / "run.started.json", phase / "run.stdout", phase / "run.stderr"]
            if before is not None:
                artifacts.append(phase / "input-before.bin")
            entry = {"phase": index, "summary": outcome, "artifacts": binding.snapshot(artifacts)}
            write(phase / "observed.json", entry)
            summary.append(entry)
            previous = after
            print(json.dumps(entry["summary"], ensure_ascii=False), flush=True)
        require(save.read_bytes() == previous, "final shared file changed")
        write(out / "coordinator-observed.json", {"status": "TWO_ORIGINAL_PE_RUNS_OBSERVED_NOT_FINAL_ACCEPTANCE",
              "started_sha256": binding.sha(out / "coordinator.started.json"), "phases": summary,
              "final_shared_save": binding.snapshot([save]), "new_guest_executions": 2})
    except Exception as error:
        write(out / "coordinator-failure.json", {"status": "FAIL_PRESERVED", "error": str(error), "completed_phases": summary})
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--run", action="store_true", required=True)
    args = parser.parse_args()
    run(args.out)
