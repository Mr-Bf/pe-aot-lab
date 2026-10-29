#!/usr/bin/env python3
"""Measure the validated full-State transactional runtime without hiding its cost."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/integration-stage3/performance"
sys.path.insert(0, str(ROOT))
from memory_stage2.image_loader import load_image, EXEC

NATIVE_SOURCE = r'''#include <stdint.h>
#include <string.h>
__attribute__((noinline)) uint32_t source_kernel(uint8_t *data, uint32_t count) {
    uint32_t value=0;
    for(uint32_t i=0;i<count;i++) {
        uint32_t word;memcpy(&word,data+(size_t)i*4,4);
        value^=word;value=(value<<5)|(value>>27);
        memcpy(data+(size_t)i*4,&value,4);
    }
    return value;
}
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require_hash(path, expected, description):
    if not Path(path).is_file() or sha(path) != expected:
        raise ValueError("Stale or changed " + description + ": " + str(path))


def verify_inputs(root=ROOT):
    """Reject stale correctness and changed PE/IR/object before any compilation."""
    evidence_path = root / "build/integration-stage3/memory/evidence.json"
    evidence = json.loads(evidence_path.read_text())
    if evidence.get("status") != "PASS":
        raise ValueError("Run integration_stage3/test_memory.py successfully first")
    for filename, digest in evidence["source_sha256"].items():
        require_hash(root / filename, digest, "correctness source")
    sample = next(row for row in evidence["samples"] if row["name"] == "mutate")
    if sample.get("status") != "PASS" or not sample.get("cases"):
        raise ValueError("mutate has no passing correctness evidence")
    compiled = root / "build/integration-stage3/memory/mutate"
    pe = root / "build/integration-stage3/memory/fixtures/mutate.exe"
    require_hash(pe, sample["input_sha256"], "correctness PE")
    require_hash(compiled / "arm64.o", sample["arm64_object_sha256"], "correctness ARM64 object")
    require_hash(compiled / "program.dylib", sample["dylib_sha256"], "correctness dynamic library")
    native_path = compiled / "native-artifact.json"
    native = json.loads(native_path.read_text())
    if native["library_sha256"] != sample["dylib_sha256"] or native["input_sha256"] != sample["input_sha256"]:
        raise ValueError("actual loaded library identity differs from correctness evidence")
    require_hash(Path(native["library_path"]), native["library_sha256"], "actually loaded immutable library")
    manifest_path = compiled / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("status") != "PASS" or manifest["input_sha256"] != sample["input_sha256"]:
        raise ValueError("lifter manifest is not the validated fixture")
    for filename, digest in manifest["source_sha256"].items():
        require_hash(root / "integration_stage3" / filename, digest, "lifter source")
    for filename, digest in manifest["artifact_sha256"].items():
        require_hash(compiled / filename, digest, "lifter artifact")
    build_path = root / "build/integration-stage3/lifter/build-manifest.json"
    build = json.loads(build_path.read_text())
    if build.get("status") != "PASS" or build["lifter_sha256"] != manifest["lifter_sha256"]:
        raise ValueError("lifter version changed after correctness testing")
    require_hash(Path(build["lifter"]), manifest["lifter_sha256"], "lifter binary")
    for filename, digest in build["patch_sha256"].items():
        require_hash(root / "integration_stage3" / filename, digest, "lifter patch")
    image = load_image(pe)
    section = next(section for section in image.sections if section["permissions"] & EXEC)
    text = bytes(image.data[section["rva"]:section["rva"] + min(section["virtual_size"], section["raw_size"])])
    if text != (compiled / "text.bin").read_bytes():
        raise ValueError("oracle text differs from the validated PE executable bytes")
    return {"correctness_evidence_sha256": sha(evidence_path),
            "manifest_sha256": sha(manifest_path), "build_manifest_sha256": sha(build_path),
            "input_pe_sha256": sha(pe), "arm64_object_sha256": sha(compiled / "arm64.o"),
            "native_artifact_sha256": sha(native_path), "loaded_library_sha256": native["library_sha256"],
            "validated_fixture_cases": sample["cases"], "correctness_total_cases": evidence["functional_cases"]}, manifest, image, text


def generate_fixture(manifest, image, text):
    instructions = []
    for instruction in manifest["instructions"]:
        kind = instruction["kind"]
        if isinstance(kind, str):
            kind = {"NORMAL": 0, "CALL": 1, "RET": 2}[kind]
        instructions.append("{%d,%d,%d,0,UINT64_C(%d)}" % (
            instruction["rva"], instruction["length"], kind, instruction.get("target_rva", 0)))
    header = "static const uint64_t kImageBase=UINT64_C(%d);\n" % image.base
    header += "static const uint64_t kEntryPC=UINT64_C(%d);\n" % (image.base + image.entry_rva)
    header += "static const uint8_t kImage[]={" + ",".join(map(str, image.data)) + "};\n"
    header += "static const uint8_t kImagePermissions[]={" + ",".join(map(str, image.permissions)) + "};\n"
    header += "static const AotInstruction kInstructions[]={" + ",".join(instructions) + "};\n"
    (OUT / "fixture.h").write_text(header)
    (OUT / "original_x86.s").write_text(".text\n.globl _guest_entry\n_guest_entry:\n.byte "
                                         + ",".join("0x%02x" % byte for byte in text) + "\n")
    (OUT / "source_kernel.c").write_text(NATIVE_SOURCE)


def run(command, commands):
    command = list(map(str, command))
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    commands.append({"argv": command, "exit_code": completed.returncode, "stderr": completed.stderr})
    if completed.returncode:
        raise RuntimeError("command failed: " + " ".join(command) + "\n" + completed.stderr)
    return completed.stdout


def describe(values):
    median = statistics.median(values)
    return {"median": median, "min": min(values), "max": max(values),
            "mean": statistics.mean(values), "population_stddev": statistics.pstdev(values),
            "median_absolute_deviation": statistics.median(abs(value - median) for value in values)}


def main(count=65536, calls=32, rounds=9, warmups=2):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("Native Apple Silicon macOS is required")
    if subprocess.run(["arch", "-x86_64", "/usr/bin/true"], capture_output=True).returncode:
        raise SystemExit("Rosetta is required for the unchanged x86-byte comparison")
    gate, manifest, image, text = verify_inputs()
    OUT.mkdir(parents=True, exist_ok=True)
    report_path = OUT / "benchmark.json"
    if report_path.exists():
        history = OUT / "history"
        history.mkdir(exist_ok=True)
        (history / (sha(report_path) + ".json")).write_bytes(report_path.read_bytes())
    report_path.write_text('{"status":"RUNNING"}\n')
    source_paths = [ROOT / "integration_stage3/bench.c", Path(__file__).resolve(),
                    ROOT / "integration_stage3/runtime.c", ROOT / "integration_stage3/runtime.h",
                    ROOT / "memory_stage2/guest_memory.h"]
    sources_before = {str(path.relative_to(ROOT)): sha(path) for path in source_paths}
    generate_fixture(manifest, image, text)
    commands = []
    variants = [("transactional_aot", 0, "arm64"), ("original_x86_rosetta", 1, "x86_64"),
                ("source_arm64", 2, "arm64")]
    executables = {}
    for name, mode, architecture in variants:
        executable = OUT / name
        extra = ([ROOT / "integration_stage3/runtime.c", ROOT / "build/integration-stage3/memory/mutate/arm64.o"]
                 if mode == 0 else [OUT / "original_x86.s"] if mode == 1 else [OUT / "source_kernel.c"])
        command = ["xcrun", "clang", "-arch", architecture, "-std=c11", "-O3", "-fno-lto",
                   "-Wall", "-Wextra", "-Werror", "-I", OUT, "-DBENCH_MODE=%d" % mode,
                   ROOT / "integration_stage3/bench.c", *extra, "-o", executable]
        run(command, commands)
        executables[name] = executable
        (OUT / (name + ".asm")).write_text(run(["xcrun", "llvm-objdump", "--disassemble", executable], commands))
    samples = {name: [] for name, _, _ in variants}
    names = list(samples)
    identities = set()
    for round_no in range(rounds):
        for name in names[round_no % 3:] + names[:round_no % 3]:
            command = (["arch", "-x86_64"] if name == "original_x86_rosetta" else [])
            command += [executables[name], count, calls, warmups]
            sample = json.loads(run(command, commands))
            if sample["count"] != count or sample["calls"] != calls or sample["full_buffer_checked_calls"] != calls + warmups:
                raise AssertionError("workload mismatch: " + name)
            identities.add(tuple(sample[key] for key in ("checksum", "return_value", "initial_buffer_hash", "final_buffer_hash")))
            samples[name].append(sample)
    if len(identities) != 1:
        raise AssertionError("input/return/final-data identities differ across variants")
    if verify_inputs()[0] != gate:
        raise ValueError("correctness artifacts changed during timing")
    if any(sha(ROOT / filename) != digest for filename, digest in sources_before.items()):
        raise ValueError("benchmark/runtime sources changed during timing")
    result = {name: {"ns_per_element": describe([sample["ns_per_element"] for sample in rows]),
                     "samples": rows} for name, rows in samples.items()}
    aot_median = result["transactional_aot"]["ns_per_element"]["median"]
    steps = {sample["guest_steps"] for sample in samples["transactional_aot"]}
    if len(steps) != 1:
        raise AssertionError("guest instruction counts differ across equivalent runs")
    steps_per_call = next(iter(steps)) // calls
    compiler = run(["xcrun", "clang", "--version"], commands).strip()
    cpu = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True)
    report = {
        "status": "PASS", "scope": "Same self-authored mutate PE: full-State transactional Remill AOT vs unchanged COFF x86 under Rosetta vs source ARM64; no game/API/graphics claim",
        "configuration": {"elements_per_call": count, "calls_per_sample": calls, "rotating_rounds": rounds,
                          "same_process_warmup_calls": warmups, "unaligned_data_offset": 1,
                          "same_calls_and_fresh_input_in_all_modes": True},
        "timing": {"timer": "C CLOCK_MONOTONIC_RAW, summed separately timed invocations",
                   "included_aot": "aot_execute plus RAX extraction, including instruction lookup/fetch checks, 3504-byte State snapshot per guest instruction, memory mapping/permission checks, stores and actual guest RET",
                   "included_baselines": "complete external kernel call and returned uint32 value",
                   "excluded_all": "fixture loading, input restoration, allocation, AOT State/context/mapping construction, full-output verification, checksum accumulation, destruction, process startup",
                   "limits": "No CPU isolation, frequency control, or idle-host guarantee; same input size/call count but different implementations and ABI contracts. No isolated attribution to snapshot versus checking cost."},
        "correctness_gate": gate, "full_buffer_comparison_every_call": True,
        "guest_instructions_per_aot_call": steps_per_call,
        "logical_state_snapshot_bytes_per_aot_call": steps_per_call * 3504,
        "snapshot_bytes_note": "Logical memcpy volume into a reused snapshot; not measured DRAM traffic or isolated copy time",
        "aot_to_baseline_median_ratio": {name: aot_median / result[name]["ns_per_element"]["median"]
                                         for name in ("original_x86_rosetta", "source_arm64")},
        "results": result, "environment": {"platform": platform.platform(), "machine": platform.machine(),
                                            "cpu": cpu.stdout.strip() if cpu.returncode == 0 else "unknown",
                                            "compiler": compiler},
        "source_sha256": sources_before,
        "generated_sha256": {path.name: sha(path) for path in [OUT / "fixture.h", OUT / "source_kernel.c", OUT / "original_x86.s", *executables.values()]},
        "commands": commands,
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "configuration": report["configuration"],
                      "median_ns_per_element": {name: row["ns_per_element"]["median"] for name, row in result.items()},
                      "aot_to_baseline_median_ratio": report["aot_to_baseline_median_ratio"],
                      "guest_instructions_per_aot_call": steps_per_call}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=65536)
    parser.add_argument("--calls", type=int, default=32)
    parser.add_argument("--rounds", type=int, default=9)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.count <= 1 << 20 or not 1 <= args.calls <= 1024 or args.rounds < 3 or not 0 <= args.warmups <= 10:
        parser.error("count/calls/rounds/warmups outside the bounded experiment")
    try:
        if args.check_only:
            print(json.dumps(verify_inputs()[0], indent=2))
        else:
            main(args.count, args.calls, args.rounds, args.warmups)
    except Exception as error:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "failure.json").write_text(json.dumps({"status": "FAIL", "error": str(error),
                                                      "traceback": traceback.format_exc()}, indent=2) + "\n")
        raise
