#!/usr/bin/env python3
"""Real lifted Windows AMD64 CALL/RET integration tests.

Normal paths are compared per input with unchanged COFF text executed by
Rosetta. Faults use the declared guest-memory/return-check contract, not a
Windows hardware-exception oracle. No game, DRM, or external API is involved.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import subprocess
import sys
import traceback

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = ROOT / "build/integration-stage3/calls"
sys.path.insert(0, str(ROOT))
from integration_stage3.call_fixtures import build, expected, FUNCTIONAL, REJECTED, IMAGE_BASE

PAGE = 4096
READ = 1
WRITE = 2
STACK_BASE = 0x70000000
STACK_SIZE = 65536
ENTRY_RSP = STACK_BASE + STACK_SIZE - 0x108
EXIT_SENTINEL = 0x7fff00000000
NONVOLATILE = ("RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15")


def arguments_for(name, count):
    rng = random.Random(20261027)
    edges = [0, 1, 2, 15, 16, 127, 255, 65535, 65536, 0x7fffffff,
             0x80000000, 0xffffffff, 0x100000000, 0x7fffffffffffffff,
             0x8000000000000000, 0xffffffffffffffff]
    rows = []
    for index in range(count):
        values = ([edges[(index + arg) % len(edges)] for arg in range(6)]
                  if index < len(edges) else [rng.getrandbits(64) for _ in range(6)])
        if name == "recursive":
            values[0] = index % 25
        rows.append(values)
    return rows


def run_oracle(name, fixture, rows, directory, commands):
    executable = directory / (name + "-oracle-x86")
    command = ["xcrun", "clang", "-arch", "x86_64", "-O3",
               str(directory / "oracle.c"), fixture["oracle_asm"], "-o", str(executable)]
    completed = subprocess.run(command, capture_output=True, text=True)
    commands.append({"argv": command, "exit_code": completed.returncode, "stderr": completed.stderr})
    if completed.returncode:
        raise RuntimeError(completed.stderr)
    data = "".join(" ".join("%016x" % value for value in row) + "\n" for row in rows)
    command = ["arch", "-x86_64", str(executable)]
    completed = subprocess.run(command, input=data, capture_output=True, text=True)
    commands.append({"argv": command, "exit_code": completed.returncode, "stderr": completed.stderr})
    if completed.returncode:
        raise RuntimeError("original byte oracle failed: " + completed.stderr)
    answers = [int(line, 16) for line in completed.stdout.splitlines()]
    assert len(answers) == len(rows), (name, "oracle row count")
    assert answers == [expected(name, row) for row in rows], (name, "fixture disagrees with mathematical reference")
    return answers, hashlib.sha256(data.encode()).hexdigest()


def fault_summary(result):
    return {"runtime_status": result.status, "returned": result.returned,
            "fault": result.fault, "steps": result.steps}


def check_fault(result, *, status, pc=None, address=None, width=None, access=None):
    assert result.status != 0 and not result.returned, fault_summary(result)
    assert result.status == status and result.fault["status"] == status, fault_summary(result)
    if pc is not None:
        assert result.fault["pc"] == pc, ("fault PC", fault_summary(result), pc)
    if address is not None:
        assert result.fault["address"] == address, ("fault EA", fault_summary(result), address)
    if width is not None:
        assert result.fault["width"] == width, ("fault width", fault_summary(result), width)
    if access is not None:
        assert result.fault["access"] == access, ("fault access", fault_summary(result), access)


def main(case_count=512):
    from integration_stage3.bindings import Program, Region, STATUS
    codes = {name: number for number, name in STATUS.items()}
    sources = [HERE / filename for filename in ("call_fixtures.py", "test_calls.py", "bindings.py",
                                                "runtime.h", "runtime.c", "lift.py")]
    source_hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}

    OUT.mkdir(parents=True, exist_ok=True)
    directory = ROOT / "build/integration-stage3/call-fixtures"
    fixtures = build(directory)
    if subprocess.run(["arch", "-x86_64", "/usr/bin/true"], capture_output=True).returncode:
        evidence = {"status": "SKIP", "reason": "Rosetta unavailable for unchanged x86 byte oracle"}
        (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps(evidence, indent=2))
        return
    programs = {}
    commands = []
    functional = []
    boundary = []

    def program(name):
        if name not in programs:
            programs[name] = Program(Path(fixtures[name]["pe_path"]), out_dir=OUT / name)
        return programs[name]

    for name in FUNCTIONAL:
        rows = arguments_for(name, case_count)
        answers, input_hash = run_oracle(name, fixtures[name], rows, directory, commands)
        output_hash = hashlib.sha256()
        lifted = program(name)
        for index, (row, answer) in enumerate(zip(rows, answers)):
            nonvolatile = {reg: 0x1122334400000000 + number for number, reg in enumerate(NONVOLATILE)}
            registers = dict(nonvolatile)
            registers.update(zip(("RCX", "RDX", "R8", "R9"), row[:4]))
            result = lifted.run(gpr=registers, stack_args=row[4:], base=IMAGE_BASE)
            assert result.status == 0 and result.returned, (name, index, fault_summary(result))
            assert result.registers["RAX"] == answer, (name, index, result.registers["RAX"], answer)
            assert result.registers["RSP"] == ENTRY_RSP + 8, (name, index, "unbalanced guest stack", result.registers["RSP"])
            for register, value in nonvolatile.items():
                assert result.registers[register] == value, (name, index, "nonvolatile", register)
            output_hash.update(answer.to_bytes(8, "little"))
        functional.append({"fixture": name, "cases": len(rows), "status": "PASS",
                           "input_sha256": input_hash, "output_sha256": output_hash.hexdigest(),
                           "oracle": "unchanged Windows COFF .text in Rosetta ms_abi harness",
                           "checks": ["RAX", "balanced final RSP", "eight nonvolatile GPR values"]})

    # A failing inner callee must stop every caller before further guest effects.
    for name in ("fault_propagation", "nested_fault_propagation"):
        source = Region(0x50000000, bytearray(PAGE), permissions=bytearray([0]))
        destination = Region(0x50001000, bytearray(PAGE), permissions=bytearray([READ | WRITE]))
        read_address, write_address = source.base + 128, destination.base + 64
        result = program(name).run(gpr={"RCX": read_address, "RDX": write_address},
                                   regions=[source, destination], base=IMAGE_BASE)
        check_fault(result, status=codes["PROTECTION"], pc=fixtures[name]["labels"]["mark_callee_load"],
                    address=read_address, width=8, access=READ)
        wanted = bytearray(PAGE)
        wanted[64:72] = (0x11).to_bytes(8, "little")
        assert destination.data == wanted, (name, "caller continued after failed callee")
        assert source.data == bytearray(PAGE)
        boundary.append({"test": name + "_preserves_first_failure_and_prior_write", "status": "PASS", **fault_summary(result)})

    # An inner RET cannot claim the top-level sentinel or jump to an unknown VA.
    for target in (0xdeadbeef, EXIT_SENTINEL):
        destination = Region(0x50001000, bytearray(PAGE), permissions=bytearray([READ | WRITE]))
        result = program("bad_return").run(gpr={"RCX": target, "RDX": destination.base + 64},
                                            regions=[destination], base=IMAGE_BASE)
        check_fault(result, status=codes["BAD_RETURN"], pc=fixtures["bad_return"]["labels"]["mark_bad_ret"],
                    address=target, width=0, access=4)
        wanted = bytearray(PAGE)
        wanted[64:72] = (0x11).to_bytes(8, "little")
        assert destination.data == wanted, ("bad return resumed caller", target)
        boundary.append({"test": "callee_rejects_bad_return_target", "target": hex(target), **fault_summary(result)})

    # CALL's real return-address push must obey the guest stack mapping.
    for label, rsp, permission in (("write_denied", STACK_BASE + 0x808, READ),
                                   ("write_below_mapping", STACK_BASE + 0x28, READ | WRITE)):
        stack = Region(STACK_BASE, bytearray(PAGE), permissions=bytearray([permission]))
        result = program("direct").run(gpr={"RCX": 7, "RDX": 9}, stack=stack, rsp=rsp, base=IMAGE_BASE)
        check_fault(result, status=codes["PROTECTION"] if label=="write_denied" else codes["BOUNDS"],
                    pc=fixtures["direct"]["labels"]["mark_call"],
                    address=rsp - 48, width=8, access=WRITE)
        assert result.registers["RSP"] == rsp - 40, (label, "failed CALL changed RSP")
        boundary.append({"test": "call_stack_" + label, **fault_summary(result)})

    stack = Region(STACK_BASE, bytearray(PAGE), permissions=bytearray([WRITE]))
    rsp = STACK_BASE + 0x808
    result = program("return_only").run(gpr={"RCX": 5}, stack=stack, rsp=rsp, base=IMAGE_BASE)
    check_fault(result, status=codes["PROTECTION"], pc=fixtures["return_only"]["labels"]["mark_ret"], address=rsp, width=8, access=READ)
    assert result.registers["RSP"] == rsp
    boundary.append({"test": "ret_stack_read_denied", **fault_summary(result)})

    # Initial slot is valid. Guest changes RSP to make the RET load span the end.
    stack = Region(STACK_BASE, bytearray(PAGE), permissions=bytearray([READ | WRITE]))
    rsp = STACK_BASE + PAGE - 8
    result = program("return_shift").run(gpr={"RCX": 4}, stack=stack, rsp=rsp, base=IMAGE_BASE)
    check_fault(result, status=codes["BOUNDS"], pc=fixtures["return_shift"]["labels"]["mark_ret"],
                address=rsp + 4, width=8, access=READ)
    assert result.registers["RSP"] == rsp + 4
    boundary.append({"test": "ret_stack_read_crosses_mapping_end", **fault_summary(result)})

    stack = Region(STACK_BASE, bytearray(PAGE * 2), permissions=bytearray([READ | WRITE, WRITE]))
    rsp = STACK_BASE + PAGE - 8
    result = program("return_shift").run(gpr={"RCX": 4}, stack=stack, rsp=rsp, base=IMAGE_BASE)
    check_fault(result, status=codes["PROTECTION"], pc=fixtures["return_shift"]["labels"]["mark_ret"],
                address=rsp + 4, width=8, access=READ)
    assert result.registers["RSP"] == rsp + 4
    boundary.append({"test": "ret_stack_cross_page_read_permission", **fault_summary(result)})

    result = program("return_only").run(gpr={"RCX": 5}, return_address=0xdeadbeef, base=IMAGE_BASE)
    check_fault(result, status=codes["BAD_RETURN"], pc=fixtures["return_only"]["labels"]["mark_ret"],
                address=0xdeadbeef, width=0, access=4)
    boundary.append({"test": "root_rejects_bad_return_target", **fault_summary(result)})

    result = program("recursive").run(gpr={"RCX": 70}, max_steps=100000, base=IMAGE_BASE)
    check_fault(result, status=codes["CALL_DEPTH"], pc=fixtures["recursive"]["labels"]["mark_recursive_call"],
                width=0, access=4)
    boundary.append({"test": "recursive_call_depth_is_bounded", **fault_summary(result)})

    result = program("recursive").run(gpr={"RCX": 24}, max_steps=20, base=IMAGE_BASE)
    check_fault(result, status=codes["BUDGET"], width=0, access=0)
    assert result.steps <= 20, ("instruction budget not respected", result.steps)
    boundary.append({"test": "recursive_instruction_budget_is_bounded", **fault_summary(result)})

    # Rejection assertions are completed against the binding's explicit error
    # class; toolchain/build failures must never count as unsupported-code PASS.
    rejected = []
    from integration_stage3.lift import TranslationError
    for name in REJECTED:
        try:
            program(name)
        except TranslationError as error:
            reason = str(error)
            if name == "external_call":
                target = fixtures[name]["labels"]["mark_call"] + 5 + 0x4000
                assert "REJECT XED decode at " + str(target) in reason, (name, "unexpected rejection cause", reason)
            else:
                assert "REJECT control category" in reason, (name, "unexpected rejection cause", reason)
            rejected.append({"fixture": name, "status": "REJECT", "reason": reason})
        else:
            raise AssertionError("unsupported control flow accepted: " + name)

    if any(hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() != digest for filename, digest in source_hashes.items()):
        raise AssertionError("integration sources changed during the correctness run")
    native_artifacts = {}
    for name, compiled in programs.items():
        artifact = json.loads((compiled.out / "native-artifact.json").read_text())
        actual_hash = hashlib.sha256(compiled.library_path.read_bytes()).hexdigest()
        assert str(compiled.library_path) == artifact["library_path"] and actual_hash == artifact["library_sha256"]
        native_artifacts[name] = {"library_path": str(compiled.library_path), "library_sha256": actual_hash,
                                  "arm64_object_sha256": hashlib.sha256((compiled.out / "arm64.o").read_bytes()).hexdigest(),
                                  "manifest_sha256": hashlib.sha256((compiled.out / "manifest.json").read_bytes()).hexdigest()}
    evidence = {"status": "PASS", "functional_cases": sum(record["cases"] for record in functional),
                "functional": functional, "boundary_checks": [{"status": "PASS", **record} for record in boundary], "rejections": rejected,
                "original_byte_oracle": True, "commands": commands,
                "fixture_sha256": {name: fixture["pe_sha256"] for name, fixture in fixtures.items()},
                "source_sha256": source_hashes, "native_artifacts": native_artifacts,
                "limits": ["Self-authored scalar direct-call programs only; no Windows API/COM",
                           "Fault paths check the explicit guest runtime contract, not Windows SEH",
                           "Synchronous single-threaded guest execution; bounded steps and call depth",
                           "Rosetta original-byte oracle is not a Windows hardware run"]}
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({"status": "PASS", "functional_cases": evidence["functional_cases"],
                      "boundary_checks": len(boundary), "rejections": len(rejected)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=512)
    options = parser.parse_args()
    if options.cases < 25:
        parser.error("--cases must be at least 25 to cover recursive base/depth samples")
    try:
        main(options.cases)
    except Exception as error:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "failure.json").write_text(json.dumps({"status": "FAIL", "error": str(error),
                                                      "traceback": traceback.format_exc()}, indent=2) + "\n")
        raise
