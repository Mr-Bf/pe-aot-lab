#!/usr/bin/env python3
"""Independent review cases for the explicitly restricted memory-loop contract.

Run test_memory.py first. This compares both compiled ARM64 paths with a Python
memory/permission model; it does not claim to model Windows hardware exceptions.
The original-x86-byte comparison remains in test_memory.py.
"""
import ctypes
import hashlib
import json
from pathlib import Path
import random
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = ROOT / "build/memory-stage2"
sys.path.insert(0, str(HERE))
from test_memory import Memory, Result, memory, result_tuple
from translate import recover
from pe_aot import PE, Unsupported

SEED = 20261028
NAMES = ("sum", "mix", "mutate")
MODES = ("checked", "fast")


def reference(name, raw, base, address, count, permissions):
    """Model guest effects directly, without generated code or CFG metadata."""
    data = bytearray(raw)
    accumulator = 0
    for _ in range(count):
        offset = address - base
        if offset < 0 or offset + 4 > len(data):
            return accumulator, 1, address, bytes(data), "load"
        pages = range(offset // 4096, (offset + 3) // 4096 + 1)
        if any(not permissions[page] & 1 for page in pages):
            return accumulator, 2, address, bytes(data), "load"
        word = int.from_bytes(data[offset:offset + 4], "little")
        if name == "sum":
            accumulator = (accumulator + word) & 0xffffffff
        else:
            accumulator ^= word
            accumulator = ((accumulator << 5) | (accumulator >> 27)) & 0xffffffff
            if name == "mix":
                accumulator = (accumulator + 17) & 0xffffffff
        if name == "mutate":
            if any(not permissions[page] & 2 for page in pages):
                return accumulator, 2, address, bytes(data), "store"
            data[offset:offset + 4] = accumulator.to_bytes(4, "little")
        address = (address + 4) & 0xffffffffffffffff
    return accumulator, 0, 0, bytes(data), "none"


def fixture_code(pe):
    section = next(s for s in pe.sections
                   if s["rva"] <= pe.entry < s["rva"] + s["size"])
    offset = pe.entry - section["rva"]
    start = section["raw"] + offset
    end = section["raw"] + min(section["size"], section["rawsize"])
    return start, pe.data[start:end]


def expected_pcs(name, pe):
    # Locate the known fixture's memory instruction bytes, independently of
    # translator-produced translation.json and recovered CFG operation names.
    _, code = fixture_code(pe)
    assert code[:4] == b"\x31\xc0\x85\xd2", "review model expects zero-seeded fixtures"
    load = b"\x03\x01" if name == "sum" else b"\x33\x01"
    assert code.count(load) == 1
    pcs = {"load": pe.base + pe.entry + code.index(load), "none": 0}
    if name == "mutate":
        assert code.count(b"\x89\x01") == 1
        pcs["store"] = pe.base + pe.entry + code.index(b"\x89\x01")
    return pcs


def main():
    required = [OUT / name / "aot.dylib" for name in NAMES]
    required += [OUT / "fixtures" / (name + ".exe") for name in NAMES]
    if not all(path.is_file() for path in required):
        raise SystemExit("Run python3 memory_stage2/test_memory.py first")
    rng = random.Random(SEED)
    checks = zero_checks = invalid_checks = 0
    for name in NAMES:
        lib = ctypes.CDLL(str(OUT / name / "aot.dylib"))
        for mode in MODES:
            function = getattr(lib, "guest_" + mode)
            function.argtypes = [ctypes.POINTER(Memory), ctypes.c_uint64, ctypes.c_uint32]
            function.restype = Result
        pe = PE((OUT / "fixtures" / (name + ".exe")).read_bytes())
        pcs = expected_pcs(name, pe)
        for case in range(1200):
            size = rng.choice([1, 3, 4, 17, 4095, 4096, 4097, 8192])
            base = 0x170000000 + rng.randrange(1000) * 4096
            raw = bytes(rng.getrandbits(8) for _ in range(size))
            permissions = [rng.randrange(4) for _ in range((size + 4095) // 4096)]
            address = base + rng.choice([-1, 0, 1, max(0, size - 5),
                                        max(0, size - 2), 4094, size, size + 1])
            count = rng.choice([0, 1, 2, 3, 17, 1025, 0xffffffff])
            expected = reference(name, raw, base, address, count, permissions)
            expected_result = (*expected[:3], pcs[expected[4]])
            for mode in MODES:
                mapped = memory(raw, base, permissions)
                result = getattr(lib, "guest_" + mode)(ctypes.byref(mapped), address, count)
                actual = result_tuple(result)
                assert actual == expected_result, (name, mode, case, actual, expected_result)
                assert bytes(mapped.owner[0]) == expected[3], (name, mode, case, "write effects")
            checks += 1
        for mode in MODES:
            result = getattr(lib, "guest_" + mode)(None, 2**64 - 1, 0)
            assert result_tuple(result) == (0, 0, 0, 0)
            zero_checks += 1
        for invalid in ("misaligned_base", "overflowed_region", "missing_permissions",
                        "bad_page_count", "zero_size"):
            mapped = memory(b"\x11" * 8192)
            if invalid == "misaligned_base":
                mapped.base += 1
            elif invalid == "overflowed_region":
                mapped.base = 2**64 - 4096
            elif invalid == "missing_permissions":
                mapped.permissions = ctypes.POINTER(ctypes.c_uint8)()
            elif invalid == "bad_page_count":
                mapped.page_count = 1
            else:
                mapped.size = 0
            for mode in MODES:
                before = bytes(mapped.owner[0])
                result = getattr(lib, "guest_" + mode)(ctypes.byref(mapped), mapped.base, 1)
                assert result_tuple(result) == (0, 3, mapped.base, pcs["load"]), (name, mode, invalid)
                assert bytes(mapped.owner[0]) == before
                invalid_checks += 1

    original = (OUT / "fixtures/sum.exe").read_bytes()
    start, code = fixture_code(PE(original))
    rejected = []
    # Change only the branch displacement, keeping every decoded opcode valid.
    patches = [("wrong_exit", code.index(b"\x85\xd2\x74") + 3),
               ("wrong_backedge", code.index(b"\x83\xea\x01\x75") + 4)]
    for label, offset in patches:
        patched = bytearray(original)
        patched[start + offset] = 0
        try:
            recover(PE(bytes(patched)))
        except Unsupported as error:
            assert str(error) == "unproven branch target", (label, str(error))
            rejected.append({"case": label, "status": "REJECT", "reason": str(error)})
        else:
            raise AssertionError("unexpected accepted branch target: " + label)

    tracked = [HERE / name for name in ("translate.py", "guest_memory.h", "test_memory.py",
                                      "test_review_cases.py", "benchmark.py", "bench.c")]
    tracked += required
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in tracked}
    evidence = {
        "status": "PASS", "seed": SEED, "random_profile_cases": checks,
        "modes_per_case": len(MODES), "null_zero_count_checks": zero_checks,
        "invalid_descriptor_checks": invalid_checks, "branch_rejections": rejected,
        "oracle": "independent Python memory/effects model; shared ctypes layout and PE parser",
        "compared": ["result", "status", "access_address (operand EA)", "guest_pc", "entire backing bytes"],
        "limits": ["Only three zero-seeded recognized stream-loop fixtures",
                   "Failure behavior is the declared guest-memory model, not a Windows SEH oracle",
                   "Host backing pointers and lengths are trusted; mappings are stable and single-threaded",
                   "Compiled dylibs must be regenerated by test_memory.py after implementation edits"],
        "sha256": hashes,
    }
    destination = OUT / "review-evidence.json"
    destination.write_text(json.dumps(evidence, indent=2) + "\n")
    print(json.dumps({key: evidence[key] for key in (
        "status", "random_profile_cases", "modes_per_case", "null_zero_count_checks",
        "invalid_descriptor_checks", "branch_rejections")}, indent=2))


if __name__ == "__main__":
    main()
