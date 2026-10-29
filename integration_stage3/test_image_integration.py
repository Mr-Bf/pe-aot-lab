#!/usr/bin/env python3
"""Real integration acceptance tests, once Program/Region are available.

The comparison model is explicit uint32 arithmetic and image bytes in Python.
It is not an x86 hardware/Rosetta oracle; source AMD64 bytes are saved separately.
"""
import argparse
import ctypes
import hashlib
import json
import pathlib
import random
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from integration_stage3.make_image import (build_fixture, export_loaded, ARRAY_RVA,
                                           BSS_RVA, POINTER_RVA)
from memory_stage2.image_loader import load_image

OUT = ROOT / 'build/integration-stage3/image-integration'
STACK_BASE = 0x70000000
STACK_SIZE = 0x10000
RSP = STACK_BASE + STACK_SIZE - 0x108
RETURN_ADDRESS = 0x7fff00000000


def word(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def reference(initial, seed, count, array_rva=ARRAY_RVA, finish=True):
    data = bytearray(initial)
    accumulator = seed
    for index in range(count):
        address = array_rva + 4 * index
        accumulator = (accumulator + word(data, address)) & 0xffffffff
        struct.pack_into('<I', data, address, accumulator)
    if finish:
        struct.pack_into('<I', data, BSS_RVA, accumulator)
    return data, accumulator


def field(value, name):
    return value[name] if isinstance(value, dict) else getattr(value, name)


def run_suite(random_bases=1000):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'evidence.json').write_text(json.dumps({'status': 'RUNNING', 'random_bases': random_bases}) + '\n')
    # Import inside execution mode: preparing a fixture must not imply a working runtime.
    from integration_stage3.bindings import Program, Region

    exe, metadata = build_fixture(OUT / 'fixture')
    program = Program(exe, out_dir=OUT / 'compiled')
    rng = random.Random(20261028)
    bases = [0x140000000, 0x180000000, 0x100000000]
    bases += [rng.randrange(0x10000, 0x100000) * 65536 for _ in range(random_bases)]
    digest = hashlib.sha256()
    records = []

    def execute(base, count, mutate=None, bad_stack=False):
        loaded = load_image(exe, base)
        region = Region(base, bytearray(loaded.data), permissions=bytearray(loaded.permissions))
        if mutate:
            mutate(region)
        assert base != ctypes.addressof(ctypes.c_ubyte.from_buffer(region.data))
        before = bytes(region.data)
        stack_flags = bytearray([0] + [3] * (STACK_SIZE // 4096 - 1))
        if bad_stack:
            stack_flags[-1] = 0
        stack = Region(STACK_BASE, bytearray(STACK_SIZE), permissions=stack_flags)
        result = program.run(gpr={'RDX': count}, regions=[region], base=base,
                             stack=stack, rsp=RSP, return_address=RETURN_ADDRESS,
                             max_steps=100000)
        return region, before, result

    for index, base in enumerate(bases):
        count = [0, 1, 64][index] if index < 3 else rng.randrange(65)
        region, before, result = execute(base, count)
        expected, accumulator = reference(before, metadata['accumulator_seed'], count)
        assert field(result, 'status') == 0 and field(result, 'returned')
        registers = field(result, 'registers')
        assert registers['RAX'] == accumulator
        assert registers['RSP'] == RSP + 8 and registers['RIP'] == RETURN_ADDRESS
        assert region.data == expected, (index, base, count)
        assert struct.unpack_from('<Q', region.data, POINTER_RVA)[0] == base + ARRAY_RVA
        digest.update(struct.pack('<QII', base, count, accumulator))
        digest.update(region.data)
    records.append({'case': 'rebase_rip_relative_dir64_bss_ret', 'cases': len(bases),
                    'status': 'PASS', 'result_sha256': digest.hexdigest()})

    base = 0x180000000
    labels = metadata['labels']

    def check_fault(result, pc_rva, address, access):
        assert field(result, 'status') != 0 and not field(result, 'returned')
        fault = field(result, 'fault')
        assert field(fault, 'pc') == base + pc_rva
        assert field(fault, 'address') == address
        assert field(fault, 'width') == 4 and field(fault, 'access') == access
        assert field(result, 'registers')['RIP'] == base + pc_rva

    def record_fault(name, result, region, **extra):
        fault = field(result, 'fault')
        registers = field(result, 'registers')
        records.append({'case': name, 'status': 'PASS', 'expected_execution': 'FAULT',
                        'fault': {key: field(fault, key) for key in ('status', 'pc', 'address', 'width', 'access')},
                        'registers': {key: registers[key] for key in ('RAX', 'RCX', 'RDX', 'RSP', 'RIP')},
                        'image_sha256': hashlib.sha256(region.data).hexdigest(), **extra})

    # Read/seed operations succeed, then the first array write is denied.
    region, before, result = execute(base, 2, lambda r: r.permissions.__setitem__(2, 1))
    check_fault(result, labels['guest_array_store'], base + ARRAY_RVA, 2)
    assert region.data == before
    assert field(result, 'registers')['RAX'] == (metadata['accumulator_seed'] + word(before, ARRAY_RVA)) & 0xffffffff
    record_fault('readonly_array_store', result, region)

    # 960 completed writes reach the .reloc boundary. Its readable contents let
    # ADD complete, while the subsequent store faults and must not commit.
    prefix_count = (0x3000 - ARRAY_RVA) // 4
    region, before, result = execute(base, prefix_count + 1)
    expected, accumulator = reference(before, metadata['accumulator_seed'], prefix_count, finish=False)
    check_fault(result, labels['guest_array_store'], base + 0x3000, 2)
    assert region.data == expected
    assert field(result, 'registers')['RAX'] == (accumulator + word(before, 0x3000)) & 0xffffffff
    assert field(result, 'registers')['RDX'] == 1
    record_fault('completed_writes_survive_later_store_fault', result, region, completed_writes=prefix_count)

    region, before, result = execute(base, prefix_count + 1, lambda r: r.permissions.__setitem__(3, 0))
    expected, accumulator = reference(before, metadata['accumulator_seed'], prefix_count, finish=False)
    check_fault(result, labels['guest_array_load'], base + 0x3000, 1)
    assert region.data == expected and field(result, 'registers')['RAX'] == accumulator
    record_fault('failed_read_preserves_prior_registers_and_writes', result, region)

    def crossing(region):
        struct.pack_into('<Q', region.data, POINTER_RVA, base + 0x2ffe)

    region, before, result = execute(base, 1, crossing)
    check_fault(result, labels['guest_array_store'], base + 0x2ffe, 2)
    assert region.data == before
    record_fault('cross_page_store_has_no_partial_write', result, region)

    region, before, result = execute(base, 2, bad_stack=True)
    expected, accumulator = reference(before, metadata['accumulator_seed'], 2)
    assert region.data == expected and field(result, 'status') != 0 and not field(result, 'returned')
    fault = field(result, 'fault')
    assert field(fault, 'pc') == base + labels['guest_return']
    assert field(fault, 'address') == RSP and field(fault, 'width') == 8 and field(fault, 'access') == 1
    registers = field(result, 'registers')
    assert registers['RSP'] == RSP and registers['RAX'] == accumulator
    assert registers['RIP'] == base + labels['guest_return']
    record_fault('ret_stack_fault_preserves_completed_image_writes', result, region)

    # Program is a frozen translation snapshot. Changing the original file must
    # not silently mix newly loaded data/code with the already compiled object.
    original = exe.read_bytes()
    changed = bytearray(original)
    changed[changed.index(b'\x48\x83\xc1\x04') + 3] = 8
    struct.pack_into('<I', changed, 1024 + 0x10, (metadata['accumulator_seed'] + 7) & 0xffffffff)
    try:
        exe.write_bytes(changed)
        result = program.run(gpr={'RDX': 2}, base=base)
        expected = (metadata['accumulator_seed'] + sum(metadata['array'][:2])) & 0xffffffff
        assert field(result, 'status') == 0 and field(result, 'registers')['RAX'] == expected
    finally:
        exe.write_bytes(original)
    records.append({'case': 'source_file_change_uses_frozen_translation_snapshot', 'status': 'PASS'})

    def reject_setup(name, configure):
        loaded = load_image(exe, base)
        image_region = Region(base, bytearray(loaded.data), permissions=bytearray(loaded.permissions))
        options = {'gpr': {'RDX': 0}, 'base': base, 'regions': [image_region]}
        configure(image_region, options)
        before = bytes(image_region.data)
        try:
            program.run(**options)
        except ValueError as error:
            assert image_region.data == before, 'rejected setup must not overwrite image bytes'
            records.append({'case': name, 'status': 'PASS', 'expected_execution': 'REJECT', 'reason': str(error)})
        else:
            raise AssertionError('setup unexpectedly accepted: ' + name)

    reject_setup('changed_executable_mapping', lambda r, o: r.data.__setitem__(0x1000, 0x90))
    reject_setup('image_reused_as_stack', lambda r, o: o.update(stack=r, rsp=base + 0x1008))
    reject_setup('writable_host_alias_of_executable_image',
                 lambda r, o: o['regions'].append(Region(0x300000000, r.data)))
    reject_setup('stack_guest_range_overlaps_image',
                 lambda r, o: o.update(stack=Region(base, bytearray(0x10000)), rsp=base + 0x1008))
    reject_setup('overlapping_guest_region',
                 lambda r, o: o['regions'].append(Region(base + 0x1000, bytearray(4096))))
    reject_setup('writable_executable_page', lambda r, o: r.permissions.__setitem__(1, 7))
    reject_setup('unknown_permission_bits', lambda r, o: r.permissions.__setitem__(2, 0x83))

    loaded = load_image(exe, base)
    image_region = Region(base, bytearray(loaded.data), permissions=bytearray(loaded.permissions))
    image_region.permissions[1] = 1
    before = bytes(image_region.data)
    result = program.run(gpr={'RDX': 2}, base=base, regions=[image_region])
    fault = field(result, 'fault')
    assert field(result, 'status') == 2 and not field(result, 'returned')
    assert field(fault, 'pc') == base + 0x1000 and field(fault, 'access') == 4
    assert image_region.data == before
    record_fault('instruction_fetch_permission_fault', result, image_region)

    # A second translation at the same output path must not dlopen the first
    # program's already loaded image. Keep A alive and exercise A -> B -> A.
    shared_output = OUT / 'shared-output'
    alternate = bytearray(original)
    alternate[alternate.index(b'\x48\x83\xc1\x04') + 3] = 8
    alternate_path = OUT / 'alternate-stride.exe'
    alternate_path.write_bytes(alternate)
    first = Program(exe, out_dir=shared_output)
    first_result = first.run(gpr={'RDX': 2}, base=base)
    second = Program(alternate_path, out_dir=shared_output)
    second_result = second.run(gpr={'RDX': 2}, base=base)
    first_again = first.run(gpr={'RDX': 2}, base=base)
    expected_first = (metadata['accumulator_seed'] + sum(metadata['array'][:2])) & 0xffffffff
    expected_second = (metadata['accumulator_seed'] + metadata['array'][0] + metadata['array'][2]) & 0xffffffff
    assert first.library_path != second.library_path
    assert all(field(r, 'status') == 0 and field(r, 'returned') for r in (first_result, second_result, first_again))
    assert field(first_result, 'registers')['RAX'] == expected_first
    assert field(first_again, 'registers')['RAX'] == expected_first
    assert field(second_result, 'registers')['RAX'] == expected_second
    records.append({'case': 'shared_output_directory_keeps_loaded_programs_distinct', 'status': 'PASS',
                    'sequence': ['A', 'B', 'A'], 'rax': [expected_first, expected_second, expected_first],
                    'library_sha256': [hashlib.sha256(pathlib.Path(p.library_path).read_bytes()).hexdigest()
                                       for p in (first, second)]})

    report = {'status': 'PASS', 'scope': 'real Remill + explicit guest memory + relocated PE data + guest RET',
              'reference': 'Python uint32 and image-byte model; no x86 execution oracle in this suite',
              'fixture_pe_sha256': metadata['pe_sha256'], 'records': records,
              'source_sha256': {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in [HERE / 'make_image.py', pathlib.Path(__file__).resolve(),
                                             HERE / 'runtime.c', HERE / 'runtime.h', HERE / 'bindings.py',
                                             HERE / 'lift.py', ROOT / 'memory_stage2/image_loader.py']},
              'tested_artifact_sha256': {
                  str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in [OUT / 'compiled/arm64.o', pathlib.Path(program.library_path)]}}
    (OUT / 'evidence.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--random-bases', type=int, default=1000)
    args = parser.parse_args()
    if args.random_bases < 0:
        parser.error('--random-bases must be nonnegative')
    if args.prepare_only:
        exe, metadata = build_fixture(OUT / 'fixture')
        export_loaded(exe, 0x180000000, OUT / 'prepared-image')
        print(json.dumps({'status': 'PREPARED', 'pe_sha256': metadata['pe_sha256'],
                          'scope': 'no guest execution; Program runtime integration still required'}))
        return
    try:
        run_suite(args.random_bases)
    except Exception as error:
        (OUT / 'evidence.json').write_text(json.dumps({'status': 'FAIL', 'error': str(error),
            'error_type': type(error).__name__}, indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
