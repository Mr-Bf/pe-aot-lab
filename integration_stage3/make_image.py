#!/usr/bin/env python3
"""Self-authored 3-section PE fixture; no execution or translation claim.

The assembler produces the original AMD64 bytes. RIP displacements are explicit
fixture-linker expressions; .text has no COFF relocations. The PE's one DIR64
entry relocates a .data pointer to an array. Program input is EDX=count.
"""
import argparse
import hashlib
import json
import pathlib
import random
import struct
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
from fixtures import pe_image, text_from_coff
from memory_stage2.image_loader import load_image

PREFERRED_BASE = 0x140000000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
POINTER_RVA = 0x2000
SEED_RVA = 0x2010
ARRAY_RVA = 0x2100
BSS_RVA = 0x2300
RELOC_RVA = 0x3000
ARRAY_COUNT = 64
ASSEMBLY = r""".text
.globl guest_entry
guest_entry:
  # movq pointer_slot(%rip), %rcx
  .byte 0x48,0x8b,0x0d
  .long 0x2000 - (0x1000 + (. - guest_entry) + 4)
  # movl seed(%rip), %eax
  .byte 0x8b,0x05
  .long 0x2010 - (0x1000 + (. - guest_entry) + 4)
  testl %edx,%edx
  jz guest_done
guest_array_load:
  addl (%rcx),%eax
guest_array_store:
  movl %eax,(%rcx)
  addq $4,%rcx
  subl $1,%edx
  jnz guest_array_load
guest_done:
guest_bss_store:
  # movl %eax, bss_output(%rip)
  .byte 0x89,0x05
  .long 0x2300 - (0x1000 + (. - guest_entry) + 4)
guest_return:
  retq
"""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def coff_labels(data):
    """Read assembler label values; these are fixture metadata, not CFG recovery."""
    _, _, _, symbols_at, symbol_count, _, _ = struct.unpack_from('<HHIIIHH', data)
    strings_at = symbols_at + symbol_count * 18
    labels = {}
    index = 0
    while index < symbol_count:
        name, value, section, _, _, aux = struct.unpack_from('<8sIhHBB', data, symbols_at + 18 * index)
        if name[:4] == b'\0' * 4:
            offset = struct.unpack_from('<I', name, 4)[0]
            start = strings_at + offset
            name = data[start:data.index(b'\0', start)]
        else:
            name = name.rstrip(b'\0')
        decoded = name.decode('ascii')
        if decoded.startswith('guest_') and section == 1:
            labels[decoded] = TEXT_RVA + value
        index += 1 + aux
    return labels


def build_fixture(output, seed=20261027):
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=True)
    source, obj, exe = output / 'image.s', output / 'image.obj', output / 'image.exe'
    source.write_text(ASSEMBLY)
    command = ['xcrun', 'clang', '-target', 'x86_64-pc-windows-msvc', '-c', str(source), '-o', str(obj)]
    subprocess.run(command, check=True, capture_output=True, text=True)
    object_bytes = obj.read_bytes()
    code = text_from_coff(object_bytes)
    labels = coff_labels(object_bytes)
    assert {'guest_entry', 'guest_array_load', 'guest_array_store', 'guest_bss_store', 'guest_return'} <= labels.keys()
    assert all(TEXT_RVA <= rva < TEXT_RVA + len(code) for rva in labels.values())

    data = bytearray(pe_image(code)[:512])
    pe, opt, table = 0x80, 0x98, 0x188
    struct.pack_into('<H', data, pe + 6, 3)
    struct.pack_into('<H', data, pe + 22, 0x22)  # executable, large-address-aware; relocations not stripped
    struct.pack_into('<I', data, opt + 8, 1024)
    struct.pack_into('<I', data, opt + 12, 0x700)
    struct.pack_into('<I', data, opt + 56, 0x4000)
    struct.pack_into('<II', data, opt + 112 + 5 * 8, RELOC_RVA, 12)

    def section(name, virtual_size, rva, raw, flags):
        return struct.pack('<8sIIIIIIHHI', name, virtual_size, rva, 512, raw, 0, 0, 0, 0, flags)

    data[table:table + 120] = (
        section(b'.text', len(code), TEXT_RVA, 512, 0x60000020)
        + section(b'.data', 0x900, DATA_RVA, 1024, 0xc0000040)
        + section(b'.reloc', 12, RELOC_RVA, 1536, 0x40000040))
    payload = bytearray(512)
    struct.pack_into('<Q', payload, POINTER_RVA - DATA_RVA, PREFERRED_BASE + ARRAY_RVA)
    rng = random.Random(seed)
    accumulator_seed = rng.getrandbits(32)
    values = [rng.getrandbits(32) for _ in range(ARRAY_COUNT)]
    struct.pack_into('<I', payload, SEED_RVA - DATA_RVA, accumulator_seed)
    struct.pack_into('<64I', payload, ARRAY_RVA - DATA_RVA, *values)
    relocations = struct.pack('<IIHH', DATA_RVA, 12, 0xa000, 0)
    pe_bytes = bytes(data) + code.ljust(512, b'\0') + payload + relocations.ljust(512, b'\0')
    exe.write_bytes(pe_bytes)
    manifest = {
        'scope': 'self-authored AMD64 PE fixture and loader validation only; execution requires unified integration tests',
        'input_contract': 'EDX=count; zero-extended RDX is supplied by tests',
        'preferred_base': PREFERRED_BASE,
        'entry_rva': TEXT_RVA,
        'pointer_rva': POINTER_RVA,
        'array_rva': ARRAY_RVA,
        'bss_output_rva': BSS_RVA,
        'accumulator_seed': accumulator_seed,
        'array': values,
        'labels': labels,
        'code_bytes': code.hex(),
        'source_sha256': sha256(ASSEMBLY.encode()),
        'coff_sha256': sha256(object_bytes),
        'pe_sha256': sha256(pe_bytes),
        'command': command,
    }
    (output / 'fixture.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return exe, manifest


def export_loaded(source, base, output):
    """Export loader output without running guest instructions."""
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=True)
    image = load_image(pathlib.Path(source), base)
    (output / 'image.bin').write_bytes(image.data)
    (output / 'permissions.bin').write_bytes(bytes(image.permissions))
    manifest = image.manifest()
    manifest['image_sha256'] = sha256(image.data)
    manifest['permissions_sha256'] = sha256(bytes(image.permissions))
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return image


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=pathlib.Path, default=ROOT / 'build/integration-stage3/image')
    parser.add_argument('--base', type=lambda value: int(value, 0), default=0x180000000)
    args = parser.parse_args()
    exe, manifest = build_fixture(args.out)
    image = export_loaded(exe, args.base, args.out / 'loaded')
    pointer = struct.unpack('<Q', image.read(args.base + POINTER_RVA, 8))[0]
    assert pointer == args.base + ARRAY_RVA
    assert image.read(args.base + BSS_RVA, 4) == b'\0' * 4
    print(json.dumps({'status': 'PREPARED', 'pe': str(exe), 'code_bytes': manifest['code_bytes'],
                      'base': args.base, 'relocated_pointer': pointer,
                      'scope': 'fixture assembly and data-image loading only; guest execution not tested'}))


if __name__ == '__main__':
    main()
