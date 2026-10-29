#!/usr/bin/env python3
"""Self-authored Windows AMD64 CALL/RET fixtures, with no COFF relocations.

All functions and call targets reside in one .text. Relative CALL displacements
are assembler-resolved label differences. Original text bytes are also embedded
unchanged in a Mach-O ms_abi oracle; fault fixtures are never run by that oracle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fixtures import pe_image

IMAGE_BASE = 0x140000000
TEXT_RVA = 0x1000
MASK64 = (1 << 64) - 1


def call(target, marker):
    return f"{marker}:\n.byte 0xe8\n.long {target} - . - 4\n"


SOURCES = {
    "direct": "guest_entry:\nsubq $40, %rsp\n"
        + call("fn_add", "mark_call")
        + "mark_after_call:\naddq $7, %rax\naddq $40, %rsp\nretq\n"
          "fn_add:\nmovq %rcx, %rax\naddq %rdx, %rax\nretq\n",
    "stack6": "guest_entry:\nmovq 40(%rsp), %r10\nmovq 48(%rsp), %r11\n"
        "subq $56, %rsp\nmovq %r10, 32(%rsp)\nmovq %r11, 40(%rsp)\n"
        + call("fn_six", "mark_call")
        + "mark_after_call:\naddq $56, %rsp\nretq\n"
          "fn_six:\nmovq %rcx, %rax\nleaq (%rdx,%rdx,2), %r10\naddq %r10, %rax\n"
          "leaq (%r8,%r8,4), %r10\naddq %r10, %rax\n"
          "leaq (%r9,%r9,2), %r10\nleaq (%r9,%r10,2), %r10\naddq %r10, %rax\n"
          "movq 40(%rsp), %r10\nleaq (%r10,%r10,4), %r11\n"
          "leaq (%r10,%r11,2), %r10\naddq %r10, %rax\n"
          "movq 48(%rsp), %r10\nleaq (%r10,%r10,2), %r11\n"
          "leaq (%r10,%r11,4), %r10\naddq %r10, %rax\nretq\n",
    "shadow": "guest_entry:\nsubq $40, %rsp\n"
        + call("fn_shadow", "mark_call")
        + "mark_after_call:\naddq $40, %rsp\nretq\n"
          "fn_shadow:\nmovq %rcx, 8(%rsp)\nmovq %rdx, 16(%rsp)\n"
          "movq %r8, 24(%rsp)\nmovq %r9, 32(%rsp)\n"
          "movq 8(%rsp), %rax\nmovq 16(%rsp), %r10\naddq %r10, %rax\naddq %r10, %rax\n"
          "movq 24(%rsp), %r10\naddq %r10, %rax\naddq %r10, %rax\naddq %r10, %rax\n"
          "movq 32(%rsp), %r10\naddq %r10, %rax\naddq %r10, %rax\n"
          "addq %r10, %rax\naddq %r10, %rax\nretq\n",
    "nested": "guest_entry:\nsubq $40, %rsp\n"
        + call("fn_middle", "mark_call")
        + "mark_after_call:\naddq $5, %rax\naddq $40, %rsp\nretq\n"
          "fn_middle:\nsubq $40, %rsp\n"
        + call("fn_inner", "mark_inner_call")
        + "mark_after_inner:\naddq $3, %rax\naddq $40, %rsp\nretq\n"
          "fn_inner:\nmovq %rcx, %rax\naddq %rdx, %rax\nretq\n",
    "recursive": "guest_entry:\ntestq %rcx, %rcx\njz mark_base_case\n"
        "subq $40, %rsp\nmovq %rcx, 32(%rsp)\nsubq $1, %rcx\n"
        + call("guest_entry", "mark_recursive_call")
        + "mark_after_call:\nmovq 32(%rsp), %rdx\naddq %rdx, %rax\n"
          "addq $40, %rsp\nretq\nmark_base_case:\nxorl %eax, %eax\nretq\n",
    "fault_propagation": "guest_entry:\nmark_before_call_store:\nmovq $0x11, (%rdx)\n"
        "subq $40, %rsp\n"
        + call("fn_fault", "mark_call")
        + "mark_after_call_store:\nmovq $0x22, (%rdx)\naddq $40, %rsp\nretq\n"
          "fn_fault:\nmark_callee_load:\nmovq (%rcx), %rax\nretq\n",
    "nested_fault_propagation": "guest_entry:\nmark_before_call_store:\nmovq $0x11, (%rdx)\n"
        "subq $40, %rsp\n"
        + call("fn_fault_middle", "mark_call")
        + "mark_after_call_store:\nmovq $0x22, (%rdx)\naddq $40, %rsp\nretq\n"
          "fn_fault_middle:\nsubq $40, %rsp\n"
        + call("fn_fault_inner", "mark_inner_call")
        + "mark_middle_after_call_store:\nmovq $0x33, (%rdx)\naddq $40, %rsp\nretq\n"
          "fn_fault_inner:\nmark_callee_load:\nmovq (%rcx), %rax\nretq\n",
    "bad_return": "guest_entry:\nmark_before_call_store:\nmovq $0x11, (%rdx)\n"
        "subq $40, %rsp\n"
        + call("fn_corrupt_return", "mark_call")
        + "mark_after_call_store:\nmovq $0x22, (%rdx)\naddq $40, %rsp\nretq\n"
          "fn_corrupt_return:\nmovq %rcx, (%rsp)\nmovq $0x3333, %rax\n"
          "mark_bad_ret:\nretq\n",
    "return_only": "guest_entry:\nmovq %rcx, %rax\nmark_ret:\nretq\n",
    "return_shift": "guest_entry:\naddq %rcx, %rsp\nmark_ret:\nretq\n",
    "external_call": "guest_entry:\nsubq $40, %rsp\nmark_call:\n"
        ".byte 0xe8\n.long 0x4000\naddq $40, %rsp\nretq\n",
    "indirect_call": "guest_entry:\nsubq $40, %rsp\nmark_call:\n"
        "callq *%rcx\naddq $40, %rsp\nretq\n",
}
FUNCTIONAL = ("direct", "stack6", "shadow", "nested", "recursive", "return_only")
REJECTED = ("external_call", "indirect_call")

ORACLE_C = r'''#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
__attribute__((ms_abi)) uint64_t guest_entry(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
int main(void) {
    uint64_t a,b,c,d,e,f;
    while(scanf("%" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64 " %" SCNx64,
                &a,&b,&c,&d,&e,&f)==6)
        printf("%016" PRIx64 "\n",guest_entry(a,b,c,d,e,f));
    return 0;
}
'''


def parse_coff(data):
    machine, section_count, _, symbol_table, symbol_count, optional_size, _ = struct.unpack_from("<HHIIIHH", data)
    if machine != 0x8664:
        raise ValueError("fixture requires AMD64 COFF")
    text_section = None
    for index in range(section_count):
        fields = struct.unpack_from("<8sIIIIIIHHI", data, 20 + optional_size + index * 40)
        name, _, _, size, raw, _, _, relocations, _, _ = fields
        if name.rstrip(b"\0") == b".text":
            if relocations:
                raise ValueError("fixture .text must have no COFF relocations")
            text_section = (index + 1, data[raw:raw + size])
    if text_section is None:
        raise ValueError("fixture has no .text")
    strings_start = symbol_table + symbol_count * 18
    labels = {}
    index = 0
    while index < symbol_count:
        name, value, section, _, _, auxiliary = struct.unpack_from("<8sIhHBB", data, symbol_table + index * 18)
        if name[:4] == b"\0\0\0\0":
            offset, = struct.unpack_from("<I", name, 4)
            start = strings_start + offset
            name = data[start:data.index(b"\0", start)]
        else:
            name = name.rstrip(b"\0")
        label = name.decode("ascii")
        if section == text_section[0] and (label == "guest_entry" or label.startswith(("fn_", "mark_"))):
            labels[label] = value
        index += 1 + auxiliary
    return text_section[1], labels


def expected(name, arguments):
    a, b, c, d, e, f = arguments
    if name == "direct":
        value = a + b + 7
    elif name == "stack6":
        value = a + 3*b + 5*c + 7*d + 11*e + 13*f
    elif name == "shadow":
        value = a + 2*b + 3*c + 4*d
    elif name == "nested":
        value = a + b + 8
    elif name == "recursive":
        value = a * (a + 1) // 2
    elif name == "return_only":
        value = a
    else:
        raise ValueError("no normal-execution oracle for " + name)
    return value & MASK64


def build(directory):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {}
    (directory / "oracle.c").write_text(ORACLE_C)
    for name, body in SOURCES.items():
        names = re.findall(r"^([A-Za-z_][A-Za-z_0-9]*):", body, re.MULTILINE)
        asm = ".text\n" + "".join(".globl " + label + "\n" for label in names) + body
        source, obj, pe = (directory / (name + suffix) for suffix in (".s", ".obj", ".exe"))
        source.write_text(asm)
        subprocess.run(["xcrun", "clang", "-target", "x86_64-pc-windows-msvc",
                        "-c", str(source), "-o", str(obj)], check=True)
        raw, labels = parse_coff(obj.read_bytes())
        if set(labels) != set(names) or labels["guest_entry"] != 0:
            raise ValueError("fixture symbols not retained: " + name)
        pe.write_bytes(pe_image(raw))
        oracle_asm = directory / (name + "-oracle.s")
        oracle_asm.write_text(".text\n.globl _guest_entry\n_guest_entry:\n.byte "
                              + ",".join("0x%02x" % byte for byte in raw) + "\n")
        manifest[name] = {
            "name": name, "pe_path": str(pe), "oracle_asm": str(oracle_asm),
            "kind": "functional" if name in FUNCTIONAL else "rejection" if name in REJECTED else "fault",
            "image_base": IMAGE_BASE, "entry_rva": TEXT_RVA, "entry_va": IMAGE_BASE + TEXT_RVA,
            "text_sha256": hashlib.sha256(raw).hexdigest(), "text_hex": raw.hex(),
            "pe_sha256": hashlib.sha256(pe.read_bytes()).hexdigest(), "coff_relocations": 0,
            "labels": {label: IMAGE_BASE + TEXT_RVA + offset for label, offset in labels.items()},
        }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path, nargs="?", default=ROOT / "build/integration-stage3/call-fixtures")
    args = parser.parse_args()
    print(json.dumps(build(args.output), indent=2))
