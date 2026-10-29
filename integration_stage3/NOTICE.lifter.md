# Remill lifter attribution and changes

This directory's Remill patches and the resulting lifted LLVM IR / ARM64 objects
contain work derived from Remill, copyright Trail of Bits, Inc. and contributors,
Apache License 2.0. See `LICENSE.remill`. Pinned upstream commit:
`56918a8c2554088e93389e97d292f4035286506c`.
The source archive contains no root NOTICE file.

Local changes, 2026-10-27:

- `xed-only.patch`: disables non-XED guest backends and unrelated Sleigh/Ghidra
  build dependencies. Instruction decoder and AMD64 instruction semantics are
  unchanged by this patch.
- `transactions.patch`: adds side-effecting instruction begin/commit hooks and
  early returns before the first LLVM optimizer pass; direct lifted calls also
  check runtime status immediately after the child returns.
- `aot-profile.patch`: validates a closed scalar profile using XED plus Remill,
  emits decoded metadata, discovers/lifts direct callees, requires raw State ABI,
  and clears misleading helper/call-site memory effects before optimization.

No stage2 source or toolchain is modified. Stage3 reads the pinned LLVM 17,
XED/gflags/glog dependencies and source archive already present under
`work/remill-stage2/`. Their original licenses still apply; see stage2's
`NOTICE.md` for the tool dependency inventory. This directory's runtime,
fixture scripts and harnesses written specifically for PE AOT Lab are covered
by the repository license, except for the identified Remill-derived portions.

Redistribution of the generated objects or lifted IR must preserve the Apache
license and relevant attribution/modification notices; the repository MIT
license does not replace Remill's license.
