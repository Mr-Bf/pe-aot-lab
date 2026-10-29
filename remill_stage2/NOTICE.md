# Attribution and modification notice

This experiment uses Remill, copyright Trail of Bits, Inc. and its contributors,
under the Apache License 2.0. The full upstream license is `LICENSE.remill`.
Pinned source: <https://github.com/lifting-bits/remill/tree/56918a8c2554088e93389e97d292f4035286506c>.
The pinned source archive has no root NOTICE file.

The generated LLVM IR, native objects and probe executables in
`../build/remill-stage2/` incorporate semantics derived from Remill. Their
Remill-derived portions remain under Apache 2.0; the repository's MIT license
does not replace that license. Redistributing these artifacts should include
`LICENSE.remill` and this notice. Upstream source remains in workspace-local
`work/remill-stage2/` and retains its source headers.

Local modifications, 2026-10-27:

- `xed-only.patch` removes non-XED architecture build dependencies and the
  Sleigh umbrella include; disabled guest architectures return null.
  XED decoding, InstructionLifter, TraceLifter and AMD64 instruction semantics
  are not changed by this patch.
- `wrapper-null-memory.patch` modifies the CLI prototype wrapper in `Lift.cpp`
  to initialize its Memory token to null before any wrapper optimization.
  This fixes undefined tokens passed into `noundef` helper parameters.
- `runtime.ll` implements a restricted test runtime, with identity annotation
  helpers following the behavior in Remill `tests/X86/Run.cpp`. It is not a
  general Remill runtime or Windows implementation.

Tool dependencies are downloaded locally, not vendored as project source:

| Dependency | License | Role |
| --- | --- | --- |
| LLVM 17.0.6 / Clang | Apache-2.0 WITH LLVM-exception (component exceptions apply) | Build, optimize and lower IR |
| Intel XED / mbuild | Apache-2.0 | Build-time AMD64 decoder / build helper |
| gflags | BSD-3-Clause | Build-time CLI flags |
| glog | BSD-3-Clause | Build-time logging |
| GoogleTest | BSD-3-Clause | Remill dependency superbuild; tests disabled in Remill build |
| CMake | BSD-3-Clause; bundled component licenses also apply | Build tool |
| Ninja | Apache-2.0 | Build tool |
| zstd | dual BSD-3-Clause / GPL-2.0; choose BSD for this use | Existing host library required by LLVM bottle |

The generated ARM64 test executables do not link LLVM, XED, glog or gflags;
those remain tooling dependencies. Preserve their upstream license files if
redistributing the local toolchain. Apple SDK/system libraries are supplied by
Xcode and are not redistributed by this experiment.
