# External declarations and tools

- Interface declarations are read from the unchanged fixed source of [misyltoad/mingw-directx-headers](https://github.com/misyltoad/mingw-directx-headers/tree/9df86f2341616ef1888ae59919feaa6d4fad693d). Its README and `COPYING.MinGW-w64.txt` identify DirectX/DDK headers as LGPL-2.1-or-later and explain the limited declaration/small-inline use case. The complete headers remain in the external work tree; they are not copied into this fixture source directory.
- Basic Windows/IUnknown declarations are read from [DXMT](https://github.com/3Shain/dxmt/tree/d162ea44a31fbf9089ea09977337f0beb30bd082), retaining that source tree and its licensing notices. No DXMT runtime is linked into this Windows PE preparation artifact.
- LLVM/Clang 17, llvm-dlltool, and LLD provide the Windows COFF/PE build tools. The frozen Remill/XED COM-profile executable is used only to demonstrate its static rejection boundary. Existing toolchain notices and pinned manifests remain applicable; no new assertion of unrestricted binary redistribution is made here.
- `compat/cstdint` and `compat/cstring` are local freestanding declaration adapters. They do not replace any DirectX interface definition or provide a C/C++ runtime implementation.

This fixture is self-authored. It contains no commercial game, Steamworks SDK, DRM, or anti-cheat material.

## AOT producer and native bridge additions

The independent D3D11 producer also builds Remill commit `56918a8c2554088e93389e97d292f4035286506c` with the versioned patches in this directory. Its Apache-2.0 license is preserved in [LICENSE.remill](LICENSE.remill). Lifted IR, objects, and executables contain Remill-derived instruction semantics; the surrounding project MIT license does not remove that attribution or applicable obligations. LLVM/XED/compiler-runtime notices from the pinned toolchain remain applicable.

The local runtime, typed native adapter, host, and tests are original project code derived from earlier project profiles. `transaction_v1.c` is a separate version with D3D11 call binding and map-permission lifetime support; frozen COM and earlier profiles are not edited. The native adapter links the separately built DXMT libraries, whose own LGPL and other component notices must accompany any eventual distribution as applicable. This prototype has not completed a final App distribution package or a redistribution review of that package.
