#!/usr/bin/env python3
"""Compile/inspect the window sample. Never execute Windows, AOT or GPU code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
WORK = ROOT.parents[1] / 'work'
sys.path.insert(0, str(ROOT))
from callback_bridge.imports_v1 import load_imported_image
from graphics_stage5.build_shaders import verify_shaders

OUT = ROOT / 'build/window-bridge/prepared-v2'
PREP = ROOT / 'build/window-bridge/preparation'
LLVM = WORK / 'remill-stage2/llvm@17/17.0.6/bin'
LINK = WORK / 'file-bridge/tools/lld-link'
HEADERS = WORK / 'window-bridge/headers/sysroot/include'
DXHEADERS = WORK / 'graphics-stage5/sources/mingw-directx-headers-9df86f2341616ef1888ae59919feaa6d4fad693d'
BASE = 0x140000000
APIS = {
    'kernel32': ['CloseHandle', 'CreateFileA', 'ExitProcess', 'GetLastError',
                 'GetModuleHandleA', 'WriteFile'],
    'user32': ['AdjustWindowRectEx', 'CreateWindowExA', 'DefWindowProcA',
               'DestroyWindow', 'DispatchMessageA', 'GetClientRect', 'GetMessageA',
               'PostQuitMessage', 'RegisterClassExA', 'SetFocus', 'ShowWindow',
               'UnregisterClassA', 'ValidateRect'],
    'd3d11': ['D3D11CreateDeviceAndSwapChain'],
}
# Parser-only distinct labels. These numbers DO NOT register runtime APIs.
PARSE_PROFILE = {(dll + '.dll', name): index + 1 for index, (dll, name) in
                 enumerate((dll, name) for dll, names in APIS.items() for name in names)}
FLAGS = ['-target', 'x86_64-w64-windows-gnu', '-O2', '-std=c++17',
         '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-nostdinc++',
         '-fno-builtin', '-fno-stack-protector', '-mno-stack-arg-probe',
         '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
         '-fno-vectorize', '-fno-slp-vectorize', '-mno-sse', '-mno-sse2',
         '-mno-mmx', '-fno-jump-tables', '-fno-optimize-sibling-calls',
         '-fno-exceptions', '-fno-rtti', '-fno-lto',
         '-isystem', str(DXHEADERS), '-isystem', str(HEADERS)]


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot(paths):
    return {str(p): sha(p) for p in sorted({Path(p).resolve() for p in paths})}


def run(args, log=None):
    args = list(map(str, args))
    result = subprocess.run(args, text=True, capture_output=True)
    if log:
        Path(log).write_text(json.dumps({'command': args, 'returncode': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    require(result.returncode == 0, 'command failed: ' + json.dumps(args) + ' log=' + str(log) + '\n' + result.stderr[-2500:])
    return result.stdout


def dependencies():
    result = {}
    for source in ('fixture.cpp', 'abi_layout.cpp'):
        text = run([LLVM / 'clang', *FLAGS, '-M', '-MT', 'inputs', HERE / source])
        require(text.startswith('inputs:'), 'unexpected dependency output')
        result[source] = sorted(str(Path(s).resolve()) for s in shlex.split(text.split(':', 1)[1].replace('\\\n', ' ')))
    require(str(HEADERS / 'winuser.h') in result['fixture.cpp'], 'WinUser not in actual dependency set')
    require(str(DXHEADERS / 'd3d11.h') in result['fixture.cpp'], 'original DirectX header absent')
    return result


def inputs(deps):
    paths = {Path(p) for values in deps.values() for p in values}
    paths |= {Path(__file__), ROOT / 'callback_bridge/imports_v1.py',
              ROOT / 'memory_stage2/image_loader.py', ROOT / 'graphics_stage5/build_shaders.py',
              ROOT / 'build/graphics-stage5/shaders/evidence.json',
              PREP / 'header-archive.json', PREP / 'mingw-source-ref.json',
              PREP / 'headers-configure.json', PREP / 'headers-install.json',
              Path(sys.executable), LINK}
    paths |= {LLVM / name for name in ('clang', 'llvm-dlltool', 'llvm-nm', 'llvm-objdump', 'llvm-readobj')}
    # Actual tool dylibs are separately listed by otool; system shared cache is
    # deliberately not claimed to be hashed or executed-image traced here.
    paths |= {LLVM.parent / 'lib/libLLVM.dylib', LLVM.parent / 'lib/libclang-cpp.dylib',
              Path('/opt/homebrew/opt/zstd/lib/libzstd.1.dylib')}
    return paths


def inspect(out):
    image = load_imported_image(out / 'integer-tile.exe', signatures=PARSE_PROFILE)
    symbols = {}
    for line in (out / 'integer-tile.map').read_text().splitlines():
        m = re.match(r'^\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{16})\b', line)
        if m:
            symbols[m[1]] = int(m[2], 16) - BASE
    require(symbols.get('window_entry') == image.entry_rva and 'window_proc' in symbols, 'entry/callback roots missing')
    imports = [{k: row[k] for k in ('dll', 'name', 'iat_rva')} for row in image.imports]
    require({(i['dll'], i['name']) for i in imports} == set(PARSE_PROFILE), 'actual import set changed')
    instructions = []
    for line in (out / 'disassembly.txt').read_text().splitlines():
        m = re.match(r'^\s*([0-9a-fA-F]+):((?:\s+[0-9a-fA-F]{2})+)\s+([a-z][a-z0-9]*)\s*(.*)$', line)
        if not m:
            continue
        raw = bytes.fromhex(m[2]); rva = int(m[1], 16) - image.base
        require(image.read(image.base + rva, len(raw)) == raw, 'disassembly differs from PE')
        instructions.append({'rva': rva, 'bytes': raw.hex(), 'mnemonic': m[3], 'operand': m[4].strip()})
    require(not any(re.search(r'%[xyz]mm\d+|%mm[0-7]', i['operand']) for i in instructions), 'unexpected SIMD')
    virtual_calls = []
    register_calls = []
    for row in instructions:
        if row['mnemonic'] not in ('call', 'callq') or '*' not in row['operand'] or '%rip' in row['operand']:
            continue
        register = re.fullmatch(r'\*%(r\w+)', row['operand'])
        if register:
            register_calls.append({**row, 'register': register[1].upper(),
                'status': 'UNSUPPORTED_BY_FROZEN_PRODUCER_REQUIRES_TARGET_PROOF'})
            continue
        m = re.fullmatch(r'\*(?:(0x[0-9a-f]+|\d+))?\(%(r\w+)\)', row['operand'])
        require(m, 'non-slot indirect call requires separate review: ' + row['operand'])
        disp = int(m[1], 0) if m[1] else 0
        require(disp % 8 == 0, 'non-pointer-aligned vtable displacement')
        virtual_calls.append({**row, 'base_reg': m[2].upper(), 'displacement': disp, 'slot': disp // 8})
    layout = json.loads((out / 'abi-layout.json').read_text())
    require(layout['size_MSG'] == 48 and layout['size_WNDCLASSEXA'] == 80 and layout['slot_IDXGISwapChain_Present'] == 8,
            'Windows ABI probe changed')
    return {'status': 'WINDOW_PE_PREPARED_NOT_EXECUTED', 'pe_sha256': sha(out / 'integer-tile.exe'),
        'entry_rva': image.entry_rva, 'callback_roots': [{'rva': symbols['window_proc'], 'symbol': 'window_proc',
            'contract': 'LRESULT(HWND,UINT,WPARAM,LPARAM); 4 Win64 register arguments'}],
        'imports': imports, 'symbols': symbols, 'sections': image.sections, 'relocations': image.relocations,
        'instructions': instructions, 'mnemonics': sorted({i['mnemonic'] for i in instructions}),
        'virtual_calls': virtual_calls, 'register_calls': register_calls, 'abi': layout,
        'guest_executions': 0, 'gpu_executions': 0, 'windows_executions': 0,
        'runtime_signature_ids_assigned': False}


def verify(out=OUT):
    out = Path(out).resolve(); e = json.loads((out / 'evidence.json').read_text())
    require(e['status'] == 'WINDOW_PE_PREPARED_NOT_EXECUTED', 'wrong evidence scope')
    require(e['guest_executions'] == e['gpu_executions'] == e['windows_executions'] == 0, 'unexpected execution claim')
    verify_shaders()
    deps = dependencies()
    require(deps == e['dependencies'], 'actual compiler dependencies changed')
    require(snapshot(inputs(deps)) == e['inputs_before'] == e['inputs_after'], 'build inputs changed')
    required = {'integer-tile.exe', 'integer-tile.obj', 'integer-tile.map', 'manifest.json',
                'disassembly.txt', 'headers.txt', 'compile.json', 'link.json', 'abi-layout.ll', 'abi-layout.json',
                'undefined-symbols.txt', 'dependencies.json', 'tool-provenance.json'}
    require(required <= set(e['artifacts']), 'required artifacts missing')
    require(all(Path(name).name == name for name in e['artifacts']), 'unsafe artifact name')
    require({name: sha(out / name) for name in e['artifacts']} == e['artifacts'], 'artifact changed')
    m = inspect(out)
    require(m == json.loads((out / 'manifest.json').read_text()), 'PE/header metadata differs')
    return {'status': 'WINDOW_PE_CURRENT_NOT_EXECUTED', 'pe_sha256': m['pe_sha256'],
            'imported_apis': len(m['imports']), 'static_instructions': len(m['instructions']),
            'static_virtual_call_sites': len(m['virtual_calls']), 'static_register_call_sites': len(m['register_calls']),
            'actual_header_source_dependencies': len(set(sum(deps.values(), []))),
            'guest_executions': 0, 'gpu_executions': 0, 'windows_executions': 0}


def build(out=OUT):
    out = Path(out).resolve()
    require(not (out / 'evidence.json').exists(), 'use a fresh output directory to preserve prior evidence')
    out.mkdir(parents=True, exist_ok=True)
    try:
        shader_proof = verify_shaders(); deps = dependencies(); before = snapshot(inputs(deps))
        (out / 'dependencies.json').write_text(json.dumps(deps, indent=2) + '\n')
        tools = {}
        for path in [LLVM / x for x in ('clang', 'llvm-dlltool', 'llvm-nm', 'llvm-objdump', 'llvm-readobj')] + [LINK]:
            # llvm-dlltool 17 has no --version: its usage and exit 1 are evidence,
            # not a version string and not an import-library build failure.
            version = subprocess.run([str(path), '--version'], text=True, capture_output=True)
            require(version.returncode == 0 or (path.name == 'llvm-dlltool' and version.returncode == 1
                    and version.stdout.startswith('OVERVIEW: llvm-dlltool')), 'tool identity query failed')
            tools[str(path)] = {'realpath': str(path.resolve()), 'sha256': sha(path),
                'version_query': {'returncode': version.returncode, 'stdout': version.stdout, 'stderr': version.stderr},
                'otool_dependencies': run(['/usr/bin/otool', '-L', path.resolve()])}
        (out / 'tool-provenance.json').write_text(json.dumps(tools, indent=2) + '\n')
        run([LLVM / 'clang', *FLAGS, '-S', '-emit-llvm', HERE / 'abi_layout.cpp', '-o', out / 'abi-layout.ll'], out / 'abi-compile.json')
        layout = {m[1]: int(m[2]) for m in re.finditer(r'^@(\w+) = .*constant i64 (\d+)', (out / 'abi-layout.ll').read_text(), re.M)}
        (out / 'abi-layout.json').write_text(json.dumps(layout, indent=2) + '\n')
        run([LLVM / 'clang', *FLAGS, '-c', HERE / 'fixture.cpp', '-o', out / 'integer-tile.obj'], out / 'compile.json')
        undefined = run([LLVM / 'llvm-nm', '--undefined-only', out / 'integer-tile.obj'])
        (out / 'undefined-symbols.txt').write_text(undefined)
        require({line.split()[-1] for line in undefined.splitlines()} == {'__imp_' + name for _, name in PARSE_PROFILE}, 'unexpected CRT/helper dependency')
        libraries = []
        for dll, names in APIS.items():
            definition = out / (dll + '.def'); library = out / (dll + '.lib')
            definition.write_text('LIBRARY ' + dll + '.dll\nEXPORTS\n' + ''.join('    ' + name + '\n' for name in names))
            run([LLVM / 'llvm-dlltool', '-m', 'i386:x86-64', '-d', definition, '-l', library], out / (dll + '-import.json'))
            libraries.append(library)
        run([LINK, '/entry:window_entry', '/subsystem:windows', '/nodefaultlib', '/machine:x64',
             '/base:' + hex(BASE), '/dynamicbase', '/nxcompat', '/fixed:no', '/timestamp:0',
             '/out:' + str(out / 'integer-tile.exe'), '/map:' + str(out / 'integer-tile.map'),
             out / 'integer-tile.obj', *libraries], out / 'link.json')
        (out / 'disassembly.txt').write_text(run([LLVM / 'llvm-objdump', '--disassemble', out / 'integer-tile.exe']))
        (out / 'headers.txt').write_text(run([LLVM / 'llvm-readobj', '--file-headers', '--sections', '--coff-imports', '--coff-basereloc', out / 'integer-tile.exe']))
        m = inspect(out); (out / 'manifest.json').write_text(json.dumps(m, indent=2) + '\n')
        after = snapshot(inputs(dependencies())); require(before == after, 'inputs changed during preparation')
        evidence = {'status': m['status'], 'inputs_before': before, 'inputs_after': after, 'dependencies': deps,
            'shader_proof': shader_proof, 'artifacts': {p.name: sha(p) for p in sorted(out.iterdir()) if p.is_file()},
            'guest_executions': 0, 'gpu_executions': 0, 'windows_executions': 0,
            'limits': ['No AOT lowering/runtime/window/input/file/GPU execution.',
                      'Header tarball is pinned by source URL/commit and SHA; no independent full Git-tree or signature proof.',
                      'Tool executable and known LLVM dylib hashes plus static otool dependency listings; no actual dyld trace or system cache hash.',
                      'Parser-only numeric labels are removed from manifest; no runtime signature assignment.']}
        (out / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
        return verify(out)
    except Exception as error:
        record = {'status': 'FAIL_PREPARATION_NOT_EXECUTED', 'error': str(error), 'guest_executions': 0, 'gpu_executions': 0, 'windows_executions': 0}
        (out / 'first-failure.json').write_text(json.dumps(record, indent=2) + '\n')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=OUT)
    parser.add_argument('--verify', action='store_true')
    options = parser.parse_args()
    print(json.dumps(verify(options.out) if options.verify else build(options.out), indent=2))
