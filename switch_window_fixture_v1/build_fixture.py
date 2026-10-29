"""Explicit-tool, source-to-PE window/switch fixture preparation. No execution."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import traceback

from callback_bridge.imports_v1 import load_imported_image
from switch_supported_fixture_v1.build_fixture import inspect_coff, instructions
from window_inc_v1.loader import SIGNATURES

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
BASE = 0x140000000
APIS = {
    'kernel32': ['CloseHandle', 'CreateFileA', 'ExitProcess', 'GetLastError',
                 'GetModuleHandleA', 'ReadFile', 'WriteFile'],
    'user32': ['AdjustWindowRectEx', 'CreateWindowExA', 'DefWindowProcA',
               'DestroyWindow', 'DispatchMessageA', 'GetClientRect', 'GetMessageA',
               'PostQuitMessage', 'RegisterClassExA', 'SetFocus', 'ShowWindow',
               'UnregisterClassA', 'ValidateRect'],
    'd3d11': ['D3D11CreateDeviceAndSwapChain'],
}
OBSERVATIONS = {'window_state': 20, 'window_result': 60, 'window_message': 48,
                'window_rectangle': 16, 'window_client': 16, 'window_swap_desc': 72,
                'window_feature': 4, 'window_handle': 8, 'window_instance': 8,
                'window_load_result': 36, 'window_load_candidate': 20,
                'window_load_extra': 1, 'window_load_count': 4,
                'window_load_extra_count': 4}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    Path(path).open('x').write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def make_flags(headers, dxheaders):
    return ['-target', 'x86_64-w64-windows-gnu', '-O2', '-std=c++17',
            '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-nostdinc++',
            '-fno-builtin', '-fno-stack-protector', '-mno-stack-arg-probe',
            '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
            '-fno-vectorize', '-fno-slp-vectorize', '-mno-sse', '-mno-sse2',
            '-mno-mmx', '-fno-jump-tables', '-fno-optimize-sibling-calls',
            '-fno-exceptions', '-fno-rtti', '-fno-lto',
            '-isystem', str(dxheaders), '-isystem', str(headers)]


def build(provider, linker, headers, dxheaders, out):
    provider, linker, headers, dxheaders, out = [Path(p).resolve() for p in
                                                (provider, linker, headers, dxheaders, out)]
    require(not os.path.lexists(out), 'fresh absent output directory required')
    area = ROOT / 'build/switch-window-fixture-v1'
    require(out != area and out.is_relative_to(area), 'new switch-window experiment output required')
    require(not out.is_relative_to(provider) and not provider.is_relative_to(out), 'provider/output overlap')
    out.mkdir(parents=True)
    records = []
    env = {k: os.environ[k] for k in ('HOME', 'TMPDIR') if k in os.environ}
    env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
    inputs = {}

    def run(label, args, expected=0):
        args = list(map(str, args))
        record = dict(argv=args, cwd=str(out), environment=env, started_at=now(), expected=expected)
        print('RUN ' + label, flush=True)
        write(out / (label + '.started.json'), record)
        try:
            with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
                process = subprocess.run(args, cwd=out, env=env, stdout=stdout, stderr=stderr, timeout=60)
            record['returncode'] = process.returncode
        except BaseException as error:
            record.update(returncode=None, error=repr(error))
            raise
        finally:
            record['finished_at'] = now()
            for kind in ('stdout', 'stderr'):
                p = out / (label + '.' + kind)
                if p.exists():
                    record[kind + '_path'] = str(p)
                    record[kind + '_sha256'] = sha(p)
            records.append(record)
            write(out / (label + '.result.json'), record)
        require(record['returncode'] == expected, 'tool failed: ' + label)
        return (out / (label + '.stdout')).read_text()

    try:
        descriptor = json.loads((provider / 'provider.json').read_bytes())
        require(descriptor.get('status') == 'CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED', 'CPU provider required')
        llvm = provider / descriptor['layout']['llvm']
        # Keep the llvm-dlltool alias path: llvm-ar selects its frontend by argv[0].
        tools = {name: llvm / 'bin' / name for name in ('clang', 'llvm-objdump', 'llvm-readobj', 'llvm-nm', 'llvm-dlltool')}
        require(all(p.is_file() for p in tools.values()) and linker.is_file(), 'explicit compiler tools missing')
        flags = make_flags(headers, dxheaders)
        leaf_flags = ['--target=x86_64-pc-windows-msvc', '-std=c11', '-O2', '-ffreestanding',
                      '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror']
        source = HERE / 'switch_tile.cpp'
        leaf = HERE / 'switch8.c'
        fixed = [Path(__file__), HERE / '__init__.py', source, leaf,
                 ROOT / 'switch_supported_fixture_v1/build_fixture.py',
                 ROOT / 'switch_supported_fixture_v1/switch8.c',
                 ROOT / 'window_bridge/fixture_v2.cpp', ROOT / 'window_inc_v1/loader.py',
                 ROOT / 'callback_bridge/imports_v1.py', ROOT / 'memory_stage2/image_loader.py',
                 provider / 'provider.json', linker, *tools.values()]
        require(leaf.read_bytes() == (ROOT / 'switch_supported_fixture_v1/switch8.c').read_bytes(), 'leaf source ancestry differs')
        inputs = {str(p.resolve()): sha(p) for p in fixed}
        for p in (source, leaf, Path(__file__)):
            shutil.copyfile(p, out / p.name)
        write(out / 'started.json', dict(status='FIXTURE_BUILD_STARTED_NOT_EXECUTED', inputs=inputs,
              provider=str(provider), provider_sha256=sha(provider / 'provider.json'), tools={k: str(v) for k, v in tools.items()},
              linker=str(linker), headers=str(headers), directx_headers=str(dxheaders),
              scope='Self-authored PE compiler input only. Existing explicit compiler/linker/headers; not a clean install or AOT/App execution.'))
        run('01-clang-version', [tools['clang'], '--version'])
        run('02-linker-version', [linker, '--version'])
        dependencies = run('03-window-dependencies', [tools['clang'], *flags, '-M', '-MT', 'inputs', source])
        require(dependencies.startswith('inputs:'), 'dependency syntax differs')
        paths = [Path(p).resolve() for p in shlex.split(dependencies.split(':', 1)[1].replace('\\\n', ' '))]
        require(headers / 'winuser.h' in paths and dxheaders / 'd3d11.h' in paths, 'real Windows/DirectX header missing')
        inputs.update({str(p): sha(p) for p in paths})
        write(out / 'dependencies.json', dict(paths=[str(p) for p in paths], sha256={str(p): sha(p) for p in paths}))
        run('04-window-compile', [tools['clang'], *flags, '-c', source, '-o', out / 'switch_tile.obj'])
        run('05-switch-compile', [tools['clang'], *leaf_flags, '-c', leaf, '-o', out / 'switch8.obj'])
        leaf_disassembly = run('06-switch-disassembly', [tools['llvm-objdump'], '--disassemble', '--reloc', '--x86-asm-syntax=intel', out / 'switch8.obj'])
        leaf_sections, leaf_rows = inspect_coff(out / 'switch8.obj', leaf_disassembly)
        run('07-switch-coff', [tools['llvm-readobj'], '--sections', '--symbols', '--relocations', out / 'switch8.obj'])
        run('08-window-coff', [tools['llvm-readobj'], '--sections', '--symbols', '--relocations', out / 'switch_tile.obj'])
        undefined = run('09-window-undefined', [tools['llvm-nm'], '--undefined-only', out / 'switch_tile.obj'])
        expected = {'__imp_' + name for names in APIS.values() for name in names} | {'switch8'}
        require({line.split()[-1] for line in undefined.splitlines()} == expected, 'unexpected CRT/helper or missing leaf call')
        libraries = []
        for index, (dll, names) in enumerate(APIS.items(), 10):
            definition, library = out / (dll + '.def'), out / (dll + '.lib')
            definition.write_text('LIBRARY ' + dll + '.dll\nEXPORTS\n' + ''.join('    ' + name + '\n' for name in names))
            run(str(index) + '-' + dll + '-import', [tools['llvm-dlltool'], '-m', 'i386:x86-64', '-d', definition, '-l', library])
            libraries.append(library)
        pe = out / 'switch_tile.exe'
        run('13-link', [linker, '/entry:window_entry', '/subsystem:windows', '/nodefaultlib', '/machine:x64',
            '/base:' + hex(BASE), '/dynamicbase', '/nxcompat', '/fixed:no', '/timestamp:0',
            '/out:' + str(pe), '/map:' + str(out / 'switch_tile.map'), out / 'switch_tile.obj', out / 'switch8.obj', *libraries])
        text = run('14-pe-disassembly', [tools['llvm-objdump'], '--disassemble', '--x86-asm-syntax=intel', pe])
        run('15-pe-metadata', [tools['llvm-readobj'], '--file-headers', '--sections', '--coff-imports', '--coff-basereloc', pe])
        symbols = {m[1]: int(m[2], 16) - BASE for line in (out / 'switch_tile.map').read_text().splitlines()
                   if (m := re.match(r'^\s+[0-9a-fA-F]{4}:[0-9a-fA-F]{8}\s+(\S+)\s+([0-9a-fA-F]{16})\b', line))}
        image = load_imported_image(pe, signatures=SIGNATURES)
        require(image.entry_rva == symbols['window_entry'], 'entry differs from actual symbol')
        require(sorted((x['dll'], x['name']) for x in image.imports) == sorted(SIGNATURES), 'import contract changed')
        rows = instructions(text)
        for row in rows:
            row['rva'] = row['address'] - BASE
            raw = bytes.fromhex(row['bytes'])
            require(image.read(row['address'], len(raw)) == raw, 'disassembly does not match actual PE')
        start = symbols['switch8']
        leaf_bytes = image.read(BASE + start, leaf_sections['.text']['size'])
        table = start + 16 + struct.unpack_from('<i', leaf_bytes, 12)[0]
        require(leaf_bytes[:12] == leaf_sections['.text']['bytes'][:12] and
                leaf_bytes[16:] == leaf_sections['.text']['bytes'][16:], 'linked leaf bytes changed outside LEA relocation')
        table_bytes = image.read(BASE + table, 32)
        changes = []
        for name, rva in (('.text', start), ('.rdata', table)):
            section = leaf_sections[name]
            expected_bytes = bytearray(section['bytes'])
            for rel in section['relocations']:
                target = {'.text': start, '.rdata': table}[rel['target_section']] + rel['target_value']
                linked = rel['addend'] + target - (rva + rel['offset'] + 4)
                require(-(1 << 31) <= linked < 1 << 31, 'REL32 overflow')
                struct.pack_into('<i', expected_bytes, rel['offset'], linked)
                changes.append(dict(section=name, site_rva=rva + rel['offset'], target_symbol_rva=target,
                                    addend=rel['addend'], linked_signed_value=linked))
            require(image.read(BASE + rva, section['size']) == expected_bytes, 'COFF relocation reconstruction differs')
        require(all(image.permissions[(table + i) // 4096] == 1 for i in range(32)), 'switch table is not exactly read-only')
        require(not any(rel['rva'] < table + 32 and rel['rva'] + 8 > table
                        for rel in image.relocations), 'DIR64 overlaps switch table')
        targets = [table + struct.unpack_from('<i', table_bytes, n)[0] for n in range(0, 32, 4)]
        leaf_boundaries = {start + r['address'] for r in leaf_rows}
        require(len(set(targets)) == 8 and set(targets) <= leaf_boundaries, 'linked switch targets differ')
        calls = []
        for row in rows:
            raw = bytes.fromhex(row['bytes'])
            if len(raw) == 5 and raw[0] == 0xe8 and row['rva'] + 5 + struct.unpack_from('<i', raw, 1)[0] == start:
                calls.append(row)
        require(len(calls) == 1 and symbols['window_proc'] <= calls[0]['rva'] < symbols['window_entry'],
                'leaf must have one actual direct call inside window_proc')
        seeds = [2, 3, 1, 0x20000000, 0, 5, 0, 7]
        reference = [((v + 7) if s == 0 else (v ^ 0x5a39c6e1) if s == 1 else
                      (v * 3) if s == 2 else ((v << 5) | (v >> 27)) if s == 3 else
                      (v - 11) if s == 4 else (v ^ 0x0a5197f3) if s == 5 else
                      (v + 0x319f) if s == 6 else ((v ^ 0x1379bdf1) + 1)) & 7
                     for s, v in enumerate(seeds)]
        require(reference == [1, 2, 3, 4, 5, 6, 7, 7], 'right-key mapping differs')
        profile = dict(schema=1, runtime_contract='win32-d3d11-tile-v1', pe_sha256=sha(pe),
                       callback_rvas=[symbols['window_proc']],
                       imports=[{'dll': dll, 'name': name} for dll, name in sorted(SIGNATURES)],
                       observations={name: {'rva': symbols[name], 'size': size} for name, size in OBSERVATIONS.items()},
                       save_observation='switch-tile.bin', resources='embedded-pe-only')
        write(out / 'profile-base-v1.json', profile)
        manifest = dict(status='WINDOW_SWITCH_PE_STATIC_INPUT_READY_NOT_AOT_NOT_EXECUTED', pe_sha256=sha(pe),
            entry_rva=image.entry_rva, callback_rvas=[symbols['window_proc']], symbols=symbols,
            imports=image.imports, sections=image.sections, relocations=image.relocations,
            instructions=rows, switch=dict(root_rva=start, code_size=len(leaf_bytes), table_rva=table,
                table_bytes=table_bytes.hex(), target_rvas=targets, coff_relocations_checked=changes,
                call_sites=calls, selector='window_state.position on WM_KEYDOWN/VK_RIGHT',
                source_value_seeds=seeds, expected_right_positions=reference,
                result_use='return & 7 drives window_state.position, rendering and save'),
            guest_executions=0, gpu_executions=0, windows_executions=0)
        write(out / 'manifest.json', manifest)
        require(all(sha(p) == digest for p, digest in inputs.items()), 'build inputs changed')
        result = dict(status=manifest['status'], inputs_before=inputs, inputs_after={p: sha(p) for p in inputs},
            dependencies=[str(p) for p in paths], commands=records,
            artifacts={p.name: sha(p) for p in out.iterdir() if p.is_file()},
            pe_sha256=sha(pe), switch_root_rva=start, switch_table_rva=table,
            callback_call_site_rva=calls[0]['rva'], source_mapping_reference=reference,
            guest_executions=0, gpu_executions=0, windows_executions=0,
            limitation='Compiler/PE static evidence only; no proof of runtime path execution or final profile/provider admission. Base v1 profile records existing ABI metadata, not permission to execute switches.')
        write(out / 'result.json', result)
        return result
    except BaseException as error:
        write(out / 'failure.json', dict(status='FIXTURE_PREPARATION_FAILED_NOT_EXECUTED', error=repr(error),
              traceback=traceback.format_exc(), commands=records, inputs_before=inputs,
              guest_executions=0, gpu_executions=0))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('provider', 'linker', 'headers', 'dxheaders', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = build(args.provider, args.linker, args.headers, args.dxheaders, args.out)
    print(json.dumps({k: v for k, v in result.items() if k not in ('commands', 'inputs_before', 'inputs_after', 'artifacts', 'dependencies')}, indent=2))
