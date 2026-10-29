"""One bounded C -> COFF -> PE input experiment; never executes guest code."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import traceback

from memory_stage2.image_loader import load_image
from portable_lifter_v1 import tools
from switch_fixture_v1.build_fixture import sha, write

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parents[1] / 'work'
PROVIDER_SHA = 'b9219c1305711dd8d96efeb03c488761de9c57b75827fd23aa2bbaf21b16b237'
ALLOWED = {'mov', 'cmp', 'ja', 'lea', 'movsxd', 'add', 'sub', 'jmp', 'xor', 'rol', 'inc', 'ret', 'nop'}


def require(value, message):
    if not value:
        raise ValueError(message)


def coff_sections(data):
    require(20 <= len(data) <= 65536, 'bounded COFF input required')
    machine, count, _, symbols, symbol_count, optional, _ = struct.unpack_from('<HHIIIHH', data)
    require(machine == 0x8664 and optional == 0 and 1 <= count <= 8, 'AMD64 object required')
    require(20 + count * 40 <= len(data) and symbols + symbol_count * 18 <= len(data), 'COFF tables truncated')
    strings_at = symbols + symbol_count * 18
    require(strings_at + 4 <= len(data), 'COFF string-table header truncated')
    strings_size = struct.unpack_from('<I', data, strings_at)[0]
    require(4 <= strings_size <= len(data) - strings_at, 'COFF string-table bounds')
    strings = data[strings_at:strings_at + strings_size]
    sections = {}
    numbered = {}
    for index in range(count):
        row = struct.unpack_from('<8sIIIIIIHHI', data, 20 + index * 40)
        name = row[0].rstrip(b'\0').decode('ascii')
        if name.startswith('/'):
            require(name[1:].isdecimal(), 'invalid COFF long section name')
            offset = int(name[1:])
            require(4 <= offset < strings_size and b'\0' in strings[offset:], 'COFF section-name offset out of bounds')
            name = strings[offset:].split(b'\0', 1)[0].decode('ascii')
        size, start, reloc, nrel, flags = row[3], row[4], row[5], row[7], row[9]
        require(name not in sections and start + size <= len(data) and reloc + nrel * 10 <= len(data), 'COFF section bounds')
        item = dict(number=index + 1, size=size, start=start, flags=flags, bytes=data[start:start + size], relocations=[])
        sections[name] = item; numbered[index + 1] = name
        for offset in range(nrel):
            site, symbol, kind = struct.unpack_from('<IIH', data, reloc + offset * 10)
            require(site + 4 <= size and symbol < symbol_count and kind == 4, 'only bounded COFF REL32 supported by inspector')
            _, value, section, _, _, _ = struct.unpack_from('<8sIhHBB', data, symbols + symbol * 18)
            item['relocations'].append(dict(offset=site, symbol_index=symbol, target_section_number=section,
                                            target_value=value, type=kind,
                                            addend=struct.unpack_from('<i', item['bytes'], site)[0]))
    for item in sections.values():
        for relocation in item['relocations']:
            require(relocation['target_section_number'] in numbered, 'external relocation unsupported')
            relocation['target_section'] = numbered[relocation['target_section_number']]
    return sections


def instructions(text):
    rows = []
    for line in text.splitlines():
        match = re.fullmatch(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*([a-z][a-z0-9]*)\s*(.*)', line)
        if match:
            address, raw, name, operands = match.groups()
            rows.append(dict(address=int(address, 16), bytes=bytes.fromhex(raw).hex(), mnemonic=name,
                             operands=operands.split('#', 1)[0].strip()))
    require(rows, 'actual disassembly has no instruction rows')
    return rows


def inspect_coff(obj, disassembly):
    sections = coff_sections(obj.read_bytes())
    require(set(sections) <= {'.text', '.rdata', '.data', '.bss', '.llvm_addrsig'}, 'unexpected COFF section')
    require('.text' in sections and '.rdata' in sections, 'missing text/table section')
    text, table = sections['.text'], sections['.rdata']
    require(table['size'] == 32 and table['flags'] & 0xe0000000 == 0x40000000, 'eight read-only rel32 entries required')
    require(len(text['relocations']) == 1 and len(table['relocations']) == 8, 'expected 1+8 COFF relocations')
    require(all(not item['size'] and not item['relocations'] for name, item in sections.items()
                if name not in ('.text', '.rdata')), 'fixture contains extra initialized data/relocations')
    rows = instructions(disassembly)
    require(rows[0]['address'] == 0 and all(row['mnemonic'] in ALLOWED for row in rows), 'new iclass outside intended scalar names')
    cursor = 0
    for row in rows:
        raw = bytes.fromhex(row['bytes'])
        require(row['address'] == cursor and raw == text['bytes'][cursor:cursor + len(raw)], 'COFF disassembly does not cover exact bytes')
        cursor += len(raw)
    require(cursor == text['size'], 'COFF text not fully covered')
    # This is an observed compiler-fixture shape check, not a general decoder.
    expected = [(0, 'mov', 'eax, edx'), (2, 'cmp', 'ecx, 0x7'), (5, 'ja', None),
                (7, 'mov', 'ecx, ecx'), (9, 'lea', 'rdx, [rip]'),
                (16, 'movsxd', 'rcx, dword ptr [rdx + 4*rcx]'), (20, 'add', 'rcx, rdx'), (23, 'jmp', 'rcx')]
    require(len(rows) > len(expected), 'missing switch cases')
    for row, (address, name, operands) in zip(rows, expected):
        require(row['address'] == address and row['mnemonic'] == name and
                (operands is None or row['operands'] == operands), 'compiler produced a different dispatch shape')
    require(text['relocations'][0]['offset'] == 12 and text['relocations'][0]['target_section'] == '.rdata' and
            text['relocations'][0]['target_value'] == 0, 'LEA relocation is not table base')
    require([r['offset'] for r in table['relocations']] == list(range(0, 32, 4)) and
            all(r['target_section'] == '.text' and r['target_value'] == 0 for r in table['relocations']), 'table relocations differ')
    return sections, rows


def inspect_pe(path, sections, coff_rows, disassembly):
    image = load_image(path)
    by_name = {s['name']: s for s in image.sections}
    require(set(by_name) == {'.text', '.rdata'} and not image.relocations, 'minimal PE section/base-relocation set differs')
    require(image.entry_rva == by_name['.text']['rva'], 'PE entry is not switch8 at text start')
    changes = []
    for name in ('.text', '.rdata'):
        original, final = sections[name], by_name[name]
        require(final['virtual_size'] == original['size'], 'linked section logical size differs')
        expected = bytearray(original['bytes'])
        for rel in original['relocations']:
            source_rva = final['rva'] + rel['offset']
            target_rva = by_name[rel['target_section']]['rva'] + rel['target_value']
            result = rel['addend'] + target_rva - (source_rva + 4)
            require(-(1 << 31) <= result < 1 << 31, 'linked REL32 overflow')
            struct.pack_into('<i', expected, rel['offset'], result)
            changes.append(dict(source_section=name, source_rva=source_rva, target_symbol_rva=target_rva,
                                coff_addend=rel['addend'], linked_signed_value=result, coff_relocation_type='IMAGE_REL_AMD64_REL32'))
        actual = image.read(image.base + final['rva'], original['size'])
        require(actual == expected, 'LLD output differs from all and only actual COFF relocations')
    text, table = by_name['.text'], by_name['.rdata']
    require(text['permissions'] == 5 and table['permissions'] == 1 and table['virtual_size'] == 32, 'PE section permissions differ')
    require(all(image.permissions[(table['rva'] + i) // 4096] == 1 for i in range(32)), 'table pages not read-only')
    rows = instructions(disassembly)
    require(len(rows) == len(coff_rows), 'PE instruction count differs')
    for a, b in zip(rows, coff_rows):
        require(a['address'] == image.base + text['rva'] + b['address'] and a['mnemonic'] == b['mnemonic'] and
                len(a['bytes']) == len(b['bytes']), 'PE instruction boundaries/mnemonics differ')
    boundaries = {row['address'] - image.base for row in rows}
    table_bytes = image.read(image.base + table['rva'], 32)
    targets = [table['rva'] + struct.unpack_from('<i', table_bytes, offset)[0] for offset in range(0, 32, 4)]
    require(len(set(targets)) == 8 and all(target in boundaries and target >= text['rva'] + 25 for target in targets), 'case targets not distinct case boundaries')
    default_rva = text['rva'] + 7 + struct.unpack_from('<b', sections['.text']['bytes'], 6)[0]
    require(default_rva in boundaries and rows[-1]['address'] - image.base == default_rva and rows[-1]['mnemonic'] == 'ret', 'default is not final RET')
    lea_displacement = struct.unpack_from('<i', image.data, text['rva'] + 12)[0]
    require(text['rva'] + 16 + lea_displacement == table['rva'], 'linked LEA does not address table start')
    return dict(status='STATIC_COMPILER_PE_RELOCATION_AND_SWITCH_SHAPE_CONFIRMED_NOT_DECODER_ADMITTED',
                pe_sha256=sha(path), base=image.base, entry_rva=image.entry_rva, sections=image.sections,
                base_relocations=image.relocations, coff_relocations_checked=changes,
                table_rva=table['rva'], table_bytes=table_bytes.hex(), target_rvas=targets, default_rva=default_rva,
                instructions=rows, current_decoder_admitted=False, guest_executions=0)


def build(prefix, out, linker):
    prefix, out, linker = map(tools.real_path, (prefix, out, linker))
    require(not os.path.lexists(out), 'fresh absent output required')
    require(out.is_relative_to(ROOT / 'build/switch-supported-fixture-v1') and out != ROOT / 'build/switch-supported-fixture-v1', 'output outside new experiment root')
    require(not out.is_relative_to(prefix) and not prefix.is_relative_to(out), 'provider/output overlap')
    out.mkdir(parents=True)
    records = []
    try:
        provider_path = prefix / 'provider.json'
        require(sha(provider_path) == PROVIDER_SHA, 'requires accepted fresh-03 CPU provider')
        provider = json.loads(provider_path.read_bytes())
        llvm = prefix / provider['layout']['llvm']
        selected = {name: (llvm / 'bin' / name).resolve(strict=True) for name in ('clang', 'llvm-objdump', 'llvm-readobj')}
        graph = tools.selected_closure(prefix, list(selected.values()))
        preparation = ROOT / 'build/file-bridge/tools/preparation.json'
        old = json.loads(preparation.read_bytes())
        require(str(linker) == old['isolated_linker'] and sha(linker) == old['isolated_linker_sha256'], 'existing linker identity differs')
        legacy_paths = [linker, (WORK / 'remill-stage2/llvm@17/17.0.6/lib/libLLVM.dylib').resolve(strict=True),
                        Path(old['zstd_realpath']).resolve(strict=True)]
        legacy = {str(p): dict(**tools.macho(p), sha256=sha(p)) for p in legacy_paths}
        for node in legacy.values():
            for dep in node['dependencies']:
                require(tools.system_image(dep) or (dep.startswith('/') and str(Path(dep).resolve(strict=True)) in legacy),
                        'unrecorded existing linker dependency')
        source = Path(__file__).with_name('switch8.c')
        sources = [source, Path(__file__), ROOT / 'switch_fixture_v1/build_fixture.py', ROOT / 'portable_lifter_v1/tools.py',
                   ROOT / 'memory_stage2/image_loader.py', provider_path, preparation]
        inputs = {str(p.resolve()): sha(p) for p in sources}
        inputs.update({p: n['sha256'] for p, n in graph['nodes'].items()})
        inputs.update({p: n['sha256'] for p, n in legacy.items()})
        for p in (source, Path(__file__)):
            shutil.copyfile(p, out / p.name)
        write(out / 'started.json', dict(inputs=inputs, selected={k:str(v) for k,v in selected.items()}, selected_graph=graph,
              linker=str(linker), existing_linker_graph=legacy, provider_sha256=PROVIDER_SHA,
              scope='Fresh compiler input; existing local LLD, not a clean-install or production AOT claim. No guest/native-App execution.'))
        env = {k: os.environ[k] for k in ('HOME', 'TMPDIR') if k in os.environ}
        env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')

        def run(label, args):
            row = dict(argv=list(map(str, args)), cwd=str(out), env=env,
                       started_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            write(out / (label + '.started.json'), row)
            print('RUN ' + label, flush=True)
            try:
                with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
                    result = subprocess.run(row['argv'], cwd=out, env=env, stdout=stdout, stderr=stderr, timeout=60)
                row['returncode'] = result.returncode
            except BaseException as error:
                row.update(returncode=None, error_type=type(error).__name__, error=str(error)); raise
            finally:
                row['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                for suffix in ('stdout', 'stderr'):
                    path = out / (label + '.' + suffix)
                    if path.exists(): row[suffix] = dict(path=str(path), sha256=sha(path))
                write(out / (label + '.result.json'), row); records.append(row)
            require(row['returncode'] == 0, 'tool failure: ' + label)

        obj, pe = out / 'switch8.obj', out / 'switch8.exe'
        run('01-clang-version', [selected['clang'], '--version'])
        run('02-compile', [selected['clang'], '--target=x86_64-pc-windows-msvc', '-std=c11', '-O2', '-ffreestanding',
            '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror', '-c', out / 'switch8.c', '-o', obj])
        run('03-coff-disassembly', [selected['llvm-objdump'], '--disassemble', '--reloc', '--x86-asm-syntax=intel', obj])
        run('04-coff-metadata', [selected['llvm-readobj'], '--file-headers', '--sections', '--symbols', '--relocations', obj])
        run('05-coff-bytes', [selected['llvm-objdump'], '--full-contents', obj])
        sections, rows = inspect_coff(obj, (out / '03-coff-disassembly.stdout').read_text())
        write(out / 'coff-shape.json', dict(status='COFF_SHAPE_CONFIRMED_NOT_PE_NOT_DECODER_ADMITTED', coff_sha256=sha(obj),
              instructions=rows, sections={k:{a:b for a,b in v.items() if a != 'bytes'} for k,v in sections.items()}))
        run('06-linker-version', [linker, '--version'])
        run('07-link', [linker, '/entry:switch8', '/subsystem:console', '/nodefaultlib', '/machine:x64',
             '/base:0x140000000', '/fixed', '/dynamicbase:no', '/nxcompat', '/timestamp:0', '/out:' + str(pe), obj])
        run('08-pe-disassembly', [selected['llvm-objdump'], '--disassemble', '--x86-asm-syntax=intel', pe])
        run('09-pe-metadata', [selected['llvm-readobj'], '--file-headers', '--sections', '--coff-imports', '--coff-basereloc', pe])
        run('10-pe-bytes', [selected['llvm-objdump'], '--full-contents', pe])
        evidence = inspect_pe(pe, sections, rows, (out / '08-pe-disassembly.stdout').read_text())
        write(out / 'pe-shape.json', evidence)
        require(all(sha(Path(p)) == h for p,h in inputs.items()) and sha(out / 'switch8.c') == inputs[str(source.resolve())], 'inputs changed')
        result = dict(status='CLANG_COFF_LLD_PE_STATIC_SWITCH_INPUT_READY_NOT_AOT_NOT_EXECUTED', inputs_before=inputs,
                      inputs_after={p:sha(Path(p)) for p in inputs}, coff_sha256=sha(obj), pe_sha256=sha(pe),
                      pe_shape_sha256=sha(out / 'pe-shape.json'), commands=records,
                      guest_executions=0, app_executions=0, gpu_executions=0, decoder_executions=0,
                      artifacts={p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file()})
        write(out / 'result.json', result)
        return result
    except BaseException as error:
        write(out / 'failure.json', dict(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc(), commands=records))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True); parser.add_argument('--out', required=True); parser.add_argument('--linker', required=True)
    args = parser.parse_args()
    print(build(args.prefix, args.out, args.linker)['status'])
