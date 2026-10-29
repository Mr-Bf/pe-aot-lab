"""Second real compiler input, static COFF/PE evidence only; no guest execution."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import traceback

from memory_stage2.image_loader import load_image
from portable_lifter_v1 import tools
from switch_fixture_v1.build_fixture import sha, write
from switch_supported_fixture_v1.build_fixture import coff_sections, instructions, ALLOWED, PROVIDER_SHA

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parents[1] / 'work'
BASELINE = ROOT / 'build/switch-supported-fixture-v1/pe-02/switch8.exe'
BASELINE_SHA = 'c34e9d55cc9719fe3219a4f991ec4f53fca5583b5d026eb8cdc58aa26a12181c'


def require(value, message):
    if not value:
        raise ValueError(message)


def inspect_coff(obj, disassembly):
    sections = coff_sections(obj.read_bytes())
    require(set(sections) <= {'.text', '.rdata', '.data', '.bss', '.llvm_addrsig'} and
            {'.text', '.rdata'} <= set(sections), 'unexpected compiler COFF sections')
    text, table = sections['.text'], sections['.rdata']
    require(table['size'] == 32 and table['flags'] & 0xe0000000 == 0x40000000, 'eight read-only table entries required')
    require(len(text['relocations']) == 1 and len(table['relocations']) == 8, 'requires 1+8 actual COFF REL32 records')
    require(all(not item['size'] and not item['relocations'] for name,item in sections.items()
                if name not in ('.text', '.rdata')), 'extra initialized section or relocation')
    rows = instructions(disassembly)
    cursor = 0
    for row in rows:
        raw = bytes.fromhex(row['bytes'])
        require(row['mnemonic'] in ALLOWED and row['address'] == cursor and
                raw == text['bytes'][cursor:cursor + len(raw)], 'unsupported mnemonic or incomplete actual byte coverage')
        cursor += len(raw)
    require(cursor == text['size'], 'text coverage differs')
    candidates = [i for i,row in enumerate(rows) if row['mnemonic'] == 'jmp']
    require(len(candidates) == 1, 'expected one actual indirect JMP')
    jump = candidates[0]
    require(jump >= 6, 'dispatch has no complete unsigned guard')
    sequence = rows[jump - 6:jump + 1]
    require([r['mnemonic'] for r in sequence] == ['cmp','ja','mov','lea','movsxd','add','jmp'],
            'different compiler dispatch sequence')
    compare, branch, zero_extend, lea, load, add, indirect = sequence
    require(compare['operands'].endswith(', 0x7') and '[rip]' in lea['operands'] and
            'dword ptr' in load['operands'] and '4*' in load['operands'] and '[' not in indirect['operands'],
            'not the intended eight-case signed32 register-JMP shape')
    code_rel = text['relocations'][0]
    require(code_rel['target_section'] == '.rdata' and code_rel['target_value'] == 0 and
            lea['address'] < code_rel['offset'] and code_rel['offset'] + 4 == lea['address'] + len(bytes.fromhex(lea['bytes'])),
            'LEA does not contain the table relocation')
    require([r['offset'] for r in table['relocations']] == list(range(0,32,4)) and
            all(r['target_section'] == '.text' and r['target_value'] == 0 for r in table['relocations']), 'different table relocation closure')
    branch_bytes = bytes.fromhex(branch['bytes'])
    if len(branch_bytes) == 2 and branch_bytes[0] == 0x77:
        default = branch['address'] + 2 + struct.unpack_from('<b', branch_bytes, 1)[0]
    elif len(branch_bytes) == 6 and branch_bytes[:2] == b'\x0f\x87':
        default = branch['address'] + 6 + struct.unpack_from('<i', branch_bytes, 2)[0]
    else:
        raise ValueError('unexpected JA encoding')
    require(any(r['address'] == default and r['mnemonic'] == 'ret' for r in rows), 'default does not reach a RET boundary')
    return sections, rows, dict(guard_offset=compare['address'], guard_operands=compare['operands'],
        zero_extend_offset=zero_extend['address'], zero_extend_operands=zero_extend['operands'],
        lea_offset=lea['address'], lea_end=lea['address'] + len(bytes.fromhex(lea['bytes'])),
        lea_operands=lea['operands'], load_offset=load['address'], load_operands=load['operands'],
        add_offset=add['address'], add_operands=add['operands'], jump_offset=indirect['address'],
        jump_operands=indirect['operands'], jump_end=indirect['address'] + len(bytes.fromhex(indirect['bytes'])), default_offset=default)


def inspect_pe(path, sections, rows, shape, disassembly):
    image = load_image(path)
    by_name = {s['name']:s for s in image.sections}
    require(set(by_name) == {'.text','.rdata'} and not image.relocations, 'minimal PE section/base relocation set differs')
    require(image.entry_rva == by_name['.text']['rva'], 'variant is not actual PE entry')
    changes = []
    for name in ('.text','.rdata'):
        original, final = sections[name], by_name[name]
        require(final['virtual_size'] == original['size'], 'linked section logical size differs')
        expected = bytearray(original['bytes'])
        for rel in original['relocations']:
            source_rva = final['rva'] + rel['offset']
            target_rva = by_name[rel['target_section']]['rva'] + rel['target_value']
            result = rel['addend'] + target_rva - (source_rva + 4)
            require(-(1 << 31) <= result < 1 << 31, 'REL32 overflow')
            struct.pack_into('<i',expected,rel['offset'],result)
            changes.append(dict(source_section=name, source_rva=source_rva, target_symbol_rva=target_rva,
                                coff_addend=rel['addend'], linked_signed_value=result))
        require(image.read(image.base + final['rva'], original['size']) == expected, 'LLD output is not exact COFF+REL32 content')
    text, table = by_name['.text'], by_name['.rdata']
    require(text['permissions'] == 5 and table['permissions'] == 1 and table['virtual_size'] == 32, 'PE permissions/size differ')
    require(all(image.permissions[(table['rva'] + i)//4096] == 1 for i in range(32)), 'table pages not read-only')
    linked_rows = instructions(disassembly)
    require(len(linked_rows) == len(rows), 'PE/COFF instruction counts differ')
    for a,b in zip(linked_rows,rows):
        address = image.base + text['rva'] + b['address']
        require(a['address'] == address and a['mnemonic'] == b['mnemonic'] and len(a['bytes']) == len(b['bytes']) and
                bytes.fromhex(a['bytes']) == image.read(address,len(bytes.fromhex(a['bytes']))), 'PE disassembly byte/boundary mismatch')
    boundaries = {r['address'] - image.base for r in linked_rows}
    table_bytes = image.read(image.base + table['rva'],32)
    targets = [table['rva'] + struct.unpack_from('<i',table_bytes,i)[0] for i in range(0,32,4)]
    require(len(set(targets)) == 8 and all(t in boundaries and t >= text['rva'] + shape['jump_end'] for t in targets), 'targets do not identify distinct case boundaries')
    default_rva = text['rva'] + shape['default_offset']
    require(default_rva in boundaries, 'default not a PE instruction boundary')
    lea_field = sections['.text']['relocations'][0]['offset']
    lea_disp = struct.unpack_from('<i',image.data,text['rva'] + lea_field)[0]
    require(text['rva'] + shape['lea_end'] + lea_disp == table['rva'], 'linked LEA target differs')
    baseline = load_image(BASELINE)
    baseline_text = next(s for s in baseline.sections if s['name'] == '.text')
    actual_text = image.read(image.base + text['rva'],text['virtual_size'])
    old_text = baseline.read(baseline.base + baseline_text['rva'],baseline_text['virtual_size'])
    require(sha(path) != BASELINE_SHA and actual_text != old_text and shape['guard_offset'] != 2 and
            targets != [0x1019,0x101d,0x1023,0x1027,0x102b,0x102f,0x1035,0x103b], 'variant did not change PE/text/guard/targets')
    return dict(status='SECOND_STATIC_COMPILER_PE_SWITCH_INPUT_CONFIRMED_NOT_DECODER_ADMITTED',
        pe_sha256=sha(path), base=image.base, entry_rva=image.entry_rva, sections=image.sections,
        base_relocations=image.relocations, coff_relocations_checked=changes,
        table_rva=table['rva'], table_bytes=table_bytes.hex(), target_rvas=targets, default_rva=default_rva,
        shape=shape, instructions=linked_rows, baseline_pe_sha256=BASELINE_SHA,
        text_sha256=hashlib.sha256(actual_text).hexdigest(), baseline_text_sha256=hashlib.sha256(old_text).hexdigest(),
        current_decoder_admitted=False, decoder_executions=0, guest_executions=0)


def build(prefix, out, linker):
    prefix, out, linker = map(tools.real_path,(prefix,out,linker))
    require(not os.path.lexists(out) and out.is_relative_to(ROOT / 'build/switch-variant-fixture-v1') and
            out != ROOT / 'build/switch-variant-fixture-v1', 'new exclusive experiment output required')
    require(not out.is_relative_to(prefix) and not prefix.is_relative_to(out), 'provider/output overlap')
    out.mkdir(parents=True); records=[]
    try:
        provider_path = prefix / 'provider.json'
        require(sha(provider_path) == PROVIDER_SHA and sha(BASELINE) == BASELINE_SHA, 'fixed input provider/baseline differs')
        provider = json.loads(provider_path.read_bytes())
        llvm = prefix / provider['layout']['llvm']
        selected = {name:(llvm/'bin'/name).resolve(strict=True) for name in ('clang','llvm-objdump','llvm-readobj')}
        graph = tools.selected_closure(prefix,list(selected.values()))
        preparation = ROOT/'build/file-bridge/tools/preparation.json'; old = json.loads(preparation.read_bytes())
        require(str(linker) == old['isolated_linker'] and sha(linker) == old['isolated_linker_sha256'], 'existing linker differs')
        legacy_paths = [linker,(WORK/'remill-stage2/llvm@17/17.0.6/lib/libLLVM.dylib').resolve(strict=True),Path(old['zstd_realpath']).resolve(strict=True)]
        legacy = {str(p):dict(**tools.macho(p),sha256=sha(p)) for p in legacy_paths}
        for node in legacy.values():
            for dep in node['dependencies']:
                require(tools.system_image(dep) or (dep.startswith('/') and str(Path(dep).resolve(strict=True)) in legacy), 'unrecorded linker dependency')
        source = Path(__file__).with_name('switch8_variant.c')
        sources = [source,Path(__file__),BASELINE,ROOT/'switch_supported_fixture_v1/build_fixture.py',
                   ROOT/'switch_fixture_v1/build_fixture.py',ROOT/'portable_lifter_v1/tools.py',
                   ROOT/'memory_stage2/image_loader.py',provider_path,preparation]
        inputs = {str(p.resolve()):sha(p) for p in sources}
        inputs.update({p:n['sha256'] for p,n in graph['nodes'].items()}); inputs.update({p:n['sha256'] for p,n in legacy.items()})
        for p in (source,Path(__file__)): shutil.copyfile(p,out/p.name)
        write(out/'started.json',dict(inputs=inputs,selected={k:str(v) for k,v in selected.items()},selected_graph=graph,
              linker=str(linker),existing_linker_graph=legacy,provider_sha256=PROVIDER_SHA,
              scope='Second real C/COFF/PE static input; explicit existing local LLD; no decoder/guest/App/GPU execution.'))
        env = {k:os.environ[k] for k in ('HOME','TMPDIR') if k in os.environ}
        env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin',LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')

        def run(label,args):
            row=dict(argv=list(map(str,args)),cwd=str(out),env=env,started_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            write(out/(label+'.started.json'),row);print('RUN '+label,flush=True)
            try:
                with (out/(label+'.stdout')).open('xb') as stdout,(out/(label+'.stderr')).open('xb') as stderr:
                    process=subprocess.run(row['argv'],cwd=out,env=env,stdout=stdout,stderr=stderr,timeout=60)
                row['returncode']=process.returncode
            except BaseException as error:
                row.update(returncode=None,error_type=type(error).__name__,error=str(error));raise
            finally:
                row['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
                for suffix in ('stdout','stderr'):
                    path=out/(label+'.'+suffix)
                    if path.exists():row[suffix]=dict(path=str(path),sha256=sha(path))
                write(out/(label+'.result.json'),row);records.append(row)
            require(row['returncode']==0,'tool failure: '+label)

        obj,pe=out/'switch8_variant.obj',out/'switch8_variant.exe'
        run('01-clang-version',[selected['clang'],'--version'])
        run('02-compile',[selected['clang'],'--target=x86_64-pc-windows-msvc','-std=c11','-O2','-ffreestanding',
            '-fno-stack-protector','-fno-asynchronous-unwind-tables','-Wall','-Wextra','-Werror','-c',out/source.name,'-o',obj])
        run('03-coff-disassembly',[selected['llvm-objdump'],'--disassemble','--reloc','--x86-asm-syntax=intel',obj])
        run('04-coff-metadata',[selected['llvm-readobj'],'--file-headers','--sections','--symbols','--relocations',obj])
        run('05-coff-bytes',[selected['llvm-objdump'],'--full-contents',obj])
        sections,rows,shape=inspect_coff(obj,(out/'03-coff-disassembly.stdout').read_text())
        write(out/'coff-shape.json',dict(status='SECOND_COFF_SHAPE_CONFIRMED_NOT_PE_NOT_DECODER_ADMITTED',coff_sha256=sha(obj),
              instructions=rows,shape=shape,sections={k:{a:b for a,b in v.items() if a!='bytes'} for k,v in sections.items()}))
        run('06-linker-version',[linker,'--version'])
        run('07-link',[linker,'/entry:switch8_variant','/subsystem:console','/nodefaultlib','/machine:x64',
             '/base:0x140000000','/fixed','/dynamicbase:no','/nxcompat','/timestamp:0','/out:'+str(pe),obj])
        run('08-pe-disassembly',[selected['llvm-objdump'],'--disassemble','--x86-asm-syntax=intel',pe])
        run('09-pe-metadata',[selected['llvm-readobj'],'--file-headers','--sections','--coff-imports','--coff-basereloc',pe])
        run('10-pe-bytes',[selected['llvm-objdump'],'--full-contents',pe])
        write(out/'pe-shape.json',inspect_pe(pe,sections,rows,shape,(out/'08-pe-disassembly.stdout').read_text()))
        require(all(sha(Path(p))==h for p,h in inputs.items()) and sha(out/source.name)==inputs[str(source.resolve())], 'inputs changed')
        result=dict(status='SECOND_CLANG_COFF_LLD_PE_STATIC_SWITCH_INPUT_READY_NOT_AOT_NOT_EXECUTED',
            inputs_before=inputs,inputs_after={p:sha(Path(p)) for p in inputs},coff_sha256=sha(obj),pe_sha256=sha(pe),
            pe_shape_sha256=sha(out/'pe-shape.json'),commands=records,decoder_executions=0,guest_executions=0,
            app_executions=0,gpu_executions=0,artifacts={p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file()})
        write(out/'result.json',result);return result
    except BaseException as error:
        write(out/'failure.json',dict(error_type=type(error).__name__,error=str(error),traceback=traceback.format_exc(),commands=records));raise


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--prefix',required=True);parser.add_argument('--out',required=True);parser.add_argument('--linker',required=True)
    args=parser.parse_args();print(build(args.prefix,args.out,args.linker)['status'])
