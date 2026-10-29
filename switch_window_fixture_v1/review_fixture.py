"""Read raw fixture bytes and exercise old decoder rejection; never emit IR."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess

from portable_lifter_v1 import build as provider_tools
from window_inc_v1.loader import load_image
from switch_window_fixture_v1.build_fixture import ROOT, sha, write, require, now


def review(fixture, provider, out):
    fixture, provider, out = [Path(p).resolve() for p in (fixture, provider, out)]
    area = ROOT / 'build/switch-window-fixture-v1'
    require(out != area and out.is_relative_to(area) and not out.exists(), 'new review output required')
    out.mkdir(parents=True)
    build = json.loads((fixture / 'result.json').read_text())
    require(build['status'] == 'WINDOW_SWITCH_PE_STATIC_INPUT_READY_NOT_AOT_NOT_EXECUTED', 'fixture build not successful')
    for name, digest in build['artifacts'].items():
        require(Path(name).name == name and sha(fixture / name) == digest, 'fixture artifact changed: ' + name)
    manifest = json.loads((fixture / 'manifest.json').read_text())
    pe = fixture / 'switch_tile.exe'
    raw = pe.read_bytes()
    require(sha(pe) == manifest['pe_sha256'] == build['pe_sha256'], 'PE identities differ')
    # Parse file-backed raw ranges independently of the image loader.
    nt = struct.unpack_from('<I', raw, 0x3c)[0]
    require(raw[nt:nt + 4] == b'PE\0\0', 'PE signature differs')
    count, optional_size = struct.unpack_from('<H', raw, nt + 6)[0], struct.unpack_from('<H', raw, nt + 20)[0]
    optional = nt + 24
    base = struct.unpack_from('<Q', raw, optional + 24)[0]
    require(base == 0x140000000, 'fixture image base changed')
    sections = []
    for index in range(count):
        row = struct.unpack_from('<8sIIIIIIHHI', raw, optional + optional_size + index * 40)
        sections.append(dict(name=row[0].rstrip(b'\0').decode(), size=row[1], rva=row[2],
                             raw_size=row[3], offset=row[4], flags=row[9]))

    def read(rva, size, permission=None):
        matches = [s for s in sections if s['rva'] <= rva and
                   rva + size <= s['rva'] + min(s['size'], s['raw_size'])]
        require(len(matches) == 1, 'raw range not wholly file-backed')
        section = matches[0]
        if permission is not None:
            require(section['flags'] & 0xe0000000 == permission, 'raw section permissions differ')
        offset = section['offset'] + rva - section['rva']
        require(offset + size <= len(raw), 'raw range outside file')
        return raw[offset:offset + size]

    switch = manifest['switch']
    root, table = switch['root_rva'], switch['table_rva']
    leaf = read(root, 67, 0x60000000)
    require(root + 16 + struct.unpack_from('<i', leaf, 12)[0] == table, 'raw LEA does not point to table')
    table_bytes = read(table, 32, 0x40000000)
    require(table_bytes.hex() == switch['table_bytes'], 'raw table bytes differ')
    targets = [table + struct.unpack_from('<i', table_bytes, n)[0] for n in range(0, 32, 4)]
    require(targets == switch['target_rvas'] and len(set(targets)) == 8, 'raw rel32 targets differ')
    rows = {r['rva']: r for r in manifest['instructions']}
    require(all(t in rows and root < t < root + 67 for t in targets), 'target not leaf instruction boundary')
    image = load_image(raw)
    require(not any(rel['rva'] < table + 32 and rel['rva'] + 8 > table for rel in image.relocations), 'table/relocation overlap')
    start, end = manifest['symbols']['window_proc'], manifest['symbols']['window_entry']
    call = switch['call_sites'][0]['rva']
    require(read(call, 5)[0] == 0xe8 and call + 5 + struct.unpack_from('<i', read(call + 1, 4))[0] == root, 'raw call target differs')
    seen, pending = set(), [start]
    while pending:
        pc = pending.pop()
        if pc in seen:
            continue
        require(start <= pc < end and pc in rows, 'callback CFG leaves exact instruction boundary')
        seen.add(pc)
        code = bytes.fromhex(rows[pc]['bytes'])
        require(read(pc, len(code)) == code, 'callback row not raw PE bytes')
        next_pc = pc + len(code)
        if code == b'\xc3':
            continue
        if code[0] in (0xeb, 0xe9):
            pending.append(next_pc + int.from_bytes(code[1:], 'little', signed=True))
        elif 0x70 <= code[0] <= 0x7f or code[:1] == b'\x0f' and len(code) == 6 and 0x80 <= code[1] <= 0x8f:
            displacement = code[1:] if len(code) == 2 else code[2:]
            pending.extend((next_pc, next_pc + int.from_bytes(displacement, 'little', signed=True)))
        else:
            require(not (code[0] == 0xff and (code[1] >> 3) & 7 == 4), 'unexpected callback indirect JMP')
            pending.append(next_pc)
    require(call in seen, 'switch call unreachable in callback CFG')
    # Verify actual Win64 arguments and the raw seed array used by the call.
    argument_start = call - 12
    require(read(argument_start, 3) == b'\x48\x8d\x05', 'seed-array LEA differs')
    seeds_rva = argument_start + 7 + struct.unpack('<i', read(argument_start + 3, 4))[0]
    seeds = list(struct.unpack('<8I', read(seeds_rva, 32, 0x40000000)))
    require(seeds == [2, 3, 1, 0x20000000, 0, 5, 0, 7], 'actual seed bytes differ')
    require(read(call - 5, 5) == b'\x8b\x14\xb0\x89\xf1', 'actual EDX/ECX call arguments differ')
    require(read(targets[7], 8) == b'\x35\xf1\xbd\x79\x13\xff\xc0\xc3', 'actual case7 XOR/INC/RET differs')
    require(((seeds[7] ^ 0x1379bdf1) + 1) & 7 == 7, 'actual boundary7 result differs')
    # These raw instructions are the actual return-value consumer, not a C comment.
    require(read(call + 5, 3) == b'\x83\xe0\x07', 'return is not AND EAX,7')
    require(read(call + 8, 2) == b'\x39\xf0', 'return is not compared to old ESI position')
    conditional = call + 10
    require(read(conditional, 1) == b'\x74', 'unchanged-position branch missing')
    skip = conditional + 2 + struct.unpack('<b', read(conditional + 1, 1))[0]
    store = conditional + 2
    require(read(store, 2) == b'\x89\x05', 'new position is not stored from EAX')
    require(store + 6 + struct.unpack('<i', read(store + 2, 4))[0] == manifest['symbols']['window_state'] + 8,
            'return store does not address SampleState.position')
    require(read(store + 6, 2) == b'\xff\x05' and store + 12 + struct.unpack('<i', read(store + 8, 4))[0] == manifest['symbols']['window_state'] + 12,
            'move counter is not on changed-position path')
    require(read(skip, 2) == b'\x31\xc0' and skip < store, 'unchanged branch does not bypass stores')
    require(switch['expected_right_positions'] == [1, 2, 3, 4, 5, 6, 7, 7], 'source reference differs')

    descriptor, paths = provider_tools.paths_for(provider)
    provider_sha = sha(provider / 'provider.json')
    source_paths = [Path(__file__), ROOT / 'switch_window_fixture_v1/build_fixture.py',
                    ROOT / 'window_inc_v1/loader.py', ROOT / 'callback_bridge/imports_v1.py',
                    ROOT / 'memory_stage2/image_loader.py', ROOT / 'portable_lifter_v1/build.py',
                    provider / 'provider.json', paths['lifter'], paths['semantics']]
    inputs = {str(p.resolve()): sha(p) for p in source_paths}
    executable = next(s for s in image.sections if s['permissions'] & 4)
    text_start = executable['rva']
    code = bytes(image.data[text_start:text_start + executable['virtual_size']])
    (out / 'text.bin').write_bytes(code)
    env = {k: os.environ[k] for k in ('HOME', 'TMPDIR') if k in os.environ}
    env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C')
    argv = [str(paths['lifter']), '--os=windows', '--arch=amd64', '--address=' + str(image.base + text_start),
            '--entry_address=' + str(image.base + start), '--bytes=' + code.hex(),
            '--aot_semantics=' + str(paths['semantics'].resolve()), '--aot_vtable_mem64', '--aot_import_reg64', '--aot_inc_base32',
            '--aot_iat_slots=' + ','.join(str(image.base + row['iat_rva']) for row in image.imports),
            '--aot_manifest=' + str(out / 'must-not-exist.json'), '--aot_decode_only']
    record = dict(argv=argv, cwd=str(out), environment=env, started_at=now())
    write(out / 'decode.started.json', record)
    with (out / 'decode.stdout').open('xb') as stdout, (out / 'decode.stderr').open('xb') as stderr:
        process = subprocess.run(argv, cwd=out, env=env, stdout=stdout, stderr=stderr, timeout=60)
    reason = (out / 'decode.stderr').read_text()
    record.update(returncode=process.returncode, finished_at=now(),
                  stdout_sha256=sha(out / 'decode.stdout'), stderr_sha256=sha(out / 'decode.stderr'))
    write(out / 'decode.result.json', record)
    require(process.returncode == 1 and 'REJECT' in reason, 'old provider did not clearly reject')
    require(not (out / 'must-not-exist.json').exists(), 'old provider emitted accepted manifest')
    require(sha(provider / 'provider.json') == provider_sha, 'old provider metadata changed')
    require(all(sha(p) == digest for p, digest in inputs.items()), 'review input changed')
    result = dict(status='PASS_RAW_FIXTURE_FLOW_AND_OLD_DECODER_REJECTION_NOT_EXECUTED',
        fixture_result_sha256=sha(fixture / 'result.json'), pe_sha256=sha(pe), raw_sections=sections,
        switch_call_rva=call, switch_root_rva=root, switch_table_rva=table, switch_targets=targets,
        callback_reachable_instruction_boundaries=len(seen), position_store_rva=store,
        unchanged_position_skip_rva=skip, actual_imports=image.imports,
        seed_array_rva=seeds_rva, actual_seed_values=seeds,
        inputs_before=inputs, inputs_after={p: sha(p) for p in inputs},
        table_overlapping_relocations=[], provider_manifest_sha256=provider_sha,
        driver_sha256=sha(paths['lifter']), old_decoder_exit=process.returncode,
        old_decoder_reason=reason, command=record, guest_executions=0, gpu_executions=0,
        boundary_7='RIGHT invokes selector 7; result remains 7, JE bypasses position/moves/dirty writes. Extra guest steps are intentional; no step-count equivalence claim.',
        scope='Raw-byte flow/permissions/reference checks and actual old decode rejection only; no ARM/x86 function/App execution.')
    write(out / 'result.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'provider', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    result = review(**vars(parser.parse_args()))
    print(json.dumps({k: v for k, v in result.items() if k not in ('actual_imports', 'command', 'raw_sections', 'inputs_before', 'inputs_after')}, indent=2))
