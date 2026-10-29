"""Independent read-only verifier for offline v6 installation and recovery.

No installer success validator, builder, subprocess or App is invoked. Mature
metadata loaders are used as additional checks, alongside original receipts,
source/patch replay, file digests and stage relationships. Only a new requested
JSON report is written.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
from types import SimpleNamespace

from portable_lifter_v1 import build as cpu, deps, tools
from portable_graphics_v2 import cache as graphics_cache
from portable_graphics_v1 import build as graphics
from window_switch_v1 import provider as overlay, profile, admission, lift, headers, package, producer
from window_app_v1.noarg import spec

ROOT = Path(__file__).resolve().parents[1]
STAGES = ('cpu-build', 'switch-build', 'graphics-build', 'app-build', 'app-verify')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: need(False, 'nonfinite JSON: ' + value))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Audit:
    def __init__(self):
        self.files = {}
        self.links = {}

    def sha(self, value, expected=None):
        path = Path(value).absolute()
        # Metadata loaders independently constrain where provider links resolve.
        current = path
        while current != current.parent:
            if current.is_symlink():
                target = os.readlink(current)
                need(str(current) not in self.links or self.links[str(current)] == target,
                     'symlink changed during review: ' + str(current))
                self.links[str(current)] = target
            current = current.parent
        path = path.resolve(strict=True)
        info = path.stat()
        need(stat.S_ISREG(info.st_mode), 'regular file required: ' + str(path))
        if str(path) in self.files:
            actual = self.files[str(path)]['sha256']
        else:
            with path.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            after = path.stat()
            need((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                 'file changed while hashing: ' + str(path))
            self.files[str(path)] = dict(sha256=actual, bytes=info.st_size,
                                         mode=stat.S_IMODE(info.st_mode))
        need(expected is None or actual == expected, 'SHA differs: ' + str(path))
        return actual

    def read(self, path, expected=None):
        actual = self.sha(path, expected)
        raw = Path(path).read_bytes()
        need(digest(raw) == actual, 'file changed while reading: ' + str(path))
        return raw

    def json(self, path, expected=None):
        target=Path(path).absolute()
        need(target==target.resolve() and not target.is_symlink(), 'aliased JSON/control receipt: '+str(path))
        return decode(self.read(path, expected))

    def identities(self, values):
        need(type(values) is dict and bool(values), 'nonempty input identity map required')
        for name, expected in values.items():
            self.sha(name, expected)

    def relative_identities(self, values, root=ROOT):
        need(type(values) is dict and bool(values), 'nonempty relative identity map required')
        for name, expected in values.items():
            relative = PurePosixPath(name)
            need(not relative.is_absolute() and '..' not in relative.parts, 'unsafe relative source path')
            self.sha(root / name, expected)

    def tree(self, root, *, modes=True, links=False, exclude=()):
        root = Path(root).absolute()
        need(root == root.resolve(strict=True) and root.is_dir(), 'canonical tree root required')
        result = {}
        for path in sorted(root.rglob('*')):
            relative = path.relative_to(root).as_posix()
            if relative in exclude:
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                need(links, 'artifact contains symlink: ' + str(path))
                self.links[str(path)] = os.readlink(path)
                result[relative] = {'symlink': self.links[str(path)]}
            elif stat.S_ISREG(mode):
                result[relative] = {'sha256': self.sha(path)}
                if modes:
                    result[relative]['mode'] = stat.S_IMODE(mode)
            else:
                need(stat.S_ISDIR(mode), 'special tree member: ' + str(path))
        return result

    def finish(self):
        for name, expected in self.links.items():
            need(Path(name).is_symlink() and os.readlink(name) == expected, 'review link changed: ' + name)
        for name, expected in self.files.items():
            path = Path(name)
            with path.open('rb') as stream:
                actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            need(actual == expected['sha256'] and path.stat().st_size == expected['bytes'] and
                 stat.S_IMODE(path.stat().st_mode) == expected['mode'], 'review input changed: ' + name)


def replay_patch(files, raw):
    """Apply exact unified text hunks in memory; no patch tool or disk writes."""
    lines = raw.decode().splitlines(keepends=True)
    at = 0
    result = dict(files)
    while at < len(lines):
        if not lines[at].startswith('--- '):
            need(not lines[at].startswith('@@'), 'hunk without file header')
            at += 1
            continue
        old_name = lines[at][4:].split('\t')[0].strip(); at += 1
        need(at < len(lines) and lines[at].startswith('+++ '), 'missing new patch path')
        new_name = lines[at][4:].split('\t')[0].strip(); at += 1
        need(old_name.startswith('a/') and new_name.startswith('b/') and old_name[2:] == new_name[2:],
             'unsupported patch rename/create/delete')
        name = old_name[2:]
        need(name in result, 'patch file absent: ' + name)
        original = result[name].decode().splitlines(keepends=True)
        out, cursor = [], 0
        while at < len(lines) and lines[at].startswith('@@ '):
            match = re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n?', lines[at])
            need(match is not None, 'invalid unified hunk')
            start = int(match[1]) - 1
            old_count, new_count = int(match[2] or 1), int(match[4] or 1)
            need(cursor <= start <= len(original), 'overlapping/outside patch hunk')
            out.extend(original[cursor:start]); cursor = start; at += 1
            consumed = produced = 0
            while at < len(lines) and not lines[at].startswith(('@@ ', '--- ')):
                line = lines[at]
                need(line and line[0] in ' +-', 'unsupported patch line')
                if line[0] in ' -':
                    need(cursor < len(original) and original[cursor] == line[1:], 'inexact patch context')
                    cursor += 1; consumed += 1
                if line[0] in ' +':
                    out.append(line[1:]); produced += 1
                at += 1
            need((consumed, produced) == (old_count, new_count), 'patch hunk counts differ')
        out.extend(original[cursor:]); result[name] = ''.join(out).encode()
    return result


def verify_commands(audit, commands):
    need(type(commands) is list and bool(commands), 'actual build commands required')
    for row in commands:
        need(type(row) is dict and type(row.get('argv')) is list and bool(row['argv']) and
             all(type(arg) is str for arg in row['argv']), 'invalid command argv')
        expected = row.get('expected', 0)
        need(type(expected) is int and type(row.get('returncode')) is int and row['returncode'] == expected and
             row.get('launch_error') is None, 'build command did not succeed as expected')
        for stream in ('stdout', 'stderr'):
            audit.sha(row[stream + '_path'], row[stream + '_sha256'])


def exports(audit, path):
    """Read thin ARM64 external definitions without invoking nm or loading code."""
    raw=audit.read(path)
    need(len(raw)>=32, 'short Mach-O symbol input')
    magic,cpu_type,_,_,count,size,_,_=struct.unpack_from('<8I',raw)
    need(magic==0xfeedfacf and cpu_type==0x100000c and 0<count<=4096 and 32+size<=len(raw),
         'invalid thin ARM64 symbol header')
    position,table=32,None
    for _ in range(count):
        need(position+8<=32+size,'short Mach-O symbol command')
        command,length=struct.unpack_from('<II',raw,position)
        need(length>=8 and position+length<=32+size,'invalid Mach-O command size')
        if command==2:
            need(length==24 and table is None,'invalid/duplicate LC_SYMTAB')
            table=struct.unpack_from('<4I',raw,position+8)
        position+=length
    need(position==32+size and table is not None,'symbol table absent')
    offset,nsyms,strings,string_size=table
    need(nsyms<=1000000 and offset+nsyms*16<=len(raw) and strings+string_size<=len(raw),
         'symbol/string table outside file')
    names=[]
    for n in range(nsyms):
        index,kind,_,_,_=struct.unpack_from('<IBBHQ',raw,offset+n*16)
        if kind&0xe0 or not kind&1 or not kind&0x0e:
            continue
        need(index<string_size,'symbol string index outside table')
        end=raw.find(b'\0',strings+index,strings+string_size)
        need(end>=0,'unterminated symbol name')
        names.append(raw[strings+index:end].decode())
    need(len(names)==len(set(names)),'duplicate external symbol definitions')
    return sorted(names)


def source_recipe(audit, cpu_prefix, cpu_record, cache):
    archive = Path(cache) / 'remill.tar.gz'
    audit.sha(archive, cpu.REMILL_ARCHIVE_SHA)
    prefix = 'remill-' + cpu.REMILL_SHA + '/'
    files, modes = {}, {}
    with tarfile.open(archive, 'r:gz') as source:
        for member in source.getmembers():
            if member.isfile():
                need(member.name.startswith(prefix), 'unexpected Remill archive root')
                files[member.name[len(prefix):]] = source.extractfile(member).read()
                modes[member.name[len(prefix):]] = member.mode & 0o777
            else:
                need(member.isdir(), 'unsupported Remill archive link/member')
    for patch in cpu.PATCHES:
        files = replay_patch(files, audit.read(patch))
    expected = {name: dict(sha256=digest(raw), mode=modes[name]) for name, raw in files.items()}
    need(expected == cpu_record['source_tree'], 'prepared CPU source differs from pinned source/patch replay')
    return files


def verify_cpu(audit, prefix, receipt, returned, cache):
    prefix = Path(prefix)
    provider = audit.json(prefix / 'provider.json')
    need(provider == returned, 'CPU returned value differs from provider')
    row = audit.json(receipt)
    need(row.get('status') == provider.get('status') == 'CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED' and
         row.get('prefix') == str(prefix) and row.get('provider_sha256') == audit.sha(prefix/'provider.json'),
         'CPU receipt does not bind provider/prefix')
    loaded, paths = cpu.paths_for(prefix)
    need(loaded == provider and deps.tree(paths['source']) == provider['source_tree'], 'CPU source/loader differs')
    for name, value in provider['runtime_files'].items():
        audit.sha(prefix/name, value['sha256'])
    audit.relative_identities(provider['implementation'])
    audit.relative_identities(provider['patches'])
    actual = audit.tree(paths['source'])
    need(actual == provider['source_tree'], 'CPU source files differ')
    files = source_recipe(audit, prefix, provider, cache)
    verify_commands(audit, row['commands'])
    need(tools.selected_closure(prefix, [paths['lifter'], *[paths['llvm']/'bin'/n for n in ('clang','opt','llvm-link')]]) ==
         row['selected_graph'], 'CPU runtime graph differs')
    return dict(prefix=str(prefix), provider_sha256=audit.sha(prefix/'provider.json'),
                source_files=files, manifest=provider, paths=paths)


def verify_switch(audit, prefix, receipt, returned, base):
    prefix = Path(prefix)
    provider = audit.json(prefix/'provider.json')
    need(provider == returned == audit.json(receipt), 'switch result/provider/return differ')
    need(provider.get('status') == overlay.STATUS and provider.get('capabilities') == ['window-rel32-v1'] and
         provider.get('provider') == base['prefix'] and provider.get('provider_sha256') == base['provider_sha256'],
         'switch capability/CPU parent differs')
    loaded, paths = overlay.paths_for(prefix)
    need(loaded == provider, 'switch loader differs')
    audit.sha(paths['lifter'], provider['driver_sha256'])
    audit.sha(paths['semantics'], provider['semantics_sha256'])
    audit.relative_identities(provider['sources'])
    files = dict(base['source_files'])
    for name in ('switch_aot_v1/driver.patch', 'window_switch_v1/window-driver.patch'):
        files = replay_patch(files, audit.read(ROOT/name))
    files['bin/lift/SwitchProfile.h'] = audit.read(ROOT/'window_switch_v1/SwitchProfile.h')
    modes = {name: item['mode'] for name,item in base['manifest']['source_tree'].items()}
    modes['bin/lift/SwitchProfile.h'] = stat.S_IMODE((ROOT/'window_switch_v1/SwitchProfile.h').stat().st_mode)
    expected = {name: dict(sha256=digest(raw), mode=modes[name]) for name, raw in files.items()}
    actual = audit.tree(paths['source'])
    need(expected == provider['prepared_source'] == actual,
         'switch prepared source differs from base/patch/header replay')
    verify_commands(audit, provider['commands'])
    return dict(prefix=str(prefix), provider_sha256=audit.sha(prefix/'provider.json'), manifest=provider, paths=paths)


def verify_graphics(audit, prefix, receipt, returned):
    prefix = Path(prefix)
    provider = audit.json(prefix/'provider.json')
    need(provider == returned, 'graphics return/provider differ')
    row = audit.json(receipt)
    need(row.get('status') == provider.get('status') == graphics.STATUS and row.get('prefix') == str(prefix) and
         row.get('provider_sha256') == audit.sha(prefix/'provider.json'), 'graphics receipt binding differs')
    paths = graphics.paths_for(prefix)
    need(paths['provider_sha256'] == audit.sha(prefix/'provider.json'), 'graphics loader manifest differs')
    need(audit.tree(paths['source'], links=True) == provider['source_tree'], 'graphics source tree differs')
    need(audit.tree(prefix/'licenses', links=True) == provider['licenses'], 'graphics license tree differs')
    for name, value in provider['runtime_files'].items():
        audit.sha(prefix/name, value['sha256'])
    audit.relative_identities(provider['implementation'])
    for item in provider['external_prerequisites']['tools'].values():
        audit.sha(item['path'], item['sha256'])
    for name, sha in provider['external_prerequisites']['sdk_settings'].items():
        audit.sha(Path(provider['external_prerequisites']['sdk'])/name, sha)
    verify_commands(audit, row['commands'])
    need(tools.selected_closure(prefix, [paths['d3d11']]) == row['runtime_graph'], 'graphics runtime graph differs')
    return dict(prefix=str(prefix), provider_sha256=audit.sha(prefix/'provider.json'), manifest=provider, paths=paths)


def verify_product(audit, product, returned, frozen_pe, frozen_profile, identifier, switch, backend):
    product = Path(product)
    value = audit.json(product/'result.json')
    need(value == returned and type(value.get('schema')) is int and value['schema'] == 1 and
         value.get('profile') == 'window-switch-v6' and value.get('status') == 'BUILT_PORTABLE_WINDOW_APP_NOT_EXECUTED',
         'v6 product/return/status differs')
    raw_pe = audit.read(frozen_pe)
    profile_value = audit.json(frozen_profile)
    profile_value, image, _ = profile.validate(raw_pe, profile_value)
    need(value['input_sha256'] == audit.sha(frozen_pe) == audit.sha(product/'input.exe') and
         value['profile_sha256'] == audit.sha(frozen_profile) == audit.sha(product/'profile.json'), 'product input/profile differs')
    need(value['original_input'] == str(frozen_pe) and value['cpu_prefix'] == switch['prefix'] and
         value['backend_prefix'] == backend['prefix'] and value['cpu_provider_sha256'] == switch['provider_sha256'] and
         value['graphics_provider_sha256'] == backend['provider_sha256'] and
         value['spec'] == spec(dict(identifier=identifier, name='PE AOT Portable Window')), 'product role/spec binding differs')
    need(value['guest_executions'] == value['gpu_executions'] == 0 and value['requires_arguments'] is False,
         'static product scope differs')
    need(audit.tree(product, exclude=('result.json',)) == value['files'], 'complete product file set/bytes/modes differ')
    audit.identities(value['sources'])
    native = audit.json(product/'native/producer.json', value['producer_sha256'])
    packaged = audit.json(product/'package/package.json', value['package_sha256'])
    need(native['input_sha256'] == native['source_sha256'] == value['input_sha256'] and
         native['profile'] == profile_value and native['cpu_prefix'] == switch['prefix'] and
         native['cpu_provider_sha256'] == switch['provider_sha256'] and native['identifier'] == identifier,
         'native producer identity differs')
    need(native['inputs_before'] == native['inputs_after'] and
         native['compile_inputs_before'] == native['compile_inputs_after'] and
         packaged['inputs_before'] == packaged['inputs_after'], 'native/package inputs changed')
    for mapping in (native['inputs_before'], native['compile_inputs_before'], native['producer_sources'], packaged['inputs_before']):
        audit.identities(mapping)
    native_out = product/'native'
    roots = audit.json(native_out/'compiler/roots.json')
    need(roots == native['root_manifest'] and [roots['main'], *roots['roots']] == native['roots'], 'native roots differ')
    proof = admission.verify_root_set([r['manifest']['switch_proof'] for r in native['roots']], raw_pe,
                                      [image.entry_rva, *profile_value['callback_rvas']], profile_value['switch_leaf_rva'])
    need(proof == roots['switch_program'], 'program proof differs from original PE recomputation')
    target = audit.read(native_out/'compiler/target.ll').decode().splitlines()
    layout = next(line for line in target if line.startswith('target datalayout'))
    triple = next(line for line in target if line.startswith('target triple'))
    for root in native['roots']:
        directory = Path(root['directory']); manifest = root['manifest']
        need(audit.json(directory/'manifest.json') == manifest, 'root manifest binding differs')
        audit.identities(manifest['inputs_before'])
        need(manifest['inputs_before'] == manifest['inputs_after'], 'root input changed')
        ir = audit.read(directory/'lifted.ll').decode()
        arm, private = lift.retarget(ir, image.base+root['rva'], root['rva'], root['symbol'], layout, triple)
        need(audit.read(directory/'arm64.ll').decode() == arm and private == manifest['private_trace_symbols'],
             'root retarget/ABI differs')
        for item in manifest['objects'].values():
            audit.sha(item['path'], item['sha256'])
            need(lift.macho(Path(item['path']), 1)['file_type'] == 1, 'root object is not ARM64 Mach-O object')
            need(exports(audit,item['path']) == item['exports'] == ['_'+root['symbol']], 'actual root export ABI differs')
    generated = SimpleNamespace(image=image, source_bytes=raw_pe, source_sha256=digest(raw_pe),
                                out=native_out, roots=native['roots'], root_manifest=roots)
    headers.generate_headers(generated, profile_value, write=False)
    need(set(generated.generated_headers) == set(native['generated_headers']), 'generated header receipt set differs')
    for name, text in generated.generated_headers.items():
        need(native['generated_headers'][name] == dict(path=str(native_out/name),sha256=digest(text.encode())) and
             audit.read(native_out/name).decode() == text, 'actual generated header differs')
    shim_dir=native_out/'ret-shim/lift'
    shim=audit.json(shim_dir/'manifest.json')
    need(shim==native['ret_manifest'] and shim['function_symbol']==shim['symbol']=='aot_import_ret' and
         shim['imports']==[] and audit.read(shim_dir/'text.bin')==b'\xc3' and len(shim['instructions'])==1 and
         shim['instructions'][0]['kind']==2 and shim['instructions'][0]['bytes']=='c3' and
         shim['input_sha256']==audit.sha(native_out/'ret-shim/synthetic-ret.exe'), 'actual RET shim identity differs')
    shim_image=lift.load_image(audit.read(native_out/'ret-shim/synthetic-ret.exe'))
    audit.identities(shim['inputs_before'])
    need(shim['inputs_before']==shim['inputs_after'], 'RET shim inputs changed')
    shim_ir=audit.read(shim_dir/'lifted.ll').decode()
    shim_arm,shim_private=lift.retarget(shim_ir,shim['root_rva']+shim_image.base,shim['root_rva'],'aot_import_ret',layout,triple)
    need(audit.read(shim_dir/'arm64.ll').decode()==shim_arm and shim_private==shim['private_trace_symbols'],
         'RET shim ABI/retarget differs')
    for item in shim['objects'].values():
        audit.sha(item['path'],item['sha256'])
        need(exports(audit,item['path'])==item['exports']==['_aot_import_ret'], 'actual RET shim exports differ')
    units=producer.compilation_units(native_out,native['backend'],native['tools'])
    need(len(native['native_objects'])==6 and set(native['native_objects'])=={row[0] for row in units},
         'six compiled native units required')
    for name,source,compiler,flags in units:
        actual=native['native_objects'][name]
        need(actual['source']==str(source) and actual['compiler']==compiler and actual['flags']==flags,
             'native compilation recipe differs: '+name)
        graph=native['dependency_graphs'][name]
        need(audit.read(native_out/(name+'.d')).decode()==graph, 'compiler dependency record differs')
        for dependency in producer.generated_dependencies(name,graph,native_out):
            need(str(dependency.resolve()) in native['compile_inputs_before'], 'compiler dependency absent from frozen inputs')
    for name, item in native['native_objects'].items():
        audit.sha(item['path'], item['sha256'])
        need(lift.macho(Path(item['path']), 1)['file_type'] == 1, 'native unit not ARM64 object')
        need('-DAOT_WINDOW_SWITCH_V1' in item['flags'] and '-include' in item['flags'], 'window switch runtime macro/header absent')
        need(exports(audit,item['path']) == sorted(item['exports']), 'actual native export ABI differs')
    app = product/'PE AOT Converted.app'
    need(value['app'] == str(app) and value['executable'] == str(app/'Contents/MacOS/pe-aot-window'), 'final App paths differ')
    audit.sha(value['executable'], value['executable_sha256'])
    need(tools.macho(value['executable'])['filetype'] == 2, 'final executable not thin ARM64')
    need(package.formats.tree(app) == value['app_tree'] == packaged['app_tree'] and
         package.graph(app, value['spec'], value['minimum_macos']) == value['graph'], 'App tree/graph/ABI differs')
    need(packaged['original_pe_sha256'] == value['input_sha256'] and
         packaged['producer_sha256'] == value['producer_sha256'], 'package producer/original identity differs')
    commands = [audit.json(p) for p in sorted((product/'commands').glob('*.result.json'))]
    verify_commands(audit, commands)
    return dict(product=str(product), product_sha256=audit.sha(product/'result.json'), app=str(app),
                files=len(value['files']), command_count=len(commands))


EXPECTED = dict(zip(STAGES, ('CPU_PROVIDER_BUILT_NOT_GUEST_EXECUTED', overlay.STATUS, graphics.STATUS,
                            'BUILT_PORTABLE_WINDOW_APP_NOT_EXECUTED', 'PORTABLE_APP_FILES_VERIFIED_NOT_EXECUTED')))


def canonical(value):
    path = Path(value).absolute()
    need(path == path.resolve(), 'canonical path without symlinks/dot segments required: ' + str(path))
    return path


def expected_arguments(stage, directory, accepted, plan, installation):
    prefix = Path(plan['paths']['work_root'])/'attempts'/directory.name
    if stage == 'cpu-build':
        return dict(prefix=str(prefix), cache=plan['paths']['cpu_cache'], out=str(directory/'builder'), jobs=plan['jobs'])
    if stage == 'switch-build':
        return dict(provider=accepted['cpu-build']['arguments']['prefix'], prefix=str(prefix),
                    out=str(directory/'builder'), jobs=plan['jobs'])
    if stage == 'graphics-build':
        return dict(prefix=str(prefix), cache_path=plan['paths']['graphics_cache'],
                    out=str(directory/'builder'), jobs=plan['jobs'])
    if stage == 'app-build':
        return dict(pe=str(installation/'inputs/input.exe'), profile=decode((installation/'inputs/profile.json').read_bytes()),
                    identifier=plan['identifier'], cpu_prefix=accepted['switch-build']['arguments']['prefix'],
                    backend_prefix=accepted['graphics-build']['arguments']['prefix'], out=str(prefix))
    return dict(out=accepted['app-build']['arguments']['out'])


def verify_environment(audit, installation, plan):
    need(type(plan.get('schema')) is int and plan['schema'] == 2 and
         plan.get('status') == 'OFFLINE_V6_INSTALL_PLAN_READY_NOT_DECODED_NOT_BUILT' and
         plan.get('stages') == list(STAGES) and plan.get('capability') == 'window-rel32-v1', 'unsupported v2 installation plan')
    need(type(plan.get('jobs')) is int and plan['jobs'] in (1,2), 'invalid planned jobs')
    paths = {name: canonical(value) for name,value in plan['paths'].items()}
    need(paths['out'] == installation, 'plan initial output differs')
    roots = [paths[n] for n in ('work_root','out','cpu_cache','graphics_cache')]
    for i,left in enumerate(roots):
        for right in roots[i+1:]:
            need(not left.is_relative_to(right) and not right.is_relative_to(left), 'cache/work/initial output overlap')
    for name in ('pe','profile'):
        for destination in roots[:2]:
            need(not paths[name].is_relative_to(destination) and not destination.is_relative_to(paths[name]), 'output/input overlap')
    raw = audit.read(paths['pe'], plan['inputs']['pe_sha256'])
    original_profile = audit.json(paths['profile'], plan['inputs']['profile_sha256'])
    frozen_pe, frozen_profile = installation/'inputs/input.exe', installation/'inputs/profile.json'
    need(audit.read(frozen_pe) == raw and audit.json(frozen_profile) == original_profile, 'frozen input/profile differs')
    if 'canonical_profile_sha256' in plan['inputs']:
        audit.sha(frozen_profile, plan['inputs']['canonical_profile_sha256'])
    normalized, image, _ = profile.validate(raw, original_profile)
    need(normalized == original_profile and profile.analyze(raw, normalized) == plan['inputs']['analysis'], 'planned v6 admission differs')
    need(spec(dict(identifier=plan['identifier'], name='PE AOT Portable Window')) == plan['spec'], 'planned App spec differs')
    audit.relative_identities(plan['implementation'])
    audit.relative_identities(plan['implementation'], installation/'sources')
    expected_caches = dict(cpu=dict(tools=tools.check_cache(paths['cpu_cache']), sources=deps.sources(paths['cpu_cache']),
                                   remill=dict(path=str(paths['cpu_cache']/'remill.tar.gz'), sha256=cpu.REMILL_ARCHIVE_SHA,
                                               bytes=(paths['cpu_cache']/'remill.tar.gz').stat().st_size)),
                           graphics=graphics_cache.check_cache(paths['graphics_cache']))
    need(expected_caches == plan['caches'], 'pinned offline cache metadata differs')
    for cache in (paths['cpu_cache'], paths['graphics_cache']):
        for member in cache.rglob('*'):
            if member.is_file():
                audit.sha(member)
    apple = plan['apple']
    audit.identities(apple['tool_sha256'])
    audit.sha(apple['python'], apple['python_sha256'])
    for name, sha in apple['sdk_settings'].items():
        audit.sha(Path(apple['sdk'])/name, sha)
    need(Path(apple['sdk']).is_relative_to(apple['developer']), 'SDK/developer relationship differs')
    for query in apple['queries']:
        need(type(query['returncode']) is int and query['returncode'] == 0 and
             len(query['stdout'].strip().splitlines()) == 1 and query['stdout'].strip().startswith('/'),
             'frozen Apple discovery query did not succeed uniquely')
    return paths, frozen_pe, frozen_profile


def verify_worker(audit, directory, job, *, accepted=None, expected_python=None):
    launched = audit.json(directory/'launched.json')
    need(launched.get('protocol') == 'REGISTER_BEFORE_BUILDER_V1' and launched.get('stage') == job['stage'] and
         type(launched.get('pid')) is int and launched['pid'] > 1 and launched['pid'] == launched.get('pgid') and
         launched.get('job_sha256') == audit.sha(directory/'job.json'), 'worker registration differs')
    need(launched.get('lock_identity') == job.get('lock_identity'), 'worker inherited lock declaration differs')
    identity = launched['process_identity']
    need(identity.get('pid') == launched['pid'] and identity.get('pgid') == launched['pgid'] and
         type(identity.get('argv')) is list and identity['argv'][1:4] == ['-B','-m','migration_install_v2'] and
         identity['argv'][4:] == ['_worker', str(directory/'job.json')], 'declared worker command identity differs')
    if expected_python is not None:
        need(Path(identity['argv'][0]).resolve(strict=True)==Path(expected_python).resolve(strict=True),
             'worker Python identity differs')
        audit.sha(identity['argv'][0],audit.sha(expected_python))
    ended = audit.json(directory/'worker-exit.json')
    need(type(ended.get('returncode')) is int and ended.get('pid') == ended.get('pgid') == launched['pid'] and
         ended.get('group_state') in ('ABSENT','PRESENT','UNOBSERVABLE'), 'worker exit observation differs')
    for stream in ('stdout','stderr'):
        audit.sha(directory/('worker.'+stream), ended[stream+'_sha256'])
    result_path = directory/'worker-result.json'
    result = audit.json(result_path) if result_path.exists() else None
    if result is not None:
        need(result.get('stage') == job['stage'] and result.get('job_sha256') == audit.sha(directory/'job.json') and
             result.get('status') in ('WORKER_RETURNED','WORKER_FAILED'), 'worker return identity differs')
    if accepted is not None:
        need(ended['returncode'] == 0 and ended['group_state'] == 'ABSENT' and result is not None and
             result['status'] == 'WORKER_RETURNED' and result.get('returned') == accepted['returned'],
             'accepted stage has no normal owned worker result')
        for name,key in [('job.json','job_sha256'),('launched.json','launched_sha256'),
                         ('worker-exit.json','worker_exit_sha256'),('worker-result.json','worker_result_sha256')]:
            audit.sha(directory/name, accepted[key])
    return launched, ended, result


def verify_probe(audit, probe, installation, plan, attempts):
    probe=canonical(probe)
    started=audit.json(probe/'started.json');coordinator=audit.json(probe/'coordinator.json')
    controlled=audit.json(probe/'controlled-signal.json');result=audit.json(probe/'result.json')
    attached=started.get('status')=='ATTACHING_NO_NEW_BUILDERS'
    source_name='recovery_attach.py' if attached else 'recovery_probe.py'
    source=ROOT/'migration_install_v2'/source_name
    audit.sha(source,started['source_sha256'])
    audit.sha(probe/'sources/migration_install_v2'/source_name,started['source_sha256'])
    original=canonical(started['original_probe']) if attached else probe
    original_started=audit.json(original/'started.json')
    if attached:
        need(audit.json(original/'coordinator.json')==coordinator and started['installation']==str(installation) and
             started['coordinator_pid']==coordinator['pid'] and result.get('original_probe')==str(original),
             'attach does not bind original coordinator/installation')
        audit.sha(ROOT/'migration_install_v2/recovery_probe.py',original_started['source_sha256'])
        audit.sha(original/'sources/migration_install_v2/recovery_probe.py',original_started['source_sha256'])
        failure=audit.json(original/'observation-failure.json')
        need(failure.get('status')=='EXPERIMENT_NOT_ACCEPTED_CHILD_STATE_REQUIRES_OBSERVATION' and
             failure.get('coordinator_pid')==coordinator['pid'] and failure.get('returncode') is None and
             failure.get('error_type')=='PermissionError' and not (original/'result.json').exists(),
             'original observer failure was replaced or falsely completed')
    expected=[original_started['argv'][0],'-B','-m','migration_install_v2','install']
    for name in ('cpu_cache','graphics_cache','pe','profile','identifier','work_root'):
        expected.extend(['--'+name.replace('_','-'),plan['identifier'] if name=='identifier' else plan['paths'][name]])
    expected.extend(['--out',str(installation),'--jobs',str(plan['jobs'])])
    need(original_started['argv']==coordinator['argv']==expected and original_started['cwd']==str(ROOT) and
         Path(expected[0]).resolve()==Path(plan['apple']['python']).resolve() and
         type(coordinator.get('pid')) is int and coordinator['pid']>1 and coordinator['pid']==coordinator['pgid'],
         'controlled probe coordinator/plan identity differs')
    need(controlled.get('stage')=='graphics-build' and type(controlled.get('pid')) is int and
         controlled['pid']>1 and controlled['pid']==controlled.get('pgid') and controlled.get('signal')==15 and
         controlled.get('coordinator_pid')==coordinator['pid'], 'controlled signal ownership declaration differs')
    attempt=Path(controlled['job']).parent
    audit.sha(controlled['job'],controlled['job_sha256'])
    job=audit.json(controlled['job']);launch=audit.json(attempt/'launched.json')
    need(job['stage']=='graphics-build' and launch['pid']==launch['pgid']==controlled['pid'] and
         job['arguments']['prefix']==controlled['prefix'] and attempt.is_relative_to(installation/'attempts'),
         'controlled signal does not target original graphics worker')
    matches=[row for row in attempts if row['attempt']==str(attempt)]
    need(len(matches)==1 and matches[0]['stage']=='graphics-build' and not matches[0]['accepted'] and
         matches[0]['returncode']==-15 and matches[0]['pid']==controlled['pid'], 'SIGTERM not confirmed by actual failed worker exit')
    members=controlled['members'];seen=set()
    for member in members:
        need(type(member['pid']) is int and member['pid']>1 and member['pid'] not in seen and
             member['pgid']==controlled['pid'] and type(member['parent_pid']) is int and type(member['command']) is str,
             'invalid/duplicate controlled process group member')
        seen.add(member['pid'])
    owner=next((member for member in members if member['pid']==controlled['pid']),None)
    need(owner is not None and owner['parent_pid']==coordinator['pid'] and
         'migration_install_v2 _worker ' in owner['command'] and controlled['job'] in owner['command'],
         'controlled worker PPID/command does not belong to coordinator')
    need(any(controlled['prefix'] in member['command'] and ('--build ' in member['command'] or 'clang' in member['command'])
             for member in members), 'no actual compiler/build group member observed before SIGTERM')
    failed=audit.json(installation/'result.json',result['failed_install_result_sha256'])
    need(result.get('installation')==str(installation) and
         result.get('worker_pgid')==controlled['pid'] and result.get('final_group_state')=='ABSENT' and
         result.get('completed_stages')==failed['completed_stages']==['cpu-build','switch-build'] and
         result.get('failed_install_status')==failed['status']=='INSTALL_FAILED' and failed['stage']=='graphics-build' and
         result.get('app_executions')==result.get('gpu_executions')==0,
         'probe intent has no matching terminal/coordinator/group-absent result')
    if attached:
        sent=audit.json(probe/'signal-sent.json')
        need(sent==dict(status='OS_SIGNAL_CALL_SUCCEEDED',pid=controlled['pid'],pgid=controlled['pid'],signal=15),
             'attach has only signal intent, not successful OS signal call record')
        owner=controlled['coordinator_observation']
        need(owner['pid']==owner['pgid']==coordinator['pid'] and 'migration_install_v2 install ' in owner['command'] and
             str(installation) in owner['command'] and plan['paths']['work_root'] in owner['command'],
             'attach OS coordinator observation differs from original job')
        need(result.get('status')=='ATTACHED_REAL_GRAPHICS_INTERRUPTION_OBSERVED_NOT_RESUMED' and
             result.get('coordinator_returncode') is None and result.get('coordinator_group_state')=='ABSENT' and
             result.get('new_builders_started')==0 and
             result.get('worker_exit_sha256')==audit.sha(attempt/'worker-exit.json'),
             'attach invented a non-child exit status or changed terminal evidence')
    else:
        need(result.get('status')=='CONTROLLED_REAL_GRAPHICS_INTERRUPTION_OBSERVED_NOT_RESUMED' and
             result.get('coordinator_returncode')==1 and result.get('native_builds_invoked') is True,
             'controlled child probe did not observe its terminal coordinator')
    raw=audit.read(original/'install.stdout').decode();audit.sha(original/'install.stderr')
    decoder=json.JSONDecoder(object_pairs_hook=pairs,parse_constant=lambda value:need(False,'nonfinite coordinator JSON'))
    documents=[];offset=0
    while offset<len(raw):
        while offset<len(raw) and raw[offset].isspace():offset+=1
        if offset==len(raw):break
        value,offset=decoder.raw_decode(raw,offset);documents.append(value)
    expected_failure=dict(failed);expected_failure.pop('finished_at',None)
    need(documents and documents[-1]==expected_failure and any(value.get('status')=='LIVE_INSTALL_STAGE_WORKER' and
         value.get('stage')=='graphics-build' and value.get('pid')==controlled['pid'] and
         value.get('attempt')==str(attempt) for value in documents[:-1]), 'raw coordinator output differs from failed stage/worker records')
    return dict(probe=str(probe),original_probe=str(original),attached_after_observer_permission_failure=attached,
                coordinator_pid=coordinator['pid'],worker_pid=controlled['pid'],signal=15,
                coordinator_returncode=result['coordinator_returncode'],
                confirmation='durable intent plus original worker returncode -15, final installer failure JSON and observed group ABSENT',
                actual_build_members=len(members),failed_install_result_sha256=audit.sha(installation/'result.json'))


def review(installation, session, out, probe=None):
    installation, session, out = map(canonical, (installation,session,out))
    need(not out.exists() and not out.is_symlink(), 'new absent review output required')
    audit = Audit()
    audit.sha(__file__)
    plan = audit.json(installation/'plan.json')
    paths, frozen_pe, frozen_profile = verify_environment(audit, installation, plan)
    work_identity = audit.json(installation/'work-identity.json')
    lock = paths['work_root']/'.install.lock'
    lock_info = lock.lstat()
    expected_lock = dict(path=str(lock),device=lock_info.st_dev,inode=lock_info.st_ino)
    need(stat.S_ISREG(lock_info.st_mode) and work_identity.get('schema') == 1 and
         work_identity.get('work_root') == str(paths['work_root']) and work_identity.get('lock_identity') == expected_lock,
         'work lock path/device/inode differs')
    audit.sha(lock)
    indexes = sorted((installation/'sessions').glob('*.json'))
    sessions = []
    for number,path in enumerate(indexes,1):
        need(path.name == f'{number:04d}.json', 'session index sequence differs')
        record = audit.json(path)
        directory = canonical(record['directory'])
        need(record.get('schema') == 1 and record.get('sequence') == number and record.get('installation') == str(installation) and
             record.get('plan_sha256') == audit.sha(installation/'plan.json') and
             audit.json(directory/'session.json') == record, 'session/index/plan binding differs')
        need((number == 1 and directory == installation and record['invocation'] == 'install') or
             (number > 1 and directory != installation and record['invocation'] == 'resume'), 'session invocation differs')
        sessions.append(directory)
        if directory == session:
            break
    need(sessions and sessions[0] == installation and sessions[-1] == session, 'selected session not in installation chain')
    for i,directory in enumerate(sessions[1:],1):
        for protected in [*sessions[:i],paths['work_root'],paths['cpu_cache'],paths['graphics_cache'],paths['pe'],paths['profile']]:
            need(not directory.is_relative_to(protected) and not protected.is_relative_to(directory), 'resume evidence overlaps protected input')
    need(not any(out.is_relative_to(root) for root in (paths['work_root'],paths['cpu_cache'],paths['graphics_cache'])),
         'review output overlaps mutable build/cache data')
    accepted, bindings, stage_checks, attempts, historical, summaries = {}, {}, {}, [], [], []
    counts = {stage:0 for stage in STAGES}
    for directory in sessions:
        previous = dict(accepted)
        history = audit.json(directory/'historical-groups.json')
        need(history.get('schema') == 1 and history.get('installation') == str(installation) and
             history.get('session') == str(directory), 'historical group observation identity differs')
        observations = history['observations']
        need(type(observations) is list and len(observations) == len(historical), 'historical group coverage differs')
        expected_groups = {str(d): (job, launched) for d,job,launched in historical}
        observed = set()
        for row in observations:
            name = row['attempt']; need(name in expected_groups and name not in observed, 'unknown/duplicate historical group')
            job, launched = expected_groups[name]; observed.add(name)
            need(row['job_sha256'] == audit.sha(Path(name)/'job.json') and row['pid'] == row['pgid'] == launched['pid'] and
                 row['observed_state'] == 'ABSENT', 'historical worker still live/unknown or identity differs')
        need(observed == set(expected_groups), 'historical group missing')
        revalidated = audit.json(directory/'revalidated.json')
        need(revalidated['completed_stages'] == list(previous) and revalidated['dependencies'] == bindings,
             'session reuse differs from independently accepted previous stages')
        found = []
        for attempt in (directory/'attempts').iterdir():
            need(attempt.is_dir() and not attempt.is_symlink(), 'attempt is not a real directory')
            job = audit.json(attempt/'job.json')
            need(job.get('stage') in STAGES, 'unknown attempt stage')
            found.append((attempt,job))
        found.sort(key=lambda x:(STAGES.index(x[1]['stage']),x[0].name))
        for attempt,job in found:
            stage=job['stage']; counts[stage]+=1
            need(attempt.name == f'{stage}-{counts[stage]:04d}', 'attempt number reused/skipped')
            need(job.get('schema') == 1 and job.get('expected_status') == EXPECTED[stage] and
                 job.get('plan_sha256') == audit.sha(installation/'plan.json'), 'job capability/plan binding differs')
            need(job.get('lock_identity') == expected_lock, 'job installation lock inode differs')
            need(len(accepted)<len(STAGES) and stage == STAGES[len(accepted)], 'attempt did not target next incomplete stage')
            arguments = expected_arguments(stage,attempt,accepted,plan,installation)
            need(job['arguments'] == arguments, 'attempt allocation/parent/input arguments differ')
            receipt = None if stage=='app-verify' else str(Path(arguments['out'])/'result.json')
            need(job['builder_receipt'] == receipt and job['worker_result'] == str(attempt/'worker-result.json') and
                 job['worker_exit'] == str(attempt/'worker-exit.json') and job['launched'] == str(attempt/'launched.json'),
                 'job receipt paths escaped allocated attempt')
            marker = attempt/'accepted.json'
            value = audit.json(marker) if marker.exists() else None
            launched,ended,worker_result = verify_worker(audit,attempt,job,accepted=value,expected_python=plan['apple']['python'])
            historical.append((attempt,job,launched))
            attempts.append(dict(stage=stage,attempt=str(attempt),pid=launched['pid'],returncode=ended['returncode'],
                                 group_state=ended['group_state'],accepted=value is not None,
                                 signal=-ended['returncode'] if ended['returncode']<0 else None))
            if value is None:
                need(ended['returncode'] != 0 or worker_result is None or worker_result['status'] != 'WORKER_RETURNED' or
                     worker_result.get('returned',{}).get('status') != EXPECTED[stage] or
                     ended['group_state'] != 'ABSENT', 'normal complete worker was not accepted; cannot infer why')
                for command in sorted((attempt/'builder/commands').glob('*.started.json')):
                    audit.json(command)
                for log in sorted((attempt/'builder/commands').glob('*')):
                    if log.is_file(): audit.sha(log)
                continue
            need(value.get('stage') == stage and value.get('schema') == 1 and value['arguments'] == arguments and
                 value['dependencies'] == bindings, 'accepted stage arguments/dependencies differ')
            returned=value['returned']
            need(returned.get('status') == EXPECTED[stage], 'accepted return status differs')
            if receipt:
                audit.sha(receipt,value['builder_receipt_sha256'])
            else:
                need(value['builder_receipt_sha256'] is None, 'verify stage must not fabricate a builder receipt')
            if stage=='cpu-build':
                stage_checks[stage]=verify_cpu(audit,arguments['prefix'],receipt,returned,paths['cpu_cache'])
            elif stage=='switch-build':
                stage_checks[stage]=verify_switch(audit,arguments['prefix'],receipt,returned,stage_checks['cpu-build'])
            elif stage=='graphics-build':
                stage_checks[stage]=verify_graphics(audit,arguments['prefix'],receipt,returned)
            elif stage=='app-build':
                stage_checks[stage]=verify_product(audit,arguments['out'],returned,frozen_pe,frozen_profile,plan['identifier'],
                                                   stage_checks['switch-build'],stage_checks['graphics-build'])
            else:
                product_check=stage_checks['app-build']
                need(returned == dict(status=EXPECTED[stage],app=product_check['app'],files=product_check['files'],
                                      guest_executions=0,gpu_executions=0), 'verify return differs from independently checked product')
            accepted[stage]=dict(directory=str(attempt),arguments=arguments,returned=returned)
            if stage in ('cpu-build','switch-build','graphics-build'):
                name=str(Path(arguments['prefix'])/'provider.json'); bindings[name]=audit.sha(name)
        result=audit.json(directory/'result.json')
        need(result.get('schema')==2 and result.get('installation')==str(installation) and result.get('session')==str(directory) and
             result.get('plan_sha256')==audit.sha(installation/'plan.json') and result.get('completed_stages')==list(accepted),
             'session result does not bind actual completed stages')
        need(result.get('guest_executions')==result.get('gpu_executions')==result.get('app_executions')==0 and
             result.get('automatic_retry') is False,'installation execution scope differs')
        if len(accepted)==len(STAGES):
            product=stage_checks['app-build']
            need(result.get('status')=='OFFLINE_V6_APP_BUILT_VERIFIED_NOT_EXECUTED' and result.get('stage')=='complete' and
                 result['reused_stages']==list(previous) and result['dependencies']==bindings and
                 result['accepted_attempts']=={k:v['directory'] for k,v in accepted.items()} and
                 result['product']==product['product'] and result['product_sha256']==product['product_sha256'] and
                 result['app']==product['app'], 'final install result differs from independently reconstructed chain')
        else:
            need(result.get('status') in ('INSTALL_FAILED','INSTALL_CANCELLED_CHILD_STATE_UNKNOWN') and
                 result.get('stage')==STAGES[len(accepted)],'incomplete session reported success or wrong failed stage')
        summaries.append(dict(session=str(directory),status=result['status'],reused_stages=list(previous),
                              independently_completed_stages=list(accepted)))
    need(len(accepted)==len(STAGES),'selected session has not completed all five stages')
    controlled=verify_probe(audit,probe,installation,plan,attempts) if probe is not None else None
    audit.finish()
    report=dict(schema=1,status='PASS_OFFLINE_V6_INSTALL_AND_RECOVERY_INDEPENDENTLY_REVIEWED',
                installation=str(installation),session=str(session),plan_sha256=audit.sha(installation/'plan.json'),
                sessions=summaries,attempts=attempts,accepted_attempts={k:v['directory'] for k,v in accepted.items()},
                controlled_interruption=controlled,
                product=stage_checks['app-build'],source_patch_replay='pinned CPU Remill archive/CPU patches; base-to-switch patches/header',
                unique_files_read=len(audit.files),files=audit.files,symlinks=audit.links,
                guest_executions=0,app_executions=0,gpu_executions=0,native_builds=0,
                limitations=['Read-only current files plus frozen process observations, no live process query or signals.',
                             'Worker argv identity is a durable self-declaration under the pinned registration protocol, not a sampled OS start token.',
                             'Static install/product validation is not actual App/Cocoa/GPU, clean-machine or performance acceptance.'])
    with out.open('x') as stream:
        json.dump(report,stream,ensure_ascii=False,sort_keys=True,indent=2);stream.write('\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('installation','session','out'): parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--probe',type=Path,help='Optional frozen controlled-SIGTERM experiment side evidence')
    args=parser.parse_args()
    value=review(**vars(args))
    print(json.dumps({k:value[k] for k in ('status','unique_files_read','product')},ensure_ascii=False))


if __name__=='__main__':
    main()
