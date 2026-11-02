"""Independent frozen-file review of the versioned lookup production App.

No production validator, compiler, process, GPU or UI is imported/invoked.
The previous independent run reader supplies only file and Mach-O utilities.
"""
import argparse
import json
from pathlib import Path
import plistlib
import re
import shlex
import struct
import uuid

from migration_run_v3 import review as files

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'inline-instruction-search-v1'
RUNTIME = 'window_bridge/window_runtime/runtime.c'
TRANSACTION = 'window_bridge/window_runtime/transaction_v1.c'
LOOKUP = 'window_lookup_v1/lookup_impl.inc'
PINS = {RUNTIME: '9051c121f680988bc4f13a072dacbf213e8612fd3d095acc5704b388f87defd8',
        TRANSACTION: '0b0baf46ea802e3984065dad3be3f36a10a6fcc6d4f0d102e52a5913becaf8ed',
        LOOKUP: 'ebb0a1a8ffa6be1df541b01645dc0a4629b4fb9ad3888def4082eb7c320c3ea0'}
ORIGINAL = b'''static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    AotInstruction key={(uint32_t)(pc-ctx->module_base),0,0,0,0};
    return bsearch(&key,ctx->instructions,ctx->instruction_count,sizeof key,compare_instruction);
}
'''
need, read, js, digest = files.need, files.read, files.js, files.digest


def replacement(template, implementation):
    need(template.count(ORIGINAL) == 1, 'unique frozen lookup function required')
    need(digest(implementation) == PINS[LOOKUP], 'lookup implementation is not verified candidate')
    return template.replace(ORIGINAL, implementation, 1)


def dependency_paths(text):
    need(text.startswith('probe:'), 'dependency target differs')
    names = shlex.split(text.replace('\\\n', '')[6:])
    need(names and all(Path(name).is_absolute() for name in names), 'absolute dependency paths required')
    return {str(Path(name).resolve(strict=True)) for name in names}


def load_commands(raw, kind):
    need(len(raw) >= 32, 'short Mach-O')
    magic, cpu, subtype, actual, count, size, flags, reserved = struct.unpack_from('<8I', raw)
    need((magic, cpu, actual) == (0xfeedfacf, 0x100000c, kind), 'thin ARM64 file type required')
    need(0 < count < 4096 and size <= len(raw) - 32, 'invalid load command extent')
    at = 32
    result = []
    for _ in range(count):
        need(at + 8 <= 32 + size, 'truncated command header')
        command, length = struct.unpack_from('<II', raw, at)
        need(length >= 8 and length % 8 == 0 and at + length <= 32 + size, 'invalid load command length')
        result.append((command, at, length))
        at += length
    need(at == 32 + size, 'load command count differs')
    return result


def symbols(raw):
    tables = [(at, length) for command, at, length in load_commands(raw, 1) if command == 2]
    need(len(tables) == 1 and tables[0][1] == 24, 'unique symbol table required')
    offset, count, strings, size = struct.unpack_from('<4I', raw, tables[0][0] + 8)
    need(count <= (len(raw) - offset) // 16 and 0 <= strings <= len(raw) and size <= len(raw) - strings,
         'symbol table extent differs')
    result = []
    for index in range(count):
        name, typ, section, desc, value = struct.unpack_from('<IBBHQ', raw, offset + index * 16)
        need(name < size, 'symbol string offset differs')
        text = raw[strings + name:strings + size]
        need(b'\0' in text, 'unterminated symbol')
        result.append(text.split(b'\0', 1)[0].decode())
    return result


def sections(raw, kind):
    result = {}
    for command, at, length in load_commands(raw, kind):
        if command != 0x19:
            continue
        need(length >= 72, 'short segment')
        count = struct.unpack_from('<I', raw, at + 64)[0]
        need(length == 72 + 80 * count, 'section extent differs')
        for index in range(count):
            values = struct.unpack_from('<16s16sQQ8I', raw, at + 72 + 80 * index)
            name, segment, address, size, offset, alignment, reloc, nreloc, flags, r1, r2, r3 = values
            key = segment.split(b'\0', 1)[0].decode() + '/' + name.split(b'\0', 1)[0].decode()
            need(key not in result, 'duplicate section')
            zerofill = (flags & 255) in (1, 12, 18)
            need(zerofill or (offset <= len(raw) and size <= len(raw) - offset), 'section outside file')
            result[key] = dict(address=address, size=size, alignment=alignment, flags=flags,
                relocation_count=nreloc, reserved=[r1, r2, r3],
                sha256=None if zerofill else digest(raw[offset:offset + size]))
    need(result and '__TEXT/__text' in result, 'code section missing')
    return result


def app_images(app, record):
    minimum = record['minimum_macos']
    need(type(minimum) is str and re.fullmatch(r'[0-9]+\.[0-9]+(?:\.[0-9]+)?', minimum), 'numeric minimum macOS required')
    version = list(map(int, minimum.split('.')))
    version += [0] * (3 - len(version))
    need([15, 2, 0] <= version and all(0 <= n < 65536 for n in version), 'unsupported minimum macOS')
    need(files.tree(app) == record['app_tree'], 'App file tree differs')
    plist = plistlib.loads(read(app / 'Contents/Info.plist'))
    need(plist['CFBundleIdentifier'] == record['spec']['identifier'] and plist['LSMinimumSystemVersion'] == minimum,
         'App identity/deployment differs')
    main = app / 'Contents/MacOS/pe-aot-window'
    paths = [main, *(app / 'Contents/Frameworks' / name for name in sorted(files.NAMES))]
    images = {}
    for path in paths:
        is_main = path == main
        raw = read(path)
        identity, versions, rpaths, dependencies, ids = [], [], [], [], []
        for command, at, length in load_commands(raw, 2 if is_main else 6):
            if command == 0x1b:
                need(length == 24, 'invalid UUID command')
                identity.append(str(uuid.UUID(bytes=raw[at + 8:at + 24])).upper())
            elif command in (0x32, 0x24):
                need(length >= (24 if command == 0x32 else 16), 'short deployment command')
                if command == 0x32: need(struct.unpack_from('<I', raw, at + 8)[0] == 1, 'non-macOS image')
                packed = struct.unpack_from('<I', raw, at + (12 if command == 0x32 else 8))[0]
                versions.append([packed >> 16, (packed >> 8) & 255, packed & 255])
            elif command in (0xc, 0xd, 0x80000018, 0x8000001f, 0x20, 0x80000023, 0x8000001c):
                need(length >= 12, 'short load-string command')
                offset = struct.unpack_from('<I', raw, at + 8)[0]
                need(12 <= offset < length, 'load-string offset differs')
                data = raw[at + offset:at + length]; need(b'\0' in data, 'unterminated load string')
                value = data.split(b'\0', 1)[0].decode()
                (ids if command == 0xd else rpaths if command == 0x8000001c else dependencies).append(value)
        need(len(identity) == len(versions) == 1 and versions[0] <= version and
             (not is_main or versions[0] == version), 'image UUID/deployment differs')
        need(rpaths == (['@executable_path/../Frameworks'] if is_main else ['@loader_path/']), 'image rpaths differ')
        need(ids == ([] if is_main else ['@rpath/' + path.name]), 'image dylib ID differs')
        need(all(files.system(name) or name in {'@rpath/' + n for n in files.NAMES} for name in dependencies), 'external image dependency')
        images[str(path)] = identity[0]
    read(main, record['executable_sha256'])
    return images


def command_context(a, b, product, cpu_prefix, sdk, developer):
    need(a['cwd'] == b['cwd'] == str(product / 'native'), 'command cwd differs')
    need(type(a['env']) is dict and type(b['env']) is dict, 'recorded command environment required')
    # The nested Commands record stores requested overrides. Recorder stores
    # its effective environment after applying those overrides to fixed defaults.
    additional = dict(PYTHONDONTWRITEBYTECODE='1', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
        GIT_CEILING_DIRECTORIES=str(Path(cpu_prefix).parent), DEVELOPER_DIR=developer, SDKROOT=sdk)
    need(not set(a['env']) & set(additional), 'requested environment overrides recorder-only defaults')
    need(all(a['env'].get(k) == v for k, v in dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C').items()),
         'requested command environment defaults differ')
    effective = {**a['env'], **additional}
    need(all(type(k) is str and type(v) is str for k, v in effective.items()) and b['env'] == effective,
         'effective recorder environment differs from requested overrides/defaults')


def command(product, label, argv):
    local = list((product / 'native/commands').glob('*-' + label + '.json'))
    outer = list((product / 'commands').glob('*-native-' + label + '.result.json'))
    need(len(local) == len(outer) == 1, 'unique command receipt required: ' + label)
    a, b = js(local[0]), js(outer[0])
    need(a['argv'] == b['argv'] == list(map(str, argv)), 'actual command differs: ' + label)
    need(type(a['returncode']) is type(b['returncode']) is int and a['returncode'] == b['returncode'] == 0,
         'command did not succeed: ' + label)
    need(a['expected'] == b['expected'] == 0 and b['launch_error'] is None, 'command expectation/launch differs')
    native = js(product / 'native/producer.json')
    provider = js(native['backend']['provider_manifest'], native['backend']['provider_sha256'])
    command_context(a, b, product, native['cpu_prefix'], native['backend']['sdk'],
                    provider['external_prerequisites']['developer'])
    start = js(outer[0].with_name(outer[0].name.replace('.result.json', '.started.json')))
    need(all(start[k] == b[k] for k in ('argv', 'cwd', 'env', 'expected', 'label', 'started_at')), 'started command differs')
    for name in ('stdout', 'stderr'):
        need(read(b[name + '_path'], b[name + '_sha256']).decode() == a[name], 'nested raw command output differs')
    return a


def lookup_identity(product, record, native):
    value = record['runtime_lookup']
    need(value == native['runtime_lookup'], 'native/product lookup identity differs')
    base = product / 'native/runtime-source'
    expected = dict(contract=CONTRACT, manifest_path=str(base / 'runtime.json'),
                    manifest_sha256=digest(read(base / 'runtime.json')), source_root=str(base),
                    compile_source=str(base / RUNTIME), transaction_source=str(base / TRANSACTION),
                    lookup_sha256=PINS[LOOKUP])
    need(value == expected, 'lookup descriptor differs')
    manifest = js(base / 'runtime.json', value['manifest_sha256'])
    need(manifest['schema'] == 1 and manifest['status'] == 'GENERATED_INLINE_LOOKUP_SOURCES_NOT_EXECUTED' and
         manifest['contract'] == CONTRACT and manifest['lookup_sha256'] == PINS[LOOKUP], 'runtime manifest contract differs')
    need(manifest['templates'] == {str(ROOT / name): sha for name, sha in PINS.items()}, 'template identity differs')
    originals = {name: read(ROOT / name, sha) for name, sha in PINS.items()}
    expected_bytes = {RUNTIME: originals[RUNTIME], TRANSACTION: replacement(originals[TRANSACTION], originals[LOOKUP])}
    need(manifest['generated_files'] == {name: digest(data) for name, data in expected_bytes.items()}, 'generated file identity differs')
    need(set(files.tree(base)) == {*expected_bytes, 'runtime.json'}, 'unexpected runtime overlay members')
    for name, data in expected_bytes.items():
        need(read(base / name) == data, 'runtime transformation differs: ' + name)
    compile_inputs = native['compile_inputs_before']
    for path, sha in {**manifest['templates'], **{str(base / name): digest(data) for name, data in expected_bytes.items()},
                      str(base / 'runtime.json'): value['manifest_sha256']}.items():
        need(compile_inputs.get(path) == sha, 'runtime source not bound by compilation: ' + path)
    return value


def review(product, receipt_sha):
    files.OBSERVED.clear()
    product = Path(product).absolute()
    need(product == product.resolve() and product.is_dir(), 'canonical product required')
    need(type(receipt_sha) is str and re.fullmatch('[0-9a-f]{64}', receipt_sha), 'explicit product receipt SHA required')
    read(__file__); read(files.__file__)
    record = js(product / 'result.json', receipt_sha)
    need(record['schema'] == 1 and record['profile'] == 'window-lookup-v7' and
         record['status'] == 'BUILT_PORTABLE_WINDOW_APP_NOT_EXECUTED' and
         record['guest_executions'] == record['gpu_executions'] == 0 and record['requires_arguments'] is False,
         'successful static lookup-v7 product required')
    actual = files.tree(product); actual.pop('result.json')
    need(actual == record['files'], 'product file ledger differs')
    files.identities(record['sources'])
    native = js(product / 'native/producer.json', record['producer_sha256'])
    package = js(product / 'package/package.json', record['package_sha256'])
    need(native['status'] == 'PORTABLE_NO_ARGUMENT_NATIVE_BUILT_NOT_EXECUTED' and
         native['guest_executions'] == native['gpu_executions'] == native['generated_layout_harness_executions'] == 0,
         'native build scope differs')
    for before, after in (('compile_inputs_before', 'compile_inputs_after'), ('inputs_before', 'inputs_after')):
        need(native[before] == native[after], 'native inputs changed')
        files.identities(native[before])
    files.identities(native['producer_sources'])
    need(package['inputs_before'] == package['inputs_after'], 'package inputs changed')
    files.identities(package['inputs_before'])
    profile = js(product / 'profile.json', record['profile_sha256'])
    need(profile['schema'] == 2 and profile['runtime_contract'] == 'win32-d3d11-tile-switch-v1', 'switch input contract differs')
    need(js(product / 'native/profile.json') == native['profile'] == profile, 'profile identity differs')
    need(native['input_sha256'] == native['source_sha256'] == record['input_sha256'] == profile['pe_sha256'], 'PE identity differs')
    need(read(product / 'input.exe', record['input_sha256']) == read(product / 'native/input.exe'), 'frozen PE differs')
    need(native['cpu_provider_sha256'] == record['cpu_provider_sha256'] and
         native['backend']['provider_sha256'] == record['graphics_provider_sha256'], 'provider identity differs')
    need(native['minimum_macos'] == native['backend']['minimum_macos'] == record['minimum_macos'] == package['minimum_macos'],
         'minimum macOS declarations differ')
    value = lookup_identity(product, record, native)
    obj = native['native_objects']['runtime']
    need(obj['source'] == value['compile_source'] and obj['path'] == str(product / 'native/runtime.o'), 'runtime object role differs')
    argv = [obj['compiler'], *obj['flags'], '-c', obj['source'], '-o', obj['path']]
    command(product, 'compile-runtime', argv)
    required = ['-arch', 'arm64', '-isysroot', native['tools']['sdk'], '-mmacosx-version-min=' + native['minimum_macos'],
                '-O3', '-fno-lto', '-I', str(product / 'native'), '-Wall', '-Wextra', '-Werror',
                '-DAOT_WINDOW_SWITCH_V1', '-include', str(ROOT / 'window_switch_v1/runtime.h'), '-std=c11',
                '-iquote', str(ROOT / 'window_bridge/window_runtime')]
    need(obj['flags'] == required, 'runtime compiler flags differ')
    deps = native['dependency_graphs']['runtime']
    need(read(product / 'native/runtime.d').decode() == deps, 'runtime dependency evidence differs')
    names = dependency_paths(deps)
    need({value['compile_source'], value['transaction_source'], str(product / 'native/native_imports.h')} <= names,
         'generated runtime dependency absent')
    need(str(ROOT / TRANSACTION) not in names and str(ROOT / RUNTIME) not in names, 'original runtime selected by compiler')
    need(names <= set(native['compile_inputs_before']), 'compiler dependency omitted from identity set')
    for label in ('deps-runtime', 'deps-after-runtime'):
        row = command(product, label, [obj['compiler'], *obj['flags'], '-M', '-MT', 'probe', obj['source']])
        need(row['stdout'] == deps, 'dependency graph changed')
    actual_symbols = symbols(read(obj['path'], obj['sha256']))
    need('_bsearch' not in actual_symbols and not any('aot_pair_lookup_mode' in s for s in actual_symbols),
         'runtime contains reference lookup or experiment selector')
    need('_aot_begin' in actual_symbols and '_aot_wndproc_invoke' in actual_symbols, 'production runtime entrypoints absent')
    need(obj['path'] in native['objects'], 'runtime object absent from link inputs')
    link = list((product / 'native/commands').glob('*-link.json'))
    need(len(link) == 1, 'unique native link required')
    link_record = js(link[0]); command(product, 'link', link_record['argv'])
    need(all(link_record['argv'].count(path) == 1 for path in native['objects']), 'native link omitted or repeated input')
    read(native['native_executable'], native['native_sha256'])
    app = product / 'PE AOT Converted.app'
    need(record['app'] == str(app), 'exported App path differs')
    images = app_images(app, record)
    need(package['producer_sha256'] == record['producer_sha256'] and package['app_tree'] == record['app_tree'], 'package provenance differs')
    need(set(package['code_sections']) == {'Contents/MacOS/pe-aot-window', *('Contents/Frameworks/' + n for n in files.NAMES)},
         'packaged code role set differs')
    for name, info in package['code_sections'].items():
        kind = 2 if name.startswith('Contents/MacOS/') else 6
        original = read(info['source'], info['original_sha256'])
        packaged = read(app / name, info['packaged_sha256'])
        need(sections(original, kind) == sections(packaged, kind) == info['section_identity'], 'packaging changed code/data sections')
    for path, sha in list(files.OBSERVED.items()): read(path, sha)
    need(files.tree(product) == {**record['files'], 'result.json': {'mode': 0o644, 'sha256': receipt_sha}}, 'product changed during review')
    return dict(schema=1, status='PASS_LOOKUP_V7_PRODUCT_INDEPENDENTLY_REVIEWED', product=str(product),
        product_receipt_sha256=receipt_sha, runtime_lookup=value, checked_product_files=len(record['files']),
        unique_files_read=len(files.OBSERVED), files=dict(files.OBSERVED), image_uuids=images,
        exact_lookup_only_transformation_verified=True, generated_runtime_compilation_verified=True,
        object_without_bsearch_or_selector=True, package_code_sections_unchanged=True,
        native_or_UI_commands_executed_by_reader=0,
        limitations=['Static evidence review does not execute the App, callback, GPU or original Windows program.',
                     'No App/FPS performance, general PE compatibility or clean-machine claim.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product', required=True)
    parser.add_argument('--product-receipt-sha', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    out = Path(args.out).absolute()
    need(not out.exists() and not out.is_relative_to(Path(args.product).absolute()), 'fresh external review output required')
    result = review(args.product, args.product_receipt_sha)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as stream: json.dump(result, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps({k: result[k] for k in ('status', 'checked_product_files', 'unique_files_read')}))


if __name__ == '__main__':
    main()
