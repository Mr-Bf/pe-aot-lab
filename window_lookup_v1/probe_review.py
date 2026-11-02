"""Independent read-only review of fresh production callback/budget evidence."""
import argparse
import ast
from itertools import zip_longest
import json
from pathlib import Path
import sys

from window_callback_single_v1 import review as single
from . import review as product_reader

ROOT = Path(__file__).resolve().parents[1]
need, integer = single.need, single.integer


def source_closure(audit, initial):
    pending = list(initial); seen = set()
    def enqueue(parts):
        for n in range(1, len(parts) + 1):
            path = ROOT.joinpath(*parts[:n]) / '__init__.py'
            if path.is_file(): pending.append(path)
        path = ROOT.joinpath(*parts).with_suffix('.py')
        if path.is_file(): pending.append(path)
    while pending:
        path = pending.pop()
        if path in seen: continue
        need(path.is_relative_to(ROOT), 'source escaped repository')
        seen.add(path); package = path.parent.relative_to(ROOT).parts
        for node in ast.walk(ast.parse(audit.raw(path), filename=str(path))):
            if isinstance(node, ast.Import):
                for alias in node.names: enqueue(tuple(alias.name.split('.')))
            elif isinstance(node, ast.ImportFrom):
                need(node.level <= len(package), 'relative source import escaped repository')
                base = package[:len(package) + 1 - node.level] if node.level else ()
                if node.module: base += tuple(node.module.split('.'))
                enqueue(base)
                for alias in node.names:
                    if alias.name != '*': enqueue((*base, alias.name))
    return set(map(str, seen))


def compare(audit, directory, raw, reference, expected):
    need(raw == expected, 'raw new/reference response differs')
    for index in range(8):
        for suffix in ('.bin', '.context.bin'):
            name = 'case-%d%s' % (index, suffix)
            need(audit.raw(directory / name) == audit.raw(reference / name), 'complete new/reference response differs')
    count = 0
    for a, b in zip_longest(single.budgets(audit, directory, raw), single.budgets(audit, reference, expected)):
        need(a is not None and b is not None and a == b, 'complete new/reference budget differs')
        count += 1
    need(count == 364, 'budget count differs')
    return count


def inspection(audit, directory, level):
    undefined = audit.raw(directory / ('nm-u-' + level + '.stdout')).decode()
    symbols = audit.raw(directory / ('nm-' + level + '.stdout')).decode()
    disassembly = audit.raw(directory / ('disasm-' + level + '.stdout')).decode()
    need('_bsearch' not in undefined.split(), 'production probe imports reference lookup')
    need('aot_pair_lookup_mode' not in symbols and 'aot_pair_lookup_mode' not in disassembly, 'probe has strategy selector')
    need('_aot_begin:' in disassembly and '_aot_execute:' in disassembly, 'real probe runtime disassembly absent')
    return dict(strategy='candidate', bsearch_imported=False, shared_selector_symbol=False,
        scope='Exact source overlay plus real undefined-symbol and disassembly records; not an exhaustive machine-code semantic proof.')


def review(product, receipt_sha, probe, accepted):
    product, probe, accepted = [Path(p).resolve(strict=True) for p in (product, probe, accepted)]
    product_result = product_reader.review(product, receipt_sha)
    audit = single.old.Audit()
    prepared, original, goldens, layout, instructions, anchors = single.preparation(audit, accepted)
    audit.file(Path(single.__file__).resolve()); audit.file(Path(single.pair.__file__).resolve()); audit.finish()
    accepted_identities = dict(audit.files)
    for name, sha in product_result['files'].items(): audit.file(name, sha)
    v = audit.json(probe / 'result.json')
    need(v['schema'] == 1 and v['status'] == 'PASS_PRODUCTION_LOOKUP_CALLBACK_AND_BUDGET_CHECKS' and
         v['product'] == str(product) and v['out'] == str(probe) and v['accepted'] == str(accepted), 'probe identity differs')
    for key, value in dict(normal_callbacks=32, full_budget_callbacks=1456, actual_callbacks=1488,
                           full_budget_record_comparisons=1456, timer_calls=0, app_executions=0, gpu_executions=0).items():
        need(integer(v[key]) == value, 'probe count/scope differs: ' + key)
    need(v['prior_review_status'] == 'PASS_INDEPENDENT_SINGLE_LOOKUP_PREPARATION_REVIEW', 'prior review scope differs')
    need(v['accepted_file_identities'] == accepted_identities, 'accepted file identity coverage differs')
    expected_artifacts = {str(p) for p in probe.rglob('*') if p.is_file() and p != probe / 'result.json'}
    need(set(v['artifacts']) == expected_artifacts and all(Path(p).resolve() == Path(p) for p in expected_artifacts), 'probe artifact set differs')
    audit.mapping(v['artifacts'])
    sources = source_closure(audit, [ROOT / 'window_lookup_v1/probe.py']) | {
        str(single.MODULE / name) for name in ('benchmark.c', 'lookup_bounds.inc')}
    need(set(v['sources']) == sources, 'probe source closure differs'); audit.mapping(v['sources'])
    need(v['inputs_before'] == v['inputs_after'], 'probe inputs changed'); audit.mapping(v['inputs_before'])
    native = audit.json(product / 'native/producer.json'); lookup = native['runtime_lookup']
    need(v['runtime_lookup'] == lookup == product_result['runtime_lookup'], 'probe/production lookup differs')
    root_path = product / 'native/compiler/window-proc-1000/manifest.json'; root = audit.json(root_path)
    old = Path(prepared['baseline_prepared'])
    old_root_path = Path(original['binding']['objects']['O3']).parent / 'manifest.json'
    old_root = audit.json(old_root_path)
    need(root['instructions'] == instructions == old_root['instructions'] and root['switch_proof'] == old_root['switch_proof'] and
         root['root_rva'] == 0x1000 and root['symbol'] == 'aot_window_proc_1000', 'fresh lifted root differs')
    need(root['input_sha256'] == audit.file(product / 'native/input.exe') == audit.file(Path(original['product']) / 'native/input.exe'),
         'new PE input differs')
    need(audit.json(product / 'native/profile.json') == audit.json(Path(original['product']) / 'native/profile.json'), 'new PE profile differs')
    transaction = Path(lookup['transaction_source']); overlay = Path(lookup['source_root'])
    need(audit.raw(transaction) == audit.raw(accepted / 'sources/candidate' / single.RUNTIME), 'production lookup differs from accepted bytes')
    objects = {level: Path(root['objects'][level]['path']) for level in single.LEVELS}
    expected_inputs = {product / 'result.json', product / 'native/producer.json', product / 'native/input.exe',
        product / 'native/profile.json', root_path, transaction, Path(lookup['manifest_path']), *objects.values(),
        accepted / 'result.json', old / 'result.json', old_root_path}
    need(set(v['inputs_before']) == set(map(str, expected_inputs)), 'probe input binding coverage differs')
    copies = probe / 'inputs'; names = ['callback_probe_input.h']
    names += [label + '-' + suffix + '.bin' for label in ('preferred', 'rebased') for suffix in ('image', 'permissions')]
    for name in names: need(audit.raw(copies / name) == audit.raw(old / 'inputs' / name), 'probe input copy differs')
    for level, path in objects.items():
        need(path.parent == root_path.parent, 'fresh root object escaped compiler output')
        audit.file(path, root['objects'][level]['sha256'])
        need(audit.raw(copies / (level + '.o')) == audit.raw(path), 'copied root object differs')
        single.old.native_file(audit, path, 1)
    need(set(v['generated']) == {str(copies / name) for name in names + [level + '.o' for level in single.LEVELS]}, 'generated input set differs')
    audit.mapping(v['generated'])
    cmds = single.commands(audit, v, probe)
    compiler = audit.raw(probe / 'compiler-path.stdout').decode().strip()
    sdk = audit.raw(probe / 'sdk-path.stdout').decode().strip()
    need(set(v['tools']) == {compiler, str(Path(sys.executable).resolve()), str(Path(sdk) / 'SDKSettings.json'), '/usr/bin/nm', '/usr/bin/otool'}, 'tool identity set differs')
    audit.mapping(v['tools'])
    flags = [compiler, '-std=c11', '-arch', 'arm64', '-isysroot', sdk, '-O3', '-fno-lto', '-Wall', '-Wextra', '-Werror',
        '-DAOT_WINDOW_SWITCH_V1=1', '-DAOT_SINGLE_CANDIDATE=1', '-I', str(copies), '-I', str(overlay), '-I', str(ROOT),
        '-iquote', str(ROOT / 'window_bridge/window_runtime')]
    harness = str(single.MODULE / 'benchmark.c')
    expected_commands = [('compiler-path', ['/usr/bin/xcrun', '--find', 'clang']), ('sdk-path', ['/usr/bin/xcrun', '--show-sdk-path']),
        ('compiler-version', [compiler, '--version']), ('dependencies', [*flags, '-M', '-MT', 'pair', harness])]
    for level in single.LEVELS:
        binary = str(probe / ('probe-' + level))
        expected_commands += [('compile-' + level, [*flags, harness, str(copies / (level + '.o')), '-lz', '-o', binary]),
            ('nm-u-' + level, ['/usr/bin/nm', '-u', binary]), ('nm-' + level, ['/usr/bin/nm', '-a', binary]),
            ('disasm-' + level, ['/usr/bin/otool', '-tvV', binary])]
        single.old.native_file(audit, binary, 2)
        need(v['inspection'][level] == inspection(audit, probe, level), 'probe symbol/disassembly evidence differs')
    expected_commands += [('dependencies-after', [*flags, '-M', '-MT', 'pair', harness])]
    deps = audit.raw(probe / 'dependencies.stdout')
    need(deps == audit.raw(probe / 'dependencies-after.stdout'), 'probe dependency graph changed')
    need(deps.startswith(b'pair:'), 'probe dependency target differs')
    paths = product_reader.dependency_paths('probe:' + deps.decode()[5:])
    need(set(v['compiler_dependencies']) == paths, 'probe compiler dependency identity set differs')
    required = {harness, str(single.MODULE / 'lookup_bounds.inc'), str(copies / 'callback_probe_input.h'), str(transaction),
                *(str(ROOT / n) for n in single.old.RUNTIME if n != single.RUNTIME)}
    need(required <= paths and str(ROOT / single.RUNTIME) not in paths, 'probe compiled wrong transaction')
    audit.mapping(v['compiler_dependencies'])
    matrix = [(label, base, level) for label, base in zip(('preferred', 'rebased'), single.BASES) for level in single.LEVELS]
    need(len(v['checks']) == len(matrix), 'probe check matrix count differs')
    compared = 0
    for row, (label, base, level) in zip(v['checks'], matrix):
        key = label + '-' + level; directory = probe / key; reference = accepted / (key + '-candidate')
        raw_path = probe / ('check-' + key + '.stdout')
        need(row == dict(key=key, base=base, optimization=level, output=str(directory), reference=str(reference), raw=str(raw_path)), 'probe check matrix/paths differ')
        expected_commands += [('check-' + key, [str(probe / ('probe-' + level)), '--check', str(copies / (label + '-image.bin')),
            str(copies / (label + '-permissions.bin')), hex(base), str(directory), '1', '0'])]
        raw = audit.json(raw_path)
        need(raw == audit.json(directory / 'parsed.json'), 'probe parsed/raw differs')
        _, contexts = single.response(audit, raw, directory, goldens[key], base, 'candidate', 'check', 1, 0, layout, instructions)
        need(contexts == anchors[base], 'probe Context differs from accepted state')
        compared += compare(audit, directory, raw, reference, audit.json(accepted / ('check-' + key + '-candidate.stdout')))
    need(list(cmds) == [label for label, _ in expected_commands], 'probe command order differs')
    for label, argv in expected_commands: need(cmds[label]['argv'] == argv, 'probe command argv differs: ' + label)
    audit.file(Path(__file__).resolve()); audit.finish()
    return dict(schema=1, status='PASS_PRODUCTION_LOOKUP_CALLBACK_INDEPENDENTLY_REVIEWED', product=str(product),
        product_receipt_sha256=receipt_sha, probe=str(probe), accepted=str(accepted), normal_full_responses=32,
        full_budget_records=compared, actual_callbacks=1488, unique_files_read=len(audit.files), files=dict(audit.files),
        native_or_UI_commands_executed_by_reader=0, timer_calls_by_reader=0,
        limitations=['Rejecting-API CPU harness only; no outer callback ABI, App/GPU, FPS or new performance claim.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('product', 'product-receipt-sha', 'probe', 'accepted', 'out'): parser.add_argument('--' + name, required=True)
    args = vars(parser.parse_args()); out = Path(args.pop('out')).absolute()
    need(not out.exists() and all(not out.is_relative_to(Path(args[k]).absolute()) for k in ('product', 'probe', 'accepted')), 'fresh external review output required')
    args['receipt_sha'] = args.pop('product_receipt_sha')
    value = review(**args); out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('x') as stream: json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
    print(json.dumps({k: value[k] for k in ('status', 'unique_files_read', 'actual_callbacks')}))
