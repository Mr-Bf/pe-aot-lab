"""Untimed checks of the production transaction source and freshly lifted roots.

The frozen single-strategy harness supplies complete State/image/stack and
canonical Context dumps, including every budget prefix. No App is launched.
"""
import argparse
from itertools import zip_longest
import json
from pathlib import Path
import shutil
import sys
import traceback

from migration_v7 import build as product_build
from portable_app_v1.lift import source_closure
from window_callback_bench_v1 import runner as base
from window_callback_pair_v1 import runner as pair
from window_callback_single_v1 import runner as single
from window_callback_single_v1 import review as single_review
from window_switch_v1 import admission, profile, lift
from window_inc_v1.loader import load_image

ROOT = Path(__file__).resolve().parents[1]
STATUS = 'PASS_PRODUCTION_LOOKUP_CALLBACK_AND_BUDGET_CHECKS'
need, read, sha, write = base.require, base.read, base.sha, base.write


def accepted_inputs(accepted):
    prior_review = single_review.review(accepted)
    prior, ready = single.verify_prepared(accepted)
    return prior_review, Path(prior['baseline_prepared']), ready


def dependency_command(flags, harness):
    # The frozen parser intentionally accepts only the target named "pair".
    return [*flags, '-M', '-MT', 'pair', harness]


def compare(directory, value, reference, expected):
    """Compare complete dumps, not just a caller-supplied checksum or PASS."""
    need(value == expected, 'new callback raw response differs from accepted reference')
    for case in range(8):
        for suffix in ('.bin', '.context.bin'):
            name = 'case-%d%s' % (case, suffix)
            need((directory/name).read_bytes() == (reference/name).read_bytes(),
                 'new callback complete payload differs: '+name)
    count = 0
    for current, previous in zip_longest(single.budget_records(directory, value),
                                       single.budget_records(reference, expected)):
        need(current is not None and previous is not None and current == previous,
             'new callback full budget prefix differs')
        count += 1
    need(count == 364, 'budget comparison count differs')
    return count


def run(product, accepted, out):
    base.native_host()
    product, accepted = (Path(p).resolve(strict=True) for p in (product, accepted))
    product_build.verify(product)
    prior_review, old, ready = accepted_inputs(accepted)
    native = read(product/'native/producer.json')
    descriptor = native['runtime_lookup']
    transaction = Path(descriptor['transaction_source'])
    overlay = Path(descriptor['source_root'])
    need(transaction == overlay/single.RUNTIME, 'production transaction path differs')
    need(transaction.read_bytes() == (accepted/'sources/candidate'/single.RUNTIME).read_bytes(),
         'production transaction is not the accepted fixed-strategy source')
    pe = product/'native/input.exe'
    config, image, _ = profile.validate(pe.read_bytes(), read(product/'native/profile.json'))
    manifest = product/'native/compiler/window-proc-1000/manifest.json'
    root = read(manifest)
    need(root['input_sha256'] == sha(pe) == sha(Path(ready['product'])/'native/input.exe') and
         root['root_rva'] == 0x1000 and root['symbol'] == 'aot_window_proc_1000',
         'new callback input/root differs')
    old_manifest = Path(ready['binding']['objects']['O3']).parent/'manifest.json'
    old_root = read(old_manifest)
    need(root['instructions'] == old_root['instructions'] and root['switch_proof'] == old_root['switch_proof'],
         'new callback instruction/proof differs from the accepted input')
    proof = root['switch_proof']
    admission.validate_window_switch(proof, pe.read_bytes(), proof['candidate_packet'], 0x1000,
                                     config['switch_leaf_rva'], [image.entry_rva, 0x1000])
    need(base.header(image, root, config) == (old/'inputs/callback_probe_input.h').read_bytes(),
         'reference header differs from newly built callback')
    need(config == read(Path(ready['product'])/'native/profile.json'), 'new profile differs')
    objects = {}
    for level in single.LEVELS:
        obj = Path(root['objects'][level]['path'])
        need(obj.parent == manifest.parent and sha(obj) == root['objects'][level]['sha256'],
             'new lifted object identity differs')
        lift.macho(obj, 1)
        objects[level] = obj
    inputs = base.identities([product/'result.json', product/'native/producer.json', pe,
                              product/'native/profile.json', manifest, transaction,
                              Path(descriptor['manifest_path']), *objects.values(),
                              accepted/'result.json', old/'result.json', old_manifest])
    sources = base.identities([*source_closure([Path(__file__)]),
                              single.MODULE/'benchmark.c', single.MODULE/'lookup_bounds.inc'])
    out = base.fresh(out, [product, accepted, old, ready['product'], ready['probe']])
    commands, checks = base.Commands(out), []
    write(out/'started.json', dict(status='STARTED_NOT_ACCEPTED', product=str(product), accepted=str(accepted),
                                  inputs=inputs, sources=sources))
    try:
        copies = out/'inputs'; copies.mkdir()
        names = ['callback_probe_input.h']
        for base_address, label in zip(single.BASES, ('preferred', 'rebased')):
            mapped = load_image(pe.read_bytes(), load_base=base_address)
            for suffix, expected in (('image', bytes(mapped.data)), ('permissions', bytes(mapped.permissions))):
                name = label+'-'+suffix+'.bin'
                need((old/'inputs'/name).read_bytes() == expected, 'reference PE mapping differs')
                names.append(name)
        for name in names:
            shutil.copyfile(old/'inputs'/name, copies/name)
            need((copies/name).read_bytes() == (old/'inputs'/name).read_bytes(),
                 'copied probe input differs from accepted input')
        for level, obj in objects.items():
            shutil.copyfile(obj, copies/(level+'.o'))
            need(sha(copies/(level+'.o')) == sha(obj), 'copied new callback object differs')
        generated = base.identities(p for p in copies.iterdir())
        compiler = commands.run(['/usr/bin/xcrun', '--find', 'clang'], 'compiler-path').decode().strip()
        sdk = commands.run(['/usr/bin/xcrun', '--show-sdk-path'], 'sdk-path').decode().strip()
        commands.run([compiler, '--version'], 'compiler-version')
        tools = base.identities([compiler, Path(sys.executable).resolve(), Path(sdk)/'SDKSettings.json',
                                 '/usr/bin/nm', '/usr/bin/otool'])
        flags = [compiler, '-std=c11', '-arch', 'arm64', '-isysroot', sdk, '-O3', '-fno-lto',
                 '-Wall', '-Wextra', '-Werror', '-DAOT_WINDOW_SWITCH_V1=1', '-DAOT_SINGLE_CANDIDATE=1',
                 '-I', copies, '-I', overlay, '-I', ROOT,
                 '-iquote', ROOT/'window_bridge/window_runtime']
        harness = single.MODULE/'benchmark.c'
        dependency_bytes = commands.run(dependency_command(flags, harness), 'dependencies')
        paths = pair.dependencies(dependency_bytes)
        required = {harness, single.MODULE/'lookup_bounds.inc', copies/'callback_probe_input.h', transaction,
                    *(ROOT/name for name in base.RUNTIME if name != single.RUNTIME)}
        need(required <= set(paths) and ROOT/single.RUNTIME not in paths,
             'probe did not consume the production transaction dependency')
        dependencies = base.identities(paths)
        need(native['compile_inputs_before'].get(str(transaction)) == sha(transaction),
             'production compiler did not bind the probe transaction')
        inspections = {}
        for level in single.LEVELS:
            binary = out/('probe-'+level)
            commands.run([*flags, harness, copies/(level+'.o'), '-lz', '-o', binary], 'compile-'+level)
            pair.native_binary(binary)
            undefined = commands.run(['/usr/bin/nm', '-u', binary], 'nm-u-'+level)
            symbols = commands.run(['/usr/bin/nm', '-a', binary], 'nm-'+level)
            disassembly = commands.run(['/usr/bin/otool', '-tvV', binary], 'disasm-'+level)
            inspections[level] = single.artifact_inspection(undefined, symbols, disassembly, 'candidate')
        need(commands.run(dependency_command(flags, harness), 'dependencies-after') == dependency_bytes,
             'probe dependency graph changed')
        comparisons = 0
        for address, label in zip(single.BASES, ('preferred', 'rebased')):
            for level in single.LEVELS:
                key = label+'-'+level; directory = out/key; directory.mkdir()
                raw = commands.run([out/('probe-'+level), '--check', copies/(label+'-image.bin'),
                                    copies/(label+'-permissions.bin'), hex(address), directory, 1, 0], 'check-'+key)
                value = base.parse(raw)
                single.validate_response(value, directory, ready['binding']['goldens'][key], address,
                                         'candidate', 'check', 1, 0, root['instructions'])
                reference = accepted/(key+'-candidate')
                expected = base.parse((accepted/('check-'+key+'-candidate.stdout')).read_bytes())
                comparisons += compare(directory, value, reference, expected)
                write(directory/'parsed.json', value)
                checks.append(dict(key=key, base=address, optimization=level, output=str(directory),
                                   reference=str(reference), raw=str(out/('check-'+key+'.stdout'))))
        for values in (inputs, sources, generated, tools, dependencies):
            base.unchanged(values)
        base.unchanged(prior_review['audited_files'])
        product_build.verify(product)
        result = dict(schema=1, status=STATUS, product=str(product), accepted=str(accepted), out=str(out),
                      inputs_before=inputs, inputs_after=base.identities(inputs), sources=sources,
                      prior_review_status=prior_review['status'], runtime_lookup=descriptor,
                      accepted_file_identities=prior_review['audited_files'],
                      generated=generated, tools=tools, compiler_dependencies=dependencies,
                      inspection=inspections, checks=checks, commands=commands.rows,
                      normal_callbacks=32, full_budget_callbacks=1456, actual_callbacks=1488,
                      full_budget_record_comparisons=comparisons, timer_calls=0, app_executions=0, gpu_executions=0,
                      artifacts=base.identities(p for p in out.rglob('*') if p.is_file()),
                      scope='Fresh production lifted objects and exact production transaction; frozen rejecting-API CPU harness. No outer callback ABI, App/GPU or timing claim.')
        write(out/'result.json', result)
        return result
    except BaseException as error:
        write(out/'failure.json', dict(status='FAILED_NOT_ACCEPTED', error=repr(error),
              traceback=traceback.format_exc(), checks=checks, commands=commands.rows))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('product', 'accepted', 'out'):
        parser.add_argument('--'+name, required=True)
    value = run(**vars(parser.parse_args()))
    print(json.dumps({k:value[k] for k in ('status', 'actual_callbacks', 'full_budget_record_comparisons')}))
