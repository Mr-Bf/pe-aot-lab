"""Independent reader counterexamples. Synthetic data only; never launches code."""
import ast
import copy
import json
import shlex
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from . import review, runner, validation
from .test_run import normal_result


def transition(initial_position=3, initial_moves=0, initial_draws=0, events=None):
    events = events or ['right', 'right', 'left', 'escape']
    result, profile, image = normal_result()
    initial = struct.pack('<5I', 0x31574f43, 1, initial_position, initial_moves, initial_draws)
    position, moves = initial_position, initial_moves
    for event in events[:-1]:
        after = max(0, position - 1) if event == 'left' else min(7, position + 1)
        moves = (moves + (after != position)) & 0xffffffff
        position = after
    presents = 2 + sum((event in ('left', 'right')) for event in events[:-1])
    saved = struct.pack('<5I', 0x31574f43, 1, position, moves, (initial_draws + presents) & 0xffffffff)
    guest = [0] * 15
    guest[3] = len(events) - (events[-1] == 'close')
    guest[6] = int(events[-1] == 'close')
    guest[7:11] = [1, presents, 1, 20]
    guest[13] = 1
    profile['observations'] = {name: {'rva': index * 4096, 'size': size}
                               for index, (name, size) in enumerate((('window_state', 20), ('window_result', 60), ('window_load_result', 36)))}
    result['observations'] = dict(window_state=saved.hex(), window_result=struct.pack('<15I', *guest).hex(),
                                  window_load_result=struct.pack('<9I', 1, 0, 1, 0, 0, 0, 2, 0, 0).hex())
    result['saved_file']['data_hex'] = saved.hex()
    result['switch_commits'] = events.count('right')
    result['host_after_finish']['cocoa_key_events'] = 2 * guest[3]
    result['d3d_before_cleanup']['present_calls'] = presents
    actions = {'events': list(events)}
    return result, profile, initial, actions


def lookup_fixture(directory):
    """Synthetic compiler receipts only; frozen source bytes, no compiler call."""
    product = Path(directory) / 'product with spaces'
    generated = product / 'native/runtime-source'
    original = Path(directory) / 'source with spaces'
    templates = {}
    for suffix in review.TEMPLATE_SHA:
        path = original / suffix
        path.parent.mkdir(parents=True, exist_ok=True)
        source = review.ROOT / suffix
        if suffix == 'window_lookup_v1/lookup_impl.inc':
            source = review.ROOT / 'window_callback_single_v1/lookup_impl.inc'
        path.write_bytes(source.read_bytes())
        templates[str(path)] = review.digest(path.read_bytes())
    old = original / 'window_bridge/window_runtime/transaction_v1.c'
    raw = old.read_bytes()
    begin = raw.index(b'static const AotInstruction *instruction(')
    end = raw.index(b'\n}\n', begin) + 3
    replacements = {'window_bridge/window_runtime/runtime.c':
                    (original / 'window_bridge/window_runtime/runtime.c').read_bytes(),
                    'window_bridge/window_runtime/transaction_v1.c':
                    raw[:begin] + (original / 'window_lookup_v1/lookup_impl.inc').read_bytes() + raw[end:]}
    generated_files = {}
    for suffix, raw in replacements.items():
        path = generated / suffix
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        generated_files[suffix] = review.digest(raw)
    manifest = dict(schema=1, status='GENERATED_INLINE_LOOKUP_SOURCES_NOT_EXECUTED',
                    contract='inline-instruction-search-v1', templates=templates,
                    generated_files=generated_files, lookup_sha256=review.LOOKUP_SHA)
    manifest_path = generated / 'runtime.json'
    manifest_path.write_text(json.dumps(manifest))
    descriptor = dict(contract=manifest['contract'], manifest_path=str(manifest_path),
                      manifest_sha256=review.digest(manifest_path.read_bytes()), source_root=str(generated),
                      compile_source=str(generated / 'window_bridge/window_runtime/runtime.c'),
                      transaction_source=str(generated / 'window_bridge/window_runtime/transaction_v1.c'),
                      lookup_sha256=review.LOOKUP_SHA)
    inputs = {**templates, str(manifest_path): descriptor['manifest_sha256'],
              **{str(generated / name): value for name, value in generated_files.items()}}
    obj = product / 'native/runtime.o'
    obj.write_bytes(b'SYNTHETIC_NOT_MACHO_NEVER_EXECUTED')
    flags = ['-O3', '-fno-lto', '-iquote', str(old.parent)]
    record = dict(source=descriptor['compile_source'], path=str(obj), sha256=review.digest(obj.read_bytes()),
                  compiler='/synthetic/clang', flags=flags)
    dependencies = 'probe: ' + ' '.join(shlex.quote(descriptor[n]) for n in ('compile_source', 'transaction_source')) + '\n'
    (product / 'native/runtime.d').write_text(dependencies)
    commands = product / 'native/commands'; commands.mkdir()
    (commands / '001-compile-runtime.json').write_text(json.dumps(dict(label='compile-runtime', returncode=0,
        argv=[record['compiler'], *flags, '-c', record['source'], '-o', str(obj)])))
    native = dict(runtime_lookup=descriptor, compile_inputs_before=inputs, compile_inputs_after=inputs.copy(),
                  native_objects={'runtime': record}, dependency_graphs={'runtime': dependencies})
    return product, {'runtime_lookup': descriptor.copy()}, native


def update_lookup_manifest(receipt, native, callback):
    path = Path(receipt['runtime_lookup']['manifest_path'])
    manifest = json.loads(path.read_bytes())
    callback(manifest)
    path.write_text(json.dumps(manifest))
    digest = review.digest(path.read_bytes())
    receipt['runtime_lookup']['manifest_sha256'] = native['runtime_lookup']['manifest_sha256'] = digest
    native['compile_inputs_before'][str(path)] = native['compile_inputs_after'][str(path)] = digest


class LookupProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='lookup-v7-review-')
        self.addCleanup(self.temporary.cleanup)
        self.product, self.receipt, self.native = lookup_fixture(Path(self.temporary.name).resolve())
        review.OBSERVED.clear()

    def verify(self):
        return review.lookup_provenance(self.product, self.receipt, self.native)

    def test_synthetic_exact_transformation_and_compiler_binding(self):
        record = self.verify()
        self.assertTrue(record['exact_single_function_replacement'])
        self.assertFalse(record['executed_by_reader'])
        self.assertEqual(record['lookup_sha256'], review.LOOKUP_SHA)

    def test_missing_or_mismatched_new_provenance_is_rejected(self):
        for bad in (None, {}, {**self.receipt['runtime_lookup'], 'contract': 'old'},
                    {**self.receipt['runtime_lookup'], 'lookup_sha256': '0' * 64},
                    {**self.receipt['runtime_lookup'], 'manifest_sha256': None}):
            with self.subTest(value=bad), self.assertRaisesRegex(ValueError, 'lookup'):
                review.lookup_provenance(self.product, {'runtime_lookup': bad}, self.native)

    def test_relocated_source_path_cannot_alias_an_old_transaction(self):
        self.receipt['runtime_lookup']['transaction_source'] = self.native['runtime_lookup']['transaction_source'] = '/old/transaction.c'
        with self.assertRaisesRegex(ValueError, 'descriptor'):
            self.verify()

    def test_non_function_byte_change_rejected_even_with_updated_local_hashes(self):
        path = Path(self.native['runtime_lookup']['transaction_source'])
        path.write_bytes(path.read_bytes() + b'/* extra mutation */\n')
        sha = review.digest(path.read_bytes())
        self.native['compile_inputs_before'][str(path)] = self.native['compile_inputs_after'][str(path)] = sha
        update_lookup_manifest(self.receipt, self.native,
            lambda m: m['generated_files'].update({'window_bridge/window_runtime/transaction_v1.c': sha}))
        with self.assertRaisesRegex(ValueError, 'generated file identities'):
            self.verify()

    def test_changed_template_rejected_even_with_self_consistent_hashes(self):
        manifest_path = Path(self.receipt['runtime_lookup']['manifest_path'])
        manifest = json.loads(manifest_path.read_bytes())
        path = Path(next(n for n in manifest['templates'] if n.endswith('transaction_v1.c')))
        path.write_bytes(path.read_bytes() + b'/* extra mutation */\n')
        sha = review.digest(path.read_bytes())
        self.native['compile_inputs_before'][str(path)] = self.native['compile_inputs_after'][str(path)] = sha
        update_lookup_manifest(self.receipt, self.native, lambda m: m['templates'].update({str(path): sha}))
        with self.assertRaisesRegex(ValueError, 'template identity'):
            self.verify()

    def test_manifest_and_generated_source_must_be_actual_compiler_inputs(self):
        original = self.native['compile_inputs_before'].copy()
        for key in original:
            inputs = {k: v for k, v in original.items() if k != key}
            self.native['compile_inputs_before'] = self.native['compile_inputs_after'] = inputs
            review.OBSERVED.clear()
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'compiler'):
                self.verify()

    def test_old_transaction_in_dependency_list_is_rejected(self):
        old = next(n for n in self.native['compile_inputs_before'] if n.endswith('transaction_v1.c') and 'source with spaces' in n)
        text = self.native['dependency_graphs']['runtime'].rstrip() + ' ' + shlex.quote(old) + '\n'
        self.native['dependency_graphs']['runtime'] = text
        (self.product / 'native/runtime.d').write_text(text)
        with self.assertRaisesRegex(ValueError, 'wrong transaction'):
            self.verify()

    def test_actual_runtime_command_must_match_bound_source_and_object(self):
        path = self.product / 'native/commands/001-compile-runtime.json'
        original = json.loads(path.read_bytes())
        for update in ({'returncode': True}, {'returncode': 1}, {'argv': []}, {'label': 'compile-host'}):
            path.write_text(json.dumps({**original, **update})); review.OBSERVED.clear()
            with self.subTest(update=update), self.assertRaisesRegex(ValueError, 'compilation differs'):
                self.verify()

    def test_missing_runtime_command_and_changed_object_are_rejected(self):
        command = self.product / 'native/commands/001-compile-runtime.json'
        command.unlink()
        with self.assertRaisesRegex(ValueError, 'unique actual'):
            self.verify()
        review.OBSERVED.clear()
        Path(self.native['native_objects']['runtime']['path']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'hash differs'):
            self.verify()

    def test_manifest_schema_bool_and_extra_generated_file_rejected(self):
        for callback in (lambda m: m.update(schema=True),
                         lambda m: m['generated_files'].update({'extra.c': 'a' * 64})):
            self.product, self.receipt, self.native = lookup_fixture(Path(self.temporary.name).resolve() / str(len(list(Path(self.temporary.name).iterdir()))))
            update_lookup_manifest(self.receipt, self.native, callback)
            review.OBSERVED.clear()
            with self.assertRaises(ValueError):
                self.verify()


class IndependentReviewTests(unittest.TestCase):
    def test_real_event_transition_and_boundary7_counter_are_required(self):
        for kwargs in ({}, {'initial_position': 7, 'events': ['right', 'escape']},
                       {'initial_position': 0, 'events': ['left', 'right', 'close']},
                       {'initial_moves': 0xffffffff, 'initial_draws': 0xffffffff, 'events': ['right', 'escape']}):
            with self.subTest(kwargs=kwargs):
                result, profile, initial, actions = transition(**kwargs)
                self.assertEqual(review.event_state(result, profile, initial, actions), bytes.fromhex(result['saved_file']['data_hex']))

    def test_static_only_or_wrong_counter_cannot_prove_switch_runtime(self):
        original, profile, initial, actions = transition()
        for value in (0, 1, True, -1, 100):
            result = copy.deepcopy(original)
            result['switch_commits'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                review.event_state(result, profile, initial, actions)

    def test_missing_right_wrong_state_repeat_or_legacy_profile_is_rejected(self):
        original, profile, initial, actions = transition()
        invalid = []
        result = copy.deepcopy(original); result['observations']['window_state'] = initial.hex(); invalid.append((result, actions))
        result = copy.deepcopy(original); result['host_after_finish']['cocoa_key_events'] = 0; invalid.append((result, actions))
        invalid.append((original, {'events': ['left', 'escape']}))
        invalid.append((original, {'events': ['right', 'escape', 'right']}))
        result = copy.deepcopy(original)
        words = list(struct.unpack('<15I', bytes.fromhex(result['observations']['window_result'])))
        words[4] = 1; result['observations']['window_result'] = struct.pack('<15I', *words).hex(); invalid.append((result, actions))
        for index, (result, events) in enumerate(invalid):
            with self.subTest(index=index), self.assertRaises(ValueError):
                review.event_state(result, profile, initial, events)
        result, runtime_profile, image = normal_result()
        runtime_profile.update(schema=1, runtime_contract='win32-d3d11-tile-v1')
        with self.assertRaisesRegex(ValueError, 'versioned switch'):
            validation.validate_result(result, 0, runtime_profile, image, runtime_profile['pe_sha256'])

    def test_supervisor_rejects_v5_before_static_verifier_or_any_launch(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'result.json').write_text(json.dumps(dict(schema=1, profile='window-portable-v5', status=runner.pipeline.STATUS)))
            with mock.patch.object(runner.pipeline, 'verify', side_effect=AssertionError('must reject before verifier')), \
                 mock.patch.object(runner.subprocess, 'Popen', side_effect=AssertionError('must not launch')):
                with self.assertRaisesRegex(ValueError, 'only successful migration_v7'):
                    runner.load_product(root)

    def test_review_has_no_production_or_execution_imports_and_rejects_bad_pin(self):
        source = Path(review.__file__).read_text()
        names = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                names.update(alias.name.split('.')[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or '').split('.')[0])
        self.assertLessEqual(names, {'argparse', 'hashlib', 'json', 'pathlib', 'plistlib', 're', 'shlex', 'stat', 'struct', 'uuid'})
        with tempfile.TemporaryDirectory() as temporary:
            product = Path(temporary).resolve()
            with self.assertRaisesRegex(ValueError, 'explicit product receipt SHA'):
                review.review(product, [], 'not-a-hash')
            self.assertFalse((product / 'result.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
