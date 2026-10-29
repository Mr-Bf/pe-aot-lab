#!/usr/bin/env python3
"""Test evidence consistency by in-memory mutation; never replace suite records.

Run with /opt/homebrew/bin/python3.13 integration_stage3/test_evidence_gate.py.
This tests stale/contradictory evidence rejection, not signatures or hostile forgery.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
OUT = ROOT / 'build/integration-stage3/review'
SPEC = importlib.util.spec_from_file_location('stage3_evidence_gate', HERE / 'run_tests.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_tests():
    evidence_paths = [gate.OUT / relative for relative in gate.PARTS.values()]
    if (gate.OUT / 'evidence.json').exists():
        evidence_paths.append(gate.OUT / 'evidence.json')
    before = {str(path): digest(path) for path in evidence_paths}
    positive = gate.verify()
    assert positive['status'] == 'PASS'
    original_read = gate.read_json
    original_sha = gate.sha
    cache = {}

    def cached_sha(path):
        path = Path(path).resolve()
        if path not in cache:
            cache[path] = original_sha(path)
        return cache[path]

    results = []

    def expect_rejection(name, operation):
        try:
            operation()
        except (RuntimeError, KeyError, TypeError, ValueError) as error:
            results.append({'case': name, 'status': 'REJECT', 'reason': str(error)})
        else:
            raise AssertionError('inconsistent evidence was accepted: ' + name)

    def mutate_document(name, relative, transform):
        target = (gate.OUT / relative).resolve()

        def injected_read(path):
            document = original_read(path)
            if Path(path).resolve() == target:
                document = copy.deepcopy(document)
                transform(document)
            return document

        with mock.patch.object(gate, 'read_json', side_effect=injected_read), \
             mock.patch.object(gate, 'sha', side_effect=cached_sha):
            expect_rejection(name, gate.verify)

    def set_key(key, value):
        return lambda document: document.__setitem__(key, value)

    def alter_record(key, index, field, value):
        return lambda document: document[key][index].__setitem__(field, value)

    def duplicate(key):
        return lambda document: document[key].append(copy.deepcopy(document[key][0]))

    mutations = [
        ('lifter_rejected_false', 'lifter-checks/results.json', alter_record('cases', 0, 'rejected', False)),
        ('lifter_reason_empty', 'lifter-checks/results.json', alter_record('cases', 0, 'reason', '  ')),
        ('lifter_wrong_count', 'lifter-checks/results.json', set_key('count', 999)),
        ('lifter_duplicate_fixture', 'lifter-checks/results.json', duplicate('cases')),
        ('lifter_empty_cases', 'lifter-checks/results.json', set_key('cases', [])),
        ('lifter_old_build_identity', 'lifter-checks/results.json', set_key('build_manifest_sha256', '0' * 64)),
        ('lifter_old_binary_identity', 'lifter-checks/results.json', set_key('lifter_sha256', '0' * 64)),
        ('lifter_old_semantics_identity', 'lifter-checks/results.json', set_key('semantics_sha256', '0' * 64)),
        ('lifter_missing_producer_sources', 'lifter-checks/results.json', set_key('source_sha256', {})),
        ('lifter_missing_test_source', 'lifter-checks/results.json', lambda d: d['source_sha256'].pop('integration_stage3/lifter_checks.py')),
        ('memory_nested_fail', 'memory/evidence.json', alter_record('samples', 0, 'status', 'FAIL')),
        ('memory_wrong_total', 'memory/evidence.json', set_key('functional_cases', 1)),
        ('memory_boolean_case_count', 'memory/evidence.json', alter_record('samples', 0, 'cases', True)),
        ('memory_duplicate_fixture', 'memory/evidence.json', duplicate('samples')),
        ('memory_empty_samples', 'memory/evidence.json', set_key('samples', [])),
        ('memory_boundary_fail', 'memory/evidence.json', alter_record('boundaries', 0, 'status', 'FAIL')),
        ('calls_nested_fail', 'calls/evidence.json', alter_record('functional', 0, 'status', 'FAIL')),
        ('calls_wrong_total', 'calls/evidence.json', set_key('functional_cases', 1)),
        ('calls_duplicate_fixture', 'calls/evidence.json', duplicate('functional')),
        ('calls_no_native_artifacts', 'calls/evidence.json', set_key('native_artifacts', {})),
        ('calls_not_original_bytes', 'calls/evidence.json', set_key('original_byte_oracle', False)),
        ('calls_expected_reject_is_pass', 'calls/evidence.json', alter_record('rejections', 0, 'status', 'PASS')),
        ('calls_missing_reject_reason', 'calls/evidence.json', alter_record('rejections', 0, 'reason', '')),
        ('calls_duplicate_rejection', 'calls/evidence.json', duplicate('rejections')),
        ('calls_duplicate_boundary', 'calls/evidence.json', duplicate('boundary_checks')),
        ('image_nested_fail', 'image-integration/evidence.json', alter_record('records', 0, 'status', 'FAIL')),
        ('image_empty_records', 'image-integration/evidence.json', set_key('records', [])),
        ('image_duplicate_record', 'image-integration/evidence.json', duplicate('records')),
        ('image_no_source_hashes', 'image-integration/evidence.json', set_key('source_sha256', {})),
        ('image_missing_runtime_source', 'image-integration/evidence.json', lambda d: d['source_sha256'].pop('integration_stage3/runtime.c')),
        ('image_no_tested_artifacts', 'image-integration/evidence.json', set_key('tested_artifact_sha256', {})),
        ('sanitizer_wrong_total', 'sanitizers/evidence.json', set_key('cases', 1)),
        ('sanitizer_missing_category', 'sanitizers/evidence.json', lambda d: d['outcomes'].pop('bad_return')),
        ('sanitizer_negative_outcome', 'sanitizers/evidence.json', lambda d: d['outcomes'].__setitem__('bounds', -1)),
        ('sanitizer_zero_required_category', 'sanitizers/evidence.json', lambda d: d['outcomes'].__setitem__('protection', 0)),
        ('sanitizer_no_instrumented_function', 'sanitizers/evidence.json', set_key('lifted_functions_instrumented', 0)),
        ('sanitizer_no_compiler_rt', 'sanitizers/evidence.json', set_key('compiler_rt', {})),
        ('sanitizer_false_redistribution_scope', 'sanitizers/evidence.json', lambda d: d['compiler_rt'].__setitem__('scope', 'product dependency')),
        ('module_empty_artifacts', 'memory/sum/manifest.json', set_key('artifact_sha256', {})),
        ('module_empty_sources', 'memory/sum/manifest.json', set_key('source_sha256', {})),
        ('module_missing_external_source', 'memory/sum/manifest.json', set_key('external_source_sha256', {})),
        ('module_empty_instruction_approval', 'memory/sum/manifest.json', set_key('instructions', [])),
        ('module_wrong_semantics', 'memory/sum/manifest.json', set_key('semantics_sha256', '0' * 64)),
        ('build_empty_patches', 'lifter/build-manifest.json', set_key('patch_sha256', {})),
        ('native_wrong_input_identity', 'memory/sum/native-artifact.json', set_key('input_sha256', '0' * 64)),
    ]
    for args in mutations:
        mutate_document(*args)

    sanitizer = original_read(gate.OUT / 'sanitizers/evidence.json')
    build = original_read(gate.OUT / 'lifter/build-manifest.json')
    hash_targets = [
        ('instrumented_ir_changed', gate.OUT / 'sanitizers/instrumented.ll'),
        ('actual_compiler_rt_changed', Path(sanitizer['compiler_rt']['path'])),
        ('actual_semantics_changed', Path(build['lifter']).parents[2] / 'lib/Arch/X86/Runtime/amd64.bc'),
    ]
    for name, target in hash_targets:
        target = target.resolve()

        def changed_sha(path):
            return '0' * 64 if Path(path).resolve() == target else cached_sha(path)

        with mock.patch.object(gate, 'sha', side_effect=changed_sha):
            expect_rejection(name, gate.verify)

    # JSON-level duplicate keys must not silently overwrite a prior status.
    with tempfile.TemporaryDirectory(prefix='pe-aot-evidence-gate-') as directory:
        path = Path(directory) / 'duplicate.json'
        path.write_text('{"status":"FAIL","status":"PASS"}\n')
        expect_rejection('duplicate_json_status_key', lambda: original_read(path))

    assert before == {str(path): digest(path) for path in evidence_paths}, 'formal evidence changed'
    return {
        'status': 'PASS',
        'positive_current_evidence': {key: positive[key] for key in
            ('status', 'original_byte_differential_cases', 'sanitizer_cases', 'lifter_rejections', 'dependency_scope')},
        'rejected_mutations': len(results), 'negative_cases': results,
        'formal_evidence_unchanged': True,
        'source_sha256': {str(path.relative_to(ROOT)): digest(path) for path in
                         (HERE / 'run_tests.py', Path(__file__).resolve())},
        'child_evidence_sha256': {name: digest(gate.OUT / relative) for name, relative in gate.PARTS.items()},
        'scope': 'in-memory consistency/staleness gate tests; no formal evidence mutation; not digital signatures or hostile-forgery protection',
    }


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / 'evidence-gate.json'
    path.write_text('{"status":"RUNNING"}\n')
    try:
        report = run_tests()
        path.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'rejected_mutations': report['rejected_mutations'],
                          'formal_evidence_unchanged': report['formal_evidence_unchanged']}))
    except Exception as error:
        path.write_text(json.dumps({'status': 'FAIL', 'error': str(error)}, indent=2) + '\n')
        raise


if __name__ == '__main__':
    main()
