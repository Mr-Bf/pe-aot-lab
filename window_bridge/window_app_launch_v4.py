"""One output-location diagnostic over the exact frozen v3 supervisor.

Default is read-only. --run is the only App-launching mode. The target App and
all launch/identity/watch/timeout logic stay unchanged; records live in a fresh
private /private/tmp parent and are copied, never moved, back into the project.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys
import types

from window_bridge import window_app_launch_v3 as baseline
from window_bridge import noarg_tmpio_v1 as tmpio

BASELINE_SHA = '5ffa8edd5f7cb2729391489e44e42a4868a240746ecbca480c7c7adb2222fc86'


def require(value, message):
    if not value: raise ValueError(message)


def derivation():
    path = Path(baseline.__file__).resolve(); raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == BASELINE_SHA, 'frozen v3 source changed')
    original = raw.decode(); parsed = ast.parse(original)
    nodes = [n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == 'output']
    require(len(nodes) == 1, 'one frozen output function required')
    node = nodes[0]
    old_output = ''.join(original.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
    changes = [
        ('output_path_validator', old_output, 'def output(path):\n    return tmpio.output(path)\n'),
        ('private_output_import', 'from window_bridge import kqueue_exit_v1 as exit_observer\n',
         'from window_bridge import kqueue_exit_v1 as exit_observer\nfrom window_bridge import noarg_tmpio_v1 as tmpio\n'),
        ('default_output', "OUT = ROOT / 'build/window-bridge/window-run-app-v3-ls-01'\n", 'OUT = None\n'),
        ('observation_scope', "SCOPE = ('one no-argument LaunchServices observation of the fixed save/load PE; '\n",
         "SCOPE = ('v4 private-tmp-output comparison; one no-argument LaunchServices observation of the fixed save/load PE; '\n"),
    ]
    derived = original
    for name, old, new in changes:
        require(derived.count(old) == 1, 'exact unique source replacement required: ' + name)
        derived = derived.replace(old, new, 1)
    restored = derived
    for name, old, new in reversed(changes):
        require(restored.count(new) == 1, 'exact reverse replacement required: ' + name)
        restored = restored.replace(new, old, 1)
    require(restored == original, 'non-output supervisor logic changed')
    source_paths = [Path(__file__).resolve(), path, Path(tmpio.__file__).resolve()]
    proof = {'schema': 1, 'status': 'EXACT_OUTPUT_LOCATION_DERIVATION',
             'baseline_source_sha256': BASELINE_SHA, 'derived_source_sha256': hashlib.sha256(derived.encode()).hexdigest(),
             'restored_baseline_sha256': hashlib.sha256(restored.encode()).hexdigest(),
             'changed_regions': [name for name, _, _ in changes],
             'source_sha256': {str(p): tmpio.sha(p) for p in source_paths},
             'unchanged': 'App/entry/launch argv/identity/kqueue/timeout/cleanup/observation logic'}
    return derived, proof


def module():
    source, proof = derivation()
    value = types.ModuleType('window_bridge._v4_exact_v3_derivation')
    value.__file__ = str(Path(__file__).resolve())
    value.__package__ = 'window_bridge'
    # __file__ binds the executed recipe plus its statically imported baseline
    # and tmpio implementation into v3's existing Python source-closure reader.
    # The exact derived source bytes are also persisted before any target start.
    exec(compile(source, '<exact v3 output-location derivation>', 'exec'), value.__dict__)
    return value, source, proof


def verify_derivation(records):
    records = tmpio.output(records); parent = records.parent
    source, proof = derivation()
    require((parent / 'derived-supervisor.py').read_bytes() == source.encode() and
            json.loads((parent / 'derivation.json').read_text()) == proof,
            'persisted exact derived source/proof differs')
    return proof


def execute(*, records, archive_out, timeout, preflight):
    archive_out = tmpio.archive_output(archive_out)
    require(not archive_out.exists(), 'archive destination cannot be reused')
    records = tmpio.allocate() if records is None else tmpio.output(records)
    require(not records.exists() and not any(records.parent.iterdir()), 'private output parent cannot be reused')
    driver, source, proof = module()
    with (records.parent / 'derived-supervisor.py').open('x') as stream: stream.write(source)
    tmpio.write(records.parent / 'derivation.json', proof)
    tmpio.write(records.parent / 'coordinator-started.json', {
        'status': 'PREFLIGHT_ONLY' if preflight else 'LAUNCH_REQUEST_PREPARED_NOT_ACCEPTED',
        'original_records': str(records), 'archive_destination': str(archive_out), 'timeout_seconds': timeout,
        'derivation_sha256': tmpio.sha(records.parent / 'derivation.json'),
        'scope': 'output path comparison only; no events or permission requests'})
    print(json.dumps({'private_records': str(records), 'archive_destination': str(archive_out),
                      'mode': 'preflight_no_target' if preflight else 'one_actual_launch'}), flush=True)
    result = None; failure = None
    try:
        result = driver.preflight(records, timeout) if preflight else driver.run(records, timeout)
    except BaseException as problem:
        failure = {'type': type(problem).__name__, 'message': str(problem)}
    try:
        verify_derivation(records)
    except BaseException as problem:
        failure = {'type': type(problem).__name__, 'message': 'derivation identity after attempt: ' + str(problem),
                   'earlier_failure': failure}
    # This sibling record is written after the unchanged supervisor has finished
    # cleanup. It is outside its observation artifact closure and never edits it.
    tmpio.write(records.parent / 'coordinator-finished.json', {
        'status': 'OBSERVATION_RETURNED_NOT_ACCEPTED' if failure is None else 'ATTEMPT_FAILED_PRESERVED',
        'result': result, 'failure': failure, 'original_records': str(records),
        'scope': 'archival status does not establish a successful App or game result'})
    archive = tmpio.archive(records, archive_out)
    if failure is not None:
        raise ValueError('attempt failed; original tmp and byte-identical archive retained: ' + str(archive_out))
    return {'result': result, 'archive': archive, 'App_acceptance': False}


def verify(archive_out, *, archive_only=False):
    summary = tmpio.verify_archive(archive_out)
    records = Path(summary['original_records']); verify_derivation(records)
    if archive_only:
        return {'archive': summary, 'source_derivation_current': True, 'App_acceptance': False}
    driver, _, _ = module()
    # The frozen observer's failure gate is preserved: a failed attempt cannot
    # become complete observation merely because its archive is valid.
    result = driver.verify(records)
    return {'result': result, 'archive': summary, 'App_acceptance': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, help='optional preallocated empty private records path for run/preflight')
    parser.add_argument('--archive-out', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(); mode.add_argument('--run', action='store_true')
    mode.add_argument('--preflight', action='store_true'); mode.add_argument('--verify-archive-only', action='store_true')
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    if args.run or args.preflight:
        value = execute(records=args.out, archive_out=args.archive_out, timeout=args.timeout, preflight=args.preflight)
    else:
        require(args.out is None, 'read-only mode resolves original tmp path from archive')
        value = verify(args.archive_out, archive_only=args.verify_archive_only)
    print(json.dumps(value, indent=2, sort_keys=True))
