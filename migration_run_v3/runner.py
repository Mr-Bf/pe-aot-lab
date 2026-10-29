"""Observe one migration_v6 App process; never select an App through UI APIs."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
import traceback
import uuid

from graphics_stage5 import d3d11_probe as g
from migration_v6 import build as pipeline
from window_switch_v1 import lift, package, producer
from window_switch_v1.profile import validate
from .validation import need, validate_result, validate_wrapper, image_uuid, validate_dyld

ROOT = lift.ROOT
BASE = ROOT / 'build/migration-run-v3'
STATUS = 'ACTUAL_SWITCH_V6_APP_EXECUTION_OBSERVED_NOT_ACCEPTED'
PROCESS_COMMAND = ['/bin/ps', '-ww', '-axo', 'pid=,ppid=,comm=']


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def canonical(path):
    path = Path(path).absolute()
    need(path == path.resolve(), 'canonical path without symlink traversal required')
    return path


def disjoint(out, *inputs):
    for item in inputs:
        item = canonical(item)
        need(not out.is_relative_to(item) and not item.is_relative_to(out), 'execution output overlaps an input/data directory')


def files(directory):
    directory = canonical(directory)
    if not directory.exists():
        return {}
    need(directory.is_dir(), 'data root must be a directory')
    values = {}
    total = 0
    for path in sorted(directory.rglob('*')):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'special data file or symlink')
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            need(info.st_nlink == 1 and info.st_size <= 64 * 1024 * 1024 and total <= 256 * 1024 * 1024,
                 'linked or oversized data file')
            values[str(path.relative_to(directory))] = dict(sha256=g.sha(path), size=info.st_size)
    return values


def snapshot_data(source, destination):
    """Copy only to evidence, then compare both frozen bytes and the live tree."""
    source, destination = canonical(source), canonical(destination)
    disjoint(destination, source)
    need(not destination.exists(), 'fresh snapshot destination required')
    existed = source.exists()
    before = files(source)
    if existed:
        shutil.copytree(source, destination, symlinks=True)
    need(source.exists() == existed and files(source) == before and files(destination) == before,
         'data changed while snapshotting')
    return dict(exists=existed, files=before)


def run_names(directory):
    directory = canonical(directory)
    if not directory.exists():
        return []
    need(directory.is_dir(), 'wrapper Runs path must be a directory')
    result = []
    for path in directory.iterdir():
        need(not path.is_symlink() and path.is_dir() and str(uuid.UUID(path.name)).upper() == path.name,
             'unexpected wrapper run directory')
        result.append(path.name)
    return sorted(result)


def process_rows(text):
    """Conservatively find this launcher basename at any location, with spaces."""
    result, seen = [], set()
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*([0-9]+)\s+([0-9]+)\s+(.+)', line)
        need(match is not None, 'unparseable OS process row')
        pid, ppid, executable = int(match[1]), int(match[2]), match[3]
        need(pid > 0 and pid not in seen, 'duplicate/invalid OS process PID')
        seen.add(pid)
        if Path(executable).name == 'pe-aot-window':
            need(executable.startswith('/') and executable.endswith('/Contents/MacOS/pe-aot-window'),
                 'ambiguous project launcher process path')
            result.append(dict(pid=pid, ppid=ppid, executable=executable))
    return result


def process_snapshot(out, phase):
    observed = time.time_ns()
    result = subprocess.run(PROCESS_COMMAND, capture_output=True, text=True, check=False)
    record = dict(command=PROCESS_COMMAND, returncode=result.returncode, observed_unix_ns=observed,
                  stdout=result.stdout, stderr=result.stderr)
    write(out / ('processes-' + phase + '.json'), record)
    need(result.returncode == 0, 'OS process query failed')
    record['matching_project_app_processes'] = process_rows(result.stdout)
    return record


def load_product(product):
    product = lift.path(product)
    raw = (product / 'result.json').read_bytes()
    receipt = g.strict_json(raw.decode())
    receipt_sha = hashlib.sha256(raw).hexdigest()
    need(type(receipt) is dict and type(receipt.get('schema')) is int and receipt['schema'] == 1 and
         receipt.get('profile') == 'window-switch-v6' and receipt.get('status') == pipeline.STATUS,
         'migration_run_v3 supports only successful migration_v6 window-switch-v6 products')
    pipeline.verify(product)  # Pure byte, Mach-O and package validation; no build or launch.
    profile, image, _ = validate((product / 'input.exe').read_bytes(), g.read_json(product / 'profile.json'))
    native = g.read_json(product / 'native/producer.json')
    need(native.get('status') == producer.STATUS and native.get('profile') == profile and
         native.get('input_sha256') == receipt['input_sha256'] == profile['pe_sha256'] and
         native.get('identifier') == receipt['spec']['identifier'], 'native/profile/product identity differs')
    need(g.read_json(product / 'native/profile.json') == profile, 'native explicit profile differs')
    g.same(receipt['sources'])
    need(g.sha(product / 'result.json') == receipt_sha, 'product receipt changed during validation')
    return receipt, profile, image, receipt_sha


def stop_child(child):
    """Only this Popen handle can be terminated; never kill another PID/App."""
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
    return child.returncode


def verify_unchanged(product, receipt_sha, app, app_tree, sources):
    pipeline.verify(product)
    need(g.sha(product / 'result.json') == receipt_sha, 'product receipt changed during run')
    need(package.formats.tree(app) == app_tree, 'executed App changed during run')
    g.same(sources)


def run(product, out, relocate=False, timeout=180):
    product, out = lift.path(product), canonical(out)
    need(out.parent == BASE and not out.exists(), 'fresh direct migration-run-v3 evidence directory required')
    need(type(timeout) is int and 30 <= timeout <= 600 and type(relocate) is bool, 'invalid supervision configuration')
    receipt, profile, image, receipt_sha = load_product(product)
    original_app = Path(receipt['app'])
    identifier = receipt['spec']['identifier']
    support = canonical(Path.home() / 'Library/Application Support' / identifier)
    data, runs = support / 'Data', support / 'Runs'
    disjoint(out, product, original_app, support)
    out.mkdir(parents=True)
    sources = lift.snapshot([*lift.source_closure([Path(__file__), Path(__file__).with_name('__main__.py')]),
                             *receipt['sources'], product / 'result.json'])
    record = dict(schema=2, status='STARTED_NOT_ACCEPTED', supported_product_profile='window-switch-v6',
                  product=str(product), native_directory=str(product / 'native'), uid=os.geteuid(),
                  product_receipt_sha256=receipt_sha, input_sha256=receipt['input_sha256'],
                  cpu_provider_sha256=receipt['cpu_provider_sha256'], graphics_provider_sha256=receipt['graphics_provider_sha256'],
                  profile_sha256=receipt['profile_sha256'], switch_leaf_rva=profile['switch_leaf_rva'], identifier=identifier,
                  relocated_copy=relocate, timeout_seconds=timeout, started_unix_ns=time.time_ns(),
                  launch_kind='direct bundled executable, argc=1; not Finder/LaunchServices',
                  input_kind='external Cocoa OS events; no physical keyboard or TEST_QUEUE claim',
                  expected_support=str(support), sources=sources,
                  scope='one process observation; independent review required; no pixel/performance or competitive lock test')
    write(out / 'started.json', record)
    app, child = original_app, None
    try:
        if relocate:
            app = out / 'relocated with spaces' / original_app.name
            app.parent.mkdir()
            shutil.copytree(original_app, app)
        need(package.formats.tree(app) == receipt['app_tree'], 'App copy bytes/modes differ')
        graph = package.graph(app, receipt['spec'], receipt['minimum_macos'])
        exe = package.formats.executable(app)
        images = {name: image_uuid(Path(name)) for name in graph['nodes']}
        record.update(app=str(app), app_tree=receipt['app_tree'], executable_sha256=g.sha(exe),
                      expected_images=images, command=[str(exe)], argv_count=1,
                      processes_before=process_snapshot(out, 'before'), existing_run_directories=run_names(runs))
        need(not record['processes_before']['matching_project_app_processes'], 'another project launcher is already running')
        record['data_before'] = snapshot_data(data, out / 'data-before')
        (out / 'cache/dxmt').mkdir(parents=True)
        write(out / 'prepared.json', record)
        stdout, stderr = out / 'stdout', out / 'stderr'
        environment = g.environment(out, images=True)
        write(out / 'launch-environment.json', environment)
        with stdout.open('xb') as output, stderr.open('xb') as errors:
            child = subprocess.Popen([str(exe)], stdout=output, stderr=errors, env=environment, cwd=out)
            record.update(pid=child.pid, launched_unix_ns=time.time_ns())
            write(out / 'launched.json', dict(pid=child.pid, command=[str(exe)], cwd=str(out),
                                             launched_unix_ns=record['launched_unix_ns']))
            print(json.dumps(dict(status='LIVE_NATIVE_APP_PROCESS', pid=child.pid, app=str(app), identifier=identifier)), flush=True)
            timed_out = False
            try:
                code = child.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                code = stop_child(child)
        record.update(returncode=code, external_timeout=timed_out, ended_unix_ns=time.time_ns(),
                      stdout_sha256=g.sha(stdout), stderr_sha256=g.sha(stderr),
                      data_after=snapshot_data(data, out / 'data-after'), processes_after=process_snapshot(out, 'after'))
        after_runs = run_names(runs)
        need(set(record['existing_run_directories']) <= set(after_runs), 'pre-existing wrapper run disappeared')
        new_runs = sorted(set(after_runs) - set(record['existing_run_directories']))
        record['new_run_directories'] = new_runs
        for name in new_runs:
            snapshot_data(runs / name, out / 'wrapper-runs' / name)
        verify_unchanged(product, receipt_sha, app, receipt['app_tree'], sources)
        record['product_app_sources_unchanged'] = True
        need(not timed_out and type(code) is int and code == 0, 'App did not exit normally within supervision')
        need(not record['processes_after']['matching_project_app_processes'], 'a project App remains running; no cleanup/retry')
        result = g.strict_json(stdout.read_text())
        saved = validate_result(result, code, profile, image, receipt['input_sha256'])
        record['result'] = result
        need(len(new_runs) == 1, 'exactly one new wrapper run expected')
        wrapper = out / 'wrapper-runs' / new_runs[0]
        need(set(files(wrapper)) == {'entry-started.json', 'entry-finished.json'}, 'wrapper record file set differs')
        validate_wrapper(g.read_json(wrapper / 'entry-started.json'), g.read_json(wrapper / 'entry-finished.json'),
                         pid=child.pid, run_id=new_runs[0], identifier=identifier, app=app, data=data, runs=runs, uid=os.geteuid())
        need((out / 'data-after' / profile['save_observation']).read_bytes() == saved, 'frozen disk save differs from guest observation')
        record['loaded_images'] = validate_dyld(stderr.read_text(), child.pid, images)
        record['dyld_pid'] = child.pid
        # Validate after all reads as well; subsequent live saves are not read by review.
        verify_unchanged(product, receipt_sha, app, receipt['app_tree'], sources)
        record['status'] = STATUS
    except BaseException as error:
        if child is not None:
            record['failure_cleanup_returncode'] = stop_child(child)
        (out / 'failure.txt').write_text(traceback.format_exc())
        record.update(status='FAIL_NOT_ACCEPTED', error_type=type(error).__name__, error=str(error))
        write(out / 'evidence.json', record)
        raise
    write(out / 'evidence.json', record)
    print(json.dumps(dict(status=record['status'], pid=record['pid'], returncode=record['returncode'],
                         steps=record['result']['steps'], switch_commits=record['result']['switch_commits'], save=record['result']['saved_file']), indent=2), flush=True)
    return record
