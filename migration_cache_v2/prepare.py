"""Resume only attested v1 LLVM bytes into a fresh attempt; keep v1 immutable."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import time
import urllib.error
import urllib.request

from migration_cache_v1 import prepare as previous, sources
from portable_lifter_v1 import build, deps, tools

require, digest, write, now = previous.require, previous.digest, previous.write, previous.now
CHUNK_BYTES = 16 * 1024 * 1024
RESUME_PACKAGE = 'llvm17.tar.gz'
STATUS = 'CPU_PUBLIC_CACHE_READY_NOT_BUILT'


def regular(path):
    require(path == path.resolve() and path.is_file() and not path.is_symlink() and
            path.stat().st_nlink == 1, 'regular single-link input required: ' + str(path))


def read_json(path):
    regular(path)
    require(path.stat().st_size <= 8 * 1024 * 1024, 'oversized resume metadata')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate resume metadata key')
            result[key] = value
        return result
    raw = path.read_bytes()
    value = json.loads(raw, object_pairs_hook=pairs)
    require(type(value) is dict, 'resume metadata object required')
    return value, hashlib.sha256(raw).hexdigest()


def v1_inputs():
    return [*sorted(Path(previous.__file__).parent.glob('*.py')), sources.LOCK,
            Path(tools.__file__), Path(deps.__file__), Path(build.__file__)]


def inspect_resume(origin, plan):
    """Read and bind the failed v1 attempt. This never changes its files."""
    origin = tools.real_path(origin)
    require(origin.is_dir() and not (origin / 'result.json').exists() and not (origin / 'result.json').is_symlink(),
            'failed v1 acquisition directory required')
    identities = {}
    def read(relative):
        path = origin / relative
        value, fingerprint = read_json(path)
        identities[str(path)] = fingerprint
        return value
    started = read('started.json')
    failed = read('failure.json')
    package_start = read('logs/' + RESUME_PACKAGE + '.started.json')
    package_failure = read('logs/' + RESUME_PACKAGE + '.failure.json')
    require(started.get('schema') == 1 and started.get('plan') == plan,
            'resume plan differs from fixed CPU acquisition plan')
    require(failed.get('schema') == 1 and failed.get('status') == 'CPU_PUBLIC_CACHE_PREPARATION_FAILED' and
            package_failure.get('status') == 'DOWNLOAD_FAILED' and
            failed.get('error') == package_failure.get('error'), 'resume attempt must have matching download failure')
    expected_sources = {str(path.relative_to(sources.ROOT)): digest(path) for path in v1_inputs()}
    require(started.get('sources') == expected_sources, 'resume v1 implementation differs')
    for relative, expected in expected_sources.items():
        snapshot = origin / 'implementation' / relative
        regular(snapshot)
        require(digest(snapshot) == expected, 'resume implementation snapshot differs: ' + relative)
        identities[str(snapshot)] = expected
    expected = plan['packages'][RESUME_PACKAGE]
    require(package_start.get('name') == RESUME_PACKAGE and package_start.get('url') == expected['url'] and
            package_start.get('sha256_expected') == expected['sha256'] and
            package_start.get('credential_source') == 'anonymous-public-pull', 'resume package identity differs')
    require(all(package_failure.get(key) == value for key, value in package_start.items()),
            'resume package start/failure binding differs')
    require(type(started.get('cache')) is str, 'resume cache path absent')
    cache = tools.real_path(started['cache'])
    require(cache.is_dir(), 'resume cache absent')
    partial = cache / (RESUME_PACKAGE + '.partial')
    regular(partial)
    # This narrow recovery is for the first v1 package only. Other caches or a
    # completed package cannot be silently imported through this option.
    require({path.name for path in cache.iterdir()} == {partial.name}, 'resume cache must contain only failed LLVM prefix')
    completion = origin / 'logs' / (RESUME_PACKAGE + '.result.json')
    require(not completion.exists() and not completion.is_symlink(), 'successful package cannot be resumed')
    info = package_failure.get('partial')
    require(type(info) is dict and info.get('path') == str(partial) and type(info.get('bytes')) is int and
            0 < info['bytes'] < previous.MAX_DOWNLOAD_BYTES and partial.stat().st_size == info['bytes'],
            'resume partial path or length differs')
    actual = digest(partial)
    require(info.get('sha256') == actual, 'resume partial hash differs')
    identities[str(partial)] = actual
    return {'origin': str(origin), 'package': RESUME_PACKAGE, 'partial': str(partial),
            'bytes': info['bytes'], 'sha256': actual, 'sha256_expected': expected['sha256'],
            'origin_files': identities, 'scope': 'explicit failed-public-download prefix; completeness not yet verified'}


def check_origin(record):
    for name, expected in record['origin_files'].items():
        path = Path(name); regular(path)
        require(digest(path) == expected, 'resume origin changed: ' + name)


def copy_resume(record, cache):
    check_origin(record)
    target = cache / (record['package'] + '.partial')
    with Path(record['partial']).open('rb') as original, target.open('xb') as copied:
        shutil.copyfileobj(original, copied, length=1024 * 1024)
    require(target.stat().st_size == record['bytes'] and digest(target) == record['sha256'],
            'resumed prefix copy differs')
    check_origin(record)
    return target


def range_identity(response, start, requested_end, known_total):
    require(response.status == 206, 'Range request requires HTTP 206; no full-download fallback')
    content_range = response.headers.get('Content-Range', '')
    match = re.fullmatch(r'bytes ([0-9]+)-([0-9]+)/([0-9]+)', content_range)
    require(match is not None, 'valid numeric Content-Range required')
    first, last, total = map(int, match.groups())
    require(0 < total <= previous.MAX_DOWNLOAD_BYTES and first == start and
            first <= last == min(requested_end, total - 1), 'Content-Range bounds differ')
    require(known_total is None or total == known_total, 'Content-Range total changed')
    length = response.headers.get('Content-Length')
    require(type(length) is str and length.isdigit() and int(length) == last - first + 1,
            'range Content-Length differs')
    require(response.headers.get('Content-Encoding', 'identity') == 'identity',
            'encoded byte ranges are not accepted')
    return {'start': first, 'end': last, 'total': total, 'bytes': int(length),
            'http_status': response.status, 'content_range': content_range, 'content_length': length}


def observe_response(response, path):
    headers = {}
    truncated = []
    for name in ('Content-Range', 'Content-Length', 'Content-Encoding'):
        value = response.headers.get(name)
        if value is not None and (type(value) is not str or len(value) > 1024):
            truncated.append(name)
            value = value[:1024] if type(value) is str else '<non-string>'
        headers[name] = value
    write(path, {'http_status': response.status, 'headers': headers, 'truncated_fields': truncated})
    require(not truncated, 'range response headers exceed recording bounds')


def download_ranges(name, spec, cache, logs, prefix=None, client=None):
    require(spec['kind'] == 'ghcr', 'bounded ranges currently apply only to GHCR bottles')
    client = client or previous.opener()
    partial, final = cache / (name + '.partial'), cache / name
    require(not final.exists() and not final.is_symlink(), 'preserve existing final archive')
    if prefix is None:
        with partial.open('xb'):
            pass
        position = 0
    else:
        require(prefix['package'] == name and prefix['sha256_expected'] == spec['sha256'], 'range prefix package differs')
        regular(partial)
        require(partial.stat().st_size == prefix['bytes'] and digest(partial) == prefix['sha256'], 'range prefix identity differs')
        position = prefix['bytes']
    record = {'name': name, 'url': spec['url'], 'sha256_expected': spec['sha256'], 'started_at': now(),
              'credential_source': 'anonymous-public-pull', 'chunk_bytes': CHUNK_BYTES,
              'resumed_bytes': position, 'resumed_prefix_sha256': prefix['sha256'] if prefix else None}
    write(logs / (name + '.started.json'), record)
    total = None
    segments = []
    started = time.monotonic()
    try:
        while total is None or position < total:
            require(time.monotonic() - started <= previous.DOWNLOAD_SECONDS, 'ranged archive overall timeout')
            requested_end = position + CHUNK_BYTES - 1
            if total is not None:
                requested_end = min(requested_end, total - 1)
            stem = logs / (name + f'.range-{len(segments) + 1:03d}')
            segment = {'url': spec['url'], 'requested_start': position, 'requested_end': requested_end, 'started_at': now()}
            write(Path(str(stem) + '.started.json'), segment)
            try:
                token = previous.token_for(spec['repository'], client)
                request = urllib.request.Request(spec['url'], headers={
                    'User-Agent': 'pe-aot-lab-cache/2', 'Accept-Encoding': 'identity',
                    'Range': f'bytes={position}-{requested_end}', 'Authorization': 'Bearer ' + token})
                with client.open(request, timeout=previous.SOCKET_SECONDS) as response:
                    observe_response(response, Path(str(stem) + '.response.json'))
                    identity = range_identity(response, position, requested_end, total)
                    # One bounded segment stays in memory until its complete
                    # payload is present. A short response never extends the
                    # known-good prefix in the new attempt.
                    payload = bytearray()
                    while len(payload) <= identity['bytes']:
                        require(time.monotonic() - started <= previous.DOWNLOAD_SECONDS, 'ranged archive overall timeout')
                        chunk = response.read(min(1024 * 1024, identity['bytes'] + 1 - len(payload)))
                        if not chunk:
                            break
                        payload.extend(chunk)
                    require(len(payload) == identity['bytes'], 'range payload length differs')
                with partial.open('ab') as output:
                    require(output.tell() == position, 'range partial length changed')
                    output.write(payload)
                position += len(payload)
                total = identity['total']
                result = dict(segment, **identity, status='RANGE_APPENDED',
                              payload_sha256=hashlib.sha256(payload).hexdigest(), finished_at=now())
                write(Path(str(stem) + '.result.json'), result)
                segments.append(result)
                print('RANGE ' + name + ' ' + str(position) + '/' + str(total), flush=True)
            except BaseException as error:
                response_path = Path(str(stem) + '.response.json')
                if isinstance(error, urllib.error.HTTPError) and not response_path.exists():
                    try:
                        observe_response(error, response_path)
                    except ValueError:
                        pass  # Bounded fields are retained; preserve the original HTTP failure.
                write(Path(str(stem) + '.failure.json'), dict(segment, status='RANGE_FAILED',
                      error=previous.error_record(error), finished_at=now()))
                raise
        require(partial.stat().st_size == total, 'final ranged archive size differs')
        identity = previous.publish(partial, final, spec['sha256'])
        result = dict(record, **identity, status='RANGED_DOWNLOAD_AND_HASH_VERIFIED',
                      segments=segments, finished_at=now())
        write(logs / (name + '.result.json'), result)
        return result
    except BaseException as error:
        failure = dict(record, status='DOWNLOAD_FAILED', finished_at=now(), error=previous.error_record(error),
                       partial={'path': str(partial), 'bytes': partial.stat().st_size, 'sha256': digest(partial)},
                       accepted_segments=len(segments))
        write(logs / (name + '.failure.json'), failure)
        raise


def prepare_cpu(cache, out, resume_from=None):
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required')
    cache, out = map(tools.real_path, (cache, out))
    require(not cache.exists() and not out.exists(), 'fresh absent cache and evidence directories required')
    require(not cache.is_relative_to(out) and not out.is_relative_to(cache), 'cache/evidence must be disjoint')
    plan = sources.plan()
    resume = inspect_resume(resume_from, plan) if resume_from is not None else None
    if resume is not None:
        for old in (Path(resume['origin']), Path(resume['partial']).parent):
            require(all(not path.is_relative_to(old) and not old.is_relative_to(path) for path in (cache, out)),
                    'new attempt must be disjoint from resume origin')
    out.mkdir(parents=True)
    (out / 'logs').mkdir()
    inputs = [*sorted(Path(__file__).parent.glob('*.py')), *v1_inputs()]
    snapshots = {}
    for source in inputs:
        relative = source.relative_to(sources.ROOT)
        target = out / 'implementation' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        snapshots[str(relative)] = digest(target)
        require(digest(source) == snapshots[str(relative)], 'implementation changed during snapshot')
    write(out / 'started.json', {'schema': 2, 'started_at': now(), 'cache': str(cache), 'plan': plan,
                                'sources': snapshots, 'resume': resume,
                                'scope': 'bounded GHCR ranges; explicit failed-v1 LLVM prefix; other inputs use v1 acquisition'})
    try:
        cache.mkdir(parents=True)
        if resume is not None:
            copy_resume(resume, cache)
            write(out / 'resume-copy.json', dict(resume, copied_to=str(cache / (RESUME_PACKAGE + '.partial')),
                                               copied_at=now(), status='PREFIX_COPIED_NOT_COMPLETE'))
        run = previous.GitRecorder(out)
        version = run(['--version'], 'git-version').decode().strip()
        records = {'schema': 1, 'status': 'PREPARING', 'packages': {}, 'sources': {}}
        for name, spec in plan['packages'].items():
            print('DOWNLOAD ' + name, flush=True)
            if spec['kind'] == 'ghcr':
                records['packages'][name] = download_ranges(name, spec, cache, out / 'logs',
                    prefix=resume if resume is not None and name == RESUME_PACKAGE else None)
            else:
                records['packages'][name] = previous.download(name, spec, cache, out / 'logs')
        for name, spec in plan['sources'].items():
            print('FETCH ' + name, flush=True)
            records['sources'][name] = previous.acquire_source(name, spec, cache, out, run)
        require(all(digest(sources.ROOT / name) == value for name, value in snapshots.items()),
                'implementation/lock changed during acquisition')
        if resume is not None:
            check_origin(resume)
        records['status'] = 'PINNED_PUBLIC_INPUTS_MATERIALIZED'
        write(cache / 'cache.json', records)
        verified = previous.validate(cache)
        result = {'schema': 2, 'status': STATUS, 'cache': str(cache), 'git_version': version,
                  'package_count': 9, 'finished_at': now(), 'cache_metadata_sha256': digest(cache / 'cache.json'),
                  'validation': verified, 'sources': snapshots, 'resume': resume,
                  'scope': 'CPU cache only; explicit public prefix reuse is not a fresh full download, build or performance claim'}
        write(out / 'result.json', result)
        return result
    except BaseException as error:
        write(out / 'failure.json', {'schema': 2, 'status': 'CPU_PUBLIC_CACHE_PREPARATION_FAILED',
                                    'error': previous.error_record(error), 'finished_at': now()})
        raise
