"""Complete four Git inputs after an attested v2 five-package download.

Independent continuation entry; v1/v2 execution code and old attempts stay
unchanged. The proxy is explicit, credential-free and applies to this recorder
instance only. This module does not download the five packages again.
"""
import argparse
from pathlib import Path
import shutil
import sys
import urllib.parse

from . import prepare as ranged
from migration_cache_v1 import prepare as previous, sources
from portable_lifter_v1 import tools

require, digest, write, now = previous.require, previous.digest, previous.write, previous.now


def validate_proxy(value):
    require(type(value) is str and value and all(32 < ord(c) < 127 for c in value),
            'explicit proxy URL without whitespace required')
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme in ('http', 'https') and parsed.hostname and
            parsed.username is None and parsed.password is None and
            not parsed.query and not parsed.fragment and parsed.path in ('', '/'),
            'proxy must be HTTP(S) without credentials, query, fragment or path')
    require(parsed.port is None or 0 < parsed.port <= 65535, 'proxy port outside bounds')
    return value


class ProxyGitRecorder(previous.GitRecorder):
    def __init__(self, out, proxy):
        proxy = validate_proxy(proxy)
        super().__init__(out)
        self.prefix = [*self.prefix, '-c', 'http.proxy=' + proxy]


def frozen_range_inputs():
    # Exactly the fourteen inputs snapshotted by the old v2 attempt. New
    # continuation files must not retroactively change its required manifest.
    directory = Path(ranged.__file__).parent
    return [*ranged.v1_inputs(), *(directory / name for name in
            ('__init__.py', '__main__.py', 'prepare.py', 'test_prepare.py', 'test_review.py'))]


def inspect_downloads(origin, plan):
    origin = tools.real_path(origin)
    require(origin.is_dir() and not (origin / 'result.json').exists() and not (origin / 'result.json').is_symlink(),
            'failed v2 acquisition directory required')
    identities = {}
    def read(relative):
        path = origin / relative
        value, fingerprint = ranged.read_json(path)
        identities[str(path)] = fingerprint
        return value
    started = read('started.json')
    failed = read('failure.json')
    require(started.get('schema') == 2 and started.get('plan') == plan, 'completed-download plan differs')
    require(failed.get('schema') == 2 and failed.get('status') == 'CPU_PUBLIC_CACHE_PREPARATION_FAILED' and
            failed.get('error') == {'type': 'ValueError', 'message': 'Git command failed: gflags-fetch'},
            'continuation requires the failed first Git fetch after downloads')
    expected_sources = {str(path.relative_to(sources.ROOT)): digest(path) for path in frozen_range_inputs()}
    require(started.get('sources') == expected_sources, 'old v2 implementation manifest differs')
    for relative, expected in expected_sources.items():
        path = origin / 'implementation' / relative
        ranged.regular(path)
        require(digest(path) == expected, 'old v2 implementation snapshot differs')
        identities[str(path)] = expected
    require(type(started.get('cache')) is str, 'completed cache path absent')
    cache = tools.real_path(started['cache'])
    require(cache.is_dir() and {path.name for path in cache.iterdir()} == set(plan['packages']),
            'origin cache must contain exactly five completed packages')
    packages = {}
    for name, spec in plan['packages'].items():
        package_start = read('logs/' + name + '.started.json')
        package_result = read('logs/' + name + '.result.json')
        require(package_start.get('name') == name and package_start.get('url') == spec['url'] and
                package_start.get('sha256_expected') == spec['sha256'] and
                type(package_start.get('started_at')) is str and bool(package_start['started_at']),
                'package start identity differs: ' + name)
        require(all(package_result.get(key) == value for key, value in package_start.items()),
                'package start/result binding differs: ' + name)
        expected_status = 'RANGED_DOWNLOAD_AND_HASH_VERIFIED' if spec['kind'] == 'ghcr' else 'DOWNLOADED_AND_HASH_VERIFIED'
        require(package_result.get('status') == expected_status and package_result.get('name') == name and
                package_result.get('url') == spec['url'] and package_result.get('sha256') == spec['sha256'] and
                package_result.get('sha256_expected') == spec['sha256'] and type(package_result.get('bytes')) is int and
                0 < package_result['bytes'] <= previous.MAX_DOWNLOAD_BYTES, 'completed package identity differs: ' + name)
        path = cache / name; ranged.regular(path)
        require(path.stat().st_size == package_result['bytes'] and digest(path) == spec['sha256'],
                'completed package bytes differ: ' + name)
        identities[str(path)] = spec['sha256']
        packages[name] = {'path': str(path), 'sha256': spec['sha256'], 'bytes': package_result['bytes'],
                          'download_result': str(origin / 'logs' / (name + '.result.json'))}
    fetch_start = read('logs/003-gflags-fetch.started.json')
    fetch_result = read('logs/003-gflags-fetch.result.json')
    require(set(fetch_start) == {'argv', 'cwd', 'env', 'started_at', 'stdout_path', 'stderr_path'},
            'failed fetch start record fields differ')
    require(all(fetch_result.get(key) == value for key, value in fetch_start.items()), 'failed fetch start/result differs')
    expected_tail = ['-C', str(origin / 'repositories/gflags.git'), 'fetch', '--no-tags', '--depth=1',
                     plan['sources']['gflags']['repository'], plan['sources']['gflags']['commit']]
    expected_prefix = previous.GitRecorder(origin).prefix
    require(fetch_result.get('argv') == expected_prefix + expected_tail and
            type(fetch_result.get('returncode')) is int and fetch_result['returncode'] != 0 and
            fetch_result.get('error') is None and fetch_result.get('cwd') == str(origin), 'failed fetch command differs')
    for kind in ('stdout', 'stderr'):
        path = origin / 'logs' / ('003-gflags-fetch.' + kind)
        ranged.regular(path)
        require(fetch_result.get(kind + '_path') == str(path) and
                digest(path) == fetch_result.get(kind + '_sha256'), 'failed fetch raw log differs')
        identities[str(path)] = fetch_result[kind + '_sha256']
    return {'origin': str(origin), 'cache': str(cache), 'packages': packages, 'origin_files': identities,
            'scope': 'five complete public downloads from failed v2 acquisition; no Git source reuse'}


def copy_downloads(record, cache):
    ranged.check_origin(record)
    copied = {}
    for name, identity in record['packages'].items():
        target = cache / name
        with Path(identity['path']).open('rb') as original, target.open('xb') as output:
            shutil.copyfileobj(original, output, length=1024 * 1024)
        require(target.stat().st_size == identity['bytes'] and digest(target) == identity['sha256'],
                'completed package copy differs: ' + name)
        copied[name] = dict(identity, destination=str(target))
    ranged.check_origin(record)
    return copied


def complete(cache, out, from_downloads, git_proxy):
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required')
    proxy = validate_proxy(git_proxy)
    cache, out = map(tools.real_path, (cache, out))
    require(not cache.exists() and not out.exists(), 'fresh absent cache and evidence directories required')
    require(not cache.is_relative_to(out) and not out.is_relative_to(cache), 'cache/evidence must be disjoint')
    plan = sources.plan()
    origin = inspect_downloads(from_downloads, plan)
    for old in (Path(origin['origin']), Path(origin['cache'])):
        require(all(not path.is_relative_to(old) and not old.is_relative_to(path) for path in (cache, out)),
                'continuation must be disjoint from old evidence and cache')
    out.mkdir(parents=True); (out / 'logs').mkdir()
    inputs = [*frozen_range_inputs(), Path(__file__), Path(__file__).with_name('test_complete.py'),
              Path(__file__).with_name('test_complete_review.py')]
    snapshots = {}
    for source in inputs:
        relative = source.relative_to(sources.ROOT)
        target = out / 'implementation' / relative
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source, target)
        snapshots[str(relative)] = digest(target)
        require(digest(source) == snapshots[str(relative)], 'continuation implementation changed during snapshot')
    write(out / 'started.json', {'schema': 3, 'started_at': now(), 'cache': str(cache), 'plan': plan,
                                'sources': snapshots, 'from_downloads': origin, 'git_proxy': proxy})
    try:
        cache.mkdir(parents=True)
        copied = copy_downloads(origin, cache)
        write(out / 'copied-downloads.json', {'status': 'FIVE_COMPLETE_PUBLIC_DOWNLOADS_COPIED',
                                            'origin': origin, 'copies': copied, 'copied_at': now()})
        run = ProxyGitRecorder(out, proxy)
        version = run(['--version'], 'git-version').decode().strip()
        records = {'schema': 1, 'status': 'PREPARING', 'packages': copied, 'sources': {}}
        for name, spec in plan['sources'].items():
            print('FETCH ' + name, flush=True)
            records['sources'][name] = previous.acquire_source(name, spec, cache, out, run)
        require(all(digest(sources.ROOT / name) == value for name, value in snapshots.items()),
                'implementation/lock changed during continuation')
        ranged.check_origin(origin)
        records['status'] = 'PINNED_PUBLIC_INPUTS_MATERIALIZED'
        write(cache / 'cache.json', records)
        verified = previous.validate(cache)
        result = {'schema': 3, 'status': previous.STATUS, 'cache': str(cache), 'git_version': version,
                  'package_count': 9, 'finished_at': now(), 'cache_metadata_sha256': digest(cache / 'cache.json'),
                  'validation': verified, 'sources': snapshots, 'from_downloads': origin, 'git_proxy': proxy,
                  'scope': 'explicit five-package copy plus four public Git exports; no full redownload, compilation or clean-machine claim'}
        write(out / 'result.json', result)
        return result
    except BaseException as error:
        write(out / 'failure.json', {'schema': 3, 'status': 'CPU_PUBLIC_CACHE_PREPARATION_FAILED',
                                    'error': previous.error_record(error), 'finished_at': now()})
        raise


def main():
    parser = argparse.ArgumentParser(description='Continue an attested v2 download attempt with an explicit Git proxy')
    for name in ('cache', 'out', 'from-downloads', 'git-proxy'):
        parser.add_argument('--' + name, required=True)
    try:
        print(complete(**vars(parser.parse_args()))['status'])
        return 0
    except Exception as error:
        print('CACHE_COMPLETION_FAILED: ' + str(previous.error_record(error)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
