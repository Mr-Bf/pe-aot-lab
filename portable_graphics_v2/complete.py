"""Continue five completed public packages, then fetch LLVM into a new repo.

Only the fixed LLVM selected-checkout command gets 1,200 seconds. All other
Git commands retain 300 seconds; frozen acquisition modules stay unchanged.
"""
import argparse
import datetime
from pathlib import Path
import os
import shutil
import signal
import subprocess
import sys

from . import prepare as original

network, cache = original.network, original.cache
require, digest, write = network.require, network.digest, network.write


class CheckoutRecorder(network.GitRecorder):
    def __init__(self, out, git_proxy=None):
        base = original.git_recorder(out, git_proxy)
        self.out, self.count = base.out, 0
        self.prefix, self.env = list(base.prefix), dict(base.env)

    def __call__(self, arguments, label, stdout_path=None):
        arguments = list(map(str, arguments))
        timeout = 300
        if label == 'llvm-selected-checkout':
            require(arguments == ['-C', str(self.out / 'llvm-git'), 'checkout', '--detach', cache.LLVM_COMMIT],
                    'long deadline is only for the fixed new LLVM checkout')
            timeout = 1200
        self.count += 1
        stem = self.out / 'logs' / (f'{self.count:03d}-' + label)
        argv = [*self.prefix, *arguments]
        stdout_path = stdout_path or stem.with_suffix('.stdout')
        stderr_path = stem.with_suffix('.stderr')
        started = datetime.datetime.now(datetime.timezone.utc)
        record = {'argv': argv, 'cwd': str(self.out), 'env': self.env, 'started_at': started.isoformat(),
                  'timeout_seconds': timeout, 'deadline_at': (started + datetime.timedelta(seconds=timeout)).isoformat(),
                  'stdout_path': str(stdout_path), 'stderr_path': str(stderr_path)}
        write(stem.with_suffix('.started.json'), record)
        error = None; returncode = None; cleanup = []
        try:
            with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
                process = subprocess.Popen(argv, cwd=self.out, env=self.env, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    returncode = process.wait(timeout=timeout)
                except BaseException:
                    # Same ownership boundary as the frozen recorder: this
                    # invocation's newly created process group, never a name.
                    for sig in (signal.SIGTERM, signal.SIGKILL):
                        try:
                            os.killpg(process.pid, sig)
                            cleanup.append({'signal': int(sig), 'group': process.pid})
                        except ProcessLookupError:
                            cleanup.append({'signal': int(sig), 'group_absent': True})
                        if sig == signal.SIGTERM:
                            try:
                                process.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                pass
                    returncode = process.wait(timeout=5)
                    raise
        except BaseException as caught:
            error = caught
        result = dict(record, returncode=returncode, finished_at=network.now(),
                      error=network.error_record(error) if error else None, owned_group_cleanup=cleanup)
        for kind, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            if path.is_file():
                result[kind + '_sha256'] = digest(path)
        write(stem.with_suffix('.result.json'), result)
        if error:
            raise error
        require(returncode == 0, 'Git command failed: ' + label)
        return stdout_path.read_bytes() if stdout_path.stat().st_size <= 65536 else b''


def inspect_acquisition(origin, lock):
    origin = original.tools.real_path(origin)
    require(origin.is_dir() and not (origin / 'result.json').exists() and not (origin / 'result.json').is_symlink(),
            'failed graphics acquisition directory required')
    identities = {}
    def read(relative):
        path = origin / relative
        value, fingerprint = original.ranges.read_json(path)
        identities[str(path)] = fingerprint
        return value
    started = read('started.json'); failed = read('failure.json')
    timeout_error = {'category': 'git-command-timeout', 'type': 'TimeoutExpired'}
    require(started.get('schema') == 2 and started.get('content_lock_sha256') == digest(cache.LOCK),
            'original acquisition content lock differs')
    require(failed.get('schema') == 2 and failed.get('status') == 'PUBLIC_GRAPHICS_CACHE_ACQUISITION_FAILED' and
            failed.get('error') == timeout_error, 'original acquisition must have typed Git timeout failure')
    expected_sources = {str(path.relative_to(original.ROOT)): digest(path) for path in original.implementation_inputs()}
    require(started.get('sources') == expected_sources, 'original acquisition implementation differs')
    for relative, fingerprint in expected_sources.items():
        snapshot = origin / 'implementation' / relative
        original.ranges.regular(snapshot)
        require(digest(snapshot) == fingerprint, 'original acquisition snapshot differs')
        identities[str(snapshot)] = fingerprint
    require(type(started.get('cache')) is str, 'original cache path absent')
    old_cache = original.tools.real_path(started['cache'])
    roles = ('dxmt', 'headers', 'cmake', 'ninja', 'meson')
    require(old_cache.is_dir() and {path.name for path in old_cache.iterdir()} ==
            {lock['packages'][role]['archive'] for role in roles}, 'old cache must contain exactly five completed public packages')
    packages = {}
    for role in roles:
        spec = lock['packages'][role]; name = spec['archive']
        began = read('logs/' + name + '.started.json')
        result = read('logs/' + name + '.result.json')
        require(began.get('name') == name and began.get('url') == spec['source']['url'] and
                began.get('sha256_expected') == spec['sha256'] and type(began.get('started_at')) is str,
                'original public package start differs: ' + role)
        require(all(result.get(key) == value for key, value in began.items()), 'original download start/result differs')
        expected_status = 'RANGED_DOWNLOAD_AND_HASH_VERIFIED' if role in ('cmake', 'ninja') else 'DOWNLOADED_AND_HASH_VERIFIED'
        require(result.get('status') == expected_status and result.get('sha256') == spec['sha256'] and
                type(result.get('bytes')) is int and result['bytes'] == spec['size'], 'original complete package receipt differs')
        path = old_cache / name; original.ranges.regular(path)
        require(path.stat().st_size == spec['size'] and digest(path) == spec['sha256'], 'original public package bytes differ')
        identities[str(path)] = spec['sha256']
        packages[name] = {'role': role, 'path': str(path), 'bytes': spec['size'], 'sha256': spec['sha256'],
                          'download_result': str(origin / 'logs' / (name + '.result.json'))}
    metadata = read('pypi-meson-1.10.0.json'); metadata_check = read('pypi-check.json')
    selected = original.check_meson_metadata(metadata, lock['packages']['meson'])
    require(metadata_check.get('selected') == selected and metadata_check.get('metadata_url') == original.PYPI_URL and
            metadata_check.get('metadata_path') == str(origin / 'pypi-meson-1.10.0.json') and
            metadata_check.get('metadata_sha256') == identities[str(origin / 'pypi-meson-1.10.0.json')],
            'original PyPI identity receipt differs')
    begin = read('logs/012-llvm-selected-checkout.started.json')
    result = read('logs/012-llvm-selected-checkout.result.json')
    old_run = original.git_recorder(origin, started.get('git_proxy'))
    expected_argv = [*old_run.prefix, '-C', str(origin / 'llvm-git'), 'checkout', '--detach', cache.LLVM_COMMIT]
    require(set(begin) == {'argv', 'cwd', 'env', 'started_at', 'stdout_path', 'stderr_path'} and
            all(result.get(key) == value for key, value in begin.items()) and result.get('argv') == expected_argv and
            result.get('cwd') == str(origin) and result.get('env') == old_run.env and
            result.get('error') == timeout_error and type(result.get('returncode')) is int and result['returncode'] < 0,
            'original selected-checkout timeout record differs')
    require(type(result.get('owned_group_cleanup')) is list and bool(result['owned_group_cleanup']),
            'original timeout cleanup record absent')
    for kind in ('stdout', 'stderr'):
        path = origin / 'logs' / ('012-llvm-selected-checkout.' + kind); original.ranges.regular(path)
        require(result.get(kind + '_path') == str(path) and result.get(kind + '_sha256') == digest(path),
                'original timeout raw output differs')
        identities[str(path)] = digest(path)
    return {'origin': str(origin), 'cache': str(old_cache), 'packages': packages, 'origin_files': identities,
            'scope': 'five complete public packages only; old LLVM checkout, source and partial objects are not reused'}


def complete(cache_path, out, from_acquisition, git_proxy=None):
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required')
    if git_proxy is not None:
        git_proxy = original.proxy_support.validate_proxy(git_proxy)
    cache_path, out = map(original.tools.real_path, (cache_path, out))
    require(not cache_path.exists() and not out.exists(), 'fresh absent cache and evidence directories required')
    require(not cache_path.is_relative_to(out) and not out.is_relative_to(cache_path), 'cache/evidence must be disjoint')
    lock = cache.load_lock(); lock_sha = digest(cache.LOCK)
    origin = inspect_acquisition(from_acquisition, lock)
    for old in (Path(origin['origin']), Path(origin['cache'])):
        require(all(not path.is_relative_to(old) and not old.is_relative_to(path) for path in (cache_path, out)),
                'continuation paths must be disjoint from old acquisition')
    out.mkdir(parents=True); (out / 'logs').mkdir()
    inputs = [*original.implementation_inputs(), Path(__file__), Path(__file__).with_name('test_complete.py'),
              Path(__file__).with_name('test_complete_review.py')]
    snapshots = {}
    for path in inputs:
        relative = path.relative_to(original.ROOT); target = out / 'implementation' / relative
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, target)
        snapshots[str(relative)] = digest(target)
        require(digest(path) == snapshots[str(relative)], 'completion implementation changed during snapshot')
    write(out / 'started.json', {'schema': 2, 'started_at': network.now(), 'cache': str(cache_path),
          'content_lock_sha256': lock_sha, 'sources': snapshots, 'git_proxy': git_proxy, 'from_acquisition': origin,
          'checkout_timeout_seconds': 1200, 'other_git_timeout_seconds': 300,
          'scope': 'reuse five verified public packages from failed acquisition; new public LLVM repo/fetch; no native build'})
    try:
        cache_path.mkdir(parents=True)
        copied = original.proxy_support.copy_downloads(origin, cache_path)
        write(out / 'copied-downloads.json', {'status': 'FIVE_COMPLETE_PUBLIC_PACKAGES_COPIED', 'copies': copied,
                                            'origin': origin, 'copied_at': network.now()})
        run = CheckoutRecorder(out, git_proxy)
        git_version = run(['--version'], 'git-version').decode().strip()
        print('FETCH new public LLVM repo; checkout bound 1200 seconds', flush=True)
        source, llvm_record = original.acquire_llvm(out, run)
        exported = cache.export_llvm(source, cache_path / lock['packages']['llvm']['archive'],
                                     cache_path / lock['llvm_inventory']['file'])
        write(out / 'llvm-export.json', exported)
        verified = cache.check_cache(cache_path)
        original.ranges.check_origin(origin)
        require(digest(cache.LOCK) == lock_sha and all(digest(original.ROOT / path) == fingerprint
                for path, fingerprint in snapshots.items()), 'completion implementation/content lock changed')
        result = {'schema': 2, 'status': original.STATUS, 'cache': str(cache_path), 'finished_at': network.now(),
                  'content_lock_sha256': lock_sha, 'sources': snapshots, 'packages': copied,
                  'from_acquisition': origin, 'llvm': llvm_record, 'llvm_export': exported,
                  'git_version': git_version, 'git_proxy': git_proxy, 'verification': verified,
                  'scope': 'five verified public packages copied from old failed attempt plus fresh public LLVM fetch/export; not full redownload, compilation, GPU or clean-machine proof'}
        write(out / 'result.json', result)
        return result
    except BaseException as error:
        write(out / 'failure.json', {'schema': 2, 'status': 'PUBLIC_GRAPHICS_CACHE_COMPLETION_FAILED',
                                    'error': network.error_record(error), 'finished_at': network.now()})
        raise


def main():
    parser = argparse.ArgumentParser(description='Continue completed public graphics packages with a new bounded LLVM fetch')
    parser.add_argument('--cache', dest='cache_path', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--from-acquisition', required=True)
    parser.add_argument('--git-proxy')
    try:
        print(complete(**vars(parser.parse_args()))['status'])
        return 0
    except Exception as error:
        print('GRAPHICS_COMPLETION_FAILED: ' + str(network.error_record(error)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
