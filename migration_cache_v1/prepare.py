"""Acquire nine pinned public inputs; never compile or execute their payloads.

Each attempt owns fresh cache/evidence directories. Partial files and failures
remain in place. No local-cache fallback, retries, global install or lock edits.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from portable_lifter_v1 import build, deps, tools
from . import sources

require = tools.require
digest = tools.digest
MAX_DOWNLOAD_BYTES = 1024 ** 3
DOWNLOAD_SECONDS = 1200
GIT_SECONDS = 300
SOCKET_SECONDS = 30
STATUS = 'CPU_PUBLIC_CACHE_READY_NOT_BUILT'


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def error_record(error):
    # Network exceptions may carry signed redirect URLs. Never serialize the
    # exception or response body, or the anonymous GHCR bearer token.
    if isinstance(error, urllib.error.HTTPError):
        return {'type': 'HTTPError', 'http_status': error.code}
    if isinstance(error, (urllib.error.URLError, TimeoutError)):
        return {'type': type(error).__name__, 'category': 'network-or-timeout'}
    if isinstance(error, subprocess.TimeoutExpired):
        return {'type': 'TimeoutExpired', 'category': 'git-command-timeout'}
    # Only our explicit contract errors carry public, controlled messages.
    return {'type': type(error).__name__, **({'message': str(error)} if type(error) is ValueError else {})}


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        require(target.scheme == 'https' and target.hostname and not target.username
                and not target.password, 'redirect must remain HTTPS without credentials')
        result = super().redirect_request(request, response, code, message, headers, newurl)
        if result is not None and urllib.parse.urlsplit(request.full_url).netloc != target.netloc:
            result.remove_header('Authorization')
        return result


def opener():
    # No environment proxy credentials, user cookies or authenticated sessions.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSRedirect())


def token_for(repository, client):
    scope = urllib.parse.urlencode({'service': 'ghcr.io',
                                   'scope': 'repository:homebrew/core/' + repository + ':pull'})
    request = urllib.request.Request('https://ghcr.io/token?' + scope,
                                     headers={'User-Agent': 'pe-aot-lab-cache/1'})
    with client.open(request, timeout=SOCKET_SECONDS) as response:
        require(response.status == 200, 'GHCR token response was not successful')
        raw = response.read(65537)
    require(len(raw) <= 65536, 'oversized GHCR token response')
    token = json.loads(raw).get('token')
    require(type(token) is str and 0 < len(token) <= 32768 and
            all(33 <= ord(c) <= 126 for c in token), 'invalid anonymous GHCR token')
    return token


def publish(partial, final, expected):
    require(partial.is_file() and not partial.is_symlink() and partial.stat().st_nlink == 1,
            'regular single-link partial file required')
    actual = digest(partial)
    require(actual == expected, 'acquired file SHA-256 mismatch: ' + final.name)
    size = partial.stat().st_size
    # Atomic no-clobber publication in the same directory, including EEXIST for
    # dangling symlinks. The temporary second link is removed immediately.
    os.link(partial, final)
    partial.unlink()
    return {'sha256': actual, 'bytes': size}


def download(name, spec, cache, logs, client=None):
    client = client or opener()
    partial, final = cache / (name + '.partial'), cache / name
    row = {'name': name, 'url': spec['url'], 'sha256_expected': spec['sha256'],
           'started_at': now(), 'credential_source': 'anonymous-public-pull' if spec['kind'] == 'ghcr' else 'none'}
    write(logs / (name + '.started.json'), row)
    started = time.monotonic()
    try:
        headers = {'User-Agent': 'pe-aot-lab-cache/1', 'Accept-Encoding': 'identity'}
        if spec['kind'] == 'ghcr':
            headers['Authorization'] = 'Bearer ' + token_for(spec['repository'], client)
        request = urllib.request.Request(spec['url'], headers=headers)
        with partial.open('xb') as output, client.open(request, timeout=SOCKET_SECONDS) as response:
            require(response.status == 200, 'archive HTTP response was not 200')
            length = response.headers.get('Content-Length')
            require(length is None or (length.isdigit() and 0 < int(length) <= MAX_DOWNLOAD_BYTES),
                    'archive Content-Length outside bounds')
            size = 0
            while True:
                require(time.monotonic() - started <= DOWNLOAD_SECONDS, 'archive overall timeout')
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= MAX_DOWNLOAD_BYTES, 'archive size outside bounds')
                output.write(chunk)
            require(length is None or size == int(length), 'truncated archive response')
        result = dict(row, **publish(partial, final, spec['sha256']),
                      status='DOWNLOADED_AND_HASH_VERIFIED', finished_at=now())
        write(logs / (name + '.result.json'), result)
        return result
    except BaseException as error:
        failure = dict(row, status='DOWNLOAD_FAILED', finished_at=now(), error=error_record(error))
        if partial.is_file() and not partial.is_symlink():
            failure['partial'] = {'path': str(partial), 'bytes': partial.stat().st_size, 'sha256': digest(partial)}
        write(logs / (name + '.failure.json'), failure)
        raise


class GitRecorder:
    def __init__(self, out):
        self.out = out
        self.count = 0
        self.env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C',
                    'GIT_CONFIG_NOSYSTEM': '1',
                    'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
                    'GIT_ASKPASS': '/usr/bin/false', 'SSH_ASKPASS': '/usr/bin/false'}
        self.prefix = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null',
                       '-c', 'core.attributesFile=/dev/null', '-c', 'credential.helper=',
                       '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never',
                       '-c', 'tar.umask=0002']

    def __call__(self, arguments, label, stdout_path=None):
        self.count += 1
        stem = self.out / 'logs' / (f'{self.count:03d}-' + label)
        argv = [*self.prefix, *map(str, arguments)]
        stdout_path = stdout_path or stem.with_suffix('.stdout')
        stderr_path = stem.with_suffix('.stderr')
        record = {'argv': argv, 'cwd': str(self.out), 'env': self.env, 'started_at': now(),
                  'stdout_path': str(stdout_path), 'stderr_path': str(stderr_path)}
        write(stem.with_suffix('.started.json'), record)
        error = None
        returncode = None
        process = None
        cleanup = []
        try:
            with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
                process = subprocess.Popen(argv, cwd=self.out, env=self.env, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    returncode = process.wait(timeout=GIT_SECONDS)
                except BaseException:
                    # This new session belongs only to this command, including
                    # git-remote-https. Never leave a helper downloading after
                    # the supervised Git command times out or is interrupted.
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
        result = dict(record, returncode=returncode, finished_at=now(),
                      error=error_record(error) if error else None, owned_group_cleanup=cleanup)
        for key, path in (('stdout', stdout_path), ('stderr', stderr_path)):
            if path.is_file():
                result[key + '_sha256'] = digest(path)
        write(stem.with_suffix('.result.json'), result)
        if error:
            raise error
        require(returncode == 0, 'Git command failed: ' + label)
        return stdout_path.read_bytes() if stdout_path.stat().st_size <= 65536 else b''


def acquire_source(name, spec, cache, out, run):
    repository = out / 'repositories' / (name + '.git')
    partial = cache / (spec['archive'] + '.partial')
    run(['init', '--bare', '--template=', repository], name + '-init')
    run(['-C', repository, 'fetch', '--no-tags', '--depth=1', spec['repository'], spec['commit']], name + '-fetch')
    commit = run(['-C', repository, 'rev-parse', 'FETCH_HEAD^{commit}'], name + '-commit').decode().strip()
    tree = run(['-C', repository, 'rev-parse', 'FETCH_HEAD^{tree}'], name + '-tree').decode().strip()
    require(commit == spec['commit'] and tree == spec['tree'], 'fetched Git identity differs: ' + name)
    run(['-C', repository, 'archive', '--format=tar', '--prefix=' + name + '/', spec['commit']],
        name + '-archive', stdout_path=partial)
    identity = publish(partial, cache / spec['archive'], spec['sha256'])
    return dict(spec, **identity, status='PUBLIC_GIT_SOURCE_EXPORTED_AND_HASH_VERIFIED')


def validate(cache):
    """Use the frozen consumers, plus their separate Remill archive gate."""
    packages = tools.check_cache(cache)
    source_record = deps.sources(cache)
    remill = cache / 'remill.tar.gz'
    require(remill.is_file() and not remill.is_symlink() and digest(remill) == build.REMILL_ARCHIVE_SHA,
            'Remill source archive mismatch')
    return {'tools': packages, 'sources': source_record,
            'remill': {'sha256': digest(remill), 'bytes': remill.stat().st_size}}


def prepare_cpu(cache, out):
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required by the frozen cache consumers')
    cache, out = map(tools.real_path, (cache, out))
    require(not cache.exists() and not out.exists(), 'fresh absent cache and evidence directories required')
    require(not cache.is_relative_to(out) and not out.is_relative_to(cache), 'cache/evidence must be disjoint')
    plan = sources.plan()
    out.mkdir(parents=True)
    (out / 'logs').mkdir()
    inputs = [*sorted(Path(__file__).parent.glob('*.py')), sources.LOCK,
              Path(tools.__file__), Path(deps.__file__), Path(build.__file__)]
    source_hashes = {}
    for source in inputs:
        relative = source.relative_to(sources.ROOT)
        destination = out / 'implementation' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        source_hashes[str(relative)] = digest(destination)
        require(digest(source) == source_hashes[str(relative)], 'implementation changed while snapshotting')
    write(out / 'started.json', {'schema': 1, 'started_at': now(), 'cache': str(cache), 'plan': plan,
                                'sources': source_hashes, 'scope': 'public cache acquisition only; no native build or payload execution'})
    try:
        cache.mkdir(parents=True)
        run = GitRecorder(out)
        version = run(['--version'], 'git-version').decode().strip()
        records = {'schema': 1, 'status': 'PREPARING', 'packages': {}, 'sources': {}}
        for name, spec in plan['packages'].items():
            print('DOWNLOAD ' + name, flush=True)
            records['packages'][name] = download(name, spec, cache, out / 'logs')
        for name, spec in plan['sources'].items():
            print('FETCH ' + name, flush=True)
            records['sources'][name] = acquire_source(name, spec, cache, out, run)
        require(all(digest(sources.ROOT / name) == value for name, value in source_hashes.items()),
                'implementation/lock changed during acquisition')
        records['status'] = 'PINNED_PUBLIC_INPUTS_MATERIALIZED'
        write(cache / 'cache.json', records)
        verified = validate(cache)
        result = {'schema': 1, 'status': STATUS, 'cache': str(cache), 'git_version': version,
                  'package_count': len(plan['packages']) + len(plan['sources']), 'finished_at': now(),
                  'cache_metadata_sha256': digest(cache / 'cache.json'), 'validation': verified,
                  'sources': source_hashes, 'scope': 'nine CPU inputs ready for existing offline consumers; not a build, clean-machine, GPU or performance claim'}
        write(out / 'result.json', result)
        return result
    except BaseException as error:
        write(out / 'failure.json', {'schema': 1, 'status': 'CPU_PUBLIC_CACHE_PREPARATION_FAILED',
                                    'error': error_record(error), 'finished_at': now(),
                                    'scope': 'preserve this attempt; use fresh cache/evidence paths for retries'})
        raise
