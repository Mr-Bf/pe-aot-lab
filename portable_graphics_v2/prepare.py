"""Public graphics inputs, then exact Git-tree/canonical-cache verification.

No old source path or installed provider is an input. The reference content
lock must already be sealed. Receipts stay in the separate evidence directory.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import urllib.request

from migration_cache_v1 import prepare as network
from migration_cache_v2 import prepare as ranges, complete as proxy_support
from portable_lifter_v1 import build as cpu_build, deps as cpu_deps, tools
from portable_graphics_v1 import cache as legacy_cache
from . import cache

ROOT = Path(__file__).resolve().parents[1]
PYPI_URL = 'https://pypi.org/pypi/meson/1.10.0/json'
METADATA_LIMIT = 256 * 1024
RAW_ATTRIBUTES = b'* -text -eol -filter -ident -working-tree-encoding\n'
STATUS = 'PUBLIC_GRAPHICS_CACHE_VERIFIED_NOT_BUILT'
require, digest, write = network.require, network.digest, network.write


def check_meson_metadata(value, spec):
    require(type(value) is dict and type(value.get('info')) is dict and
            value['info'].get('name') == 'meson' and value['info'].get('version') == '1.10.0' and
            type(value.get('urls')) is list, 'PyPI metadata package/version differs')
    rows = [row for row in value['urls'] if type(row) is dict and row.get('filename') == spec['archive']]
    require(len(rows) == 1, 'one fixed Meson wheel required in PyPI metadata')
    row = rows[0]
    require(row.get('packagetype') == 'bdist_wheel' and row.get('python_version') == 'py3' and
            row.get('yanked') is False and row.get('url') == spec['source']['url'] and
            type(row.get('size')) is int and row['size'] == spec['size'] and
            type(row.get('digests')) is dict and row['digests'].get('sha256') == spec['sha256'],
            'PyPI wheel URL, digest, size or availability differs from fixed lock')
    return {'filename': row['filename'], 'url': row['url'], 'sha256': row['digests']['sha256'],
            'bytes': row['size'], 'scope': 'official metadata identity; not signature verification'}


def fetch_meson_metadata(spec, out, client=None):
    require(spec['source']['metadata_url'] == PYPI_URL, 'fixed PyPI metadata endpoint required')
    client = client or network.opener()
    target = out / 'pypi-meson-1.10.0.json'
    request = urllib.request.Request(PYPI_URL, headers={'User-Agent': 'pe-aot-lab-graphics-cache/2'})
    with target.open('xb') as raw_output, client.open(request, timeout=network.SOCKET_SECONDS) as response:
        require(response.status == 200, 'PyPI metadata HTTP response was not 200')
        raw = response.read(METADATA_LIMIT + 1)
        raw_output.write(raw)
    require(len(raw) <= METADATA_LIMIT, 'PyPI metadata exceeds size limit')
    value = cache.read_json(target)  # Reject duplicate keys as well as invalid JSON.
    selected = check_meson_metadata(value, spec)
    record = {'metadata_url': PYPI_URL, 'metadata_path': str(target), 'metadata_sha256': digest(target),
              'checked_at': network.now(), 'selected': selected}
    write(out / 'pypi-check.json', record)
    return record


def git_recorder(out, git_proxy):
    if git_proxy is None:
        run = network.GitRecorder(out)
    else:
        run = proxy_support.ProxyGitRecorder(out, git_proxy)
    # These options accompany checkout's lazy fetch too; no global Git config
    # or user attributes decide the selected source bytes.
    run.prefix = [*run.prefix, '-c', 'core.autocrlf=false', '-c', 'core.symlinks=true']
    run.env['GIT_ATTR_NOSYSTEM'] = '1'
    return run


def acquire_llvm(out, run):
    repository = out / 'llvm-git'
    source = out / 'llvm-source'
    require(not repository.exists() and not source.exists(), 'fresh LLVM acquisition paths required')
    url = 'https://github.com/llvm/llvm-project.git'
    run(['init', '--template=', repository], 'llvm-init')
    run(['-C', repository, 'remote', 'add', 'origin', url], 'llvm-origin')
    run(['-C', repository, 'config', 'remote.origin.promisor', 'true'], 'llvm-promisor')
    run(['-C', repository, 'config', 'remote.origin.partialclonefilter', 'blob:none'], 'llvm-filter')
    run(['-C', repository, '-c', 'protocol.version=2', 'fetch', '--no-tags', '--depth=1',
         '--filter=blob:none', 'origin', cache.LLVM_COMMIT], 'llvm-fetch')
    actual_commit = run(['-C', repository, 'rev-parse', 'FETCH_HEAD^{commit}'], 'llvm-commit').decode().strip()
    require(actual_commit == cache.LLVM_COMMIT, 'public LLVM commit differs')
    trees = {}
    for name, expected in sorted(cache.LLVM_TREES.items()):
        actual = run(['-C', repository, 'rev-parse', 'FETCH_HEAD:' + name], 'llvm-tree-' + name).decode().strip()
        require(actual == expected, 'public LLVM selected tree differs: ' + name)
        trees[name] = actual
    attributes = repository / '.git/info/attributes'
    attributes.parent.mkdir(parents=True, exist_ok=True)
    with attributes.open('xb') as stream:
        stream.write(RAW_ATTRIBUTES)
    run(['-C', repository, 'sparse-checkout', 'init', '--no-cone'], 'llvm-sparse-init')
    run(['-C', repository, 'sparse-checkout', 'set', '--no-cone', '/llvm/', '/cmake/'], 'llvm-sparse-set')
    run(['-C', repository, 'checkout', '--detach', cache.LLVM_COMMIT], 'llvm-selected-checkout')
    require({path.name for path in repository.iterdir()} == {'.git', *cache.LLVM_TREES},
            'LLVM sparse checkout includes unexpected root entries')
    require(attributes.read_bytes() == RAW_ATTRIBUTES, 'LLVM raw-byte attributes changed')
    source.mkdir()
    for name in sorted(cache.LLVM_TREES):
        require((repository / name).is_dir() and not (repository / name).is_symlink(), 'LLVM selected source directory absent')
        # Preserve links rather than following them; the canonical exporter
        # subsequently validates every link, byte, mode and reconstructed tree.
        shutil.copytree(repository / name, source / name, symlinks=True)
    record = {'repository': url, 'commit': actual_commit, 'trees': trees,
              'source': str(source), 'checkout': str(repository), 'raw_attributes_sha256': digest(attributes),
              'fetch_filter_requested': 'blob:none', 'checkout_patterns': ['/llvm/', '/cmake/'],
              'scope': 'new public partial-clone/sparse acquisition; exact source acceptance belongs to canonical export'}
    write(out / 'llvm-acquisition.json', record)
    return source, record


def download_package(name, spec, cache_path, out):
    download = {'url': spec['source']['url'], 'sha256': spec['sha256'], 'kind': 'https'}
    if name in ('cmake', 'ninja'):
        download.update(kind='ghcr', repository=name)
        record = ranges.download_ranges(spec['archive'], download, cache_path, out / 'logs')
    else:
        record = network.download(spec['archive'], download, cache_path, out / 'logs')
    require(record['bytes'] == spec['size'], 'fixed original package size differs: ' + name)
    return record


def implementation_inputs():
    return [Path(__file__), Path(__file__).with_name('__main__.py'), Path(cache.__file__), cache.LOCK,
            Path(legacy_cache.__file__), Path(network.__file__), Path(network.sources.__file__),
            Path(ranges.__file__), Path(proxy_support.__file__), Path(tools.__file__),
            Path(cpu_build.__file__), Path(cpu_deps.__file__)]


def prepare(cache_path, out, git_proxy=None):
    require(sys.version_info >= (3, 13), 'Python >= 3.13 required')
    if git_proxy is not None:
        git_proxy = proxy_support.validate_proxy(git_proxy)
    cache_path, out = map(tools.real_path, (cache_path, out))
    require(not cache_path.exists() and not out.exists(), 'fresh absent cache and evidence directories required')
    require(not cache_path.is_relative_to(out) and not out.is_relative_to(cache_path), 'cache/evidence must be disjoint')
    lock = cache.load_lock()  # Fail before creating directories or doing network I/O if unsealed.
    lock_sha = digest(cache.LOCK)
    out.mkdir(parents=True); (out / 'logs').mkdir()
    snapshots = {}
    for path in implementation_inputs():
        relative = path.relative_to(ROOT)
        target = out / 'implementation' / relative
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(path, target)
        snapshots[str(relative)] = digest(target)
        require(digest(path) == snapshots[str(relative)], 'implementation changed while snapshotting')
    write(out / 'started.json', {'schema': 2, 'started_at': network.now(), 'cache': str(cache_path),
          'content_lock_sha256': lock_sha, 'sources': snapshots, 'git_proxy': git_proxy,
          'scope': 'public graphics cache acquisition only; no compile or reference-source import'})
    try:
        cache_path.mkdir(parents=True)
        metadata = fetch_meson_metadata(lock['packages']['meson'], out)
        packages = {}
        for name in ('dxmt', 'headers', 'cmake', 'ninja', 'meson'):
            print('DOWNLOAD ' + name, flush=True)
            packages[name] = download_package(name, lock['packages'][name], cache_path, out)
        run = git_recorder(out, git_proxy)
        git_version = run(['--version'], 'git-version').decode().strip()
        print('FETCH LLVM selected subtrees', flush=True)
        llvm_source, llvm_record = acquire_llvm(out, run)
        exported = cache.export_llvm(llvm_source, cache_path / lock['packages']['llvm']['archive'],
                                     cache_path / lock['llvm_inventory']['file'])
        write(out / 'llvm-export.json', exported)
        verified = cache.check_cache(cache_path)
        # Acquisition receipt is never copied into the cache or incorporated in
        # its content identity; the independently sealed lock is unchanged.
        require(digest(cache.LOCK) == lock_sha and all(digest(ROOT / path) == fingerprint
                for path, fingerprint in snapshots.items()), 'implementation/content lock changed during acquisition')
        result = {'schema': 2, 'status': STATUS, 'cache': str(cache_path), 'finished_at': network.now(),
                  'content_lock_sha256': lock_sha, 'sources': snapshots, 'packages': packages,
                  'meson_metadata': metadata, 'llvm': llvm_record, 'llvm_export': exported,
                  'git_version': git_version, 'git_proxy': git_proxy, 'verification': verified,
                  'scope': 'five public packages and two fixed Git subtrees verified against sealed content lock; not build, GPU or clean-machine proof'}
        write(out / 'result.json', result)
        return result
    except BaseException as error:
        write(out / 'failure.json', {'schema': 2, 'status': 'PUBLIC_GRAPHICS_CACHE_ACQUISITION_FAILED',
                                    'error': network.error_record(error), 'finished_at': network.now()})
        raise
