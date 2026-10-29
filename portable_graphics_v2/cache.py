"""Fixed graphics content, independent of machine-specific acquisition receipts.

Reference export establishes new canonical hashes; it does not prove a public
fetch. Consumers never read an acquisition receipt or an old build receipt.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import tarfile
import zlib

from portable_graphics_v1 import cache as legacy

LOCK = Path(__file__).with_name('cache-lock.json')
LLVM_COMMIT = legacy.LLVM_COMMIT
LLVM_TREES = dict(legacy.LLVM_TREES)
LLVM_FILE_COUNT = legacy.LLVM_FILE_COUNT
DXMT_COMMIT, HEADERS_COMMIT = legacy.DXMT_COMMIT, legacy.HEADERS_COMMIT
PINS = {name: dict(sha256=digest, size=size) for name, digest, size in (
    ('dxmt', 'f94d264a4a8030c852f4ade3502118e597a22e87b63a5f1f4236954fe84d4973', 802203),
    ('headers', '9c1b8bbfd2d6c758fac4d93c2808a46bc1eee429fe656b4f21b29e02615aa8aa', 473287),
    ('cmake', 'b2a7da6b1f351024c84fe36af692f31a196cb21be74dae8a3f36925467fa676b', 20140308),
    ('ninja', '2c07378c1ccb6cfde4bc2e12877c9f365b31c62ddc4ec631421cb80e3a7e1f11', 160558),
    ('meson', '4b27aafce281e652dcb437b28007457411245d975c48b5db3a797d3e93ae1585', 1057029))}
PROFILE = dict(name='llvm-selected-git-modes-v2', tar_format='pax', regular_modes=[0o644, 0o755],
               directory_mode=0o755, symlink_mode=0o777, uid=0, gid=0, mtime=0,
               uname='', gname='', ordering='path-filesystem-bytes', gzip_filename='',
               gzip_mtime=0, gzip_compresslevel=1)
MESON_URL = ('https://files.pythonhosted.org/packages/32/4f/'
             'c398c6f06ece1c6c246e008d5dac3824c98f54d3eb3d8014f4910afd6d48/'
             'meson-1.10.0-py3-none-any.whl')
require, real, sha = legacy.require, legacy.real, legacy.sha
read_json, write_json, encoded, regular = legacy.read_json, legacy.write_json, legacy.encoded, legacy.regular


def safe_extract(archive, destination, archive_root):
    result = legacy.safe_extract(archive, destination, archive_root)
    if archive_root == 'llvm15-subtrees':
        for path in result.rglob('*'):
            if path.is_symlink() and stat.S_IMODE(path.lstat().st_mode) != 0o777:
                # macOS link creation follows umask. Change the link, never its target.
                os.chmod(path, 0o777, follow_symlinks=False)
    return result


def specs():
    result = legacy.specs()
    result['llvm']['source'] = dict(repository='llvm/llvm-project',
        url='https://github.com/llvm/llvm-project.git', commit=LLVM_COMMIT, trees=LLVM_TREES,
        scope='complete llvm and cmake Git subtrees only; not a full monorepo')
    result['meson']['source'] = dict(version='1.10.0', project='https://github.com/mesonbuild/meson',
                                    url=MESON_URL, metadata_url='https://pypi.org/pypi/meson/1.10.0/json')
    return result


def digest_shape(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def check_inventory(value):
    require(type(value) is dict and value.get('schema') == 1 and value.get('commit') == LLVM_COMMIT
            and value.get('trees') == LLVM_TREES and type(value.get('files')) is list
            and len(value['files']) == LLVM_FILE_COUNT, 'fixed LLVM Git trees/file count differ')


def canonical_inventory(value):
    check_inventory(value)
    result = json.loads(json.dumps(value))
    for row in result['files']:
        mode, git_mode = row.get('mode'), row.get('git_mode')
        require(type(mode) is int and 0 <= mode <= 0o777 and git_mode in ('100644', '100755', '120000'),
                'unsupported LLVM mode')
        if git_mode != '120000':
            require(bool(mode & 0o100) == (git_mode == '100755'), 'LLVM executable bit differs from Git mode')
        row['mode'] = {'100644': 0o644, '100755': 0o755, '120000': 0o777}[git_mode]
    return result


def source_inventory(source):
    source = real(source)
    require(source.is_dir() and {p.name for p in source.iterdir()} == set(LLVM_TREES),
            'LLVM source root must contain only llvm and cmake')
    value = legacy.llvm_inventory(source)
    check_inventory(value)
    return value


def lock_for_export(exported):
    """Return a sealable content lock; caller persists reference provenance separately."""
    require(exported.get('export_profile') == PROFILE, 'reference export profile differs')
    archive, inventory = exported['archive'], exported['inventory']
    require(digest_shape(archive.get('sha256')) and digest_shape(archive.get('tar_sha256')) and
            all(type(archive.get(key)) is int and archive[key] > 0 for key in ('size', 'tar_size')) and
            digest_shape(inventory.get('sha256')) and inventory.get('file_count') == LLVM_FILE_COUNT,
            'incomplete reference export identities')
    packages = {name: dict(spec, **PINS[name]) for name, spec in specs().items() if name != 'llvm'}
    packages['llvm'] = dict(specs()['llvm'], **{key: archive[key] for key in ('sha256', 'size', 'tar_sha256', 'tar_size')})
    return dict(schema=2, status='CONTENT_LOCK_SEALED', export_profile=PROFILE, packages=packages,
                llvm_inventory=dict(file='llvm15-files.json', sha256=inventory['sha256'], file_count=LLVM_FILE_COUNT))


def load_lock():
    regular(LOCK)
    lock = read_json(LOCK)
    require(type(lock) is dict and lock.get('schema') == 2 and lock.get('status') == 'CONTENT_LOCK_SEALED',
            'graphics v2 content lock is not sealed')
    require(set(lock) == {'schema', 'status', 'export_profile', 'packages', 'llvm_inventory'} and
            lock['export_profile'] == PROFILE and type(lock['packages']) is dict and
            set(lock['packages']) == set(specs()), 'invalid graphics v2 lock fields/profile')
    for name, spec in specs().items():
        row = lock['packages'][name]
        extra = {'sha256', 'size', 'tar_sha256', 'tar_size'} if name == 'llvm' else {'sha256', 'size'}
        require(type(row) is dict and set(row) == set(spec) | extra and
                {key: row[key] for key in spec} == spec, 'locked package source differs: ' + name)
        require(digest_shape(row['sha256']) and type(row['size']) is int and row['size'] > 0,
                'invalid package hash/size: ' + name)
        if name != 'llvm':
            require({key: row[key] for key in PINS[name]} == PINS[name], 'fixed original package differs: ' + name)
        else:
            require(digest_shape(row['tar_sha256']) and type(row['tar_size']) is int and
                    0 < row['tar_size'] <= 4 * 1024**3, 'invalid canonical tar identity')
    row = lock['llvm_inventory']
    require(type(row) is dict and set(row) == {'file', 'sha256', 'file_count'} and
            row['file'] == 'llvm15-files.json' and digest_shape(row['sha256']) and
            row['file_count'] == LLVM_FILE_COUNT, 'invalid LLVM inventory lock')
    return lock


def tar_identity(archive):
    digest, size = hashlib.sha256(), 0
    with gzip.open(archive, 'rb') as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(raw)
            require(size <= 4 * 1024**3, 'canonical tar size limit exceeded')
            digest.update(raw)
    return dict(tar_sha256=digest.hexdigest(), tar_size=size)


def check_cache(cache):
    cache = real(cache)
    require(cache.is_dir(), 'graphics cache absent')
    lock = load_lock()
    result = dict(cache=str(cache), lock_sha256=sha(LOCK), export_profile=PROFILE, packages={})
    for name, row in lock['packages'].items():
        path = cache / row['archive']; regular(path)
        require(path.stat().st_size == row['size'] and sha(path) == row['sha256'],
                'cache package hash/size differs: ' + name)
        if name == 'llvm':
            require(tar_identity(path) == {key: row[key] for key in ('tar_sha256', 'tar_size')},
                    'canonical LLVM tar differs')
        result['packages'][name] = dict(row, path=str(path))
    row = lock['llvm_inventory']; path = cache / row['file']; regular(path)
    require(sha(path) == row['sha256'], 'LLVM inventory hash differs')
    inventory = read_json(path)
    require(inventory == canonical_inventory(inventory), 'LLVM inventory permission profile differs')
    result['llvm_inventory'] = dict(row, path=str(path))
    return result


def extract_sources(cache, destination):
    destination = real(destination)
    require(not destination.exists() and not destination.is_symlink(), 'fresh source destination required')
    before = check_cache(cache)
    require(not destination.is_relative_to(Path(before['cache'])) and
            not Path(before['cache']).is_relative_to(destination), 'cache/source paths overlap')
    destination.mkdir(parents=True)
    write_json(destination / 'started.json', dict(cache=before, scope='source extraction only; no native build'))
    try:
        result = {}
        for name in ('llvm', 'dxmt', 'headers'):
            row = before['packages'][name]
            result[name] = str(safe_extract(row['path'], destination, row['archive_root']))
        actual = source_inventory(result['llvm'])
        require(actual == read_json(before['llvm_inventory']['path']), 'extracted LLVM identity/modes differ')
        require(before == check_cache(cache), 'graphics cache changed during extraction')
        write_json(destination / 'result.json', dict(status='SOURCES_EXTRACTED_NOT_BUILT', sources=result,
                   llvm_trees=actual['trees'], llvm_file_count=len(actual['files']), export_profile=PROFILE,
                   extracted_llvm_inventory_sha256=hashlib.sha256(encoded(actual)).hexdigest()))
        return result
    except Exception as error:
        write_json(destination / 'failure.json', dict(status='SOURCE_EXTRACTION_FAILED', error=str(error)))
        raise


class _DigestWriter:
    def __init__(self, stream):
        self.stream, self.digest, self.size = stream, hashlib.sha256(), 0

    def write(self, raw):
        self.digest.update(raw); self.size += len(raw)
        return self.stream.write(raw)


class _DigestReader:
    def __init__(self, stream):
        self.stream, self.digest = stream, hashlib.sha256()

    def read(self, size=-1):
        raw = self.stream.read(size); self.digest.update(raw)
        return raw


def export_llvm(source, archive, inventory_path):
    """Export the fixed trees canonically; never identify this operation as a public fetch."""
    source, archive, inventory_path = map(real, (source, archive, inventory_path))
    require(archive != inventory_path, 'distinct archive/inventory outputs required')
    for path in (archive, inventory_path):
        require(not path.exists() and not path.is_symlink() and path.parent.is_dir(), 'fresh export file/parent required')
        require(not path.is_relative_to(source), 'export output must be outside source')
    before = source_inventory(source)
    inventory = canonical_inventory(before)
    files = {row['path']: row for row in inventory['files']}
    directories = set(LLVM_TREES)
    for name in files:
        directories.update(str(p) for p in PurePosixPath(name).parents if str(p) != '.')
    with archive.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', compresslevel=1, mtime=0, fileobj=raw) as compressed:
        bound = _DigestWriter(compressed)
        with tarfile.open(fileobj=bound, mode='w|', format=tarfile.PAX_FORMAT) as output:
            for name in ['', *sorted(set(files) | directories, key=os.fsencode)]:
                member = tarfile.TarInfo('llvm15-subtrees' + ('/' + name if name else ''))
                member.uid = member.gid = member.mtime = 0; member.uname = member.gname = ''
                if not name or name in directories:
                    member.type = tarfile.DIRTYPE; member.mode = 0o755; output.addfile(member)
                else:
                    row = files[name]; path = source / name; member.mode = row['mode']
                    if row['git_mode'] == '120000':
                        require(path.is_symlink() and os.readlink(path) == row['link_target'], 'source link changed during export')
                        member.type = tarfile.SYMTYPE; member.linkname = row['link_target']; output.addfile(member)
                    else:
                        regular(path); member.size = row['size']
                        with path.open('rb') as stream:
                            reader = _DigestReader(stream); output.addfile(member, reader)
                            require(reader.digest.hexdigest() == row['sha256'], 'source bytes changed during export')
    require(before == source_inventory(source), 'LLVM source changed during export')
    write_json(inventory_path, inventory)
    return dict(archive=dict(sha256=sha(archive), size=archive.stat().st_size,
                             tar_sha256=bound.digest.hexdigest(), tar_size=bound.size),
                inventory=dict(sha256=sha(inventory_path), file_count=len(inventory['files'])),
                export_profile=PROFILE, runtime=dict(python=platform.python_version(),
                    zlib_compile=zlib.ZLIB_VERSION, zlib_runtime=zlib.ZLIB_RUNTIME_VERSION),
                scope='canonical content export only; not evidence of a public fetch or native build')
