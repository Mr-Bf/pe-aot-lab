"""Pinned offline inputs for the native DXMT branch, without historical builds.

Preparation takes explicit source paths. Consumers read only this package's
versioned lock and the supplied cache; origin paths are descriptive metadata.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile

LOCK = Path(__file__).with_name('cache-lock.json')
LLVM_COMMIT = '8dfdcc7b7bf66834a761bd8de445840ef68e4d1a'
LLVM_TREES = {'llvm': 'eca74668552b64f2cb839a2084f8b5bbfe680a9b',
              'cmake': '1facab5a57298bef497f4a6d184184c87267c749'}
LLVM_FILE_COUNT = 55599
DXMT_COMMIT = 'd162ea44a31fbf9089ea09977337f0beb30bd082'
HEADERS_COMMIT = '9df86f2341616ef1888ae59919feaa6d4fad693d'
FIXED_SHA = {
    'dxmt': 'f94d264a4a8030c852f4ade3502118e597a22e87b63a5f1f4236954fe84d4973',
    'headers': '9c1b8bbfd2d6c758fac4d93c2808a46bc1eee429fe656b4f21b29e02615aa8aa',
    'cmake': 'b2a7da6b1f351024c84fe36af692f31a196cb21be74dae8a3f36925467fa676b',
    'ninja': '2c07378c1ccb6cfde4bc2e12877c9f365b31c62ddc4ec631421cb80e3a7e1f11',
    'meson': '4b27aafce281e652dcb437b28007457411245d975c48b5db3a797d3e93ae1585',
}


def specs():
    return {
        'llvm': dict(archive='llvm15-subtrees.tar.gz', archive_root='llvm15-subtrees',
                     source=dict(repository='llvm/llvm-project', commit=LLVM_COMMIT, trees=LLVM_TREES,
                                 scope='complete llvm and cmake Git subtrees only; not a full monorepo')),
        'dxmt': dict(archive='dxmt.tar.gz', archive_root='dxmt-' + DXMT_COMMIT,
                     source=dict(repository='3Shain/dxmt', commit=DXMT_COMMIT,
                                 url='https://codeload.github.com/3Shain/dxmt/tar.gz/' + DXMT_COMMIT)),
        'headers': dict(archive='directx-headers.tar.gz', archive_root='mingw-directx-headers-' + HEADERS_COMMIT,
                        source=dict(repository='misyltoad/mingw-directx-headers', commit=HEADERS_COMMIT,
                                    url='https://codeload.github.com/misyltoad/mingw-directx-headers/tar.gz/' + HEADERS_COMMIT)),
        'cmake': dict(archive='cmake.tar.gz', archive_root='cmake',
                      source=dict(version='4.4.4', url='https://ghcr.io/v2/homebrew/core/cmake/blobs/sha256:' + FIXED_SHA['cmake'])),
        'ninja': dict(archive='ninja.tar.gz', archive_root='ninja',
                      source=dict(version='1.13.2', url='https://ghcr.io/v2/homebrew/core/ninja/blobs/sha256:' + FIXED_SHA['ninja'])),
        'meson': dict(archive='meson-1.10.0-py3-none-any.whl', archive_root=None,
                      source=dict(version='1.10.0', project='https://github.com/mesonbuild/meson',
                                  origin='local pip HTTP cache; py3-none-any wheel; upstream signature not verified')),
    }


def require(ok, message):
    if not ok:
        raise ValueError(message)


def real(path):
    path = Path(path).absolute()
    require(path == path.resolve(), 'real path without symlink traversal required: ' + str(path))
    return path


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def write_json(path, value):
    with Path(path).open('xb') as stream:
        stream.write(encoded(value))


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_bytes(), object_pairs_hook=pairs)


def regular(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
            'regular unlinked input file required: ' + str(path))


def git_object(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def llvm_inventory(root):
    """Independently rebuild Git trees from actual bytes, modes and link targets."""
    root = real(root)
    files = []

    def walk(directory):
        entries = []
        for path in directory.iterdir():
            info = path.lstat(); mode = stat.S_IMODE(info.st_mode)
            relative = path.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode):
                oid = walk(path); git_mode = '40000'; is_directory = True
            else:
                is_directory = False
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(path)
                    require(not Path(target).is_absolute() and path.resolve().is_relative_to(root),
                            'LLVM source link escapes selected root: ' + relative)
                    raw = os.fsencode(target); git_mode = '120000'
                    row = dict(path=relative, mode=mode, git_mode=git_mode, size=len(raw),
                               sha256=hashlib.sha256(raw).hexdigest(), link_target=target)
                    oid = git_object('blob', raw)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                            'non-regular/hardlinked LLVM source: ' + relative)
                    git_mode = '100755' if mode & 0o100 else '100644'
                    digest = hashlib.sha256()
                    git = hashlib.sha1(b'blob ' + str(info.st_size).encode() + b'\0')
                    with path.open('rb') as stream:
                        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                            digest.update(chunk); git.update(chunk)
                    oid = git.hexdigest()
                    row = dict(path=relative, mode=mode, git_mode=git_mode, size=info.st_size,
                               sha256=digest.hexdigest())
                row['git_oid'] = oid; files.append(row)
            name = os.fsencode(path.name)
            entries.append((name + (b'/' if is_directory else b''),
                            git_mode.encode() + b' ' + name + b'\0' + bytes.fromhex(oid)))
        require(bool(entries), 'untracked empty directory in LLVM source: ' + str(directory))
        return git_object('tree', b''.join(raw for _, raw in sorted(entries)))

    trees = {}
    for name in sorted(LLVM_TREES):
        directory = root / name
        require(directory.is_dir() and not directory.is_symlink(), 'LLVM selected subtree absent: ' + name)
        trees[name] = walk(directory)
    return dict(schema=1, commit=LLVM_COMMIT, trees=trees,
                files=sorted(files, key=lambda item: os.fsencode(item['path'])))


def check_llvm_inventory(inventory):
    require(type(inventory) is dict and inventory.get('schema') == 1 and
            inventory.get('commit') == LLVM_COMMIT and inventory.get('trees') == LLVM_TREES and
            type(inventory.get('files')) is list and len(inventory['files']) == LLVM_FILE_COUNT,
            'LLVM inventory does not describe the fixed selected Git subtrees')


def extracted_llvm_inventory(inventory):
    """Expected filesystem identity after the declared archive-mode policy.

    The locked inventory retains original archive modes (including 664/775).
    Extraction sets regular files to 644/755 using the owner's executable bit;
    link modes and every content/Git identity field remain exact comparisons.
    """
    check_llvm_inventory(inventory)
    expected = json.loads(json.dumps(inventory))
    for row in expected['files']:
        mode, git_mode = row.get('mode'), row.get('git_mode')
        require(type(mode) is int and 0 <= mode <= 0o777, 'unsupported LLVM archive permission mode')
        require(git_mode in ('100644', '100755', '120000'), 'unsupported LLVM archive Git mode')
        if git_mode != '120000':
            require(bool(mode & 0o100) == (git_mode == '100755'), 'LLVM archive mode/Git executable bit differs')
            row['mode'] = 0o755 if mode & 0o100 else 0o644
    return expected


def check_cache(cache):
    cache = real(cache)
    require(cache.is_dir(), 'offline graphics cache directory absent')
    lock = read_json(LOCK)
    require(type(lock) is dict and lock.get('schema') == 1 and
            type(lock.get('packages')) is dict and set(lock['packages']) == set(specs()), 'invalid graphics cache lock')
    result = dict(cache=str(cache), lock_sha256=sha(LOCK), packages={})
    for name, expected in specs().items():
        row = lock['packages'][name]
        require(type(row) is dict and {key: row.get(key) for key in expected} == expected,
                'locked package identity differs: ' + name)
        require(type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']) and
                type(row.get('size')) is int and row['size'] > 0, 'invalid package digest/size: ' + name)
        if name in FIXED_SHA:
            require(row['sha256'] == FIXED_SHA[name], 'fixed original archive digest differs: ' + name)
        path = cache / expected['archive']; regular(path)
        require(path.stat().st_size == row['size'] and sha(path) == row['sha256'], 'cache package hash/size differs: ' + name)
        result['packages'][name] = dict(row, path=str(path))
    for key, filename in (('llvm_inventory', 'llvm15-files.json'), ('origins', 'origins.json')):
        row = lock.get(key)
        require(type(row) is dict and row.get('file') == filename and
                type(row.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'invalid cache metadata lock: ' + key)
        path = cache / filename; regular(path)
        require(sha(path) == row['sha256'], 'cache metadata hash differs: ' + key)
        result[key] = dict(row, path=str(path))
    inventory = read_json(result['llvm_inventory']['path']); check_llvm_inventory(inventory)
    require(lock['llvm_inventory'].get('file_count') == LLVM_FILE_COUNT, 'LLVM locked file count differs')
    return result


def safe_extract(archive, destination, archive_root):
    """Preflight the whole tar, then write files before contained symlinks.

    Source permissions become 644/755 while Git executable bits are preserved;
    no owner IDs, hardlinks, special files or pre-existing targets are accepted.
    """
    destination = real(destination)
    require(destination.is_dir(), 'archive destination parent absent')
    target = destination / archive_root
    require(not target.exists() and not target.is_symlink(), 'preserve existing source root: ' + str(target))
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        require(0 < len(members) <= 200000, 'archive member count outside bounds')
        seen = {}; size = 0
        for member in members:
            parts = member.name.rstrip('/').split('/')
            require(parts and parts[0] == archive_root and all(part not in ('', '.', '..') for part in parts)
                    and '\0' not in member.name and not member.name.startswith('/') and
                    (member.isdir() or member.isfile() or member.issym()) and not member.sparse and
                    not member.mode & 0o7000, 'unsafe archive member: ' + member.name)
            name = '/'.join(parts)
            require(name not in seen and (len(parts) > 1 or member.isdir()), 'duplicate/invalid archive root: ' + name)
            seen[name] = member; size += member.size
            require(size <= 4 * 1024 ** 3, 'archive expanded size outside bounds')
            if member.issym():
                link = PurePosixPath(member.linkname)
                require(bool(member.linkname) and not link.is_absolute() and '\0' not in member.linkname,
                        'unsafe archive link target')
                stack = parts[:-1]
                for part in link.parts:
                    if part == '..':
                        require(len(stack) > 1, 'archive link escapes root'); stack.pop()
                    elif part != '.':
                        stack.append(part)
                require(stack and stack[0] == archive_root, 'archive link escapes root')
        for name in seen:
            for parent in PurePosixPath(name).parents:
                if str(parent) in seen:
                    require(seen[str(parent)].isdir(), 'archive member traverses non-directory: ' + name)
        for name, member in seen.items():
            path = destination / name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True); path.chmod(0o755)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                original = stream.extractfile(member)
                require(original is not None, 'archive regular payload absent')
                with original, path.open('xb') as output:
                    shutil.copyfileobj(original, output)
                require(path.stat().st_size == member.size, 'archive payload truncated')
                path.chmod(0o755 if member.mode & 0o100 else 0o644)
        for name, member in seen.items():
            if member.issym():
                path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(member.linkname)
        for path in target.rglob('*'):
            require(path.resolve().is_relative_to(target), 'extracted path escapes root')
    require(target.is_dir() and not target.is_symlink(), 'source root absent after extraction')
    return target


def extract_sources(cache, destination):
    destination = real(destination)
    require(not destination.exists() and not destination.is_symlink(), 'fresh source destination required')
    before = check_cache(cache)
    destination.mkdir(parents=True)
    write_json(destination / 'started.json', dict(cache=before, scope='source extraction only; no native build'))
    try:
        result = {}
        for name in ('llvm', 'dxmt', 'headers'):
            row = before['packages'][name]
            result[name] = str(safe_extract(row['path'], destination, row['archive_root']))
        llvm = Path(result['llvm'])
        require({p.name for p in llvm.iterdir()} == set(LLVM_TREES), 'unexpected LLVM source root entries')
        actual = llvm_inventory(llvm); check_llvm_inventory(actual)
        expected = extracted_llvm_inventory(read_json(before['llvm_inventory']['path']))
        require(actual == expected, 'extracted LLVM inventory differs after explicit permission normalization')
        require(before == check_cache(cache), 'offline cache changed during extraction')
        write_json(destination / 'result.json', dict(status='SOURCES_EXTRACTED_NOT_BUILT', sources=result,
                                                    llvm_trees=actual['trees'], llvm_file_count=len(actual['files']),
                                                    permission_profile='regular-0644-or-0755-preserving-owner-executable-bit; symlink-mode-exact',
                                                    extracted_llvm_inventory_sha256=hashlib.sha256(encoded(actual)).hexdigest()))
        return result
    except Exception as error:
        write_json(destination / 'failure.json', dict(status='SOURCE_EXTRACTION_FAILED', error=str(error)))
        raise


def export_llvm(source, archive, inventory_path):
    """Create a deterministic archive from verified trees, never a build tree."""
    source = real(source)
    before = llvm_inventory(source); check_llvm_inventory(before)
    write_json(inventory_path, before)
    paths = []
    for name in sorted(LLVM_TREES):
        paths.append(source / name); paths.extend((source / name).rglob('*'))
    with Path(archive).open('xb') as raw, gzip.GzipFile(filename='', mode='wb', compresslevel=1, mtime=0, fileobj=raw) as compressed:
        with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as output:
            root = tarfile.TarInfo('llvm15-subtrees'); root.type = tarfile.DIRTYPE; root.mode = 0o755
            output.addfile(root)
            for path in sorted(paths, key=lambda p: os.fsencode(p.relative_to(source).as_posix())):
                info = path.lstat(); member = tarfile.TarInfo('llvm15-subtrees/' + path.relative_to(source).as_posix())
                member.mode = stat.S_IMODE(info.st_mode); member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ''
                if stat.S_ISDIR(info.st_mode):
                    member.type = tarfile.DIRTYPE; output.addfile(member)
                elif stat.S_ISLNK(info.st_mode):
                    member.type = tarfile.SYMTYPE; member.linkname = os.readlink(path); output.addfile(member)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'source changed to non-regular file')
                    member.size = info.st_size
                    with path.open('rb') as stream:
                        output.addfile(member, stream)
    require(before == llvm_inventory(source), 'LLVM source changed during export')
    return before


def prepare_cache(cache, llvm_source, archives):
    """Explicit preparation helper; returns the lock for exclusive publication."""
    cache = real(cache)
    require(not cache.exists() and not cache.is_symlink(), 'fresh cache directory required')
    require(set(archives) == set(FIXED_SHA), 'five original package paths required')
    inputs = {}
    for name, expected in FIXED_SHA.items():
        path = real(archives[name]); regular(path)
        require(sha(path) == expected, 'preparation original archive differs: ' + name)
        inputs[name] = dict(path=str(path), sha256=expected, size=path.stat().st_size)
    cache.mkdir(parents=True)
    try:
        for name, row in inputs.items():
            with Path(row['path']).open('rb') as original, (cache / specs()[name]['archive']).open('xb') as copied:
                shutil.copyfileobj(original, copied)
            require(sha(cache / specs()[name]['archive']) == row['sha256'], 'original archive changed during copy')
        inventory = export_llvm(llvm_source, cache / 'llvm15-subtrees.tar.gz', cache / 'llvm15-files.json')
        origins = dict(schema=1, original_packages=inputs, llvm_source=str(real(llvm_source)),
                       llvm_commit=LLVM_COMMIT, llvm_trees=LLVM_TREES,
                       export=dict(gzip_mtime=0, tar_uid=0, tar_gid=0, tar_mtime=0, compression_level=1),
                       scope='offline cached sources and packaged build tools; not full LLVM monorepo, build, or signature proof',
                       source_references={name: row['source'] for name, row in specs().items()})
        write_json(cache / 'origins.json', origins)
        packages = {name: dict(row, sha256=sha(cache / row['archive']), size=(cache / row['archive']).stat().st_size)
                    for name, row in specs().items()}
        return dict(schema=1, packages=packages,
                    llvm_inventory=dict(file='llvm15-files.json', sha256=sha(cache / 'llvm15-files.json'), file_count=len(inventory['files'])),
                    origins=dict(file='origins.json', sha256=sha(cache / 'origins.json')))
    except Exception as error:
        write_json(cache / 'preparation-failure.json', dict(status='CACHE_PREPARATION_FAILED', error=str(error)))
        raise
