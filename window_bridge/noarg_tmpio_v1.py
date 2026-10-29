"""Private diagnostic output and byte-preserving archival; never launches code."""
from __future__ import annotations
import hashlib
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'pe-aot-ls-v4-'


def require(value, message):
    if not value: raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
        stream.flush(); os.fsync(stream.fileno())


def no_extended_acl(fd):
    """Darwin absent ACL=NULL/ENOENT; entry return 0 means an ACE exists."""
    require(sys.platform == 'darwin', 'Darwin ACL contract required')
    api = ctypes.CDLL(None, use_errno=True)
    api.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]; api.acl_get_fd_np.restype = ctypes.c_void_p
    api.acl_valid.argtypes = [ctypes.c_void_p]; api.acl_valid.restype = ctypes.c_int
    api.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]; api.acl_get_entry.restype = ctypes.c_int
    api.acl_free.argtypes = [ctypes.c_void_p]; api.acl_free.restype = ctypes.c_int
    ctypes.set_errno(0); acl = api.acl_get_fd_np(fd, 0x100)  # ACL_TYPE_EXTENDED in Darwin sys/acl.h.
    if not acl: return ctypes.get_errno() == errno.ENOENT
    try:
        if api.acl_valid(acl) != 0: return False
        entry = ctypes.c_void_p(); ctypes.set_errno(0)
        result = api.acl_get_entry(acl, 0, ctypes.byref(entry))  # ACL_FIRST_ENTRY.
        return result == -1 and ctypes.get_errno() == errno.EINVAL
    finally:
        api.acl_free(acl)


def output(path):
    require(path is not None, 'explicit existing output required for read-only mode')
    path = Path(path).absolute(); parent = path.parent
    require(path == path.resolve() and path.name == 'records' and parent.parent == Path('/private/tmp') and
            re.fullmatch(r'pe-aot-ls-v4-[a-z0-9_]{8}', parent.name) is not None,
            'exclusive canonical /private/tmp v4 parent required')
    info = parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
            info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
            'private output parent owner/mode differs')
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(fd)
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino) and no_extended_acl(fd),
                'private output parent has an extended ACL or ACL query failed')
    finally:
        os.close(fd)
    if path.exists():
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid(),
                'records root is not an owned real directory')
    return path


def allocate():
    parent = Path(tempfile.mkdtemp(prefix=PREFIX, dir='/private/tmp'))
    return output(parent / 'records')


def archive_output(path):
    path = Path(path).absolute()
    require(path == path.resolve() and path.parent == ROOT / 'build/window-bridge' and
            path.name.startswith('window-run-app-v4-'), 'new project window-run-app-v4-* archive required')
    return path


def tree(directory):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), 'real source tree required')
    # Include the root: a correct copy with a widened root mode would expose
    # otherwise identical private records beneath a traversable archive parent.
    rows = {'.': {'kind': 'directory', 'mode': stat.S_IMODE(directory.lstat().st_mode)}}
    for path in sorted(directory.rglob('*')):
        info = path.lstat(); name = str(path.relative_to(directory)); mode = stat.S_IMODE(info.st_mode)
        require(not stat.S_ISLNK(info.st_mode), 'archive cannot follow a symlink')
        if stat.S_ISDIR(info.st_mode): rows[name] = {'kind': 'directory', 'mode': mode}
        else:
            require(stat.S_ISREG(info.st_mode), 'archive requires ordinary files')
            require(info.st_size <= 128 * 1024 * 1024, 'archive file exceeds diagnostic bound')
            digest = sha(path); after = path.lstat()
            require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                    'source file changed while hashing')
            rows[name] = {'kind': 'file', 'mode': mode, 'size': info.st_size, 'sha256': digest}
    return rows


def archive(records, target):
    records = output(records); source = records.parent; target = archive_output(target)
    require(not target.exists(), 'archive output cannot be reused')
    before = tree(source)
    # copytree refuses an existing destination. Failed copies stay marked as
    # partial; the original private tmp tree is never removed or renamed.
    created = False
    try:
        target.mkdir()
        created = True
        shutil.copytree(source, target / 'original', copy_function=shutil.copy2)
        require(tree(source) == before == tree(target / 'original'), 'archive byte/mode identity mismatch')
        mapping = {str(source / name): {'archive': str(target / 'original' / name), **row}
                   for name, row in before.items()}
        record = {'status': 'ARCHIVED_ORIGINAL_BYTES_NOT_APP_ACCEPTANCE', 'source_parent': str(source),
                  'original_records': str(records), 'source_preserved': True, 'tree': before, 'mapping': mapping,
                  'source_sha256': {str(Path(__file__).resolve()): sha(__file__)},
                  'scope': 'unchanged original bytes/modes; absolute paths inside receipts are not rewritten'}
        write(target / 'archive.json', record)
        return verify_archive(target)
    except BaseException as problem:
        failure = {'status': 'ARCHIVE_FAILED_ORIGINAL_RETAINED', 'error': repr(problem),
                   'source_parent': str(source), 'original_records': str(records), 'target': str(target),
                   'scope': 'partial archive is not accepted; inspect retained original tmp tree'}
        if created and target.is_dir() and not (target / 'archive-failure.json').exists():
            write(target / 'archive-failure.json', failure)
        raise


def verify_archive(target):
    target = archive_output(target); raw = (target / 'archive.json').read_bytes(); record = json.loads(raw)
    require(record['status'] == 'ARCHIVED_ORIGINAL_BYTES_NOT_APP_ACCEPTANCE' and record['source_preserved'] is True,
            'archive is not complete')
    require(not (target / 'archive-failure.json').exists(), 'failed archive cannot be accepted')
    records = output(record['original_records']); source = records.parent
    require(record['source_parent'] == str(source) and record['source_sha256'] ==
            {str(Path(__file__).resolve()): sha(__file__)}, 'archive source/profile changed')
    expected = tree(source)
    require(expected == record['tree'] == tree(target / 'original'), 'original/archive current bytes or modes changed')
    require(record['mapping'] == {str(source / name): {'archive': str(target / 'original' / name), **row}
                                 for name, row in expected.items()}, 'archive path mapping differs')
    require({p.name for p in target.iterdir()} == {'archive.json', 'original'}, 'archive artifact set differs')
    require((target / 'archive.json').read_bytes() == raw, 'archive receipt changed during read')
    return {'status': record['status'], 'original_records': str(records),
            'archive_sha256': sha(target / 'archive.json'), 'files': sum(r['kind'] == 'file' for r in expected.values()),
            'source_retained': True, 'App_acceptance': False}
