"""Fresh offline graphics build tools. No pip, global installation or old receipts."""
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import zipfile

from portable_lifter_v1 import tools as shared

PINS = {
    'cmake.tar.gz': ('b2a7da6b1f351024c84fe36af692f31a196cb21be74dae8a3f36925467fa676b', 'cmake/4.4.4'),
    'ninja.tar.gz': ('2c07378c1ccb6cfde4bc2e12877c9f365b31c62ddc4ec631421cb80e3a7e1f11', 'ninja/1.13.2'),
    'meson-1.10.0-py3-none-any.whl': ('4b27aafce281e652dcb437b28007457411245d975c48b5db3a797d3e93ae1585', None),
}
DIST = 'meson-1.10.0.dist-info'
require, sha, real = shared.require, shared.digest, shared.real_path


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')


def inventory(root):
    result = {}
    for path in sorted(Path(root).rglob('*')):
        require(not path.is_symlink(), 'unexpected install symlink: ' + str(path))
        if path.is_file():
            require(path.stat().st_nlink == 1, 'unexpected hardlink')
            result[str(path.relative_to(root))] = dict(sha256=sha(path), mode=stat.S_IMODE(path.stat().st_mode))
        else:
            require(path.is_dir(), 'special file')
    return result


def wheel_contents(path):
    """Validate paths, complete RECORD hashes/sizes and pure-Python wheel metadata."""
    files = {}; seen = set()
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(0 < len(members) <= 3000 and sum(item.file_size for item in members) <= 128 * 1024**2, 'wheel size bounds')
        for item in members:
            name = item.filename.rstrip('/'); parts = name.split('/')
            require(name and '\\' not in name and ':' not in name and '\0' not in name and
                    all(part not in ('', '.', '..') for part in parts), 'unsafe wheel path')
            require(parts[0] in ('mesonbuild', DIST, 'meson-1.10.0.data'), 'unexpected wheel root')
            require(name.casefold() not in seen, 'duplicate/case-colliding wheel path'); seen.add(name.casefold())
            mode = item.external_attr >> 16
            require(not mode & 0o7000 and not item.flag_bits & 1, 'special mode or encrypted wheel entry')
            if item.is_dir():
                require(stat.S_IFMT(mode) in (0, stat.S_IFDIR), 'bad wheel directory'); continue
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG), 'wheel link/special entry')
            require(not name.endswith(('.pth', '.pyc', '.pyo', '.so', '.dylib')), 'wheel executable extension/injection unsupported')
            require(item.file_size <= 16 * 1024**2, 'wheel member too large')
            files[name] = (archive.read(item), mode & 0o777 or 0o644)
    record_name = DIST + '/RECORD'
    require(record_name in files, 'wheel RECORD missing')
    rows = list(csv.reader(io.StringIO(files[record_name][0].decode('utf-8')))); recorded = set()
    for row in rows:
        require(len(row) == 3 and row[0] in files and row[0] not in recorded, 'invalid/duplicate RECORD row')
        name, encoded, size = row; recorded.add(name)
        if name == record_name:
            require(encoded == size == '', 'RECORD self identity must be empty'); continue
        require(re.fullmatch(r'sha256=[A-Za-z0-9_-]{43}', encoded) is not None, 'RECORD SHA256 required')
        require(size == str(len(files[name][0])), 'RECORD size mismatch')
        expected = base64.urlsafe_b64decode(encoded[7:] + '=')
        require(hashlib.sha256(files[name][0]).digest() == expected, 'RECORD content hash mismatch')
    require(recorded == set(files), 'RECORD omitted a file')
    wheel = files[DIST + '/WHEEL'][0].decode(); metadata = files[DIST + '/METADATA'][0].decode()
    require('Root-Is-Purelib: true' in wheel and 'Tag: py3-none-any' in wheel, 'pure Python wheel required')
    require(re.search(r'^Name: meson$', metadata, re.M) and re.search(r'^Version: 1\.10\.0$', metadata, re.M), 'Meson metadata version differs')
    require(DIST + '/licenses/COPYING' in files and 'mesonbuild/mesonmain.py' in files, 'wheel license/module absent')
    for name in files:
        for parent in Path(name).parents:
            require(str(parent) not in files, 'wheel file used as directory')
    return files


def extract_wheel(path, destination):
    destination = real(destination)
    require(not destination.exists(), 'fresh wheel directory required')
    files = wheel_contents(path)  # No directory creation until every RECORD row is checked.
    destination.mkdir(parents=True)
    for name, (data, mode) in files.items():
        target = destination / name; target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(mode)
    return inventory(destination)


def meson_env(tools, python, sdk):
    """Pair this with [python, '-S', '-m', 'mesonbuild.mesonmain', ...]."""
    python, sdk = Path(python).absolute(), Path(sdk).absolute()
    require(python.is_file() and sdk.is_dir(), 'explicit Python and Apple SDK required')
    env = {key: os.environ[key] for key in ('HOME', 'TMPDIR') if key in os.environ}
    env.update(PATH=':'.join([str(Path(tools['cmake']).parent), str(Path(tools['ninja']).parent), '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
               LANG='C', LC_ALL='C', PYTHONPATH=str(tools['meson']), PYTHONNOUSERSITE='1', PYTHONDONTWRITEBYTECODE='1',
               SDKROOT=str(sdk), MACOSX_DEPLOYMENT_TARGET='15.2', CC='/usr/bin/clang', CXX='/usr/bin/clang++',
               AR='/usr/bin/ar', LD='/usr/bin/ld', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_CEILING_DIRECTORIES=str(Path(tools['meson']).parent.parent))
    return env


def call(run, argv, label, env, cwd=None):
    record = run(list(map(str, argv)), label, cwd=str(cwd) if cwd else None, env=env, expected=0)
    require(type(record) is dict and type(record.get('returncode')) is int and record['returncode'] == 0 and
            type(record.get('stdout')) is str and type(record.get('stderr')) is str, 'unsuccessful/incomplete command record: ' + label)
    return record


def install(prefix, cache, sdk, python, run):
    prefix, cache = real(prefix), real(cache)
    require(not prefix.exists(), 'fresh absent tooling prefix required')
    helper = Path(shared.__file__).resolve(); helper_hash = sha(helper)
    packages = {}
    for name, (expected, _) in PINS.items():
        path = cache / name
        require(path.is_file() and not path.is_symlink() and sha(path) == expected, 'fixed tool archive differs: ' + name)
        packages[name] = dict(path=str(path), sha256=expected)
    wheel = cache / 'meson-1.10.0-py3-none-any.whl'
    wheel_contents(wheel)
    prefix.mkdir(parents=True)
    for name in ('cmake.tar.gz', 'ninja.tar.gz'):
        shared.extract_archive(cache / name, prefix, PINS[name][1])
    tools = dict(cmake=prefix / 'cmake/4.4.4/bin/cmake', ninja=prefix / 'ninja/1.13.2/bin/ninja', meson=prefix / 'meson')
    meson_files = extract_wheel(wheel, tools['meson'])
    graph = shared.selected_closure(prefix, [tools['cmake'], tools['ninja']])
    env = meson_env(tools, python, sdk)
    commands = [call(run, [tools['cmake'], '--version'], 'graphics-tools-cmake-version', env),
                call(run, [tools['ninja'], '--version'], 'graphics-tools-ninja-version', env),
                call(run, [python, '-S', '-m', 'mesonbuild.mesonmain', '--version'], 'graphics-tools-meson-version', env, prefix)]
    require(commands[0]['stdout'].splitlines()[0] == 'cmake version 4.4.4' and commands[1]['stdout'].strip() == '1.13.2' and
            commands[2]['stdout'].strip() == '1.10.0', 'installed tool versions differ')
    require(all(sha(cache / name) == identity['sha256'] for name, identity in packages.items()) and sha(helper) == helper_hash, 'tool inputs changed')
    write(prefix / 'tooling.json', dict(schema=1, status='FRESH_OFFLINE_GRAPHICS_TOOLS_VERIFIED', packages=packages,
          paths={k:str(v.relative_to(prefix)) for k,v in tools.items()}, meson_files=meson_files, selected_graph=graph,
          shared_helper=dict(path=str(helper), sha256=helper_hash), commands=commands,
          external=dict(python=str(Path(python).resolve()), python_sha256=sha(python), sdk=str(sdk)),
          licenses={str(p.relative_to(prefix)):sha(p) for p in (prefix/'cmake/4.4.4/LICENSE.rst', prefix/'ninja/1.13.2/COPYING', tools['meson']/DIST/'licenses/COPYING')}))
    return tools
