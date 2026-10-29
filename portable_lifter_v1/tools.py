"""Install selected native build tools from pinned cache archives into a new prefix.

The caller supplies the command recorder. No download, global installation,
old-work symlink or Homebrew runtime fallback is used here. LLVM's unused tools
are retained as original package contents, not claimed to be fully validated.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import posixpath
import shutil
import struct
import tarfile


PACKAGES = {
    'llvm17.tar.gz': ('608b1dc67fe4d80baf65077c69a7c4d58350c800a9e25fce4438f11c90340d9c', 'llvm@17/17.0.6'),
    'cmake.tar.gz': ('b2a7da6b1f351024c84fe36af692f31a196cb21be74dae8a3f36925467fa676b', 'cmake/4.4.4'),
    'ninja.tar.gz': ('2c07378c1ccb6cfde4bc2e12877c9f365b31c62ddc4ec631421cb80e3a7e1f11', 'ninja/1.13.2'),
    'zstd-1.5.7.tar.gz': ('37d7284556b20954e56e1ca85b80226768902e2edabd3b649e9e72c0c9012ee3', 'zstd-1.5.7'),
}
ZSTD_SOURCE_URL = 'https://github.com/facebook/zstd/archive/refs/tags/v1.5.7.tar.gz'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def real_path(path):
    path = Path(path).absolute()
    require(path == path.resolve(), 'path may not traverse a symlink or dot segments: ' + str(path))
    return path


def check_cache(cache):
    cache = real_path(cache)
    require(cache.is_dir(), 'real cache directory required')
    result = {}
    for name, (expected, _) in PACKAGES.items():
        path = cache / name
        require(not path.is_symlink() and path.is_file(), 'regular cached archive required: ' + name)
        actual = digest(path)
        require(actual == expected, 'cached archive SHA-256 mismatch: ' + name)
        result[name] = dict(path=str(path), sha256=actual, bytes=path.stat().st_size)
    return result


def extract_archive(archive, destination, package_root):
    """Validate the entire member graph before writing ordinary files or links."""
    destination = real_path(destination)
    root_parts = PurePosixPath(package_root).parts
    require(root_parts and all(part not in ('.', '..', '') for part in root_parts) and
            not package_root.startswith('/'), 'invalid expected package root')
    require(destination.is_dir() and not (destination / package_root).exists(), 'fresh package destination required')
    with tarfile.open(archive, mode='r:gz') as tar:
        members = tar.getmembers()
        require(0 < len(members) <= 30000 and sum(m.size for m in members) <= 4 * 1024**3,
                'archive count or unpacked size exceeds selected-package bounds')
        entries = {}
        for member in members:
            name = member.name.rstrip('/')
            parts = name.split('/')
            require(name and not name.startswith('/') and '\\' not in name and
                    all(part not in ('', '.', '..') for part in parts), 'unsafe archive path: ' + member.name)
            require(tuple(parts[:len(root_parts)]) == root_parts, 'archive escaped expected package root: ' + name)
            require(name not in entries, 'duplicate archive member: ' + name)
            require(member.isfile() or member.isdir() or member.issym(), 'unsupported archive member kind: ' + name)
            require(0 <= member.size <= 512 * 1024**2, 'oversized archive member')
            entries[name] = member
        require(package_root in entries and entries[package_root].isdir(), 'package root directory absent')
        links = {}
        for name, member in entries.items():
            parent = PurePosixPath(name).parent
            while str(parent) != '.':
                if str(parent) in entries:
                    require(entries[str(parent)].isdir(), 'archive traverses a non-directory member')
                existing = destination / str(parent)
                require(not existing.is_symlink() and (not existing.exists() or existing.is_dir()),
                        'archive traverses an existing non-directory or symlink')
                parent = parent.parent
            require(not (destination / name).exists() and not (destination / name).is_symlink(),
                    'archive would replace existing content')
            if member.issym():
                target = member.linkname
                require(target and not target.startswith('/') and '\\' not in target, 'absolute or invalid archive link')
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                require(resolved == package_root or resolved.startswith(package_root + '/'), 'archive link escapes package')
                require(resolved in entries, 'archive link target absent')
                links[name] = resolved
        for origin in links:
            seen = set(); current = origin
            while current in links:
                require(current not in seen, 'archive symlink cycle')
                seen.add(current); current = links[current]
        # Links are created last, so no extraction write can traverse one.
        for name, member in entries.items():
            path = destination / name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as source, path.open('xb') as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                require(path.stat().st_size == member.size, 'archive file truncated')
                path.chmod(member.mode & 0o777)
        for name in links:
            path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(entries[name].linkname)
        for name, member in entries.items():
            if member.isdir():
                (destination / name).chmod(member.mode & 0o777)
    return dict(package_root=package_root, members=len(members), symlinks=len(links),
                regular_bytes=sum(m.size for m in members if m.isfile()))


def macho(path):
    """Read only load commands; this never executes or loads the inspected image."""
    with Path(path).open('rb') as stream:
        header = stream.read(32)
        require(len(header) == 32, 'truncated Mach-O header')
        magic, cpu, _, filetype, count, size, _, _ = struct.unpack('<8I', header)
        require(magic == 0xfeedfacf and cpu == 0x100000c and filetype in (2, 6), 'thin ARM64 code required')
        require(0 < count <= 4096 and 0 < size <= 4 * 1024**2, 'Mach-O load command bounds')
        data = stream.read(size)
    require(len(data) == size, 'truncated load commands')
    result = dict(filetype=filetype, identity=None, rpaths=[], dependencies=[])
    position = 0
    for _ in range(count):
        require(position + 8 <= size, 'load command header outside buffer')
        command, length = struct.unpack_from('<II', data, position)
        require(length >= 8 and position + length <= size, 'invalid load command length')
        if command in (0xc, 0xd, 0x80000018, 0x8000001f, 0x20, 0x80000023, 0x8000001c):
            require(length >= 12, 'short string load command')
            offset = struct.unpack_from('<I', data, position + 8)[0]
            require(12 <= offset < length, 'load command string offset')
            raw = data[position + offset:position + length]
            require(b'\0' in raw, 'unterminated load command string')
            value = raw.split(b'\0')[0].decode()
            if command == 0xd:
                require(result['identity'] is None, 'duplicate dylib identity'); result['identity'] = value
            elif command == 0x8000001c:
                result['rpaths'].append(value)
            else:
                result['dependencies'].append(value)
        position += length
    require(position == size, 'load command total differs')
    return result


def system_image(value):
    return value.startswith(('/usr/lib/', '/System/Library/')) and '..' not in PurePosixPath(value).parts


def selected_closure(prefix, seeds):
    """Reject any non-system runtime resolution outside this installation."""
    prefix = real_path(prefix); pending = list(map(Path, seeds)); nodes = {}; edges = []
    while pending:
        path = pending.pop().resolve()
        require(path.is_relative_to(prefix) and path.is_file(), 'selected image escaped installation')
        if str(path) in nodes:
            continue
        info = macho(path)
        if info['identity'] is not None:
            require(info['identity'].startswith('@rpath/') and '/' not in info['identity'][7:], 'non-relative selected dylib identity')
        rpaths = []
        for value in info['rpaths']:
            require(value == '@loader_path' or value.startswith('@loader_path/'), 'non-relative selected search path')
            resolved = (path.parent / value[len('@loader_path'):].lstrip('/')).resolve()
            require(resolved.is_relative_to(prefix), 'selected search path escaped installation')
            rpaths.append(resolved)
        for dependency in info['dependencies']:
            if system_image(dependency):
                edges.append([str(path), dependency, dependency]); continue
            if dependency.startswith('@loader_path/'):
                candidates = [(path.parent / dependency[len('@loader_path/'):]).resolve()]
            elif dependency.startswith('@rpath/'):
                candidates = [(directory / dependency[len('@rpath/'):]).resolve() for directory in rpaths]
            else:
                raise ValueError('non-relative non-system dependency: ' + dependency)
            require(candidates and all(p.is_relative_to(prefix) for p in candidates), 'dependency search escaped installation')
            matches = list(dict.fromkeys(p for p in candidates if p.is_file()))
            require(len(matches) == 1, 'missing or ambiguous installed dependency: ' + dependency)
            edges.append([str(path), dependency, str(matches[0])]); pending.append(matches[0])
        nodes[str(path)] = dict(**info, sha256=digest(path))
    return dict(nodes=nodes, edges=edges)


def install(prefix, cache, run, jobs=2):
    """Return a manifest; caller records commands and writes its own receipt."""
    prefix = real_path(prefix)
    require(type(jobs) is int and 1 <= jobs <= 8, 'jobs must be 1..8')
    require(not prefix.exists() or (prefix.is_dir() and not any(prefix.iterdir())), 'fresh empty tool prefix required')
    packages = check_cache(cache)  # All pinned hashes precede extraction or execution.
    prefix.mkdir(parents=True, exist_ok=True)
    extracted = {}
    for name, (_, package_root) in PACKAGES.items():
        destination = prefix
        if name.startswith('zstd-'):
            destination = prefix / 'sources'; destination.mkdir()
        extracted[name] = extract_archive(packages[name]['path'], destination, package_root)
    require(check_cache(cache) == packages, 'cached packages changed during extraction')
    llvm = prefix / 'llvm@17/17.0.6'; cmake = prefix / 'cmake/4.4.4/bin/cmake'
    ninja = prefix / 'ninja/1.13.2/bin/ninja'; source = prefix / 'sources/zstd-1.5.7'
    zstd = prefix / 'zstd'; build = prefix / 'build/zstd'
    bootstrap_graph = selected_closure(prefix, [cmake, ninja])
    env = {key: os.environ[key] for key in ('HOME', 'TMPDIR') if key in os.environ}
    env.update(PATH=str(cmake.parent) + ':' + str(ninja.parent) + ':/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C')
    commands = []

    def execute(argv, label, cwd=None):
        record = run(list(map(str, argv)), label, cwd=cwd, env=env)
        require(type(record.get('returncode')) is int and record['returncode'] == 0, 'command did not succeed: ' + label)
        commands.append(record)
        return record

    sdk_result = execute(['/usr/bin/xcrun', '--show-sdk-path'], 'tools-sdk')
    sdk = sdk_result['stdout'].strip()
    require(sdk.startswith('/') and '\n' not in sdk and Path(sdk).is_dir(), 'native macOS SDK unavailable')
    execute([cmake, '-S', source / 'build/cmake', '-B', build, '-G', 'Ninja',
             '-DCMAKE_MAKE_PROGRAM=' + str(ninja), '-DCMAKE_C_COMPILER=/usr/bin/clang',
             '-DCMAKE_CXX_COMPILER=/usr/bin/clang++', '-DCMAKE_OSX_ARCHITECTURES=arm64',
             '-DCMAKE_OSX_SYSROOT=' + sdk, '-DCMAKE_BUILD_TYPE=Release',
             '-DCMAKE_INSTALL_PREFIX=' + str(zstd), '-DCMAKE_INSTALL_LIBDIR=lib',
             '-DCMAKE_INSTALL_NAME_DIR=@rpath', '-DCMAKE_INSTALL_RPATH=@loader_path',
             '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF', '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
             '-DZSTD_BUILD_SHARED=ON', '-DZSTD_BUILD_STATIC=OFF', '-DBUILD_SHARED_LIBS=ON',
             '-DZSTD_BUILD_PROGRAMS=OFF', '-DZSTD_BUILD_TESTS=OFF', '-DZSTD_BUILD_CONTRIB=OFF',
             '-DZSTD_LEGACY_SUPPORT=ON', '-DZSTD_MULTITHREAD_SUPPORT=ON'], 'tools-zstd-configure')
    execute([cmake, '--build', build, '--target', 'libzstd_shared', '--parallel', str(jobs)], 'tools-zstd-build')
    execute([cmake, '--install', build], 'tools-zstd-install')
    zstd_library = zstd / 'lib/libzstd.1.5.7.dylib'
    require(zstd_library.is_file() and (zstd / 'lib/libzstd.1.dylib').resolve() == zstd_library, 'installed zstd version/link differs')
    licenses = {}
    for name in ('LICENSE', 'COPYING'):
        destination = zstd / 'share/licenses/zstd' / name
        destination.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(source / name, destination)
        licenses[str(destination.relative_to(prefix))] = digest(destination)
    # pkg-config is not used by this build, but must not retain the first prefix.
    pkgconfig = zstd / 'lib/pkgconfig/libzstd.pc'; text = pkgconfig.read_text()
    require(text.count('prefix=' + str(zstd)) == 1, 'unexpected zstd pkg-config prefix')
    pkgconfig.write_text(text.replace('prefix=' + str(zstd), 'prefix=${pcfiledir}/../..', 1))
    modified = []
    for name, identity in [('libLLVM.dylib', 'libLLVM.dylib'), ('libclang-cpp.dylib', 'libclang-cpp.dylib'),
                           ('libunwind.1.0.dylib', 'libunwind.1.dylib')]:
        path = llvm / 'lib' / name; before = digest(path); info = macho(path)
        require(info['identity'].startswith('@@HOMEBREW_PREFIX@@/opt/llvm@17/'), 'unexpected pristine LLVM dylib identity')
        execute(['/usr/bin/install_name_tool', '-id', '@rpath/' + identity, path], 'tools-id-' + name)
        if name == 'libLLVM.dylib':
            dependency = '@@HOMEBREW_PREFIX@@/opt/zstd/lib/libzstd.1.dylib'
            require(info['dependencies'].count(dependency) == 1, 'unexpected pristine LLVM zstd dependency')
            execute(['/usr/bin/install_name_tool', '-change', dependency,
                     '@loader_path/../../../zstd/lib/libzstd.1.dylib', path], 'tools-zstd-relative-reference')
        execute(['/usr/bin/codesign', '--force', '--sign', '-', path], 'tools-sign-' + name)
        modified.append(dict(path=str(path),before_sha256=before,after_sha256=digest(path)))
    execute(['/usr/bin/install_name_tool', '-id', '@rpath/libzstd.1.dylib', zstd_library], 'tools-id-zstd')
    execute(['/usr/bin/codesign', '--force', '--sign', '-', zstd_library], 'tools-sign-zstd')
    seeds = [cmake, ninja, llvm / 'bin/clang', llvm / 'bin/opt', llvm / 'bin/llvm-link',
             llvm / 'lib/libunwind.1.0.dylib', zstd_library]
    graph = selected_closure(prefix, seeds)
    for path in prefix.rglob('*'):
        if path.is_symlink():
            require(path.resolve().is_relative_to(prefix) and path.resolve().exists(), 'installed symlink escaped prefix or is broken')
    require(check_cache(cache) == packages, 'cached packages changed during installation')
    return dict(schema=1,status='TOOLS_INSTALLED_SELECTED_NATIVE_CLOSURE_VERIFIED',prefix=str(prefix),
                paths=dict(cmake=str(cmake),ninja=str(ninja),llvm=str(llvm),zstd=str(zstd)),
                packages=packages,extracted=extracted,commands=commands,modified_llvm=modified,
                zstd_source_url=ZSTD_SOURCE_URL,zstd_source_sha256=PACKAGES['zstd-1.5.7.tar.gz'][0],
                licenses=licenses,bootstrap_graph=bootstrap_graph,selected_graph=graph,
                external_prerequisites=dict(sdk=sdk,cc='/usr/bin/clang',cxx='/usr/bin/clang++'),
                guest_executions=0,gpu_executions=0,
                scope='Fresh cached packages and locally compiled zstd; selected runtime load paths closed within prefix plus Apple system libraries. No Remill build, guest execution or clean-machine claim; unused LLVM tools are not validated.')
