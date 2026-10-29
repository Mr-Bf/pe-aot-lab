#!/usr/bin/env python3
"""Rebuild two original HLSL fixtures with a pinned native vkd3d compiler.

No GPU, Wine, Rosetta, or guest CPU execution occurs here. The compiler is a
build-time tool; it is not a dependency to package with the resulting App.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import struct
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parents[1] / 'work/shader-source-research'
OUT = ROOT / 'build/graphics-stage5/shaders'
SHADERS = ROOT / 'graphics_stage5/shaders'
TOOL_BUILD = WORK / 'build-vkd3d-formal'
TOOL_RECORD = OUT / 'compiler.json'
CLANG = Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang')
SDK = Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk')
ARCHIVES = {
    'vkd3d-1.17.tar.xz': ('vkd3d-1.17', 'bc61cb9e84d5045cbcaffbdd707940d399d8bf62874663dfe5809a0bfb87e9b6', 'https://dl.winehq.org/vkd3d/source/vkd3d-1.17.tar.xz'),
    'spirv-headers-1.3.290.0.tar.gz': ('SPIRV-Headers-vulkan-sdk-1.3.290.0', '1b9ff8a33e07814671dee61fe246c67ccbcfc9be6581f229e251784499700e24', 'https://codeload.github.com/KhronosGroup/SPIRV-Headers/tar.gz/refs/tags/vulkan-sdk-1.3.290.0'),
    'vulkan-headers-1.3.290.tar.gz': ('Vulkan-Headers-1.3.290', 'f38a653bf93cab7a2a229a53d2d53b1cba9a2819e4c0a7de13c54085bde9bcf5', 'https://codeload.github.com/KhronosGroup/Vulkan-Headers/tar.gz/refs/tags/v1.3.290'),
    'bison-3.8.2.tar.xz': ('bison-3.8.2', '9bba0214ccf7f1079c5d59210045227bcf619519840ebfa80cd3849cff5a5bf2', 'https://ftp.gnu.org/gnu/bison/bison-3.8.2.tar.xz'),
    'make-4.4.1.tar.gz': ('make-4.4.1', 'dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3', 'https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz'),
}
TOOL_SOURCES = ('vkd3d-1.17', 'SPIRV-Headers-vulkan-sdk-1.3.290.0', 'Vulkan-Headers-1.3.290')
BISON = WORK / 'build-bison/install/bin/bison'
MAKE = WORK / 'build-make/install/bin/make'
COMPILER = TOOL_BUILD / 'vkd3d-compiler'
HEADER = SHADERS / 'draw_shaders.h'
PROFILES = {'vs': ('vs_5_0', 'kTriangleVsDxbc', 1), 'ps': ('ps_5_0', 'kTrianglePsDxbc', 0)}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(paths):
    result = {}
    for path in sorted(set(map(Path, paths))):
        require(path.is_file(), 'missing dependency: ' + str(path))
        result[str(path.absolute())] = {'resolved': str(path.resolve()), 'sha256': sha(path)}
    return result


def check_identity(record):
    require(isinstance(record, dict) and record, 'empty dependency map')
    require(identity(record) == record, 'dependency identity changed')


def dump(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def command(args, name, cwd=ROOT, env=None):
    OUT.mkdir(parents=True, exist_ok=True)
    args = list(map(str, args))
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = OUT / (name + '.stdout')
    stderr = OUT / (name + '.stderr')
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    record = {'command': args, 'cwd': str(cwd), 'returncode': result.returncode,
              'stdout': str(stdout), 'stderr': str(stderr),
              'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr)}
    if result.returncode:
        dump(OUT / (name + '.failure.json'), record)
        raise RuntimeError('command failed; see ' + str(stderr))
    return record


def archive_files(name, verify=True):
    """Only regular files/directories, no traversal, symlinks, or hardlinks."""
    prefix, digest, _ = ARCHIVES[name]
    archive = WORK / 'downloads' / name
    require(sha(archive) == digest, 'fixed official archive SHA mismatch: ' + name)
    expected = {}
    with tarfile.open(archive) as stream:
        for member in stream:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts and path.parts[0] == prefix,
                    'unsafe source archive path')
            require(member.isfile() or member.isdir(), 'unsupported source archive member')
            if member.isfile():
                require(member.name not in expected, 'duplicate source file')
                data = stream.extractfile(member).read()
                expected[member.name] = hashlib.sha256(data).hexdigest()
        if not (WORK / prefix).exists():
            stream.extractall(WORK, filter='data')
    actual = {str(p.relative_to(WORK)): sha(p) for p in (WORK / prefix).rglob('*') if p.is_file()}
    require(not any(p.is_symlink() for p in (WORK / prefix).rglob('*')), 'source symlink rejected')
    if verify:
        require(actual == expected, 'actual source differs from complete archive: ' + name)
    return [WORK / relative for relative in expected]


def compiler_inputs():
    paths = [Path(__file__), CLANG, CLANG.parent/'ld', Path('/usr/bin/flex'),
             Path('/usr/bin/m4'), Path('/usr/bin/ar'), Path('/usr/bin/ranlib'),
             Path('/bin/sh'), BISON, MAKE]
    for name in ARCHIVES:
        paths.append(WORK / 'downloads' / name)
        require(sha(paths[-1]) == ARCHIVES[name][1], 'fixed tool archive differs: '+name)
        if ARCHIVES[name][0] in TOOL_SOURCES:
            paths.extend(archive_files(name))
    paths += [p for p in (WORK/'build-bison/install/share/bison').rglob('*') if p.is_file()]
    return paths


def c_dependencies():
    paths = set()
    for depfile in TOOL_BUILD.rglob('*.Po'):
        text = depfile.read_text().replace('\\\n', ' ')
        meaningful = [line for line in text.splitlines() if line.strip() and not line.startswith('#')]
        if not meaningful:
            require(depfile.relative_to(TOOL_BUILD).parts[0] in ('demos','tests') and
                    text.strip() in ('', '# dummy'), 'unknown empty dependency placeholder')
            continue
        first = meaningful[0]
        require(':' in first, 'malformed C dependency file')
        for token in shlex.split(first.split(':', 1)[1]):
            p = Path(token)
            paths.add((p if p.is_absolute() else TOOL_BUILD/p).absolute())
    require(len(paths) > 30, 'missing actual compiler C dependency closure')
    return sorted(paths)


def prepare_tool():
    """GNU Bison/Make are workspace tools; see shaders/README.md for bootstrap."""
    require(BISON.is_file() and MAKE.is_file(), 'build workspace Bison/Make first; see shaders/README.md')
    require(not TOOL_RECORD.exists(), 'compiler record exists; use verify instead of overwriting it')
    before = identity(compiler_inputs())
    TOOL_BUILD.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CC=str(CLANG), OBJC=str(CLANG), AR='/usr/bin/ar', RANLIB='/usr/bin/ranlib')
    args = [WORK/'vkd3d-1.17/configure', '--disable-tests', '--disable-demos', '--disable-doc',
            '--disable-shared', '--enable-static', '--disable-maintainer-mode', '--without-ncurses',
            '--without-opengl', '--without-xcb', '--without-spirv-tools',
            'SONAME_LIBVULKAN=libvulkan.dylib', 'BISON='+str(BISON),
            'CPPFLAGS=-I'+str(WORK/'SPIRV-Headers-vulkan-sdk-1.3.290.0/include')+
            ' -I'+str(WORK/'Vulkan-Headers-1.3.290/include'),
            'CFLAGS=-O2 -isysroot '+str(SDK)]
    commands = [command(args, 'compiler-configure', TOOL_BUILD, env)]
    commands.append(command([MAKE, 'include/private/vkd3d_version.h'], 'compiler-generate-version', TOOL_BUILD, env))
    commands.append(command([MAKE, '-j2', 'vkd3d-compiler', 'vkd3d-dxbc'], 'compiler-make', TOOL_BUILD, env))
    after = identity(compiler_inputs())
    require(before == after, 'compiler source/tool changed during build')
    require(COMPILER.read_bytes()[:8] == bytes.fromhex('cffaedfe0c000001'), 'compiler is not thin native ARM64')
    commands.append(command(['/usr/bin/otool', '-L', COMPILER], 'compiler-libraries'))
    libraries = (OUT/'compiler-libraries.stdout').read_text().splitlines()[1:]
    require(len(libraries) == 1 and libraries[0].strip().startswith('/usr/lib/libSystem.B.dylib '),
            'unexpected compiler runtime dependency')
    commands.append(command([COMPILER, '--version'], 'compiler-version'))
    artifacts = [COMPILER, TOOL_BUILD/'vkd3d-dxbc', TOOL_BUILD/'.libs/libvkd3d-shader.a',
                 TOOL_BUILD/'.libs/libvkd3d-common.a', TOOL_BUILD/'Makefile', TOOL_BUILD/'config.log',
                 TOOL_BUILD/'include/config.h']
    artifacts += [p for p in TOOL_BUILD.rglob('*.Po')]
    for cmd in commands:
        artifacts += [Path(cmd['stdout']), Path(cmd['stderr'])]
    record = {'schema': 1, 'status': 'NATIVE_COMPILER_BUILT', 'commands': commands,
              'sources_before': before, 'sources_after': after,
              'c_dependencies': identity(c_dependencies()), 'artifacts': identity(artifacts),
              'archives': ARCHIVES, 'compiler': str(COMPILER),
              'scope': 'native compiler only; explicit source/tool and actual C include closure; not all OS subprocess dependencies'}
    dump(TOOL_RECORD, record)
    return verify_compiler()


def verify_compiler():
    record = json.loads(TOOL_RECORD.read_text())
    require(record['status'] == 'NATIVE_COMPILER_BUILT' and record['archives'] == json.loads(json.dumps(ARCHIVES)), 'compiler record scope/version changed')
    actual = identity(compiler_inputs())
    require(actual == record['sources_before'] == record['sources_after'], 'compiler source/tool closure changed')
    require(identity(c_dependencies()) == record['c_dependencies'], 'actual compiler C include closure changed')
    check_identity(record['artifacts'])
    require(str(COMPILER) in record['artifacts'] and str(TOOL_BUILD/'.libs/libvkd3d-shader.a') in record['artifacts'], 'missing compiler artifacts')
    require(len(record['commands']) == 5 and all(c['returncode'] == 0 for c in record['commands']), 'compiler command failure')
    for cmd in record['commands']:
        for field in ('stdout', 'stderr'):
            require(sha(cmd[field]) == cmd[field+'_sha256'], 'compiler command log changed')
    return record


def inspect_dxbc(data, shader_type):
    require(len(data) >= 36 and data[:4] == b'DXBC', 'not a DXBC container')
    version, size, count = struct.unpack_from('<3I', data, 20)
    require(version == 1 and size == len(data) and 0 < count < 20, 'invalid DXBC header')
    require(32+count*4 <= size, 'truncated chunk table')
    chunks, spans, tokens = [], [], []
    for i in range(count):
        offset = struct.unpack_from('<I', data, 32+4*i)[0]
        require(offset >= 32+count*4 and offset+8 <= size, 'invalid chunk offset')
        length = struct.unpack_from('<I', data, offset+4)[0]
        end = offset+8+length
        require(end <= size and all(end <= lo or offset >= hi for lo,hi in spans), 'invalid/overlapping chunk')
        spans.append((offset,end))
        tag = data[offset:offset+4].decode('ascii')
        require(tag != 'DXIL', 'DXIL is not the DXBC/TPF profile')
        chunks.append({'tag': tag, 'offset': offset, 'size': length})
        if tag in ('SHDR', 'SHEX'):
            require(length >= 8 and length % 4 == 0, 'malformed TPF')
            token, words = struct.unpack_from('<2I', data, offset+8)
            require(token == (shader_type << 16)|0x50 and words*4 == length, 'wrong TPF stage/model')
            tokens.append(token)
    require(len(tokens) == 1 and any(c['tag']=='ISGN' for c in chunks) and any(c['tag']=='OSGN' for c in chunks), 'missing TPF/signatures')
    return {'container': 'DXBC', 'model': '5_0', 'shader_type': shader_type, 'size': size, 'chunks': chunks}


def header_text(blobs):
    result = ['// Generated from original HLSL by pinned vkd3d 1.17; see evidence.json.',
              '// SPDX-License-Identifier: MIT', '#pragma once', '#include <stdint.h>', '']
    for stage, (_, symbol, _) in PROFILES.items():
        result.append('static const uint8_t '+symbol+'[] = {')
        data = blobs[stage]
        result.extend('    '+', '.join('0x%02x'%b for b in data[i:i+12])+',' for i in range(0,len(data),12))
        result += ['};', '']
    return '\n'.join(result)


def shader_input_paths():
    return [Path(__file__), TOOL_RECORD, COMPILER,
            SHADERS/'triangle_vs.hlsl', SHADERS/'triangle_ps.hlsl']


def build_shaders():
    verify_compiler()
    before = identity(shader_input_paths())
    blobs, records, commands = {}, {}, []
    for stage, (profile, symbol, kind) in PROFILES.items():
        output = OUT/('triangle.'+stage+'.dxbc')
        source = SHADERS/('triangle_'+stage+'.hlsl')
        commands.append(command([COMPILER, '-x', 'hlsl', '-b', 'dxbc-tpf', '-p', profile,
                                 '-e', 'main', '-o', output, source], 'compile-'+stage))
        blobs[stage] = output.read_bytes()
        records[stage] = inspect_dxbc(blobs[stage], kind)
        records[stage].update({'sha256': sha(output), 'profile': profile, 'symbol': symbol})
        commands.append(command([COMPILER, '-x', 'dxbc-tpf', '-b', 'd3d-asm', output], 'disassemble-'+stage))
        assembly = (OUT/('disassemble-'+stage+'.stdout')).read_text()
        require(assembly.startswith(profile+'\n'), 'disassembler stage mismatch')
        if stage == 'vs':
            require('vertex_id' in assembly and 'position' in assembly, 'vertex shader signature missing')
        else:
            require('mov o0.xyzw, l(0, 1.00000000e+00, 0, 1.00000000e+00)' in assembly, 'pixel constant unexpected')
        # Independent second compiler invocation, same source/tool, exact bytes.
        replay = OUT/('triangle.'+stage+'.replay.dxbc')
        commands.append(command([COMPILER, '-x', 'hlsl', '-b', 'dxbc-tpf', '-p', profile,
                                 '-e', 'main', '-o', replay, source], 'recompile-'+stage))
        require(replay.read_bytes() == blobs[stage], 'non-reproducible DXBC output')
    HEADER.write_text(header_text(blobs))
    after = identity(shader_input_paths())
    require(before == after, 'shader source/compiler changed during compile')
    verify_compiler()
    artifacts = [HEADER] + [OUT/('triangle.'+stage+suffix) for stage in PROFILES for suffix in ('.dxbc','.replay.dxbc')]
    for cmd in commands:
        artifacts += [Path(cmd['stdout']), Path(cmd['stderr'])]
    record = {'schema': 1, 'status': 'SHADERS_BUILT_NOT_EXECUTED',
              'inputs_before': before, 'inputs_after': after, 'artifacts': identity(artifacts),
              'commands': commands, 'bytecode': records, 'gpu_executions': 0, 'guest_executions': 0,
              'expected_rgba8': [0,255,0,255], 'clear_rgba8': [255,0,255,255],
              'vertices': [[-1,-1,0,1],[3,-1,0,1],[-1,3,0,1]], 'vertex_count': 3,
              'rasterizer_contract': 'TRIANGLELIST, CULL_NONE, viewport32x32, no vertex buffers/input layout',
              'scope': 'two original HLSL sources compiled to DXBC/TPF by native build-time tool; no GPU/guest proof'}
    dump(OUT/'evidence.json', record)
    return verify_shaders()


def verify_shaders():
    compiler = verify_compiler()
    record = json.loads((OUT/'evidence.json').read_text())
    require(record['status'] == 'SHADERS_BUILT_NOT_EXECUTED' and record['gpu_executions'] == record['guest_executions'] == 0, 'shader scope/status changed')
    require(identity(shader_input_paths()) == record['inputs_before'] == record['inputs_after'], 'shader exact inputs changed')
    check_identity(record['artifacts'])
    expected = {str(HEADER)} | {str(OUT/('triangle.'+stage+suffix)) for stage in PROFILES for suffix in ('.dxbc','.replay.dxbc')}
    expected |= {str(OUT/(action+'-'+stage+'.'+stream)) for stage in PROFILES for action in ('compile','disassemble','recompile') for stream in ('stdout','stderr')}
    require(set(record['artifacts']) == expected, 'shader artifact closure changed')
    require(set(record['bytecode']) == set(PROFILES), 'shader stage set changed')
    require(record['expected_rgba8'] == [0,255,0,255] and record['vertex_count'] == 3, 'shader contract changed')
    require(record['clear_rgba8'] == [255,0,255,255] and record['vertices'] ==
            [[-1,-1,0,1],[3,-1,0,1],[-1,3,0,1]], 'shader geometry/clear contract changed')
    require(len(record['commands']) == 6 and all(c['returncode']==0 for c in record['commands']), 'shader compiler command failure')
    blobs = {}
    for stage, (profile, symbol, kind) in PROFILES.items():
        path = OUT/('triangle.'+stage+'.dxbc')
        blobs[stage] = path.read_bytes()
        expected_record = inspect_dxbc(blobs[stage], kind)
        expected_record.update({'sha256': sha(path), 'profile': profile, 'symbol': symbol})
        require(record['bytecode'][stage] == expected_record, 'shader bytecode metadata differs')
        require((OUT/('triangle.'+stage+'.replay.dxbc')).read_bytes() == blobs[stage], 'recompiled shader differs')
    require(HEADER.read_text() == header_text(blobs), 'header does not match actual DXBC')
    for cmd in record['commands']:
        for field in ('stdout','stderr'):
            require(sha(cmd[field]) == cmd[field+'_sha256'], 'shader command log changed')
    return {'status': 'SHADERS_CURRENT_NOT_EXECUTED', 'evidence': str(OUT/'evidence.json'),
            'evidence_sha256': sha(OUT/'evidence.json'), 'compiler_manifest_sha256': sha(TOOL_RECORD),
            'inputs': {**compiler['sources_after'], **compiler['c_dependencies'], **record['inputs_after']},
            'artifacts': {**compiler['artifacts'], **record['artifacts']}, 'bytecode': record['bytecode'],
            'expected_rgba8': record['expected_rgba8'], 'gpu_executions': 0, 'guest_executions': 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare-tool', action='store_true')
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    result = prepare_tool() if args.prepare_tool else verify_shaders() if args.verify_only else build_shaders()
    print(json.dumps({k: v for k,v in result.items() if k in ('status','evidence','evidence_sha256','compiler_manifest_sha256','bytecode','gpu_executions','guest_executions')}, indent=2))
