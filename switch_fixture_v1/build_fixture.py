"""One serial, offline COFF shape experiment; never executes produced code."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import traceback

from portable_lifter_v1 import tools


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def build(prefix, out):
    prefix = tools.real_path(prefix)
    out = tools.real_path(out)
    if os.path.lexists(out):
        raise ValueError('fresh absent evidence directory required')
    if out.is_relative_to(prefix) or prefix.is_relative_to(out):
        raise ValueError('evidence and provider must be disjoint')
    out.mkdir(parents=True)
    records = []
    try:
        provider_path = prefix / 'provider.json'
        provider_sha = sha(provider_path)
        if provider_sha != 'b9219c1305711dd8d96efeb03c488761de9c57b75827fd23aa2bbaf21b16b237':
            raise ValueError('this experiment requires the accepted fresh-03 provider')
        provider = json.loads(provider_path.read_bytes())
        llvm = prefix / provider['layout']['llvm']
        selected = {name: (llvm / 'bin' / name).resolve(strict=True)
                    for name in ('clang', 'llvm-objdump', 'llvm-readobj')}
        # objdump/readobj were retained bottle contents, not earlier provider
        # runtime roles: check their actual native dependency closure now.
        graph = tools.selected_closure(prefix, list(selected.values()))
        source = Path(__file__).with_name('switch8.c')
        inputs = {str(path.resolve()): sha(path) for path in (source, Path(__file__), provider_path)}
        for name, item in graph['nodes'].items():
            inputs[name] = item['sha256']
        frozen = out / 'switch8.c'; shutil.copyfile(source, frozen)
        write(out / 'started.json', dict(prefix=str(prefix), inputs=inputs, selected= {k:str(v) for k,v in selected.items()},
            selected_graph=graph, provider_sha256=provider_sha,
            scope='One Windows x86-64 COFF compilation and static inspection; not linked PE or translated/executed code.'))
        env = {k: os.environ[k] for k in ('HOME', 'TMPDIR') if k in os.environ}
        env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')

        def run(label, argv):
            argv = list(map(str, argv))
            row = dict(argv=argv, cwd=str(out), env=env, started_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            write(out / (label + '.started.json'), row)
            print('RUN ' + label, flush=True)
            try:
                with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
                    process = subprocess.run(argv, cwd=out, env=env, stdout=stdout, stderr=stderr, timeout=60)
                row['returncode'] = process.returncode
            except BaseException as error:
                row.update(returncode=None, error_type=type(error).__name__, error=str(error))
                raise
            finally:
                row['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                for name in ('stdout', 'stderr'):
                    path = out / (label + '.' + name)
                    if path.is_file(): row[name] = dict(path=str(path), sha256=sha(path))
                write(out / (label + '.result.json'), row)
                records.append(row)
            if row['returncode'] != 0:
                raise ValueError('tool failure; original output preserved: ' + label)

        obj = out / 'switch8.obj'
        run('01-clang-version', [selected['clang'], '--version'])
        run('02-compile', [selected['clang'], '--target=x86_64-pc-windows-msvc', '-std=c11', '-O2', '-ffreestanding',
            '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-Wall', '-Wextra', '-Werror', '-c', frozen, '-o', obj])
        run('03-disassembly', [selected['llvm-objdump'], '--disassemble', '--reloc', '--x86-asm-syntax=intel', obj])
        run('04-coff-metadata', [selected['llvm-readobj'], '--file-headers', '--sections', '--symbols', '--relocations', obj])
        run('05-section-bytes', [selected['llvm-objdump'], '--full-contents', obj])
        header = struct.unpack('<HHIIIHH', obj.read_bytes()[:20])
        if header[0] != 0x8664 or header[5] != 0:
            raise ValueError('not an x86-64 COFF object with no optional executable header')
        if sha(frozen) != inputs[str(source.resolve())] or any(sha(Path(p)) != value for p, value in inputs.items()):
            raise ValueError('source or selected provider inputs changed')
        result = dict(status='COFF_COMPILED_STATIC_INSPECTED_NOT_PE_NOT_EXECUTED', provider_sha256=provider_sha,
            coff=dict(machine=header[0], section_count=header[1], optional_header_bytes=header[5], sha256=sha(obj)),
            source_sha256=sha(frozen), commands=records, guest_executions=0, app_executions=0, gpu_executions=0,
            note='Whether this contains the intended jump-table shape requires review of the saved disassembly and relocation records.')
        write(out / 'result.json', result)
        return result
    except BaseException as error:
        write(out / 'failure.json', dict(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc(),
            commands=records, guest_executions=0, app_executions=0, gpu_executions=0))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True); parser.add_argument('--out', required=True)
    arguments = parser.parse_args()
    print(build(arguments.prefix, arguments.out)['status'])
