"""Real fresh Win64 PE -> unified CLI -> ARM64 App -> persisted guest state.

Explicit test driver; unlike build/analyze, this command DOES execute the
translated guest. Use a new --out directory for every attempt.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parent.parent / 'work'
LLVM = WORK / 'remill-stage2/llvm@17/17.0.6/bin'
LINKER = WORK / 'file-bridge/tools/lld-link'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dump(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def execute(out):
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(name, argv, expected=0):
        argv = list(map(str, argv))
        completed = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=300)
        (out / (name + '.stdout')).write_bytes(completed.stdout)
        (out / (name + '.stderr')).write_bytes(completed.stderr)
        commands.append(dict(name=name, argv=argv, returncode=completed.returncode, expected_returncode=expected))
        dump(out / (name + '.command.json'), commands[-1])
        require(completed.returncode == expected, name + ' unexpected return code: ' + str(completed.returncode))
        return completed.stdout

    try:
        source = ROOT / 'migration_v1/examples/counter.c'
        import_def = ROOT / 'process_bridge/kernel32.def'
        tools = [LLVM / n for n in ('clang', 'llvm-dlltool', 'llvm-readobj')]
        sources = {str(p): sha(p) for p in (source, import_def, Path(__file__), *tools, LINKER)}
        run('import-library', [LLVM / 'llvm-dlltool', '-m', 'i386:x86-64', '-d', import_def, '-l', out / 'kernel32.lib'])
        flags = ['-target', 'x86_64-pc-windows-msvc', '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
                 '-ffreestanding', '-nostdinc', '-fno-builtin', '-fno-stack-protector', '-mno-stack-arg-probe',
                 '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-fno-vectorize', '-fno-slp-vectorize',
                 '-mno-sse', '-mno-sse2', '-mno-mmx', '-fno-optimize-sibling-calls']
        run('compile-pe', [LLVM / 'clang', *flags, '-c', source, '-o', out / 'counter.obj'])
        pe = out / 'counter.exe'
        run('link-pe', [LINKER, '/entry:migration_entry', '/subsystem:console', '/nodefaultlib', '/machine:x64',
                       '/base:0x140000000', '/dynamicbase', '/nxcompat', '/fixed:no', '/timestamp:0',
                       '/include:counter_anchor', '/out:' + str(pe), out / 'counter.obj', out / 'kernel32.lib'])
        run('pe-inventory-oracle', [LLVM / 'llvm-readobj', '--file-headers', '--sections', '--coff-imports', pe])
        analysis = json.loads(run('analyze', [sys.executable, '-m', 'migration_v1', 'analyze', pe]))
        require(analysis['status'] == 'ELIGIBLE_FOR_BUILD_NOT_DECODED', 'fresh PE metadata rejected')
        product = out / 'product'
        result = json.loads(run('build', [sys.executable, '-m', 'migration_v1', 'build', pe, '--out', product]))
        require(result['status'] == 'BUILT_NOT_EXECUTED' and result['input_sha256'] == sha(pe), 'real AOT build not established')
        require(result['instructions'] > 1 and result['guest_executions'] == 0, 'build claim inconsistent')
        metadata = json.loads((product / 'native/fixture-metadata.json').read_bytes())
        require(metadata == {}, 'fixture observations or external addresses were supplied')
        executable = Path(result['executable'])
        magic, cpu = struct.unpack_from('<II', executable.read_bytes())
        require((magic, cpu) == (0xfeedfacf, 0x100000c), 'output is not thin ARM64 Mach-O')
        run('signature', ['codesign', '--verify', '--strict', result['app']])
        dependencies = run('dependencies', ['otool', '-L', executable]).decode()
        require([l.strip().split(' (', 1)[0] for l in dependencies.splitlines()[1:] if l.strip()]
                == ['/usr/lib/libSystem.B.dylib'], 'unexpected executable dependency')
        data = out / 'data'
        data.mkdir(mode=0o700)
        executions = []
        for index in (1, 2):
            payload = json.loads(run('native-' + str(index), [executable, '--data-dir', data]))
            saved = (data / 'migration-counter.bin').read_bytes()
            (out / ('save-' + str(index) + '.bin')).write_bytes(saved)
            require(saved == struct.pack('<I', index), 'guest save/restore value differs')
            require(payload['outcome'] == 'PROCESS_EXITED' and payload['exit_requested'] == 1
                    and payload['exit_code'] == 0 and payload['fault']['status'] == 0, 'guest failed')
            require(payload['pe_sha256'] == sha(pe) and payload['entry_arguments'] == 0, 'guest input identity differs')
            require(payload['bytes_written'] == 4 and payload['bytes_read'] == (0 if index == 1 else 4), 'guest I/O totals differ')
            require(payload['open_before_cleanup'] == payload['open_after_cleanup'] == payload['cleanup_closes']
                    == payload['cleanup_errors'] == 0, 'cleanup masked a guest handle leak')
            executions.append(payload)
        run('verify', [sys.executable, '-m', 'migration_v1', 'verify', product])
        run('verify-optimized', [sys.executable, '-O', '-m', 'migration_v1', 'verify', product])
        before = sha(product / 'result.json')
        run('existing-out-rejected', [sys.executable, '-m', 'migration_v1', 'build', pe, '--out', product], 64)
        require(sha(product / 'result.json') == before, 'failed overwrite changed existing receipt')
        unknown = out / 'unknown-import.exe'
        changed = pe.read_bytes().replace(b'ExitProcess\0', b'ExitProcesX\0')
        require(changed != pe.read_bytes(), 'unknown import mutation absent')
        unknown.write_bytes(changed)
        rejected = json.loads(run('unknown-import', [sys.executable, '-m', 'migration_v1', 'build', unknown, '--out', out / 'reject-import'], 2))
        require(rejected['stage'] == 'analysis' and not (out / 'reject-import/native').exists(), 'unsupported import reached compilation')
        # A metadata-eligible PE can still fail instruction admission. SYSCALL is
        # intentionally outside this single-module typed API profile.
        invalid = bytearray(pe.read_bytes())
        info = analysis['inventory']
        section = next(s for s in info['sections'] if s['rva'] <= info['entry_rva'] < s['rva'] + s['raw_size'])
        at = section['raw_offset'] + info['entry_rva'] - section['rva']
        invalid[at:at + 2] = b'\x0f\x05'
        syscall = out / 'syscall.exe'
        syscall.write_bytes(invalid)
        require(json.loads(run('syscall-analysis', [sys.executable, '-m', 'migration_v1', 'analyze', syscall]))['status']
                == 'ELIGIBLE_FOR_BUILD_NOT_DECODED', 'metadata test accidentally decoded instructions')
        rejection = json.loads(run('syscall-build', [sys.executable, '-m', 'migration_v1', 'build', syscall, '--out', out / 'reject-syscall'], 2))
        require(rejection['stage'] == 'aot-build' and 'REJECT' in rejection['error'], 'decoder rejection missing')
        require(not list((out / 'reject-syscall').glob('*.app')), 'rejected instruction produced App')
        require({p: sha(p) for p in sources} == sources, 'fixture build input changed')
        result = dict(status='PASS', sources=sources, input_sha256=sha(pe), executable_sha256=sha(executable),
                      build_receipt_sha256=sha(product / 'result.json'), instructions=result['instructions'],
                      guest_executions=2, executions=executions, commands=commands,
                      limitations=['CLI bundle, not a GUI App', 'no Windows/Wine oracle or performance comparison',
                                   'local toolchain; clean-machine setup not verified'])
        dump(out / 'evidence.json', result)
        print(json.dumps({k: result[k] for k in ('status', 'input_sha256', 'executable_sha256', 'instructions', 'guest_executions')}, indent=2))
    except Exception as error:
        dump(out / 'failure.json', dict(status='FAIL', error_type=type(error).__name__, error=str(error), commands=commands))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    execute(parser.parse_args().out)
