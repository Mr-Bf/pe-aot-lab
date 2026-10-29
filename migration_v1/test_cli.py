"""Regression of unified CLI on an existing accepted PE, not a new target pass.

The separate fresh counter integration remains failing until its instruction
gaps are implemented. This test must not substitute for that acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


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
        p = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=300)
        (out / (name + '.stdout')).write_bytes(p.stdout)
        (out / (name + '.stderr')).write_bytes(p.stderr)
        row = dict(name=name, argv=argv, returncode=p.returncode, expected_returncode=expected)
        commands.append(row)
        dump(out / (name + '.command.json'), row)
        require(p.returncode == expected, name + ': unexpected return code ' + str(p.returncode))
        return p.stdout

    try:
        original = ROOT / 'build/process-bridge/fixtures/normal.exe'
        require(sha(original) == '5b7c5608d4b3dec83b4223cb08b26f2ac6c542d644330fe63b6cf27e0fc63b50', 'old fixture differs')
        pe = out / 'input with spaces.exe'
        shutil.copy2(original, pe)
        product = out / 'product with spaces'
        analysis = json.loads(run('analyze', [sys.executable, '-m', 'migration_v1', 'analyze', pe]))
        result = json.loads(run('build', [sys.executable, '-m', 'migration_v1', 'build', pe, '--out', product]))
        require(result['status'] == 'BUILT_NOT_EXECUTED' and result['input_sha256'] == sha(pe), 'build not established')
        require(json.loads((product / 'native/fixture-metadata.json').read_bytes()) == {}, 'external metadata was supplied')
        executable = Path(result['executable'])
        require(struct.unpack_from('<II', executable.read_bytes()) == (0xfeedfacf, 0x100000c), 'not thin ARM64 Mach-O')
        run('signature', ['codesign', '--verify', '--strict', result['app']])
        dylibs = run('libraries', ['otool', '-L', executable]).decode()
        require([l.strip().split(' (', 1)[0] for l in dylibs.splitlines()[1:] if l.strip()]
                == ['/usr/lib/libSystem.B.dylib'], 'unexpected runtime dependency')
        data = out / 'data'
        data.mkdir(mode=0o700)
        payload = json.loads(run('native', [executable, '--data-dir', data]))
        expected = b'PE process_entry: static buffers, real file APIs, guest exit.\n'.ljust(67, b'\0')
        require((data / 'process-save.bin').read_bytes() == expected, 'saved bytes differ')
        require(payload['outcome'] == 'PROCESS_EXITED' and payload['exit_code'] == 0 and payload['exit_requested'] == 1,
                'guest did not exit successfully')
        require(payload['pe_sha256'] == sha(pe) and payload['observations'] == {} and payload['entry_arguments'] == 0,
                'input or metadata differs')
        require(payload['bytes_written'] == payload['bytes_read'] == 67 and payload['fault']['status'] == 0, 'guest I/O or fault differs')
        require(payload['open_before_cleanup'] == payload['open_after_cleanup'] == payload['cleanup_closes']
                == payload['cleanup_errors'] == 0, 'cleanup masked leaked handles')
        ordinary = run('verify', [sys.executable, '-m', 'migration_v1', 'verify', product])
        optimized = run('verify-optimized', [sys.executable, '-O', '-m', 'migration_v1', 'verify', product])
        require(ordinary == optimized, 'ordinary/-O verification differs')
        before = sha(product / 'result.json')
        run('no-overwrite', [sys.executable, '-m', 'migration_v1', 'build', pe, '--out', product], 64)
        require(sha(product / 'result.json') == before, 'overwrite refusal changed receipt')
        unknown = out / 'unknown-import.exe'
        unknown.write_bytes(pe.read_bytes().replace(b'ExitProcess\0', b'ExitProcesX\0'))
        rejected = json.loads(run('unknown-import', [sys.executable, '-m', 'migration_v1', 'build', unknown,
                                                   '--out', out / 'reject-import'], 2))
        require(rejected['stage'] == 'analysis' and not (out / 'reject-import/native').exists(), 'unknown API reached compiler')
        # Retain actual decoder rejection separately from metadata admission.
        invalid = bytearray(pe.read_bytes())
        info = analysis['inventory']
        section = next(s for s in info['sections'] if s['rva'] <= info['entry_rva'] < s['rva'] + s['raw_size'])
        offset = section['raw_offset'] + info['entry_rva'] - section['rva']
        invalid[offset:offset + 2] = b'\x0f\x05'
        syscall = out / 'syscall.exe'
        syscall.write_bytes(invalid)
        candidate = json.loads(run('syscall-analysis', [sys.executable, '-m', 'migration_v1', 'analyze', syscall]))
        require(candidate['status'] == 'ELIGIBLE_FOR_BUILD_NOT_DECODED', 'metadata stage claimed instruction analysis')
        rejected = json.loads(run('syscall-build', [sys.executable, '-m', 'migration_v1', 'build', syscall,
                                                   '--out', out / 'reject-syscall'], 2))
        require(rejected['diagnostic']['code'] == 'INSTRUCTION_UNSUPPORTED' and
                rejected['diagnostic']['iclass'] == 'SYSCALL' and rejected['stage'] == 'aot-build', 'wrong decoder failure diagnostic')
        require(not list((out / 'reject-syscall').glob('*.app')), 'rejected input produced App')
        # Mutate disposable copies, never the accepted output, to test read-only verifier gates.
        for name, action in [('missing-entry', 'delete'), ('unlisted-file', 'add')]:
            altered = out / name
            shutil.copytree(product, altered)
            record = json.loads((altered / 'result.json').read_bytes())
            record['output'] = str(altered)
            if action == 'delete':
                del record['files']['input.exe']
            else:
                (altered / 'unexpected.bin').write_bytes(b'extra')
            (altered / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
            failed = json.loads(run(name, [sys.executable, '-m', 'migration_v1', 'verify', altered], 64))
            require('file set' in failed['error'], 'wrong verifier rejection')
        dump(out / 'evidence.json', dict(status='PASS_EXISTING_PE_CLI_REGRESSION', commands=commands,
             input_sha256=sha(pe), executable_sha256=sha(executable), build_receipt_sha256=before,
             native=payload, guest_executions=1, producer_test_sha256=sha(__file__),
             scope='existing accepted PE through new CLI with no fixture metadata; fresh counter integration remains unaccepted'))
        print(json.dumps(dict(status='PASS_EXISTING_PE_CLI_REGRESSION', guest_executions=1,
                              instructions=result['instructions'], executable_sha256=sha(executable)), indent=2))
    except Exception as error:
        dump(out / 'failure.json', dict(status='FAIL', error=str(error), commands=commands))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    execute(parser.parse_args().out)
