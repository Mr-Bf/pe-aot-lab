"""Independent stdlib-only evidence reader for the first CLI regression.

No producer imports, compiler calls or guest executions. This reviews this
specific record, not arbitrary untrusted receipts or Windows compatibility.
"""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / 'build/migration-v1/cli-regression-01'
EXPECTED_PE = '5b7c5608d4b3dec83b4223cb08b26f2ac6c542d644330fe63b6cf27e0fc63b50'
EXPECTED_RECEIPT = '72c13809cdfa69ac0525b9348021983c74a98fa9916085b69cf1fc67e73a745d'
EXPECTED_EVIDENCE = '30c21bb62a00ea65a74fef9958bed64fb805d68fe1f9e10e48d068f3dac5c7fc'
seen = {}


def check(ok, message):
    if not ok:
        raise ValueError(message)


def read(path, expected=None):
    path = Path(path)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected is not None:
        check(digest == expected, 'bytes changed: ' + str(path))
    if str(path) in seen:
        check(seen[str(path)] == digest, 'same file changed during review')
    seen[str(path)] = digest
    return data


def review():
    evidence = json.loads(read(RUN / 'evidence.json', EXPECTED_EVIDENCE))
    product = RUN / 'product with spaces'
    result = json.loads(read(product / 'result.json', EXPECTED_RECEIPT))
    check(result['status'] == 'BUILT_NOT_EXECUTED' and evidence['guest_executions'] == 1, 'scope differs')
    for name, item in result['files'].items():
        path = product / name
        check(path.resolve() == path and path.is_relative_to(product), 'artifact path escapes')
        read(path, item['sha256'])
        check(path.stat().st_mode & 0o777 == item['mode'], 'file mode changed')
    for group in ('sources', 'source_inputs'):
        for path, digest in result[group].items():
            read(path, digest)
    pe = read(product / 'input.exe', EXPECTED_PE)
    check(pe == read(RUN / 'input with spaces.exe', EXPECTED_PE), 'input copies differ')
    native = json.loads(read(product / 'native/program-build.json'))
    check(native['input_sha256'] == EXPECTED_PE and native['observations'] == {}, 'native input/observations differ')
    check(json.loads(read(product / 'native/fixture-metadata.json')) == {}, 'symbol metadata supplied')
    compiler = json.loads(read(product / 'native/compiler/manifest.json'))
    check(compiler['input_sha256'] == EXPECTED_PE and len(compiler['instructions']) == 152, 'lift differs')
    for directory in ('compiler', 'ret-shim'):
        record = json.loads(read(product / 'native' / directory / 'manifest.json'))
        check(record['status'] == 'PASS' and record['inputs_before'] == record['inputs_after'], 'producer input changed')
        for name, digest in record['artifact_sha256'].items():
            read(product / 'native' / directory / name, digest)
        for path, digest in record['inputs_before'].items():
            read(path, digest)
    executable = Path(result['executable'])
    check(struct.unpack_from('<II', read(executable, evidence['executable_sha256'])) == (0xfeedfacf, 0x100000c), 'wrong architecture')
    commands = {row['name']: row for row in evidence['commands']}
    check(len(commands) == 13, 'unexpected CLI command count')
    for name, row in commands.items():
        check(json.loads(read(RUN / (name + '.command.json'))) == row, 'raw command differs')
        check(row['returncode'] == row['expected_returncode'], 'recorded command failed')
        read(RUN / (name + '.stdout'))
        read(RUN / (name + '.stderr'))
    check(commands['native']['argv'] == [str(executable), '--data-dir', str(RUN / 'data')], 'native invocation differs')
    payload = json.loads(read(RUN / 'native.stdout'))
    check(payload == evidence['native'], 'raw native output differs')
    expected = b'PE process_entry: static buffers, real file APIs, guest exit.\n'.ljust(67, b'\0')
    check(read(RUN / 'data/process-save.bin') == expected and expected in pe, 'save bytes not original PE payload')
    check(payload['exit_requested'] == 1 and payload['outcome'] == 'PROCESS_EXITED' and payload['exit_code'] == 0,
          'guest normal exit not established')
    check(payload['bytes_read'] == payload['bytes_written'] == 67 and payload['fault']['status'] == 0, 'I/O or guest fault differs')
    check(all(payload[key] == 0 for key in ('open_before_cleanup', 'open_after_cleanup', 'cleanup_closes', 'cleanup_errors')),
          'guest resource closure failed')
    check(read(RUN / 'verify.stdout') == read(RUN / 'verify-optimized.stdout'), 'ordinary/-O verifier differs')
    unsupported = json.loads(read(RUN / 'syscall-build.stdout'))
    check(unsupported['status'] == 'UNSUPPORTED' and unsupported['diagnostic']['iclass'] == 'SYSCALL', 'missing actual instruction rejection')
    first = json.loads(read(ROOT / 'build/migration-v1/integration-01/product/result.json'))
    check(first['status'] == 'UNSUPPORTED' and 'CMOVNB' in first['error'] and first['guest_executions'] == 0,
          'fresh counter was wrongly counted as success')
    return dict(status='PASS_FILE_ONLY_CLI_REVIEW', authenticated_files=len(seen),
                historical_guest_executions=1, new_guest_executions=0,
                input_sha256=EXPECTED_PE, instructions=152,
                fresh_counter_status='UNSUPPORTED_CMOVNB',
                limitation='existing self-authored PE; no new game, Windows execution or performance proof')


if __name__ == '__main__':
    print(json.dumps(review(), indent=2, sort_keys=True))
