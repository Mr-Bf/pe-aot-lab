"""Run original PE image bytes under an x86 test process; compare frozen ARM runs.

No ARM execution, App, graphics, fault oracle or timing/performance claim. The
reference maps original text/rdata together; only capture stack/RIP and image
addresses are normalized. Complete source/PE/request/raw response are retained.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import traceback

from memory_stage2.image_loader import load_image
from switch_aot_v1.admission import validate_switch

ROOT = Path(__file__).resolve().parents[1]
ASM = ROOT / 'd3d11_bridge/scalar_oracle.S'
ASM_SHA = 'd8b6bf73af2945db64a56f244dad06f08e921232a83354889e566facf4272b5c'
MASK = 0x8d5
RSP = 0x7000fef8
EXIT = 0x7fff00000000
OFFSETS = (2216, 2248, 2264, 2232, 2312, 2328, 2280, 2296,
           2344, 2360, 2376, 2392, 2408, 2424, 2440, 2456, 2472)
FLAG_BYTES = ((2065, 0), (2067, 2), (2069, 4), (2071, 6), (2073, 7), (2077, 11))
FIXTURES = {
    'supported': ('build/switch-supported-fixture-v1/pe-02/switch8.exe',
                  'c34e9d55cc9719fe3219a4f991ec4f53fca5583b5d026eb8cdc58aa26a12181c'),
    'variant': ('build/switch-variant-fixture-v1/pe-01/switch8_variant.exe',
                '822fbe1e6b82d4229772cd964a5ac27c9c688510206ebc3cb571bae6c2eba099'),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return sha(Path(path).read_bytes())


def write(path, record):
    with Path(path).open('x') as stream:
        stream.write(json.dumps(record, indent=2, sort_keys=True) + '\n')


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Commands:
    def __init__(self, out):
        self.out = out / 'commands'
        self.out.mkdir()
        self.records = []

    def run(self, argv, label, data=None, timeout=60):
        argv = list(map(str, argv))
        prefix = self.out / ('%03d-' % (len(self.records)+1) + label)
        env = {key: os.environ[key] for key in ('HOME', 'TMPDIR') if key in os.environ}
        env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C')
        record = dict(argv=argv, cwd=str(self.out.parent), environment=env,
                      label=label, timeout_seconds=timeout, started_at=stamp(),
                      stdin_sha256=sha(data) if data is not None else None)
        write(str(prefix)+'.started.json', record)
        try:
            result = subprocess.run(argv, cwd=self.out.parent, env=env, input=data,
                                    capture_output=True, timeout=timeout)
            stdout, stderr, rc = result.stdout, result.stderr, result.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            stdout = getattr(error, 'stdout', None) or b''
            stderr = getattr(error, 'stderr', None) or b''
            rc = None
            record['launch_or_timeout_error'] = repr(error)
        for name, value in (('stdout', stdout), ('stderr', stderr)):
            path = Path(str(prefix)+'.'+name)
            path.write_bytes(value)
            record[name+'_path'] = str(path)
            record[name+'_sha256'] = sha(value)
        record.update(returncode=rc, finished_at=stamp())
        write(str(prefix)+'.result.json', record)
        self.records.append(record)
        require(rc == 0, label + ' command failed; raw streams preserved')
        return stdout, stderr


def final_mask(proof, selector):
    """Defined flags along the admitted path; values are never modelled here."""
    candidate = proof['switch']
    rows = {row['address']: row for row in proof['instructions']}
    pc = proof['image_base'] + proof['root_rva']
    valid, visited = MASK, []  # Reference starts all six arithmetic flags at zero.
    while pc not in visited and len(visited) <= len(rows):
        visited.append(pc)
        row = rows[pc]
        valid = (valid | row['flags_written']) & ~row['flags_undefined']
        if row['kind'] == 2:
            return valid & MASK, visited
        if pc == candidate['branch_pc']:
            pc = candidate['default_pc'] if selector >= candidate['count'] else row['next_pc']
        elif row['kind'] == 5:
            require(selector < candidate['count'], 'out-of-range path reached table')
            pc = candidate['targets'][selector]
        else:
            require(len(row['successors']) == 1, 'unexpected additional branch in reference corpus')
            pc = row['successors'][0]
    raise ValueError('reference path is not a finite leaf')


def compare(response, normal, proof, image):
    size = 184 + len(image.data) + 65536
    require(len(response) == size * len(normal), 'raw response record count/size')
    reports = []
    for index, case in enumerate(normal):
        data = response[index*size:(index+1)*size]
        fields = struct.unpack_from('<8s22Q', data)
        require(fields[0] == b'SWOUT001', 'raw response magic')
        raw_gpr, flags, rip = list(fields[1:17]), fields[17], fields[18]
        native_image, native_stack, native_rsp, capture = fields[19:23]
        require(native_image % 4096 == 0 and native_rsp == native_stack+0xfef8,
                'raw mapping/stack identity')
        require(raw_gpr[4] == native_rsp+8 and rip == capture, 'raw RET capture mismatch')
        actual_image = data[184:184+len(image.data)]
        actual_stack = data[184+len(image.data):]
        expected_stack = bytearray(b'\x5a'*65536)
        struct.pack_into('<Q', expected_stack, 0xfef8, EXIT)
        require(actual_image == image.data and actual_stack == expected_stack,
                'original image or normalized full stack changed')
        memory_hash = sha(actual_image+actual_stack)
        mask, path = final_mask(proof, case['selector'])
        modes = {}
        for mode in ('O0', 'O3'):
            arm = case['results'][mode]
            require(arm['status'] == 0 and arm['returned'] == 1 and arm['depth'] == 0,
                    'ARM record was not normal completion')
            require(arm['steps'] == len(path), 'ARM path instruction count mismatch')
            require(arm['fault'] == dict(status=0, access=0, pc=0, address=0, width=0),
                    'unexpected ARM fault record')
            expected = arm['registers']
            require(len(expected) == 17 and expected[4] == RSP+8 and expected[16] == EXIT,
                    'ARM register/RET contract')
            normalized, changed = list(raw_gpr), []
            normalized[4] = RSP+8
            for reg in range(16):
                if reg == 4:
                    continue
                if image.base <= expected[reg] < image.base+len(image.data):
                    require(native_image <= raw_gpr[reg] < native_image+len(image.data),
                            f'case {index} {mode} GPR {reg}: expected mapped image address')
                    normalized[reg] = image.base + raw_gpr[reg] - native_image
                    changed.append(reg)
            require(normalized+[EXIT] == expected, f'case {index} {mode}: complete GPR mismatch')
            require(flags & mask == arm['flags'] & mask,
                    f'case {index} {mode}: defined flags mismatch mask={mask:x} raw={flags:x} ARM={arm["flags"]:x}')
            require(memory_hash == arm['memory_sha256'], 'raw/ARM complete memory identity')
            state = bytes.fromhex(arm['state'])
            require(len(state) == 3504, 'ARM full State size')
            require([struct.unpack_from('<Q', state, offset)[0] for offset in OFFSETS] == expected,
                    'ARM fields differ from raw State')
            require(sum(bool(state[offset]) << bit for offset, bit in FLAG_BYTES) == arm['flags'],
                    'ARM flags differ from raw State')
            modes[mode] = dict(status='PASS', normalized_image_registers=changed,
                               state_sha256=sha(state), memory_sha256=memory_hash)
        require(case['results']['O0'] == case['results']['O3'], 'ARM modes differ')
        reports.append(dict(index=index, selector=case['selector'], value=case['value'],
                            defined_flags_mask=mask, raw_flags=flags, path=path, modes=modes))
    return reports


def main(arm, out, supported_pe=None, variant_pe=None):
    arm, out = Path(arm).resolve(strict=True), Path(out).absolute()
    require(not out.exists() and not out.is_symlink(), 'fresh oracle output required')
    require(not out.is_relative_to(arm) and not arm.is_relative_to(out), 'output overlaps frozen ARM input')
    require(digest(ASM) == ASM_SHA, 'capture assembly changed')
    out.mkdir(parents=True)
    run = Commands(out)
    inputs = {}
    def bind(path, expected=None):
        path = Path(path).resolve(strict=True)
        value = digest(path)
        require(expected is None or value == expected, 'input identity: '+str(path))
        if str(path) in inputs:
            require(inputs[str(path)] == value, 'input changed while binding')
        inputs[str(path)] = value
        return path
    for path in (Path(__file__), Path(__file__).with_suffix('.c'), ASM,
                 ROOT/'memory_stage2/image_loader.py', ROOT/'switch_aot_v1/admission.py',
                 Path(sys.executable).resolve(), arm/'result.json'):
        bind(path)
    initial = dict(inputs)
    write(out/'started.json', dict(status='STARTED_NOT_PASSED', arm=str(arm), sources=initial))
    reports = []
    pe_overrides = {'supported': supported_pe, 'variant': variant_pe}
    try:
        receipt = json.loads((arm/'result.json').read_bytes())
        require(receipt['status'] == 'PASS_ARM64_O0_O3_AND_NATIVE_C_REFERENCE' and
                receipt['app_executions'] == receipt['gpu_executions'] == 0,
                'wrong ARM input result/scope')
        require([row['label'] for row in receipt['records']] == list(FIXTURES), 'ARM fixture set')
        # These are historical source snapshots. A later stronger Python gate
        # may differ; validate_switch below independently re-proves both inputs.
        for name, expected in receipt['sources'].items():
            bind(arm/'sources'/name, expected)
        compiler = Path(run.run(['/usr/bin/xcrun', '--find', 'clang'], 'compiler')[0].decode().strip()).resolve(strict=True)
        sdk = Path(run.run(['/usr/bin/xcrun', '--show-sdk-path'], 'sdk')[0].decode().strip()).resolve(strict=True)
        bind(compiler)
        for name in ('SDKSettings.json', 'SDKSettings.plist'):
            if (sdk/name).exists(): bind(sdk/name)
        run.run([compiler, '--version'], 'compiler-version')
        for record in receipt['records']:
            label = record['label']
            pe_path, pe_hash = FIXTURES[label]
            pe_file = ROOT/pe_path if pe_overrides[label] is None else Path(pe_overrides[label])
            pe = bind(pe_file, pe_hash).read_bytes()
            require(record['pe_sha256'] == pe_hash and record['normal_cases'] == 72, 'ARM PE/corpus identity')
            area = out/label; area.mkdir()
            for name, expected in record['artifacts'].items():
                require(Path(name).name == name, 'artifact path escaped area')
                bind(arm/label/name, expected)
            for mode in ('O0', 'O3'):
                require(struct.unpack_from('<II', (arm/label/(mode+'.o')).read_bytes()) ==
                        (0xfeedfacf, 0x100000c), 'ARM object is not native arm64')
            proof = json.loads((arm/label/'proof.json').read_bytes())
            packet = json.loads((arm/label/'candidate.json').read_bytes())
            validate_switch(proof, pe, packet)
            image = load_image(pe)
            require(all(p & 1 and not p & 2 for p in image.permissions), 'oracle image permission profile')
            normal = json.loads((arm/label/'normal.json').read_bytes())
            require(len(normal) == 72, 'actual normal corpus count')
            for case in normal:
                regs = case['input_registers']
                require(len(regs) == 16 and regs[4] == RSP and all(type(x) is int and 0 <= x < 1 << 64 for x in regs), 'input GPR frame')
                values = (case['selector'], case['value']) if label == 'supported' else (case['value'], case['selector'])
                require(tuple(x & 0xffffffff for x in regs[1:3]) == values, 'fixture argument ABI')
            header = area/'oracle_image.h'
            header.write_text('static const unsigned char kImage[] = {'+','.join(map(str,image.data))+'};\n'+
                              'static const unsigned char kPermissions[] = {'+','.join(map(str,image.permissions))+'};\n'+
                              'static const unsigned kEntryRva='+str(image.entry_rva)+';\n')
            request = b''.join(struct.pack('<8s17Q', b'SWIN0001', *case['input_registers'], 2) for case in normal)
            request_path = area/'request.bin'; request_path.write_bytes(request)
            exe = area/'raw-x86'
            flags = ['-arch', 'x86_64', '-isysroot', sdk, '-mmacosx-version-min=11.0', '-std=c11',
                     '-O2', '-Wall', '-Wextra', '-Werror', '-I'+str(area)]
            run.run([compiler, *flags, Path(__file__).with_suffix('.c'), ASM, '-MD', '-MF', area/'dependencies.d', '-o', exe], label+'-compile')
            require(struct.unpack_from('<II', exe.read_bytes()) == (0xfeedfacf, 0x1000007), 'reference is not thin x86_64 Mach-O')
            # The compiler dependency file can be overwritten by its assembly
            # input; bind explicit C/header/assembly regardless of that file.
            for path in (header, request_path, exe, area/'dependencies.d'):
                bind(path)
            before = dict(inputs)
            stdout, stderr = run.run(['/usr/bin/arch', '-x86_64', exe], label+'-raw-x86', request)
            (area/'response.bin').write_bytes(stdout)
            require(json.loads(stderr) == dict(status='RAW_PE_SWITCH_X86_PASS', cases=72,
                    translated=1, raw_image_identity=True, stack_unchanged=True), 'raw process report')
            cases = compare(stdout, normal, proof, image)
            write(area/'comparison.json', cases)
            require(all(digest(path) == expected for path, expected in before.items()), 'execution input changed')
            reports.append(dict(label=label, raw_executions=len(cases), arm_comparisons=2*len(cases),
                                pe_sha256=pe_hash, request_sha256=sha(request), response_sha256=sha(stdout),
                                comparison_sha256=digest(area/'comparison.json'),
                                image_size=len(image.data), stack_size=65536))
        require(all(digest(path) == expected for path, expected in inputs.items()), 'final input drift')
        result = dict(schema=1, status='PASS_ORIGINAL_PE_X86_ARM64_DIFFERENTIAL', records=reports,
                      raw_x86_executions=144, existing_arm_comparisons=288,
                      commands=run.records, inputs_before=inputs, inputs_after={p:digest(p) for p in inputs},
                      historical_arm_sources=receipt['sources'],
                      app_executions=0, gpu_executions=0, arm_reruns=0,
                      scope='Two finite fixtures only. Original full PE image bytes under Rosetta test oracle; all 16 GPRs, defined flags, normalized RIP/stack/image and full image+stack matched to frozen ARM O0/O3. No Windows fault or performance claim.')
        write(out/'result.json', result)
        print(json.dumps({key:result[key] for key in ('status','raw_x86_executions','existing_arm_comparisons')}))
    except BaseException as error:
        write(out/'failure.json', dict(status='FAIL_ORACLE_NOT_PASSED', error=repr(error),
              traceback=traceback.format_exc(), completed=reports, commands=run.records, inputs=inputs))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--arm', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--supported-pe', type=Path,
                        help='explicit original switch8.exe; fixed fixture SHA is still required')
    parser.add_argument('--variant-pe', type=Path,
                        help='explicit original switch8_variant.exe; fixed fixture SHA is still required')
    args = parser.parse_args()
    main(args.arm, args.out, args.supported_pe, args.variant_pe)
