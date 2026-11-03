"""Pinned local XED adapter. Decoding host code never executes guest bytes.

Flow describes only nominal instruction successors; it is not a lifter support
claim or a model of faults, exceptions, external calls, or runtime targets.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

UINT64_MASK = (1 << 64) - 1
SOURCE = Path(__file__).with_suffix('.c')
# Deliberately closed: new/unknown XED categories are analysis frontiers.
NORMAL_CATEGORIES = frozenset('''3DNOW ADOX_ADCX AES AVX AVX2 AVX2GATHER AVX512
AVX512_4FMAPS AVX512_4VNNIW AVX512_BITALG AVX512_VBMI AVX512_VP2INTERSECT
AVX_IFMA BINARY BITBYTE BLEND BMI1 BMI2 BROADCAST CLDEMOTE CLFLUSHOPT CLWB
CMOV COMPRESS CONFLICT CONVERT DATAXFER DECIMAL EXPAND FCMOV FLAGOP FMA4
FP16 GATHER GFNI IFMA KMASK LOGICAL LOGICAL_FP LZCNT MMX NOP PCLMULQDQ
POP PREFETCH PREFETCHWT1 PUSH RDRAND RDSEED ROTATE SCATTER SEMAPHORE SETCC
SHA SHA512 SHIFT SSE STRINGOP STTNI TBM VAES VBMI2 VEX VFMA VPCLMULQDQ
WIDENOP X87_ALU XOP XSAVE XSAVEOPT'''.split())
MISC_NORMAL = frozenset('CPUID ENTER LEA LEAVE PAUSE RDTSC RDTSCP XLAT'.split())
CONDITIONAL = frozenset('''JB JBE JCXZ JECXZ JL JLE JNB JNBE JNL JNLE JNO JNP
JNS JNZ JO JP JRCXZ JS JZ LOOP LOOPE LOOPNE'''.split())
TRANSACTION_CLASSES = frozenset(('XBEGIN', 'XABORT', 'XEND', 'XTEST'))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def classify(record, va):
    """Close the flow vocabulary without treating an unknown opcode as linear."""
    cls, category = record['iclass'], record['category']
    next_va = (va + record['length']) & UINT64_MASK
    width = record['branch_displacement_width']
    target = (next_va + record['branch_displacement']) & UINT64_MASK if width else None
    flow, reason = 'unclassified_control', 'category_or_form_not_reviewed'
    if cls in ('UD0', 'UD1', 'UD2', 'INT3', 'HLT'):
        flow, reason = 'terminal', 'explicit_trap_or_halt_static_stop'
    elif record['ring0'] or record['far_transfer']:
        reason = 'privileged_or_far_transfer_not_modeled'
    elif cls in ('CLI', 'STI'):
        # XED does not mark these RING0: legality also depends on IOPL/VME/PVI.
        reason = 'privilege_sensitive_interrupt_state_not_modeled'
    elif cls in TRANSACTION_CLASSES or record['prefixes']['xacquire'] or record['prefixes']['xrelease']:
        reason = 'transactional_control_not_modeled'
    elif category == 'CALL' and cls == 'CALL_NEAR':
        flow, reason = ('direct_call' if width else 'indirect_call'), 'near_call'
    elif category == 'UNCOND_BR' and cls == 'JMP':
        flow, reason = ('direct_jump' if width else 'indirect_jump'), 'near_jump'
    elif category == 'COND_BR' and cls in CONDITIONAL and width:
        flow, reason = 'conditional_branch', 'reviewed_relative_condition_or_loop'
    elif category == 'RET' and cls == 'RET_NEAR':
        flow, reason = 'return', 'near_return'
    elif category in NORMAL_CATEGORIES or (category == 'MISC' and cls in MISC_NORMAL):
        flow, reason = 'normal', 'reviewed_nominal_linear_category'
    record.update(flow=flow, flow_reason=reason,
                  target_va=target if flow in ('direct_call', 'direct_jump', 'conditional_branch') else None,
                  fallthrough_va=next_va if flow in ('normal', 'direct_call', 'indirect_call', 'conditional_branch') else None)
    # FS/GS bases and any register-derived addresses are runtime state. Long
    # mode ignores the bases of DS/ES/SS/CS, so only these permit static addresses.
    for memory in record['memory_operands']:
        address = None
        if memory['segment'] in ('INVALID', 'DS', 'ES', 'SS', 'CS') and memory['index'] == 'INVALID':
            if memory['base'] in ('RIP', 'EIP'):
                address = next_va + memory['displacement']
            elif memory['base'] == 'INVALID':
                address = memory['displacement']
            if address is not None:
                address &= (1 << memory['address_width']) - 1
        memory['address_va'] = address
    return record


def _inputs(prefix, clang, sdk):
    paths = [SOURCE, Path(__file__), prefix / 'lib/libxed.a', clang]
    headers = sorted((prefix / 'include/xed').glob('*.h'))
    require(headers and (prefix / 'include/xed/xed-interface.h') in headers, 'XED headers missing')
    paths += headers
    paths += [sdk / name for name in ('SDKSettings.json', 'SDKSettings.plist') if (sdk / name).is_file()]
    for path in paths:
        require(path.is_file() and not path.is_symlink(), 'nonregular build input: ' + str(path))
    return {str(path): sha(path) for path in paths}


def build_decoder(out, xed_prefix, clang='/usr/bin/clang'):
    """Compile only this tiny bridge against an already installed XED archive."""
    out, prefix, compiler = Path(out).absolute(), Path(xed_prefix).absolute(), Path(clang).resolve()
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'this receipt targets macOS arm64')
    require(out == out.resolve() and not out.exists(), 'fresh canonical decoder output required')
    require(prefix == prefix.resolve() and prefix.is_dir(), 'canonical existing XED prefix required')
    require(compiler.is_file(), 'clang not found')
    environment = dict(os.environ)
    # Remove compiler include injection; explicit SDK/prefix form the build inputs.
    for key in ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH', 'SDKROOT', 'MACOSX_DEPLOYMENT_TARGET'):
        environment.pop(key, None)
    sdk_command = ['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']
    sdk_result = subprocess.run(sdk_command, env=environment, capture_output=True, text=True, check=True)
    sdk = Path(sdk_result.stdout.strip()).resolve()
    require(sdk.is_dir(), 'macOS SDK unavailable')
    inputs = _inputs(prefix, compiler, sdk)
    out.mkdir(parents=True)
    library = out / 'decoder.dylib'
    command = [str(compiler), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
               '-arch', 'arm64', '-mmacosx-version-min=11.0', '-isysroot', str(sdk),
               '-dynamiclib', '-I' + str(prefix / 'include'), str(SOURCE),
               str(prefix / 'lib/libxed.a'), '-o', str(library)]
    result = subprocess.run(command, cwd=out, env=environment, capture_output=True, text=True)
    (out / 'compile.stdout.txt').write_text(result.stdout)
    (out / 'compile.stderr.txt').write_text(result.stderr)
    write_json(out / 'compile.json', dict(argv=command, cwd=str(out), returncode=result.returncode,
               stdout_sha256=sha(out / 'compile.stdout.txt'), stderr_sha256=sha(out / 'compile.stderr.txt')))
    require(result.returncode == 0, 'decoder bridge compilation failed; inspect retained compile logs')
    require(_inputs(prefix, compiler, sdk) == inputs, 'decoder inputs changed during compilation')
    version = subprocess.run([str(compiler), '--version'], env=environment, capture_output=True, text=True, check=True)
    record = dict(schema=1, tool='real-pe-cfg-xed-decoder-v1', status='BUILT_NOT_GUEST_EXECUTED',
                  machine='LONG_64', chip='ALL', stack_address_width=64, host='arm64-apple-macos',
                  isa_alias_policy='recognize_all_compiled_forms_not_runtime_cpuid',
                  xed_prefix=str(prefix), inputs=inputs, source_sha256=sha(SOURCE),
                  adapter_sha256=sha(Path(__file__)), library=str(library), library_sha256=sha(library),
                  compile=str(out / 'compile.json'), compile_sha256=sha(out / 'compile.json'),
                  compiler=str(compiler), compiler_version=version.stdout, sdk=str(sdk),
                  sdk_query=dict(argv=sdk_command, returncode=sdk_result.returncode, stdout=sdk_result.stdout,
                                 stderr=sdk_result.stderr, xcrun_sha256=sha('/usr/bin/xcrun')),
                  guest_executions=0)
    write_json(out / 'decoder.json', record)
    return record


class Decoder:
    def __init__(self, receipt):
        receipt = Path(receipt).absolute()
        require(receipt == receipt.resolve() and receipt.is_file(), 'canonical decoder receipt required')
        record = json.loads(receipt.read_text())
        require(type(record) is dict and type(record.get('schema')) is int and record['schema'] == 1 and
                record.get('tool') == 'real-pe-cfg-xed-decoder-v1' and
                record.get('status') == 'BUILT_NOT_GUEST_EXECUTED', 'decoder receipt contract differs')
        require(record.get('adapter_sha256') == sha(Path(__file__)) and record.get('source_sha256') == sha(SOURCE),
                'decoder adapter source identity differs')
        for name, expected in record['inputs'].items():
            path = Path(name)
            require(path.is_file() and not path.is_symlink() and sha(path) == expected, 'decoder input hash differs: ' + name)
        library = Path(record['library'])
        require(library == receipt.parent / 'decoder.dylib' and library.is_file() and not library.is_symlink() and
                sha(library) == record['library_sha256'], 'decoder library identity differs')
        require(sha(record['compile']) == record['compile_sha256'], 'decoder command identity differs')
        self.identity = dict(receipt=str(receipt), receipt_sha256=sha(receipt), **record)
        self._library = ctypes.CDLL(str(library))
        self._library.pe_cfg_xed_init.argtypes = []
        self._library.pe_cfg_xed_init.restype = None
        self._library.pe_cfg_xed_init()
        self._decode = self._library.pe_cfg_xed_decode
        self._decode.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        self._decode.restype = ctypes.c_int

    def decode(self, data, va):
        require(type(data) is bytes and 1 <= len(data) <= 15, 'decode requires 1..15 immutable bytes')
        require(type(va) is int and 0 <= va <= UINT64_MASK, 'decode VA must be uint64')
        require(self._decode is not None, 'decoder is closed')
        raw = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        output = ctypes.create_string_buffer(16384)
        size = self._decode(raw, len(data), output, len(output))
        require(0 < size < len(output), 'XED adapter output failure')
        record = json.loads(output.raw[:size])
        if record.get('status') == 'invalid':
            return dict(record, bytes_hex=data.hex(), flow='unclassified_control', target_va=None,
                        fallthrough_va=None, memory_operands=[], flow_reason='xed_decode_failure')
        require(record.get('status') == 'decoded' and type(record.get('length')) is int and
                1 <= record['length'] <= len(data), 'XED decoded length contract differs')
        for name in ('iclass', 'category', 'extension', 'isa_set'):
            require(type(record.get(name)) is str and re.fullmatch('[A-Z0-9_]+', record[name]), 'invalid XED enum field')
        require(record['address_width'] in (32, 64) and record['branch_displacement_width'] in (0, 8, 16, 32),
                'unsupported XED addressing/branch width')
        require(len(record['memory_operands']) <= 2, 'unexpected XED memory operand count')
        for memory in record['memory_operands']:
            require(memory['address_width'] in (32, 64), 'unsupported memory address width')
        record['bytes_hex'] = data[:record['length']].hex()
        return classify(record, va)

    def close(self):
        # ctypes owns the handle until process exit; no unsafe manual dlclose.
        self._decode = None
