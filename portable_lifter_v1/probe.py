"""Exercise an explicitly supplied provider on the fixed two-root window PE.

This is a static lifting/code-generation probe, not a guest runtime test. Only
the tiny native State-layout harness is executed. Frozen front-end validators
are reused as pure functions; their legacy tool paths/orchestration are unused.
"""
import hashlib
import json
from pathlib import Path
import re
import struct

from memory_stage2.image_loader import EXEC
from window_inc_v1.loader import load_image
from window_inc_v1.lift import (
    validate_flags, validate_helper_effects, validate_inc_metadata,
    validate_register_instruction, validate_virtual_instruction,
)

REPO = Path(__file__).resolve().parents[1]
INPUT_SHA256 = '254be0c36be784a028db912eb89522a963039a9ec140941fb41ea1643f1730ac'
ROOTS = ((4416, 'aot_entry', 568), (4096, 'aot_window_proc_1000', 75))
EXPECTED_LAYOUT = [3504, 16] + list(range(2216, 2473, 16)) + list(range(2065, 2078, 2))
SCOPE = 'STATIC_LIFT_ARM_OBJECTS_NOT_GUEST_EXECUTED'
SOURCE_FILES = (
    'portable_lifter_v1/probe.py', 'portable_lifter_v1/explicit-semantics.patch',
    'window_inc_v1/lift.py', 'window_inc_v1/loader.py',
    'window_inc_v1/build_lifter.py', 'callback_bridge/imports_v1.py',
    'memory_stage2/image_loader.py', 'fixtures.py',
    'integration_stage3/lifter_layout.cpp',
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def snapshot(paths):
    return {str(p): sha(p) for p in sorted(set(Path(p).resolve(strict=True) for p in paths))}


def source_tree(source):
    result = {}
    for path in sorted(source.rglob('*')):
        require(not path.is_symlink(), 'prepared source contains a symlink: ' + str(path))
        if path.is_file():
            result[str(path.relative_to(source))] = sha(path)
        else:
            require(path.is_dir(), 'non-regular prepared source member: ' + str(path))
    require(bool(result), 'prepared source tree is empty')
    return result


def write_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def macho(path, filetype):
    header = path.read_bytes()[:32]
    require(len(header) == 32, 'truncated Mach-O: ' + str(path))
    magic, cpu, subtype, kind, commands, size, flags, reserved = struct.unpack('<8I', header)
    require(magic == 0xfeedfacf and cpu == 0x0100000c and kind == filetype,
            'expected thin ARM64 Mach-O of requested type: ' + str(path))
    return dict(cpu_type=cpu, cpu_subtype=subtype, file_type=kind,
                load_commands=commands, command_bytes=size, flags=flags, reserved=reserved)


def normalize(raw, image, start, code, imports, entry):
    require(type(raw) is list and bool(raw), 'decoder manifest must be a nonempty list')
    result = []
    seen = set()
    for original in raw:
        require(type(original) is dict, 'instruction must be an object')
        row = dict(original)
        pc, length = row.get('address'), row.get('length')
        require(type(pc) is int and type(length) is int and 1 <= length <= 15,
                'invalid decoded address/length')
        rva = pc - image.base
        require(start <= rva and rva + length <= start + len(code),
                'decoded bytes outside executable file-backed range')
        require(rva not in seen, 'duplicate instruction RVA')
        seen.add(rva)
        row.update(rva=rva, bytes=code[rva-start:rva-start+length].hex(),
                   target_rva=row['target_pc']-image.base if row['target_pc'] else 0,
                   iat_slot_rva=row.get('iat_slot_pc', 0)-image.base if row.get('iat_slot_pc') else 0)
        if row['kind'] == 3:
            validate_virtual_instruction(row)
        elif row['kind'] == 4:
            validate_register_instruction(row)
        elif row.get('call_form') in ('VTABLE_MEM64', 'IAT_REG64'):
            raise ValueError('indirect form requires kind 3/4')
        if row['kind'] != 4 and row.get('operand_reg', ''):
            raise ValueError('register operand requires kind 4')
        if row['iat_slot_rva']:
            require(row['iat_slot_rva'] in imports and row['kind'] == 1,
                    'decoded IAT call is not an authorized import')
            binding = imports[row['iat_slot_rva']]
            row.update(target_rva=binding['target_rva'], signature=binding['signature'],
                       import_=dict(dll=binding['dll'], name=binding['name']))
            row['import'] = row.pop('import_')
        if row['immediate_width'] == 64 and image.base <= row['immediate'] < image.base+len(image.data):
            raise ValueError('absolute guest image-address immediate unsupported')
        result.append(row)
    validate_inc_metadata(result)
    validate_flags(result, image.base + entry)
    return result


def validate_trace_abi(ir):
    """Accept only the observed direct-call IR grammar and default C/ccc ABI.

    This deliberately is not an LLVM parser. A new syntax/attribute must be
    reviewed before admission. In particular, checking a few known non-C
    convention names would silently admit newly encountered conventions.
    """
    local = r'%[-a-zA-Z$._0-9]+'
    global_name = r'[-a-zA-Z$._0-9]+'
    trace_name = r'sub_[0-9a-f]+'
    # No sret, byval, inalloca, address spaces, varargs or ABI-changing
    # parameter attributes belong to the trace contract.
    definition_parameters = (r'ptr(?: noalias)? ' + local + r', i64 ' + local +
                             r', ptr(?: noalias)? ' + local)
    call_parameters = r'ptr ' + local + r', i64 (?:' + local + r'|-?[0-9]+), ptr ' + local
    definition = re.compile(r'define (?:ccc )?ptr @(' + trace_name + r')\((' +
                            definition_parameters + r')\) \{')
    # Helpers may have integer result extensions and an explicit vararg
    # function type. Every other prefix token, including any other cc, fails.
    value_prefix = r'(?:ccc )?(?:zeroext )?(?:ptr|i1|i8|i16|i32|i64)'
    declaration = re.compile(r'declare (?:dso_local )?' + value_prefix +
                             r' @(' + global_name + r')\((.*)\)(?: #[0-9]+)?')
    call = re.compile(r'(?:(?:' + local + r') = )?(?:(?:tail|notail|musttail) )?call '
                      r'(' + value_prefix + r'(?: \(i1, \.\.\.\))?) @(' +
                      global_name + r')\((.*)\)(?: #[0-9]+)?')
    definitions = set()
    trace_calls = []
    for line in ir.splitlines():
        code = line.split(';', 1)[0].strip()
        if not code:
            continue
        if re.match(r'define\b', code):
            match = definition.fullmatch(code)
            require(match is not None, 'unsupported trace definition ABI or calling convention')
            name = match.group(1)
            require(name not in definitions, 'duplicate trace definition')
            definitions.add(name)
            continue
        if re.match(r'declare\b', code):
            match = declaration.fullmatch(code)
            require(match is not None, 'unsupported helper declaration ABI or calling convention')
            require(not re.fullmatch(trace_name, match.group(1)), 'trace must be defined, not declared')
            continue
        if re.search(r'\b(?:call|invoke|callbr)\b', code):
            match = call.fullmatch(code)
            require(match is not None, 'unsupported direct call grammar or calling convention')
            prefix, name, parameters = match.groups()
            if name.startswith('sub_'):
                require(re.fullmatch(trace_name, name) is not None and
                        re.fullmatch(r'(?:ccc )?ptr', prefix) is not None and
                        re.fullmatch(call_parameters, parameters) is not None,
                        'trace call must have ptr(ptr,i64,ptr) ABI')
                trace_calls.append(name)
            continue
        require(not re.search(r'@sub_[0-9a-f]+\b', code),
                'trace address used outside a supported direct call')
    require(bool(definitions), 'no valid trace definitions')
    require(all(name in definitions for name in trace_calls), 'direct trace target has no validated definition')
    return definitions


def retarget(ir, entry_pc, entry_rva, entry_symbol, layout_line, triple_line):
    require('x86_fp80' not in ir and 'llvm.x86.' not in ir, 'target-specific lifted IR')
    require(not re.search(r'\binttoptr\b', ir), 'guest integer-to-host-pointer cast')
    sub_symbols = validate_trace_abi(ir)
    allowed = {'aot_begin', 'aot_commit', 'aot_should_exit', '__remill_function_return',
               '__remill_function_call'}
    allowed |= {'__remill_undefined_' + str(n) for n in (8, 16, 32, 64)}
    allowed |= {'__remill_' + op + '_memory_' + str(n)
                for op in ('read', 'write') for n in (8, 16, 32, 64)}
    allowed |= {'__remill_flag_computation_' + n for n in ('zero', 'sign', 'carry', 'overflow')}
    allowed |= {'__remill_compare_' + n for n in ('sle', 'slt', 'sge', 'sgt', 'ule', 'ult', 'uge', 'ugt', 'eq', 'neq')}
    for line in ir.splitlines():
        if line.startswith('declare '):
            match = re.search(r'@([^(]+)\(', line)
            require(match is not None, 'unrecognized helper declaration')
            symbol = match.group(1)
            require(symbol in allowed or symbol.startswith(('llvm.ctpop.', 'llvm.fshl.', 'llvm.fshr.')),
                    'unknown lifted helper: ' + symbol)
    require('store ptr undef' not in ir and not re.search(r'noundef[^,()]*\bundef\b', ir),
            'undefined memory token')
    validate_helper_effects(ir)
    entry = 'sub_%x' % entry_pc
    require(entry in sub_symbols, 'selected root definition missing')
    rename = {name: entry_symbol if name == entry else f'window_{entry_rva:x}_{name}'
              for name in sub_symbols}
    for old, new in rename.items():
        ir = re.sub('@' + re.escape(old) + r'\b', '@' + new, ir)
    for private in set(rename.values()) - {entry_symbol}:
        ir, count = re.subn(r'^(define )(?!internal )([^\n]*@' + re.escape(private) + r'\()',
                            r'\1internal \2', ir, flags=re.M)
        require(count == 1, 'cannot internalize private trace: ' + private)
    ir, layouts = re.subn(r'^target datalayout.*$', layout_line, ir, flags=re.M)
    ir, triples = re.subn(r'^target triple.*$', triple_line, ir, flags=re.M)
    require(layouts == triples == 1, 'lifted target declaration count differs')
    ir = re.sub(r' "(?:target-cpu|target-features|tune-cpu)"="[^"]*"', '', ir)
    return ir, sorted(set(rename.values()) - {entry_symbol})


def run_probe(toolchain, pe, out, run):
    """Use only explicit provider paths; return a JSON-serializable receipt.

    run(argv, label, cwd=None, env=None, expected=0) must return a dict with
    stdout/stderr/returncode, or an object with the same attributes. This caller
    also stores complete command results and independently enforces exit codes.
    llvm may denote the LLVM prefix or its bin directory. out must be empty.
    """
    paths = {key: Path(toolchain[key]).resolve(strict=True)
             for key in ('lifter', 'llvm', 'semantics', 'source', 'sdk')}
    if not (paths['llvm'] / 'clang').is_file() and (paths['llvm'] / 'bin/clang').is_file():
        paths['llvm'] = paths['llvm'] / 'bin'
    lifter, llvm, semantics, source, sdk = (paths[key] for key in ('lifter', 'llvm', 'semantics', 'source', 'sdk'))
    require(lifter.is_file() and semantics.is_file() and source.is_dir() and sdk.is_dir(),
            'explicit provider files/directories required')
    require(all((llvm / name).is_file() for name in ('clang', 'clang++', 'opt')), 'LLVM tools missing')
    require((source / 'include/remill/Arch/X86/Runtime/State.h').is_file(), 'new State source missing')
    pe = Path(pe).resolve(strict=True)
    require(sha(pe) == INPUT_SHA256, 'this probe accepts only the fixed 254be0c3 window PE')
    out = Path(out).absolute()
    require(not out.is_symlink(), 'probe output must not be a symlink')
    if out.exists():
        require(out.is_dir() and not any(out.iterdir()), 'probe output must be empty')
    else:
        out.mkdir(parents=True)
    out = out.resolve(strict=True)
    commands = []

    def execute(argv, label, expected=0):
        argv = [str(value) for value in argv]
        result = run(argv, 'probe-' + label, cwd=out, expected=expected)
        fields = result if isinstance(result, dict) else vars(result)
        record = dict(argv=argv, label=label, cwd=str(out), expected=expected,
                      returncode=fields.get('returncode'), stdout=fields.get('stdout'), stderr=fields.get('stderr'))
        require(type(record['stdout']) is str and type(record['stderr']) is str,
                'runner must return textual stdout/stderr')
        commands.append(record)
        write_json(out / (f'command-{len(commands):03d}-{label}.json'), record)
        require(type(record['returncode']) is int and record['returncode'] == expected,
                'unexpected tool returncode: ' + label)
        return record

    dependencies = [pe, lifter, semantics, *(llvm / n for n in ('clang', 'clang++', 'opt')),
                    Path('/usr/bin/nm'), Path('/usr/bin/ld'), *(REPO / p for p in SOURCE_FILES)]
    for name in ('SDKSettings.json', 'SDKSettings.plist'):
        if (sdk / name).is_file():
            dependencies.append(sdk / name)
    before = snapshot(dependencies)
    tree_before = source_tree(source)
    try:
        image = load_image(pe)
        require(image.source_sha256 == INPUT_SHA256 and image.entry_rva == ROOTS[0][0], 'loaded PE identity/root differs')
        sections = [s for s in image.sections if s['permissions'] & EXEC]
        require(len(sections) == 1, 'requires one executable text range')
        section = sections[0]
        start, length = section['rva'], min(section['virtual_size'], section['raw_size'])
        require(start == 4096 and length == 3110, 'fixed sample text range differs')
        require(not any(start <= r['rva'] < start + length for r in image.relocations), 'text relocation unsupported')
        code = bytes(image.data[start:start+length])
        (out / 'text.bin').write_bytes(code)
        imports = {item['iat_rva']: item for item in image.imports}
        require(len(imports) == len(image.imports) == 21, 'fixed sample import contract differs')
        common = [lifter, '--os=windows', '--arch=amd64', '--address=' + str(image.base + start),
                  '--bytes=' + code.hex(), '--aot_vtable_mem64', '--aot_import_reg64', '--aot_inc_base32',
                  '--aot_iat_slots=' + ','.join(str(image.base + slot) for slot in sorted(imports))]
        negative = out / 'negative'
        negative.mkdir()
        bad = negative / 'invalid.bc'
        bad.write_bytes(b'This is deliberately not LLVM bitcode or LLVM assembly.\n')
        missing = negative / 'does-not-exist.bc'
        negative_results = []
        cases = [('missing-option', [], 'requires an absolute file path'),
                 ('missing-file', ['--aot_semantics=' + str(missing)], 'does not exist or is not regular'),
                 ('invalid-bitcode', ['--aot_semantics=' + str(bad)], 'cannot parse explicit semantics file')]
        for label, option, reason in cases:
            manifest = negative / (label + '.json')
            result = execute(common + ['--entry_address=' + str(image.base + ROOTS[0][0]),
                                       '--aot_manifest=' + str(manifest), '--aot_decode_only'] + option,
                             label, expected=1)
            require('REJECT:' in result['stderr'] and reason in result['stderr'], 'negative case refused for wrong reason: ' + label)
            require(not manifest.exists(), 'failed semantics selection produced an instruction manifest')
            negative_results.append(dict(case=label, returncode=1, reason=reason))

        empty = out / 'target.c'
        empty.write_text('int empty;\n')
        execute([llvm / 'clang', '-target', 'arm64-apple-macos11', '-S', '-emit-llvm', empty,
                 '-o', out / 'target.ll'], 'arm-target')
        target_lines = (out / 'target.ll').read_text().splitlines()
        layouts = [line for line in target_lines if line.startswith('target datalayout')]
        triples = [line for line in target_lines if line.startswith('target triple')]
        require(len(layouts) == len(triples) == 1 and 'arm64-apple-macos' in triples[0], 'LLVM did not produce ARM64 target metadata')
        layout_line, triple_line = layouts[0], triples[0]
        source_layouts = {}
        for target in ('x86_64-none-elf', 'aarch64-none-elf', 'x86_64-pc-windows-msvc', 'arm64-apple-macos11'):
            output = out / ('state-' + target + '.ll')
            execute([llvm / 'clang++', '-target', target, '-std=c++17', '-nostdinc++', '-ffreestanding',
                     '-isystem', source / 'include/remill/Arch/Runtime/sysroot', '-I', source / 'include',
                     '-DADDRESS_SIZE_BITS=64', '-DHAS_FEATURE_AVX=0', '-DHAS_FEATURE_AVX512=0',
                     '-S', '-emit-llvm', REPO / 'integration_stage3/lifter_layout.cpp', '-o', output], 'state-' + target)
            rows = [line for line in output.read_text().splitlines() if re.search(r'^@offsets\s*=', line)]
            require(len(rows) == 1, 'State layout declaration missing/duplicated')
            values = [int(value) for value in re.findall(r'i64 (\d+)', rows[0])]
            require(values == EXPECTED_LAYOUT, 'new source State layout differs: ' + target)
            source_layouts[target] = values

        roots = []
        merged = {}
        for root_rva, symbol, expected_count in ROOTS:
            directory = out / ('root-%x' % root_rva)
            directory.mkdir()
            decode_manifest, lift_manifest = directory / 'decode.json', directory / 'lift.json'
            arguments = common + ['--entry_address=' + str(image.base + root_rva), '--aot_semantics=' + str(semantics)]
            decode = execute(arguments + ['--aot_manifest=' + str(decode_manifest), '--aot_decode_only'], 'decode-%x' % root_rva)
            require('AOT_SEMANTICS_PATH=' + str(semantics) + '\n' in decode['stderr'], 'decoder explicit semantics marker differs')
            raw = json.loads(decode_manifest.read_bytes())
            instructions = normalize(raw, image, start, code, imports, root_rva)
            require(len(instructions) == expected_count, 'fixed root instruction count differs')
            write_json(directory / 'instructions.json', instructions)
            raw_ir, pre_ir = directory / 'lifted.ll', directory / 'pre-optimization.ll'
            lifted = execute(arguments + ['--aot_manifest=' + str(lift_manifest), '--ir_out=' + str(raw_ir),
                                           '--ir_pre_out=' + str(pre_ir)], 'lift-%x' % root_rva)
            require('AOT_SEMANTICS_PATH=' + str(semantics) + '\n' in lifted['stderr'], 'lifter explicit semantics marker differs')
            require(json.loads(lift_manifest.read_bytes()) == raw, 'decode and real lift instruction metadata differ')
            require(pre_ir.is_file() and pre_ir.stat().st_size > 0, 'actual pre-optimization IR missing')
            ir = raw_ir.read_text()
            arm, private = retarget(ir, image.base + root_rva, root_rva, symbol, layout_line, triple_line)
            (directory / 'arm64.ll').write_text(arm)

            # Probe the actual lifted types. The second GEP measures alignment
            # via the first State field's padding in {i8, State}, not a header.
            types = '\n'.join(line for line in ir.splitlines() if re.match(r'^%.* = type ', line))
            require('%struct.State = type ' in types, 'actual lifted State type missing')
            expressions = ['getelementptr (%struct.State, ptr null, i32 1)',
                           'getelementptr ({ i8, %struct.State }, ptr null, i32 0, i32 1)']
            expressions += [f'getelementptr (%struct.State, ptr null, i32 0, i32 0, i32 6, i32 {1+2*i}, i32 0, i32 0)' for i in range(17)]
            expressions += [f'getelementptr (%struct.State, ptr null, i32 0, i32 0, i32 2, i32 {1+2*i})' for i in range(7)]
            layout_ir = layout_line + '\n' + triple_line + '\n' + types + '\n'
            for index, expression in enumerate(expressions):
                layout_ir += f'define i64 @layout_{index}() {{ ret i64 ptrtoint (ptr {expression} to i64) }}\n'
            (directory / 'state-retargeted.ll').write_text(layout_ir)
            harness = '#include <stdio.h>\n'
            harness += ''.join(f'unsigned long long layout_{i}(void);\n' for i in range(len(expressions)))
            harness += 'int main(void){' + ''.join(f'printf("%llu ",layout_{i}());' for i in range(len(expressions))) + 'return 0;}\n'
            (directory / 'state-retargeted.c').write_text(harness)
            layout_object, executable = directory / 'state-retargeted.o', directory / 'state-retargeted'
            execute([llvm / 'clang', '-target', 'arm64-apple-macos11', '-O2', '-c', directory / 'state-retargeted.ll',
                     '-o', layout_object], 'layout-object-%x' % root_rva)
            macho(layout_object, 1)
            execute([llvm / 'clang', '-target', 'arm64-apple-macos11', '-isysroot', sdk,
                     '--sysroot=' + str(sdk), '--ld-path=/usr/bin/ld', '-Wl,-syslibroot,' + str(sdk),
                     directory / 'state-retargeted.c', layout_object, '-o', executable], 'layout-link-%x' % root_rva)
            executable_header = macho(executable, 2)
            observed = execute([executable], 'layout-execute-%x' % root_rva)
            values = [int(value) for value in observed['stdout'].split()]
            require(values == EXPECTED_LAYOUT, 'actual lifted LLVM State layout differs')
            write_json(directory / 'state-layout.json', dict(source=source_layouts, actual_retargeted_ir=values,
                                                            native_harness=executable_header))
            execute([llvm / 'opt', '-passes=verify', '-disable-output', directory / 'arm64.ll'], 'verify-%x' % root_rva)
            objects = {}
            for level in ('O3', 'O0'):
                obj = directory / ('arm64-' + level + '.o')
                execute([llvm / 'clang', '-target', 'arm64-apple-macos11', '-' + level, '-c', directory / 'arm64.ll',
                         '-o', obj], 'object-%x-%s' % (root_rva, level))
                header = macho(obj, 1)
                nm = execute(['/usr/bin/nm', '-gU', obj], 'symbols-%x-%s' % (root_rva, level))
                exports = [line.split()[-1] for line in nm['stdout'].splitlines() if line.split()]
                require(exports == ['_' + symbol], 'unexpected external object definitions')
                objects[level] = dict(path=str(obj), sha256=sha(obj), exports=exports, macho=header)
            for row in instructions:
                rva = row['rva']
                require(rva not in merged or merged[rva] == row, 'conflicting instruction across roots')
                merged[rva] = row
            roots.append(dict(rva=root_rva, symbol=symbol, instruction_count=len(instructions),
                              private_symbols=private, objects=objects, actual_state_layout=values))
        require(len(merged) == 643, 'fixed sample merged instruction count differs')
        write_json(out / 'instructions.json', [merged[rva] for rva in sorted(merged)])
        after = snapshot(dependencies)
        tree_after = source_tree(source)
        require(before == after and tree_before == tree_after, 'probe inputs changed during execution')
        result = dict(status='PASS', validation_level=SCOPE, input_sha256=INPUT_SHA256,
                      toolchain={key: str(value) for key, value in paths.items()}, roots=roots,
                      merged_instruction_count=len(merged), explicit_semantics_negative_cases=negative_results,
                      source_layouts=source_layouts, native_layout_harness_executions=2,
                      guest_executions=0, gpu_executions=0, inputs_before=before, inputs_after=after,
                      prepared_source_sha256=tree_before, command_count=len(commands),
                      artifact_sha256={str(p.relative_to(out)): sha(p) for p in sorted(out.rglob('*')) if p.is_file()})
        write_json(out / 'probe.json', result)
        return result
    except Exception as error:
        write_json(out / 'probe-failure.json', dict(status='FAIL', validation_level=SCOPE, error=str(error),
                   input_sha256=INPUT_SHA256, inputs_before=before, command_count=len(commands),
                   guest_executions=0, gpu_executions=0))
        raise
