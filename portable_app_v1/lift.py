"""Production AOT roots and RET shim using an explicit installed CPU provider.

No fixture hash, old build receipt, or legacy executable path selects the input.
State-layout GEPs are evaluated by the selected LLVM DataLayout without running
a generated executable. The frozen probe supplies only pure IR validators.
"""
import ast
import hashlib
import json
from pathlib import Path
import re

from fixtures import pe_image
from memory_stage2.image_loader import EXEC
from portable_lifter_v1 import build as cpu_build, deps as cpu_deps
from portable_lifter_v1.probe import EXPECTED_LAYOUT, macho, normalize, retarget as frozen_retarget
from window_inc_v1.loader import load_image
from window_inc_v1.lift import validate_register_instruction, validate_virtual_instruction

ROOT = Path(__file__).resolve().parents[1]
OLD_WORK = ROOT.parents[1] / 'work'
TARGET = 'arm64-apple-macos11'
STATUS = 'STATIC_LIFT_ARM_OBJECTS_NOT_GUEST_EXECUTED'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def path(value, *, exists=True):
    item = Path(value).absolute()
    require(item == item.resolve(strict=exists), 'canonical non-symlink path required: ' + str(item))
    require(not item.is_relative_to(OLD_WORK), 'old work dependency rejected: ' + str(item))
    return item


def snapshot(paths):
    result = {}
    for original in sorted(set(map(Path, paths))):
        resolved = original.resolve(strict=True)
        require(not resolved.is_relative_to(OLD_WORK), 'dependency resolved into old work: ' + str(original))
        require(resolved.is_file(), 'regular input required: ' + str(original))
        result[str(resolved)] = sha(resolved)
    return result


def unchanged(identity):
    require(snapshot(identity) == identity, 'recorded inputs changed')


def write(pathname, record):
    with Path(pathname).open('x') as stream:
        json.dump(record, stream, indent=2, sort_keys=True)
        stream.write('\n')


def artifacts(directory, excluded=()):
    result = {}
    for member in sorted(Path(directory).rglob('*')):
        require(not member.is_symlink(), 'artifact symlink rejected')
        if member.is_file() and str(member.relative_to(directory)) not in excluded:
            result[str(member.relative_to(directory))] = sha(member)
        elif not member.is_file():
            require(member.is_dir(), 'non-regular artifact rejected')
    return result


def source_closure(paths):
    """Repository-local static imports, including ``from . import module``.

    Every syntactic import is included regardless of branch conditions. This
    does not claim discovery of dynamic imports or non-Python resource reads.
    """
    pending = [Path(item).resolve(strict=True) for item in paths]
    seen = set()

    def enqueue(parts):
        if not parts:
            return
        for count in range(1, len(parts) + 1):
            initializer = ROOT.joinpath(*parts[:count]) / '__init__.py'
            if initializer.is_file():
                pending.append(initializer.resolve())
        module = ROOT.joinpath(*parts).with_suffix('.py')
        if module.is_file():
            pending.append(module.resolve())

    while pending:
        item = pending.pop()
        require(item.is_relative_to(ROOT) and item.is_file(), 'local Python source escaped repository')
        if item in seen:
            continue
        seen.add(item)
        package = item.parent.relative_to(ROOT).parts
        for node in ast.walk(ast.parse(item.read_text(), filename=str(item))):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    enqueue(tuple(alias.name.split('.')))
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    require(node.level <= len(package), 'relative import escaped repository package')
                    base = package[:len(package) - node.level + 1]
                else:
                    base = ()
                base += tuple(node.module.split('.')) if node.module else ()
                enqueue(base)
                for alias in node.names:
                    if alias.name != '*':
                        enqueue((*base, alias.name))
    return seen


def helper_contract(name):
    fixed = {'aot_begin': ('i32', ('ptr', 'i64', 'ptr')),
             'aot_commit': ('i32', ('ptr', 'i64', 'ptr')),
             'aot_should_exit': ('i32', ('ptr',)),
             '__remill_function_call': ('ptr', ('ptr', 'i64', 'ptr')),
             '__remill_function_return': ('ptr', ('ptr', 'i64', 'ptr'))}
    if name in fixed:
        return *fixed[name], False
    match = re.fullmatch(r'__remill_undefined_(8|16|32|64)', name)
    if match:
        return 'i' + match.group(1), (), False
    match = re.fullmatch(r'__remill_(read|write)_memory_(8|16|32|64)', name)
    if match:
        integer = 'i' + match.group(2)
        return (integer, ('ptr', 'i64'), False) if match.group(1) == 'read' else ('ptr', ('ptr', 'i64', integer), False)
    if re.fullmatch(r'__remill_flag_computation_(zero|sign|carry|overflow)', name):
        return 'i1', ('i1',), True
    if re.fullmatch(r'__remill_compare_(sle|slt|sge|sgt|ule|ult|uge|ugt|eq|neq)', name):
        return 'i1', ('i1',), False
    match = re.fullmatch(r'llvm\.(ctpop|fshl|fshr)\.(i8|i16|i32|i64)', name)
    if match:
        integer = match.group(2)
        return integer, (integer,) * (1 if match.group(1) == 'ctpop' else 3), False
    raise ValueError('unsupported lifted helper: ' + name)


def helper_parameters(text, declaration):
    result = []
    if not text:
        return result
    for parameter in text.split(','):
        parameter = parameter.strip()
        if parameter == '...':
            require(declaration, 'vararg marker is not a call operand')
            result.append('...')
            continue
        match = re.fullmatch(r'(ptr|i1|i8|i16|i32|i64)((?: (?:noundef|nonnull|noalias|zeroext|align [0-9]+))*)(.*)', parameter)
        require(match is not None, 'unsupported helper parameter type/attribute')
        kind, _, value = match.groups()
        if declaration:
            require(not value, 'unsupported helper declaration parameter syntax')
        else:
            require(re.fullmatch(r' (?:%[-a-zA-Z$._0-9]+|-?[0-9]+|true|false|null)', value) is not None,
                    'unsupported helper call operand syntax')
        result.append(kind)
    return result


def validate_helper_extensions(name, return_prefix, parameters, fixed_count):
    """Preserve the unsigned narrow-integer ABI of the observed C helpers."""
    result_type, _, _ = helper_contract(name)
    external = name.startswith('__remill_')
    require(('zeroext' in return_prefix.split()) == (external and result_type in ('i1', 'i8', 'i16')),
            'helper return extension ABI differs: ' + name)
    for parameter in parameters.split(',')[:fixed_count]:
        tokens = parameter.strip().split()
        require(('zeroext' in tokens) == (external and tokens[0] in ('i1', 'i8', 'i16')),
                'helper parameter extension ABI differs: ' + name)


def validate_helpers(ir):
    """Constrain helper ABIs and top-level syntax before frozen IR validation.

    Frozen validators parse canonical LLVM top-level lines. Reject unsupported
    indentation/formatting instead of rewriting IR and potentially changing the
    meaning of an attribute group before validating callback memory effects.
    """
    declarations, calls, groups, referenced_groups = {}, [], set(), set()
    prefix = r'(?:ccc )?(?:zeroext )?(ptr|i1|i8|i16|i32|i64)'
    for line in ir.splitlines():
        stripped = line.lstrip()
        if re.match(r'(?:declare|attributes|define)\b', stripped):
            require(line == stripped, 'noncanonical top-level LLVM indentation')
        if stripped.startswith('attributes'):
            match = re.fullmatch(r'attributes #([0-9]+) = \{(.*)\}', line)
            require(match is not None and int(match.group(1)) not in groups,
                    'unsupported or duplicate LLVM attribute-group syntax')
            groups.add(int(match.group(1)))
            continue
        if re.match(r'declare\b', stripped):
            match = re.fullmatch(r'declare (?:dso_local )?' + prefix + r' @([-a-zA-Z$._0-9]+)\((.*)\)(?: #([0-9]+))?', line)
            require(match is not None, 'unsupported helper declaration syntax')
            result_type, name, parameters, group = match.groups()
            expected_type, expected_parameters, varargs = helper_contract(name)
            actual = helper_parameters(parameters, True)
            require(result_type == expected_type and actual == [*expected_parameters, *(['...'] if varargs else [])],
                    'helper declaration ABI differs: ' + name)
            validate_helper_extensions(name, line.split('@', 1)[0], parameters, len(expected_parameters))
            require(name not in declarations, 'duplicate helper declaration')
            declarations[name] = (result_type, tuple(actual))
            if group is not None:
                referenced_groups.add(int(group))
        elif re.search(r'\bcall\b', line.split(';', 1)[0]):
            match = re.fullmatch(r'\s*(?:%[-a-zA-Z$._0-9]+ = )?(?:(?:tail|notail|musttail) )?call ' + prefix +
                                 r'( \(i1, \.\.\.\))? @([-a-zA-Z$._0-9]+)\((.*)\)(?: #([0-9]+))?', line)
            require(match is not None, 'unsupported helper/direct-call syntax')
            result_type, explicit_varargs, name, parameters, group = match.groups()
            if group is not None:
                referenced_groups.add(int(group))
            if name.startswith('sub_'):
                continue  # Frozen retarget validates each trace definition and call.
            expected_type, expected_parameters, varargs = helper_contract(name)
            actual = helper_parameters(parameters, False)
            require(result_type == expected_type and bool(explicit_varargs) == varargs and
                    (actual[:len(expected_parameters)] == list(expected_parameters) if varargs else actual == list(expected_parameters)),
                    'helper call ABI differs: ' + name)
            validate_helper_extensions(name, line.split('@', 1)[0], parameters, len(expected_parameters))
            calls.append(name)
    require(all(name in declarations for name in calls), 'called helper lacks a validated declaration')
    require(referenced_groups <= groups, 'undefined LLVM attribute-group reference')


def retarget(ir, entry_pc, entry_rva, entry_symbol, layout_line, triple_line):
    validate_helpers(ir)
    return frozen_retarget(ir, entry_pc, entry_rva, entry_symbol, layout_line, triple_line)


class Commands:
    """Keep actual argv/results even when the outer recorder has its own logs."""
    def __init__(self, out, run, namespace):
        self.out, self.run, self.namespace = Path(out), run, namespace
        self.directory = self.out / 'commands'
        self.directory.mkdir()
        self.records = []

    def __call__(self, argv, label, cwd=None, env=None, expected=0):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', label), 'invalid command label')
        argv = list(map(str, argv))
        cwd = str(Path(cwd or self.out).resolve())
        require(str(OLD_WORK) not in json.dumps([argv, cwd, env]), 'old work path in actual command')
        number = len(self.records) + 1
        record = dict(argv=argv, label=label, cwd=cwd, env=env, expected=expected)
        filename = self.directory / (f'{number:03d}-' + label + '.json')
        try:
            returned = self.run(argv, self.namespace + '-' + label, cwd=cwd, env=env, expected=expected)
        except Exception as error:
            record.update(status='RECORDER_OR_COMMAND_FAILED', error=repr(error))
            write(filename, record)
            self.records.append(record)
            raise
        require(isinstance(returned, dict), 'command recorder must return a dictionary')
        record.update({key: returned.get(key) for key in ('stdout', 'stderr', 'returncode')})
        write(filename, record)
        self.records.append(record)
        require(type(record['returncode']) is int and record['returncode'] == expected,
                'unexpected command exit: ' + label)
        require(type(record['stdout']) is str and type(record['stderr']) is str,
                'command recorder must retain textual stdout/stderr')
        return record


def cpu_identity(prefix):
    prefix = path(prefix)
    provider, selected = cpu_build.paths_for(prefix)
    require(cpu_deps.tree(selected['source']) == provider['source_tree'], 'installed CPU source changed')
    for value in selected.values():
        require(not Path(value).resolve().is_relative_to(OLD_WORK), 'CPU provider role resolves into old work')
    return provider, selected, sha(prefix / 'provider.json')


def executable_bytes(image, callback_rvas):
    require(type(callback_rvas) in (list, tuple) and len(callback_rvas) <= 8 and
            all(type(rva) is int for rva in callback_rvas), 'explicit bounded integer callback roots required')
    require(len(set(callback_rvas)) == len(callback_rvas) and image.entry_rva not in callback_rvas,
            'duplicate or entry callback root')
    sections = [section for section in image.sections if section['permissions'] & EXEC]
    require(len(sections) == 1, 'one executable range required')
    section = sections[0]
    start, size = section['rva'], min(section['virtual_size'], section['raw_size'])
    require(0 < size <= 32768, 'bounded executable byte range required')
    require(all(start <= rva < start + size for rva in (image.entry_rva, *callback_rvas)),
            'root outside executable file-backed bytes')
    require(not any(rel['rva'] < start + size and start < rel['rva'] + 8 for rel in image.relocations),
            'executable relocation unsupported')
    return start, bytes(image.data[start:start + size])


def layout_ir(ir, layout, triple):
    types = '\n'.join(line for line in ir.splitlines() if re.match(r'^%.* = type ', line))
    require('%struct.State = type ' in types, 'actual lifted State type absent')
    expressions = ['getelementptr (%struct.State, ptr null, i32 1)',
                   'getelementptr ({ i8, %struct.State }, ptr null, i32 0, i32 1)']
    expressions += [f'getelementptr (%struct.State, ptr null, i32 0, i32 0, i32 6, i32 {1+2*i}, i32 0, i32 0)' for i in range(17)]
    expressions += [f'getelementptr (%struct.State, ptr null, i32 0, i32 0, i32 2, i32 {1+2*i})' for i in range(7)]
    return layout + '\n' + triple + '\n' + types + '\n' + ''.join(
        f'define i64 @layout_{i}() {{ ret i64 ptrtoint (ptr {value} to i64) }}\n'
        for i, value in enumerate(expressions))


def folded_layout(ir):
    rows = re.findall(r'^define\s+i64\s+@layout_(\d+)\(\)[^\n]*\{([^}]+)\}', ir, re.M)
    require(len(rows) == len(EXPECTED_LAYOUT), 'folded State layout function count differs')
    values = {}
    for index, body in rows:
        require(int(index) not in values, 'duplicate State layout function')
        # A label/comment is harmless; any remaining instruction or symbolic
        # expression means the selected LLVM did not prove a constant layout.
        clean = '\n'.join(line.split(';', 1)[0].strip() for line in body.splitlines())
        clean = re.sub(r'^[-a-zA-Z$._0-9]+:\s*', '', clean.strip())
        match = re.fullmatch(r'ret i64 ([0-9]+)', clean.strip())
        require(match is not None, 'State layout did not fold to a single constant return')
        values[int(index)] = int(match.group(1))
    require(set(values) == set(range(len(EXPECTED_LAYOUT))), 'State layout function indices differ')
    result = [values[index] for index in range(len(EXPECTED_LAYOUT))]
    require(result == EXPECTED_LAYOUT, 'actual lifted State layout differs')
    return result


class Session:
    def __init__(self, cpu_prefix, out, run):
        self.prefix = path(cpu_prefix)
        self.provider, self.tools, self.provider_sha256 = cpu_identity(self.prefix)
        self.out = path(out, exists=False)
        require(not self.out.exists(), 'fresh compiler directory required')
        self.out.mkdir(parents=True)
        self.run = Commands(self.out, run, 'aot')
        self.llvm = self.tools['llvm'] / 'bin'
        self.sources = source_closure([Path(__file__), ROOT / 'portable_lifter_v1/probe.py'])
        dependencies = [*self.sources, ROOT / 'integration_stage3/lifter_layout.cpp',
                        self.prefix / 'provider.json', Path('/usr/bin/nm'),
                        *[self.prefix / name for name in self.provider['runtime_files']],
                        *[self.tools['source'] / name for name in self.provider['source_tree']],
                        *[self.llvm / name for name in ('clang', 'clang++', 'opt')]]
        self.inputs = snapshot(dependencies)
        self.prepare_layout()

    def verify(self):
        provider, tools, digest = cpu_identity(self.prefix)
        require(provider == self.provider and tools == self.tools and digest == self.provider_sha256,
                'CPU provider changed during production')
        unchanged(self.inputs)

    def prepare_layout(self):
        empty = self.out / 'target.c'
        empty.write_text('int empty;\n')
        self.run([self.llvm / 'clang', '-target', TARGET, '-S', '-emit-llvm', empty,
                  '-o', self.out / 'target.ll'], 'target')
        lines = (self.out / 'target.ll').read_text().splitlines()
        layout = [line for line in lines if line.startswith('target datalayout')]
        triple = [line for line in lines if line.startswith('target triple')]
        require(len(layout) == len(triple) == 1 and 'arm64-apple-macos' in triple[0], 'ARM64 target metadata absent')
        self.layout, self.triple = layout[0], triple[0]
        self.source_layout = {}
        source = self.tools['source']
        for target in ('x86_64-none-elf', 'aarch64-none-elf', 'x86_64-pc-windows-msvc', TARGET):
            output = self.out / ('state-' + target + '.ll')
            self.run([self.llvm / 'clang++', '-target', target, '-std=c++17', '-nostdinc++', '-ffreestanding',
                      '-isystem', source / 'include/remill/Arch/Runtime/sysroot', '-I', source / 'include',
                      '-DADDRESS_SIZE_BITS=64', '-DHAS_FEATURE_AVX=0', '-DHAS_FEATURE_AVX512=0',
                      '-S', '-emit-llvm', ROOT / 'integration_stage3/lifter_layout.cpp', '-o', output], 'state-' + target)
            rows = [line for line in output.read_text().splitlines() if re.match(r'^@offsets\s*=', line)]
            require(len(rows) == 1, 'State source layout declaration count differs')
            values = [int(value) for value in re.findall(r'i64 (\d+)', rows[0])]
            require(values == EXPECTED_LAYOUT, 'State source layout differs: ' + target)
            self.source_layout[target] = values
        write(self.out / 'source-layout.json', self.source_layout)

    def root(self, pe, directory, image, root_rva, symbol, *, shim=False):
        pe = path(pe)
        directory = path(directory, exists=False)
        require(not directory.exists(), 'fresh per-root output required')
        require(symbol == ('aot_import_ret' if shim else ('aot_entry' if root_rva == image.entry_rva else f'aot_window_proc_{root_rva:x}')),
                'invalid trace export name')
        require(type(root_rva) is int, 'integer root RVA required')
        start, code = executable_bytes(image, [] if root_rva == image.entry_rva else [root_rva])
        before = {**self.inputs, **snapshot([pe])}
        require(sha(pe) == image.source_sha256, 'loaded image differs from input bytes')
        directory.mkdir(parents=True)
        (directory / 'text.bin').write_bytes(code)
        imports = {item['iat_rva']: item for item in image.imports}
        require(len(imports) == len(image.imports), 'duplicate input IAT slot')
        arguments = [self.tools['lifter'], '--os=windows', '--arch=amd64', '--address=' + str(image.base + start),
                     '--entry_address=' + str(image.base + root_rva), '--bytes=' + code.hex(),
                     '--aot_semantics=' + str(self.tools['semantics'].resolve()),
                     '--aot_vtable_mem64', '--aot_import_reg64', '--aot_inc_base32']
        if imports:
            arguments.append('--aot_iat_slots=' + ','.join(str(image.base + slot) for slot in sorted(imports)))
        label = 'ret' if shim else f'root-{root_rva:x}'
        decode_path, lift_path = directory / 'instructions-raw.json', directory / 'lift-instructions-raw.json'
        decoded = self.run(arguments + ['--aot_manifest=' + str(decode_path), '--aot_decode_only'], label + '-decode')
        marker = 'AOT_SEMANTICS_PATH=' + str(self.tools['semantics'].resolve()) + '\n'
        require(marker in decoded['stderr'], 'decoder selected different semantics')
        raw = json.loads(decode_path.read_bytes())
        instructions = normalize(raw, image, start, code, imports, root_rva)
        require(all(type(row['kind']) is int and row['kind'] in (0, 1, 2, 3, 4) for row in instructions),
                'unknown instruction kind')
        if shim:
            require(code == b'\xc3' and len(instructions) == 1 and instructions[0]['bytes'] == 'c3' and
                    instructions[0]['kind'] == 2 and not imports, 'RET shim must be exactly one actual C3 instruction')
        ir_path = directory / 'lifted.ll'
        lifted = self.run(arguments + ['--aot_manifest=' + str(lift_path), '--ir_out=' + str(ir_path),
                                      '--ir_pre_out=' + str(directory / 'pre-optimization.ll')], label + '-lift')
        require(marker in lifted['stderr'], 'lifter selected different semantics')
        require(json.loads(lift_path.read_bytes()) == raw, 'decode and lift instruction manifests differ')
        require((directory / 'pre-optimization.ll').stat().st_size > 0, 'pre-optimization IR absent')
        ir = ir_path.read_text()
        arm, private = retarget(ir, image.base + root_rva, root_rva, symbol, self.layout, self.triple)
        (directory / 'arm64.ll').write_text(arm)
        (directory / 'state-layout.ll').write_text(layout_ir(ir, self.layout, self.triple))
        self.run([self.llvm / 'opt', '-S', '-passes=instcombine', directory / 'state-layout.ll',
                  '-o', directory / 'state-layout-folded.ll'], label + '-layout-fold')
        actual_layout = folded_layout((directory / 'state-layout-folded.ll').read_text())
        self.run([self.llvm / 'opt', '-passes=verify', '-disable-output', directory / 'arm64.ll'], label + '-verify')
        objects = {}
        for level, name in (('O3', 'arm64.o'), ('O0', 'arm64-o0.o')):
            obj = directory / name
            self.run([self.llvm / 'clang', '-target', TARGET, '-' + level, '-c', directory / 'arm64.ll', '-o', obj], label + '-' + level)
            info = macho(obj, 1)
            symbols = self.run(['/usr/bin/nm', '-gU', obj], label + '-' + level + '-symbols')['stdout']
            exports = [line.split()[-1] for line in symbols.splitlines() if line.split()]
            require(exports == ['_' + symbol], 'unexpected lifted object exports')
            objects[level] = dict(path=str(obj), sha256=sha(obj), macho=info, exports=exports)
        unchanged(before)
        record = dict(status='PASS', validation_level=STATUS, symbol=symbol, function_symbol=symbol,
                      root_rva=root_rva, original_entry_rva=image.entry_rva, input_sha256=image.source_sha256,
                      object=str(directory / 'arm64.o'), objects=objects, instructions=instructions,
                      virtual_calls=[validate_virtual_instruction(row) for row in instructions if row['kind'] == 3],
                      register_calls=[validate_register_instruction(row) for row in instructions if row['kind'] == 4],
                      imports=image.imports, private_trace_symbols=private,
                      state_layout=dict(source=self.source_layout, actual_ir=actual_layout, evaluation='LLVM instcombine constant DataLayout GEPs'),
                      cpu_provider_sha256=self.provider_sha256, inputs_before=before, inputs_after=snapshot(before),
                      generated_layout_harness_executions=0, guest_executions=0, gpu_executions=0,
                      artifact_sha256=artifacts(directory))
        write(directory / 'manifest.json', record)
        return record

    def roots(self, pe, callback_rvas):
        pe = path(pe)
        image = load_image(pe)
        executable_bytes(image, callback_rvas)
        main = self.root(pe, self.out / 'main', image, image.entry_rva, 'aot_entry')
        main_root = dict(rva=image.entry_rva, symbol='aot_entry', directory=str(self.out / 'main'), manifest=main)
        roots = []
        for rva in callback_rvas:
            directory = self.out / ('window-proc-%x' % rva)
            symbol = 'aot_window_proc_%x' % rva
            record = self.root(pe, directory, image, rva, symbol)
            roots.append(dict(rva=rva, symbol=symbol, directory=str(directory), manifest=record,
                              signature='LRESULT(HWND,UINT,WPARAM,LPARAM)'))
        merged = {}
        for root in [main_root, *roots]:
            for row in root['manifest']['instructions']:
                require(row['rva'] not in merged or merged[row['rva']] == row, 'conflicting instructions across roots')
                merged[row['rva']] = row
        self.verify()
        result = dict(status=STATUS, input_sha256=image.source_sha256, main=main_root, roots=roots,
                      instructions=[merged[rva] for rva in sorted(merged)], cpu_provider_sha256=self.provider_sha256,
                      generated_layout_harness_executions=0, guest_executions=0, gpu_executions=0)
        write(self.out / 'roots.json', result)
        return result

    def ret_shim(self, out):
        out = path(out, exists=False)
        require(not out.exists(), 'fresh RET shim destination required')
        out.mkdir(parents=True)
        pe = out / 'synthetic-ret.exe'
        pe.write_bytes(pe_image(b'\xc3'))
        image = load_image(pe)
        record = self.root(pe, out / 'lift', image, image.entry_rva, 'aot_import_ret', shim=True)
        self.verify()
        return record


def verify_root(directory, record):
    directory = path(directory)
    require(json.loads((directory / 'manifest.json').read_bytes()) == record and record['status'] == 'PASS' and
            record['validation_level'] == STATUS, 'root receipt identity differs')
    require(artifacts(directory, ('manifest.json',)) == record['artifact_sha256'], 'actual root artifacts differ')
    unchanged(record['inputs_before'])
    require(record['inputs_before'] == record['inputs_after'], 'root inputs changed')
    for item in record['objects'].values():
        obj = Path(item['path'])
        require(obj.parent == directory and sha(obj) == item['sha256'] and macho(obj, 1) == item['macho'],
                'root object differs from verified producer result')
