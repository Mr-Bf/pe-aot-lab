"""Whole-root finite-switch lifting with immutable provider and original-byte proof."""
import json
from pathlib import Path
import re
from portable_app_v1 import lift as base
from portable_app_v1.lift import *
from portable_lifter_v1 import deps
from window_inc_v1.lift import validate_inc_metadata, validate_flags, validate_helper_effects
from portable_lifter_v1 import probe as frozen
from . import provider as switch_provider, admission


def cpu_identity(prefix):
    prefix = path(prefix)
    record, tools = switch_provider.paths_for(prefix)
    require(not any(Path(v).resolve().is_relative_to(OLD_WORK) for v in tools.values()), 'old provider path rejected')
    return record, tools, sha(prefix / 'provider.json')


def helper_contract(name):
    if name == 'aot_switch_miss':
        return 'ptr', ('ptr', 'i64', 'ptr'), False
    return base.helper_contract(name)

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
    require('x86_fp80' not in ir and 'llvm.x86.' not in ir, 'target-specific lifted IR')
    require(not re.search(r'\binttoptr\b', ir), 'guest integer-to-host-pointer cast')
    validate_helpers(ir)
    sub_symbols = frozen.validate_trace_abi(ir)
    allowed = {'aot_begin', 'aot_commit', 'aot_should_exit', '__remill_function_return',
               '__remill_function_call', 'aot_switch_miss'}
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


def validate_window_flags(instructions,entry,candidates):
 mask=0x8d5;by={i['address']:i for i in instructions};pred={p:[] for p in by};roots={entry}
 for pc,i in by.items():
  if i['kind']==2:succ=[]
  elif i['kind']==5:
   matches=[c for c in candidates if c['jump_pc']==pc]
   require(len(matches)==1, 'finite jump requires exactly one independently proven candidate')
   succ=matches[0]['targets']
  elif i['kind'] in (3,4):succ=[i['next_pc']]
  elif i['kind']==1:
   if i.get('iat_slot_rva'):succ=[i['next_pc']]
   else:succ=[i['next_pc'],i['target_pc']];roots.add(i['target_pc'])
  elif i['iclass']=='JMP':succ=[i['target_pc']]
  elif i['iclass'].startswith('J'):succ=[i['target_pc'],i['next_pc']]
  else:succ=[i['next_pc']]
  for target in succ:
   if target not in by:raise ValueError('CFG target outside approved instructions')
   pred[target].append(pc)
 valid={p:mask for p in by}
 while True:
  changed=False
  for pc,i in by.items():
   incoming=0 if pc in roots else mask
   for parent in pred[pc]:
    prev=by[parent]
    after=0 if prev['kind'] in (1,3,4) else ((valid[parent]|prev['flags_written'])&~prev['flags_undefined'])&mask
    incoming&=after
   if incoming!=valid[pc]:valid[pc]=incoming;changed=True
  if not changed:break
 for pc,i in by.items():
  if i['flags_read']&mask&~valid[pc]:raise ValueError('undefined flags read at RVA %#x'%i['rva'])

def normalize(raw, image, start, code, imports, entry, candidates):
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
    validate_window_flags(result, image.base + entry, candidates)
    return result


class Session(base.Session):
    def __init__(self, cpu_prefix, out, run):
        self.prefix = path(cpu_prefix)
        self.provider, self.tools, self.provider_sha256 = cpu_identity(self.prefix)
        self.out = path(out, exists=False)
        require(not self.out.exists(), 'fresh compiler directory required')
        self.out.mkdir(parents=True)
        self.run = Commands(self.out, run, 'aot')
        self.llvm = self.tools['llvm'] / 'bin'
        self.sources = source_closure([Path(__file__), Path(__file__).with_name('provider.py')])
        self.inputs = snapshot([*self.sources, ROOT / 'integration_stage3/lifter_layout.cpp',
                                self.prefix / 'provider.json', Path(self.provider['provider']) / 'provider.json',
                                self.tools['lifter'], self.tools['semantics'], Path('/usr/bin/nm'),
                                *[self.tools['source'] / n for n in self.provider['prepared_source']],
                                *[self.llvm / n for n in ('clang','clang++','opt')]])
        self.prepare_layout()

    def verify(self):
        provider, tools, identity = cpu_identity(self.prefix)
        require(provider == self.provider and tools == self.tools and identity == self.provider_sha256,
                'window switch provider changed during production')
        unchanged(self.inputs)

    def roots(self, pe, callback_rvas, leaf_rva):
        pe = path(pe)
        raw_pe = pe.read_bytes()
        image = load_image(raw_pe)
        start, code = executable_bytes(image, callback_rvas)
        readonly = [s for s in image.sections if s['permissions'] == 1 and s['name'] != '.reloc'
                    and min(s['virtual_size'], s['raw_size'])]
        require(len(readonly) == 1, 'one file-backed readonly switch data section required')
        section = readonly[0]
        size = min(section['virtual_size'], section['raw_size'])
        require(0 < size <= 65536, 'bounded readonly data range required')
        data_va = image.base + section['rva']
        data_bytes = bytes(image.data[section['rva']:section['rva']+size])
        data_path = self.out / 'switch-data.bin'
        data_path.write_bytes(data_bytes)
        roots = [image.entry_rva, *callback_rvas]
        imports = {item['iat_rva']: item for item in image.imports}
        prepared = []
        before = {**self.inputs, **snapshot([pe])}
        for rva in roots:
            directory = self.out / ('main' if rva == image.entry_rva else f'window-proc-{rva:x}')
            directory.mkdir()
            (directory / 'text.bin').write_bytes(code)
            arguments = [self.tools['lifter'], '--os=windows', '--arch=amd64',
                         '--address=' + str(image.base + start), '--entry_address=' + str(image.base + rva),
                         '--bytes=' + code.hex(), '--aot_semantics=' + str(self.tools['semantics'].resolve()),
                         '--aot_vtable_mem64', '--aot_import_reg64', '--aot_inc_base32',
                         '--aot_switch_profile=window-rel32-v1', '--aot_switch_data_path=' + str(data_path),
                         '--aot_switch_data_va=' + str(data_va)]
            if imports:
                arguments.append('--aot_iat_slots=' + ','.join(str(image.base + s) for s in sorted(imports)))
            packet_path = directory / 'candidate.json'
            result = self.run(arguments + ['--aot_decode_only', '--aot_manifest=' + str(packet_path)], f'root-{rva:x}-decode')
            require('AOT_SEMANTICS_PATH=' + str(self.tools['semantics'].resolve()) + '\n' in result['stderr'],
                    'decoder used different semantics')
            packet = json.loads(packet_path.read_bytes())
            proof = admission.prove_window_switch(raw_pe, packet, rva, leaf_rva, roots)
            prepared.append(dict(rva=rva, directory=directory, arguments=arguments, packet=packet, proof=proof))
        program_proof = admission.verify_root_set([r['proof'] for r in prepared], raw_pe, roots, leaf_rva)
        write(self.out / 'program-proof.json', program_proof)
        records = []
        for item in prepared:
            rva, directory, packet, proof = item['rva'], item['directory'], item['packet'], item['proof']
            admission.validate_window_switch(proof, raw_pe, packet, rva, leaf_rva, roots)
            symbol = 'aot_entry' if rva == image.entry_rva else f'aot_window_proc_{rva:x}'
            proof_path = directory / 'proof.json'
            write(proof_path, proof)
            instructions = normalize(packet['instructions'], image, start, code, imports, rva, packet['switch_candidates'])
            require(all(type(i['kind']) is int and i['kind'] in (0,1,2,3,4,5) for i in instructions), 'unknown instruction kind')
            ir_path = directory / 'lifted.ll'
            lifted_path = directory / 'lift-candidate.json'
            self.run(item['arguments'] + ['--aot_switch_proof_path=' + str(proof_path),
                     '--aot_manifest=' + str(lifted_path), '--ir_out=' + str(ir_path),
                     '--ir_pre_out=' + str(directory / 'pre-optimization.ll')], f'root-{rva:x}-lift')
            require(json.loads(lifted_path.read_bytes()) == packet, 'decode/lift packet changed')
            ir = ir_path.read_text()
            arm, private = retarget(ir, image.base+rva, rva, symbol, self.layout, self.triple)
            (directory / 'arm64.ll').write_text(arm)
            (directory / 'state-layout.ll').write_text(layout_ir(ir, self.layout, self.triple))
            self.run([self.llvm/'opt','-S','-passes=instcombine',directory/'state-layout.ll','-o',directory/'state-layout-folded.ll'], f'root-{rva:x}-layout')
            actual = folded_layout((directory/'state-layout-folded.ll').read_text())
            self.run([self.llvm/'opt','-passes=verify','-disable-output',directory/'arm64.ll'], f'root-{rva:x}-verify')
            objects = {}
            for level, filename in [('O3','arm64.o'),('O0','arm64-o0.o')]:
                obj = directory / filename
                self.run([self.llvm/'clang','-target',TARGET,'-'+level,'-c',directory/'arm64.ll','-o',obj], f'root-{rva:x}-{level}')
                info = macho(obj,1)
                exports = [line.split()[-1] for line in self.run(['/usr/bin/nm','-gU',obj], f'root-{rva:x}-{level}-symbols')['stdout'].splitlines() if line.split()]
                require(exports == ['_'+symbol], 'unexpected lifted exports')
                objects[level] = dict(path=str(obj),sha256=sha(obj),macho=info,exports=exports)
            unchanged(before)
            record = dict(status='PASS',validation_level=STATUS,symbol=symbol,function_symbol=symbol,
                          root_rva=rva,original_entry_rva=image.entry_rva,input_sha256=image.source_sha256,
                          object=str(directory/'arm64.o'),objects=objects,instructions=instructions,
                          virtual_calls=[validate_virtual_instruction(i) for i in instructions if i['kind']==3],
                          register_calls=[validate_register_instruction(i) for i in instructions if i['kind']==4],
                          imports=image.imports,private_trace_symbols=private,switch_proof=proof,
                          state_layout=dict(source=self.source_layout,actual_ir=actual,evaluation='LLVM instcombine constant DataLayout GEPs'),
                          cpu_provider_sha256=self.provider_sha256,inputs_before=before,inputs_after=snapshot(before),
                          generated_layout_harness_executions=0,guest_executions=0,gpu_executions=0,
                          artifact_sha256=artifacts(directory))
            write(directory/'manifest.json',record)
            row = dict(rva=rva,symbol=symbol,directory=str(directory),manifest=record)
            if rva != image.entry_rva: row['signature']='LRESULT(HWND,UINT,WPARAM,LPARAM)'
            records.append(row)
        merged = {}
        for row in records:
            for ins in row['manifest']['instructions']:
                require(ins['rva'] not in merged or merged[ins['rva']] == ins, 'conflicting root instruction')
                merged[ins['rva']] = ins
        self.verify()
        result = dict(status=STATUS,input_sha256=image.source_sha256,main=records[0],roots=records[1:],
                      instructions=[merged[r] for r in sorted(merged)],cpu_provider_sha256=self.provider_sha256,
                      switch_program=program_proof,generated_layout_harness_executions=0,guest_executions=0,gpu_executions=0)
        write(self.out/'roots.json',result)
        return result
