"""Inventory facts and current gates; never an AOT compatibility admission.

The strict loader below maps bytes into Python data, never executable memory.
It neither starts a Windows process nor calls guest code. Its first rejection
is kept separate from all other statically observed requirements.
"""
import hashlib
import json
from pathlib import Path

from real_pe_inventory_v1.inventory import inventory_path, read_input, need
from window_inc_v1.loader import load_image, SIGNATURES, ImageError

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    'window_inc_v1/loader.py': 'a9ca3264b05ac89152d841ad9aabb83700c10d97845c957e61afb5430f7bfd26',
    'callback_bridge/imports_v1.py': '6816eb0b1f20e396ee3bfc148ddb32aa83dfda3449f7c169cf65009ac8f59b76',
    'memory_stage2/image_loader.py': '5d174054e3252fb94fc9323870f0361c5b03e3564fd3fb8a4f97c9fea372461c',
    'window_switch_v1/profile.py': 'd3f12eb3be4c69efd71d080de0f80d06c67398ba6d034297508c54f5c8af7698',
    'window_profile_v1/profile.py': '0fd41140e9cb963df65f6a463803f7d68e3b4244a2e2efcca75e5e628f29c123',
    'window_bridge/user32_v1.inc': '14a319668cd5e8856b017f9a7d54782556d461295033755f875fafadc14d20cf',
    'window_bridge/file_api.inc': '66c2b474dc296fd198d510252c5b52240f3c3a2b1333b5b50089443a62076b31',
    'window_bridge/window_runtime/runtime.c': '9051c121f680988bc4f13a072dacbf213e8612fd3d095acc5704b388f87defd8',
    'migration_v7/__main__.py': 'f7406f5965b1d94f108cfbf9c35731cc79102b5aae05e790816c233e5ca27a8c',
    'portable_app_v1/lift.py': '9c2ef5dd4bbb1e155643cc567151d72cab1c0a781da80556c4ed221a632363f0',
    'window_switch_v1/lift.py': 'b8eb19a14f70c8d8588dc712bcd9c853c7139122e360662f74414206143e0194',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)+'\n').encode()


def check_sources(root=ROOT):
    result = []
    for name, expected in sorted(PINS.items()):
        data = read_input(root/name)
        actual = digest(data)
        need(actual == expected, 'reviewed v7 source changed: '+name)
        result.append(dict(path=name, sha256=actual, bytes=len(data)))
    return result


def compare_file(item, labels=SIGNATURES):
    """Only name/metadata facts: no supported=True derived from an import name."""
    headers = item.get('headers', {})
    imports = []
    for descriptor in item.get('imports', []):
        dll = descriptor.get('dll')
        if dll is None or descriptor.get('status') != 'parsed':
            imports.append(dict(descriptor_status='unparsed', raw=descriptor))
        if dll is None:
            continue
        for symbol in descriptor.get('symbols', []):
            name = symbol.get('name')
            signature = labels.get((dll.lower(), name)) if name is not None else None
            imports.append(dict(dll=dll, name=name, ordinal=symbol.get('ordinal'),
                kind=descriptor.get('kind'), iat_rva=symbol.get('iat_rva'),
                label_known=signature is not None, signature_id=signature,
                argument_contract='restricted; see reviewed runtime sources' if signature is not None else 'not_in_v7_label_table',
                target_arguments_verified=False,
                status='runtime_arguments_unproven' if signature is not None else 'blocked_by_current_label_gate'))
    blocked_dirs = [dict(index=d['index'], name=d['name'], address=d['address'], size=d['size'],
                         parse_status=d['parse_status'])
                    for d in item.get('directories', [])
                    if (d['address'] or d['size']) and d['index'] not in (1, 5, 12)]
    executable = [s for s in item.get('sections', []) if s['executable']]
    code_size = min(executable[0]['raw_size'], executable[0]['virtual_size']) if len(executable) == 1 else None
    code_status = 'not_examined' if 'headers' not in item else ('shape_only_within_gate' if
        code_size is not None and 0 < code_size <= 32768 else 'blocked_by_current_gate')
    return dict(path=item['path'], sha256=item['sha256'], inventory_status=item['status'],
        metadata_complete=item['metadata_complete'],
        image_type='dll' if headers.get('is_dll') else 'exe_or_unclassified',
        dll_loading='blocked_by_current_gate' if headers.get('is_dll') else 'not_a_dll_or_unparsed',
        nonempty_directories_blocked_by_current_policy=blocked_dirs,
        declared_executable_sections=[dict(name=s['name'], rva=s['rva'], raw_size=s['raw_size'],
            virtual_size=s['virtual_size']) for s in item.get('sections', []) if s['executable']],
        executable_shape_gate=dict(status=code_status, executable_sections=len(executable),
            file_backed_code_bytes=code_size, maximum_bytes=32768,
            source='portable_app_v1/lift.py:executable_bytes',
            roots_and_text_relocations='not_examined', instructions_decoded=0),
        import_labels=imports,
        known_name_occurrences=sum(i.get('label_known', False) for i in imports),
        unknown_name_or_ordinal_occurrences=sum(i.get('label_known') is False for i in imports),
        unparsed_descriptors=sum(i.get('descriptor_status') == 'unparsed' for i in imports))


def probe(data):
    try:
        image = load_image(data)
    except ImageError as error:
        return dict(status='blocked_by_current_loader', reason=str(error), guest_executions=0)
    return dict(status='loader_admitted_not_decoded', image_size=len(image.data),
                reason='Data-image admission only; profile, decode, ABI and execution remain unproved', guest_executions=0)


def build_report(source, entry):
    source = Path(source).absolute()
    reviewed = check_sources()
    inventory = inventory_path(source)
    need(entry in [f['path'] for f in inventory['files']], 'entry must exactly match one inventoried relative path')
    root = source.parent if source.is_file() else source
    files = []
    for item in inventory['files']:
        result = compare_file(item)
        if item['sha256'] is None or item['status'] == 'REJECTED':
            result['loader_probe'] = dict(status='not_examined', reason='input inventory rejected', guest_executions=0)
        else:
            data = read_input(root/item['path'])
            need(digest(data) == item['sha256'], 'input changed between inventory and loader probe: '+item['path'])
            result['loader_probe'] = probe(data)
        files.append(result)
    need(check_sources() == reviewed, 'reviewed source changed during inventory')
    selected = next(f for f in files if f['path'] == entry)
    return dict(schema=1, tool='real-target-gap-v1', status='GAP_INVENTORY_ONLY', entry=entry,
        entry_sha256=selected['sha256'], reviewed_sources=reviewed,
        inventory_sha256=digest(encoded(inventory)), inventory=inventory,
        v7_import_label_count=len(SIGNATURES), files=files,
        profile_gate=dict(status='requires_explicit_profile', profile_supplied=False,
            source='migration_v7/__main__.py', reason='v7 requires explicit callback roots and one proved switch leaf; none synthesized'),
        semantic_gates=[dict(id=name, status='not_examined') for name in
            ('reachable_cfg_and_indirect_targets', 'x86_instruction_operand_flags_simd_coverage',
             'tls_initialization_and_teb', 'seh_unwind_language_semantics', 'crt_dll_startup_and_shutdown',
             'dynamic_code_and_runtime_module_loading', 'guest_host_abi_and_callback_contracts',
             'graphics_audio_input_file_api_semantics', 'third_party_binary_source_and_license_closure',
             'native_arm64_execution', 'game_functionality', 'performance')],
        totals=dict(files=len(files), loader_blocked=sum(f['loader_probe']['status']=='blocked_by_current_loader' for f in files),
            loader_admitted_not_decoded=sum(f['loader_probe']['status']=='loader_admitted_not_decoded' for f in files),
            known_name_occurrences=sum(f['known_name_occurrences'] for f in files),
            unknown_name_or_ordinal_occurrences=sum(f['unknown_name_or_ordinal_occurrences'] for f in files)),
        limitations=['DLL basename candidates are not Windows loader resolution.',
            'Not declared in PE metadata does not imply absent at runtime.',
            'Current gate rejection is an implementation limitation, not proof a PE is corrupt or impossible to port.',
            'Same import label never proves compatible arguments or runtime behavior.',
            'Static inspection neither decodes the program nor runs it; no success percentage is inferred.'],
        guest_executions=0, aot_builds=0, converted_third_party_programs=0)


def markdown(report):
    def safe(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('`', "'")
    lines = ['# 真实目标与当前 v7 的静态缺口', '',
        f"目标：`{safe(report['entry'])}`，SHA-256 `{report['entry_sha256']}`。", '',
        '状态：GAP_INVENTORY_ONLY。没有执行 PE、生成 AOT 或证明目标可运行。', '',
        '## 实际 loader 试读与导入名比较', '',
        '| PE | loader 结果 | 首个拒绝原因 | 已知名称 / 未知名称或序号 |', '|---|---|---|---|']
    for f in report['files']:
        p = f['loader_probe']
        lines.append(f"| {safe(f['path'])} | {p['status']} | {safe(p['reason'])} | {f['known_name_occurrences']} / {f['unknown_name_or_ordinal_occurrences']} |")
    lines += ['', '已知名称仅表示命中当前 21 项标签表；参数、调用约定和动态行为仍未验证。', '',
        '## 目标的当前目录门禁', '']
    selected = next(f for f in report['files'] if f['path'] == report['entry'])
    lines += [f"- 目录 {d['index']} `{d['name']}`：地址 {d['address']:#x}，大小 {d['size']:#x}；当前 policy 拒绝。"
              for d in selected['nonempty_directories_blocked_by_current_policy']]
    lines += ['', '显式 profile 尚未提供；不会根据库存伪造 callback 根或 switch 证明。', '',
        '## 尚未验收', '']
    lines += ['- '+g['id'] for g in report['semantic_gates']]
    lines += ['', *report['limitations'], '']
    return '\n'.join(lines)
