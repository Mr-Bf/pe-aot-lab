"""Exact, versioned diagnostics overlay. Does not itself execute; generated hook performs bounded replay."""
import difflib
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = 'window_bridge/window_runtime/runtime.c'
TRANSACTION = 'window_bridge/window_runtime/transaction_v1.c'
CALLBACK = 'window_bridge/callback_v1.inc'
LOOKUP = 'window_lookup_v1/lookup_impl.inc'
INSTRUMENTATION = 'window_outer_replay_v1/instrumentation.inc'
PINS = {
    RUNTIME: '9051c121f680988bc4f13a072dacbf213e8612fd3d095acc5704b388f87defd8',
    TRANSACTION: '0b0baf46ea802e3984065dad3be3f36a10a6fcc6d4f0d102e52a5913becaf8ed',
    LOOKUP: 'ebb0a1a8ffa6be1df541b01645dc0a4629b4fb9ad3888def4082eb7c320c3ea0',
    CALLBACK: 'fa0c8108f08e10feaed87936a9440503b30ef1eaf2cce4eefb79470781f0ada2',
    'window_bridge/user32_v1.inc': '14a319668cd5e8856b017f9a7d54782556d461295033755f875fafadc14d20cf',
    'window_bridge/file_api.inc': '66c2b474dc296fd198d510252c5b52240f3c3a2b1333b5b50089443a62076b31',
    'window_bridge/window_runtime/runtime.h': '90cc91f6e94ed0fc64468662ee46cbcefb90414ca964209b359adeba2a954344',
    'window_bridge/callback_v1.h': '3e1a77a9b60624b4cd7357177fa4309bcfe351e85243b66db98d5005d901b250',
    'window_bridge/user32_v1.h': 'ffd2bc7a3e633a5ef4de49663625fe4f12e763ef6f0f1b193672993709772518',
    'window_switch_v1/runtime_fields.inc': '76914960267b0a9f61909c85e366fbf8c66472f9cc686d3efa6c83c1257c4d2a',
}
CALL_ANCHOR = b'void *__remill_function_call(void *state,uint64_t pc,void *opaque) {'
RET_ANCHOR = b'    aot_import_ret(state,pc,opaque);return opaque;'
CALLBACK_ANCHOR = b'uint32_t aot_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,'
LOOKUP_ANCHOR = b'''static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    AotInstruction key={(uint32_t)(pc-ctx->module_base),0,0,0,0};
    return bsearch(&key,ctx->instructions,ctx->instruction_count,sizeof key,compare_instruction);
}
'''
CONTRACT = 'outer-abi-replay-v1'


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(data, old, new):
    need(data.count(old) == 1, 'diagnostic anchor must occur exactly once')
    return data.replace(old, new, 1)


def expected_sources(strategy):
    need(strategy in ('reference', 'inline'), 'unsupported lookup strategy')
    inputs = {}
    for name, digest in PINS.items():
        path = ROOT / name
        need(path.is_file() and not path.is_symlink(), 'missing or linked fixed source: ' + name)
        data = path.read_bytes()
        need(sha(data) == digest, 'fixed source differs: ' + name)
        inputs[name] = data
    hook = ROOT / INSTRUMENTATION
    need(hook.is_file() and not hook.is_symlink(), 'missing diagnostic instrumentation')
    instrumentation = hook.read_bytes()
    runtime = replace_once(inputs[RUNTIME], CALL_ANCHOR,
        b'static void aot_outer_observe_ret(void *,uint64_t,void *,uint32_t);\n'
        b'static void *aot_outer_original_function_call(void *state,uint64_t pc,void *opaque) {')
    runtime = replace_once(runtime, RET_ANCHOR,
        b'    aot_outer_observe_ret(state,pc,opaque,signature);return opaque;')
    runtime += b'\n/* Versioned untimed replay; production templates remain unchanged. */\n' + instrumentation
    callback = replace_once(inputs[CALLBACK], CALLBACK_ANCHOR,
        b'static uint32_t aot_outer_original_wndproc_invoke(AotState *s,AotContext *ctx,uint64_t target,')
    transaction = inputs[TRANSACTION]
    if strategy == 'inline':
        transaction = replace_once(transaction, LOOKUP_ANCHOR, inputs[LOOKUP])
    return {RUNTIME: runtime, TRANSACTION: transaction, CALLBACK: callback}, inputs, instrumentation


def expected_manifest(strategy, generated, inputs, instrumentation):
    return dict(schema=1, contract=CONTRACT, status='GENERATED_REPLAY_ABI_SOURCES_NOT_EXECUTED',
                strategy=strategy, templates={str(ROOT / n): sha(v) for n, v in inputs.items()},
                instrumentation={str(ROOT / INSTRUMENTATION): sha(instrumentation)},
                generated={n: sha(v) for n, v in generated.items()},
                replay_enabled=True, diagnostics_per_event=2,
                scope='Two diagnostic replays with MSG bytes32..43 fixed, then original continuation; exact guest reset and unchanged permission check; no host session reset, timing or performance claim')


def prepare(out, strategy='inline'):
    out = Path(out).absolute()
    need(out == out.resolve(), 'canonical output path required')
    need(not out.exists() and not out.is_symlink(), 'new absent overlay output required')
    generated, inputs, hook = expected_sources(strategy)
    out.mkdir(parents=True)
    for n, data in generated.items():
        p = out / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    diffs = ''.join(''.join(difflib.unified_diff(inputs[n].decode().splitlines(True), data.decode().splitlines(True),
                        fromfile=n, tofile='generated/' + n)) for n, data in generated.items())
    (out / 'overlay.diff').write_text(diffs)
    manifest = expected_manifest(strategy, generated, inputs, hook)
    manifest['diff_sha256'] = sha(diffs.encode())
    (out / 'overlay.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
    record = dict(contract=CONTRACT, strategy=strategy, source_root=str(out),
                  compile_source=str(out / RUNTIME), manifest_path=str(out / 'overlay.json'),
                  manifest_sha256=sha((out / 'overlay.json').read_bytes()))
    verify(record)
    return record


def verify(record):
    need(type(record) is dict and type(record.get('source_root')) is str, 'overlay descriptor required')
    root = Path(record['source_root'])
    need(root.is_absolute() and root.resolve() == root and root.is_dir(), 'canonical overlay directory required')
    generated, inputs, hook = expected_sources(record.get('strategy'))
    wanted = {*generated, 'overlay.json', 'overlay.diff'}
    files = set()
    for p in root.rglob('*'):
        need(not p.is_symlink(), 'overlay symlink forbidden')
        if p.is_file():
            files.add(str(p.relative_to(root)))
        else:
            need(p.is_dir(), 'overlay special member forbidden')
    need(files == wanted, 'overlay file set differs')
    for n, data in generated.items():
        need((root / n).read_bytes() == data, 'generated source differs: ' + n)
    diffs = ''.join(''.join(difflib.unified_diff(inputs[n].decode().splitlines(True), data.decode().splitlines(True),
                        fromfile=n, tofile='generated/' + n)) for n, data in generated.items())
    need((root / 'overlay.diff').read_bytes() == diffs.encode(), 'overlay diff differs')
    expected = expected_manifest(record['strategy'], generated, inputs, hook)
    expected['diff_sha256'] = sha(diffs.encode())
    need(json.loads((root / 'overlay.json').read_bytes()) == expected, 'overlay manifest differs')
    need(record == dict(contract=CONTRACT, strategy=record['strategy'], source_root=str(root),
                       compile_source=str(root / RUNTIME), manifest_path=str(root / 'overlay.json'),
                       manifest_sha256=sha((root / 'overlay.json').read_bytes())), 'overlay descriptor differs')
    return dict(status='REPLAY_ABI_SOURCES_VERIFIED_NOT_EXECUTED', generated_files=len(generated))
