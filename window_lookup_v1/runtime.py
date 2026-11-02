"""Generate two frozen runtime sources with one exact lookup replacement.

The generated runtime.c is byte-identical to its template. Its adjacent
transaction_v1.c takes precedence over -iquote; all remaining quoted includes
are resolved by the original runtime directory and recorded by the compiler.
"""
import hashlib
import json
from pathlib import Path

from window_switch_v1 import lift
from graphics_stage5.d3d11_probe import dependency_paths

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = 'window_bridge/window_runtime/runtime.c'
TRANSACTION = 'window_bridge/window_runtime/transaction_v1.c'
LOOKUP = 'window_lookup_v1/lookup_impl.inc'
CONTRACT = 'inline-instruction-search-v1'
STATUS = 'GENERATED_INLINE_LOOKUP_SOURCES_NOT_EXECUTED'
FROZEN = {
    RUNTIME: '9051c121f680988bc4f13a072dacbf213e8612fd3d095acc5704b388f87defd8',
    TRANSACTION: '0b0baf46ea802e3984065dad3be3f36a10a6fcc6d4f0d102e52a5913becaf8ed',
    LOOKUP: 'ebb0a1a8ffa6be1df541b01645dc0a4629b4fb9ad3888def4082eb7c320c3ea0',
}
ORIGINAL = b'''static const AotInstruction *instruction(AotContext *ctx,uint64_t pc) {
    if(pc<ctx->module_base || pc-ctx->module_base>UINT32_MAX)return NULL;
    AotInstruction key={(uint32_t)(pc-ctx->module_base),0,0,0,0};
    return bsearch(&key,ctx->instructions,ctx->instruction_count,sizeof key,compare_instruction);
}
'''
SCOPE = 'One exact instruction lookup replacement; all other runtime bytes, ABI, permission checks and snapshots unchanged; no execution or performance claim.'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def template_paths():
    return [ROOT / name for name in FROZEN]


def transform(transaction, lookup):
    lift.require(digest(transaction) == FROZEN[TRANSACTION], 'frozen transaction template differs')
    lift.require(digest(lookup) == FROZEN[LOOKUP], 'frozen inline lookup differs')
    lift.require(transaction.count(ORIGINAL) == 1, 'lookup anchor is not unique')
    result = transaction.replace(ORIGINAL, lookup, 1)
    lift.require(b'aot_pair_lookup_mode' not in result, 'experimental selector forbidden')
    return result


def expected_sources():
    sources = {}
    for name, expected in FROZEN.items():
        path = lift.path(ROOT / name)
        lift.require(path.is_file() and lift.sha(path) == expected, 'frozen runtime source differs: ' + name)
        sources[name] = path.read_bytes()
        lift.require(digest(sources[name]) == expected, 'runtime source changed during read')
    return {RUNTIME: sources[RUNTIME], TRANSACTION: transform(sources[TRANSACTION], sources[LOOKUP])}


def manifest(generated):
    return dict(schema=1, status=STATUS, contract=CONTRACT,
                templates={str(ROOT / name): value for name, value in FROZEN.items()},
                generated_files={name: digest(data) for name, data in generated.items()},
                lookup_sha256=FROZEN[LOOKUP], scope=SCOPE)


def descriptor(out):
    return dict(contract=CONTRACT, manifest_path=str(out / 'runtime.json'),
                manifest_sha256=lift.sha(out / 'runtime.json'), source_root=str(out),
                compile_source=str(out / RUNTIME), transaction_source=str(out / TRANSACTION),
                lookup_sha256=FROZEN[LOOKUP])


def prepare(out):
    out = lift.path(out, exists=False)
    lift.require(not out.exists(), 'fresh runtime source directory required')
    generated = expected_sources()
    out.mkdir(parents=True)
    for name, data in generated.items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    lift.write(out / 'runtime.json', manifest(generated))
    record = descriptor(out)
    verify(record)
    return record


def verify(record):
    lift.require(type(record) is dict and type(record.get('source_root')) is str, 'runtime lookup descriptor required')
    out = lift.path(record['source_root'])
    lift.require(out.is_dir(), 'runtime source directory required')
    lift.require(record == descriptor(out), 'runtime lookup descriptor differs')
    generated = expected_sources()
    wanted = {*generated, 'runtime.json'}
    files = set()
    for path in out.rglob('*'):
        lift.require(not path.is_symlink(), 'runtime source link rejected')
        if path.is_file():
            files.add(str(path.relative_to(out)))
        else:
            lift.require(path.is_dir(), 'runtime source nonregular member')
    lift.require(files == wanted, 'runtime source file set differs')
    value = json.loads((out / 'runtime.json').read_bytes())
    lift.require(value == manifest(generated), 'runtime source manifest differs')
    for name, data in generated.items():
        lift.require((out / name).read_bytes() == data, 'generated runtime bytes differ: ' + name)
    lift.require(record == descriptor(out), 'runtime source receipt changed during verification')
    return dict(status='INLINE_LOOKUP_SOURCES_VERIFIED_NOT_EXECUTED', generated_files=len(generated))


def validate_dependencies(text, record):
    paths = dependency_paths(text)
    generated = {Path(record['compile_source']), Path(record['transaction_source'])}
    lift.require(generated <= set(paths), 'generated runtime compilation sources absent')
    lift.require(ROOT / TRANSACTION not in paths and ROOT / RUNTIME not in paths,
                 'compiler selected an original runtime compilation source')
    lift.require(all(paths.count(path) == 1 for path in generated), 'runtime compilation source repeated')


def verify_product(record, product):
    """A product may only bind its own generated runtime source directory."""
    product = lift.path(product)
    lift.require(type(record) is dict and record.get('source_root') == str(product / 'native/runtime-source'),
                 'runtime source is not this product overlay')
    return verify(record)
