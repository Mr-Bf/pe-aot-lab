"""Build a local XED decoder or statically inspect a PE, without guest execution."""
import argparse
import json
from pathlib import Path
import sys

from real_pe_inventory_v1.inventory import read_input, need
from real_pe_inventory_v1.__main__ import output_path
from .graph import discover, encoded, markdown, sha


def sources():
    root = Path(__file__).resolve().parents[1]
    files = [p for name in ('real_pe_cfg_v1', 'real_pe_inventory_v1') for p in (root/name).glob('*')
             if p.suffix in ('.py', '.c') and not p.name.startswith('test_')]
    return {str(p.relative_to(root)): sha(read_input(p)) for p in sorted(files)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build-decoder')
    build.add_argument('--xed-prefix', type=Path, required=True)
    build.add_argument('--out', type=Path, required=True)
    build.add_argument('--clang', default='/usr/bin/clang')
    analyze = commands.add_parser('analyze')
    analyze.add_argument('pe', type=Path)
    analyze.add_argument('--decoder-receipt', type=Path, required=True)
    analyze.add_argument('--max-instructions', type=int, default=100000)
    analyze.add_argument('--json-out', type=Path, required=True)
    analyze.add_argument('--markdown-out', type=Path)
    args = parser.parse_args(argv)
    # The graph module's pure tests/imports do not need a native decoder.
    from .decoder import Decoder, build_decoder, sha as file_sha
    if args.command == 'build-decoder':
        result = build_decoder(args.out, args.xed_prefix, args.clang)
        print(json.dumps(dict(status=result['status'], library_sha256=result['library_sha256'], guest_executions=0)))
        return 0
    source = args.pe.absolute()
    need(source.is_file(), 'analyze requires one PE file')
    json_out = output_path(args.json_out, source)
    md_out = output_path(args.markdown_out, source) if args.markdown_out else None
    need(json_out != md_out, 'JSON and Markdown outputs must differ')
    before = sources(); data = read_input(source)
    decoder = Decoder(args.decoder_receipt)
    try:
        report = discover(data, decoder, source.name, args.max_instructions)
    finally:
        decoder.close()
    need(sources() == before and sha(read_input(source)) == sha(data), 'source or PE changed during graph discovery')
    for name, expected in decoder.identity['inputs'].items():
        need(file_sha(name) == expected, 'decoder build input changed during discovery: '+name)
    need(file_sha(decoder.identity['library']) == decoder.identity['library_sha256'] and
         file_sha(args.decoder_receipt) == decoder.identity['receipt_sha256'],
         'decoder library or receipt changed during discovery')
    report['implementation_sha256'] = before
    raw = encoded(report)
    with json_out.open('xb') as stream:
        stream.write(raw)
    if md_out:
        with md_out.open('x', encoding='utf-8') as stream:
            stream.write(markdown(report))
    compact = {key: value for key, value in report['summary'].items() if not key.endswith('_histogram')}
    compact['frontier_histogram'] = report['summary']['frontier_histogram']
    print(json.dumps(dict(status=report['status'], summary=compact,
                         report_sha256=sha(raw), guest_executions=0), sort_keys=True))
    # A useful inventory is intentionally not a closed/supported CFG admission.
    return 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(json.dumps(dict(status='INPUT_OR_TOOL_REJECTED', error=str(error), guest_executions=0)), file=sys.stderr)
        sys.exit(2)
