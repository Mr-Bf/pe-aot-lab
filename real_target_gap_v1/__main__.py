"""Read-only real PE inventory versus reviewed v7 gates, with no guest execution."""
import argparse
import sys
from pathlib import Path
from real_pe_inventory_v1.inventory import InventoryError
from real_pe_inventory_v1.__main__ import output_path
from .report import build_report, encoded, markdown, digest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--entry', required=True)
    parser.add_argument('--json-out', required=True, type=Path)
    parser.add_argument('--markdown-out', type=Path)
    args = parser.parse_args(argv)
    source = args.input.absolute()
    json_out = output_path(args.json_out, source)
    md_out = output_path(args.markdown_out, source) if args.markdown_out else None
    if md_out == json_out:
        raise InventoryError('JSON and Markdown outputs must differ')
    report = build_report(source, args.entry)
    packages = [Path(__file__).resolve().parent, Path(__file__).resolve().parents[1]/'real_pe_inventory_v1']
    report['implementation_sha256'] = {p.parent.name+'/'+p.name: digest(p.read_bytes())
        for package in packages for p in sorted(package.glob('*.py')) if not p.name.startswith('test_')}
    data = encoded(report)
    with json_out.open('xb') as stream:
        stream.write(data)
    if md_out:
        with md_out.open('x', encoding='utf-8') as stream:
            stream.write(markdown(report))
    print(encoded(dict(status=report['status'], totals=report['totals'], report_sha256=digest(data), guest_executions=0)).decode(), end='')
    # Successful report generation is not successful migration admission.
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (InventoryError, OSError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
