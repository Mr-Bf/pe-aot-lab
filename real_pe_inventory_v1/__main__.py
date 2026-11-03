"""CLI: file-only inventory, exclusive new reports, no PE execution."""
import argparse
import json
from pathlib import Path
import sys
from .inventory import InventoryError, inventory_path, markdown, need, sha


def output_path(value,source):
    path=Path(value).absolute()
    need(path==path.resolve() and path.parent.is_dir(),'output needs a canonical existing parent')
    need(not path.exists() and not path.is_symlink(),'output must be a new absent file')
    need(path!=source and not (source.is_dir() and path.is_relative_to(source)),
         'output must not modify the inventoried input tree')
    return path


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--json-out',type=Path)
    parser.add_argument('--markdown-out',type=Path)
    args=parser.parse_args(argv);source=args.input.absolute()
    outputs=[output_path(v,source) if v else None for v in (args.json_out,args.markdown_out)]
    need(not all(outputs) or outputs[0]!=outputs[1],'JSON and Markdown outputs must differ')
    report=inventory_path(source)
    package=Path(__file__).resolve().parent
    report['implementation_sha256']={p.name:sha(p.read_bytes()) for p in sorted(package.glob('*.py')) if not p.name.startswith('test_')}
    encoded=json.dumps(report,ensure_ascii=False,sort_keys=True,indent=2)+'\n'
    for path,text in zip(outputs,(encoded,markdown(report))):
        if path:
            with path.open('x',encoding='utf-8') as stream:stream.write(text)
    if outputs[0]:print(json.dumps(dict(status=report['status'],summary=report['summary'],json_out=str(outputs[0]),guest_executions=0),sort_keys=True))
    else:print(encoded,end='')
    return 0 if report['status']=='INVENTORIED' else 2


if __name__=='__main__':
    try:sys.exit(main())
    except (InventoryError,OSError) as error:
        print(json.dumps(dict(status='INPUT_OR_OUTPUT_REJECTED',error=str(error),guest_executions=0),sort_keys=True),file=sys.stderr)
        sys.exit(2)
