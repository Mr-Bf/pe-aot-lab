import argparse
import json
from .build import build
from .run import run


def main():
    parser = argparse.ArgumentParser(description='Untimed same-address replay diagnostics; never edits the production App')
    commands = parser.add_subparsers(dest='operation', required=True)
    part = commands.add_parser('build')
    part.add_argument('--product', required=True); part.add_argument('--out', required=True)
    part = commands.add_parser('run')
    part.add_argument('--build', required=True); part.add_argument('--out', required=True)
    part.add_argument('--timeout', type=int, default=60)
    values = vars(parser.parse_args()); operation = values.pop('operation')
    value = (build if operation == 'build' else run)(**values)
    print(json.dumps({k: v for k, v in value.items() if k in ('status', 'scope')}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
