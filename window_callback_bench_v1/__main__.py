import argparse
import json
from .runner import prepare, measure


def main():
    parser = argparse.ArgumentParser(description='Prepare verified callback objects, then explicitly measure a bounded CPU baseline')
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare')
    for name in ('product', 'probe', 'out'):
        p.add_argument('--'+name, required=True)
    p = commands.add_parser('measure')
    for name in ('prepared', 'out'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--iterations', type=int, default=4096)
    p.add_argument('--rounds', type=int, default=12)
    args = vars(parser.parse_args()); command = args.pop('command')
    result = (prepare if command == 'prepare' else measure)(**args)
    print(json.dumps({k: result[k] for k in ('status', 'out')}, sort_keys=True))


if __name__ == '__main__':
    main()
