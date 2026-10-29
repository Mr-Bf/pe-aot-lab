import argparse
import sys
from .prepare import prepare_cpu
from migration_cache_v1.prepare import error_record


def main():
    parser = argparse.ArgumentParser(description='Acquire fixed CPU inputs with bounded GHCR ranges')
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('prepare-cpu')
    command.add_argument('--cache', required=True)
    command.add_argument('--out', required=True)
    command.add_argument('--resume-from', help='explicit failed v1 acquisition evidence directory; LLVM prefix only')
    args = vars(parser.parse_args()); args.pop('command')
    try:
        print(prepare_cpu(**args)['status'])
        return 0
    except Exception as error:
        print('CACHE_PREPARATION_FAILED: ' + str(error_record(error)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
