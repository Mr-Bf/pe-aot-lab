import argparse
import sys
from .prepare import prepare_cpu, error_record


def main():
    parser = argparse.ArgumentParser(description='Acquire nine pinned public CPU build inputs; no compilation')
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare-cpu')
    prepare.add_argument('--cache', required=True)
    prepare.add_argument('--out', required=True)
    args = parser.parse_args()
    try:
        print(prepare_cpu(args.cache, args.out)['status'])
        return 0
    except Exception as error:
        # Do not render network exception tracebacks containing redirect tokens.
        print('CACHE_PREPARATION_FAILED: ' + str(error_record(error)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
