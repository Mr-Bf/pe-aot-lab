import argparse
import json
import sys

from . import runner


def main():
    parser = argparse.ArgumentParser(description='Plan or build the existing v5 App from two offline public caches; never launches the App')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('plan', 'install'):
        part = commands.add_parser(name)
        for option in ('cpu-cache', 'graphics-cache', 'pe', 'profile', 'identifier', 'work-root', 'out'):
            part.add_argument('--' + option, required=True)
        part.add_argument('--jobs', type=int, default=2)
    args = vars(parser.parse_args())
    command = args.pop('command')
    try:
        result = getattr(runner, command)(**args)
    except KeyboardInterrupt:
        print('INSTALL_INTERRUPTED: child state is unknown; no automatic retry or cleanup is claimed', file=sys.stderr)
        return 130
    except Exception as error:
        print(json.dumps({'status': 'INSTALL_INPUT_OR_PREFLIGHT_FAILED', 'error_type': type(error).__name__,
                          'error': str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result['status'] in (runner.PLAN_STATUS, runner.STATUS) else 1


if __name__ == '__main__':
    raise SystemExit(main())
