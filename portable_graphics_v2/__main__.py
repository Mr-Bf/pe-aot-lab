"""Explicit cache and build commands; preparation never launches compilation."""
import argparse
import json
import sys

from migration_cache_v1.prepare import error_record


def main():
    parser = argparse.ArgumentParser(description='Public graphics cache and explicit native provider build')
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('--cache', dest='cache_path', required=True)
    prepare.add_argument('--out', required=True)
    prepare.add_argument('--git-proxy')
    check = commands.add_parser('check')
    check.add_argument('--cache', required=True)
    extract = commands.add_parser('extract')
    extract.add_argument('--cache', required=True)
    extract.add_argument('--out', dest='destination', required=True)
    build = commands.add_parser('build')
    build.add_argument('--prefix', required=True)
    build.add_argument('--cache', dest='cache_path', required=True)
    build.add_argument('--out', required=True)
    build.add_argument('--jobs', type=int, default=2)
    args = vars(parser.parse_args()); command = args.pop('command')
    try:
        if command == 'prepare':
            from .prepare import prepare
            print(prepare(**args)['status'])
        elif command == 'build':
            from .build import build
            print(build(**args)['status'])
        elif command == 'check':
            from .cache import check_cache
            result = check_cache(**args)
            print(json.dumps({'status': 'CONTENT_CACHE_VERIFIED_NOT_BUILT', 'cache': result['cache'],
                              'lock_sha256': result['lock_sha256']}, sort_keys=True))
        else:
            from .cache import extract_sources
            print(json.dumps({'status': 'SOURCES_EXTRACTED_NOT_BUILT', 'sources': extract_sources(**args)}, sort_keys=True))
        return 0
    except Exception as error:
        print('GRAPHICS_V2_FAILED: ' + str(error_record(error)), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
