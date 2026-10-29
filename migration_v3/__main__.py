"""Unified PE tooling; window --profile currently produces a native CLI host."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='PE AOT：控制台 App 或显式配置的受限窗口原生宿主')
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('analyze', 'build'):
        command = sub.add_parser(name)
        command.add_argument('input', type=Path)
        command.add_argument('--profile', type=Path, help='窗口 JSON 配置；省略则使用 process-scalar-v2')
        if name == 'build':
            command.add_argument('--out', type=Path, required=True)
    verification = sub.add_parser('verify')
    verification.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'verify':
            receipt = json.loads((args.output / 'result.json').read_bytes())
            if receipt.get('profile') == 'win32-d3d11-tile-v1':
                from window_profile_v1.build import verify
            elif receipt.get('profile') == 'process-scalar-v2':
                from migration_v2.build import verify
            else:
                raise ValueError('unknown build profile')
            result = verify(args.output)
        elif args.profile is not None:
            from window_profile_v1.profile import read_profile, read_input, analyze
            profile = read_profile(args.profile)
            if args.command == 'analyze':
                result = analyze(read_input(args.input), profile)
            else:
                from window_profile_v1.build import build
                result = build(args.input, args.out, profile)
        else:
            from migration_v2.analyze import analyze, read_input
            if args.command == 'analyze':
                result = analyze(read_input(args.input))
            else:
                from migration_v2.build import build
                result = build(args.input, args.out)
        code = 2 if result['status'] == 'UNSUPPORTED' else 70 if result['status'] == 'BUILD_FAILED' else 0
    except (OSError, ValueError) as error:
        result = dict(status='INPUT_OR_ENVIRONMENT_ERROR', error_type=type(error).__name__, error=str(error))
        code = 64
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
