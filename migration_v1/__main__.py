"""python -m migration_v1 {analyze,build,verify}; JSON on stdout, stable exit classes."""
import argparse
import json
from pathlib import Path

from migration_v1.analyze import analyze, read_input


def main():
    parser = argparse.ArgumentParser(description='受限 PE → ARM64 迁移入口；分析通过不等于可运行')
    sub = parser.add_subparsers(dest='command', required=True)
    analysis = sub.add_parser('analyze', help='只读分析 PE 元数据及 process-v1 装载条件，不解码或启动程序')
    analysis.add_argument('input', type=Path)
    build = sub.add_parser('build', help='真实 AOT 构建受限命令行 App；不启动 guest；输出目录必须不存在')
    build.add_argument('input', type=Path)
    build.add_argument('--out', type=Path, required=True)
    verify = sub.add_parser('verify', help='只读核对本机构建记录，不执行目标')
    verify.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'analyze':
            result = analyze(read_input(args.input))
        else:
            from migration_v1 import build as implementation
            result = implementation.build(args.input, args.out) if args.command == 'build' else implementation.verify(args.output)
        code = 2 if result['status'] == 'UNSUPPORTED' else 70 if result['status'] == 'BUILD_FAILED' else 0
    except (OSError, ValueError) as error:
        result = dict(status='INPUT_OR_ENVIRONMENT_ERROR', error_type=type(error).__name__, error=str(error))
        code = 64
    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
