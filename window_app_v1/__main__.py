import argparse
import json
from pathlib import Path

from window_app_v1 import package


def main():
    parser=argparse.ArgumentParser(description='将已验证的窗口 PE 构建打包为无参数 App；不自动启动')
    sub=parser.add_subparsers(dest='command',required=True)
    build=sub.add_parser('build');build.add_argument('--source',type=Path,required=True);build.add_argument('--out',type=Path,required=True)
    build.add_argument('--identifier',required=True);build.add_argument('--name',default='PE AOT Configured Window')
    verify=sub.add_parser('verify');verify.add_argument('output',type=Path)
    args=parser.parse_args()
    try:
        r=package.build(args.source,args.out,dict(identifier=args.identifier,name=args.name)) if args.command=='build' else package.verify(args.output)
        print(json.dumps(dict(status=r['status'],app=r['app'],relocated=r['relocated'],pe_sha256=r['pe_sha256'],
                             identifier=r['spec']['identifier'],requires_arguments=False,guest_executions=0),indent=2))
        return 0
    except (OSError,ValueError,RuntimeError) as error:
        print(json.dumps(dict(status='BUILD_OR_VERIFY_FAILED',error_type=type(error).__name__,error=str(error)),indent=2))
        return 70


if __name__=='__main__':raise SystemExit(main())
