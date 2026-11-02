import argparse
import json
from .runner import prepare, measure


def main():
    parser=argparse.ArgumentParser(description='Prepare a lookup-only overlay and run a bounded same-process paired experiment')
    commands=parser.add_subparsers(dest='command',required=True)
    p=commands.add_parser('prepare')
    p.add_argument('--baseline-prepared',required=True)
    p.add_argument('--out',required=True)
    p=commands.add_parser('measure')
    p.add_argument('--prepared',required=True)
    p.add_argument('--out',required=True)
    p.add_argument('--iterations',type=int,default=4096)
    p.add_argument('--rounds',type=int,default=12)
    args=vars(parser.parse_args());command=args.pop('command')
    result=(prepare if command=='prepare' else measure)(**args)
    print(json.dumps({key:result[key] for key in ('status','out')},sort_keys=True))


if __name__=='__main__':
    main()
