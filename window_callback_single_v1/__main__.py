import argparse
import json
from .runner import prepare, measure


def main():
    p=argparse.ArgumentParser(description='Validate fixed lookup artifacts, then measure process-paired callback batches')
    commands=p.add_subparsers(dest='command',required=True)
    q=commands.add_parser('prepare')
    q.add_argument('--baseline-prepared',required=True);q.add_argument('--out',required=True)
    q=commands.add_parser('measure')
    q.add_argument('--prepared',required=True);q.add_argument('--out',required=True)
    q.add_argument('--iterations',type=int,default=4096);q.add_argument('--rounds',type=int,default=12)
    args=vars(p.parse_args());command=args.pop('command');v=(prepare if command=='prepare' else measure)(**args)
    print(json.dumps({k:v[k] for k in ('status','out')},sort_keys=True))


if __name__=='__main__':main()
