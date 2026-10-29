import argparse
import json
from pathlib import Path

from portable_graphics_v1.cache import read_json
from window_switch_v1.profile import read_input,analyze
from .build import build,verify,STATUS

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Configured window PE to App using explicit independent CPU/graphics providers')
    commands=parser.add_subparsers(dest='command',required=True)
    for name in ('analyze','build'):
        part=commands.add_parser(name);part.add_argument('pe');part.add_argument('--profile',required=True)
        if name=='build':
            for key in ('identifier','cpu-prefix','backend-prefix','out'):part.add_argument('--'+key,required=True)
    part=commands.add_parser('verify');part.add_argument('out')
    args=vars(parser.parse_args());command=args.pop('command')
    if command in ('analyze','build'):args['profile']=read_json(args['profile'])
    if command=='analyze':
        result=analyze(read_input(args['pe']),args['profile'])
        code=0 if result['status']=='ELIGIBLE_FOR_BUILD_NOT_DECODED' else 2
    elif command=='build':
        result=build(**args);code=0 if result['status']==STATUS else (2 if result['status']=='UNSUPPORTED' else 1)
    else:result=verify(**args);code=0
    print(json.dumps({key:result[key] for key in ('status','stage','app','files','error') if key in result and key!='files'}))
    raise SystemExit(code)
