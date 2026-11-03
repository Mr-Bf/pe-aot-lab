"""One project config: inspect, plan, build, resume and verify a restricted App."""
import argparse
import json
from pathlib import Path
import sys

from . import config, workflow


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True,metavar='{init,check,plan,build,resume,verify,status}')
    part=commands.add_parser('init')
    part.add_argument('--config',required=True)
    part.add_argument('--pe',required=True)
    part.add_argument('--profile')
    part.add_argument('--identifier',default='org.peaotlab.converted')
    for name in ('cpu-prefix','graphics-prefix','cpu-cache','graphics-cache'):
        part.add_argument('--'+name)
    part.add_argument('--jobs',type=int,default=2)
    for name in ('check','plan','build'):
        part=commands.add_parser(name);part.add_argument('config');part.add_argument('--out',required=True)
    for name in ('resume','verify','status'):
        commands.add_parser(name).add_argument('workspace')
    part=commands.add_parser('_worker')
    part.add_argument('job');part.add_argument('--lock-fd',type=int,required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='_worker':return workflow.worker(args.job,args.lock_fd)
        if args.command=='init':
            provider=bool(args.cpu_prefix or args.graphics_prefix)
            offline=bool(args.cpu_cache or args.graphics_cache)
            config.require(provider != offline,'INVALID_BACKEND','请选择完整的一组provider或offline cache路径')
            if provider:
                config.require(args.cpu_prefix and args.graphics_prefix,'INVALID_BACKEND','需要cpu-prefix及graphics-prefix')
                backend=dict(mode='providers',cpu_prefix=args.cpu_prefix,graphics_prefix=args.graphics_prefix)
            else:
                config.require(args.cpu_cache and args.graphics_cache,'INVALID_BACKEND','需要cpu-cache及graphics-cache')
                backend=dict(mode='offline',cpu_cache=args.cpu_cache,graphics_cache=args.graphics_cache,jobs=args.jobs)
            result=config.initialize(args.config,dict(schema=1,pe=args.pe,profile=args.profile,
                identifier=args.identifier,build=backend))
        elif args.command in ('check','plan'):
            result=workflow.check(args.config,args.out)
            if args.command=='plan':
                result=dict(result,plan_only=True,stages=['input-and-recipe','dependency-preflight','fresh-or-resumed-build','package-app','verify-product'],
                    build_command=[sys.executable,'-B','-m','migration_workflow_v1','build',str(Path(args.config).absolute()),'--out',str(Path(args.out).absolute())])
        elif args.command=='build':result=workflow.build(args.config,args.out)
        else:result=getattr(workflow,args.command)(args.workspace)
    except KeyboardInterrupt:
        print(json.dumps(dict(status='MIGRATION_INTERRUPTED_WORKER_STATE_UNKNOWN',
            next_action='请用status查看；resume会重验锁和旧进程组，不要重复build')),file=sys.stderr)
        return 130
    except Exception as error:
        print(json.dumps(dict(status='MIGRATION_COMMAND_REJECTED',**workflow.error_record(error,args.command)),ensure_ascii=False),file=sys.stderr)
        return 2
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))
    if result['status']=='MIGRATION_BUILD_FAILED':return 1
    return 2 if result['status']=='MIGRATION_BLOCKED' else 0


if __name__=='__main__':
    raise SystemExit(main())
