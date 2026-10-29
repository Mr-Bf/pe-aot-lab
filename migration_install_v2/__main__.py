import argparse
import json
import sys
from . import runner


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '_worker':
        parser = argparse.ArgumentParser(description='Internal inherited-lock stage worker')
        parser.add_argument('_worker'); parser.add_argument('job')
        parser.add_argument('--lock-fd', type=int, required=True)
        values = parser.parse_args()
        return runner.worker(values.job, values.lock_fd)
    parser = argparse.ArgumentParser(description='Offline v6 install/resume with independently verified stages; never launches App')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('plan', 'install'):
        part = commands.add_parser(name)
        for option in ('cpu-cache','graphics-cache','pe','profile','identifier','work-root','out'):
            part.add_argument('--'+option, required=True)
        part.add_argument('--jobs',type=int,default=2)
    part = commands.add_parser('resume')
    part.add_argument('--installation',required=True); part.add_argument('--out',required=True)
    values = vars(parser.parse_args()); command = values.pop('command')
    try:
        result = getattr(runner,command)(**values)
    except KeyboardInterrupt:
        print('INSTALL_INTERRUPTED_CHILD_STATE_UNKNOWN: resume requires lock and OS group revalidation',file=sys.stderr)
        return 130
    except Exception as error:
        print(json.dumps(dict(status='INSTALL_INPUT_OR_PREFLIGHT_FAILED',error_type=type(error).__name__,error=str(error))),file=sys.stderr)
        return 2
    print(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2))
    return 0 if result['status'] in (runner.PLAN_STATUS,runner.STATUS) else 1


if __name__ == '__main__':
    raise SystemExit(main())
