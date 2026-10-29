import argparse
from . import build


def main():
    parser = argparse.ArgumentParser(description='Build/probe a fresh-prefix, bounded ARM64 CPU lifter')
    commands = parser.add_subparsers(dest='command', required=True)
    install = commands.add_parser('build')
    install.add_argument('--prefix', required=True)
    install.add_argument('--cache', required=True)
    install.add_argument('--out', required=True)
    install.add_argument('--jobs',type=int,default=2)
    probe = commands.add_parser('probe')
    probe.add_argument('--prefix',required=True)
    probe.add_argument('--pe',required=True)
    probe.add_argument('--out',required=True)
    args = vars(parser.parse_args())
    command = args.pop('command')
    result = getattr(build,command)(**args)
    print(result['status'])


if __name__ == '__main__':
    main()
