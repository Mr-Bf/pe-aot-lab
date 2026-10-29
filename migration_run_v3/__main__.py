import argparse
from pathlib import Path

from .runner import run

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Supervise one verified migration_v6 App; OS input is supplied separately')
    parser.add_argument('--product', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--relocate', action='store_true')
    parser.add_argument('--timeout', type=int, default=180)
    args = parser.parse_args()
    run(args.product, args.out, args.relocate, args.timeout)
