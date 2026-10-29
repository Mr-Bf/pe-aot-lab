import argparse
from .build import build

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Build a fixed-source native graphics provider in a fresh prefix')
    parser.add_argument('--prefix',required=True)
    parser.add_argument('--cache',dest='cache_path',required=True)
    parser.add_argument('--out',required=True)
    parser.add_argument('--jobs',type=int,default=2)
    print(build(**vars(parser.parse_args()))['status'])
