import argparse
import json
from .doctor import diagnose, READY


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only v7 installation prerequisites; stdout JSON, no builders or App')
    for option in ('cpu-cache', 'graphics-cache', 'pe', 'profile', 'identifier', 'work-root', 'out'):
        parser.add_argument('--' + option, required=True)
    parser.add_argument('--jobs', type=int, default=2)
    values = vars(parser.parse_args(argv))
    result = diagnose(**values)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result['status'] == READY else 2


if __name__ == '__main__':
    raise SystemExit(main())
